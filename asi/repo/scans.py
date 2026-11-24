"""Skany i ich wyniki (zasoby, krawędzie grafu, ustalenia, log, punkt wznowienia).

Pola z surowymi danymi ze skanowanych hostów (log, szczegóły ustaleń, dane zasobów) są szyfrowane
w spoczynku (crypto.py); identyfikatory, tytuły i ważności zostają jawne, bo na nich działa diff i sortowanie.
Szyfrowanie jest szczegółem tego modułu - wyżej widać zwykły tekst.
"""
import base64
import json
import threading
import time
import zlib

from .. import crypto, db

ACTIVE = ("queued", "running")
LOG_LOCK = threading.Lock()  # log jest szyfrowany, więc doklejenie to odczyt+zapis - serializujemy wątki jednego procesu


# ---------- cykl życia skanu ----------
def create(display_target, target_hash, opts, targets):
    """Zakłada rekord skanu wraz z jego celami (już zwalidowanymi i rozwiniętymi). Zwraca id."""
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,target_hash,opts,created,hosts_total) VALUES(?,?,?,?,?)",
                        (display_target, target_hash, json.dumps(opts), time.time(), len(targets))).lastrowid
        c.executemany("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)", [(sid, t) for t in targets])
    return sid


def create_imported(target, target_hash, score, assets, edges, findings):
    """Skan z zaimportowanych wyników (stage 'zaimportowany'). Zwraca (id, liczba zapisanych ustaleń)."""
    now = time.time()
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,target_hash,opts,status,stage,score,hosts_total,hosts_done,created,finished,log) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (target, target_hash, "{}", "done", "zaimportowany", score, len(assets), len(assets), now, now,
                         crypto.enc(""))).lastrowid
        c.execute("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)", (sid, target))
        for a in assets:
            c.execute("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                      (sid, a["id"], a["kind"], a["value"], crypto.enc(json.dumps(a.get("data") or {}))))
        for e in edges:
            c.execute("INSERT OR IGNORE INTO edges(scan_id,src,dst) VALUES(?,?,?)", (sid, e["src"], e["dst"]))
        for f in findings:
            c.execute("INSERT INTO findings(scan_id,asset,severity,title,source,detail,fix) VALUES(?,?,?,?,?,?,?)",
                      (sid, f["asset"], f["severity"], f["title"], f["source"], crypto.enc(f["detail"]), f["fix"]))
    return sid, len(findings)


def set_score(sid, score):
    with db.conn() as c:
        c.execute("UPDATE scans SET score=? WHERE id=?", (score, sid))


def run_info(sid):
    """(display_target, opts, created, [cele]) - to, czego potrzebuje kontekst skanu. LookupError, gdy skanu nie ma."""
    with db.conn() as c:
        r = c.execute("SELECT target, opts, created FROM scans WHERE id=?", (sid,)).fetchone()
        if r is None:
            raise LookupError(f"skan {sid} nie istnieje")
        targets = [t["target"] for t in c.execute("SELECT target FROM scan_targets WHERE scan_id=?", (sid,))]
    return r["target"], json.loads(r["opts"]), r["created"], targets


def mark_running(sid):
    with db.conn() as c:
        c.execute("UPDATE scans SET status='running' WHERE id=?", (sid,))


def claim_resume(sid):
    """Atomowo: wstrzymany oknem czasowym -> w kolejce. False, gdy ktoś inny już go wznowił albo skan nie jest wstrzymany.

    UPDATE ... WHERE zamiast SELECT-potem-UPDATE: dwa równoległe wywołania (np. ręczne /resume i harmonogram) nie mogą
    oba przejść i wystartować dwóch wątków dla tego samego skanu, ścigających się o punkt wznowienia."""
    with db.conn() as c:
        return c.execute("UPDATE scans SET status='queued', stage='wznowienie' WHERE id=? AND status='paused_window'",
                         (sid,)).rowcount > 0


def request_stop(sid):
    with db.conn() as c:
        c.execute("UPDATE scans SET stop_requested=1 WHERE id=?", (sid,))


def stop_requested(sid):
    with db.conn() as c:
        r = c.execute("SELECT stop_requested FROM scans WHERE id=?", (sid,)).fetchone()
    return bool(r and r["stop_requested"])


def mark_interrupted():
    """Po restarcie procesu skany 'w toku' już nie żyją - oznaczamy je jako przerwane."""
    with db.conn() as c:
        c.execute("UPDATE scans SET status='failed', stage='przerwany (restart)' WHERE status IN (?,?)", ACTIVE)


def status(sid):
    with db.conn() as c:
        r = c.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()
    return r["status"] if r else None


def is_busy(target):
    with db.conn() as c:
        return c.execute("SELECT 1 FROM scans WHERE target=? AND status IN (?,?)", (target, *ACTIVE)).fetchone() is not None


def delete(sid):
    with db.conn() as c:
        for t in ("assets", "edges", "findings", "scan_targets", "nmap_runs"):
            c.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
        c.execute("DELETE FROM scans WHERE id=?", (sid,))


# ---------- zapis w trakcie skanu (bezpieczny z dowolnego wątku) ----------
def append_log(sid, line):
    with LOG_LOCK, db.conn() as c:
        cur = c.execute("SELECT log FROM scans WHERE id=?", (sid,)).fetchone()
        c.execute("UPDATE scans SET log=? WHERE id=?", (crypto.enc(crypto.dec(cur["log"]) + line), sid))


def set_stage(sid, stage):
    with db.conn() as c:
        c.execute("UPDATE scans SET stage=? WHERE id=?", (stage, sid))


class Writer:
    """Zapisy z głównego wątku pipeline'u na jednym trwałym połączeniu.

    Otwieranie połączenia + commit + close przy KAŻDYM zasobie i ustaleniu mierzalnie spowalniało skany na tysiącach
    hostów. Połączenie SQLite nie jest współdzielone między wątkami, więc wszystko, co woła wątek roboczy
    (log, stage, odczyt flagi stopu), idzie przez funkcje modułu powyżej, nie przez Writer."""

    def __init__(self, sid):
        self.sid = sid
        self._c = db.raw_connect()

    def close(self):
        self._c.close()

    def _run(self, sql, *args):
        r = self._c.execute(sql, args)
        self._c.commit()
        return r

    def upsert_asset(self, aid, kind, value, data):
        self._run("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                  self.sid, aid, kind, value, crypto.enc(json.dumps(data)))

    def has_asset(self, aid):
        return self._c.execute("SELECT 1 FROM assets WHERE scan_id=? AND id=?", (self.sid, aid)).fetchone() is not None

    def merge_tech(self, aid, tech):
        r = self._c.execute("SELECT data FROM assets WHERE scan_id=? AND id=?", (self.sid, aid)).fetchone()
        if r:
            d = json.loads(crypto.dec(r["data"]))
            d["tech"] = sorted(set(d.get("tech", [])) | set(tech))
            self._run("UPDATE assets SET data=? WHERE scan_id=? AND id=?", crypto.enc(json.dumps(d)), self.sid, aid)

    def merge_data(self, aid, kind, value, data):
        """Dokłada pola do danych zasobu, zakładając go, gdy go jeszcze nie ma."""
        r = self._c.execute("SELECT data FROM assets WHERE scan_id=? AND id=?", (self.sid, aid)).fetchone()
        self.upsert_asset(aid, kind, value, {**(json.loads(crypto.dec(r["data"])) if r else {}), **data})

    def add_nmap_run(self, command, started, elapsed, complete, hosts, hosts_up, xml):
        self._run("INSERT INTO nmap_runs(scan_id,command,started,elapsed,complete,hosts,hosts_up,xml) VALUES(?,?,?,?,?,?,?,?)",
                  self.sid, crypto.enc(command), started, elapsed, int(complete), hosts, hosts_up, _pack(xml))

    def add_edge(self, src, dst):
        self._run("INSERT OR IGNORE INTO edges(scan_id,src,dst) VALUES(?,?,?)", self.sid, src, dst)

    def override_for(self, asset, title):
        """Trwała decyzja operatora (zmiana ważności, fałszywy alarm) dla tej pary - albo None."""
        return self._c.execute("SELECT severity, fix, false_positive FROM finding_overrides WHERE asset=? AND title=?",
                               (asset, title)).fetchone()

    def add_finding(self, asset, severity, title, source, detail, fix):
        self._run("INSERT INTO findings(scan_id,asset,severity,title,source,detail,fix) VALUES(?,?,?,?,?,?,?)",
                  self.sid, asset, severity, title, source, crypto.enc(detail), fix)

    def stored_ports(self):
        """{ip: [port]} z zasobów 'port' zapisanych dla tego skanu."""
        out = {}
        for r in self._c.execute("SELECT value, data FROM assets WHERE scan_id=? AND kind='port'", (self.sid,)):
            ip, _, _ = r["value"].rpartition(":")
            out.setdefault(ip, []).append(json.loads(crypto.dec(r["data"])))
        return out

    def set_hosts_total(self, n):
        self._run("UPDATE scans SET hosts_total=? WHERE id=?", n, self.sid)

    def set_hosts_done(self, n):
        self._run("UPDATE scans SET hosts_done=? WHERE id=?", n, self.sid)

    def severities(self):
        return [r["severity"] for r in self._c.execute("SELECT severity FROM findings WHERE scan_id=?", (self.sid,))]

    def host_count(self):
        return self._c.execute("SELECT COUNT(*) AS n FROM assets WHERE scan_id=? AND kind='ip'", (self.sid,)).fetchone()["n"]

    def finish(self, status, stage, score, duration_s):
        self._run("UPDATE scans SET status=?, stage=?, score=?, finished=?, duration_s=? WHERE id=?",
                  status, stage, score, time.time(), duration_s, self.sid)

    def load_checkpoint(self):
        row = self._c.execute("SELECT checkpoint FROM scans WHERE id=?", (self.sid,)).fetchone()
        return json.loads(row["checkpoint"]) if row and row["checkpoint"] else None

    def save_checkpoint(self, cp):
        self._run("UPDATE scans SET checkpoint=? WHERE id=?", json.dumps(cp), self.sid)

    def clear_checkpoint(self):
        self._run("UPDATE scans SET checkpoint=NULL WHERE id=?", self.sid)


# ---------- surowe wyniki nmap ----------
def _pack(text):
    """XML jest bardzo powtarzalny: kompresja przed szyfrowaniem zmniejsza bazę o rząd wielkości."""
    return crypto.enc(base64.b64encode(zlib.compress(text.encode("utf-8"))).decode("ascii"))


def _unpack(stored):
    return zlib.decompress(base64.b64decode(crypto.dec(stored))).decode("utf-8")


def nmap_runs(sid):
    """Uruchomienia nmapa w skanie (bez XML), w kolejności."""
    with db.conn() as c:
        rows = c.execute("SELECT id,command,started,elapsed,complete,hosts,hosts_up FROM nmap_runs WHERE scan_id=? ORDER BY id", (sid,)).fetchall()
    return [dict(r, command=crypto.dec(r["command"]), complete=bool(r["complete"])) for r in rows]


def nmap_xml(sid):
    """Surowe wyniki XML kolejnych uruchomień nmapa."""
    with db.conn() as c:
        rows = c.execute("SELECT xml FROM nmap_runs WHERE scan_id=? ORDER BY id", (sid,)).fetchall()
    return [_unpack(r["xml"]) for r in rows]


# ---------- odczyt ----------
def list_recent(limit=50):
    with db.conn() as c:
        rows = c.execute("SELECT s.id,s.target,s.status,s.stage,s.score,s.created,s.finished,"
                         "s.hosts_total,s.hosts_done,s.duration_s,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s ORDER BY s.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def targets_of(sid):
    with db.conn() as c:
        return [r["target"] for r in c.execute("SELECT target FROM scan_targets WHERE scan_id=? ORDER BY target", (sid,))]


def load(sid):
    """(scan, assets, edges, findings) albo None, gdy skanu nie ma. Dane odszyfrowane; ustalenia z `rowid`."""
    with db.conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        assets = [dict(r, data=json.loads(crypto.dec(r["data"]))) for r in
                  c.execute("SELECT id,kind,value,data FROM assets WHERE scan_id=?", (sid,))]
        edges = [dict(r) for r in c.execute("SELECT src,dst FROM edges WHERE scan_id=?", (sid,))]
        findings = [dict(r) for r in c.execute("SELECT rowid, * FROM findings WHERE scan_id=?", (sid,))]
    for f in findings:
        f["detail"] = crypto.dec(f["detail"])
    s = dict(s)
    s["log"] = crypto.dec(s["log"])
    return s, assets, edges, findings


def previous_done(target_hash, before_id, limit=1):
    """Ostatnie zakończone (nie zaimportowane) skany tego samego zakresu przed danym, od najnowszego: [{"id","score"}]."""
    if not target_hash:
        return []
    with db.conn() as c:
        rows = c.execute("SELECT id,score FROM scans WHERE target_hash=? AND status='done' AND stage!='zaimportowany' "
                         "AND id<? ORDER BY id DESC LIMIT ?", (target_hash, before_id, limit)).fetchall()
    return [dict(r) for r in rows]


def trend(target_hash, upto_id, limit=12):
    """Ostatnie zakończone skany zakresu, rosnąco po czasie."""
    if not target_hash:
        return []
    with db.conn() as c:
        rows = c.execute("SELECT id,score,created,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s WHERE target_hash=? AND status='done' AND stage!='zaimportowany' AND id<=? "
                         "ORDER BY id DESC LIMIT ?", (target_hash, upto_id, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]


# ---------- zakresy (grupa skanów o tych samych celach = target_hash) ----------
def range_runs(rid_prefix):
    """Skany (od najnowszego) zakresu o identyfikatorze zaczynającym się od prefiksu, bez zaimportowanych."""
    with db.conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, target_hash, opts, status FROM scans WHERE target_hash LIKE ? AND stage!='zaimportowany' ORDER BY id DESC",
            (rid_prefix + "%",))]


def run_info_or_none(sid):
    """Jak run_info, ale None zamiast wyjątku, gdy skanu nie ma."""
    try:
        return run_info(sid)
    except LookupError:
        return None
