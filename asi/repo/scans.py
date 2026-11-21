"""Skany i ich wyniki (zasoby, krawędzie grafu, ustalenia, log)."""
import json
import time

from .. import db

ACTIVE = ("queued", "running")


# ---------- cykl życia skanu ----------
def create(target, opts):
    with db.conn() as c:
        return c.execute("INSERT INTO scans(target,opts,created) VALUES(?,?,?)",
                         (target, json.dumps(opts), time.time())).lastrowid


def target_and_opts(sid):
    with db.conn() as c:
        r = c.execute("SELECT target, opts FROM scans WHERE id=?", (sid,)).fetchone()
    if r is None:
        raise LookupError(f"skan {sid} nie istnieje")
    return r["target"], json.loads(r["opts"])


def mark_running(sid):
    with db.conn() as c:
        c.execute("UPDATE scans SET status='running' WHERE id=?", (sid,))


def finish(sid, status, stage, score):
    with db.conn() as c:
        c.execute("UPDATE scans SET status=?, stage=?, score=?, finished=? WHERE id=?",
                  (status, stage, score, time.time(), sid))


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
        for t in ("assets", "edges", "findings"):
            c.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
        c.execute("DELETE FROM scans WHERE id=?", (sid,))


# ---------- zapis w trakcie skanu ----------
def append_log(sid, line):
    with db.conn() as c:
        c.execute("UPDATE scans SET log = log || ? WHERE id=?", (line, sid))


def set_stage(sid, stage):
    with db.conn() as c:
        c.execute("UPDATE scans SET stage=? WHERE id=?", (stage, sid))


def upsert_asset(sid, aid, kind, value, data):
    with db.conn() as c:
        c.execute("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                  (sid, aid, kind, value, json.dumps(data)))


def has_asset(sid, aid):
    with db.conn() as c:
        return c.execute("SELECT 1 FROM assets WHERE scan_id=? AND id=?", (sid, aid)).fetchone() is not None


def merge_tech(sid, aid, tech):
    with db.conn() as c:
        r = c.execute("SELECT data FROM assets WHERE scan_id=? AND id=?", (sid, aid)).fetchone()
        if r:
            d = json.loads(r["data"])
            d["tech"] = sorted(set(d.get("tech", [])) | set(tech))
            c.execute("UPDATE assets SET data=? WHERE scan_id=? AND id=?", (json.dumps(d), sid, aid))


def add_edge(sid, src, dst):
    with db.conn() as c:
        c.execute("INSERT OR IGNORE INTO edges(scan_id,src,dst) VALUES(?,?,?)", (sid, src, dst))


def add_finding(sid, asset, severity, title, source, detail, fix):
    with db.conn() as c:
        c.execute("INSERT INTO findings(scan_id,asset,severity,title,source,detail,fix) VALUES(?,?,?,?,?,?,?)",
                  (sid, asset, severity, title, source, detail, fix))


def severities(sid):
    with db.conn() as c:
        return [r["severity"] for r in c.execute("SELECT severity FROM findings WHERE scan_id=?", (sid,))]


# ---------- odczyt ----------
def list_recent(limit=50):
    with db.conn() as c:
        rows = c.execute("SELECT s.id,s.target,s.status,s.stage,s.score,s.created,s.finished,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s ORDER BY s.id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def load(sid):
    """Zwraca (scan, assets, edges, findings) albo None, gdy skanu nie ma. Ustalenia w kolejności zapisu."""
    with db.conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        assets = [dict(r, data=json.loads(r["data"])) for r in
                  c.execute("SELECT id,kind,value,data FROM assets WHERE scan_id=?", (sid,))]
        edges = [dict(r) for r in c.execute("SELECT src,dst FROM edges WHERE scan_id=?", (sid,))]
        findings = [dict(r) for r in c.execute("SELECT * FROM findings WHERE scan_id=?", (sid,))]
    return dict(s), assets, edges, findings


def previous_done(target, before_id):
    """Ostatni zakończony skan celu przed danym: {"id", "score"} albo None."""
    with db.conn() as c:
        r = c.execute("SELECT id,score FROM scans WHERE target=? AND status='done' AND id<? "
                      "ORDER BY id DESC LIMIT 1", (target, before_id)).fetchone()
    return dict(r) if r else None


def trend(target, upto_id, limit=12):
    """Ostatnie zakończone skany celu, rosnąco po czasie."""
    with db.conn() as c:
        rows = c.execute("SELECT id,score,created,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s WHERE target=? AND status='done' AND id<=? "
                         "ORDER BY id DESC LIMIT ?", (target, upto_id, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]
