"""API + serwowanie UI. Start: uvicorn asi.main:app --host 127.0.0.1 --port 8000"""
import csv
import hashlib
import html
import io
import json
import os
import sqlite3
import threading
import time

from fastapi import Cookie, Depends, FastAPI, File, Form, HTTPException, Response as FastAPIResponse, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from . import auth, crypto, db, defectdojo, scanner
from . import signatures as signatures_mod
from . import targets as targets_mod

app = FastAPI(title="Attack Surface Intelligence PoC")
STATIC = os.path.join(db.ROOT, "static")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _scheduler_loop():
    while True:
        try:
            now = time.time()
            with db.conn() as c:
                due = c.execute(
                    "SELECT id, target, opts, interval_hours, time_window_mins FROM schedules "
                    "WHERE enabled=1 AND next_run <= ?", (now,)).fetchall()
                for s in due:
                    opts = json.loads(s["opts"] or "{}")
                    if s["time_window_mins"]:
                        opts["time_window_mins"] = s["time_window_mins"]
                    targets = [t.strip() for t in s["target"].split(",") if t.strip()]
                    try:
                        _start_scan(targets, opts)
                        next_t = now + max(1, s["interval_hours"]) * 3600
                        c.execute("UPDATE schedules SET last_run=?, next_run=? WHERE id=?", (now, next_t, s["id"]))
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(30)


@app.on_event("startup")
def _startup():
    db.init()
    auth.bootstrap_admin()
    threading.Thread(target=_scheduler_loop, daemon=True).start()


class LoginReq(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(req: LoginReq, response: FastAPIResponse):
    user = auth.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(401, "Nieprawidłowy login lub hasło.")
    auth.set_session_cookie(response, auth.create_session(user["id"]))
    return {"username": user["username"], "role": user["role"]}


@app.post("/api/logout")
def logout(response: FastAPIResponse, asi_session: str | None = Cookie(default=None)):
    if asi_session:
        auth.destroy_session(asi_session)
    auth.clear_session_cookie(response)
    return {"ok": True}


@app.get("/api/me")
def me(user: dict = Depends(auth.current_user_dep)):
    return {"username": user["username"], "role": user["role"]}


class UserCreate(BaseModel):
    username: str
    password: str
    role: str


@app.get("/api/users")
def list_users(user: dict = Depends(auth.require("admin"))):
    with db.conn() as c:
        rows = c.execute("SELECT id, username, role, created FROM users ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user_ep(req: UserCreate, user: dict = Depends(auth.require("admin"))):
    if req.role not in auth.ROLES:
        raise HTTPException(400, f"Rola musi być jedną z: {', '.join(auth.ROLES)}")
    try:
        auth.create_user(req.username, req.password, req.role)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Taki użytkownik już istnieje.")
    return {"ok": True}


@app.delete("/api/users/{uid}")
def delete_user_ep(uid: int, user: dict = Depends(auth.require("admin"))):
    if uid == user["id"]:
        raise HTTPException(400, "Nie możesz usunąć samego siebie.")
    with db.conn() as c:
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
    return {"ok": True}


class SignatureReq(BaseModel):
    name: str
    type: str
    pattern: str
    severity: str = "low"
    title: str = ""
    fix: str = ""
    enabled: bool = True


def _validate_signature(req):
    if req.type not in signatures_mod.TYPES:
        raise HTTPException(400, f"Typ musi być jednym z: {', '.join(signatures_mod.TYPES)}")
    if req.severity not in SEV_ORDER:
        raise HTTPException(400, "Nieprawidłowa waga.")


@app.get("/api/signatures")
def list_signatures(user: dict = Depends(auth.require("read"))):
    return signatures_mod.list_all(enabled_only=False)


@app.post("/api/signatures")
def create_signature(req: SignatureReq, user: dict = Depends(auth.require("add_remove_modify"))):
    _validate_signature(req)
    with db.conn() as c:
        c.execute("INSERT INTO signatures(name,type,pattern,severity,title,fix,enabled) VALUES(?,?,?,?,?,?,?)",
                  (req.name, req.type, req.pattern, req.severity, req.title, req.fix, int(req.enabled)))
    return {"ok": True}


@app.patch("/api/signatures/{sid}")
def update_signature(sid: int, req: SignatureReq, user: dict = Depends(auth.require("read_modify"))):
    _validate_signature(req)
    with db.conn() as c:
        cur = c.execute("UPDATE signatures SET name=?,type=?,pattern=?,severity=?,title=?,fix=?,enabled=? WHERE id=?",
                        (req.name, req.type, req.pattern, req.severity, req.title, req.fix, int(req.enabled), sid))
        if cur.rowcount == 0:
            raise HTTPException(404, "Nie ma takiej sygnatury.")
    return {"ok": True}


@app.delete("/api/signatures/{sid}")
def delete_signature(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    with db.conn() as c:
        c.execute("DELETE FROM signatures WHERE id=?", (sid,))
    return {"ok": True}


class ScanReq(BaseModel):
    target: str | None = None
    targets: list[str] | None = None
    authorized: bool = False
    nuclei: bool = False
    gvm: bool = False
    rate_limit: int | None = None
    time_window_mins: int | None = None


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/tools")
def tools(user: dict = Depends(auth.require("read"))):
    return scanner.tool_status()


def _start_scan(raw_items, opts):
    resolved, errors = targets_mod.expand(raw_items)
    if not resolved:
        detail = "; ".join(f"{r}: {e}" for r, e in errors[:5]) or "Brak celów."
        raise HTTPException(400, f"Brak prawidłowych celów. {detail}")
    display = targets_mod.display_name(raw_items, resolved)
    thash = hashlib.sha256("\n".join(sorted(resolved)).encode()).hexdigest()
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,target_hash,opts,created,hosts_total) VALUES(?,?,?,?,?)",
                        (display, thash, json.dumps(opts), time.time(), len(resolved))).lastrowid
        c.executemany("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)",
                      [(sid, t) for t in resolved])
    threading.Thread(target=scanner.run_scan, args=(sid,), daemon=True).start()
    return sid, errors


def _opts_from(nuclei, gvm, rate_limit, time_window_mins=None):
    opts = {"nuclei": bool(nuclei), "gvm": bool(gvm)}
    if rate_limit:
        rate_limit = int(rate_limit)
        if not (1 <= rate_limit <= 10000):
            raise HTTPException(400, "rate_limit musi być w zakresie 1-10000 pakietów/s.")
        opts["rate_limit"] = rate_limit
    if time_window_mins:
        opts["time_window_mins"] = int(time_window_mins)
    return opts


@app.post("/api/scans")
def create_scan(req: ScanReq, user: dict = Depends(auth.require("add_remove_modify"))):
    if not req.authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na skanowanie tego celu/celów.")
    raw_items = req.targets if req.targets else ([req.target] if req.target else [])
    if not raw_items:
        raise HTTPException(400, "Podaj cel (target) lub listę celów (targets).")
    sid, errors = _start_scan(raw_items, _opts_from(req.nuclei, req.gvm, req.rate_limit, req.time_window_mins))
    resp = {"id": sid}
    if errors:
        resp["warnings"] = [f"{r}: {e}" for r, e in errors[:20]]
    return resp


@app.post("/api/scans/import-targets")
def import_targets(file: UploadFile = File(...), authorized: bool = Form(False),
                   nuclei: bool = Form(False), gvm: bool = Form(False),
                   rate_limit: int | None = Form(None),
                   time_window_mins: int | None = Form(None),
                   user: dict = Depends(auth.require("add_remove_modify"))):
    if not authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na skanowanie tych celów.")
    text = file.file.read().decode("utf-8", "ignore")
    name = (file.filename or "").lower()
    if name.endswith(".json"):
        raw_items = targets_mod.parse_json(text)
    elif name.endswith(".csv"):
        raw_items = targets_mod.parse_csv(text)
    else:
        raw_items = targets_mod.parse_text(text)
    if not raw_items:
        raise HTTPException(400, "Plik nie zawiera żadnych celów.")
    sid, errors = _start_scan(raw_items, _opts_from(nuclei, gvm, rate_limit, time_window_mins))
    resp = {"id": sid}
    if errors:
        resp["warnings"] = [f"{r}: {e}" for r, e in errors[:20]]
    return resp


@app.post("/api/scans/import-results")
def import_results(file: UploadFile = File(...), user: dict = Depends(auth.require("add_remove_modify"))):
    """Import gotowych wyników (nie celów do skanowania) - format symetryczny do
    /api/scans/{id}/export.json. CSV (format export.csv) importuje same findingi,
    bez grafu zasobów. def (nie async def) - patrz komentarz w import_targets()."""
    text = file.file.read().decode("utf-8", "ignore")
    name = (file.filename or "").lower()
    scan_meta, assets, edges, findings = {}, [], [], []
    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"Nieprawidłowy JSON: {e}")
        scan_meta = data.get("scan") or {}
        assets = [a for a in (data.get("assets") or []) if a.get("id") and a.get("kind") and "value" in a]
        edges = [e for e in (data.get("edges") or []) if e.get("src") and e.get("dst")]
        findings = data.get("findings") or []
    elif name.endswith(".csv"):
        findings = list(csv.DictReader(io.StringIO(text)))
    else:
        raise HTTPException(400, "Obsługiwane formaty pliku: .json, .csv")
    if not assets and not findings:
        raise HTTPException(400, "Plik nie zawiera żadnych wyników do zaimportowania.")

    target = str(scan_meta.get("target") or file.filename or "zaimportowany skan")[:500]
    now = time.time()
    with db.conn() as c:
        sid = c.execute(
            "INSERT INTO scans(target,target_hash,opts,status,stage,score,hosts_total,hosts_done,"
            "created,finished,log) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            # target_hash NIE jest brany z pliku (mógłby podszyć się pod realny cel i zatruć
            # baseline diffowania) - własna przestrzeń nazw, strukturalnie nigdy nie koliduje
            # z hashem liczonym w _start_scan (tam to zawsze surowy hex bez prefiksu).
            (target, "import:" + hashlib.sha256(target.encode()).hexdigest(), "{}", "done", "zaimportowany",
             int(scan_meta.get("score") or 0), len(assets), len(assets), now, now, crypto.enc(""))).lastrowid
        c.execute("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)", (sid, target))
        for a in assets:
            c.execute("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                      (sid, a["id"], a["kind"], a["value"], crypto.enc(json.dumps(a.get("data") or {}))))
        for e in edges:
            c.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?)", (sid, e["src"], e["dst"]))
        n = 0
        for f in findings:
            sev = f.get("severity") or "info"
            if sev not in SEV_ORDER:
                sev = "info"
            asset = str(f.get("asset") or f"scan:{sid}")
            title = str(f.get("title") or "?")[:200]
            if not asset.strip() or not title.strip("?"):
                continue
            c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                      (sid, asset, sev, title, str(f.get("source") or "import"),
                       crypto.enc(str(f.get("detail") or "")[:1000]), str(f.get("fix") or "")))
            n += 1
        if not assets:
            c.execute("UPDATE scans SET score=? WHERE id=?",
                      (scanner.risk_score([f.get("severity", "info") for f in findings]), sid))
    return {"id": sid, "assets": len(assets), "findings": n}


@app.get("/api/scans")
def list_scans(user: dict = Depends(auth.require("read"))):
    with db.conn() as c:
        rows = c.execute("SELECT s.id,s.target,s.status,s.stage,s.score,s.created,s.finished,"
                         "s.hosts_total,s.hosts_done,s.duration_s,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s ORDER BY s.id DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scans/{sid}/targets")
def scan_targets(sid: int, user: dict = Depends(auth.require("read"))):
    with db.conn() as c:
        rows = c.execute("SELECT target FROM scan_targets WHERE scan_id=? ORDER BY target", (sid,)).fetchall()
    return [r["target"] for r in rows]


def _load(sid):
    with db.conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Nie ma takiego skanu")
        assets = [dict(r, data=json.loads(crypto.dec(r["data"]))) for r in
                  c.execute("SELECT id,kind,value,data FROM assets WHERE scan_id=?", (sid,))]
        edges = [dict(r) for r in c.execute("SELECT src,dst FROM edges WHERE scan_id=?", (sid,))]
        findings = [dict(r) for r in c.execute("SELECT rowid, * FROM findings WHERE scan_id=?", (sid,))]
    for f in findings:
        f["detail"] = crypto.dec(f["detail"])
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    s = dict(s)
    s["log"] = crypto.dec(s["log"])
    return s, assets, edges, findings


def _diff(sid, target_hash, assets, findings):
    if not target_hash:
        return None
    with db.conn() as c:
        hist = c.execute("SELECT id FROM scans WHERE target_hash=? AND status='done' "
                         "AND stage!='zaimportowany' AND id<? "
                         "ORDER BY id DESC LIMIT 4", (target_hash, sid)).fetchall()
    if not hist:
        return None
    prev_id = hist[0]["id"]
    _, passets, _, pfind = _load(prev_id)
    cur, old = {a["id"] for a in assets}, {a["id"] for a in passets}
    cf = {(f["asset"], f["title"]) for f in findings}
    of = {(f["asset"], f["title"]) for f in pfind}

    # Analiza flappingu i stabilności hostów (Kryterium AGH: dany adres może odpowiadać lub nie zależnie od pory)
    flapping = []
    hist_sets = []
    if len(hist) > 1:
        for h in hist[1:]:
            try:
                _, ha, _, _ = _load(h["id"])
                hist_sets.append({a["id"] for a in ha})
            except Exception:
                pass
        for aid in cur:
            if aid not in old and any(aid in hs for hs in hist_sets):
                flapping.append(aid)
            elif aid in old and any(aid not in hs for hs in hist_sets):
                flapping.append(aid)

    # Potwierdzony brak odpowiedzi po sukcesywnych skanach (specyfikacja AGH)
    confirmed_offline = []
    missing_from_cur = old - cur
    if len(hist_sets) >= 2 and missing_from_cur:
        for aid in missing_from_cur:
            if all(aid not in hs for hs in hist_sets[:2]):
                confirmed_offline.append(aid)

    return {
        "against": prev_id,
        "new_assets": sorted(cur - old),
        "removed_assets": sorted(old - cur),
        "flapping_assets": sorted(set(flapping)),
        "confirmed_offline": sorted(set(confirmed_offline)),
        "new_findings": [{"asset": a, "title": t} for a, t in sorted(cf - of)],
        "resolved_findings": [{"asset": a, "title": t} for a, t in sorted(of - cf)]
    }


class FindingEdit(BaseModel):
    fix: str | None = None
    severity: str | None = None
    false_positive: bool | None = None
    persist_future: bool = True


@app.patch("/api/findings/{rowid}")
def edit_finding(rowid: int, req: FindingEdit, user: dict = Depends(auth.require("read_modify"))):
    """Edycja ustalenia niezależna od stanu skanu (pkt 14 specyfikacji) oraz trwały triage
    zachowywany przy kolejnych skanach w finding_overrides."""
    with db.conn() as c:
        row = c.execute("SELECT scan_id, asset, title, severity, fix FROM findings WHERE rowid=?", (rowid,)).fetchone()
        if not row:
            raise HTTPException(404, "Nie ma takiego ustalenia.")
        sev = req.severity or row["severity"]
        if sev not in SEV_ORDER:
            raise HTTPException(400, "Nieprawidłowa waga.")
        fix = req.fix if req.fix is not None else row["fix"]
        title = row["title"]
        if req.false_positive:
            sev = "info"
            if not title.startswith("[False Positive] "):
                title = f"[False Positive] {title}"
        elif req.false_positive is False and title.startswith("[False Positive] "):
            title = title.replace("[False Positive] ", "")

        c.execute("UPDATE findings SET severity=?, fix=?, title=? WHERE rowid=?", (sev, fix, title, rowid))
        if req.persist_future:
            c.execute(
                "INSERT OR REPLACE INTO finding_overrides(asset, title, severity, fix, false_positive, updated) "
                "VALUES(?,?,?,?,?,?)",
                (row["asset"], row["title"].replace("[False Positive] ", ""), sev, fix, 1 if req.false_positive else 0, time.time()))
    return {"ok": True}


@app.get("/api/scans/{sid}")
def get_scan(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, edges, findings = _load(sid)
    s["log"] = "".join(s["log"].splitlines(True)[-400:])
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    live_score = scanner.risk_score([f["severity"] for f in findings])
    s["score"] = s["score"] if s["status"] == "done" else live_score
    return {"scan": s, "assets": assets, "edges": edges, "findings": findings, "counts": counts,
            "diff": _diff(sid, s["target_hash"], assets, findings) if s["status"] == "done" else None}


@app.delete("/api/scans/{sid}")
def delete_scan(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    _load(sid)
    with db.conn() as c:
        if c.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()["status"] in ("queued", "running"):
            raise HTTPException(409, "Skan jeszcze trwa")
        for t in ("assets", "edges", "findings", "scan_targets"):
            c.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
        c.execute("DELETE FROM scans WHERE id=?", (sid,))
    return {"ok": True}


@app.get("/api/scans/{sid}/export.json")
def export_json(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, edges, findings = _load(sid)
    s.pop("log")
    return JSONResponse({"scan": s, "assets": assets, "edges": edges, "findings": findings},
                        headers={"Content-Disposition": f'attachment; filename="asi-scan-{sid}.json"'})


@app.get("/api/scans/{sid}/export.csv")
def export_csv(sid: int, user: dict = Depends(auth.require("read"))):
    _, _, _, findings = _load(sid)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "title", "asset", "detail", "fix", "source"])
    for f in findings:
        # ochrona przed CSV injection (dane pochodzą ze skanowanych hostów)
        w.writerow([("'" + str(f[k])) if str(f[k])[:1] in "=+-@\t\r" and f[k] else f[k]
                    for k in ("severity", "title", "asset", "detail", "fix", "source")])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="asi-findings-{sid}.csv"'})


@app.post("/api/scans/{sid}/defectdojo")
def export_defectdojo(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    if not defectdojo.configured():
        raise HTTPException(400, "DefectDojo nieskonfigurowany (ASI_DEFECTDOJO_URL / ASI_DEFECTDOJO_API_KEY).")
    s, _, _, findings = _load(sid)
    if not findings:
        raise HTTPException(400, "Brak ustaleń do eksportu.")
    try:
        result = defectdojo.export_scan(s["target"], findings)
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return {"ok": True, "defectdojo": result}


@app.get("/api/scans/{sid}/report", response_class=HTMLResponse)
def report(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, _, findings = _load(sid)
    e = html.escape
    rows = "".join(f"<tr><td>{e(f['severity'])}</td><td>{e(f['title'])}</td><td>{e(f['asset'])}</td>"
                   f"<td>{e(f['fix'])}</td></tr>" for f in findings)
    return (f"<!doctype html><meta charset=utf-8><title>Raport ASI #{sid}</title>"
            "<style>body{font:14px sans-serif;margin:2rem}td,th{border:1px solid #bbb;padding:4px 8px;"
            "text-align:left}table{border-collapse:collapse}</style>"
            f"<h1>Raport powierzchni ataku: {e(s['target'])}</h1>"
            f"<p>Wynik ryzyka: <b>{s['score']}/100</b> · zasobów: {len(assets)} · ustaleń: {len(findings)}</p>"
            f"<table><tr><th>Waga</th><th>Ustalenie</th><th>Zasób</th><th>Zalecenie</th></tr>{rows}</table>")


class DefectDojoSettingsReq(BaseModel):
    url: str
    api_key: str


@app.get("/api/settings")
def get_settings(user: dict = Depends(auth.require("read"))):
    dd_url, dd_key = defectdojo.get_config()
    return {
        "defectdojo_url": dd_url or "",
        "defectdojo_configured": bool(dd_url and dd_key),
        "openvas_configured": scanner.tool_status().get("openvas", {}).get("installed", False)
    }


@app.post("/api/settings/defectdojo")
def save_defectdojo_settings(req: DefectDojoSettingsReq, user: dict = Depends(auth.require("add_remove_modify"))):
    with db.conn() as c:
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('defectdojo_url', ?)", (req.url.strip(),))
        c.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('defectdojo_api_key', ?)", (req.api_key.strip(),))
    return {"ok": True}


class ScheduleReq(BaseModel):
    target: str
    interval_hours: int = 24
    time_window_mins: int = 60
    nuclei: bool = False
    gvm: bool = False
    rate_limit: int | None = None


@app.get("/api/schedules")
def list_schedules(user: dict = Depends(auth.require("read"))):
    with db.conn() as c:
        rows = c.execute("SELECT id, target, opts, interval_hours, time_window_mins, last_run, next_run, enabled FROM schedules ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/schedules")
def create_schedule(req: ScheduleReq, user: dict = Depends(auth.require("add_remove_modify"))):
    opts = _opts_from(req.nuclei, req.gvm, req.rate_limit, req.time_window_mins)
    now = time.time()
    next_run = now + max(1, req.interval_hours) * 3600
    with db.conn() as c:
        sid = c.execute(
            "INSERT INTO schedules(target, opts, interval_hours, time_window_mins, next_run, enabled) "
            "VALUES(?,?,?,?,?,1)",
            (req.target.strip(), json.dumps(opts), req.interval_hours, req.time_window_mins, next_run)).lastrowid
    return {"id": sid}


@app.delete("/api/schedules/{sid}")
def delete_schedule(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    with db.conn() as c:
        c.execute("DELETE FROM schedules WHERE id=?", (sid,))
    return {"ok": True}

