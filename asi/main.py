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

from . import auth, crypto, db, scanner
from . import targets as targets_mod

app = FastAPI(title="Attack Surface Intelligence PoC")
STATIC = os.path.join(db.ROOT, "static")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@app.on_event("startup")
def _startup():
    db.init()
    auth.bootstrap_admin()


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


class ScanReq(BaseModel):
    target: str | None = None
    targets: list[str] | None = None
    authorized: bool = False
    nuclei: bool = False
    gvm: bool = False
    rate_limit: int | None = None


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


def _opts_from(nuclei, gvm, rate_limit):
    opts = {"nuclei": bool(nuclei), "gvm": bool(gvm)}
    if rate_limit:
        opts["rate_limit"] = int(rate_limit)
    return opts


@app.post("/api/scans")
def create_scan(req: ScanReq, user: dict = Depends(auth.require("add_remove_modify"))):
    if not req.authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na skanowanie tego celu/celów.")
    raw_items = req.targets if req.targets else ([req.target] if req.target else [])
    if not raw_items:
        raise HTTPException(400, "Podaj cel (target) lub listę celów (targets).")
    sid, errors = _start_scan(raw_items, _opts_from(req.nuclei, req.gvm, req.rate_limit))
    resp = {"id": sid}
    if errors:
        resp["warnings"] = [f"{r}: {e}" for r, e in errors[:20]]
    return resp


@app.post("/api/scans/import-targets")
async def import_targets(file: UploadFile = File(...), authorized: bool = Form(False),
                         nuclei: bool = Form(False), gvm: bool = Form(False),
                         rate_limit: int | None = Form(None),
                         user: dict = Depends(auth.require("add_remove_modify"))):
    if not authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na skanowanie tych celów.")
    text = (await file.read()).decode("utf-8", "ignore")
    name = (file.filename or "").lower()
    if name.endswith(".json"):
        raw_items = targets_mod.parse_json(text)
    elif name.endswith(".csv"):
        raw_items = targets_mod.parse_csv(text)
    else:
        raw_items = targets_mod.parse_text(text)
    if not raw_items:
        raise HTTPException(400, "Plik nie zawiera żadnych celów.")
    sid, errors = _start_scan(raw_items, _opts_from(nuclei, gvm, rate_limit))
    resp = {"id": sid}
    if errors:
        resp["warnings"] = [f"{r}: {e}" for r, e in errors[:20]]
    return resp


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
        prev = c.execute("SELECT id FROM scans WHERE target_hash=? AND status='done' AND id<? "
                         "ORDER BY id DESC LIMIT 1", (target_hash, sid)).fetchone()
    if not prev:
        return None
    _, passets, _, pfind = _load(prev["id"])
    cur, old = {a["id"] for a in assets}, {a["id"] for a in passets}
    cf = {(f["asset"], f["title"]) for f in findings}
    of = {(f["asset"], f["title"]) for f in pfind}
    return {"against": prev["id"], "new_assets": sorted(cur - old), "removed_assets": sorted(old - cur),
            "new_findings": [{"asset": a, "title": t} for a, t in sorted(cf - of)],
            "resolved_findings": [{"asset": a, "title": t} for a, t in sorted(of - cf)]}


class FindingEdit(BaseModel):
    fix: str | None = None
    severity: str | None = None


@app.patch("/api/findings/{rowid}")
def edit_finding(rowid: int, req: FindingEdit, user: dict = Depends(auth.require("read_modify"))):
    """Edycja ustalenia niezależna od stanu skanu (pkt 14 specyfikacji) - zmiana zostaje
    w tym samym wierszu, więc przetrwa do kolejnych odczytów tego skanu."""
    fields, vals = [], []
    if req.fix is not None:
        fields.append("fix=?")
        vals.append(req.fix)
    if req.severity is not None:
        if req.severity not in SEV_ORDER:
            raise HTTPException(400, "Nieprawidłowa waga.")
        fields.append("severity=?")
        vals.append(req.severity)
    if not fields:
        raise HTTPException(400, "Brak pól do edycji.")
    vals.append(rowid)
    with db.conn() as c:
        cur = c.execute(f"UPDATE findings SET {','.join(fields)} WHERE rowid=?", vals)
        if cur.rowcount == 0:
            raise HTTPException(404, "Nie ma takiego ustalenia.")
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
