"""API + serwowanie UI. Start: uvicorn asi.main:app --host 127.0.0.1 --port 8000"""
import csv
import html
import io
import json
import os
import threading
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from . import db, scanner

app = FastAPI(title="Attack Surface Intelligence PoC")
STATIC = os.path.join(db.ROOT, "static")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@app.on_event("startup")
def _startup():
    db.init()


class ScanReq(BaseModel):
    target: str
    authorized: bool = False
    nuclei: bool = False


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/api/tools")
def tools():
    return scanner.tool_status()


@app.post("/api/scans")
def create_scan(req: ScanReq):
    if not req.authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na skanowanie tego celu.")
    try:
        target = scanner.normalize_target(req.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,opts,created) VALUES(?,?,?)",
                        (target, json.dumps({"nuclei": req.nuclei}), time.time())).lastrowid
    threading.Thread(target=scanner.run_scan, args=(sid,), daemon=True).start()
    return {"id": sid}


@app.get("/api/scans")
def list_scans():
    with db.conn() as c:
        rows = c.execute("SELECT s.id,s.target,s.status,s.stage,s.score,s.created,s.finished,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s ORDER BY s.id DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


def _load(sid):
    with db.conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Nie ma takiego skanu")
        assets = [dict(r, data=json.loads(r["data"])) for r in
                  c.execute("SELECT id,kind,value,data FROM assets WHERE scan_id=?", (sid,))]
        edges = [dict(r) for r in c.execute("SELECT src,dst FROM edges WHERE scan_id=?", (sid,))]
        findings = [dict(r) for r in c.execute("SELECT * FROM findings WHERE scan_id=?", (sid,))]
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
    return dict(s), assets, edges, findings


def _diff(sid, target, assets, findings):
    with db.conn() as c:
        prev = c.execute("SELECT id FROM scans WHERE target=? AND status='done' AND id<? "
                         "ORDER BY id DESC LIMIT 1", (target, sid)).fetchone()
    if not prev:
        return None
    _, passets, _, pfind = _load(prev["id"])
    cur, old = {a["id"] for a in assets}, {a["id"] for a in passets}
    cf = {(f["asset"], f["title"]) for f in findings}
    of = {(f["asset"], f["title"]) for f in pfind}
    return {"against": prev["id"], "new_assets": sorted(cur - old), "removed_assets": sorted(old - cur),
            "new_findings": [{"asset": a, "title": t} for a, t in sorted(cf - of)],
            "resolved_findings": [{"asset": a, "title": t} for a, t in sorted(of - cf)]}


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    s, assets, edges, findings = _load(sid)
    s["log"] = "".join(s["log"].splitlines(True)[-400:])
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    live_score = scanner.risk_score([f["severity"] for f in findings])
    s["score"] = s["score"] if s["status"] == "done" else live_score
    return {"scan": s, "assets": assets, "edges": edges, "findings": findings, "counts": counts,
            "diff": _diff(sid, s["target"], assets, findings) if s["status"] == "done" else None}


@app.delete("/api/scans/{sid}")
def delete_scan(sid: int):
    _load(sid)
    with db.conn() as c:
        if c.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()["status"] in ("queued", "running"):
            raise HTTPException(409, "Skan jeszcze trwa")
        for t in ("assets", "edges", "findings"):
            c.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
        c.execute("DELETE FROM scans WHERE id=?", (sid,))
    return {"ok": True}


@app.get("/api/scans/{sid}/export.json")
def export_json(sid: int):
    s, assets, edges, findings = _load(sid)
    s.pop("log")
    return JSONResponse({"scan": s, "assets": assets, "edges": edges, "findings": findings},
                        headers={"Content-Disposition": f'attachment; filename="asi-scan-{sid}.json"'})


@app.get("/api/scans/{sid}/export.csv")
def export_csv(sid: int):
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
def report(sid: int):
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
