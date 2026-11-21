"""API + serwowanie UI. Start: uvicorn asi.main:app --host 127.0.0.1 --port 8000"""
import csv
import html
import io
import os
import time

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, scanner, scheduler, settings, store

app = FastAPI(title="Attack Surface Intelligence PoC")
STATIC = os.path.join(db.ROOT, "static")
SEV_ORDER = store.SEV_ORDER


@app.on_event("startup")
def _startup():
    db.init()
    scheduler.start()


class ScanReq(BaseModel):
    target: str
    authorized: bool = False
    nuclei: bool = False
    deep: bool = False


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


# zbudowany frontend (React/Vite, patrz frontend/) - zasoby pod /static/assets
app.mount("/static", StaticFiles(directory=STATIC), name="static")


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
    sid = scanner.start_scan(target, {"nuclei": req.nuclei, "deep": req.deep})
    return {"id": sid}


@app.get("/api/scans")
def list_scans():
    with db.conn() as c:
        rows = c.execute("SELECT s.id,s.target,s.status,s.stage,s.score,s.created,s.finished,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s ORDER BY s.id DESC LIMIT 50").fetchall()
    return [dict(r) for r in rows]


def _load(sid):
    r = store.load(sid)
    if not r:
        raise HTTPException(404, "Nie ma takiego skanu")
    return r


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
            "diff": store.diff(sid, s["target"], assets, findings) if s["status"] == "done" else None,
            "trend": store.trend(s["target"], sid) if s["status"] == "done" else []}


# ---------- harmonogramy (automatyczny monitoring) ----------
class ScheduleReq(BaseModel):
    target: str
    authorized: bool = False
    nuclei: bool = False
    deep: bool = False
    interval_hours: int = 168


class SchedulePatch(BaseModel):
    enabled: bool


@app.get("/api/schedules")
def list_schedules():
    with db.conn() as c:
        rows = c.execute(
            "SELECT h.*, (SELECT id FROM scans s WHERE s.target=h.target AND s.status='done' ORDER BY id DESC LIMIT 1) AS last_scan,"
            "(SELECT score FROM scans s WHERE s.target=h.target AND s.status='done' ORDER BY id DESC LIMIT 1) AS last_score "
            "FROM schedules h ORDER BY h.id DESC").fetchall()
    return {"intervals": scheduler.INTERVALS, "items": [dict(r) for r in rows]}


@app.post("/api/schedules")
def create_schedule(req: ScheduleReq):
    if not req.authorized:
        raise HTTPException(400, "Potwierdź, że masz zgodę na cykliczne sprawdzanie tego celu.")
    if req.interval_hours not in scheduler.INTERVALS:
        raise HTTPException(400, "Niedozwolony odstęp czasu.")
    try:
        target = scanner.normalize_target(req.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    now = time.time()
    with db.conn() as c:
        if c.execute("SELECT 1 FROM schedules WHERE target=?", (target,)).fetchone():
            raise HTTPException(409, "Ta strona jest już objęta automatycznym sprawdzaniem.")
        hid = c.execute("INSERT INTO schedules(target,nuclei,deep,interval_hours,created,last_run,next_run) VALUES(?,?,?,?,?,?,?)",
                        (target, int(req.nuclei), int(req.deep), req.interval_hours, now, now,
                         now + req.interval_hours * 3600)).lastrowid
    sid = scanner.start_scan(target, {"nuclei": req.nuclei, "deep": req.deep, "schedule_id": hid})  # pierwszy skan od razu
    return {"id": hid, "scan_id": sid}


@app.patch("/api/schedules/{hid}")
def patch_schedule(hid: int, req: SchedulePatch):
    with db.conn() as c:
        if not c.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(req.enabled), hid)).rowcount:
            raise HTTPException(404, "Nie ma takiego harmonogramu")
    return {"ok": True}


@app.delete("/api/schedules/{hid}")
def delete_schedule(hid: int):
    with db.conn() as c:
        if not c.execute("DELETE FROM schedules WHERE id=?", (hid,)).rowcount:
            raise HTTPException(404, "Nie ma takiego harmonogramu")
    return {"ok": True}


# ---------- ustawienia i klucze API (wartości nigdy nie wracają do przeglądarki) ----------
class SettingReq(BaseModel):
    value: str


@app.get("/api/settings")
def get_settings():
    return settings.status()


@app.put("/api/settings/{key}")
def put_setting(key: str, req: SettingReq):
    try:
        settings.put(key, req.value)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.delete("/api/settings/{key}")
def delete_setting(key: str):
    if key not in settings.KEYS:
        raise HTTPException(404, "Nieznane ustawienie.")
    settings.delete(key)
    return {"ok": True}


# ---------- alerty ----------
@app.get("/api/alerts")
def list_alerts():
    with db.conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 30").fetchall()
        unread = c.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0]
    return {"unread": unread, "items": [dict(r) for r in rows]}


@app.post("/api/alerts/read")
def read_alerts():
    with db.conn() as c:
        c.execute("UPDATE alerts SET read=1 WHERE read=0")
    return {"ok": True}


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


SEV_PL = {"critical": "Krytyczne", "high": "Wysokie", "medium": "Średnie", "low": "Niskie", "info": "Informacja"}
SEV_WHEN = {"critical": "napraw natychmiast", "high": "napraw w tym tygodniu", "medium": "zaplanuj naprawę",
            "low": "popraw przy okazji", "info": "do wiadomości"}
REPORT_CSS = ("body{font:16px/1.55 'Segoe UI',Arial,sans-serif;color:#17202e;max-width:52rem;margin:2rem auto;padding:0 1rem}"
              "h1{font-size:1.6rem;margin:0 0 .3rem}h2{font-size:1.2rem;margin:1.8rem 0 .5rem}"
              ".meta{color:#44505f;margin:0 0 1rem}.box{border:2px solid;border-radius:6px;padding:1rem 1.2rem;margin:1rem 0}"
              ".bad{background:#fdecec;border-color:#b3202a}.warn{background:#fff3d1;border-color:#a56a00}"
              ".good{background:#e7f4ea;border-color:#1e7b3c}.box b.t{font-size:1.25rem;display:block}"
              ".f{border:1px solid #c6cdd8;border-radius:6px;padding:.8rem 1rem;margin:.7rem 0;break-inside:avoid}"
              ".f h3{margin:0 0 .3rem;font-size:1.05rem}.tag{display:inline-block;font-weight:700;font-size:.8rem;"
              "padding:.1rem .5rem;border-radius:4px;background:#17202e;color:#fff;margin-right:.5rem}"
              ".f p{margin:.2rem 0}.f .k{font-weight:700}code{font:.85rem Consolas,monospace;word-break:break-all}"
              "button{font:inherit;font-weight:600;padding:.6rem 1.2rem;border:2px solid #0b4f9e;background:#0b4f9e;"
              "color:#fff;border-radius:6px;cursor:pointer}@media print{button{display:none}body{margin:0}}")


@app.get("/api/scans/{sid}/report", response_class=HTMLResponse)
def report(sid: int):
    s, assets, _, findings = _load(sid)
    e = html.escape
    sc = s["score"] or 0
    crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
    if sc >= 60 or any(f["severity"] == "critical" for f in findings):
        tone, head, text = "bad", "Wymaga pilnej uwagi", "Znaleziono poważne problemy. Przekaż ten raport informatykowi jeszcze dziś."
    elif sc >= 30 or crit:
        tone, head, text = "warn", "Wymaga poprawek", "Znaleziono problemy, które warto naprawić w najbliższym czasie."
    else:
        tone, head, text = ("good", "Nie znaleziono poważnych problemów",
                            "To nie zastępuje pełnego audytu bezpieczeństwa.")
    when = time.strftime("%d.%m.%Y %H:%M", time.localtime(s["created"])) if s.get("created") else ""
    items = "".join(
        f"<div class=f><h3><span class=tag>{e(SEV_PL.get(f['severity'], f['severity']))}</span>{e(f['title'])}</h3>"
        f"<p><span class=k>Dotyczy:</span> <code>{e(f['asset'])}</code></p>"
        + (f"<p><span class=k>Co zrobić:</span> {e(f['fix'])}</p>" if f["fix"] else "")
        + f"<p><span class=k>Termin:</span> {e(SEV_WHEN.get(f['severity'], ''))}</p></div>"
        for f in findings) or "<p>Nie znaleziono żadnych uwag.</p>"
    return (f"<!doctype html><html lang=pl><meta charset=utf-8><title>Raport z sprawdzenia: {e(s['target'])}</title>"
            f"<style>{REPORT_CSS}</style>"
            f"<p><button onclick=print()>Drukuj lub zapisz jako PDF</button></p>"
            f"<h1>Raport z sprawdzenia bezpieczeństwa strony</h1>"
            f"<p class=meta>Strona: <b>{e(s['target'])}</b> · sprawdzenie nr {sid} · {e(when)}</p>"
            f"<div class='box {tone}'><b class=t>{head}</b>{text}<br>Ocena ryzyka: <b>{sc} na 100</b> "
            f"(im niżej, tym lepiej) · uwag: <b>{len(findings)}</b> · w tym pilnych: <b>{crit}</b></div>"
            f"<h2>Co należy naprawić</h2>{items}"
            f"<h2>O tym raporcie</h2><p>Raport obejmuje wyłącznie to, co jest widoczne z internetu "
            f"({len(assets)} wykrytych elementów). Program niczego nie zmienia na sprawdzanej stronie. "
            f"Wynik nie zastępuje audytu bezpieczeństwa.</p>")
