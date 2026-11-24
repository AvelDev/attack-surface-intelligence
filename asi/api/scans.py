"""Skany: uruchamianie (formularz, import celów), odczyt, eksporty, zatrzymanie i wznowienie, import wyników."""
import json

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .. import auth, config, domain, findings, geo, history, importer, report, targets
from ..errors import Conflict, InvalidInput, NotFound
from ..nmap import options as nmap_options
from ..nmap import parser as nmap_parser
from ..nmap import policy
from ..repo import scans as repo
from ..scan import nmap_scan, runner

router = APIRouter(tags=["scans"])
LOG_TAIL_LINES = 400
MAX_RATE = 10000


class ScanReq(BaseModel):
    target: str | None = Field(default=None, max_length=300)
    targets: list[str] | None = None
    authorized: bool = False
    nuclei: bool = False
    deep: bool = False
    intel: bool = False
    gvm: bool = False
    rate_limit: int | None = None
    time_window_mins: int | None = None
    nmap: dict | None = None


def require_authorization(authorized, message):
    if not authorized:
        raise InvalidInput(message)


def scan_options(user, nuclei=False, gvm=False, rate_limit=None, time_window_mins=None, deep=False, intel=False, nmap=None):
    opts = {"nuclei": bool(nuclei), "gvm": bool(gvm), "deep": bool(deep), "intel": bool(intel)}
    if rate_limit:
        if not 1 <= int(rate_limit) <= MAX_RATE:
            raise InvalidInput(f"rate_limit musi być w zakresie 1-{MAX_RATE} pakietów/s.")
        opts["rate_limit"] = int(rate_limit)
    if time_window_mins:
        opts["time_window_mins"] = int(time_window_mins)
    if nmap:
        opts["nmap"] = nmap_options.dump(authorized_nmap(nmap, user, opts))
    return opts


def authorized_nmap(raw, user, opts):
    """Opcje nmap po walidacji i sprawdzeniu, czy ta rola może uruchomić wybrane skrypty na tym serwerze."""
    parsed = nmap_options.parse(raw)
    policy.check(parsed, gated=config.load().nmap_intrusive and user["role"] == "admin", external=nmap_scan.external_allowed(opts))
    return parsed


def _started(raw_items, opts):
    sid, errors = runner.start_scan(raw_items, opts)
    resp = {"id": sid}
    if errors:
        resp["warnings"] = [f"{r}: {e}" for r, e in errors[:20]]
    return resp


@router.post("/scans")
def create_scan(req: ScanReq, user: dict = Depends(auth.require("add_remove_modify"))):
    require_authorization(req.authorized, "Potwierdź, że masz zgodę na skanowanie tego celu/celów.")
    raw_items = req.targets if req.targets else ([req.target] if req.target else [])
    if not raw_items:
        raise InvalidInput("Podaj cel (target) lub listę celów (targets).")
    return _started(raw_items, scan_options(user, req.nuclei, req.gvm, req.rate_limit, req.time_window_mins, req.deep, req.intel, req.nmap))


@router.post("/scans/import-targets")
def import_targets(file: UploadFile = File(...), authorized: bool = Form(False), nuclei: bool = Form(False),
                   gvm: bool = Form(False), deep: bool = Form(False), intel: bool = Form(False),
                   rate_limit: int | None = Form(None), time_window_mins: int | None = Form(None), nmap: str = Form(""),
                   user: dict = Depends(auth.require("add_remove_modify"))):
    # def (nie async def): FastAPI uruchamia ją w puli wątków, więc odczyt pliku nie blokuje pętli zdarzeń.
    require_authorization(authorized, "Potwierdź, że masz zgodę na skanowanie tych celów.")
    text = file.file.read().decode("utf-8", "ignore")
    name = (file.filename or "").lower()
    parse = targets.parse_json if name.endswith(".json") else targets.parse_csv if name.endswith(".csv") else targets.parse_text
    raw_items = parse(text)
    if not raw_items:
        raise InvalidInput("Plik nie zawiera żadnych celów.")
    try:
        nmap_opts = json.loads(nmap) if nmap else None
    except json.JSONDecodeError as e:
        raise InvalidInput("Opcje nmap: nieprawidłowy JSON.") from e
    return _started(raw_items, scan_options(user, nuclei, gvm, rate_limit, time_window_mins, deep, intel, nmap_opts))


@router.post("/scans/import-results")
def import_results(file: UploadFile = File(...), user: dict = Depends(auth.require("add_remove_modify"))):
    return importer.import_results(file.file.read().decode("utf-8", "ignore"), file.filename)


@router.get("/scans")
def list_scans(user: dict = Depends(auth.require("read"))):
    return repo.list_recent()


@router.get("/scans/{sid}/targets")
def scan_targets(sid: int, user: dict = Depends(auth.require("read"))):
    return repo.targets_of(sid)


@router.get("/scans/{sid}")
def get_scan(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, edges, items = history.load(sid)
    s["log"] = "".join(s["log"].splitlines(True)[-LOG_TAIL_LINES:])
    done = s["status"] == "done"
    if not done:  # w trakcie skanu ocena rośnie na żywo
        s["score"] = domain.risk_score([f["severity"] for f in items], sum(1 for a in assets if a["kind"] == "ip"))
    return {"scan": s, "assets": assets, "edges": edges, "findings": items,
            "counts": domain.count_by_severity(items),
            "diff": history.diff(sid, s["target_hash"], assets, items) if done else None,
            "trend": history.trend(s["target_hash"], sid) if done else []}


@router.get("/scans/{sid}/geo")
def get_scan_geo(sid: int, user: dict = Depends(auth.require("read"))):
    """Geolokalizacja dla mapy 3D Command Center - osobny endpoint, bo lookupy IP (sieciowe dla publicznych adresów)
    nie mogą obciążać głównego pollingu /api/scans/{id} co 2 s, którego używa zwykły dashboard."""
    _, assets, _, items = history.load(sid)
    threat = findings.threat_map(items)
    ips, seen = [], set()
    for a in assets:
        ip_val = a["value"] if a["kind"] == "ip" else (a["value"].split(":")[0] if a["kind"] == "port" else None)
        if ip_val and ip_val not in seen:
            seen.add(ip_val)
            ips.append((a["id"], ip_val))
    geo_map = geo.locate_many([ip for _, ip in ips])  # równolegle, nie sekwencyjnie
    nodes = []
    for aid, ip_val in ips:
        g = geo_map[ip_val]
        nodes.append({"id": aid, "ip": ip_val, "lat": g["lat"], "lon": g["lon"], "country": g["country"], "city": g["city"],
                      "is_hq": g.get("is_hq", False), "severity": threat.get(aid, threat.get(f"ip:{ip_val}", "low"))})
    nodes.append({"id": "scanner:hq", "ip": "127.0.0.1", "lat": geo.HQ_KRAKOW["lat"], "lon": geo.HQ_KRAKOW["lon"],
                  "country": "PL", "city": "CBI AGH (Kraków)", "is_hq": True, "severity": "ok"})
    return {"geo_nodes": nodes}


@router.delete("/scans/{sid}")
def delete_scan(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    s, *_ = history.load(sid)
    if s["status"] in repo.ACTIVE:
        raise Conflict("Skan jeszcze trwa")
    repo.delete(sid)
    return {"ok": True}


@router.get("/scans/{sid}/export.json")
def export_json(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, edges, items = history.load(sid)
    s.pop("log")
    return JSONResponse({"scan": s, "assets": assets, "edges": edges, "findings": items},
                        headers={"Content-Disposition": f'attachment; filename="asi-scan-{sid}.json"'})


@router.get("/scans/{sid}/export.csv")
def export_csv(sid: int, user: dict = Depends(auth.require("read"))):
    *_, items = history.load(sid)
    return Response(report.findings_csv(items), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="asi-findings-{sid}.csv"'})


@router.get("/scans/{sid}/nmap")
def nmap_runs(sid: int, user: dict = Depends(auth.require("read"))):
    """Uruchomienia nmapa w tym skanie (dane hostów są w zasobach skanu)."""
    _existing(sid)
    return {"runs": repo.nmap_runs(sid)}


@router.get("/scans/{sid}/nmap.xml")
def nmap_xml(sid: int, user: dict = Depends(auth.require("read"))):
    """Wynik w formacie nmap -oX, do otwarcia w Zenmapie, ndiff albo imporcie do innych narzędzi."""
    _existing(sid)
    merged = nmap_parser.merge(repo.nmap_xml(sid))
    if merged is None:
        raise NotFound("W tym skanie nmap nie był uruchamiany.")
    return Response(merged, media_type="application/xml", headers={"Content-Disposition": f'attachment; filename="asi-nmap-{sid}.xml"'})


def _existing(sid):
    if repo.status(sid) is None:
        raise NotFound("Nie ma takiego skanu")


@router.get("/scans/{sid}/report", response_class=HTMLResponse)
def html_report(sid: int, user: dict = Depends(auth.require("read"))):
    s, assets, _, items = history.load(sid)
    return report.html_report(s, assets, items)


@router.post("/scans/{sid}/stop")
def stop_scan(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    status = repo.status(sid)
    if status is None:
        raise NotFound("Nie ma takiego skanu")
    if status not in repo.ACTIVE:
        raise Conflict("Skan nie jest w toku.")
    repo.request_stop(sid)
    return {"ok": True}


@router.post("/scans/{sid}/resume")
def resume_scan(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    """Wznawia skan wstrzymany oknem czasowym - dokończenie od punktu kontrolnego, nie nowy przebieg od zera."""
    if repo.status(sid) is None:
        raise NotFound("Nie ma takiego skanu")
    if not runner.resume(sid):
        raise Conflict("Ten skan nie jest wstrzymany oknem czasowym.")
    return {"ok": True}
