from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .. import domain, history, report, targets
from ..errors import Conflict, InvalidInput
from ..repo import scans as repo
from ..scan import runner

router = APIRouter(tags=["scans"])
LOG_TAIL_LINES = 400


class ScanReq(BaseModel):
    target: str = Field(max_length=300)
    authorized: bool = False
    nuclei: bool = False
    deep: bool = False


def require_authorization(authorized, message):
    if not authorized:
        raise InvalidInput(message)


@router.post("/scans")
def create_scan(req: ScanReq):
    require_authorization(req.authorized, "Potwierdź, że masz zgodę na skanowanie tego celu.")
    sid = runner.start_scan(targets.normalize(req.target), {"nuclei": req.nuclei, "deep": req.deep})
    return {"id": sid}


@router.get("/scans")
def list_scans():
    return repo.list_recent()


@router.get("/scans/{sid}")
def get_scan(sid: int):
    s, assets, edges, findings = history.load(sid)
    s["log"] = "".join(s["log"].splitlines(True)[-LOG_TAIL_LINES:])
    done = s["status"] == "done"
    if not done:  # w trakcie skanu ocena rośnie na żywo
        s["score"] = domain.risk_score([f["severity"] for f in findings])
    return {"scan": s, "assets": assets, "edges": edges, "findings": findings,
            "counts": domain.count_by_severity(findings),
            "diff": history.diff(sid, s["target"], assets, findings) if done else None,
            "trend": history.trend(s["target"], sid) if done else []}


@router.delete("/scans/{sid}")
def delete_scan(sid: int):
    s, *_ = history.load(sid)
    if s["status"] in repo.ACTIVE:
        raise Conflict("Skan jeszcze trwa")
    repo.delete(sid)
    return {"ok": True}


@router.get("/scans/{sid}/export.json")
def export_json(sid: int):
    s, assets, edges, findings = history.load(sid)
    s.pop("log")
    return JSONResponse({"scan": s, "assets": assets, "edges": edges, "findings": findings},
                        headers={"Content-Disposition": f'attachment; filename="asi-scan-{sid}.json"'})


@router.get("/scans/{sid}/export.csv")
def export_csv(sid: int):
    *_, findings = history.load(sid)
    return Response(report.findings_csv(findings), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="asi-findings-{sid}.csv"'})


@router.get("/scans/{sid}/report", response_class=HTMLResponse)
def html_report(sid: int):
    s, assets, _, findings = history.load(sid)
    return report.html_report(s, assets, findings)
