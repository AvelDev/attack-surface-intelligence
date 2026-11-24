"""Eksport ustaleń do DefectDojo (cały skan albo zaznaczone obserwacje z dashboardu)."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from .. import auth, defectdojo, history
from ..errors import InvalidInput
from ..repo import findings as findings_repo
from ..repo import scans as scans_repo

router = APIRouter(tags=["defectdojo"])
MAX_SELECTION = 500
NOT_CONFIGURED = "DefectDojo nieskonfigurowany (Ustawienia lub ASI_DEFECTDOJO_URL / ASI_DEFECTDOJO_API_KEY)."


class DojoItem(BaseModel):
    scan_id: int
    asset: str
    kind: str
    title: str
    finding_rowid: int | None = None


class DojoSelection(BaseModel):
    items: list[DojoItem]


def _export(target, items, **kw):
    try:
        return defectdojo.export_scan(target, items, **kw)
    except RuntimeError as e:
        raise HTTPException(502, str(e)) from e  # błąd po stronie DefectDojo, nie nasz i nie klienta


@router.post("/scans/{sid}/defectdojo")
def export_scan(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    if not defectdojo.configured():
        raise InvalidInput(NOT_CONFIGURED)
    s, _, _, items = history.load(sid)
    if not items:
        raise InvalidInput("Brak ustaleń do eksportu.")
    return {"ok": True, "defectdojo": _export(s["target"], items)}


@router.post("/defectdojo/export")
def export_selection(req: DojoSelection, user: dict = Depends(auth.require("add_remove_modify"))):
    """Eksport zaznaczonych obserwacji z dashboardu: ustalenia jak są, zmiany jako ustalenia informacyjne
    (obserwacja jako dowód)."""
    if not defectdojo.configured():
        raise InvalidInput(NOT_CONFIGURED)
    if not req.items or len(req.items) > MAX_SELECTION:
        raise InvalidInput(f"Zaznacz od 1 do {MAX_SELECTION} obserwacji.")
    out, target = [], None
    for it in req.items:
        scan = scans_repo.run_info_or_none(it.scan_id)
        if scan is None:
            continue
        target = target or scan[0]
        if it.finding_rowid is not None:
            f = findings_repo.get(it.finding_rowid, scan_id=it.scan_id)
            if f:
                out.append(f)
            continue
        out.append({"severity": "info", "title": f"[ASI {it.kind}] {it.asset}: {it.title}"[:500],
                    "detail": f"Zmiana wykryta przez ASI w przebiegu #{it.scan_id} ({scan[0]}).", "fix": "", "source": "asi-diff"})
    if not out:
        raise InvalidInput("Żadna z zaznaczonych obserwacji nie istnieje.")
    return {"ok": True, "count": len(out), "defectdojo": _export(target or "ASI", out, engagement_name="ASI - wybrane obserwacje")}
