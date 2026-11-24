"""Edycja ustaleń i triage - decyzje operatora, które przetrwają kolejne skany."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth, findings

router = APIRouter(tags=["findings"])


class FindingEdit(BaseModel):
    fix: str | None = None
    severity: str | None = None
    false_positive: bool | None = None
    persist_future: bool = True


class TriageReq(BaseModel):
    asset: str
    key: str
    status: str
    note: str = ""
    finding_rowid: int | None = None


@router.patch("/findings/{rowid}")
def edit_finding(rowid: int, req: FindingEdit, user: dict = Depends(auth.require("read_modify"))):
    findings.edit(rowid, req.fix, req.severity, req.false_positive, req.persist_future)
    return {"ok": True}


@router.post("/triage")
def set_triage(req: TriageReq, user: dict = Depends(auth.require("read_modify"))):
    findings.triage(req.asset, req.key, req.status, req.note, user["username"], req.finding_rowid)
    return {"ok": True}
