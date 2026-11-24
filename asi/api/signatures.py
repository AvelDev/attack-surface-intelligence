"""Sygnatury (reguły wykrywania technologii/podatności definiowane przez operatora)."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth, signatures

router = APIRouter(tags=["signatures"])


class SignatureReq(BaseModel):
    name: str
    type: str
    pattern: str
    severity: str = "low"
    title: str = ""
    fix: str = ""
    enabled: bool = True


@router.get("/signatures")
def list_signatures(user: dict = Depends(auth.require("read"))):
    return signatures.list_all(enabled_only=False)


@router.post("/signatures")
def create_signature(req: SignatureReq, user: dict = Depends(auth.require("add_remove_modify"))):
    signatures.create(req.name, req.type, req.pattern, req.severity, req.title, req.fix, req.enabled)
    return {"ok": True}


@router.patch("/signatures/{sid}")
def update_signature(sid: int, req: SignatureReq, user: dict = Depends(auth.require("read_modify"))):
    signatures.update(sid, req.name, req.type, req.pattern, req.severity, req.title, req.fix, req.enabled)
    return {"ok": True}


@router.delete("/signatures/{sid}")
def delete_signature(sid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    signatures.delete(sid)
    return {"ok": True}
