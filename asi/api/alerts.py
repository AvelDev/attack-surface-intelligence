"""Alerty po skanach (nowe pilne problemy, pogorszenie oceny, nowe adresy)."""
from fastapi import APIRouter, Depends

from .. import alerts, auth

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(user: dict = Depends(auth.require("read"))):
    return alerts.recent()


@router.post("/alerts/read")
def read_alerts(user: dict = Depends(auth.require("read"))):
    alerts.mark_all_read()
    return {"ok": True}
