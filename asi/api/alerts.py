from fastapi import APIRouter

from .. import alerts

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts():
    return alerts.recent()


@router.post("/alerts/read")
def read_alerts():
    alerts.mark_all_read()
    return {"ok": True}
