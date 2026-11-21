from fastapi import APIRouter
from pydantic import BaseModel, Field

from .. import domain, scheduler
from .scans import require_authorization

router = APIRouter(tags=["schedules"])


class ScheduleReq(BaseModel):
    target: str = Field(max_length=300)
    authorized: bool = False
    nuclei: bool = False
    deep: bool = False
    interval_hours: int = domain.DEFAULT_INTERVAL


class SchedulePatch(BaseModel):
    enabled: bool


@router.get("/schedules")
def list_schedules():
    return scheduler.listing()


@router.post("/schedules")
def create_schedule(req: ScheduleReq):
    require_authorization(req.authorized, "Potwierdź, że masz zgodę na cykliczne sprawdzanie tego celu.")
    hid, sid = scheduler.create(req.target, req.interval_hours, nuclei=req.nuclei, deep=req.deep)
    return {"id": hid, "scan_id": sid}


@router.patch("/schedules/{hid}")
def patch_schedule(hid: int, req: SchedulePatch):
    scheduler.set_enabled(hid, req.enabled)
    return {"ok": True}


@router.delete("/schedules/{hid}")
def delete_schedule(hid: int):
    scheduler.delete(hid)
    return {"ok": True}
