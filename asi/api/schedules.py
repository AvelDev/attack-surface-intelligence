"""Harmonogramy cyklicznych skanów."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth, scheduler
from .scans import scan_options

router = APIRouter(tags=["schedules"])


class ScheduleReq(BaseModel):
    target: str
    interval_hours: int = 24
    time_window_mins: int = 60
    nuclei: bool = False
    gvm: bool = False
    deep: bool = False
    rate_limit: int | None = None


class SchedulePatch(BaseModel):
    enabled: bool


@router.get("/schedules")
def list_schedules(user: dict = Depends(auth.require("read"))):
    return scheduler.listing()


@router.post("/schedules")
def create_schedule(req: ScheduleReq, user: dict = Depends(auth.require("add_remove_modify"))):
    opts = scan_options(req.nuclei, req.gvm, req.rate_limit, req.time_window_mins, req.deep)
    return {"id": scheduler.create(req.target, req.interval_hours, req.time_window_mins, opts)}


@router.patch("/schedules/{hid}")
def patch_schedule(hid: int, req: SchedulePatch, user: dict = Depends(auth.require("add_remove_modify"))):
    scheduler.set_enabled(hid, req.enabled)
    return {"ok": True}


@router.delete("/schedules/{hid}")
def delete_schedule(hid: int, user: dict = Depends(auth.require("add_remove_modify"))):
    scheduler.delete(hid)
    return {"ok": True}
