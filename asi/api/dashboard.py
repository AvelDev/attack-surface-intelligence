"""Przegląd: dashboard ponad skanami."""
from fastapi import APIRouter, Depends

from .. import auth, dashboard
from .ranges import check_range_id

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard")
def get_dashboard(range: str | None = None, scan: int | None = None, at: float | None = None,
                  user: dict = Depends(auth.require("read"))):
    if range is not None:
        check_range_id(range)
    return dashboard.build(range, scan, at)
