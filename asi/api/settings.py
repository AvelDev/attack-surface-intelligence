"""Ustawienia i klucze API. Wartości kluczy nigdy nie wracają do przeglądarki."""
from fastapi import APIRouter
from pydantic import BaseModel, Field

from .. import settings

router = APIRouter(tags=["settings"])


class SettingReq(BaseModel):
    value: str = Field(max_length=1000)


@router.get("/settings")
def get_settings():
    return settings.status()


@router.put("/settings/{key}")
def put_setting(key: str, req: SettingReq):
    settings.put(key, req.value)
    return {"ok": True}


@router.delete("/settings/{key}")
def delete_setting(key: str):
    settings.delete(key)
    return {"ok": True}
