"""Ustawienia: integracje (DefectDojo, OpenVAS/GVM) i klucze API źródeł wywiadu. Sekrety nigdy nie wracają do przeglądarki."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import auth, defectdojo, gvm_scan, settings
from ..errors import InvalidInput
from ..scan import tools

router = APIRouter(tags=["settings"])


class DefectDojoSettingsReq(BaseModel):
    url: str
    api_key: str


class GvmSettingsReq(BaseModel):
    host: str
    port: int = 9390
    username: str = "admin"
    password: str


class SettingReq(BaseModel):
    value: str = Field(max_length=1000)


@router.get("/settings")
def get_settings(user: dict = Depends(auth.require("read"))):
    dd_url, dd_key = defectdojo.get_config()
    gvm_host, gvm_port, gvm_username, gvm_password = gvm_scan.get_config()
    return {
        "defectdojo_url": dd_url or "",
        "defectdojo_configured": bool(dd_url and dd_key),
        "gvm_host": gvm_host or "",
        "gvm_port": gvm_port,
        "gvm_username": gvm_username or "",
        "gvm_configured": bool(gvm_host and gvm_password),
        "openvas_configured": tools.status().get("openvas", {}).get("installed", False),
        "api_keys": settings.status(),
    }


@router.post("/settings/defectdojo")
def save_defectdojo_settings(req: DefectDojoSettingsReq, user: dict = Depends(auth.require("admin"))):
    # admin-only: to ustawienie kieruje, gdzie trafiają ustalenia ze WSZYSTKICH skanów - rola niższa mogłaby po cichu
    # przekierować eksport na dowolny serwer (SSRF / eksfiltracja danych), stąd też walidacja URL-a.
    try:
        defectdojo.save_config(req.url, req.api_key)
    except ValueError as e:
        raise InvalidInput(str(e)) from e
    return {"ok": True}


@router.post("/settings/gvm")
def save_gvm_settings(req: GvmSettingsReq, user: dict = Depends(auth.require("admin"))):
    # admin-only, jak DefectDojo - dane logowania idą plaintextem po sieci (gvm_scan.PlainTCPConnection), więc host
    # musi być prywatny/loopback.
    try:
        gvm_scan.save_config(req.host, req.port, req.username, req.password)
    except ValueError as e:
        raise InvalidInput(str(e)) from e
    return {"ok": True}


@router.put("/settings/{key}")
def put_api_key(key: str, req: SettingReq, user: dict = Depends(auth.require("admin"))):
    settings.put(key, req.value)
    return {"ok": True}


@router.delete("/settings/{key}")
def delete_api_key(key: str, user: dict = Depends(auth.require("admin"))):
    settings.delete(key)
    return {"ok": True}
