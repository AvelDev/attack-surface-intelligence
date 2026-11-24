"""Nmap w interfejsie: co potrafi serwer, katalog skryptów NSE i podgląd komendy."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from .. import auth, config
from ..nmap import command, options, policy, scripts
from ..scan import nmap_scan, tools
from .scans import MAX_RATE, authorized_nmap

router = APIRouter(tags=["nmap"], prefix="/nmap")


class PreviewReq(BaseModel):
    options: dict
    rate_limit: int = Field(300, ge=1, le=MAX_RATE)
    intel: bool = False


def _nmap():
    """(zainstalowany, Capabilities, wersja). Bez nmapa podgląd pokazuje komendę, jaką wykonałby uprawniony."""
    path = tools.which("nmap")
    return (True, *tools.nmap_capabilities(path)) if path else (False, command.Capabilities(raw=True), "")


@router.get("")
def describe(user: dict = Depends(auth.require("read"))):
    installed, caps, version = _nmap()
    gated = config.load().nmap_intrusive and user["role"] == "admin"
    return {"installed": installed, "version": version, "raw": installed and caps.raw, "naabu": bool(tools.which("naabu")),
            "profiles": [p.model_dump() for p in options.PROFILES.values()], "defaults": options.NmapOptions().model_dump(),
            "techniques": options.TECHNIQUE_FLAG, "pings": options.PING_FLAG, "script_args": options.SCRIPT_ARGS,
            "categories": [{"id": c, "gated": c in policy.GATED, "external": c == policy.EXTERNAL,
                            "allowed": c not in policy.GATED or gated} for c in policy.CATEGORIES]}


@router.get("/scripts")
def list_scripts(user: dict = Depends(auth.require("read"))):
    return [{"name": n, "categories": c} for n, c in sorted(scripts.catalog().items()) if policy.NEVER not in c]


@router.post("/preview")
def preview(req: PreviewReq, user: dict = Depends(auth.require("add_remove_modify"))):
    """Dokładnie ta komenda, którą wykona skan, i dolna granica czasu na host przy danym limicie tempa."""
    _installed, caps, _version = _nmap()
    opts = authorized_nmap(req.options, user, {"intel": req.intel})
    opts, dropped = command.adapt(opts, caps)
    prescan = opts.prescan and bool(tools.which("naabu"))
    probes = command.probes_per_host(opts)
    cmd = ["nmap", *command.build(opts, caps, req.rate_limit)]
    if prescan:
        cmd = ["nmap", *command.build(opts, caps, req.rate_limit, only_ports=[])]
        cmd[cmd.index("-p") + 1] = "<porty z naabu>"
    return {"command": nmap_scan.display(cmd), "prescan": " ".join(["naabu", *command.naabu_ports(opts), "-rate", str(req.rate_limit)]) if prescan else None,
            "profile": opts.profile, "dropped": dropped, "probes": probes, "min_seconds": round(command.min_seconds(opts, req.rate_limit), 1)}
