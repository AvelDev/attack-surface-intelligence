"""Serwowanie interfejsu: zbudowany frontend React (frontend/dist) pod "/", stary UI pod /legacy i Command Center.

Strony HTML nie wymagają sesji (jak dotąd) - nic wrażliwego nie zawierają, a dane lecą przez /api/*, które sesji wymagają."""
import os

from fastapi import HTTPException
from fastapi.responses import FileResponse


def install(app, cfg):
    static, dist = cfg.static_dir, cfg.frontend_dist

    def has_dist():
        return os.path.isfile(os.path.join(dist, "index.html"))

    @app.get("/", include_in_schema=False)
    def index():
        if has_dist():
            return FileResponse(os.path.join(dist, "index.html"), headers={"Cache-Control": "no-cache"})
        return FileResponse(os.path.join(static, "index.html"))

    @app.get("/legacy", include_in_schema=False)
    def legacy_index():
        return FileResponse(os.path.join(static, "index.html"))

    @app.get("/command-center", include_in_schema=False)
    def command_center():
        return FileResponse(os.path.join(static, "command_center.html"))

    @app.get("/assets/{path:path}", include_in_schema=False)
    def dist_assets(path: str):
        base = os.path.realpath(os.path.join(dist, "assets"))
        full = os.path.realpath(os.path.join(base, path))
        if not full.startswith(base + os.sep) or not os.path.isfile(full):
            raise HTTPException(404)
        return FileResponse(full, headers={"Cache-Control": "public, max-age=31536000, immutable"})
