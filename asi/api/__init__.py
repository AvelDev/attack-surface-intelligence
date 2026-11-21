"""Warstwa HTTP: routery, kontrakty żądań i tłumaczenie wyjątków domenowych na kody HTTP.

Logika nie zna FastAPI; routery tylko walidują wejście, wołają moduły domenowe i formatują odpowiedź.
"""
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import config, db, scheduler
from ..errors import Conflict, InvalidInput, NotFound
from ..repo import scans as scans_repo
from . import alerts, scans, schedules, settings, system

_STATUS = {InvalidInput: 400, NotFound: 404, Conflict: 409}


@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init()
    scans_repo.mark_interrupted()
    if config.load().scheduler_enabled:
        scheduler.start()
    yield


def create_app():
    app = FastAPI(title="Attack Surface Intelligence", version="0.2.0", lifespan=lifespan)
    for exc, code in _STATUS.items():
        def handler(request: Request, e: Exception, code=code):
            return JSONResponse({"detail": str(e)}, status_code=code)
        app.add_exception_handler(exc, handler)
    for module in (scans, schedules, settings, alerts, system):
        app.include_router(module.router, prefix="/api")

    static = config.load().static_dir

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(static, "index.html"))

    # zbudowany frontend (React/Vite, patrz frontend/) - zasoby pod /static/assets
    app.mount("/static", StaticFiles(directory=static), name="static")
    return app
