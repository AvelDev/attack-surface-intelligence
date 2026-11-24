"""Warstwa HTTP: routery, kontrakty żądań i tłumaczenie wyjątków domenowych na kody HTTP.

Logika nie zna FastAPI; routery tylko walidują wejście i uprawnienia (auth.require), wołają moduły domenowe
i formatują odpowiedź.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .. import auth, config, db, scheduler
from ..errors import Conflict, InvalidInput, NotFound
from ..repo import scans as scans_repo
from . import alerts, dashboard, defectdojo, findings, frontend, ranges, scans, schedules, security, session, settings, signatures, system, users

_STATUS = {InvalidInput: 400, NotFound: 404, Conflict: 409}
ROUTERS = (session, users, signatures, scans, findings, dashboard, ranges, defectdojo, settings, schedules, alerts, system)


@asynccontextmanager
async def lifespan(app):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init()
    auth.bootstrap_admin()
    scans_repo.mark_interrupted()
    scheduler.start()
    yield


def create_app():
    app = FastAPI(title="Attack Surface Intelligence", version="0.3.0", lifespan=lifespan)
    for exc, code in _STATUS.items():
        def handler(request: Request, e: Exception, code=code):
            return JSONResponse({"detail": str(e)}, status_code=code)
        app.add_exception_handler(exc, handler)
    security.install(app)
    for module in ROUTERS:
        app.include_router(module.router, prefix="/api")
    frontend.install(app, config.load())
    return app
