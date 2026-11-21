"""Cykliczne, automatyczne skany (monitoring). Wątek w tle sprawdza harmonogramy co POLL_SECONDS.

Wyłączenie wątku (np. przy kilku instancjach lub w testach): ASI_SCHEDULER=0.
"""
import logging
import threading
import time

from . import domain, targets
from .errors import Conflict, InvalidInput, NotFound
from .repo import scans as scans_repo
from .repo import schedules as repo
from .scan import runner

log = logging.getLogger(__name__)
POLL_SECONDS = 30
_started = threading.Event()


def create(raw_target, interval_hours, nuclei=False, deep=False):
    """Zakłada harmonogram i od razu uruchamia pierwszy skan. Zwraca (id harmonogramu, id skanu)."""
    if interval_hours not in domain.INTERVALS:
        raise InvalidInput("Niedozwolony odstęp czasu.")
    target = targets.normalize(raw_target)
    hid = repo.create(target, nuclei, deep, interval_hours, time.time())
    if hid is None:
        raise Conflict("Ta strona jest już objęta automatycznym sprawdzaniem.")
    return hid, _launch(target, nuclei, deep, hid)


def _launch(target, nuclei, deep, hid):
    return runner.start_scan(target, {"nuclei": bool(nuclei), "deep": bool(deep), "schedule_id": hid})


def set_enabled(hid, enabled):
    if not repo.set_enabled(hid, enabled):
        raise NotFound("Nie ma takiego harmonogramu")


def delete(hid):
    if not repo.delete(hid):
        raise NotFound("Nie ma takiego harmonogramu")


def listing():
    return {"intervals": domain.INTERVALS, "items": repo.list_with_last_result()}


def tick(now=None):
    """Uruchamia należne skany. Cel, którego poprzedni skan jeszcze trwa, czeka do następnego obrotu."""
    now = now or time.time()
    for sch in repo.due(now):
        if scans_repo.is_busy(sch["target"]):
            continue
        repo.mark_run(sch["id"], now, now + sch["interval_hours"] * 3600)
        _launch(sch["target"], sch["nuclei"], sch["deep"], sch["id"])


def _loop():
    while True:
        try:
            tick()
        except Exception:  # pętla ma przetrwać błąd pojedynczego obrotu, ale nie po cichu
            log.exception("błąd harmonogramu")
        time.sleep(POLL_SECONDS)


def start():
    if not _started.is_set():
        _started.set()
        threading.Thread(target=_loop, daemon=True, name="asi-scheduler").start()
