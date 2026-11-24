"""Cykliczne, automatyczne skany. Wątek w tle sprawdza harmonogramy co POLL_SECONDS.

Skan wstrzymany oknem czasowym (paused_window) jest wznawiany od punktu kontrolnego przy najbliższym tyknięciu
(RESUME_RETRY_S), a nie dopiero za cały interval_hours - to kontynuacja tego samego skanu, nie nowy przebieg.
Wyłączenie wątku (np. przy kilku instancjach lub w testach): ASI_SCHEDULER=0.
"""
import json
import logging
import threading
import time

from . import config
from .errors import InvalidInput, NotFound
from .repo import scans as scans_repo
from .repo import schedules as repo
from .scan import runner

log = logging.getLogger(__name__)
POLL_SECONDS = 30
RESUME_RETRY_S = 60
MAX_INTERVAL_HOURS = 24 * 366
_started = threading.Event()


def create(target, interval_hours, time_window_mins, opts):
    """Zakłada harmonogram (pierwszy skan po upływie interwału). Zwraca id."""
    if not 1 <= interval_hours <= MAX_INTERVAL_HOURS:
        raise InvalidInput(f"Interwał musi mieć od 1 do {MAX_INTERVAL_HOURS} godzin.")
    if not target.strip():
        raise InvalidInput("Podaj cel harmonogramu.")
    return repo.create(target.strip(), json.dumps(opts), interval_hours, time_window_mins, time.time() + interval_hours * 3600)


def listing():
    return repo.list_all()


def delete(hid):
    if not repo.delete(hid):
        raise NotFound("Nie ma takiego harmonogramu")


def set_enabled(hid, enabled):
    if not repo.set_enabled(hid, enabled):
        raise NotFound("Nie ma takiego harmonogramu")


def _after_run(hid, sid, interval_hours):
    """Wołane PO zakończeniu skanu wystartowanego przez harmonogram - next_run zależy od tego, czy skan faktycznie się
    skończył, czy tylko wstrzymał na oknie."""
    now = time.time()
    paused = scans_repo.status(sid) == "paused_window"
    repo.mark_run(hid, sid, now, now + (RESUME_RETRY_S if paused else max(1, interval_hours) * 3600))


def _run_entry(hid, sid, interval_hours):
    runner.run_scan(sid)
    _after_run(hid, sid, interval_hours)


def _claim_or_create(sch):
    """Id skanu do uruchomienia: wznowiony wstrzymany albo nowy. None = ktoś inny już go skanuje - pomiń tyknięcie."""
    last = sch["last_scan_id"]
    if last:
        if scans_repo.claim_resume(last):
            return last  # wznowienie - TEN SAM scan_id, nie nowy wiersz
        if scans_repo.status(last) in scans_repo.ACTIVE:
            return None
    opts = json.loads(sch["opts"] or "{}")
    opts["schedule_id"] = sch["id"]
    if sch["time_window_mins"]:
        opts["time_window_mins"] = sch["time_window_mins"]
    sid, _errors = runner.create_scan([t.strip() for t in sch["target"].split(",") if t.strip()], opts)
    return sid


def tick(now=None):
    """Uruchamia należne skany. Błąd jednego wpisu nie blokuje pozostałych."""
    now = now or time.time()
    for sch in repo.due(now):
        try:
            sid = _claim_or_create(sch)
            if sid is None:
                continue
            repo.defer(sch["id"], now + 24 * 3600)
            threading.Thread(target=_run_entry, args=(sch["id"], sid, sch["interval_hours"]), daemon=True).start()
        except Exception:  # noqa: BLE001 - pętla ma przetrwać błąd pojedynczego wpisu, ale nie po cichu
            log.exception("błąd harmonogramu %s", sch["id"])


def _loop():
    while True:
        try:
            tick()
        except Exception:  # noqa: BLE001
            log.exception("błąd harmonogramu")
        time.sleep(POLL_SECONDS)


def start():
    if config.load().scheduler_enabled and not _started.is_set():
        _started.set()
        threading.Thread(target=_loop, daemon=True, name="asi-scheduler").start()
