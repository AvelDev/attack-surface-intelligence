"""Kolejka skanów: zakłada rekord, uruchamia pipeline w wątku w tle (po jednym naraz) i wyzwala alerty."""
import logging
import threading

from .. import alerts, targets
from ..errors import InvalidInput
from ..repo import scans as repo
from . import pipeline, tools
from .context import Ctx

log = logging.getLogger(__name__)
SEM = threading.Semaphore(1)  # skany idą w kolejce, po jednym naraz


def start_scan(target, opts):
    """Zakłada rekord skanu i uruchamia go w tle. Warunek: target już znormalizowany (targets.normalize). Zwraca id."""
    if targets.normalize(target) != target:
        raise InvalidInput("Cel musi być znormalizowany przed uruchomieniem skanu.")
    sid = repo.create(target, opts)
    threading.Thread(target=run_scan, args=(sid,), daemon=True, name=f"asi-scan-{sid}").start()
    return sid


def run_scan(scan_id):
    with SEM:
        ctx = Ctx(scan_id)
        try:
            repo.mark_running(scan_id)
            pipeline.run(ctx, tools.status())
            ctx.finish("done")
        except Exception as e:  # noqa: BLE001 - każdy błąd kończy skan jako 'failed' z wpisem w logu
            log.exception("skan %s nie powiódł się", scan_id)
            ctx.log(f"BŁĄD KRYTYCZNY: {e!r}")
            ctx.finish("failed")
            if ctx.opts.get("schedule_id"):
                alerts.add(scan_id, ctx.target, "warn", "Automatyczne sprawdzenie nie powiodło się.")
            return
    try:  # poza semaforem: alert (webhook) nie blokuje kolejnego skanu
        alerts.after_scan(scan_id)
    except Exception:  # noqa: BLE001 - zakończony skan zostaje 'done' nawet przy błędzie alertu
        log.exception("alert po skanie %s nie powiódł się", scan_id)
