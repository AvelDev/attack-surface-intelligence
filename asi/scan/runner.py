"""Kolejka skanów: zakłada rekord, uruchamia pipeline w wątku w tle (do ASI_MAX_WORKERS naraz) i wyzwala alerty."""
import logging
import threading

from .. import alerts, config, targets
from ..errors import InvalidInput
from ..repo import scans as repo
from . import pipeline, tools
from .context import Ctx, ScanStopped, WindowExceeded

log = logging.getLogger(__name__)
JOB_SEM = threading.Semaphore(config.load().max_workers)  # ile skanów (jobów) naraz


def create_scan(raw_items, opts):
    """Zapisuje rekord skanu i jego cele, NIE startuje wątku. Rozdzielone od start_scan, żeby harmonogram mógł użyć
    własnego wątku, który po zakończeniu aktualizuje next_run. Zwraca (id, [(wpis, powód)] odrzuconych celów)."""
    resolved, errors = targets.expand(raw_items)
    if not resolved:
        detail = "; ".join(f"{r}: {e}" for r, e in errors[:5]) or "Brak celów."
        raise InvalidInput(f"Brak prawidłowych celów. {detail}")
    display = targets.display_name(raw_items, resolved)
    return repo.create(display, targets.range_hash(resolved), opts, resolved), errors


def start_scan(raw_items, opts):
    """Zakłada skan i uruchamia go w tle. Zwraca (id, odrzucone cele)."""
    sid, errors = create_scan(raw_items, opts)
    launch(sid)
    return sid, errors


def launch(sid):
    threading.Thread(target=run_scan, args=(sid,), daemon=True, name=f"asi-scan-{sid}").start()


def resume(sid):
    """Wznawia skan wstrzymany oknem czasowym od punktu kontrolnego. False, gdy skan nie jest wstrzymany (albo ktoś
    inny już go wznowił - patrz repo.claim_resume)."""
    if not repo.claim_resume(sid):
        return False
    launch(sid)
    return True


def run_scan(scan_id):
    with JOB_SEM:
        ctx = Ctx(scan_id)
        try:
            repo.mark_running(scan_id)
            pipeline.run(ctx, tools.status())
            status = "done"
        except ScanStopped as e:
            ctx.log(f"ZATRZYMANO: {e}")
            status = "stopped"
        except WindowExceeded as e:
            ctx.log(f"WSTRZYMANO: {e} - wznowienie nastąpi w kolejnym oknie czasowym.")
            status = "paused_window"
        except Exception as e:  # noqa: BLE001 - każdy błąd kończy skan jako 'failed' z wpisem w logu
            log.exception("skan %s nie powiódł się", scan_id)
            ctx.log(f"BŁĄD KRYTYCZNY: {e!r}")
            status = "failed"
        try:
            ctx.finish(status)
        finally:
            ctx.close()
    if status == "done":
        _alert(scan_id, alerts.after_scan)
    elif status == "failed" and _scheduled(scan_id):
        _alert(scan_id, lambda sid: alerts.add(sid, repo.run_info(sid)[0], "warn", "Automatyczne sprawdzenie nie powiodło się."))


def _scheduled(scan_id):
    return bool(repo.run_info(scan_id)[1].get("schedule_id"))


def _alert(scan_id, fn):
    try:  # poza semaforem: alert (webhook) nie blokuje kolejnego skanu, a jego błąd nie psuje wyniku skanu
        fn(scan_id)
    except Exception:  # noqa: BLE001
        log.exception("alert po skanie %s nie powiódł się", scan_id)
