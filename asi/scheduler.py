"""Cykliczne, automatyczne skany (monitoring). Wątek w tle sprawdza harmonogramy co kilkanaście sekund."""
import threading
import time

from . import db, scanner
POLL_SECONDS = 30
_started = False


def _busy(c, target):
    return c.execute("SELECT 1 FROM scans WHERE target=? AND status IN ('queued','running')",
                     (target,)).fetchone() is not None


def tick(now=None):
    now = now or time.time()
    with db.conn() as c:
        due = c.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,)).fetchall()
    for sch in due:
        with db.conn() as c:
            if _busy(c, sch["target"]):
                continue  # poprzedni skan jeszcze trwa - spróbujemy w następnym obrocie
            c.execute("UPDATE schedules SET last_run=?, next_run=? WHERE id=?",
                      (now, now + sch["interval_hours"] * 3600, sch["id"]))
        scanner.start_scan(sch["target"], {"nuclei": bool(sch["nuclei"]), "deep": bool(sch["deep"]), "schedule_id": sch["id"]})


def _loop():
    while True:
        try:
            tick()
        except Exception:  # noqa: BLE001 - pętla ma przetrwać błąd pojedynczego obrotu
            pass
        time.sleep(POLL_SECONDS)


def start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, daemon=True, name="asi-scheduler").start()
