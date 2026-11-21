"""Połączenie z SQLite (stdlib) i wersjonowane migracje schematu.

Jedno połączenie na wywołanie - bezpieczne dla wątków. Schemat zna tylko ten moduł i pakiet repo/.
Migracje są numerowane (PRAGMA user_version): nowa zmiana schematu = nowa funkcja na końcu MIGRATIONS,
nigdy edycja istniejącej. Dzięki temu starszą bazę można bezpiecznie podnieść, a wersję sprawdzić w /api/health.
"""
import os
import sqlite3
from contextlib import contextmanager

from . import config


@contextmanager
def conn():
    c = sqlite3.connect(config.load().db_path, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _columns(c, table):
    return {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}


def _m1_base(c):
    c.executescript("""
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  opts TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  stage TEXT NOT NULL DEFAULT '',
  score INTEGER NOT NULL DEFAULT 0,
  created REAL NOT NULL,
  finished REAL,
  log TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assets(
  scan_id INTEGER NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL,
  value TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(scan_id, id)
);
CREATE TABLE IF NOT EXISTS edges(
  scan_id INTEGER NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
  PRIMARY KEY(scan_id, src, dst)
);
CREATE TABLE IF NOT EXISTS findings(
  scan_id INTEGER NOT NULL, asset TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, source TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '',
  fix TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS schedules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL UNIQUE,
  nuclei INTEGER NOT NULL DEFAULT 0,
  interval_hours INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created REAL NOT NULL,
  last_run REAL,
  next_run REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  target TEXT NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  created REAL NOT NULL,
  read INTEGER NOT NULL DEFAULT 0
);
""")


def _m2_schedule_deep(c):
    if "deep" not in _columns(c, "schedules"):  # bazy sprzed wersjonowania mogły już mieć tę kolumnę
        c.execute("ALTER TABLE schedules ADD COLUMN deep INTEGER NOT NULL DEFAULT 0")


def _m3_indexes(c):
    c.executescript("""
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS scans_target_status ON scans(target, status);
CREATE INDEX IF NOT EXISTS alerts_unread ON alerts(read);
""")


MIGRATIONS = [_m1_base, _m2_schedule_deep, _m3_indexes]
SCHEMA_VERSION = len(MIGRATIONS)


def schema_version():
    with conn() as c:
        return c.execute("PRAGMA user_version").fetchone()[0]


def init():
    """Tworzy/podnosi schemat do SCHEMA_VERSION. Odmawia pracy na bazie z nowszej wersji aplikacji."""
    path = config.load().db_path
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with conn() as c:
        current = c.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"Baza ma schemat v{current}, a aplikacja zna najwyżej v{SCHEMA_VERSION}. "
                               "Uruchom nowszą wersję aplikacji albo przywróć kopię bazy.")
        for n, migrate in enumerate(MIGRATIONS[current:], start=current + 1):
            migrate(c)
            c.execute(f"PRAGMA user_version = {n}")
            c.commit()
    try:
        os.chmod(path, 0o600)  # w bazie leżą klucze API
    except OSError:
        pass
