"""Połączenie z SQLite (stdlib) i wersjonowane migracje schematu.

Jedno połączenie na wywołanie - bezpieczne dla wątków. Schemat zna tylko ten moduł i pakiet repo/.
Migracje są numerowane (PRAGMA user_version): nowa zmiana schematu = nowa funkcja na końcu MIGRATIONS,
nigdy edycja istniejącej. Dzięki temu starszą bazę można bezpiecznie podnieść, a wersję sprawdzić w /api/health.

Bazy sprzed wersjonowania (user_version=0) mają już tabele - `CREATE TABLE IF NOT EXISTS` ich nie rusza,
a brakujące kolumny dokłada `_m2_legacy_columns`.
"""
import os
import sqlite3
from contextlib import contextmanager

from . import config

ROOT = str(config.ROOT)


@contextmanager
def conn():
    c = sqlite3.connect(config.load().db_path, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def raw_connect():
    """Połączenie bez menedżera kontekstu - dla kodu, który trzyma je na czas skanu i sam commituje/zamyka."""
    c = sqlite3.connect(config.load().db_path, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def _columns(c, table):
    return {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}


def _m1_base(c):
    c.executescript("""
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  target_hash TEXT NOT NULL DEFAULT '',
  opts TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  stage TEXT NOT NULL DEFAULT '',
  score INTEGER NOT NULL DEFAULT 0,
  hosts_total INTEGER NOT NULL DEFAULT 0,
  hosts_done INTEGER NOT NULL DEFAULT 0,
  duration_s REAL,
  created REAL NOT NULL,
  finished REAL,
  log TEXT NOT NULL DEFAULT '',
  stop_requested INTEGER NOT NULL DEFAULT 0,
  checkpoint TEXT
);
CREATE TABLE IF NOT EXISTS scan_targets(
  scan_id INTEGER NOT NULL, target TEXT NOT NULL,
  PRIMARY KEY(scan_id, target)
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
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created REAL NOT NULL,
  expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS signatures(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  pattern TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'low',
  title TEXT NOT NULL DEFAULT '',
  fix TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS finding_overrides(
  asset TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  fix TEXT NOT NULL DEFAULT '',
  false_positive INTEGER NOT NULL DEFAULT 0,
  updated REAL NOT NULL,
  PRIMARY KEY(asset, title)
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage(
  asset TEXT NOT NULL,
  key TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  updated REAL NOT NULL,
  PRIMARY KEY(asset, key)
);
CREATE TABLE IF NOT EXISTS range_notes(
  target_hash TEXT PRIMARY KEY,
  note TEXT NOT NULL DEFAULT '',
  username TEXT NOT NULL DEFAULT '',
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  opts TEXT NOT NULL DEFAULT '{}',
  interval_hours INTEGER NOT NULL DEFAULT 24,
  time_window_mins INTEGER NOT NULL DEFAULT 60,
  last_run REAL,
  next_run REAL NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_scan_id INTEGER
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


# Kolumny dodane po pierwszym wydaniu - CREATE TABLE IF NOT EXISTS nie doda ich do istniejącej bazy.
# SQLite nie ma "ADD COLUMN IF NOT EXISTS", więc sprawdzamy PRAGMA table_info.
_LEGACY_COLUMNS = {
    "scans": ("target_hash TEXT NOT NULL DEFAULT ''", "hosts_total INTEGER NOT NULL DEFAULT 0",
              "hosts_done INTEGER NOT NULL DEFAULT 0", "duration_s REAL", "stop_requested INTEGER NOT NULL DEFAULT 0",
              # Stan do prawdziwego wznowienia po oknie czasowym (adresy/mapowania celu, nie dane wrażliwe):
              # {"ip_of", "root_id", "pending_ips", "hosts_total"}. NULL = nic do kontynuowania.
              "checkpoint TEXT"),
    "schedules": ("opts TEXT NOT NULL DEFAULT '{}'", "time_window_mins INTEGER NOT NULL DEFAULT 60",
                  # ostatni skan wystartowany przez harmonogram - scheduler wznawia TEN SAM, gdy jest 'paused_window'
                  "last_scan_id INTEGER"),
}


def _m2_legacy_columns(c):
    for table, coldefs in _LEGACY_COLUMNS.items():
        have = _columns(c, table)
        for coldef in coldefs:
            if coldef.split()[0] not in have:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")


def _m3_indexes(c):
    c.executescript("""
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS scans_target_status ON scans(target, status);
CREATE INDEX IF NOT EXISTS idx_scans_target_hash ON scans(target_hash);
CREATE INDEX IF NOT EXISTS alerts_unread ON alerts(read);
""")


MIGRATIONS = [_m1_base, _m2_legacy_columns, _m3_indexes]
SCHEMA_VERSION = len(MIGRATIONS)


def schema_version():
    with conn() as c:
        return c.execute("PRAGMA user_version").fetchone()[0]


def init():
    """Tworzy/podnosi schemat do SCHEMA_VERSION. Odmawia pracy na bazie z nowszej wersji aplikacji."""
    path = config.load().db_path
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        current = c.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise RuntimeError(f"Baza ma schemat v{current}, a aplikacja zna najwyżej v{SCHEMA_VERSION}. "
                               "Uruchom nowszą wersję aplikacji albo przywróć kopię bazy.")
        for n, migrate in enumerate(MIGRATIONS[current:], start=current + 1):
            migrate(c)
            c.execute(f"PRAGMA user_version = {n}")
            c.commit()
    try:
        os.chmod(path, 0o600)  # w bazie leżą klucze API i hasze haseł
    except OSError:
        pass
