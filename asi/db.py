"""Cienka warstwa SQLite (stdlib). Jedno połączenie na wywołanie - bezpieczne dla wątków."""
import os
import sqlite3
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("ASI_DB", os.path.join(ROOT, "data", "asi.db"))

SCHEMA = """
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
  log TEXT NOT NULL DEFAULT ''
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
CREATE TABLE IF NOT EXISTS schedules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  opts TEXT NOT NULL DEFAULT '{}',
  interval_hours INTEGER NOT NULL DEFAULT 24,
  time_window_mins INTEGER NOT NULL DEFAULT 60,
  last_run REAL,
  next_run REAL NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
"""


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


# Kolumny dodane do `scans` już po pierwszym wydaniu - CREATE TABLE IF NOT EXISTS nie
# doda ich do istniejącej bazy, więc trzeba ALTER TABLE (SQLite nie ma "ADD COLUMN IF
# NOT EXISTS" - łapiemy błąd "duplicate column" na bazach, które już je mają).
_SCANS_MIGRATIONS = (
    "target_hash TEXT NOT NULL DEFAULT ''",
    "hosts_total INTEGER NOT NULL DEFAULT 0",
    "hosts_done INTEGER NOT NULL DEFAULT 0",
    "duration_s REAL",
)


def _add_column(c, table, coldef):
    try:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e):
            raise


def init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        for coldef in _SCANS_MIGRATIONS:
            _add_column(c, "scans", coldef)
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_hash ON scans(target_hash)")
        c.execute("UPDATE scans SET status='failed', stage='przerwany (restart)' "
                  "WHERE status IN ('queued','running')")
