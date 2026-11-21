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


def init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with conn() as c:
        c.executescript(SCHEMA)
        c.execute("UPDATE scans SET status='failed', stage='przerwany (restart)' "
                  "WHERE status IN ('queued','running')")
