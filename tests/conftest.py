"""Współdzielone fixture'y - izolowana baza SQLite per test (nie dotyka data/asi.db),
bo testy wznowienia skanu (test_scan_resume.py) potrzebują prawdziwego Ctx z prawdziwym
połączeniem, nie tylko atrap."""
import json
import time

import pytest

from asi import db, scanner


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test_asi.db"))
    db.init()
    return db


@pytest.fixture
def make_ctx(temp_db):
    """Fabryka: make_ctx(["1.2.3.4"], opts={}) -> nowy scanner.Ctx na własnym wierszu scans."""
    created = []

    def factory(targets, opts=None):
        with temp_db.conn() as c:
            sid = c.execute(
                "INSERT INTO scans(target,target_hash,opts,created,hosts_total) VALUES(?,?,?,?,?)",
                (",".join(targets), "", json.dumps(opts or {}), time.time(), 0)).lastrowid
            c.executemany("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)",
                          [(sid, t) for t in targets])
        ctx = scanner.Ctx(sid)
        created.append(ctx)
        return ctx

    yield factory
    for ctx in created:
        ctx.close()
