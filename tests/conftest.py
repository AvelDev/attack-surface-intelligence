import json
import time

import pytest
from fastapi.testclient import TestClient

from asi import db, domain, scanner, scheduler
from asi.main import app


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ASI_DB", str(tmp_path / "asi.db"))
    db.init()
    return tmp_path


@pytest.fixture
def started(monkeypatch):
    """Zamiast prawdziwego skanu w tle zapisuje id zleconych skanów."""
    ids = []
    monkeypatch.setattr(scanner, "run_scan", ids.append)
    return ids


@pytest.fixture
def client(monkeypatch, started):
    monkeypatch.setattr(scheduler, "start", lambda: None)
    with TestClient(app) as c:
        yield c


def seed_scan(target, findings=(), assets=(), status="done", score=None):
    """Zapisuje gotowy skan: findings = [(asset, severity, title)], assets = [id 'kind:value']."""
    sev = [f[1] for f in findings]
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,opts,status,score,created,finished) VALUES(?,?,?,?,?,?)",
                        (target, json.dumps({}), status,
                         domain.risk_score(sev) if score is None else score, time.time(), time.time())).lastrowid
        for aid in assets:
            kind, value = aid.split(":", 1)
            c.execute("INSERT INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)", (sid, aid, kind, value, "{}"))
        for asset, severity, title in findings:
            c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)", (sid, asset, severity, title, "builtin", "d", "fix"))
    return sid
