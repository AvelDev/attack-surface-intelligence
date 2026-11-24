"""Współdzielone fixture'y - izolowana baza SQLite per test (nigdy nie dotyka data/asi.db).

Testy wznowienia skanu potrzebują prawdziwego Ctx z prawdziwym połączeniem, nie tylko atrap."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from asi import auth, db, domain, targets
from asi.main import app
from asi.repo import scans as repo
from asi.scan import runner
from asi.scan.context import Ctx

TEST_USER, TEST_PASSWORD = "tester", "test-password-123"


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ASI_DB", str(tmp_path / "test_asi.db"))
    monkeypatch.setenv("ASI_SCHEDULER", "0")
    monkeypatch.setattr(auth, "ITERATIONS", 1000)  # PBKDF2 z produkcyjną liczbą iteracji spowalniałby każdy test o sekundy
    db.init()
    return db


@pytest.fixture
def make_ctx(temp_db):
    """Fabryka: make_ctx(["1.2.3.4"], opts={}) -> nowy Ctx na własnym wierszu scans."""
    created = []

    def factory(scan_targets, opts=None):
        sid = repo.create(",".join(scan_targets), targets.range_hash(scan_targets), opts or {}, scan_targets)
        ctx = Ctx(sid)
        created.append(ctx)
        return ctx

    yield factory
    for ctx in created:
        ctx.close()


@pytest.fixture
def started(monkeypatch):
    """Zamiast prawdziwego skanu w tle zapisuje id zleconych skanów."""
    ids = []
    monkeypatch.setattr(runner, "launch", ids.append)
    return ids


@pytest.fixture
def client(started):
    """Klient HTTP zalogowany jako administrator."""
    with TestClient(app) as c:
        auth.create_user(TEST_USER, TEST_PASSWORD, "admin")
        assert c.post("/api/login", json={"username": TEST_USER, "password": TEST_PASSWORD}).status_code == 200
        yield c


def login_as(role):
    """Nowy, niezalogowany klient i zalogowanie go użytkownikiem o danej roli."""
    username = f"user_{role}"
    auth.create_user(username, TEST_PASSWORD, role)
    c = TestClient(app)
    assert c.post("/api/login", json={"username": username, "password": TEST_PASSWORD}).status_code == 200
    return c


def seed_scan(target, findings=(), assets=(), status="done", score=None):
    """Zapisuje gotowy skan: findings = [(asset, severity, title)], assets = [id 'kind:value']."""
    sev = [f[1] for f in findings]
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,target_hash,opts,status,stage,score,created,finished) VALUES(?,?,?,?,?,?,?,?)",
                        (target, targets.range_hash([target]), json.dumps({}), status, "zakończony",
                         domain.risk_score(sev) if score is None else score, time.time(), time.time())).lastrowid
        c.execute("INSERT OR IGNORE INTO scan_targets(scan_id,target) VALUES(?,?)", (sid, target))
        for aid in assets:
            kind, value = aid.split(":", 1)
            c.execute("INSERT INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)", (sid, aid, kind, value, "{}"))
        for asset, severity, title in findings:
            c.execute("INSERT INTO findings(scan_id,asset,severity,title,source,detail,fix) VALUES(?,?,?,?,?,?,?)",
                      (sid, asset, severity, title, "builtin", "", "fix"))
    return sid
