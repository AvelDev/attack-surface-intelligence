import pytest

from asi import alerts, db, domain, net, scheduler, settings, targets
from asi.scan import checks
from tests.conftest import seed_scan


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("https://www.example.com:8443/a/b", "www.example.com"),
    ("example.com.", "example.com"),
    ("45.33.32.156", "45.33.32.156"),
])
def test_normalize_target_accepts(raw, expected):
    assert targets.normalize(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "exa mple.com", "-bad.com", "a" * 300 + ".com", "999.1.1.1.1"])
def test_normalize_target_rejects(raw):
    with pytest.raises(ValueError):
        targets.normalize(raw)


def test_allowlist(monkeypatch):
    monkeypatch.setenv("ASI_ALLOWED_TARGETS", "example.com")
    assert targets.normalize("api.example.com") == "api.example.com"
    with pytest.raises(ValueError):
        targets.normalize("evil.com")


def test_risk_score_bounds_and_monotonic():
    assert domain.risk_score([]) == 0
    assert domain.risk_score(["info"] * 50) == 0
    assert domain.risk_score(["low"]) < domain.risk_score(["medium"]) < domain.risk_score(["high"])
    assert domain.risk_score(["critical"] * 100) == 100


def test_settings_env_has_priority(monkeypatch):
    settings.put("shodan_api_key", "from-db-123")
    assert settings.get("shodan_api_key") == "from-db-123"
    monkeypatch.setenv("ASI_SHODAN_API_KEY", "from-env-456")
    assert settings.get("shodan_api_key") == "from-env-456"
    assert settings.get("not-a-key") == ""


def _alerts():
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT level, message FROM alerts")]


def test_alert_on_first_scan_with_urgent():
    sid = seed_scan("example.com", findings=[("domain:example.com", "high", "X")])
    alerts.after_scan(sid)
    assert _alerts()[0]["level"] == "bad"


def test_alert_on_new_urgent_finding():
    seed_scan("example.com", findings=[("domain:example.com", "low", "A")])
    sid = seed_scan("example.com", findings=[("domain:example.com", "low", "A"), ("domain:example.com", "critical", "B")])
    alerts.after_scan(sid)
    assert "B" in _alerts()[0]["message"]


def test_alert_on_new_assets_only():
    seed_scan("example.com", assets=["domain:example.com"])
    sid = seed_scan("example.com", assets=["domain:example.com", "ip:1.2.3.4"])
    alerts.after_scan(sid)
    assert _alerts()[0]["level"] == "warn"


def test_no_alert_when_nothing_changed():
    seed_scan("example.com", assets=["domain:example.com"])
    sid = seed_scan("example.com", assets=["domain:example.com"])
    alerts.after_scan(sid)
    assert _alerts() == []


def test_scheduler_runs_due_and_skips_busy(started):
    with db.conn() as c:
        c.execute("INSERT INTO schedules(target,interval_hours,created,next_run) VALUES('a.com',24,0,0)")
        c.execute("INSERT INTO schedules(target,interval_hours,created,next_run) VALUES('b.com',24,0,0)")
        c.execute("INSERT INTO schedules(target,interval_hours,created,next_run) VALUES('c.com',24,0,9e18)")
    seed_scan("b.com", status="running")
    scheduler.tick(now=1000)
    with db.conn() as c:
        targets = [r["target"] for r in c.execute("SELECT target FROM scans WHERE status='queued'")]
        nxt = c.execute("SELECT next_run FROM schedules WHERE target='a.com'").fetchone()[0]
    assert targets == ["a.com"] and len(started) == 1
    assert nxt == 1000 + 24 * 3600


def test_email_auth_flags_missing_spf_and_dmarc(monkeypatch):
    answers = {("example.com", "MX"): ["10 mx.example.com."], ("example.com", "TXT"): [], ("_dmarc.example.com", "TXT"): []}
    monkeypatch.setattr(checks, "doh", lambda n, t: answers[(n, t)])
    found, err = checks.email_auth("example.com")
    assert err is None
    assert {f[1].split(" (")[0] for f in found} == {"Brak rekordu SPF", "Brak rekordu DMARC"}


def test_email_auth_ignores_domains_without_mail(monkeypatch):
    monkeypatch.setattr(checks, "doh", lambda n, t: [])
    assert checks.email_auth("example.com") == ([], None)


def test_sensitive_files_require_signature(monkeypatch):
    def fake_fetch(url, **_):
        if url.endswith("/.env"):
            return net.Response(200, {"content-type": "text/plain"}, b"DB_PASSWORD=x\n")
        return net.Response(200, {"content-type": "text/html"}, b"<!doctype html>catch-all")
    monkeypatch.setattr(checks, "fetch", fake_fetch)
    found = checks.sensitive_files("https://example.com")
    assert [f[2] for f in found] == ["https://example.com/.env"]
