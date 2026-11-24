import pytest

from asi import alerts, db, domain, net, settings, targets
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


def test_range_expansion_dedupes_and_limits(monkeypatch):
    resolved, errors = targets.expand(["10.0.0.0/30", "10.0.0.1", "Example.com", "example.com", "zly cel"])
    assert resolved == ["10.0.0.1", "10.0.0.2", "example.com"]
    assert [e[0] for e in errors] == ["zly cel"]
    monkeypatch.setenv("ASI_MAX_TARGETS", "4")
    resolved, errors = targets.expand(["10.0.0.0/24"])  # num_addresses sprawdzane PRZED rozwinięciem zakresu
    assert resolved == [] and "limit" in errors[0][1]


def test_range_expansion_respects_allowed_networks(monkeypatch):
    monkeypatch.setenv("ASI_ALLOWED_TARGETS", "10.0.0.0/30")
    resolved, errors = targets.expand(["10.0.0.0/29"])
    assert resolved == ["10.0.0.1", "10.0.0.2", "10.0.0.3"] and errors


def test_parse_target_files():
    assert targets.parse_text("a.com, b.com\nc.com") == ["a.com", "b.com", "c.com"]
    assert targets.parse_csv("host,x\na.com,1\nb.com,2") == ["a.com", "b.com"]
    assert targets.parse_json('{"targets": ["a.com", {"host": "b.com"}]}') == ["a.com", "b.com"]


def test_risk_score_is_normalized_by_host_count():
    """182 ustaleń 'medium' rozsianych po 254 hostach to nie 100/100 - to była regresja nasycania wyniku."""
    many_small = ["medium"] * 182 + ["low"] * 794
    assert domain.risk_score(many_small, 254) < 60
    assert domain.risk_score(["critical"], 254) > domain.risk_score(many_small, 254) / 2
    assert domain.risk_score(["critical"] * 100) == 100
