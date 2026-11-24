"""Czyste reguły wydzielone ze skanera oraz kontrakty warstw (migracje, pipeline, kolejka)."""
import sqlite3
import threading

import pytest

from asi import alerts, config, db, domain, history, targets
from asi.errors import InvalidInput
from asi.repo import scans as scans_repo
from asi.scan import context, dns, pipeline, ports, runner, web
from tests.conftest import seed_scan


# ---------- domena ----------
def test_domain_spec_is_consistent():
    assert domain.SEVERITIES == ["critical", "high", "medium", "low", "info"]
    assert domain.URGENT.issubset(domain.SEVERITIES)


@pytest.mark.parametrize("score,counts,tone", [
    (0, {}, "good"), (30, {}, "warn"), (5, {"high": 1}, "warn"), (60, {}, "bad"), (1, {"critical": 1}, "bad"),
])
def test_verdict(score, counts, tone):
    assert domain.verdict(score, counts)["tone"] == tone


def test_sort_findings_puts_unknown_last():
    out = domain.sort_findings([{"severity": "x"}, {"severity": "low"}, {"severity": "critical"}])
    assert [f["severity"] for f in out] == ["critical", "low", "x"]


# ---------- porty ----------
@pytest.mark.parametrize("port,data,ok", [
    (22, b"SSH-2.0-OpenSSH", True), (22, b"HTTP/1.1 400", False), (21, b"", False), (6379, b"-ERR", True),
])
def test_banner_verdict(port, data, ok):
    assert ports.banner_verdict(port, data)[0] is ok


@pytest.mark.parametrize("port,service,scheme", [
    ({"port": 443}, "", "https"), ({"port": 8080}, "", "http"), ({"port": 22}, "ssh", None), ({"port": 9999}, "ssl/http", "https"),
])
def test_web_scheme(port, service, scheme):
    assert ports.web_scheme({**port, "service": service}) == scheme


# ---------- WWW ----------
def _titles(found):
    return {f[1] for f in found}


def test_header_findings_for_bare_http_site():
    t = _titles(web.header_findings("http://a.com", 200, {"x-powered-by": "PHP/8.1"}, server="nginx/1.25", title="Admin login"))
    assert "Usługa dostępna po nieszyfrowanym HTTP bez przekierowania" in t
    assert "Brak nagłówka Content-Security-Policy" in t
    assert "Ujawnienie technologii w nagłówku X-Powered-By" in t
    assert "Ujawnienie wersji oprogramowania w nagłówku Server" in t
    assert "Potencjalny panel administracyjny/logowania dostępny publicznie" in t
    assert "Brak nagłówka HSTS" not in t  # HSTS dotyczy tylko HTTPS


def test_header_findings_for_hardened_site():
    hdr = {"strict-transport-security": "max-age=1", "content-security-policy": "frame-ancestors 'none'",
           "x-content-type-options": "nosniff"}
    assert web.header_findings("https://a.com", 200, hdr, server="nginx") == []


@pytest.mark.parametrize("days,expected", [(-3, "high"), (10, "medium"), (90, None)])
def test_cert_days_finding(days, expected):
    f = web.cert_days_finding(days)
    assert (f[0] if f else None) == expected


def test_parse_sslyze_and_testssl():
    j = {"server_scan_results": [{"scan_result": {
        "tls_1_0_cipher_suites": {"result": {"accepted_cipher_suites": [1]}},
        "heartbleed": {"result": {"is_vulnerable_to_heartbleed": True}}}}]}
    assert {f[0] for f in web.parse_sslyze(j, "h:443")} == {"medium", "critical"}
    assert web.parse_sslyze({}, "h:443") is None
    t = [{"id": "BEAST", "severity": "LOW", "finding": "x"}, {"id": "cert_x", "severity": "HIGH"}, {"id": "ok", "severity": "OK"}]
    assert [f[0] for f in web.parse_testssl(t, "h:443")] == ["low"]


def test_waf_and_whatweb_parsing():
    assert web.waf_from_headers({"cf-ray": "1"}) == "Cloudflare"
    assert web.waf_from_headers({"server": "nginx"}) is None
    assert web.parse_whatweb([{"plugins": {"WordPress": {"version": ["6.4"]}, "IP": {}}}]) == ["WordPress 6.4"]


# ---------- DNS ----------
def test_dangling_finding():
    assert dns.dangling_finding("a.x.com", ["foo.github.io"], False, False)[0] == "high"
    assert dns.dangling_finding("a.x.com", [], False, False)[0] == "low"
    assert dns.dangling_finding("x.com", [], False, True) is None
    assert dns.dangling_finding("a.x.com", ["foo.github.io"], True, False) is None


def test_axfr_response_parsing():
    assert dns.axfr_query("example.com")[:2] == b"AS"
    ok = b"AS\x84\x00\x00\x01\x00\x05" + b"\x00" * 4
    refused = b"AS\x84\x05\x00\x01\x00\x00" + b"\x00" * 4
    assert dns.axfr_response_ok(ok) and not dns.axfr_response_ok(refused) and not dns.axfr_response_ok(b"")


# ---------- historia i alerty ----------
def test_compare_is_pure():
    d = history.compare([{"id": "a"}, {"id": "b"}], [{"asset": "a", "title": "X"}], [{"id": "a"}], [{"asset": "a", "title": "Y"}])
    assert d == {"new_assets": ["b"], "removed_assets": [], "new_findings": [{"asset": "a", "title": "X"}],
                 "resolved_findings": [{"asset": "a", "title": "Y"}]}


def test_evaluate_score_jump():
    diff = {"against_score": 10, "new_findings": [], "new_assets": []}
    assert alerts.evaluate(25, [], diff)[0] == "warn"
    assert alerts.evaluate(15, [], diff) is None


def test_webhook_failure_does_not_break_alert(monkeypatch):
    monkeypatch.setenv("ASI_WEBHOOK_URL", "http://127.0.0.1:9/hook")
    calls = []

    def boom(url, payload):
        calls.append(url)
        raise OSError("down")
    monkeypatch.setattr(alerts.net, "post_json", boom)
    sid = seed_scan("example.com")
    alerts.add(sid, "example.com", "warn", "x")
    assert calls == ["http://127.0.0.1:9/hook"] and alerts.recent()["unread"] == 1


# ---------- migracje ----------
def test_migrates_legacy_database(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE schedules(id INTEGER PRIMARY KEY, target TEXT UNIQUE, nuclei INTEGER, interval_hours INTEGER,"
                    " enabled INTEGER, created REAL, last_run REAL, next_run REAL, deep INTEGER NOT NULL DEFAULT 0);")
    c.close()
    monkeypatch.setenv("ASI_DB", str(path))
    db.init()
    assert db.schema_version() == db.SCHEMA_VERSION
    db.init()  # idempotentne
    assert db.schema_version() == db.SCHEMA_VERSION


def test_refuses_newer_schema(monkeypatch, tmp_path):
    path = tmp_path / "future.db"
    sqlite3.connect(path).execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
    monkeypatch.setenv("ASI_DB", str(path))
    with pytest.raises(RuntimeError):
        db.init()


def test_config_flags(monkeypatch):
    monkeypatch.setenv("ASI_SCHEDULER", "0")
    monkeypatch.setenv("ASI_ALLOWED_TARGETS", " A.com, b.org ,")
    cfg = config.load()
    assert cfg.scheduler_enabled is False and cfg.allowed_targets == ("a.com", "b.org")


# ---------- pipeline i kolejka ----------
def _ctx(target="example.com", opts=None):
    sid = scans_repo.create(target, targets.range_hash([target]), opts or {}, [target])
    return context.Ctx(sid)


def test_ctx_rejects_unknown_severity():
    with pytest.raises(ValueError):
        _ctx().finding("domain:example.com", "urgent!", "x", "builtin")


def test_ctx_deduplicates_findings():
    ctx = _ctx()
    ctx.finding("a", "low", "T", "builtin")
    ctx.finding("a", "high", "T", "builtin")
    assert ctx.db.severities() == ["low"]


def test_pipeline_isolates_optional_stage_failures():
    ctx = _ctx()
    ran = []

    def boom(c, st):
        raise RuntimeError("zewnętrzne API leży")
    stages = [pipeline.Stage("Opcjonalny", boom, required=False),
              pipeline.Stage("Pominięty", lambda c, st: ran.append("skip"), applies=lambda c, st: "powód pominięcia"),
              pipeline.Stage("Wymagany", lambda c, st: ran.append("ok"))]
    pipeline.run(ctx, {}, stages)
    log = scans_repo.load(ctx.id)[0]["log"]
    assert ran == ["ok"] and "etap przerwany: RuntimeError" in log and "powód pominięcia" in log


def test_pipeline_required_stage_failure_propagates():
    def boom(c, st):
        raise RuntimeError("x")
    with pytest.raises(RuntimeError):
        pipeline.run(_ctx(), {}, [pipeline.Stage("Wymagany", boom)])


def test_runner_end_to_end(monkeypatch):
    """Pocisk smugowy: zlecenie -> wątek -> pipeline -> wynik w bazie -> alert, bez sieci."""
    def fake_run(ctx, tools):
        ctx.asset("domain", ctx.target)
        ctx.finding("domain:example.com", "critical", "Krytyczny problem", "builtin")
    monkeypatch.setattr(runner.pipeline, "run", fake_run)
    monkeypatch.setattr(runner.tools, "status", dict)
    done = threading.Event()
    real = runner.run_scan
    monkeypatch.setattr(runner, "run_scan", lambda sid: (real(sid), done.set()))
    sid, errors = runner.start_scan(["example.com"], {})
    assert errors == []
    assert done.wait(10)
    s, *_ = history.load(sid)
    assert s["status"] == "done" and s["score"] == domain.risk_score(["critical"])
    assert alerts.recent()["items"][0]["level"] == "bad"


def test_runner_marks_failed_and_alerts_for_schedules(monkeypatch):
    def fake_run(ctx, tools):
        raise RuntimeError("awaria")
    monkeypatch.setattr(runner.pipeline, "run", fake_run)
    monkeypatch.setattr(runner.tools, "status", dict)
    sid = scans_repo.create("example.com", targets.range_hash(["example.com"]), {"schedule_id": 1}, ["example.com"])
    runner.run_scan(sid)
    assert history.load(sid)[0]["status"] == "failed"
    assert alerts.recent()["items"][0]["message"] == "Automatyczne sprawdzenie nie powiodło się."


def test_runner_rejects_scan_without_valid_targets():
    with pytest.raises(InvalidInput):
        runner.start_scan(["nie domena", ""], {})


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok", "schema": db.SCHEMA_VERSION, "expected_schema": db.SCHEMA_VERSION}


def test_interrupted_scans_marked_failed_on_startup(monkeypatch):
    from fastapi.testclient import TestClient

    from asi.main import app
    sid = seed_scan("example.com", status="running")
    monkeypatch.setenv("ASI_SCHEDULER", "0")
    with TestClient(app):
        pass
    assert history.load(sid)[0]["status"] == "failed"
