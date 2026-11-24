"""Kontrakt HTTP: uwierzytelnianie, role, skany, eksporty, harmonogramy, ustawienia, alerty."""
import json
import time

from fastapi.testclient import TestClient

from asi import db, scheduler
from asi.main import app
from asi.repo import scans as scans_repo
from tests.conftest import login_as, seed_scan


# ---------- uwierzytelnianie i role ----------
def test_api_requires_login():
    with TestClient(app) as anon:
        assert anon.get("/api/scans").status_code == 401
        assert anon.get("/api/tools").status_code == 401
        assert anon.get("/api/health").status_code == 200  # healthcheck kontenera działa bez sesji


def test_bad_credentials_rejected(client):
    with TestClient(app) as anon:
        assert anon.post("/api/login", json={"username": "tester", "password": "zle"}).status_code == 401


def test_roles_gate_endpoints(client):
    reader = login_as("read")
    assert reader.get("/api/scans").status_code == 200
    assert reader.post("/api/scans", json={"target": "example.com", "authorized": True}).status_code == 403
    assert reader.get("/api/users").status_code == 403
    assert reader.put("/api/settings/nvd_api_key", json={"value": "abcdefgh"}).status_code == 403
    assert reader.post("/api/settings/defectdojo", json={"url": "http://1.1.1.1", "api_key": "x"}).status_code == 403
    editor = login_as("add_remove_modify")
    assert editor.post("/api/settings/gvm", json={"host": "127.0.0.1", "password": "x"}).status_code == 403


def test_user_management(client):
    assert client.post("/api/users", json={"username": "ala", "password": "pw-123456", "role": "read"}).status_code == 200
    assert client.post("/api/users", json={"username": "ala", "password": "pw-123456", "role": "read"}).status_code == 409
    assert client.post("/api/users", json={"username": "bob", "password": "pw-123456", "role": "zly"}).status_code == 400
    users = client.get("/api/users").json()
    assert "password_hash" not in json.dumps(users)
    me = client.get("/api/me").json()
    mine = next(u for u in users if u["username"] == me["username"])
    assert client.delete(f"/api/users/{mine['id']}").status_code == 400  # nie wolno usunąć samego siebie


# ---------- skany ----------
def test_index_serves_ui(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "root" in r.text


def test_security_headers_on_every_response(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_scan_requires_authorization(client, started):
    assert client.post("/api/scans", json={"target": "example.com"}).status_code == 400
    assert started == []


def test_scan_rejects_invalid_target(client, started):
    assert client.post("/api/scans", json={"target": "not a domain", "authorized": True}).status_code == 400
    assert client.post("/api/scans", json={"authorized": True}).status_code == 400
    assert started == []


def test_scan_rejects_absurd_rate(client, started):
    r = client.post("/api/scans", json={"target": "example.com", "authorized": True, "rate_limit": 10**6})
    assert r.status_code == 400 and started == []


def test_scan_is_created_and_listed(client, started):
    r = client.post("/api/scans", json={"target": "https://Example.com/path", "authorized": True, "deep": True})
    assert r.status_code == 200
    sid = r.json()["id"]
    assert started == [sid]
    rows = client.get("/api/scans").json()
    assert rows[0]["id"] == sid and rows[0]["target"] == "example.com" and rows[0]["status"] == "queued"
    assert client.get(f"/api/scans/{sid}/targets").json() == ["example.com"]
    assert json.loads(scans_repo.load(sid)[0]["opts"])["deep"] is True


def test_cidr_targets_expand_and_report_rejected_entries(client, started):
    r = client.post("/api/scans", json={"targets": ["10.0.0.0/30", "zly cel"], "authorized": True})
    assert r.status_code == 200 and r.json()["warnings"]
    assert client.get(f"/api/scans/{r.json()['id']}/targets").json() == ["10.0.0.1", "10.0.0.2"]


def test_import_targets_from_file(client, started):
    r = client.post("/api/scans/import-targets", data={"authorized": "true"},
                    files={"file": ("cele.csv", b"target\nexample.com\nexample.org\n")})
    assert r.status_code == 200
    assert client.get(f"/api/scans/{r.json()['id']}/targets").json() == ["example.com", "example.org"]
    no_consent = client.post("/api/scans/import-targets", files={"file": ("cele.txt", b"example.com")})
    assert no_consent.status_code == 400


def test_get_scan_returns_counts_diff_and_trend(client):
    seed_scan("example.com", findings=[("domain:example.com", "high", "A")], assets=["domain:example.com"])
    sid = seed_scan("example.com", findings=[("domain:example.com", "critical", "B")],
                    assets=["domain:example.com", "subdomain:www.example.com"])
    j = client.get(f"/api/scans/{sid}").json()
    assert j["counts"]["critical"] == 1 and j["counts"]["high"] == 0
    assert j["diff"]["new_assets"] == ["subdomain:www.example.com"]
    assert j["diff"]["new_findings"] == [{"asset": "domain:example.com", "title": "B"}]
    assert j["diff"]["resolved_findings"] == [{"asset": "domain:example.com", "title": "A"}]
    assert [t["id"] for t in j["trend"]] == [sid - 1, sid]


def test_missing_scan_is_404(client):
    assert client.get("/api/scans/999").status_code == 404
    assert client.get("/api/scans/999/report").status_code == 404
    assert client.delete("/api/scans/999").status_code == 404
    assert client.post("/api/scans/999/stop").status_code == 404
    assert client.post("/api/scans/999/resume").status_code == 404


def test_delete_scan(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "low", "A")])
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_cannot_delete_running_scan(client):
    sid = seed_scan("example.com", status="running")
    assert client.delete(f"/api/scans/{sid}").status_code == 409


def test_stop_and_resume_state_machine(client, started):
    running = seed_scan("example.com", status="running")
    assert client.post(f"/api/scans/{running}/stop").status_code == 200
    assert scans_repo.stop_requested(running)
    done = seed_scan("example.org")
    assert client.post(f"/api/scans/{done}/stop").status_code == 409
    assert client.post(f"/api/scans/{done}/resume").status_code == 409  # nie jest wstrzymany oknem czasowym
    paused = seed_scan("example.net", status="paused_window")
    assert client.post(f"/api/scans/{paused}/resume").status_code == 200
    assert started == [paused] and scans_repo.status(paused) == "queued"
    assert client.post(f"/api/scans/{paused}/resume").status_code == 409  # drugie wznowienie przegrywa wyścig


def test_csv_export_neutralizes_formulas(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "low", "=HYPERLINK(1)")])
    r = client.get(f"/api/scans/{sid}/export.csv")
    assert r.status_code == 200
    assert "'=HYPERLINK(1)" in r.text


def test_json_export_has_no_log(client):
    sid = seed_scan("example.com")
    assert "log" not in client.get(f"/api/scans/{sid}/export.json").json()["scan"]


def test_report_escapes_html_and_shows_verdict(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "critical", "<script>x</script>")])
    r = client.get(f"/api/scans/{sid}/report")
    assert "<script>x</script>" not in r.text
    assert "&lt;script&gt;" in r.text
    assert "Wymaga pilnej uwagi" in r.text


def test_export_then_import_roundtrip(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "high", "A")], assets=["domain:example.com"])
    exported = client.get(f"/api/scans/{sid}/export.json").content
    r = client.post("/api/scans/import-results", files={"file": ("wyniki.json", exported)})
    assert r.status_code == 200 and r.json()["findings"] == 1 and r.json()["assets"] == 1
    assert client.post("/api/scans/import-results", files={"file": ("x.txt", b"x")}).status_code == 400
    assert client.post("/api/scans/import-results", files={"file": ("x.json", b"{}")}).status_code == 400


# ---------- ustalenia i triage ----------
def test_finding_override_and_triage(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "high", "A")])
    rowid = client.get(f"/api/scans/{sid}").json()["findings"][0]["rowid"]
    assert client.patch(f"/api/findings/{rowid}", json={"false_positive": True}).status_code == 200
    f = client.get(f"/api/scans/{sid}").json()["findings"][0]
    assert f["severity"] == "info" and f["title"].startswith("[False Positive]")
    assert client.patch(f"/api/findings/{rowid}", json={"severity": "nie-ma"}).status_code == 400
    assert client.patch("/api/findings/99999", json={"fix": "x"}).status_code == 404
    assert client.post("/api/triage", json={"asset": "a", "key": "k", "status": "ok"}).status_code == 200
    assert client.post("/api/triage", json={"asset": "a", "key": "k", "status": "zly"}).status_code == 400


def test_override_is_applied_to_future_scans(make_ctx):
    from asi.repo import findings as findings_repo
    findings_repo.save_override("ip:1.2.3.4", "Telnet", "low", "naprawa operatora", False)
    ctx = make_ctx(["1.2.3.4"])
    ctx.finding("ip:1.2.3.4", "high", "Telnet", "builtin", "d", "domyślna naprawa")
    f = scans_repo.load(ctx.id)[3][0]
    assert f["severity"] == "low" and f["fix"] == "naprawa operatora"


# ---------- harmonogramy ----------
def test_schedule_lifecycle(client):
    r = client.post("/api/schedules", json={"target": "example.com", "interval_hours": 24, "nuclei": True})
    assert r.status_code == 200
    hid = r.json()["id"]
    row = next(s for s in client.get("/api/schedules").json() if s["id"] == hid)
    assert row["target"] == "example.com" and json.loads(row["opts"])["nuclei"] is True and row["enabled"] == 1
    assert client.patch(f"/api/schedules/{hid}", json={"enabled": False}).status_code == 200
    assert client.get("/api/schedules").json()[0]["enabled"] == 0
    assert client.delete(f"/api/schedules/{hid}").status_code == 200
    assert client.delete(f"/api/schedules/{hid}").status_code == 404


def test_schedule_validation(client):
    assert client.post("/api/schedules", json={"target": "example.com", "interval_hours": 0}).status_code == 400
    assert client.post("/api/schedules", json={"target": "  ", "interval_hours": 24}).status_code == 400


def test_scheduler_runs_due_resumes_paused_and_skips_busy(monkeypatch):
    runs = []
    monkeypatch.setattr(scheduler, "_run_entry", lambda hid, sid, interval: runs.append((hid, sid)))
    paused, busy = seed_scan("p.com", status="paused_window"), seed_scan("b.com", status="running")
    with db.conn() as c:
        for target, last in (("a.com", None), ("p.com", paused), ("b.com", busy)):
            c.execute("INSERT INTO schedules(target, opts, interval_hours, time_window_mins, next_run, last_scan_id) "
                      "VALUES(?, '{}', 24, 60, 0, ?)", (target, last))
        c.execute("INSERT INTO schedules(target, opts, interval_hours, time_window_mins, next_run) VALUES('later.com','{}',24,60,9e18)")
    scheduler.tick(now=1000)
    for _ in range(100):  # wątki robocze startują asynchronicznie
        if len(runs) >= 2:
            break
        time.sleep(0.02)
    scheduled = {sid for _, sid in runs}
    assert paused in scheduled and busy not in scheduled and len(runs) == 2
    assert scans_repo.status(paused) == "queued"  # wznowiony TEN SAM skan, nie nowy
    with db.conn() as c:
        assert c.execute("SELECT next_run FROM schedules WHERE target='a.com'").fetchone()[0] == 1000 + 24 * 3600


# ---------- ustawienia ----------
def test_settings_status_never_returns_secrets(client):
    assert client.put("/api/settings/nvd_api_key", json={"value": "secret-key-123"}).status_code == 200
    body = client.get("/api/settings").text
    assert "secret-key-123" not in body
    nvd = next(i for i in client.get("/api/settings").json()["api_keys"] if i["key"] == "nvd_api_key")
    assert nvd["set"] is True and nvd["source"] == "db"
    with db.conn() as c:  # w bazie klucz leży zaszyfrowany
        assert "secret-key-123" not in c.execute("SELECT value FROM settings WHERE key='nvd_api_key'").fetchone()[0]
    assert client.delete("/api/settings/nvd_api_key").status_code == 200
    assert client.put("/api/settings/nvd_api_key", json={"value": "zła wartość"}).status_code == 400
    assert client.put("/api/settings/unknown", json={"value": "abcdefgh"}).status_code == 400
    assert client.delete("/api/settings/unknown").status_code == 404


def test_integration_settings_validation(client):
    assert client.post("/api/settings/defectdojo", json={"url": "http://127.0.0.1/api", "api_key": "k"}).status_code == 400
    assert client.post("/api/settings/gvm", json={"host": "1.1.1.1", "password": "x"}).status_code == 400
    assert client.post("/api/settings/gvm", json={"host": "127.0.0.1", "port": 99999, "password": "x"}).status_code == 400
    assert client.post("/api/settings/gvm", json={"host": "127.0.0.1", "password": "tajne"}).status_code == 200
    j = client.get("/api/settings").json()
    assert j["gvm_configured"] is True and "tajne" not in json.dumps(j)


# ---------- alerty i narzędzia ----------
def test_alerts_listing_and_read(client):
    from asi import alerts
    sid = seed_scan("example.com")
    alerts.add(sid, "example.com", "bad", "test")
    j = client.get("/api/alerts").json()
    assert j["unread"] == 1 and j["items"][0]["message"] == "test"
    client.post("/api/alerts/read")
    assert client.get("/api/alerts").json()["unread"] == 0


def test_tools_status_lists_every_tool(client):
    j = client.get("/api/tools").json()
    assert {"nmap", "httpx", "nuclei", "testssl", "openvas", "defectdojo"} <= set(j)
    assert all({"installed", "path"} <= set(v) for v in j.values())
    assert "tester" not in json.dumps(j) and "://" not in json.dumps(j).replace("null", "")  # bez danych logowania


def test_dashboard_requires_valid_range_id(client):
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/dashboard", params={"range": "ZLY!"}).status_code == 400
    assert client.put("/api/ranges/zzz/note", json={"note": "x"}).status_code == 400
    assert client.put("/api/ranges/abcdef/note", json={"note": "x"}).status_code == 404
