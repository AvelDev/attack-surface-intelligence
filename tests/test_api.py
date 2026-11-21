from tests.conftest import seed_scan


def test_index_serves_ui(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "<div id=\"root\">" in r.text or "root" in r.text


def test_scan_requires_authorization(client, started):
    r = client.post("/api/scans", json={"target": "example.com"})
    assert r.status_code == 400
    assert started == []


def test_scan_rejects_invalid_target(client, started):
    r = client.post("/api/scans", json={"target": "not a domain", "authorized": True})
    assert r.status_code == 400
    assert started == []


def test_scan_is_created_and_listed(client, started):
    r = client.post("/api/scans", json={"target": "https://Example.com/path", "authorized": True, "deep": True})
    assert r.status_code == 200
    sid = r.json()["id"]
    assert started == [sid]
    rows = client.get("/api/scans").json()
    assert rows[0]["id"] == sid and rows[0]["target"] == "example.com" and rows[0]["status"] == "queued"


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


def test_delete_scan(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "low", "A")])
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_cannot_delete_running_scan(client):
    sid = seed_scan("example.com", status="running")
    assert client.delete(f"/api/scans/{sid}").status_code == 409


def test_csv_export_neutralizes_formulas(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "low", "=HYPERLINK(1)")])
    r = client.get(f"/api/scans/{sid}/export.csv")
    assert r.status_code == 200
    assert "'=HYPERLINK(1)" in r.text


def test_json_export_has_no_log(client):
    sid = seed_scan("example.com")
    j = client.get(f"/api/scans/{sid}/export.json").json()
    assert "log" not in j["scan"]


def test_report_escapes_html_and_shows_verdict(client):
    sid = seed_scan("example.com", findings=[("domain:example.com", "critical", "<script>x</script>")])
    r = client.get(f"/api/scans/{sid}/report")
    assert "<script>x</script>" not in r.text
    assert "&lt;script&gt;" in r.text
    assert "Wymaga pilnej uwagi" in r.text


def test_schedule_lifecycle(client, started):
    r = client.post("/api/schedules", json={"target": "example.com", "authorized": True, "interval_hours": 24})
    assert r.status_code == 200
    hid = r.json()["id"]
    assert started == [r.json()["scan_id"]]  # pierwszy skan od razu
    assert client.post("/api/schedules", json={"target": "example.com", "authorized": True,
                                               "interval_hours": 24}).status_code == 409
    listing = client.get("/api/schedules").json()
    assert listing["items"][0]["id"] == hid and "24" in {str(k) for k in listing["intervals"]}
    assert client.patch(f"/api/schedules/{hid}", json={"enabled": False}).status_code == 200
    assert client.get("/api/schedules").json()["items"][0]["enabled"] == 0
    assert client.delete(f"/api/schedules/{hid}").status_code == 200
    assert client.delete(f"/api/schedules/{hid}").status_code == 404


def test_schedule_validation(client):
    assert client.post("/api/schedules", json={"target": "example.com", "interval_hours": 24}).status_code == 400
    assert client.post("/api/schedules", json={"target": "example.com", "authorized": True,
                                               "interval_hours": 5}).status_code == 400


def test_settings_never_return_values(client):
    assert client.put("/api/settings/nvd_api_key", json={"value": "secret-key-123"}).status_code == 200
    body = client.get("/api/settings").text
    assert "secret-key-123" not in body
    nvd = next(i for i in client.get("/api/settings").json() if i["key"] == "nvd_api_key")
    assert nvd["set"] is True and nvd["source"] == "db"
    assert client.delete("/api/settings/nvd_api_key").status_code == 200
    assert client.put("/api/settings/nvd_api_key", json={"value": "zła wartość"}).status_code == 400
    assert client.put("/api/settings/unknown", json={"value": "abcdefgh"}).status_code == 400
    assert client.delete("/api/settings/unknown").status_code == 404


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
    assert {"nmap", "httpx", "nuclei", "testssl"} <= set(j)
    assert all(set(v) == {"installed", "path"} for v in j.values())
