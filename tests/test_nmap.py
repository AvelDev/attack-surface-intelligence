"""Nmap: walidacja opcji, budowa komendy, zasady NSE, parser XML i droga wyniku do bazy (narzędzie zastąpione atrapą)."""
import json

import pytest

from asi import db
from asi.errors import InvalidInput
from asi.nmap import command, options, parser, policy, rules, scripts
from asi.repo import scans as scans_repo
from asi.scan import nmap_scan, ports, proc
from tests.conftest import login_as

RAW = command.Capabilities(raw=True)
XML = """<?xml version="1.0"?><!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS" start="100" version="7.95"><scaninfo type="syn" protocol="tcp"/>
<host starttime="1"><status state="up" reason="echo-reply"/><address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Cisco"/><hostnames><hostname name="a.lab" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="900"><extrareasons reason="no-response" count="900" proto="tcp"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6" extrainfo="protocol 2.0"
 ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6</cpe></service></port>
<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" method="table"/>
<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>
<port protocol="tcp" portid="25"><state state="open" reason="syn-ack"/><service name="tcpwrapped"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/><service name="http"/></port>
<port protocol="udp" portid="161"><state state="open" reason="udp-response"/><service name="snmp" method="probed"/></port></ports>
<os><osmatch name="Linux 5.4" accuracy="96"><osclass type="general purpose" osfamily="Linux"><cpe>cpe:/o:linux:linux_kernel:5.4</cpe></osclass></osmatch></os>
<uptime seconds="3600"/><distance value="2"/>
<hostscript><script id="smb-vuln-ms17-010" output="VULNERABLE: Risk factor: HIGH"><table key="CVE-2017-0143">
<elem key="title">Remote Code Execution in SMBv1</elem><elem key="state">VULNERABLE</elem><table key="ids"><elem>CVE:CVE-2017-0143</elem></table>
</table></script></hostscript>
<trace><hop ttl="1" ipaddr="10.0.0.254" rtt="0.50" host="gw"/><hop ttl="2" ipaddr="10.0.0.1" rtt="0.90"/></trace></host>
<host><status state="up" reason="user-set"/><address addr="10.0.0.2" addrtype="ipv4"/>
<ports><extraports state="filtered" count="1000"><extrareasons reason="no-response" count="1000" proto="tcp"/></extraports></ports></host>
<runstats><finished elapsed="4.2" exit="success"/></runstats></nmaprun>"""


def opts(**kw):
    return options.parse(kw)


def args(**kw):
    return command.build(opts(**kw), RAW, 300)


# ---------- opcje ----------
@pytest.mark.parametrize("bad", [
    {"oX": "/etc/passwd"}, {"ports": "22;id", "port_mode": "range"}, {"ports": "70000", "port_mode": "range"}, {"ports": "90-80", "port_mode": "range"},
    {"ports": "22,,80", "port_mode": "range"}, {"ports": "T:", "port_mode": "range"}, {"ports": "-oN x", "port_mode": "range"},
    {"port_mode": "range"}, {"techniques": ["syn", "ack"]}, {"techniques": ["protocol", "udp"]}, {"techniques": ["idle"]}, {"techniques": []},
    {"mode": "hosts"}, {"discovery": "custom"}, {"prescan": True, "techniques": ["udp"]}, {"prescan": True, "port_mode": "range", "ports": "U:53"},
    {"scripts": ["../evil"]}, {"scripts": ["a,b"]}, {"script_categories": ["default and all"]}, {"mtu": 10}, {"fragment": True, "mtu": 8},
    {"script_args": {"newtargets": "1"}}, {"script_args": {"userdb": "/etc/passwd"}}, {"script_args": {"http.useragent": "x',newtargets='1"}},
    {"script_args": {"http.useragent": "a\n"}}, {"timing": 6}, {"scanflags": ["SYN"], "techniques": ["connect"]}, {"exclude_ports": "T:80"},
    {"techniques": ["protocol"], "port_mode": "range", "ports": "300"}, {"techniques": ["protocol"], "port_mode": "all", "version": True},
])
def test_options_reject_invalid(bad):
    with pytest.raises(InvalidInput, match="Opcje nmap"):
        options.parse(bad)


@pytest.mark.parametrize("spec", ["22", "1-1024", "-100", "60000-", "-", "T:80,U:53,161"])
def test_options_accept_nmap_port_grammar(spec):
    out = args(port_mode="range", ports=spec, techniques=["syn", "udp"])
    assert out[out.index("-p") + 1] == spec


@pytest.mark.parametrize("name", options.PROFILES)
def test_profiles_survive_storage_and_build(name):
    p = options.PROFILES[name]
    again = options.parse(json.loads(json.dumps(options.dump(p))))
    assert again == p
    assert command.build(again, RAW, 300)


def test_changed_profile_is_labelled_custom():
    assert options.parse({**options.dump(options.PROFILES["full"]), "timing": 1}).profile == "custom"


# ---------- komenda ----------
def test_command_default_is_top_ports_without_discovery():
    assert args() == ["-Pn", "-sS", "--top-ports", "100", "-n", "-T3", "--max-rate", "300"]


def test_command_full_profile():
    out = command.build(options.PROFILES["full"], RAW, 1000)
    for flag in ("-p-", "-sV", "-O", "--osscan-guess", "--traceroute", "--script", "-T4"):
        assert flag in out
    assert out[out.index("--max-rate") + 1] == "1000"


def test_command_host_discovery_never_scans_ports():
    out = command.build(options.PROFILES["discovery"], RAW, 300)
    assert out[:5] == ["-sn", "-PE", "-PP", "-PS22,80,443,3389", "-PA22,80,443,3389"]
    assert "-p" not in out and "--top-ports" not in out


def test_min_rate_never_exceeds_scan_limit():
    out = args(min_rate=5000)
    assert out[out.index("--min-rate") + 1] == "300"


def test_prescan_limits_nmap_to_found_ports():
    out = command.build(options.PROFILES["service"], RAW, 300, only_ports={443, 22})
    assert out[out.index("-p") + 1] == "22,443" and "--top-ports" not in out


def test_unprivileged_server_degrades_or_refuses():
    adapted, dropped = command.adapt(options.PROFILES["full"], command.Capabilities())
    assert adapted.techniques == ["connect"] and not adapted.os and not adapted.traceroute
    assert dropped == ["-sS", "-O", "--traceroute"]
    with pytest.raises(InvalidInput, match="-sU"):
        command.adapt(options.PROFILES["udp"], command.Capabilities())


def test_min_time_includes_gaps_imposed_by_timing():
    assert command.min_seconds(opts(top_ports=1000), 500) == 2
    assert command.min_seconds(opts(top_ports=1000, timing=1), 500) == 15000
    assert command.min_seconds(opts(top_ports=1000, scan_delay_ms=100), 500) == 100


def test_heavy_scan_gets_small_batches():
    assert command.start_batch(options.PROFILES["service"]) == 200
    assert command.start_batch(options.PROFILES["full"]) == 4


# ---------- NSE ----------
@pytest.fixture
def nse(monkeypatch):
    db_text = ('Entry { filename = "http-title.nse", categories = { "default", "safe", } }\n'
               'Entry { filename = "ssh-brute.nse", categories = { "brute", "intrusive", } }\n'
               'Entry { filename = "whois-ip.nse", categories = { "discovery", "external", "safe", } }\n'
               'Entry { filename = "broadcast-ping.nse", categories = { "discovery", "safe", "broadcast", } }\n')
    known = scripts.parse_db(db_text)
    monkeypatch.setattr(scripts, "catalog", lambda: known)
    return known


def test_category_never_pulls_in_gated_scripts():
    expr = policy.script_expression(opts(script_categories=["vuln", "safe"], scripts=["http-title"]))
    assert expr == "(vuln or safe) and not (brute or exploit or dos or fuzzer or external or broadcast),http-title"


@pytest.mark.parametrize("kw,gated,external,ok", [
    ({"script_categories": ["vuln"]}, False, False, True), ({"script_categories": ["brute"]}, False, False, False),
    ({"script_categories": ["brute"]}, True, False, True), ({"script_categories": ["external"]}, True, False, False),
    ({"script_categories": ["broadcast"]}, True, True, False), ({"script_categories": ["nope"]}, True, True, False),
    ({"scripts": ["http-title"]}, False, False, True), ({"scripts": ["ssh-brute"]}, False, False, False), ({"scripts": ["ssh-brute"]}, True, False, True),
    ({"scripts": ["whois-ip"]}, True, False, False), ({"scripts": ["whois-ip"]}, False, True, True),
    ({"scripts": ["broadcast-ping"]}, True, True, False), ({"scripts": ["unknown-script"]}, True, True, False),
])
def test_policy(nse, kw, gated, external, ok):
    if ok:
        return policy.check(opts(**kw), gated=gated, external=external)
    with pytest.raises(InvalidInput):
        policy.check(opts(**kw), gated=gated, external=external)


def test_restrict_drops_what_server_no_longer_allows(nse):
    kept, dropped = policy.restrict(opts(script_categories=["default", "brute"], scripts=["ssh-brute", "http-title"]), gated=False, external=False)
    assert kept.script_categories == ["default"] and kept.scripts == ["http-title"]
    assert dropped == ["brute", "ssh-brute"]


# ---------- parser ----------
def test_parse_full_host():
    run = parser.parse(XML)
    assert run["complete"] and run["elapsed"] == 4.2 and [h["ip"] for h in run["hosts"]] == ["10.0.0.1", "10.0.0.2"]
    h = run["hosts"][0]
    assert h["mac"] == "AA:BB:CC:00:11:22" and h["vendor"] == "Cisco" and h["hostnames"] == ["a.lab"]
    assert h["os"][0]["name"] == "Linux 5.4" and h["distance"] == 2 and h["uptime_s"] == 3600 and len(h["trace"]) == 2
    assert [(p["port"], p["proto"]) for p in h["ports"]] == [(22, "tcp"), (21, "tcp"), (161, "udp")], "bez zamkniętych i tcpwrapped"
    ssh = h["ports"][0]
    assert ssh["version"] == "OpenSSH 9.6" and ssh["probed"] and ssh["cpe"] == ["cpe:/a:openbsd:openssh:9.6"] and ssh["info"] == "protocol 2.0"
    assert [(s["state"], s["count"]) for s in h["states"]] == [("filtered", 900), ("closed", 1)]


def test_parse_keeps_complete_hosts_of_interrupted_scan():
    run = parser.parse(XML[:XML.index("<runstats>") - 40])
    assert [h["ip"] for h in run["hosts"]] == ["10.0.0.1"] and not run["complete"]


@pytest.mark.parametrize("bad", ["", "nie xml", "<html><host/></html>", '<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>'])
def test_parse_rejects_other_files(bad):
    with pytest.raises(parser.BadXml):
        parser.parse(bad)


def test_merge_batches_into_one_document():
    one = parser.parse(parser.merge([XML, XML[:XML.index("<runstats>") - 40]]))
    assert [h["ip"] for h in one["hosts"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.1"]
    assert parser.merge([]) is None


def test_responded_ignores_assumed_up_hosts():
    up, assumed = parser.parse(XML)["hosts"]
    assert nmap_scan.responded(up) and not nmap_scan.responded(assumed)


# ---------- ustalenia ----------
def test_vuln_library_result_becomes_finding():
    sev, title, source, _detail, _fix = rules.findings(parser.parse(XML)["hosts"][0]["scripts"])[0]
    assert (sev, title, source) == ("high", "Remote Code Execution in SMBv1 (CVE-2017-0143)", "nmap")


def test_not_vulnerable_is_silent():
    assert rules.findings([{"id": "x", "output": "", "data": {"CVE-1": {"state": "NOT VULNERABLE", "title": "t"}}}]) == []


def test_vulners_severity_from_highest_cvss():
    data = {"cpe:/a:x": [{"id": "CVE-2020-1", "cvss": "5.0"}, {"id": "CVE-2021-2", "cvss": "9.8"}, {"id": "EXP-1", "cvss": "10"}]}
    (sev, _t, _s, detail, _f), = rules.findings([{"id": "vulners", "output": "", "data": data}])
    assert sev == "critical" and "2 CVE" in detail


def test_port_value_keeps_tcp_ids_stable():
    assert ports.port_value("1.2.3.4", {"port": 80}) == "1.2.3.4:80"
    assert ports.port_value("1.2.3.4", {"port": 53, "proto": "udp"}) == "1.2.3.4:53/udp"
    assert ports.web_scheme({"port": 443, "proto": "udp", "service": "https"}) is None


# ---------- od komendy do bazy ----------
TOOLS = {"nmap": {"installed": True, "path": "nmap"}, "naabu": {"installed": False, "path": None}}


@pytest.fixture
def fake_nmap(monkeypatch):
    calls = []

    def run_stream(ctx, cmd, timeout, stdin="", on_line=None):
        calls.append((cmd, stdin.split()))
        with open(cmd[cmd.index("-oX") + 1], "w", encoding="utf-8") as f:
            f.write(XML)
        return 0

    monkeypatch.setattr(nmap_scan, "run_stream", run_stream)
    monkeypatch.setattr(nmap_scan, "nmap_capabilities", lambda path: (RAW, "7.95"))
    monkeypatch.setattr(ports, "_verify", lambda ip, port, timeout=4: (port != 21, ""))
    return calls


def test_scan_stores_ports_host_data_findings_and_raw_xml(make_ctx, fake_nmap):
    ctx = make_ctx(["10.0.0.1", "10.0.0.2"], {"nmap": {"techniques": ["syn", "udp"]}})
    found, answered = ports.batched_port_scan(ctx, ["10.0.0.1", "10.0.0.2"], TOOLS)
    assert [p["port"] for p in found["10.0.0.1"]] == [22, 161], "21 niepotwierdzony banerem odpada, UDP i rozpoznane zostają"
    assert answered == {"10.0.0.1"}
    _s, assets, edges, findings = scans_repo.load(ctx.id)
    by_id = {a["id"]: a for a in assets}
    assert by_id["ip:10.0.0.1"]["data"]["os"][0]["name"] == "Linux 5.4"
    assert by_id["port:10.0.0.1:161/udp"]["data"]["service"] == "snmp"
    assert {"src": "ip:10.0.0.1", "dst": "port:10.0.0.1:161/udp"} in edges
    assert {("port:10.0.0.1:161/udp", "SNMP wystawiony do internetu"),
            ("ip:10.0.0.1", "Remote Code Execution in SMBv1 (CVE-2017-0143)")} <= {(f["asset"], f["title"]) for f in findings}
    run, = scans_repo.nmap_runs(ctx.id)
    assert run["hosts"] == 2 and run["hosts_up"] == 1 and run["complete"]
    assert scans_repo.nmap_xml(ctx.id) == [XML]
    with db.conn() as c:
        assert "OpenSSH" not in c.execute("SELECT xml FROM nmap_runs").fetchone()["xml"], "surowy wynik musi leżeć zaszyfrowany"
    scans_repo.delete(ctx.id)
    assert scans_repo.nmap_runs(ctx.id) == []


def test_prescan_runs_nmap_only_on_hosts_with_ports(make_ctx, fake_nmap, monkeypatch):
    monkeypatch.setattr(ports.tools_mod, "naabu_can_syn", lambda path: True)
    monkeypatch.setattr(ports, "run_cmd", lambda *a, **k: '{"ip":"10.0.0.1","port":22}\n{"ip":"10.0.0.1","port":8443}')
    ctx = make_ctx(["10.0.0.1", "10.0.0.2"], {"nmap": options.dump(options.PROFILES["service"])})
    found, _ = ports.scan_ports(ctx, ["10.0.0.1", "10.0.0.2"], {**TOOLS, "naabu": {"installed": True, "path": "naabu"}})
    cmd, targets = fake_nmap[0]
    assert targets == ["10.0.0.1"] and cmd[cmd.index("-p") + 1] == "22,8443"
    assert 8443 in [p["port"] for p in found["10.0.0.1"]], "port z naabu potwierdzony banerem zostaje, choć nmap go nie zgłosił"


def test_scan_without_nmap_options_does_not_start_nmap(make_ctx, fake_nmap, monkeypatch):
    monkeypatch.setattr(ports.tools_mod, "naabu_can_syn", lambda path: True)
    monkeypatch.setattr(ports, "run_cmd", lambda *a, **k: "")
    ports.scan_ports(make_ctx(["10.0.0.1"]), ["10.0.0.1"], {**TOOLS, "naabu": {"installed": True, "path": "naabu"}})
    assert fake_nmap == []


def test_run_stream_kills_process_when_scan_is_stopped():
    import sys

    class Ctx:
        calls = 0

        def log(self, msg):
            pass

        def check_time_limit(self):
            self.calls += 1
            if self.calls > 2:
                raise TimeoutError

    with pytest.raises(TimeoutError):
        proc.run_stream(Ctx(), [sys.executable, "-c", "import time; time.sleep(60)"], 60, poll_s=0.1)


# ---------- API ----------
def test_api_scan_stores_validated_options(client, started):
    r = client.post("/api/scans", json={"target": "10.0.0.1", "authorized": True, "nmap": options.dump(options.PROFILES["udp"])})
    assert r.status_code == 200 and started == [r.json()["id"]]
    assert scans_repo.run_info(r.json()["id"])[1]["nmap"]["profile"] == "udp"
    r = client.post("/api/scans", json={"target": "10.0.0.1", "authorized": True, "nmap": {"oX": "x"}})
    assert r.status_code == 400 and "nieznana opcja" in r.json()["detail"]


def test_api_gated_scripts_need_server_setting_and_admin(client, monkeypatch):
    body = {"target": "10.0.0.1", "authorized": True, "nmap": {"script_categories": ["brute"]}}
    assert client.post("/api/scans", json=body).status_code == 400, "bramka zamknięta nawet dla admina"
    monkeypatch.setenv("ASI_NMAP_INTRUSIVE", "1")
    operator = login_as("add_remove_modify")
    assert operator.post("/api/scans", json=body).status_code == 400, "otwarta bramka nie dotyczy operatora"
    sid = client.post("/api/scans", json=body).json()["id"]
    thash = db.raw_connect().execute("SELECT target_hash FROM scans WHERE id=?", (sid,)).fetchone()[0]
    with db.conn() as c:
        c.execute("UPDATE scans SET status='done'")
    assert operator.post(f"/api/ranges/{thash[:12]}/run").status_code == 400, "powtórka przebiegu admina nie omija bramki"


def test_api_schedule_and_file_import_accept_nmap(client):
    r = client.post("/api/schedules", json={"target": "10.0.0.1", "nmap": {"timing": 2}})
    assert r.status_code == 200 and json.loads(client.get("/api/schedules").json()[0]["opts"])["nmap"] == {"timing": 2}
    r = client.post("/api/scans/import-targets", files={"file": ("t.txt", b"10.0.0.1")}, data={"authorized": "true", "nmap": '{"timing": 4}'})
    assert scans_repo.run_info(r.json()["id"])[1]["nmap"] == {"timing": 4}
    r = client.post("/api/scans/import-targets", files={"file": ("t.txt", b"10.0.0.1")}, data={"authorized": "true", "nmap": "{"})
    assert r.status_code == 400


def test_api_preview_matches_scan_command(client, monkeypatch):
    monkeypatch.setattr("asi.api.nmap._nmap", lambda: (True, RAW, "7.95"))
    body = client.post("/api/nmap/preview", json={"options": {"port_mode": "all"}, "rate_limit": 100}).json()
    assert body["command"] == "nmap -Pn -sS -p- -n -T3 --max-rate 100" and body["min_seconds"] == 655.4
    assert login_as("read").post("/api/nmap/preview", json={"options": {}}).status_code == 403


def test_api_describe_and_xml_export(client, make_ctx, fake_nmap):
    d = client.get("/api/nmap").json()
    assert [p["profile"] for p in d["profiles"]] == list(options.PROFILES)
    assert not next(c for c in d["categories"] if c["id"] == "brute")["allowed"]
    ctx = make_ctx(["10.0.0.1"], {"nmap": {"timing": 3}})
    assert client.get(f"/api/scans/{ctx.id}/nmap.xml").status_code == 404
    ports.scan_ports(ctx, ["10.0.0.1"], TOOLS)
    assert len(client.get(f"/api/scans/{ctx.id}/nmap").json()["runs"]) == 1
    assert parser.parse(client.get(f"/api/scans/{ctx.id}/nmap.xml").content)["hosts"][0]["ip"] == "10.0.0.1"
    assert client.get("/api/scans/999999/nmap").status_code == 404


def test_import_nmap_xml(client):
    r = client.post("/api/scans/import-results", files={"file": ("wynik.xml", XML.encode())})
    assert r.status_code == 200 and r.json()["assets"] == 4
    scan = client.get(f"/api/scans/{r.json()['id']}").json()
    assert {"port:10.0.0.1:161/udp", "ip:10.0.0.1"} <= {a["id"] for a in scan["assets"]}
    assert "Anonimowe logowanie FTP" in {f["title"] for f in scan["findings"]}
    assert client.post("/api/scans/import-results", files={"file": ("x.xml", b"<html/>")}).status_code == 400


def test_dashboard_handles_udp_ports(client, make_ctx, fake_nmap):
    ctx = make_ctx(["10.0.0.1"], {"nmap": {"techniques": ["udp"]}})
    ports.batched_port_scan(ctx, ["10.0.0.1"], TOOLS)
    ctx.finish("done")
    r = client.get("/api/dashboard")
    assert r.status_code == 200 and "161/udp" in json.dumps(r.json())
