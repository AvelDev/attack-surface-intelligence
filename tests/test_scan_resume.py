"""Prawdziwe wznowienie skanu po oknie czasowym (asi/scanner.py: Ctx.*_checkpoint,
batched_port_scan, pipeline). Przed tą zmianą 'paused_window' startował cały skan od
zera przy kolejnym przebiegu - te testy pilnują, żeby to się nie powtórzyło po cichu
(docs/architektura.md §10, CURSOR_HANDOFF.md §3.1).

Używa prawdziwej (tymczasowej) bazy SQLite - fixture'y w conftest.py. Narzędzia zewnętrzne
(naabu/nmap/httpx) są zawsze zastąpione - to testuje logikę checkpointu, nie same skanery
portów/HTTP (to pokrywają istniejące testy end-to-end/smoke test Dockera).
"""
import pytest

from asi import scanner

FAKE_TOOLS = {t: {"installed": False, "path": ""} for t in
              ("nmap", "naabu", "subfinder", "dnsx", "httpx", "nuclei")}


def test_checkpoint_roundtrip_and_merge(make_ctx):
    ctx = make_ctx(["10.0.0.1"])
    assert ctx.load_checkpoint() is None
    ctx.save_checkpoint(a=1, b=2)
    assert ctx.load_checkpoint() == {"a": 1, "b": 2}
    ctx.save_checkpoint(b=3)  # merge, nie zastąpienie całości
    assert ctx.load_checkpoint() == {"a": 1, "b": 3}
    ctx.clear_checkpoint()
    assert ctx.load_checkpoint() is None


def test_finish_preserves_checkpoint_only_for_paused_window(make_ctx):
    paused = make_ctx(["10.0.0.1"])
    paused.save_checkpoint(pending_ips=["10.0.0.1"])
    paused.finish("paused_window")
    assert paused.load_checkpoint() == {"pending_ips": ["10.0.0.1"]}

    done = make_ctx(["10.0.0.2"])
    done.save_checkpoint(pending_ips=["10.0.0.2"])
    done.finish("done")
    assert done.load_checkpoint() is None


def test_batched_port_scan_checkpoints_each_batch_and_resumes(make_ctx, monkeypatch):
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    ctx = make_ctx(ips)
    ctx.hosts_total(len(ips))
    ctx.save_checkpoint(hosts_total=len(ips))

    def fake_scan_ports(_ctx, chunk, _tools, rate=None):
        found = {ip: [{"port": 22, "service": "ssh", "version": ""}] for ip in chunk}
        return found, set(chunk)

    monkeypatch.setattr(scanner, "scan_ports", fake_scan_ports)

    calls = {"n": 0}

    def raising_time_limit():
        calls["n"] += 1
        if calls["n"] >= 2:  # 1. wywołanie (paczka "10.0.0.1") przechodzi, 2. już nie
            raise TimeoutError("okno czasowe (test)")

    monkeypatch.setattr(ctx, "check_time_limit", raising_time_limit)

    with pytest.raises(TimeoutError):
        scanner.batched_port_scan(ctx, ips, FAKE_TOOLS, start_batch=1)

    cp = ctx.load_checkpoint()
    assert cp["pending_ips"] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"], \
        "checkpoint musi odzwierciedlać stan PRZED przerwaną paczką, nie po niej"

    done_so_far = scanner._reload_scanned_ports(ctx)
    assert set(done_so_far) == {"10.0.0.1"}, \
        "paczka, która ZDĄŻYŁA się wykonać, musi być w bazie, mimo że cały skan przerwano"

    # --- wznowienie: kontynuuj tylko z checkpointu, bez ograniczenia czasowego ---
    monkeypatch.setattr(ctx, "check_time_limit", lambda: None)
    cp = ctx.load_checkpoint()
    total = cp["hosts_total"]
    done_offset = total - len(cp["pending_ips"])
    assert done_offset == 1

    scanner.batched_port_scan(ctx, cp["pending_ips"], FAKE_TOOLS, start_batch=1, done_offset=done_offset)

    assert ctx.load_checkpoint().get("pending_ips") is None, "faza w całości zrobiona po wznowieniu"
    all_ports = scanner._reload_scanned_ports(ctx)
    assert set(all_ports) == set(ips), "wszystkie 4 hosty muszą mieć porty - te z pierwszego i z drugiego przebiegu"


def test_pipeline_resume_skips_already_done_phases(make_ctx, monkeypatch):
    """Port-scan się w całości skończył, ale pipeline przerywa na kolejnym etapie (HTTP) -
    wznowienie NIE może ponownie liczyć hosts_total/enumeracji (to by znaczyło restart od zera)."""
    ips = ["10.0.0.1", "10.0.0.2"]
    ctx = make_ctx(ips)

    def fake_scan_ports(_ctx, chunk, _tools, rate=None):
        return {ip: [{"port": 22, "service": "ssh", "version": ""}] for ip in chunk}, set(chunk)

    monkeypatch.setattr(scanner, "scan_ports", fake_scan_ports)
    monkeypatch.setattr(scanner, "tool_status", lambda: FAKE_TOOLS)

    calls = {"n": 0}

    def raise_on_third_call():
        calls["n"] += 1
        if calls["n"] >= 3:  # stage("Skan portów")=1, batched_port_scan=2, stage("HTTP")=3
            raise TimeoutError("okno czasowe (test)")

    monkeypatch.setattr(ctx, "check_time_limit", raise_on_third_call)

    with pytest.raises(TimeoutError):
        scanner.pipeline(ctx)

    cp = ctx.load_checkpoint()
    assert cp.get("pending_ips") is None, "port-scan się w całości skończył przed przerwaniem na HTTP"
    assert set(scanner._reload_scanned_ports(ctx)) == set(ips), \
        "porty obu hostów muszą być w bazie, mimo że CAŁY pipeline zgłosił TimeoutError później"

    # --- wznowienie ---
    monkeypatch.setattr(ctx, "check_time_limit", lambda: None)

    def boom():
        raise AssertionError("hosts_total nie powinien być przeliczany ponownie przy wznowieniu")

    monkeypatch.setattr(ctx, "hosts_total", boom)

    scanner.pipeline(ctx)  # nie powinno rzucić - dokończa z checkpointu, nie od zera


def test_resume_claim_is_atomic_not_select_then_update(temp_db):
    """Regresja (security review, TOCTOU): POST /api/scans/{id}/resume i gałąź wznowienia w
    _scheduler_loop (asi/main.py) claim'ują paused_window atomowo (UPDATE ... WHERE
    status='paused_window', sprawdzane rowcount), nie SELECT-potem-UPDATE - inaczej dwa
    równoległe wywołania (ręczne /resume + harmonogram, albo dwa kliknięcia) mogłyby oba
    przejść walidację i wystartować DWA wątki run_scan dla tego samego scan_id, ścigające się
    o checkpoint. Ten test odtwarza dokładnie zapytanie z main.py."""
    import json
    import time

    CLAIM_SQL = "UPDATE scans SET status='queued', stage='wznowienie' WHERE id=? AND status='paused_window'"

    with temp_db.conn() as c:
        sid = c.execute(
            "INSERT INTO scans(target,target_hash,opts,created,status) VALUES(?,?,?,?,?)",
            ("10.0.0.1", "", json.dumps({}), time.time(), "paused_window")).lastrowid

    with temp_db.conn() as c:
        first = c.execute(CLAIM_SQL, (sid,))
        assert first.rowcount == 1, "pierwszy caller musi wygrać wyścig o wznowienie"

    with temp_db.conn() as c:
        second = c.execute(CLAIM_SQL, (sid,))
        assert second.rowcount == 0, "drugi (jednoczesny) caller NIE może też wygrać - status już nie jest paused_window"
        status = c.execute("SELECT status FROM scans WHERE id=?", (sid,)).fetchone()["status"]
        assert status == "queued", "wygrany claim musi zostać widoczny dla kolejnego sprawdzenia"
