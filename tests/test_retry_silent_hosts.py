"""Regresja: asi/scanner.py::retry_silent_hosts ponawia TYLKO hosty, które w danym
przebiegu nie dały żadnej odpowiedzi - host z portami odrzuconymi przez verify_ports
(obecny w `answered`) się odezwał, usługa tylko nie potwierdziła się, i nie powinien
wchodzić w tę ścieżkę drugi raz (docs/architektura.md §2/§9).
"""
from asi import scanner


class _FakeCtx:
    def check_time_limit(self):
        pass

    def stage(self, msg):
        pass

    def log(self, msg):
        pass


def test_retries_only_truly_silent_hosts_and_merges_recovered_ports(monkeypatch):
    ports = {
        "10.0.0.1": [],   # silent, nie w answered -> powinien być sprawdzony ponownie
        "10.0.0.2": [80], # miał porty od razu -> nietrafiony przez silny filtr
        "10.0.0.3": [],   # silent, ALE odrzucony przez verify_ports -> w answered, nie ponawiać
        "10.0.0.4": [],   # silent, nie odpowiada też przy drugiej próbie -> zostaje pusty
    }
    answered = {"10.0.0.3"}

    alive = {"10.0.0.1": True, "10.0.0.4": False}

    def fake_host_alive(ctx, ip, gate):
        assert ip in alive, f"sprawdzany host {ip} nie powinien wchodzić w retry"
        return alive[ip]

    def fake_batched_port_scan(ctx, ips, tools, rate=None, track_progress=True):
        assert set(ips) == {"10.0.0.1"}, "tylko hosty, które ożyły przy retry, idą do pełnego skanu"
        assert track_progress is False, "retry nie powinien cofać paska postępu głównego skanu"
        return {"10.0.0.1": [22, 443]}, set()

    monkeypatch.setattr(scanner, "_host_alive", fake_host_alive)
    monkeypatch.setattr(scanner, "batched_port_scan", fake_batched_port_scan)

    out = scanner.retry_silent_hosts(_FakeCtx(), ports, answered, tools={}, rate=None, pause_s=0)

    assert out["10.0.0.1"] == [22, 443], "host, który ożył, musi dostać odzyskane porty"
    assert out["10.0.0.2"] == [80], "host, który miał porty od razu, zostaje bez zmian"
    assert out["10.0.0.3"] == [], "host odrzucony przez verify_ports nie jest dotykany"
    assert out["10.0.0.4"] == [], "host wciąż martwy przy drugiej próbie zostaje pusty"


def test_no_silent_hosts_is_a_noop(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("brak cichych hostów - retry nie powinien robić żadnej pracy sieciowej")

    monkeypatch.setattr(scanner, "_host_alive", boom)
    monkeypatch.setattr(scanner, "batched_port_scan", boom)

    ports = {"10.0.0.1": [80], "10.0.0.2": [443]}
    out = scanner.retry_silent_hosts(_FakeCtx(), ports, answered=set(), tools={}, pause_s=0)
    assert out == ports
