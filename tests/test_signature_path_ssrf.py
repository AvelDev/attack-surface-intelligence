"""Regresja SSRF w sygnaturze 'path_check' (asi/signatures.py::_fetch_path).

Przed poprawką budowa URL przez konkatenację pozwalała ścieżce typu '//evil.com'
albo pełnemu 'http://evil.com' przekierować żądanie na dowolny host. Test sprawdza,
że dla takich wejść funkcja wychodzi ZANIM cokolwiek otworzy sieciowo (monkeypatch
na opener rzuca błąd, jeśli zostanie wywołany), a dla bezpiecznej ścieżki w tym
samym originie - owszem woła sieć, z URL-em, który wciąż jest tym samym host/port.
"""
import urllib.request

import pytest

from asi import signatures

BASE = "http://example.local:8080/report"


def _boom(*a, **k):
    raise AssertionError("SSRF: _fetch_path nie powinien otworzyć sieci dla tego wejścia")


@pytest.mark.parametrize("evil_path", [
    "//evil.example/x",          # protocol-relative -> inny host
    "http://evil.example/x",     # pełny URL jako "ścieżka"
    "https://evil.example/x",
    "@evil.example/x",
    "admin",                      # brak wiodącego '/'
    "/path\nX-Injected: 1",       # znak sterujący
])
def test_fetch_path_rejects_cross_host_and_malformed_paths(monkeypatch, evil_path):
    monkeypatch.setattr(urllib.request, "build_opener", _boom)
    status, body = signatures._fetch_path(BASE, evil_path)
    assert (status, body) == (None, b"")


def test_fetch_path_allows_same_origin_path(monkeypatch):
    captured = {}

    class _FakeResp:
        status = 200

        def read(self, *_a):
            return b"ok"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _FakeOpener:
        def open(self, req, timeout):
            captured["url"] = req.full_url
            return _FakeResp()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *a, **k: _FakeOpener())
    status, body = signatures._fetch_path(BASE, "/admin/login")
    assert status == 200 and body == b"ok"
    assert captured["url"] == "http://example.local:8080/admin/login"
