"""Wspólny klient HTTP (stdlib): jeden User-Agent, jedna polityka TLS i przekierowań dla całej aplikacji."""
import json
import ssl
import urllib.error
import urllib.request
from typing import NamedTuple

USER_AGENT = "Mozilla/5.0 asi-poc"


class Response(NamedTuple):
    status: int
    headers: dict  # nazwy nagłówków małymi literami
    body: bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def insecure_tls():
    """Kontekst bez weryfikacji certyfikatu - do sondowania usług (błędny certyfikat to ustalenie, nie przeszkoda)."""
    c = ssl.create_default_context()
    c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
    return c


def fetch(url, limit=4096, timeout=6):
    """GET bez podążania za przekierowaniami i bez weryfikacji TLS. Zwraca Response albo None przy błędzie sieci."""
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=insecure_tls()))
    try:
        r = opener.open(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout)
    except urllib.error.HTTPError as e:
        r = e
    except Exception:  # noqa: BLE001 - każdy błąd sieci = "usługa nie odpowiada"
        return None
    try:
        body = r.read(limit)
    except Exception:  # noqa: BLE001
        body = b""
    return Response(getattr(r, "status", None) or r.code, {k.lower(): v for k, v in r.headers.items()}, body)


def get_text(url, timeout=20, limit=2_000_000, headers=None):
    """GET do zaufanego API (weryfikacja TLS, przekierowania). Wyjątek przy błędzie."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(limit).decode("utf-8", "ignore")


def get_json(url, timeout=15, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def post_json(url, payload, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()
