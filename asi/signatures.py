"""Własne sygnatury detekcyjne (pkt 10 specyfikacji AGH).

Wyłącznie bezpieczna detekcja obecności cech/komponentów - NIGDY eksploatacja ani
próby logowania. "path_check" to zwykłe GET (sprawdzenie czy ścieżka istnieje),
"favicon_hash" liczy własny SHA-256 pliku (nie jest kompatybilny z hashami Shodana,
które używają MurmurHash3 - to by wymagało dodatkowej zależności).

Typy:
  header_present        - nazwa nagłówka HTTP obecna w odpowiedzi
  cookie_name           - nazwa ciasteczka obecna w Set-Cookie
  html_regex            - wzorzec (regex) obecny w treści HTML
  footer_version_regex  - jw., osobny typ dla czytelności reguł "wersja w stopce"
  path_check            - ścieżka (np. /admin) zwraca <400 (bez prób logowania)
  favicon_hash          - SHA-256 pliku /favicon.ico zgadza się z podanym

Typy html_regex/footer_version_regex działają tylko gdy mamy treść strony (fallback
w czystym Pythonie ją zapisuje; httpx z ProjectDiscovery w tym PoC jej nie zwraca).
"""
import hashlib
import re
import ssl
import urllib.error
import urllib.request

from . import db

TYPES = ("header_present", "cookie_name", "html_regex", "footer_version_regex",
         "path_check", "favicon_hash")


def list_all(enabled_only=True):
    with db.conn() as c:
        q = "SELECT * FROM signatures" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY id"
        return [dict(r) for r in c.execute(q)]


def _fetch_path(url, path, timeout=6):
    ctxt = ssl.create_default_context()
    ctxt.check_hostname, ctxt.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(url.rstrip("/") + path, headers={"User-Agent": "asi-poc"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctxt) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(2048) if e.fp else b"")
    except Exception:  # noqa: BLE001
        return None, b""


def _check(sig, url, hdr, body):
    t, pat = sig["type"], sig["pattern"]
    if t == "header_present":
        return pat.lower() in hdr
    if t == "cookie_name":
        return bool(re.search(rf"(?i)\b{re.escape(pat)}=", hdr.get("set-cookie", "")))
    if t in ("html_regex", "footer_version_regex"):
        return bool(body) and bool(re.search(pat, body, re.I))
    if t == "path_check":
        status, _ = _fetch_path(url, pat)
        return status is not None and status < 400
    if t == "favicon_hash":
        status, data = _fetch_path(url, "/favicon.ico")
        return status == 200 and bool(data) and hashlib.sha256(data).hexdigest() == pat
    return False


def apply(ctx, url, hdr, body):
    wid = f"web:{url}"
    for sig in list_all():
        try:
            hit = _check(sig, url, hdr, body)
        except Exception as e:  # noqa: BLE001 - błędna sygnatura nie może wywrócić skanu
            ctx.log(f"Sygnatura '{sig['name']}': błąd {e!r}")
            continue
        if hit:
            ctx.finding(wid, sig["severity"], sig["title"] or sig["name"], "signature",
                        f"{sig['type']}: {sig['pattern']} @ {url}", sig["fix"] or "")
