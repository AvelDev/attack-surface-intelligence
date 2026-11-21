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
import multiprocessing
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import db

TYPES = ("header_present", "cookie_name", "html_regex", "footer_version_regex",
         "path_check", "favicon_hash")

REGEX_TIMEOUT_S = 2  # sygnatury html_regex/footer_version_regex to regexy od usera - limit przed ReDoS

_SAFE_PATH_RE = re.compile(r"^/[\x21-\x7e]*$")  # jeden wiodący '/', bez spacji/znaków sterujących


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _regex_worker(pat, text, q):
    try:
        q.put(bool(re.search(pat, text, re.I)))
    except re.error:
        q.put(False)


def _regex_search(pat, text):
    """re.search z limitem czasu - sygnatura to regex od użytkownika (rola add_remove_modify),
    katastroficzny backtracking (ReDoS) nie może zawiesić skanu. Osobny proces, nie wątek:
    wątku w Pythonie nie da się wymusić do zatrzymania w trakcie dopasowywania regexa w C
    (future.result(timeout=...) tylko przestaje czekać, porzucony wątek dalej pali CPU
    w nieskończoność), proces można zabić sygnałem."""
    try:
        ctx_name = "fork" if hasattr(os, "fork") else "spawn"
        ctx = multiprocessing.get_context(ctx_name)
        q = ctx.Queue()
        p = ctx.Process(target=_regex_worker, args=(pat, text, q), daemon=True)
        p.start()
        p.join(REGEX_TIMEOUT_S)
        if p.is_alive():
            p.kill()
            p.join(1)
            return False
        return q.get_nowait()
    except Exception:  # noqa: BLE001
        try:
            return bool(re.search(pat, text, re.I))
        except Exception:
            return False


def list_all(enabled_only=True):
    with db.conn() as c:
        q = "SELECT * FROM signatures" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY id"
        return [dict(r) for r in c.execute(q)]


def _fetch_path(url, path, timeout=6):
    """GET path względem url - tylko w obrębie dokładnie tego samego scheme/host/port
    (path to wzorzec sygnatury od użytkownika, bez tego sprawdzenia np. '@evil.com/x'
    albo '//evil.com' dałoby SSRF). Przekierowania wyłączone z tego samego powodu."""
    if not path.startswith("/") or path.startswith("//") or not _SAFE_PATH_RE.match(path):
        return None, b""
    base = urllib.parse.urlsplit(url)
    target = urllib.parse.urljoin(url, path)
    t = urllib.parse.urlsplit(target)
    if (t.scheme, t.hostname, t.port) != (base.scheme, base.hostname, base.port):
        return None, b""
    ctxt = ssl.create_default_context()
    ctxt.check_hostname, ctxt.verify_mode = False, ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctxt))
    req = urllib.request.Request(target, headers={"User-Agent": "asi-poc"})
    try:
        with opener.open(req, timeout=timeout) as r:
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
        if not body:
            _, raw_body = _fetch_path(url, "/")
            if raw_body:
                body = raw_body.decode("utf-8", "ignore")
        return bool(body) and _regex_search(pat, body)
    if t == "path_check":
        status, _ = _fetch_path(url, pat)
        return status is not None and status < 400
    if t == "favicon_hash":
        status, data = _fetch_path(url, "/favicon.ico")
        return status == 200 and bool(data) and hashlib.sha256(data).hexdigest() == pat
    return False


def apply(ctx, url, hdr, body, sigs):
    wid = f"web:{url}"
    for sig in sigs:
        try:
            hit = _check(sig, url, hdr, body)
        except Exception as e:  # noqa: BLE001 - błędna sygnatura nie może wywrócić skanu
            ctx.log(f"Sygnatura '{sig['name']}': błąd {e!r}")
            continue
        if hit:
            ctx.finding(wid, sig["severity"], sig["title"] or sig["name"], "signature",
                        f"{sig['type']}: {sig['pattern']} @ {url}", sig["fix"] or "")
