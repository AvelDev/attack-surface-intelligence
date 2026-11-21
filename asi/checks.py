"""Dodatkowe, bezpieczne (tylko odczyt) kontrole: ukryte pliki, poczta (SPF/DMARC), stary TLS, security.txt.

Każda funkcja zwraca listę krotek (severity, tytuł, detail, zalecenie). Nic nie modyfikuje sprawdzanej strony.
Sygnatury treści chronią przed fałszywymi alarmami (strony zwracające 200 dla każdej ścieżki).
"""
import re
import socket
import ssl
import urllib.parse

from . import net

fetch = net.fetch  # nazwa modułowa: punkt podmiany w testach


# ---------- ukryte / wrażliwe pliki ----------
def _is_html(h, b):
    return "html" in h.get("content-type", "").lower() or b.lstrip()[:15].lower().startswith((b"<!doctype", b"<html"))


# (ścieżka, funkcja-sygnatura(body, headers), severity, tytuł, zalecenie)
SENSITIVE = [
    ("/.git/HEAD", lambda b, h: re.match(rb"ref: refs/", b),
     "high", "Publicznie dostępne repozytorium Git (/.git)",
     "Zablokuj dostęp do katalogu .git na serwerze WWW i usuń go z katalogu publicznego; zmień ujawnione hasła i klucze."),
    ("/.env", lambda b, h: not _is_html(h, b) and re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+", b),
     "critical", "Publicznie dostępny plik konfiguracyjny .env",
     "Natychmiast usuń plik z katalogu publicznego i zmień wszystkie zapisane w nim hasła i klucze."),
    ("/wp-config.php.bak", lambda b, h: b"DB_PASSWORD" in b,
     "critical", "Publicznie dostępna kopia konfiguracji WordPressa",
     "Usuń kopię z serwera i zmień hasło do bazy danych."),
    ("/phpinfo.php", lambda b, h: b"PHP Version" in b or b"phpinfo()" in b,
     "medium", "Publicznie dostępna strona phpinfo",
     "Usuń plik phpinfo.php z serwera produkcyjnego."),
    ("/server-status", lambda b, h: b"Apache Server Status" in b,
     "medium", "Publicznie dostępny status serwera Apache",
     "Ogranicz /server-status do adresów administratorów."),
    ("/actuator/env", lambda b, h: b"propertySources" in b,
     "high", "Publicznie dostępny endpoint Spring Boot Actuator (/actuator/env)",
     "Wyłącz lub zabezpiecz endpointy Actuator (uwierzytelnianie, osobny port zarządzania)."),
    ("/backup.sql", lambda b, h: re.search(rb"(CREATE TABLE|INSERT INTO|DROP TABLE)", b, re.I),
     "high", "Publicznie dostępna kopia bazy danych (backup.sql)",
     "Usuń kopię z katalogu publicznego; zakładaj, że dane mogły wyciec."),
    ("/dump.sql", lambda b, h: re.search(rb"(CREATE TABLE|INSERT INTO|DROP TABLE)", b, re.I),
     "high", "Publicznie dostępna kopia bazy danych (dump.sql)",
     "Usuń kopię z katalogu publicznego; zakładaj, że dane mogły wyciec."),
    ("/backup.zip", lambda b, h: b.startswith(b"PK\x03\x04"),
     "high", "Publicznie dostępne archiwum z kopią zapasową (backup.zip)",
     "Usuń archiwum z katalogu publicznego; zakładaj, że dane mogły wyciec."),
    ("/.DS_Store", lambda b, h: b.startswith(b"\x00\x00\x00\x01Bud1"),
     "low", "Publicznie dostępny plik .DS_Store (ujawnia strukturę katalogów)",
     "Usuń plik i zablokuj pliki zaczynające się od kropki."),
]


def sensitive_files(base):
    """base: np. https://host[:port]. Zwraca listę ustaleń dla ukrytych plików."""
    out = []
    for path, sig, sev, title, fix in SENSITIVE:
        r = fetch(base + path, limit=4096, timeout=5)
        if r and r[0] == 200 and sig(r[2], r[1]):
            out.append((sev, title, base + path, fix))
    return out


def security_txt(base):
    for p in ("/.well-known/security.txt", "/security.txt"):
        r = fetch(base + p, limit=2048, timeout=5)
        if r and r[0] == 200 and b"contact:" in r[2].lower() and not _is_html(r[1], r[2]):
            return []
    return [("info", "Brak pliku security.txt",
             base + "/.well-known/security.txt",
             "Dodaj plik /.well-known/security.txt z kontaktem do zgłaszania podatności (RFC 9116).")]


# ---------- stare wersje TLS ----------
def legacy_tls(host, port):
    """Sprawdza, czy serwer przyjmuje TLS 1.0/1.1. Nieudane połączenie = dobrze (serwer odrzuca)."""
    accepted = []
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
            c.minimum_version = c.maximum_version = ver
            c.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=6) as s:
                with c.wrap_socket(s, server_hostname=host):
                    accepted.append(name)
        except Exception:  # noqa: BLE001 - brak wsparcia po naszej stronie też traktujemy jako "nie wykryto"
            continue
    if accepted:
        return [("medium", "Serwer akceptuje przestarzałe wersje TLS", f"{host}:{port} - {', '.join(accepted)}",
                 "Wyłącz TLS 1.0 i 1.1; zostaw TLS 1.2 i 1.3.")]
    return []


# ---------- poczta: SPF / DMARC (przez DNS-over-HTTPS, bez dodatkowych bibliotek) ----------
def _doh(name, rtype):
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    j = net.get_json(url, timeout=8, headers={"Accept": "application/dns-json"})
    return [a["data"].strip('"') for a in j.get("Answer", []) if "data" in a]


def email_auth(domain):
    """Zwraca (ustalenia, None) albo ([], komunikat) gdy DNS-over-HTTPS jest nieosiągalny."""
    try:
        mx = _doh(domain, "MX")
        txt = ["".join(x.replace('" "', "")) for x in _doh(domain, "TXT")]
        dmarc = ["".join(x.replace('" "', "")) for x in _doh("_dmarc." + domain, "TXT")]
    except Exception as e:  # noqa: BLE001
        return [], f"DoH niedostępne: {e}"
    if not mx:
        return [], None  # domena nie obsługuje poczty - podszywanie mniej istotne
    out = []
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    if not spf:
        out.append(("medium", "Brak rekordu SPF (łatwe podszywanie się pod pocztę instytucji)", domain,
                    "Dodaj rekord TXT SPF wskazujący serwery uprawnione do wysyłania poczty, zakończony '-all' lub '~all'."))
    elif re.search(r"[+?]all\b", spf):
        out.append(("medium", "Rekord SPF zbyt liberalny (zezwala na dowolnego nadawcę)", spf,
                    "Zakończ rekord SPF przez '-all' (lub '~all')."))
    dm = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), None)
    if not dm:
        out.append(("medium", "Brak rekordu DMARC (brak ochrony przed fałszywymi e-mailami)", "_dmarc." + domain,
                    "Dodaj rekord TXT _dmarc, najpierw z polityką p=none i raportowaniem, docelowo p=quarantine lub p=reject."))
    elif re.search(r"\bp=none\b", dm, re.I):
        out.append(("low", "Polityka DMARC tylko monitoruje (p=none)", dm,
                    "Po przeanalizowaniu raportów zmień politykę na p=quarantine lub p=reject."))
    return out, None
