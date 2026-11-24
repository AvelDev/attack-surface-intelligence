"""Wyniki skryptów NSE -> ustalenia. Reguły są tabelą: nowy skrypt = nowy wiersz, bez zmian w silniku."""
import re
from typing import NamedTuple

from .. import domain

SOURCE = "nmap"
UPDATE_FIX = "Zaktualizuj usługę do wersji bez tej podatności albo ogranicz do niej dostęp."
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f]")


class Rule(NamedTuple):
    script: str
    pattern: re.Pattern
    severity: str
    title: str
    fix: str


def _r(script, pattern, severity, title, fix):
    assert domain.is_severity(severity)
    return Rule(script, re.compile(pattern, re.I), severity, title, fix)


RULES = {r.script: r for r in (
    _r("ftp-anon", r"anonymous ftp login allowed", "high", "Anonimowe logowanie FTP", "Wyłącz konto anonymous."),
    _r("smb-protocols", r"SMBv1", "high", "Serwer obsługuje SMBv1", "Wyłącz SMBv1 (podatny m.in. na EternalBlue)."),
    _r("smb-security-mode", r"message_signing:\s*disabled", "medium", "Podpisywanie SMB wyłączone", "Wymuś podpisywanie komunikatów SMB."),
    _r("smb2-security-mode", r"not required", "medium", "Podpisywanie SMB nie jest wymagane", "Wymuś podpisywanie komunikatów SMB."),
    _r("smb-enum-shares", r"anonymous access:\s*(read|write)", "high", "Udział SMB dostępny anonimowo", "Odbierz dostęp anonimowy do udziałów."),
    _r("nfs-showmount", r"\S", "medium", "Eksporty NFS widoczne z sieci", "Ogranicz eksporty do zaufanych adresów."),
    _r("redis-info", r"version", "high", "Redis odpowiada bez uwierzytelnienia", "Włącz hasło i ogranicz nasłuch do sieci aplikacji."),
    _r("mongodb-databases", r"totalSize|databases", "critical", "MongoDB udostępnia bazy bez uwierzytelnienia",
       "Włącz uwierzytelnianie i ogranicz nasłuch."),
    _r("memcached-info", r"process id|uptime", "high", "Memcached odpowiada bez uwierzytelnienia",
       "Ogranicz nasłuch do sieci aplikacji i wyłącz UDP."),
    _r("mysql-empty-password", r"account has empty password", "critical", "Konto MySQL bez hasła", "Ustaw hasło dla wskazanego konta."),
    _r("ms-sql-empty-password", r"login success", "critical", "Konto MSSQL bez hasła", "Ustaw hasło dla wskazanego konta."),
    _r("vnc-info", r"None \(1\)|does not require authentication", "critical", "VNC bez uwierzytelnienia", "Włącz hasło i schowaj VNC za VPN."),
    _r("x11-access", r"access is granted", "high", "Serwer X11 przyjmuje połączenia z sieci", "Ogranicz dostęp do X11 (xhost, firewall)."),
    _r("dns-recursion", r"recursion appears to be enabled", "medium", "Otwarty resolver DNS", "Wyłącz rekurencję dla obcych adresów."),
    _r("ntp-monlist", r"\S", "medium", "Serwer NTP odpowiada na monlist", "Zaktualizuj ntpd albo wyłącz monlist (wzmacnianie DDoS)."),
    _r("snmp-info", r"\S", "medium", "SNMP odpowiada z sieci", "Użyj SNMPv3 i ogranicz dostęp do stacji zarządzających."),
    _r("snmp-sysdescr", r"\S", "medium", "SNMP ujawnia opis systemu", "Użyj SNMPv3 i zmień domyślne community."),
    _r("tftp-enum", r"\S", "medium", "Serwer TFTP udostępnia pliki", "Wyłącz TFTP albo ogranicz dostęp."),
    _r("sshv1", r"supports SSHv1", "high", "Serwer SSH obsługuje protokół 1", "Wyłącz SSHv1."),
    _r("ssl-enum-ciphers", r"least strength:\s*[D-F]", "medium", "Słabe szyfry TLS", "Zostaw tylko zestawy AEAD (TLS 1.2+)."),
    _r("sslv2", r"SSLv2 supported", "high", "Serwer obsługuje SSLv2", "Wyłącz SSLv2."),
    _r("http-git", r"git repository found", "high", "Katalog .git dostępny przez HTTP", "Zablokuj dostęp do .git i unieważnij ujawnione sekrety."),
    _r("http-methods", r"potentially risky methods:", "low", "Ryzykowne metody HTTP włączone", "Wyłącz metody, których aplikacja nie używa."),
    _r("http-trace", r"TRACE is enabled", "low", "Metoda HTTP TRACE włączona", "Wyłącz TRACE w konfiguracji serwera."),
    _r("http-open-proxy", r"potentially OPEN proxy", "high", "Otwarte proxy HTTP", "Ogranicz proxy do uprawnionych klientów."),
    _r("smtp-open-relay", r"server is an open relay", "high", "Otwarty przekaźnik SMTP", "Ogranicz przekazywanie poczty do własnych domen."),
    _r("rdp-enum-encryption", r"RDP Encryption level:\s*(low|none)", "medium", "Słabe szyfrowanie RDP", "Wymuś NLA i TLS."),
)}


def severity_of_cvss(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"


def _cvss(value):
    m = re.match(r"\s*(\d+(?:\.\d+)?)", str(value))
    return min(10.0, float(m[1])) if m else 0.0


def _values(data):
    """Wartości tabeli NSE niezależnie od tego, czy miała klucze."""
    return list(data.values()) if isinstance(data, dict) else data if isinstance(data, list) else []


def _vuln(script, key, entry):
    """Wpis biblioteki `vulns` (state, title, ids, scores) -> ustalenie albo None."""
    state = str(entry.get("state", "")).upper()
    if "VULNERABLE" not in state or state.startswith("NOT"):
        return None
    cves = [str(i).removeprefix("CVE:") for i in _values(entry.get("ids")) if "CVE-" in str(i)]
    score = max((_cvss(v) for v in _values(entry.get("scores"))), default=0.0)
    risk = re.search(r"risk factor:\s*(critical|high|medium|low)", script["output"], re.I)
    sev = severity_of_cvss(score) if score else risk[1].lower() if risk else "medium" if state.startswith("LIKELY") else "high"
    name = str(entry.get("title") or key)
    title = name if not cves or cves[0] in name else f"{name} ({cves[0]})"
    return sev, title[:200], SOURCE, f"{script['id']}: {state}\n{script['output']}", UPDATE_FIX


def _vulners(script):
    """Wynik skryptu vulners ({cpe: [{id, cvss}]}) -> jedno ustalenie na usługę."""
    rows = [r for group in _values(script.get("data")) for r in _values(group) if isinstance(r, dict)]
    cves = sorted({(_cvss(r.get("cvss")), r["id"]) for r in rows if str(r.get("id", "")).startswith("CVE-")}, reverse=True)
    if not cves:
        return None
    top = ", ".join(f"{cve} ({score:g})" for score, cve in cves[:8])
    return severity_of_cvss(cves[0][0]), "Wersja usługi ma znane podatności", SOURCE, f"{len(cves)} CVE według vulners: {top}", UPDATE_FIX


def findings(scripts):
    """[(ważność, tytuł, źródło, szczegół, zalecenie)] dla listy wyników NSE jednego portu albo hosta."""
    out = []
    for s in scripts or ():
        if s["id"] == "vulners":
            out.append(_vulners(s))
            continue
        data = s.get("data")
        if isinstance(data, dict):
            out += [_vuln(s, k, v) for k, v in data.items() if isinstance(v, dict) and "state" in v]
        rule = RULES.get(s["id"])
        if rule and rule.pattern.search(s["output"]):
            out.append((rule.severity, rule.title, SOURCE, f"{s['id']}\n{s['output']}", rule.fix))
    return [(sev, title, src, _CONTROL.sub("", detail), fix) for sev, title, src, detail, fix in filter(None, out)]
