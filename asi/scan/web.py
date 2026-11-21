"""Etapy WWW: sondowanie usług HTTP, certyfikat i audyt TLS, nagłówki bezpieczeństwa, WAF i technologie."""
import json
import os
import re
import socket
import ssl
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from .. import net
from . import checks
from .proc import jsonl, run_cmd

ADMIN_RE = re.compile(r"(admin|login|dashboard|jenkins|grafana|kibana|phpmyadmin|router|"
                      r"portainer|gitlab|sign in|zaloguj)", re.I)
VERSION_RE = re.compile(r"\d+\.\d+")
SEC_HEADERS = [("content-security-policy", "Brak nagłówka Content-Security-Policy", "low",
                "Dodaj CSP ograniczające źródła skryptów."),
               ("x-content-type-options", "Brak nagłówka X-Content-Type-Options", "low",
                "Dodaj 'X-Content-Type-Options: nosniff'."),
               ("x-frame-options", "Brak ochrony przed clickjackingiem (X-Frame-Options)", "low",
                "Dodaj X-Frame-Options lub CSP frame-ancestors.")]


@contextmanager
def _json_out():
    """Ścieżka do jeszcze nieistniejącego pliku wynikowego (testssl nie nadpisuje) i jej odczyt po zakończeniu."""
    with tempfile.TemporaryDirectory(prefix="asi-") as d:
        path = os.path.join(d, "out.json")
        holder = {"path": path, "data": None}
        yield holder
        try:
            with open(path, encoding="utf-8") as f:
                holder["data"] = json.load(f)
        except (OSError, ValueError):
            pass


# ---------- sondowanie ----------
def http_probe(url):
    r = net.fetch(url, limit=65536, timeout=8)
    if r is None:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", r.body.decode("utf-8", "ignore"), re.I | re.S)
    return {"url": url, "status": r.status,
            "title": re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else "",
            "server": r.headers.get("server", ""), "tech": [], "headers": r.headers}


def probe_web(ctx, urls, tools):
    """Lista {url, status, title, server, tech, headers} dla odpowiadających usług."""
    if not tools["httpx"]["installed"]:
        with ThreadPoolExecutor(16) as ex:
            return [r for r in ex.map(http_probe, urls) if r]
    raw = run_cmd(ctx, ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
                        "-web-server", "-irh", "-nc", "-t", "25", "-timeout", "8"], 600, stdin="\n".join(urls))
    out = []
    for j in jsonl(raw):
        hdr = {k.lower().replace("_", "-"): (v if isinstance(v, str) else ", ".join(v))
               for k, v in (j.get("header") or {}).items()}
        out.append({"url": j.get("input") or j.get("url"), "status": j.get("status_code", 0),
                    "title": j.get("title", ""), "server": j.get("webserver", ""),
                    "tech": j.get("tech") or [], "headers": hdr})
    return out


# ---------- reguły dla odpowiedzi HTTP (czyste funkcje) ----------
def header_findings(url, status, headers, server="", title=""):
    """Ustalenia wynikające z samej odpowiedzi: [(severity, tytuł, detail, zalecenie)]."""
    out = []
    if url.startswith("http://") and 200 <= status < 300:
        out.append(("medium", "Usługa dostępna po nieszyfrowanym HTTP bez przekierowania", f"{url} -> {status}",
                    "Wymuś przekierowanie 301 na HTTPS i włącz HSTS."))
    if url.startswith("https://") and 200 <= status < 400 and "strict-transport-security" not in headers:
        out.append(("low", "Brak nagłówka HSTS", url, "Dodaj Strict-Transport-Security."))
    if 200 <= status < 300:
        csp = headers.get("content-security-policy", "")
        for h, t, sev, fix in SEC_HEADERS:
            if h not in headers and not (h == "x-frame-options" and "frame-ancestors" in csp):
                out.append((sev, t, url, fix))
        if VERSION_RE.search(headers.get("x-powered-by", "")):
            out.append(("low", "Ujawnienie technologii w nagłówku X-Powered-By", headers["x-powered-by"],
                        "Usuń nagłówek X-Powered-By (np. expose_php=Off)."))
        if VERSION_RE.search(server):
            out.append(("low", "Ujawnienie wersji oprogramowania w nagłówku Server", server,
                        "Ukryj wersję (server_tokens off / ServerTokens Prod)."))
    if ADMIN_RE.search(title) and status < 500:
        out.append(("medium", "Potencjalny panel administracyjny/logowania dostępny publicznie", f"{url} - \"{title}\"",
                    "Ogranicz dostęp (VPN, allowlista IP, MFA)."))
    return out


def cert_days_finding(days_left):
    if days_left < 0:
        return ("high", "Certyfikat TLS wygasł", f"wygasł {-int(days_left)} dni temu")
    if days_left < 30:
        return ("medium", "Certyfikat TLS wkrótce wygasa", f"zostało {int(days_left)} dni")
    return None


def tls_check(host, port):
    """Ważność certyfikatu: None albo (severity, tytuł, detail)."""
    try:
        with socket.create_connection((host, port), timeout=6) as s, \
                ssl.create_default_context().wrap_socket(s, server_hostname=host) as t:
            left = (ssl.cert_time_to_seconds(t.getpeercert()["notAfter"]) - time.time()) / 86400
        return cert_days_finding(left)
    except ssl.SSLCertVerificationError as e:
        return ("medium", "Niepoprawny certyfikat TLS", e.verify_message or str(e))
    except Exception:  # noqa: BLE001 - brak TLS/połączenia to nie ustalenie o certyfikacie
        return None


# ---------- audyt TLS ----------
_SSLYZE_LEGACY = (("ssl_2_0_cipher_suites", "SSL 2.0", "high"), ("ssl_3_0_cipher_suites", "SSL 3.0", "high"),
                  ("tls_1_0_cipher_suites", "TLS 1.0", "medium"), ("tls_1_1_cipher_suites", "TLS 1.1", "medium"))
_TESTSSL_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "WARN": "low"}


def parse_sslyze(j, where):
    try:
        r = j["server_scan_results"][0]["scan_result"]
    except (TypeError, KeyError, IndexError):
        return None

    def res(key):
        return (r.get(key) or {}).get("result") or {}

    out = [(sev, f"Serwer akceptuje przestarzały protokół {label}", where, "Wyłącz SSL 2.0/3.0 oraz TLS 1.0/1.1; zostaw TLS 1.2 i 1.3.")
           for key, label, sev in _SSLYZE_LEGACY if res(key).get("accepted_cipher_suites")]
    if res("heartbleed").get("is_vulnerable_to_heartbleed"):
        out.append(("critical", "Serwer podatny na Heartbleed", where, "Pilnie zaktualizuj OpenSSL i wymień certyfikaty oraz klucze."))
    if res("openssl_ccs_injection").get("is_vulnerable_to_ccs_injection"):
        out.append(("high", "Serwer podatny na OpenSSL CCS Injection", where, "Zaktualizuj OpenSSL."))
    if str(res("robot").get("robot_result", "")).startswith("VULNERABLE"):
        out.append(("high", "Serwer podatny na atak ROBOT (RSA)", where, "Wyłącz szyfry z wymianą kluczy RSA lub zaktualizuj oprogramowanie TLS."))
    return out


def parse_testssl(j, where, limit=8):
    out = []
    for e in (j if isinstance(j, list) else []):
        sev = _TESTSSL_SEV.get(str(e.get("severity", "")).upper())
        eid = str(e.get("id", ""))
        if sev and not eid.startswith(("cert_", "scanTime", "engine_problem")):
            out.append((sev, f"Audyt TLS ({eid}): {str(e.get('finding', ''))[:120]}", where,
                        "Zastosuj zalecenia z testssl.sh (wyłącz słabe protokoły i szyfry, zaktualizuj bibliotekę TLS)."))
    return out[:limit]


def tls_audit(ctx, host, port, tools):
    """Lista ustaleń albo None, gdy brak sslyze i testssl (wtedy wywołujący użyje fallbacku)."""
    where = f"{host}:{port}"
    if tools["sslyze"]["installed"]:
        with _json_out() as o:
            run_cmd(ctx, ["sslyze", f"--json_out={o['path']}", where], 600 if ctx.deep else 300)
        found = parse_sslyze(o["data"], where)
        if found is None:
            ctx.log("  sslyze: brak wyniku")
        return found or []
    if tools["testssl"]["installed"]:
        with _json_out() as o:
            run_cmd(ctx, [tools["testssl"]["path"], "--quiet", "--warnings", "off", "--fast", "--jsonfile", o["path"], where],
                    600 if ctx.deep else 360)
        return parse_testssl(o["data"], where)
    return None


def tls_findings(ctx, host, port, tools):
    found = tls_audit(ctx, host, port, tools)
    return checks.legacy_tls(host, port) if found is None else found


# ---------- WAF i technologie ----------
_WAF_HEADERS = (("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"), ("x-iinfo", "Imperva"), ("x-amz-cf-id", "AWS CloudFront"),
                ("x-akamai-transformed", "Akamai"))
_WHATWEB_SKIP = {"HTTPServer", "IP", "Country", "Title", "UncommonHeaders", "RedirectLocation", "HTML5", "Cookies",
                 "Strict-Transport-Security"}


def waf_from_headers(h):
    return next((n for k, n in _WAF_HEADERS if k in h), None) or ("Cloudflare" if "cloudflare" in h.get("server", "").lower() else None)


def parse_whatweb(j):
    tech = []
    for e in (j if isinstance(j, list) else []):
        for name, v in (e.get("plugins") or {}).items():
            if name not in _WHATWEB_SKIP:
                ver = (v.get("version") or [""])[0] if isinstance(v, dict) else ""
                tech.append(f"{name} {ver}".strip())
    return tech


def waf_and_tech(ctx, url, tools):
    """Zwraca (nazwa WAF albo None, lista technologii)."""
    waf, tech = None, []
    if tools["wafw00f"]["installed"]:
        with _json_out() as o:
            run_cmd(ctx, ["wafw00f", "-f", "json", "-o", o["path"], url], 120)
        for e in (o["data"] if isinstance(o["data"], list) else []):
            if e.get("detected"):
                waf = e.get("firewall") or "nieznany"
    else:
        r = net.fetch(url, limit=1024, timeout=6)
        waf = waf_from_headers(r.headers) if r else None
    if tools["whatweb"]["installed"]:
        with _json_out() as o:
            run_cmd(ctx, ["whatweb", f"--log-json={o['path']}", "-q", "-a", "3" if ctx.deep else "1", url], 180)
        tech = parse_whatweb(o["data"])
    else:  # fallback: nagłówki i meta generator
        r = net.fetch(url, limit=65536, timeout=6)
        if r:
            if r.headers.get("x-powered-by"):
                tech.append(r.headers["x-powered-by"])
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.body.decode("utf-8", "ignore"), re.I)
            if m:
                tech.append(m.group(1)[:60])
    return waf, tech
