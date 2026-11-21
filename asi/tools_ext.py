"""Rozszerzone narzędzia: amass/assetfinder/dnsrecon, sslyze/testssl, wafw00f/whatweb, katana/gau/waybackurls.

Każda funkcja używa narzędzia, gdy jest zainstalowane, a w przeciwnym razie prostego fallbacku w Pythonie.
Tryb "deep" (opcja w UI) włącza cięższe działania: crawling (katana), aktywną enumerację amass, agresywniejsze whatweb.
Wszystkie komendy bez powłoki; adresy sprawdzane aktywnie są ograniczone do zakresu celu (domena i jej subdomeny).
"""
import json
import os
import re
import socket
import struct
import tempfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import checks
from .proc import run_cmd

UA = {"User-Agent": "asi-poc"}


def in_scope(host, root):
    host = (host or "").lower().split(":")[0]
    return host == root or host.endswith("." + root)


def _tmp(suffix):
    d = tempfile.mkdtemp(prefix="asi-")
    return d, os.path.join(d, "out" + suffix)  # katalog + nieistniejący plik (testssl nie nadpisuje)


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _cleanup(d):
    try:
        for n in os.listdir(d):
            os.unlink(os.path.join(d, n))
        os.rmdir(d)
    except OSError:
        pass


# ---------- subdomeny ----------
def _http_lines(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(2_000_000).decode("utf-8", "ignore")


def more_subdomains(ctx, root, tools, deep):
    found = set()
    have = False
    if tools["amass"]["installed"]:
        have = True
        cmd = ["amass", "enum", "-d", root, "-timeout", "5" if deep else "3", "-silent"] if deep else \
              ["amass", "enum", "-passive", "-d", root, "-timeout", "3", "-silent"]
        found |= {x.split()[0].lower() for x in run_cmd(ctx, cmd, 420 if deep else 240).splitlines() if x.strip()}
    if tools["assetfinder"]["installed"]:
        have = True
        found |= {x.strip().lower() for x in run_cmd(ctx, ["assetfinder", "--subs-only", root], 120).splitlines() if x.strip()}
    if not have:  # fallback: darmowe źródła pasywne
        for name, url, parse in (
            ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={root}", lambda t: [l.split(",")[0] for l in t.splitlines()]),
            ("Anubis", f"https://jldc.me/anubis/subdomains/{root}", lambda t: json.loads(t)),
        ):
            try:
                found |= {n.strip().lower() for n in parse(_http_lines(url)) if isinstance(n, str)}
            except Exception as e:  # noqa: BLE001
                ctx.log(f"  {name} niedostępne: {type(e).__name__}")
    return found


# ---------- transfer strefy DNS (AXFR) ----------
def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _axfr_allowed(ns_ip, domain):
    q = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00" + struct.pack(">HH", 252, 1)
    msg = struct.pack(">HHHHHH", 0x4153, 0, 1, 0, 0, 0) + q
    try:
        with socket.create_connection((ns_ip, 53), timeout=6) as s:
            s.settimeout(6)
            s.sendall(struct.pack(">H", len(msg)) + msg)
            ln = _recvn(s, 2)
            if len(ln) < 2:
                return False
            resp = _recvn(s, min(struct.unpack(">H", ln)[0], 1024))
        return len(resp) >= 12 and (resp[3] & 0x0F) == 0 and struct.unpack(">H", resp[6:8])[0] > 0
    except OSError:
        return False


def zone_transfer(ctx, root, tools):
    """Zwraca listę ustaleń. dnsrecon, jeśli jest; w przeciwnym razie własna implementacja AXFR."""
    if tools["dnsrecon"]["installed"]:
        out = run_cmd(ctx, ["dnsrecon", "-d", root, "-t", "axfr"], 120)
        if re.search(r"zone transfer was successful", out, re.I):
            return [("high", "Serwer DNS pozwala każdemu pobrać całą strefę (AXFR)", root,
                     "Ogranicz transfer stref (allow-transfer) tylko do uprawnionych serwerów pomocniczych.")]
        return []
    try:
        ns = checks._doh(root, "NS")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  AXFR pominięty (DoH niedostępne: {type(e).__name__})")
        return []
    for n in ns[:4]:
        try:
            ip = socket.gethostbyname(n.rstrip("."))
        except OSError:
            continue
        if _axfr_allowed(ip, root):
            return [("high", "Serwer DNS pozwala każdemu pobrać całą strefę (AXFR)", f"{n} ({ip})",
                     "Ogranicz transfer stref (allow-transfer) tylko do uprawnionych serwerów pomocniczych.")]
    return []


# ---------- audyt TLS ----------
_SSLYZE_LEGACY = (("ssl_2_0_cipher_suites", "SSL 2.0", "high"), ("ssl_3_0_cipher_suites", "SSL 3.0", "high"),
                  ("tls_1_0_cipher_suites", "TLS 1.0", "medium"), ("tls_1_1_cipher_suites", "TLS 1.1", "medium"))
_TESTSSL_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "WARN": "low"}


def tls_audit(ctx, host, port, tools, deep):
    """Zwraca listę ustaleń albo None, gdy brak sslyze i testssl (wtedy wywołujący użyje fallbacku)."""
    if tools["sslyze"]["installed"]:
        d, path = _tmp(".json")
        try:
            run_cmd(ctx, ["sslyze", f"--json_out={path}", f"{host}:{port}"], 600 if deep else 300)
            j = _read_json(path)
        finally:
            _cleanup(d)
        out = []
        try:
            r = j["server_scan_results"][0]["scan_result"]
        except (TypeError, KeyError, IndexError):
            ctx.log("  sslyze: brak wyniku")
            return []
        for key, label, sev in _SSLYZE_LEGACY:
            res = (r.get(key) or {}).get("result") or {}
            if res.get("accepted_cipher_suites"):
                out.append((sev, f"Serwer akceptuje przestarzały protokół {label}", f"{host}:{port}",
                            "Wyłącz SSL 2.0/3.0 oraz TLS 1.0/1.1; zostaw TLS 1.2 i 1.3."))
        if ((r.get("heartbleed") or {}).get("result") or {}).get("is_vulnerable_to_heartbleed"):
            out.append(("critical", "Serwer podatny na Heartbleed", f"{host}:{port}", "Pilnie zaktualizuj OpenSSL i wymień certyfikaty oraz klucze."))
        if ((r.get("openssl_ccs_injection") or {}).get("result") or {}).get("is_vulnerable_to_ccs_injection"):
            out.append(("high", "Serwer podatny na OpenSSL CCS Injection", f"{host}:{port}", "Zaktualizuj OpenSSL."))
        if str(((r.get("robot") or {}).get("result") or {}).get("robot_result", "")).startswith("VULNERABLE"):
            out.append(("high", "Serwer podatny na atak ROBOT (RSA)", f"{host}:{port}", "Wyłącz szyfry z wymianą kluczy RSA lub zaktualizuj oprogramowanie TLS."))
        return out
    if tools["testssl"]["installed"]:
        d, path = _tmp(".json")
        try:
            run_cmd(ctx, [tools["testssl"]["path"], "--quiet", "--warnings", "off", "--fast", "--jsonfile", path, f"{host}:{port}"],
                    600 if deep else 360)
            j = _read_json(path)
        finally:
            _cleanup(d)
        out = []
        for e in (j if isinstance(j, list) else []):
            sev = _TESTSSL_SEV.get(str(e.get("severity", "")).upper())
            eid = str(e.get("id", ""))
            if sev and not eid.startswith(("cert_", "scanTime", "engine_problem")):
                out.append((sev, f"Audyt TLS ({eid}): {str(e.get('finding', ''))[:120]}", f"{host}:{port}",
                            "Zastosuj zalecenia z testssl.sh (wyłącz słabe protokoły i szyfry, zaktualizuj bibliotekę TLS)."))
        return out[:8]
    return None


# ---------- WAF i technologie ----------
_WAF_HEADERS = (("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"), ("x-iinfo", "Imperva"), ("x-amz-cf-id", "AWS CloudFront"),
                ("x-akamai-transformed", "Akamai"))


def waf_and_tech(ctx, url, tools, deep):
    """Zwraca (nazwa WAF albo None, lista technologii)."""
    waf, tech = None, []
    if tools["wafw00f"]["installed"]:
        d, path = _tmp(".json")
        try:
            run_cmd(ctx, ["wafw00f", "-f", "json", "-o", path, url], 120)
            j = _read_json(path)
        finally:
            _cleanup(d)
        for e in (j if isinstance(j, list) else []):
            if e.get("detected"):
                waf = e.get("firewall") or "nieznany"
    else:
        r = checks.fetch(url, limit=1024, timeout=6)
        if r:
            h = r[1]
            waf = next((n for k, n in _WAF_HEADERS if k in h), None) or ("Cloudflare" if "cloudflare" in h.get("server", "").lower() else None)
    if tools["whatweb"]["installed"]:
        d, path = _tmp(".json")
        try:
            run_cmd(ctx, ["whatweb", f"--log-json={path}", "-q", "-a", "3" if deep else "1", url], 180)
            j = _read_json(path)
        finally:
            _cleanup(d)
        for e in (j if isinstance(j, list) else []):
            for name, v in (e.get("plugins") or {}).items():
                if name in ("HTTPServer", "IP", "Country", "Title", "UncommonHeaders", "RedirectLocation", "HTML5", "Cookies", "Strict-Transport-Security"):
                    continue
                ver = (v.get("version") or [""])[0] if isinstance(v, dict) else ""
                tech.append(f"{name} {ver}".strip())
    else:  # fallback: nagłówki i meta generator
        r = checks.fetch(url, limit=65536, timeout=6)
        if r:
            h, body = r[1], r[2].decode("utf-8", "ignore")
            if h.get("x-powered-by"):
                tech.append(h["x-powered-by"])
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
            if m:
                tech.append(m.group(1)[:60])
    return waf, tech


# ---------- odkrywanie adresów URL ----------
INTERESTING_EXT = {  # rozszerzenie -> severity
    "sql": "high", "env": "high", "pem": "high", "key": "high", "sqlite": "high", "db": "high", "dump": "high",
    "bak": "medium", "old": "medium", "zip": "medium", "tar": "medium", "gz": "medium", "7z": "medium", "rar": "medium",
    "log": "medium", "conf": "medium", "config": "medium", "ini": "medium", "swp": "medium",
}
URL_RE = re.compile(r"\.([a-z0-9]{2,6})(?:\?|#|$)", re.I)
MAX_URLS = 3000
MAX_PROBES = 25


def discover_urls(ctx, root, web_roots, tools, deep):
    """Zwraca zbiór adresów URL z zakresu celu (pasywnie z archiwów; w trybie deep także crawling katana)."""
    urls = set()
    passive = False
    if tools["gau"]["installed"]:
        passive = True
        urls |= set(run_cmd(ctx, ["gau", "--subs", "--threads", "5", "--timeout", "20", root], 240).split())
    if tools["waybackurls"]["installed"]:
        passive = True
        urls |= set(run_cmd(ctx, ["waybackurls", root], 240).split())
    if not passive:
        try:
            q = urllib.parse.urlencode({"url": f"*.{root}/*", "output": "txt", "fl": "original", "collapse": "urlkey", "limit": 3000})
            urls |= set(_http_lines("http://web.archive.org/cdx/search/cdx?" + q, timeout=40).split())
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  Wayback CDX niedostępny: {type(e).__name__}")
    if deep and tools["katana"]["installed"] and web_roots:
        urls |= set(run_cmd(ctx, ["katana", "-silent", "-nc", "-jc", "-d", "3", "-c", "5", "-rl", "40", "-ct", "90", "-timeout", "8"],
                            400, stdin="\n".join(web_roots[:5])).split())
    elif deep:
        ctx.log("  katana niezainstalowana - pomijam crawling")
    keep = set()
    for u in urls:
        p = urllib.parse.urlparse(u)
        if p.scheme in ("http", "https") and in_scope(p.netloc, root):
            keep.add(u)
        if len(keep) >= MAX_URLS:
            break
    return keep


def analyze_urls(ctx, urls, known_webs, root_asset):
    """Sprawdza (GET, tylko w zakresie) czy historyczne adresy z plikami wrażliwymi nadal istnieją."""
    cands, seen = [], set()
    for u in sorted(urls):
        p = urllib.parse.urlparse(u)
        m = URL_RE.search(p.path + ("?" if p.query else ""))
        ext = m.group(1).lower() if m else ""
        if ext in INTERESTING_EXT or re.search(r"/\.(git|svn)/", p.path):
            key = (p.netloc, p.path)
            if key not in seen:
                seen.add(key)
                cands.append((u, ext))
    ctx.log(f"Adresy w zakresie: {len(urls)}, potencjalnie wrażliwych: {len(cands)} (sprawdzam do {MAX_PROBES})")

    def probe(c):
        u, ext = c
        r = checks.fetch(u, limit=1024, timeout=6)
        return c, r

    with ThreadPoolExecutor(5) as ex:
        for (u, ext), r in ex.map(probe, cands[:MAX_PROBES]):
            if r and r[0] == 200 and r[2] and not checks._is_html(r[1], r[2]):
                p = urllib.parse.urlparse(u)
                wid = f"web:{p.scheme}://{p.netloc}"
                ctx.finding(wid if wid in known_webs else root_asset, INTERESTING_EXT.get(ext, "high"),
                            f"Dostępny plik, który nie powinien być publiczny (.{ext or 'git'})", "builtin", u,
                            "Usuń plik z serwera lub zablokuj dostęp; jeśli zawierał hasła lub dane, uznaj je za ujawnione.")
