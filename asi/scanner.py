"""Orkiestrator skanowania powierzchni ataku.

Każdy etap używa narzędzia z Kali/Ubuntu (subfinder, dnsx, naabu/nmap, httpx, nuclei),
a gdy go brak - czystego Pythona (fallback), więc PoC działa także bez zainstalowanych narzędzi.
Wszystkie komendy są uruchamiane BEZ powłoki (lista argumentów), cel jest walidowany.
"""
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import alerts, checks, db, intel, tools_ext
from .proc import jsonl, run_cmd

# ~/go/bin (narzędzia Go) oraz katalog bieżącego interpretera (narzędzia pip z venv: sslyze, wafw00f, dnsrecon)
os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", ""), os.path.expanduser("~/go/bin"),
                                      os.path.dirname(sys.executable)])

SEM = threading.Semaphore(1)  # skany idą w kolejce, po jednym naraz
TOOLS = ["subfinder", "dnsx", "naabu", "nmap", "httpx", "nuclei",
         "amass", "assetfinder", "dnsrecon", "sslyze", "testssl", "wafw00f", "whatweb", "katana", "gau", "waybackurls"]
TOOL_BIN = {"testssl": ("testssl.sh", "testssl")}  # nazwa narzędzia -> możliwe nazwy pliku
SEV_W = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ALLOW_PRIVATE = os.environ.get("ASI_ALLOW_PRIVATE") == "1"

PY_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723,
            3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
           111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
           993: "imaps", 995: "pop3s", 1433: "mssql", 1723: "pptp", 3000: "http", 3306: "mysql",
           3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8000: "http",
           8080: "http", 8443: "https", 9200: "elasticsearch", 27017: "mongodb"}
RISKY = {  # port -> (severity, tytuł, zalecenie)
    23: ("high", "Telnet wystawiony do internetu", "Wyłącz Telnet, użyj SSH z kluczami."),
    21: ("medium", "FTP wystawiony do internetu", "Zastąp FTP przez SFTP/FTPS lub zamknij port."),
    445: ("high", "SMB wystawiony do internetu", "Zablokuj 445 na firewallu; udostępniaj przez VPN."),
    135: ("medium", "MS-RPC wystawiony do internetu", "Zablokuj port na brzegu sieci."),
    139: ("medium", "NetBIOS wystawiony do internetu", "Zablokuj port na brzegu sieci."),
    111: ("medium", "rpcbind wystawiony do internetu", "Zamknij port lub ogranicz ACL."),
    3389: ("high", "RDP wystawiony do internetu", "Ukryj RDP za VPN/bastionem, włącz NLA i MFA."),
    5900: ("high", "VNC wystawiony do internetu", "Zamknij port, użyj tunelu SSH/VPN."),
    3306: ("high", "Baza MySQL dostępna z internetu", "Ogranicz dostęp do sieci aplikacji (firewall)."),
    5432: ("high", "Baza PostgreSQL dostępna z internetu", "Ogranicz dostęp do sieci aplikacji (firewall)."),
    1433: ("high", "Baza MSSQL dostępna z internetu", "Ogranicz dostęp do sieci aplikacji (firewall)."),
    6379: ("high", "Redis dostępny z internetu", "Zamknij port, włącz auth i bind do localhost."),
    27017: ("high", "MongoDB dostępna z internetu", "Zamknij port, włącz uwierzytelnianie."),
    9200: ("high", "Elasticsearch dostępny z internetu", "Zamknij port, włącz security i ACL."),
    1723: ("low", "PPTP VPN (przestarzały protokół)", "Migruj na WireGuard/IPsec."),
}
ADMIN_RE = re.compile(r"(admin|login|dashboard|jenkins|grafana|kibana|phpmyadmin|router|"
                      r"portainer|gitlab|sign in|zaloguj)", re.I)


def normalize_target(raw):
    t = (raw or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0].split(":")[0].strip(".")
    try:
        ipaddress.IPv4Address(t)
        return t
    except ValueError:
        pass
    if not DOMAIN_RE.match(t):
        raise ValueError("Nieprawidłowy cel - podaj domenę (example.com) lub adres IPv4.")
    allowed = [x.strip() for x in os.environ.get("ASI_ALLOWED_TARGETS", "").split(",") if x.strip()]
    if allowed and not any(t == a or t.endswith("." + a) for a in allowed):
        raise ValueError("Cel poza dozwoloną listą (ASI_ALLOWED_TARGETS).")
    return t


def is_ip(t):
    try:
        ipaddress.IPv4Address(t)
        return True
    except ValueError:
        return False


def tool_status():
    out = {}
    for n in TOOLS:
        p = next(filter(None, (shutil.which(b) for b in TOOL_BIN.get(n, (n,)))), None)
        ok = bool(p)
        if n == "httpx" and p:  # odróżnij httpx ProjectDiscovery od CLI pythonowego httpx
            try:
                r = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=10)
                txt = (r.stdout + r.stderr).lower()
                ok = "projectdiscovery" in txt or "current version" in txt
            except Exception:
                ok = False
        out[n] = {"installed": ok, "path": p if ok else None}
    return out


class Ctx:
    def __init__(self, scan_id):
        self.id = scan_id
        with db.conn() as c:
            row = c.execute("SELECT target, opts FROM scans WHERE id=?", (scan_id,)).fetchone()
        self.target, self.opts = row["target"], json.loads(row["opts"])
        self._seen_f = set()

    def log(self, msg):
        line = time.strftime("%H:%M:%S ") + str(msg)[:600] + "\n"
        with db.conn() as c:
            c.execute("UPDATE scans SET log = log || ? WHERE id=?", (line, self.id))

    def stage(self, name):
        self.log(f"=== {name} ===")
        with db.conn() as c:
            c.execute("UPDATE scans SET stage=? WHERE id=?", (name, self.id))

    def asset(self, kind, value, data=None):
        aid = f"{kind}:{value}"
        with db.conn() as c:
            c.execute("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                      (self.id, aid, kind, value, json.dumps(data or {})))
        return aid

    def edge(self, src, dst):
        if src != dst:
            with db.conn() as c:
                c.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?)", (self.id, src, dst))

    def finding(self, asset, sev, title, source, detail="", fix=""):
        key = (asset, title)
        if key in self._seen_f:
            return
        self._seen_f.add(key)
        with db.conn() as c:
            c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                      (self.id, asset, sev, title, source, detail[:1000], fix))

    def add_tech(self, aid, tech):
        with db.conn() as c:
            r = c.execute("SELECT data FROM assets WHERE scan_id=? AND id=?", (self.id, aid)).fetchone()
            if r:
                d = json.loads(r["data"])
                d["tech"] = sorted(set(d.get("tech", [])) | set(tech))
                c.execute("UPDATE assets SET data=? WHERE scan_id=? AND id=?", (json.dumps(d), self.id, aid))

    def finish(self, status):
        with db.conn() as c:
            sev = [r["severity"] for r in c.execute(
                "SELECT severity FROM findings WHERE scan_id=?", (self.id,))]
            c.execute("UPDATE scans SET status=?, stage=?, score=?, finished=? WHERE id=?",
                      (status, "zakończony" if status == "done" else "błąd",
                       risk_score(sev), time.time(), self.id))


def risk_score(severities):
    """0-100, malejące przyrosty: kilka krytycznych szybko wyciąga wynik w górę."""
    total = sum(SEV_W.get(s, 0) for s in severities)
    return min(100, int(100 * (1 - 0.985 ** total)))


# ---------- etap 1: subdomeny ----------
def enum_subdomains(ctx, root, tools):
    found = set()
    if tools["subfinder"]["installed"]:
        out = run_cmd(ctx, ["subfinder", "-d", root, "-silent", "-timeout", "20", "-max-time", "3"], 240)
        found |= {x.strip().lower() for x in out.splitlines() if x.strip()}
    found |= tools_ext.more_subdomains(ctx, root, tools, bool(ctx.opts.get("deep")))
    try:  # źródło pasywne: Certificate Transparency
        url = f"https://crt.sh/?q=%25.{root}&output=json"
        ctx.log(f"GET {url}")
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "asi-poc"}),
                                    timeout=30) as r:
            for row in json.load(r):
                for n in row.get("name_value", "").split("\n"):
                    found.add(n.strip().lower().lstrip("*."))
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  crt.sh niedostępne: {e}")
    return {n for n in found if n == root or (n.endswith("." + root) and DOMAIN_RE.match(n))}


# ---------- etap 2: DNS ----------
TAKEOVER_SUFFIXES = ("github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
                     "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
                     "netlify.app", "readme.io", "zendesk.com", "myshopify.com", "pantheonsite.io",
                     "surge.sh", "ghost.io", "wordpress.com", "fastly.net", "bitbucket.io", "statuspage.io")


def resolve(ctx, names, tools):
    """Zwraca (host -> [ip], host -> [cname])."""
    res, cnames = {}, {}
    if tools["dnsx"]["installed"]:
        out = run_cmd(ctx, ["dnsx", "-silent", "-a", "-cname", "-resp", "-json", "-retry", "1"], 180,
                      stdin="\n".join(names))
        for j in jsonl(out):
            h = j["host"].lower()
            if j.get("a"):
                res[h] = sorted(set(j["a"]))
            if j.get("cname"):
                cnames[h] = [c.rstrip(".").lower() for c in j["cname"]]
    missing = [n for n in names if n not in res]  # bez dnsx lub gdy dnsx nic nie zwrócił (np. timeout)
    if missing:
        def one(n):
            try:
                _, alias, ips = socket.gethostbyname_ex(n)
                return n, sorted(set(ips)), alias
            except OSError:
                return n, [], []
        with ThreadPoolExecutor(20) as ex:
            for n, ips, alias in ex.map(one, missing):
                if ips:
                    res[n] = ips
                if alias:
                    cnames[n] = [a.lower() for a in alias]
    return res, cnames


# ---------- etap 3: porty ----------
def _tcp_open(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(ctx, ips, tools):
    result = {ip: [] for ip in ips}
    if not ips:
        return result
    if tools["naabu"]["installed"]:
        out = run_cmd(ctx, ["naabu", "-list", "/dev/stdin", "-top-ports", "100", "-rate", "300",
                            "-s", "c", "-silent", "-json"], 600, stdin="\n".join(ips))
        for j in jsonl(out):
            ip, port = j.get("ip") or j.get("host"), j.get("port")
            if ip in result and port:
                result[ip].append({"port": int(port), "service": SERVICE.get(int(port), ""), "version": ""})
    elif tools["nmap"]["installed"]:
        out = run_cmd(ctx, ["nmap", "-Pn", "-sT", "--top-ports", "100", "-sV", "--version-light",
                            "-T3", "--open", "-oX", "-"] + list(ips), 900)
        try:
            for h in ET.fromstring(out).iter("host"):
                a = h.find("address[@addrtype='ipv4']")
                if a is None or a.get("addr") not in result:
                    continue
                for p in h.iter("port"):
                    if p.find("state").get("state") != "open":
                        continue
                    s = p.find("service")
                    s = s.attrib if s is not None else {}
                    if s.get("name") == "tcpwrapped":
                        continue  # połączenie zamykane od razu - port w rzeczywistości zamknięty
                    result[a.get("addr")].append({
                        "port": int(p.get("portid")),
                        "service": (s.get("tunnel", "") + "/" if s.get("tunnel") else "") + s.get("name", ""),
                        "version": " ".join(x for x in (s.get("product"), s.get("version")) if x)})
        except ET.ParseError:
            ctx.log("  nie udało się sparsować XML z nmap")
    else:
        ctx.log("Brak naabu/nmap - skan TCP connect w Pythonie (28 portów)")
        jobs = [(ip, p) for ip in ips for p in PY_PORTS]
        with ThreadPoolExecutor(64) as ex:
            for (ip, p), ok in zip(jobs, ex.map(lambda j: _tcp_open(*j), jobs)):
                if ok:
                    result[ip].append({"port": p, "service": SERVICE.get(p, ""), "version": ""})
    return verify_ports(ctx, result)


BANNER_EXPECT = {21: b"220", 22: b"SSH-", 25: b"220", 110: b"+OK", 143: b"* OK"}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888, 3000}
TLS_PORTS = {443, 8443, 9443, 993, 995}


def _verify(ip, port):
    """Zwraca (ok, banner). Odrzuca porty, gdzie 'połączenie' tworzy pośrednik/router
    (TCP handshake OK, ale usługa nie odpowiada) - typowe fałszywe porty 21/22 itp."""
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.settimeout(4)
            if port in TLS_PORTS:
                c = ssl.create_default_context()
                c.check_hostname, c.verify_mode = False, ssl.CERT_NONE
                with c.wrap_socket(s, server_hostname=ip) as t:
                    return True, t.version() or ""
            if port in HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            try:
                data = s.recv(256)
            except socket.timeout:
                # usługa czeka na klienta (np. SMB, RDP, Redis) - OK, chyba że oczekujemy banera
                return port not in BANNER_EXPECT, ""
            if not data:
                return False, ""  # zamknięte natychmiast = tcpwrapped / pośrednik
            exp = BANNER_EXPECT.get(port)
            if exp and not data.startswith(exp):
                return False, data[:60].decode("latin1")
            return True, (data[:120].decode("latin1", "ignore").splitlines() or [""])[0].strip()
    except (ssl.SSLError, ConnectionError):
        return False, ""
    except OSError:
        return False, ""


def verify_ports(ctx, result):
    jobs = [(ip, p) for ip, pl in result.items() for p in pl]
    with ThreadPoolExecutor(32) as ex:
        # jedna powtórka dla odrzuconych - chroni przed chwilowymi zwłokami w sieci
        verdicts = list(ex.map(lambda j: _verify(j[0], j[1]["port"]), jobs))
        retry = [i for i, v in enumerate(verdicts) if not v[0]]
        for i, v in zip(retry, ex.map(lambda i: _verify(jobs[i][0], jobs[i][1]["port"]), retry)):
            verdicts[i] = v
    out = {ip: [] for ip in result}
    dropped = []
    for (ip, p), (ok, banner) in zip(jobs, verdicts):
        if ok:
            if banner:
                p["banner"] = banner
            out[ip].append(p)
        else:
            dropped.append(f"{ip}:{p['port']}")
    if dropped:
        ctx.log(f"Odrzucono fałszywe/niepotwierdzone porty: {', '.join(dropped)}")
    for ip in out:
        out[ip].sort(key=lambda x: x["port"])
    return out


def web_scheme(p):
    port, svc = p["port"], p.get("service", "")
    if "https" in svc or "ssl/http" in svc or port in (443, 8443, 9443):
        return "https"
    if svc.endswith("http") or svc.startswith("http") or port in (80, 8000, 8008, 8080, 8888, 3000):
        return "http"
    return None


# ---------- etap 4: HTTP ----------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_probe(url):
    ctxt = ssl.create_default_context()
    ctxt.check_hostname, ctxt.verify_mode = False, ssl.CERT_NONE
    op = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctxt))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 asi-poc"})
    try:
        r = op.open(req, timeout=8)
    except urllib.error.HTTPError as e:
        r = e
    except Exception:  # noqa: BLE001
        return None
    body = r.read(65536).decode("utf-8", "ignore")
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    h = {k.lower(): v for k, v in r.headers.items()}
    return {"url": url, "status": r.status if hasattr(r, "status") else r.code,
            "title": re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else "",
            "server": h.get("server", ""), "tech": [], "headers": h}


def probe_web(ctx, urls, tools):
    out = []
    if tools["httpx"]["installed"]:
        raw = run_cmd(ctx, ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code",
                            "-web-server", "-irh", "-nc", "-t", "25", "-timeout", "8"], 600,
                      stdin="\n".join(urls))
        for j in jsonl(raw):
            hdr = {k.lower().replace("_", "-"): (v if isinstance(v, str) else ", ".join(v))
                   for k, v in (j.get("header") or {}).items()}
            out.append({"url": j.get("input") or j.get("url"), "status": j.get("status_code", 0),
                        "title": j.get("title", ""), "server": j.get("webserver", ""),
                        "tech": j.get("tech") or [], "headers": hdr})
    else:
        with ThreadPoolExecutor(16) as ex:
            out = [r for r in ex.map(http_probe, urls) if r]
    return out


def tls_check(host, port):
    """Zwraca (None | (severity, tytuł, detail))."""
    try:
        c = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as s:
            with c.wrap_socket(s, server_hostname=host) as t:
                left = (ssl.cert_time_to_seconds(t.getpeercert()["notAfter"]) - time.time()) / 86400
        if left < 0:
            return ("high", "Certyfikat TLS wygasł", f"wygasł {-int(left)} dni temu")
        if left < 30:
            return ("medium", "Certyfikat TLS wkrótce wygasa", f"zostało {int(left)} dni")
    except ssl.SSLCertVerificationError as e:
        return ("medium", "Niepoprawny certyfikat TLS", e.verify_message or str(e))
    except Exception:  # noqa: BLE001
        pass
    return None


SEC_HEADERS = [("content-security-policy", "Brak nagłówka Content-Security-Policy", "low",
                "Dodaj CSP ograniczające źródła skryptów."),
               ("x-content-type-options", "Brak nagłówka X-Content-Type-Options", "low",
                "Dodaj 'X-Content-Type-Options: nosniff'."),
               ("x-frame-options", "Brak ochrony przed clickjackingiem (X-Frame-Options)", "low",
                "Dodaj X-Frame-Options lub CSP frame-ancestors.")]


MAX_EXTRA_WEBS = 15  # limit hostów dla kontroli plików/TLS, żeby skan nie rozrastał się w nieskończoność


def extra_checks(ctx, root, target, ip_target, web_items, tools):
    """Etap: ukryte pliki, stary TLS, security.txt, SPF/DMARC. Błąd jednej kontroli nie przerywa skanu."""
    ctx.stage("Dodatkowe kontrole (pliki, poczta, szyfrowanie)")
    deep = bool(ctx.opts.get("deep"))
    items = web_items[:MAX_EXTRA_WEBS]
    tls_set = [i for i in items if i[1].startswith("https://")][:MAX_EXTRA_WEBS if deep else 3]
    if len(web_items) > len(items):
        ctx.log(f"Dodatkowe kontrole tylko dla {len(items)} z {len(web_items)} usług WWW")

    def per_web(item):
        wid, url, host, port = item
        found = []
        try:
            found += checks.sensitive_files(url)
            if item in tls_set:
                r = tools_ext.tls_audit(ctx, host, port, tools, deep)
                found += checks.legacy_tls(host, port) if r is None else r
            if host == target and not ip_target and url.startswith("https://"):
                found += checks.security_txt(url)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  kontrola {url}: {e}")
        return wid, found

    with ThreadPoolExecutor(4) as ex:
        for wid, found in ex.map(per_web, items):
            for sev, title, detail, fix in found:
                ctx.finding(wid, sev, title, "builtin", detail, fix)

    if not ip_target:
        found, err = checks.email_auth(target)
        if err:
            ctx.log("  " + err)
        for sev, title, detail, fix in found:
            ctx.finding(root, sev, title, "builtin", detail, fix)


def web_intel(ctx, root, target, ip_target, web_items, tools):
    """Etap: WAF, technologie oraz historyczne/crawlowane adresy URL (w trybie deep także crawling)."""
    ctx.stage("Analiza adresów URL i technologii")
    deep = bool(ctx.opts.get("deep"))
    items = web_items[:MAX_EXTRA_WEBS if deep else 5]

    def one(item):
        try:
            return item, tools_ext.waf_and_tech(ctx, item[1], tools, deep)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  WAF/technologie {item[1]}: {e}")
            return item, (None, [])

    with ThreadPoolExecutor(4) as ex:
        for (wid, url, host, port), (waf, tech) in ex.map(one, items):
            if tech:
                ctx.add_tech(wid, tech)
            if waf:
                ctx.finding(wid, "info", f"Wykryto zaporę aplikacyjną (WAF): {waf}", "builtin", url, "Brak działań, to dobre zabezpieczenie.")
            elif host == target:
                ctx.finding(wid, "info", "Nie wykryto zapory aplikacyjnej (WAF)", "builtin", url,
                            "Rozważ WAF (usługa dostawcy hostingu lub ModSecurity) jako dodatkową warstwę ochrony.")
    if not ip_target:
        try:
            urls = tools_ext.discover_urls(ctx, target, [w[1] for w in web_items], tools, deep)
            tools_ext.analyze_urls(ctx, urls, {w[0] for w in web_items}, root)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  analiza adresów przerwana: {e}")


# ---------- główny pipeline ----------
def pipeline(ctx):
    t, tools = ctx.target, tool_status()
    ctx.log("Narzędzia: " + ", ".join(f"{k}={'OK' if v['installed'] else 'brak (fallback)'}"
                                      for k, v in tools.items()))
    ip_target = is_ip(t)
    root = ctx.asset("ip" if ip_target else "domain", t)
    ip_of = {t: [t]} if ip_target else {}

    if not ip_target:
        ctx.stage("Enumeracja subdomen")
        names = sorted(enum_subdomains(ctx, t, tools) | {t})
        ctx.log(f"Znaleziono nazw: {len(names)}")
        for sev, title, detail, fix in tools_ext.zone_transfer(ctx, t, tools):
            ctx.finding(root, sev, title, "builtin", detail, fix)
        ctx.stage("Rozwiązywanie DNS")
        ip_of, cnames = resolve(ctx, names, tools)
        for n in names:
            nid = root if n == t else ctx.asset("subdomain", n, {"cname": cnames.get(n, [])})
            if n != t:
                ctx.edge(root, nid)
            tk = [c for c in cnames.get(n, []) if c.endswith(TAKEOVER_SUFFIXES)]
            if tk and not ip_of.get(n):
                ctx.finding(nid, "high", "Możliwy subdomain takeover (CNAME do usługi zewnętrznej bez celu)",
                            "builtin", f"{n} -> {tk[0]}",
                            "Usuń wpis CNAME albo odzyskaj zasób u dostawcy; sprawdź szablony nuclei 'takeovers'.")
            elif not ip_of.get(n) and n != t:
                ctx.finding(nid, "low", "Subdomena nie rozwiązuje się w DNS (możliwy dangling record)",
                            "builtin", n, "Usuń nieużywany wpis DNS lub zweryfikuj podatność na subdomain takeover.")
            for ip in ip_of.get(n, []):
                ctx.edge(nid, ctx.asset("ip", ip))

    ips = sorted({ip for v in ip_of.values() for ip in v})
    if not ALLOW_PRIVATE and not ip_target:
        priv = [i for i in ips if not ipaddress.ip_address(i).is_global]
        if priv:
            ctx.log(f"Pomijam adresy nieglobalne (ASI_ALLOW_PRIVATE=1 aby skanować): {priv}")
            ips = [i for i in ips if i not in priv]
    ctx.stage(f"Skan portów ({len(ips)} adresów IP)")
    ports = scan_ports(ctx, ips, tools)
    port_id = {}
    for ip, plist in ports.items():
        for p in plist:
            pid = ctx.asset("port", f"{ip}:{p['port']}", p)
            port_id[(ip, p["port"])] = pid
            ctx.edge(f"ip:{ip}", pid)
            if p["port"] in RISKY and p.get("service") != "tcpwrapped":
                sev, title, fix = RISKY[p["port"]]
                ctx.finding(pid, sev, title, "builtin", f"{ip}:{p['port']} {p['service']} {p['version']}", fix)

    ctx.stage("Sondowanie usług HTTP")
    cand = {}
    for host, hips in ip_of.items():
        for ip in hips:
            for p in ports.get(ip, []):
                sch = web_scheme(p)
                if sch:
                    default = (sch, p["port"]) in (("http", 80), ("https", 443))
                    url = f"{sch}://{host}" + ("" if default else f":{p['port']}")
                    cand[url] = (host, ip, p["port"])
    webs = probe_web(ctx, sorted(cand), tools)
    ctx.log(f"Odpowiadające usługi HTTP: {len(webs)}")
    web_items = []
    for w in webs:
        url = (w["url"] or "").rstrip("/")
        meta = cand.get(url) or cand.get(w["url"])
        if not meta:
            continue
        host, ip, port = meta
        hdr = w.pop("headers", {})
        wid = ctx.asset("web", url, w)
        web_items.append((wid, url, host, port))
        ctx.edge(port_id.get((ip, port), root if host == t else f"subdomain:{host}"), wid)
        st = w["status"]
        if url.startswith("http://") and 200 <= st < 300:
            ctx.finding(wid, "medium", "Usługa dostępna po nieszyfrowanym HTTP bez przekierowania",
                        "builtin", f"{url} -> {st}", "Wymuś przekierowanie 301 na HTTPS i włącz HSTS.")
        if url.startswith("https://"):
            r = tls_check(host, port)
            if r:
                ctx.finding(wid, r[0], r[1], "builtin", r[2], "Odnów/napraw certyfikat (np. Let's Encrypt + automatyzacja).")
            if 200 <= st < 400 and "strict-transport-security" not in hdr:
                ctx.finding(wid, "low", "Brak nagłówka HSTS", "builtin", url, "Dodaj Strict-Transport-Security.")
        if 200 <= st < 300:
            for h, title, sev, fix in SEC_HEADERS:
                if h not in hdr and not (h == "x-frame-options" and "frame-ancestors" in hdr.get("content-security-policy", "")):
                    ctx.finding(wid, sev, title, "builtin", url, fix)
            if re.search(r"\d+\.\d+", hdr.get("x-powered-by", "")):
                ctx.finding(wid, "low", "Ujawnienie technologii w nagłówku X-Powered-By", "builtin", hdr["x-powered-by"],
                            "Usuń nagłówek X-Powered-By (np. expose_php=Off).")
            if re.search(r"\d+\.\d+", w.get("server", "")):
                ctx.finding(wid, "low", "Ujawnienie wersji oprogramowania w nagłówku Server", "builtin",
                            w["server"], "Ukryj wersję (server_tokens off / ServerTokens Prod).")
        if ADMIN_RE.search(w.get("title", "")) and st < 500:
            ctx.finding(wid, "medium", "Potencjalny panel administracyjny/logowania dostępny publicznie",
                        "builtin", f"{url} - \"{w['title']}\"", "Ogranicz dostęp (VPN, allowlista IP, MFA).")

    extra_checks(ctx, root, t, ip_target, web_items, tools)
    web_intel(ctx, root, t, ip_target, web_items, tools)
    ctx.stage("Wywiad zewnętrzny (CVE, wycieki)")
    try:
        intel.enrich(ctx, ips, root, t, ip_target)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  wywiad zewnętrzny przerwany: {type(e).__name__}")

    if ctx.opts.get("nuclei") and tools["nuclei"]["installed"] and webs:
        ctx.stage("Skan podatności (nuclei)")
        if not os.path.isdir(os.path.expanduser("~/nuclei-templates")):
            ctx.log("Brak szablonów nuclei - pobieram (jednorazowo)")
            run_cmd(ctx, ["nuclei", "-update-templates", "-nc"], 600)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(w["url"] for w in webs if w.get("url")))
        try:
            out = run_cmd(ctx, ["nuclei", "-l", f.name, "-jsonl", "-silent", "-nc", "-duc",
                                "-severity", "low,medium,high,critical", "-rate-limit", "50",
                                "-timeout", "6"], 900)
        finally:
            os.unlink(f.name)
        for j in jsonl(out):
            at = (j.get("matched-at") or j.get("host") or "").rstrip("/")
            info = j.get("info", {})
            base = urlparse(at)
            wid = f"web:{base.scheme}://{base.netloc}"
            ctx.finding(wid if wid[4:] in {w['url'].rstrip('/') for w in webs} else root,
                        info.get("severity", "info"), info.get("name", j.get("template-id", "?")),
                        "nuclei", f"{j.get('template-id')} @ {at}", "; ".join(info.get("remediation", "").split("\n"))[:300]
                        or "Zob. referencje szablonu nuclei.")
    elif ctx.opts.get("nuclei"):
        ctx.log("Pomijam nuclei: " + ("brak usług HTTP do przeskanowania" if tools["nuclei"]["installed"]
                                      else "narzędzie niezainstalowane"))


def start_scan(target, opts):
    """Zakłada rekord skanu i uruchamia go w tle. Zwraca id."""
    with db.conn() as c:
        sid = c.execute("INSERT INTO scans(target,opts,created) VALUES(?,?,?)",
                        (target, json.dumps(opts), time.time())).lastrowid
    threading.Thread(target=run_scan, args=(sid,), daemon=True).start()
    return sid


def run_scan(scan_id):
    with SEM:
        ctx = Ctx(scan_id)
        try:
            with db.conn() as c:
                c.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
            pipeline(ctx)
            ctx.finish("done")
            alerts.after_scan(scan_id)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"BŁĄD KRYTYCZNY: {e!r}")
            ctx.finish("failed")
            if ctx.opts.get("schedule_id"):
                alerts.add(scan_id, ctx.target, "warn", "Automatyczne sprawdzenie nie powiodło się.")
