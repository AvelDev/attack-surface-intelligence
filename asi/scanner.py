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
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import crypto, db, defectdojo, gvm_scan, signatures

os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + os.path.expanduser("~/go/bin")

JOB_SEM = threading.Semaphore(int(os.environ.get("ASI_MAX_WORKERS", "4")))  # ile skanów (jobów) naraz
DEFAULT_RATE = int(os.environ.get("ASI_SCAN_RATE", "300"))  # pakiety/s dla naabu/nmap (per batch)
BATCH_TARGET_S = 30  # adaptacyjny rozmiar paczki hostów dąży do tylu sekund na paczkę
LOG_LOCK = threading.Lock()  # serializuje read-modify-write Ctx.log() między wątkami jednego procesu
NUCLEI_TEMPLATES_LOCK = threading.Lock()  # dwa równoległe skany nie ściągają szablonów naraz
TOOLS = ["subfinder", "dnsx", "naabu", "nmap", "httpx", "nuclei"]
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


_NAABU_SYN_CACHE = {}


def _naabu_can_syn(path):
    """SYN scan (-s s) jest dużo szybszy niż domyślny connect scan (-s c), ale wymaga
    cap_net_raw na binarce (sudo setcap cap_net_raw,cap_net_admin=eip $(which naabu)) -
    naabu NIE robi tego automatycznie nawet z uprawnieniami, trzeba podać -s jawnie.
    Sprawdzane raz (getcap), z bezpiecznym fallbackiem do connect scan, gdy się nie da
    potwierdzić (getcap niedostępny, brak capability, inny system)."""
    if path in _NAABU_SYN_CACHE:
        return _NAABU_SYN_CACHE[path]
    ok = False
    try:
        r = subprocess.run(["getcap", path], capture_output=True, text=True, timeout=5)
        ok = "cap_net_raw" in r.stdout.lower()
    except Exception:
        ok = False
    _NAABU_SYN_CACHE[path] = ok
    return ok


def tool_status():
    out = {}
    for n in TOOLS:
        p = shutil.which(n)
        ok = bool(p)
        if n == "httpx" and p:  # odróżnij httpx ProjectDiscovery od CLI pythonowego httpx
            try:
                r = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=10)
                txt = (r.stdout + r.stderr).lower()
                ok = "projectdiscovery" in txt or "current version" in txt
            except Exception:
                ok = False
        out[n] = {"installed": ok, "path": p if ok else None}
    if out["naabu"]["installed"]:
        out["naabu"]["syn"] = _naabu_can_syn(out["naabu"]["path"])
    gs = gvm_scan.status()
    out["openvas"] = {"installed": gs["reachable"], "path": f"{gvm_scan.HOST}:{gvm_scan.PORT}" if gs["configured"] else None}
    out["defectdojo"] = {"installed": defectdojo.configured(), "path": _host_only(defectdojo.get_config()[0])}
    return out


def _host_only(url):
    """Do pokazania w /api/tools (widocznym dla każdej roli, nawet 'read') - bez userinfo,
    na wypadek gdyby ktoś wpisał dane logowania wprost w ASI_DEFECTDOJO_URL."""
    if not url:
        return None
    p = urlparse(url)
    netloc = p.hostname or ""
    if p.port:
        netloc += f":{p.port}"
    return f"{p.scheme}://{netloc}" if p.scheme else netloc


class Ctx:
    def __init__(self, scan_id):
        self.id = scan_id
        with db.conn() as c:
            row = c.execute("SELECT target, opts, created FROM scans WHERE id=?", (scan_id,)).fetchone()
            self.targets = [r["target"] for r in
                            c.execute("SELECT target FROM scan_targets WHERE scan_id=?", (scan_id,))]
        self.target, self.opts, self.created = row["target"], json.loads(row["opts"]), row["created"]
        self._seen_f = set()
        # Połączenie trwałe na czas skanu dla metod wołanych wyłącznie z głównego wątku
        # pipeline'u (asset/edge/finding/hosts_*/finish) - otwieranie nowego połączenia +
        # commit + close przy KAŻDYM pojedynczym assecie/findingu mierzalnie spowalniało
        # skany na tysiącach hostów. log()/stage() zostają przy db.conn() per-call, bo log()
        # jest dzielony z wątkiem gvm_scan w tle i ma już własny LOG_LOCK na to.
        self._conn = sqlite3.connect(db.DB_PATH, timeout=30)
        self._conn.row_factory = sqlite3.Row

    def close(self):
        self._conn.close()

    def log(self, msg):
        line = time.strftime("%H:%M:%S ") + str(msg)[:600] + "\n"
        # log jest szyfrowany, więc nie da się appendować atomowo w SQL (log = log || ?) -
        # odczyt+doklejenie+zapis musi być pod globalnym lockiem, inaczej dwa wątki logujące
        # do tego samego skanu (np. główny pipeline i wątek gvm_scan) gubią sobie nawzajem linie.
        with LOG_LOCK, db.conn() as c:
            cur = c.execute("SELECT log FROM scans WHERE id=?", (self.id,)).fetchone()
            new_log = crypto.dec(cur["log"]) + line
            c.execute("UPDATE scans SET log=? WHERE id=?", (crypto.enc(new_log), self.id))

    def stage(self, name):
        self.log(f"=== {name} ===")
        with db.conn() as c:
            c.execute("UPDATE scans SET stage=? WHERE id=?", (name, self.id))

    def asset(self, kind, value, data=None):
        aid = f"{kind}:{value}"
        self._conn.execute("INSERT OR REPLACE INTO assets(scan_id,id,kind,value,data) VALUES(?,?,?,?,?)",
                           (self.id, aid, kind, value, crypto.enc(json.dumps(data or {}))))
        self._conn.commit()
        return aid

    def edge(self, src, dst):
        if src != dst:
            self._conn.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?)", (self.id, src, dst))
            self._conn.commit()

    def check_time_limit(self):
        limit_m = self.opts.get("time_window_mins")
        if limit_m and (time.time() - self.created) > (int(limit_m) * 60):
            raise TimeoutError(f"Przekroczono okno czasowe skanu ({limit_m} min)")

    def finding(self, asset, sev, title, source, detail="", fix=""):
        key = (asset, title)
        if key in self._seen_f:
            return
        self._seen_f.add(key)
        ov = self._conn.execute(
            "SELECT severity, fix, false_positive FROM finding_overrides WHERE asset=? AND title=?",
            (asset, title)).fetchone()
        if ov:
            sev = ov["severity"]
            if ov["fix"]:
                fix = ov["fix"]
            if ov["false_positive"]:
                sev = "info"
                title = f"[False Positive] {title}"
        self._conn.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                           (self.id, asset, sev, title, source, crypto.enc(detail[:1000]), fix))
        self._conn.commit()

    def hosts_total(self, n):
        self._conn.execute("UPDATE scans SET hosts_total=? WHERE id=?", (n, self.id))
        self._conn.commit()

    def hosts_progress(self, done):
        self._conn.execute("UPDATE scans SET hosts_done=? WHERE id=?", (done, self.id))
        self._conn.commit()

    def finish(self, status):
        sev = [r["severity"] for r in self._conn.execute(
            "SELECT severity FROM findings WHERE scan_id=?", (self.id,))]
        stage_txt = "zakończony" if status == "done" else ("okno czasowe (wstrzymany)" if status == "paused_window" else "błąd")
        self._conn.execute("UPDATE scans SET status=?, stage=?, score=?, finished=?, duration_s=? WHERE id=?",
                           (status, stage_txt, risk_score(sev), time.time(), time.time() - self.created, self.id))
        self._conn.commit()


def risk_score(severities):
    """0-100, malejące przyrosty: kilka krytycznych szybko wyciąga wynik w górę."""
    total = sum(SEV_W.get(s, 0) for s in severities)
    return min(100, int(100 * (1 - 0.985 ** total)))


def run_cmd(ctx, cmd, timeout, stdin=None):
    ctx.log("$ " + " ".join(cmd))
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0 and not r.stdout:
            ctx.log(f"  kod wyjścia {r.returncode}: {r.stderr.strip()[-300:]}")
        return r.stdout
    except subprocess.TimeoutExpired as e:
        ctx.log("  przekroczono limit czasu")
        o = e.stdout
        return o.decode(errors="ignore") if isinstance(o, bytes) else (o or "")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  błąd: {e}")
        return ""


def jsonl(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                pass


# ---------- etap 1: subdomeny ----------
def enum_subdomains(ctx, root, tools):
    found = set()
    if tools["subfinder"]["installed"]:
        out = run_cmd(ctx, ["subfinder", "-d", root, "-silent", "-timeout", "20", "-max-time", "3"], 240)
        found |= {x.strip().lower() for x in out.splitlines() if x.strip()}
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


def scan_ports(ctx, ips, tools, rate=None):
    rate = rate or DEFAULT_RATE
    result = {ip: [] for ip in ips}
    if not ips:
        return result
    if tools["naabu"]["installed"]:
        scan_type = "s" if _naabu_can_syn(tools["naabu"]["path"]) else "c"
        out = run_cmd(ctx, ["naabu", "-list", "/dev/stdin", "-top-ports", "100", "-rate", str(rate),
                            "-s", scan_type, "-silent", "-json"], 600, stdin="\n".join(ips))
        for j in jsonl(out):
            ip, port = j.get("ip") or j.get("host"), j.get("port")
            if ip in result and port:
                result[ip].append({"port": int(port), "service": SERVICE.get(int(port), ""), "version": ""})
    elif tools["nmap"]["installed"]:
        out = run_cmd(ctx, ["nmap", "-Pn", "-sT", "--top-ports", "100", "-sV", "--version-light",
                            "-T3", "--open", "--max-rate", str(rate), "-oX", "-"] + list(ips), 900)
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


def batched_port_scan(ctx, ips, tools, rate=None, start_batch=200):
    """Dzieli listę IP na paczki, adaptując rozmiar do zmierzonej przepustowości tak, by każda
    paczka trwała ~BATCH_TARGET_S - realizuje "podział na optymalne podgrupy" i daje postęp/czas
    trwania widoczne w trakcie (duży pojedynczy skan naabu/nmap nie dałby żadnego postępu)."""
    result = {}
    if not ips:
        return result
    batch_size, done = max(1, start_batch), 0
    i = 0
    while i < len(ips):
        ctx.check_time_limit()
        chunk = ips[i:i + batch_size]
        t0 = time.time()
        result.update(scan_ports(ctx, chunk, tools, rate=rate))
        elapsed = time.time() - t0
        i += len(chunk)
        done += len(chunk)
        ctx.hosts_progress(done)
        ctx.log(f"Paczka {len(chunk)} hostów w {elapsed:.1f}s ({done}/{len(ips)})")
        if elapsed > 0.5:
            batch_size = max(50, min(2000, int(len(chunk) / elapsed * BATCH_TARGET_S)))
    return result


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


TECH_HEADER_HINTS = [
    ("server", "nginx", "Nginx"), ("server", "apache", "Apache"), ("server", "cloudflare", "Cloudflare"),
    ("server", "microsoft-iis", "IIS"), ("server", "gunicorn", "Gunicorn"), ("server", "litespeed", "LiteSpeed"),
    ("x-powered-by", "php", "PHP"), ("x-powered-by", "asp.net", "ASP.NET"), ("x-powered-by", "express", "Express"),
]
TECH_COOKIE_HINTS = [
    ("phpsessid", "PHP"), ("jsessionid", "Java/JSP"), ("laravel_session", "Laravel"),
    ("wordpress_", "WordPress"), ("ci_session", "CodeIgniter"), ("django", "Django"),
]
TECH_BODY_HINTS = [
    ("wp-content", "WordPress"), ("wp-includes", "WordPress"), ("joomla!", "Joomla"),
    ("drupal.settings", "Drupal"), ("/sites/default/", "Drupal"), ("cdn.shopify.com", "Shopify"),
    ("__next_data__", "Next.js"), ("ng-version", "Angular"), ("data-reactroot", "React"),
]
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


def detect_tech(headers, body):
    """Proste, bezpieczne wykrywanie technologii/CMS po nagłówkach i treści strony (pkt 6
    specyfikacji) - używane tylko w fallbacku bez httpx (ProjectDiscovery), który ma własny
    -tech-detect. Wyłącznie pasywna detekcja obecności, zgodnie z duchem modułu sygnatur."""
    found = set()
    for h, needle, name in TECH_HEADER_HINTS:
        if needle in headers.get(h, "").lower():
            found.add(name)
    cookie = headers.get("set-cookie", "").lower()
    for needle, name in TECH_COOKIE_HINTS:
        if needle in cookie:
            found.add(name)
    low_body = (body or "").lower()
    for needle, name in TECH_BODY_HINTS:
        if needle in low_body:
            found.add(name)
    m = GENERATOR_RE.search(body or "")
    if m:
        found.add(m.group(1).strip()[:60])
    return sorted(found)


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
            "server": h.get("server", ""), "tech": detect_tech(h, body), "headers": h, "body": body[:20000]}


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


# ---------- główny pipeline ----------
def pipeline(ctx):
    targets, tools = ctx.targets, tool_status()
    ctx.log("Narzędzia: " + ", ".join(f"{k}={'OK' if v['installed'] else 'brak (fallback)'}"
                                      for k, v in tools.items()))
    ctx.log(f"Cele: {len(targets)}")
    domains = [t for t in targets if not is_ip(t)]
    ip_targets = [t for t in targets if is_ip(t)]

    ip_of = {}  # host (domena/subdomena/IP-cel) -> [ip,...]
    root_id = {}  # host -> id assetu reprezentującego ten cel wejściowy
    for t in ip_targets:
        root_id[t] = ctx.asset("ip", t)
        ip_of[t] = [t]

    if domains:
        ctx.stage(f"Enumeracja subdomen ({len(domains)} domen)")
        name_to_domain = {}
        for d in domains:
            root_id[d] = ctx.asset("domain", d)
            for n in enum_subdomains(ctx, d, tools) | {d}:
                name_to_domain.setdefault(n, d)
        names = sorted(name_to_domain)
        ctx.log(f"Znaleziono nazw: {len(names)}")
        ctx.stage("Rozwiązywanie DNS")
        resolved, cnames = resolve(ctx, names, tools)
        for n in names:
            d = name_to_domain[n]
            nid = root_id[d] if n == d else ctx.asset("subdomain", n, {"cname": cnames.get(n, [])})
            if n != d:
                ctx.edge(root_id[d], nid)
            tk = [c for c in cnames.get(n, []) if c.endswith(TAKEOVER_SUFFIXES)]
            if tk and not resolved.get(n):
                ctx.finding(nid, "high", "Możliwy subdomain takeover (CNAME do usługi zewnętrznej bez celu)",
                            "builtin", f"{n} -> {tk[0]}",
                            "Usuń wpis CNAME albo odzyskaj zasób u dostawcy; sprawdź szablony nuclei 'takeovers'.")
            elif not resolved.get(n) and n != d:
                ctx.finding(nid, "low", "Subdomena nie rozwiązuje się w DNS (możliwy dangling record)",
                            "builtin", n, "Usuń nieużywany wpis DNS lub zweryfikuj podatność na subdomain takeover.")
            ip_of[n] = resolved.get(n, [])
            for ip in ip_of[n]:
                ctx.edge(nid, ctx.asset("ip", ip))

    # IP podane wprost (cel lub CIDR) nie podlegają filtrowi prywatności - to świadomy wybór
    # użytkownika (np. skan wewnętrznej sieci 10.0.0.0/8). Filtr dotyczy tylko adresów
    # odkrytych przez DNS z domen - tam nieoczekiwana prywatna odpowiedź bywa podejrzana.
    direct_ips = {t for t in ip_targets}
    resolved_ips = {ip for host, v in ip_of.items() if host not in direct_ips for ip in v}
    if not ALLOW_PRIVATE:
        priv = [i for i in resolved_ips if not ipaddress.ip_address(i).is_global]
        if priv:
            ctx.log(f"Pomijam adresy nieglobalne z DNS (ASI_ALLOW_PRIVATE=1 aby skanować): {priv}")
            resolved_ips -= set(priv)
    ips = sorted(direct_ips | resolved_ips)
    ctx.hosts_total(len(ips))
    if ctx.opts.get("gvm"):
        if gvm_scan.configured():
            ctx.log(f"OpenVAS: zlecam głęboki skan w tle dla {len(ips)} adresów "
                     "(wolny, nie blokuje kolejki ani wyniku tego skanu)")
            threading.Thread(target=gvm_scan.run, args=(ctx.id, ips, ctx.log), daemon=True).start()
        else:
            ctx.log("OpenVAS: pomijam - nieskonfigurowany (ASI_GVM_HOST / ASI_GVM_PASSWORD)")

    ctx.stage(f"Skan portów ({len(ips)} adresów IP)")
    ports = batched_port_scan(ctx, ips, tools, rate=ctx.opts.get("rate_limit"))
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
    sigs = signatures.list_all()  # raz na skan, nie per-asset
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
    for w in webs:
        url = (w["url"] or "").rstrip("/")
        meta = cand.get(url) or cand.get(w["url"])
        if not meta:
            continue
        host, ip, port = meta
        hdr = w.pop("headers", {})
        body = w.pop("body", "")
        wid = ctx.asset("web", url, w)
        ctx.edge(port_id.get((ip, port), root_id.get(host, f"subdomain:{host}")), wid)
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
            if re.search(r"\d+\.\d+", w.get("server", "")):
                ctx.finding(wid, "low", "Ujawnienie wersji oprogramowania w nagłówku Server", "builtin",
                            w["server"], "Ukryj wersję (server_tokens off / ServerTokens Prod).")
        if ADMIN_RE.search(w.get("title", "")) and st < 500:
            ctx.finding(wid, "medium", "Potencjalny panel administracyjny/logowania dostępny publicznie",
                        "builtin", f"{url} - \"{w['title']}\"", "Ogranicz dostęp (VPN, allowlista IP, MFA).")
        signatures.apply(ctx, url, hdr, body, sigs)

    if ctx.opts.get("nuclei") and tools["nuclei"]["installed"] and webs:
        ctx.stage("Skan podatności (nuclei)")
        with NUCLEI_TEMPLATES_LOCK:
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
            ctx.finding(wid if wid[4:] in {w['url'].rstrip('/') for w in webs} else f"scan:{ctx.id}",
                        info.get("severity", "info"), info.get("name", j.get("template-id", "?")),
                        "nuclei", f"{j.get('template-id')} @ {at}", "; ".join(info.get("remediation", "").split("\n"))[:300]
                        or "Zob. referencje szablonu nuclei.")
    elif ctx.opts.get("nuclei"):
        ctx.log("Pomijam nuclei: " + ("brak usług HTTP do przeskanowania" if tools["nuclei"]["installed"]
                                      else "narzędzie niezainstalowane"))


def run_scan(scan_id):
    with JOB_SEM:
        ctx = Ctx(scan_id)
        try:
            with db.conn() as c:
                c.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
            pipeline(ctx)
            ctx.finish("done")
        except TimeoutError as te:
            ctx.log(f"WSTRZYMANO: {te} - wznowienie nastąpi w kolejnym oknie czasowym.")
            ctx.finish("paused_window")
        except Exception as e:  # noqa: BLE001
            ctx.log(f"BŁĄD KRYTYCZNY: {e!r}")
            ctx.finish("failed")
        finally:
            ctx.close()
