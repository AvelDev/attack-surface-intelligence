"""Etap: otwarte porty (naabu / nmap / TCP connect w Pythonie) i ich weryfikacja banerem."""
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .. import config, net
from ..nmap import command, rules
from ..nmap import options as nmap_options
from . import nmap_scan
from . import tools as tools_mod
from .proc import jsonl, run_cmd

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
RISKY_UDP = {
    69: ("medium", "TFTP wystawiony do internetu", "Wyłącz TFTP albo ogranicz dostęp."),
    161: ("medium", "SNMP wystawiony do internetu", "Użyj SNMPv3 i ogranicz dostęp do stacji zarządzających."),
    623: ("high", "IPMI wystawiony do internetu", "Przenieś interfejs zarządzania do wydzielonej sieci."),
    1900: ("medium", "SSDP/UPnP wystawiony do internetu", "Wyłącz UPnP na brzegu sieci."),
    11211: ("high", "Memcached (UDP) wystawiony do internetu", "Wyłącz UDP i ogranicz nasłuch do sieci aplikacji."),
}
SENSITIVE_PORTS = frozenset({21, 23, 445, 3389, 5900, 3306, 5432, 6379, 27017, 9200, 1433})  # warte alarmu, gdy widzi je ktoś inny
BANNER_EXPECT = {21: b"220", 22: b"SSH-", 25: b"220", 110: b"+OK", 143: b"* OK"}
HTTP_PORTS = {80, 8000, 8008, 8080, 8888, 3000}
TLS_PORTS = {443, 8443, 9443, 993, 995}
BATCH_TARGET_S = 30  # adaptacyjny rozmiar paczki hostów dąży do tylu sekund na paczkę
# Drugi przebieg nie powtarza top-100 na całej martwej sieci: najpierw kilka portów, na których żywy host zwykle coś
# odpowie. Kolejność od tych z twardym banerem (środkownik, który tylko kończy handshake, odpada) do usług z RISKY.
LIVENESS_PORTS = (80, 443, 22, 8080, 8443, 21, 25, 445, 3389)
LIVENESS_TIMEOUT = 1.2
HOST_RETRY_PAUSE_S = 3  # odstęp, żeby chwilowy zanik nie wypadł w tej samej sekundzie co pierwszy przebieg


def _port(port, service="", version=""):
    return {"port": int(port), "service": service, "version": version}


def is_tcp(p):
    return p.get("proto", "tcp") == "tcp"


def port_value(ip, p):
    """Wartość zasobu `port`. TCP bez przyrostka (zgodność z wcześniejszymi skanami), reszta z protokołem: 10.0.0.1:161/udp."""
    return f"{ip}:{p['port']}" + ("" if is_tcp(p) else f"/{p['proto']}")


def port_findings(ip, p):
    """Ustalenia wynikające z samego otwartego portu: ryzykowna usługa i wyniki skryptów NSE."""
    out = rules.findings(p.get("scripts"))
    risky = (RISKY if is_tcp(p) else RISKY_UDP if p["proto"] == "udp" else {}).get(p["port"])
    if risky and p.get("service") != "tcpwrapped":
        sev, title, fix = risky
        out.insert(0, (sev, title, "builtin", f"{port_value(ip, p)} {p.get('service', '')} {p.get('version', '')}".strip(), fix))
    return out


def _tcp_open(ip, port, timeout=1.5):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(ctx, ips, tools, rate=None):
    """Zwraca ({ip: [port]}, answered). `answered` to adresy, które cokolwiek pokazały przed weryfikacją -
    pusta lista portów BEZ wpisu w `answered` znaczy "nie odezwał się", nie "fałszywe porty"."""
    rate = rate or config.load().scan_rate
    if not ips:
        return {}, set()
    opts = nmap_scan.for_scan(ctx, tools)
    if opts is None and not tools["naabu"]["installed"] and tools["nmap"]["installed"]:
        opts = nmap_options.FALLBACK
    if opts is not None:
        result, responded = _scan_nmap(ctx, ips, opts, tools, rate)
    elif tools["naabu"]["installed"]:
        result, responded = _scan_naabu(ctx, ips, tools, rate, ["-top-ports", "100"]), set()
    else:
        result, responded = _scan_python(ctx, ips), set()
    confirmed, answered = verify_ports(ctx, result)
    return confirmed, answered | responded


def _scan_naabu(ctx, ips, tools, rate, port_args, timeout=600):
    result = {ip: [] for ip in ips}
    scan_type = "s" if tools_mod.naabu_can_syn(tools["naabu"]["path"]) else "c"
    out = run_cmd(ctx, ["naabu", "-list", "/dev/stdin", *port_args, "-rate", str(rate), "-s", scan_type, "-silent", "-json"],
                  timeout, stdin="\n".join(ips))
    for j in jsonl(out):
        ip, port = j.get("ip") or j.get("host"), j.get("port")
        if ip in result and port:
            result[ip].append(_port(port, SERVICE.get(int(port), "")))
    return result


def _scan_python(ctx, ips):
    result = {ip: [] for ip in ips}
    ctx.log(f"Brak naabu/nmap - skan TCP connect w Pythonie ({len(PY_PORTS)} portów)")
    jobs = [(ip, p) for ip in ips for p in PY_PORTS]
    with ThreadPoolExecutor(64) as ex:
        for (ip, p), ok in zip(jobs, ex.map(lambda j: _tcp_open(*j), jobs), strict=True):
            if ok:
                result[ip].append(_port(p, SERVICE.get(p, "")))
    return result


def _scan_nmap(ctx, ips, opts, tools, rate):
    """({ip: [port]}, hosty, które się odezwały). Z prescan: naabu znajduje porty, nmap bada tylko je i tylko hosty z portami."""
    result, only_ports, wanted = {ip: [] for ip in ips}, None, ips
    if opts.prescan and tools["naabu"]["installed"]:
        result = _scan_naabu(ctx, ips, tools, rate, command.naabu_ports(opts), timeout=nmap_scan.TIMEOUT_S)
        wanted = [ip for ip in ips if result[ip]]
        only_ports = {p["port"] for ip in wanted for p in result[ip]}
        if not wanted:
            return result, set()
    hosts = nmap_scan.run(ctx, wanted, opts, tools, rate, only_ports)
    for h in hosts:
        known = {(p["port"], p["proto"]) for p in h["ports"]}
        # port znaleziony przez naabu, którego nmap nie potwierdził, rozstrzyga verify_ports
        result[h["ip"]] = h["ports"] + [p for p in result[h["ip"]] if (p["port"], "tcp") not in known]
    return result, {h["ip"] for h in hosts if nmap_scan.responded(h)}


def banner_verdict(port, data):
    """Czysta reguła: czy odebrany baner potwierdza usługę. Zwraca (ok, baner)."""
    if not data:
        return False, ""  # zamknięte natychmiast = tcpwrapped / pośrednik
    exp = BANNER_EXPECT.get(port)
    if exp and not data.startswith(exp):
        return False, data[:60].decode("latin1")
    return True, (data[:120].decode("latin1", "ignore").splitlines() or [""])[0].strip()


def _verify(ip, port, timeout=4):
    """Zwraca (ok, baner). Odrzuca porty, gdzie 'połączenie' tworzy pośrednik/router
    (TCP handshake OK, ale usługa nie odpowiada) - typowe fałszywe porty 21/22 itp."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in TLS_PORTS:
                with net.insecure_tls().wrap_socket(s, server_hostname=ip) as t:
                    return True, t.version() or ""
            if port in HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            try:
                data = s.recv(256)
            except TimeoutError:
                # usługa czeka na klienta (np. SMB, RDP, Redis) - OK, chyba że oczekujemy banera
                return port not in BANNER_EXPECT, ""
            return banner_verdict(port, data)
    except (ssl.SSLError, OSError):
        return False, ""


def verify_ports(ctx, result):
    jobs = [(ip, p) for ip, pl in result.items() for p in pl if is_tcp(p)]
    with ThreadPoolExecutor(32) as ex:
        # jedna powtórka dla odrzuconych - chroni przed chwilowymi zwłokami w sieci
        verdicts = list(ex.map(lambda j: _verify(j[0], j[1]["port"]), jobs))
        retry = [i for i, v in enumerate(verdicts) if not v[0]]
        for i, v in zip(retry, ex.map(lambda i: _verify(jobs[i][0], jobs[i][1]["port"]), retry), strict=True):
            verdicts[i] = v
    out = {ip: [p for p in pl if not is_tcp(p)] for ip, pl in result.items()}
    dropped = []
    for (ip, p), (ok, banner) in zip(jobs, verdicts, strict=True):
        if ok or p.get("probed"):  # nmap -sV rozmawiał z usługą i ją rozpoznał - to mocniejszy dowód niż baner
            if ok and banner:
                p["banner"] = banner
            out[ip].append(p)
        else:
            dropped.append(f"{ip}:{p['port']}")
    if dropped:
        ctx.log(f"Odrzucono fałszywe/niepotwierdzone porty: {', '.join(dropped)}")
    for ip in out:
        out[ip].sort(key=lambda x: (x["port"], x.get("proto", "tcp")))
    # answered = host w ogóle coś pokazał (nawet jeśli weryfikacja wszystko odrzuciła)
    answered = {ip for ip, plist in result.items() if plist}
    return out, answered


def web_scheme(p):
    """'https' / 'http' / None dla wykrytego portu."""
    if not is_tcp(p):
        return None
    port, svc = p["port"], p.get("service", "")
    if "https" in svc or "ssl/http" in svc or port in (443, 8443, 9443):
        return "https"
    if svc.endswith("http") or svc.startswith("http") or port in HTTP_PORTS:
        return "http"
    return None


class _RateGate:
    """Rozsuwa start kolejnych prób tak, by nie przekroczyć rate pakietów/s."""

    def __init__(self, per_sec):
        self.interval = 1.0 / max(1, int(per_sec))
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            slot = self._next if self._next > now else now
            self._next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def _host_alive(ctx, ip, gate):
    """Jedna próba: czy host odpowiada na którymś z LIVENESS_PORTS. Pierwszy sukces kończy."""
    ctx.check_time_limit()
    for port in LIVENESS_PORTS:
        gate.wait()
        ok, _banner = _verify(ip, port, timeout=LIVENESS_TIMEOUT)
        if ok:
            return True
    return False


def persist_batch(ctx, found):
    """Zasób, krawędź i ustalenie dla portów znalezionych w JEDNEJ paczce - musi trafić do bazy zanim ewentualnie
    wywali nas kolejny ctx.check_time_limit(), inaczej cała paczka, którą naprawdę przeskanowaliśmy, przepadnie
    razem z przekroczonym oknem czasowym."""
    for ip, plist in found.items():
        for p in plist:
            pid = ctx.asset("port", port_value(ip, p), p)
            ctx.edge(f"ip:{ip}", pid)
            for f in port_findings(ip, p):
                ctx.finding(pid, *f)


def reload_scanned_ports(ctx):
    """{ip: [port]} z zasobów 'port' już zapisanych dla tego skanu - źródło prawdy dla etapu HTTP, poprawne zarówno dla
    świeżego przebiegu, jak i wznowienia po oknie czasowym (porty z przebiegu PRZED przerwaniem już są w bazie dzięki
    persist_batch, więc etap HTTP obejmie też hosty doskanowane w poprzedniej sesji)."""
    return ctx.db.stored_ports()


def retry_silent_hosts(ctx, ports, answered, tools, rate=None, pause_s=HOST_RETRY_PAUSE_S):
    """Jedno ponowne sondowanie hostów, które w tym przebiegu wcale nie odpowiedziały.

    Host z portami odrzuconymi przez verify_ports (jest w `answered`) nie jest martwy - odezwał się, tylko usługa nie
    potwierdziła się - i nie wchodzi w tę ścieżkę. Najpierw krótki test osiągalności pod tym samym limitem tempa co skan
    portów, potem pełny skan wyłącznie dla hostów, które przy drugiej próbie jednak odpowiedziały."""
    silent = [ip for ip, plist in ports.items() if not plist and ip not in answered]
    if not silent:
        return ports
    limit = rate or config.load().scan_rate
    ctx.stage(f"Ponowne sondowanie ({len(silent)} hostów bez odpowiedzi)")
    ctx.log(f"Przerwa {pause_s}s, potem test osiągalności (limit {limit} pkt/s)")
    if pause_s:
        time.sleep(pause_s)
    ctx.check_time_limit()
    gate = _RateGate(limit)
    with ThreadPoolExecutor(min(128, len(silent))) as ex:
        flags = list(ex.map(lambda ip: _host_alive(ctx, ip, gate), silent))
    woke = [ip for ip, ok in zip(silent, flags, strict=True) if ok]
    ctx.log(f"Przy ponownej próbie odpowiedziało {len(woke)} z {len(silent)}")
    if not woke:
        return ports
    extra, _ignored = batched_port_scan(ctx, woke, tools, rate=rate, track_progress=False)
    recovered = 0
    for ip, plist in extra.items():
        if plist:
            ports[ip] = plist
            recovered += 1
    ctx.log(f"Pełny skan powtórzony dla {len(woke)} hostów, potwierdzone usługi: {recovered}")
    return ports


def batched_port_scan(ctx, ips, tools, rate=None, start_batch=None, track_progress=True, done_offset=0):
    """Dzieli listę IP na paczki, adaptując rozmiar do zmierzonej przepustowości tak, by każda paczka trwała
    ~BATCH_TARGET_S - daje "podział na optymalne podgrupy" oraz postęp widoczny w trakcie (jeden wielki skan naabu/nmap
    nie dałby żadnego postępu). Zwraca (porty, answered).

    `track_progress=False` przy powtórce wąskiego podzbioru (retry_silent_hosts), żeby pasek hosts_done i punkt
    wznowienia nie cofnęły się z pełnej listy do rozmiaru tej podgrupy - zasoby z podgrupy i tak trafiają do bazy.
    `done_offset` to liczba hostów już policzona w hosts_done PRZED tym wywołaniem (wznowienie po oknie czasowym -
    pasek ma kontynuować, nie zaczynać od 0)."""
    result, answered = {}, set()
    if not ips:
        return result, answered
    first, smallest = nmap_scan.batch_bounds(ctx, tools)
    batch_size, done, i = max(1, start_batch or first), 0, 0
    while i < len(ips):
        if track_progress:
            # Zanim spróbujemy kolejnej paczki (i ewentualnie wywalimy się na oknie czasowym) - zapisz, co jeszcze zostało.
            # To jest punkt wznowienia; ip_of/root_id/hosts_total zostają nietknięte (save_checkpoint scala pola).
            ctx.save_checkpoint(pending_ips=ips[i:])
        ctx.check_time_limit()
        chunk = ips[i:i + batch_size]
        t0 = time.time()
        found, ans = scan_ports(ctx, chunk, tools, rate=rate)
        result.update(found)
        answered |= ans
        persist_batch(ctx, found)
        elapsed = time.time() - t0
        i += len(chunk)
        done += len(chunk)
        if track_progress:
            ctx.hosts_progress(done_offset + done)
        ctx.log(f"Paczka {len(chunk)} hostów w {elapsed:.1f}s ({done_offset + done}/{done_offset + len(ips)})")
        if elapsed > 0.5:
            batch_size = max(smallest, min(2000, int(len(chunk) / elapsed * BATCH_TARGET_S)))
    if track_progress:
        ctx.save_checkpoint(pending_ips=None)  # ten etap w całości zrobiony - nic do doskanowania
    return result, answered
