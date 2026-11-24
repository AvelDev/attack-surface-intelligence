"""Etap: otwarte porty (naabu / nmap / TCP connect w Pythonie) i ich weryfikacja banerem."""
import socket
import ssl
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .. import config, net
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


def parse_nmap_xml(xml, wanted_ips):
    """Wynik `nmap -oX -` -> {ip: [port]}. Pomija porty zamknięte i 'tcpwrapped'. ET.ParseError przy złym XML."""
    result = {ip: [] for ip in wanted_ips}
    for h in ET.fromstring(xml).iter("host"):
        a = h.find("address[@addrtype='ipv4']")
        if a is None or a.get("addr") not in result:
            continue
        for p in h.iter("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            s = p.find("service")
            s = s.attrib if s is not None else {}
            if s.get("name") == "tcpwrapped":
                continue  # połączenie zamykane od razu - port w rzeczywistości zamknięty
            result[a.get("addr")].append(_port(
                p.get("portid"),
                (s.get("tunnel", "") + "/" if s.get("tunnel") else "") + s.get("name", ""),
                " ".join(x for x in (s.get("product"), s.get("version")) if x)))
    return result


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
    result = {ip: [] for ip in ips}
    if not ips:
        return result, set()
    if tools["naabu"]["installed"]:
        scan_type = "s" if tools_mod.naabu_can_syn(tools["naabu"]["path"]) else "c"
        out = run_cmd(ctx, ["naabu", "-list", "/dev/stdin", "-top-ports", "100", "-rate", str(rate),
                            "-s", scan_type, "-silent", "-json"], 600, stdin="\n".join(ips))
        for j in jsonl(out):
            ip, port = j.get("ip") or j.get("host"), j.get("port")
            if ip in result and port:
                result[ip].append(_port(port, SERVICE.get(int(port), "")))
    elif tools["nmap"]["installed"]:
        out = run_cmd(ctx, ["nmap", "-Pn", "-sT", "--top-ports", "100", "-sV", "--version-light",
                            "-T3", "--open", "--max-rate", str(rate), "-oX", "-", *ips], 900)
        try:
            result = parse_nmap_xml(out, ips)
        except ET.ParseError:
            ctx.log("  nie udało się sparsować XML z nmap")
    else:
        ctx.log(f"Brak naabu/nmap - skan TCP connect w Pythonie ({len(PY_PORTS)} portów)")
        jobs = [(ip, p) for ip in ips for p in PY_PORTS]
        with ThreadPoolExecutor(64) as ex:
            for (ip, p), ok in zip(jobs, ex.map(lambda j: _tcp_open(*j), jobs), strict=True):
                if ok:
                    result[ip].append(_port(p, SERVICE.get(p, "")))
    return verify_ports(ctx, result)


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
    jobs = [(ip, p) for ip, pl in result.items() for p in pl]
    with ThreadPoolExecutor(32) as ex:
        # jedna powtórka dla odrzuconych - chroni przed chwilowymi zwłokami w sieci
        verdicts = list(ex.map(lambda j: _verify(j[0], j[1]["port"]), jobs))
        retry = [i for i, v in enumerate(verdicts) if not v[0]]
        for i, v in zip(retry, ex.map(lambda i: _verify(jobs[i][0], jobs[i][1]["port"]), retry), strict=True):
            verdicts[i] = v
    out = {ip: [] for ip in result}
    dropped = []
    for (ip, p), (ok, banner) in zip(jobs, verdicts, strict=True):
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
    # answered = host w ogóle coś pokazał (nawet jeśli weryfikacja wszystko odrzuciła)
    answered = {ip for ip, plist in result.items() if plist}
    return out, answered


def web_scheme(p):
    """'https' / 'http' / None dla wykrytego portu."""
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
            pid = ctx.asset("port", f"{ip}:{p['port']}", p)
            ctx.edge(f"ip:{ip}", pid)
            if p["port"] in RISKY and p.get("service") != "tcpwrapped":
                sev, title, fix = RISKY[p["port"]]
                ctx.finding(pid, sev, title, "builtin", f"{ip}:{p['port']} {p['service']} {p['version']}", fix)


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


def batched_port_scan(ctx, ips, tools, rate=None, start_batch=200, track_progress=True, done_offset=0):
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
    batch_size, done, i = max(1, start_batch), 0, 0
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
            batch_size = max(50, min(2000, int(len(chunk) / elapsed * BATCH_TARGET_S)))
    if track_progress:
        ctx.save_checkpoint(pending_ips=None)  # ten etap w całości zrobiony - nic do doskanowania
    return result, answered
