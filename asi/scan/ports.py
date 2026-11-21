"""Etap: otwarte porty (naabu / nmap / TCP connect w Pythonie) i ich weryfikacja banerem."""
import socket
import ssl
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .. import net
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
                result[ip].append(_port(port, SERVICE.get(int(port), "")))
    elif tools["nmap"]["installed"]:
        out = run_cmd(ctx, ["nmap", "-Pn", "-sT", "--top-ports", "100", "-sV", "--version-light",
                            "-T3", "--open", "-oX", "-", *ips], 900)
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


def _verify(ip, port):
    """Zwraca (ok, baner). Odrzuca porty, gdzie 'połączenie' tworzy pośrednik/router
    (TCP handshake OK, ale usługa nie odpowiada) - typowe fałszywe porty 21/22 itp."""
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.settimeout(4)
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
    return out


def web_scheme(p):
    """'https' / 'http' / None dla wykrytego portu."""
    port, svc = p["port"], p.get("service", "")
    if "https" in svc or "ssl/http" in svc or port in (443, 8443, 9443):
        return "https"
    if svc.endswith("http") or svc.startswith("http") or port in HTTP_PORTS:
        return "http"
    return None
