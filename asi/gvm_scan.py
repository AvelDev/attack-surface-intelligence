"""Integracja z Greenbone Vulnerability Management (OpenVAS) przez GMP (python-gvm).

Opcjonalny, głęboki skan podatności - w przeciwieństwie do resztki pipeline'u
(subfinder/naabu/httpx/nuclei) GVM bywa bardzo wolny (minuty do godzin), więc
działa w osobnym wątku w tle, poza główną kolejką szybkich skanów (scanner.SEM),
i dopisuje swoje ustalenia do tego samego skanu, gdy skończy.

GVM community edition wystawia GMP tylko po unix sockecie (/run/gvmd/gvmd.sock).
Gdy GVM stoi w innej sieci/maszynie (np. osobna WSL), potrzebny jest mostek
TCP<->socket po stronie serwera (np. kontener alpine/socat w docker-compose,
patrz docs/openvas.md) - stąd własna klasa połączenia po gołym TCP, bo python-gvm
nie ma wbudowanego "plain TCP" (tylko unix socket / TLS / SSH).
"""
import ipaddress
import os
import socket as socketlib
import threading
import time

from . import db

try:
    # AbstractGvmConnection nie jest re-eksportowana z gvm.connections (tylko Protocol
    # GvmConnection jest publiczne) - stąd import z prywatnego modułu.
    from gvm.connections._connection import AbstractGvmConnection
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeTransform
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

HOST = os.environ.get("ASI_GVM_HOST", "")
PORT = int(os.environ.get("ASI_GVM_PORT", "9390"))
USERNAME = os.environ.get("ASI_GVM_USERNAME", "admin")
PASSWORD = os.environ.get("ASI_GVM_PASSWORD", "")
SCAN_CONFIG_NAME = os.environ.get("ASI_GVM_SCAN_CONFIG", "Full and fast")
SCANNER_NAME = os.environ.get("ASI_GVM_SCANNER", "OpenVAS Default")
PORT_LIST_NAME = os.environ.get("ASI_GVM_PORT_LIST", "All IANA assigned TCP and UDP")
MAX_WAIT = int(os.environ.get("ASI_GVM_MAX_WAIT", "3600"))
POLL_EVERY = 15
CONNECT_TIMEOUT = 15

SEM = threading.Semaphore(1)  # jeden skan GVM naraz, niezależnie od kolejki szybkich skanów
THREAT_SEV = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low",
              "Log": "info", "Alarm": "high", "None": "info"}


def configured():
    return AVAILABLE and bool(HOST and PASSWORD)


def status():
    if not configured():
        return {"configured": False, "reachable": False}
    try:
        with socketlib.create_connection((HOST, PORT), timeout=3):
            return {"configured": True, "reachable": True}
    except OSError:
        return {"configured": True, "reachable": False}


if AVAILABLE:
    class PlainTCPConnection(AbstractGvmConnection):
        """GMP po gołym TCP (bez TLS) - zakłada mostek socat<->unix socket po stronie serwera."""

        def __init__(self, *, hostname="127.0.0.1", port=9390, timeout=60):
            super().__init__(timeout=timeout)
            self.hostname = hostname
            self.port = port

        def connect(self) -> None:
            self._socket = socketlib.create_connection(
                (self.hostname, int(self.port)), timeout=self._timeout)


def _find_id(root, tag, name):
    for el in root.findall(tag):
        if (el.findtext("name") or "") == name:
            return el.get("id")
    return None


def _sev_from_result(r):
    try:
        cvss = float(r.findtext("severity") or 0)
    except ValueError:
        cvss = 0.0
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return THREAT_SEV.get(r.findtext("threat") or "Log", "info")


def run(scan_id, hosts, log):
    """Odpala pełny skan GVM dla podanych hostów/IP; blokuje tylko ten wątek."""
    if not configured() or not hosts:
        return
    with SEM:
        try:
            _run(scan_id, hosts, log)
        except Exception as e:  # noqa: BLE001
            log(f"OpenVAS: błąd: {e!r}")


def _assert_private(host):
    """PlainTCPConnection idzie plaintextem (brak TLS) - nie wysyłaj danych logowania GVM
    poza sieć prywatną/loopback (np. przez przypadkową zmianę ASI_GVM_HOST na publiczny adres)."""
    try:
        ip = ipaddress.ip_address(socketlib.gethostbyname(host))
    except (OSError, ValueError) as e:
        raise RuntimeError(f"OpenVAS: nie można zweryfikować adresu {host!r}: {e}") from e
    if not (ip.is_private or ip.is_loopback):
        raise RuntimeError(
            f"OpenVAS: {host} ({ip}) nie jest adresem prywatnym/loopback - odmawiam wysłania "
            "danych logowania plaintextem (PlainTCPConnection). Dla zdalnych hostów użyj "
            "gvm.connections.TLSConnection lub SSHConnection.")


def _run(scan_id, hosts, log):
    _assert_private(HOST)
    conn = PlainTCPConnection(hostname=HOST, port=PORT, timeout=CONNECT_TIMEOUT)
    with GMP(connection=conn, transform=EtreeTransform()) as gmp:
        gmp.authenticate(USERNAME, PASSWORD)
        config_id = _find_id(gmp.get_scan_configs(), "config", SCAN_CONFIG_NAME)
        scanner_id = _find_id(gmp.get_scanners(), "scanner", SCANNER_NAME)
        port_list_id = _find_id(gmp.get_port_lists(), "port_list", PORT_LIST_NAME)
        if not (config_id and scanner_id and port_list_id):
            log(f"OpenVAS: brak konfiguracji/skanera/listy portów po nazwie "
                f"('{SCAN_CONFIG_NAME}'/'{SCANNER_NAME}'/'{PORT_LIST_NAME}') - pomijam")
            return
        name = f"asi-scan-{scan_id}-{int(time.time())}"
        target_id = gmp.create_target(name=name, hosts=hosts, port_list_id=port_list_id).get("id")
        task_id = gmp.create_task(name=name, config_id=config_id, target_id=target_id,
                                   scanner_id=scanner_id).get("id")
        log(f"OpenVAS: start skanu w tle dla {', '.join(hosts)} (limit {MAX_WAIT}s)")
        gmp.start_task(task_id)
        deadline = time.time() + MAX_WAIT
        task_status = "Requested"
        while time.time() < deadline:
            time.sleep(POLL_EVERY)
            t = gmp.get_task(task_id)
            task_status = t.findtext(".//status") or task_status
            progress = t.findtext(".//progress") or "?"
            log(f"OpenVAS: {task_status} ({progress}%)")
            if task_status in ("Done", "Stopped", "Interrupted"):
                break
        if task_status != "Done":
            gmp.stop_task(task_id)
            log(f"OpenVAS: nie zakończono w limicie czasu (status={task_status}), przerywam")
            return
        report_el = gmp.get_task(task_id).find(".//last_report/report")
        report = gmp.get_report(report_el.get("id"), details=True)
        n = 0
        with db.conn() as c:
            for r in report.findall(".//results/result"):
                sev = _sev_from_result(r)
                if sev == "info":
                    continue
                host = r.findtext("host") or ""
                nvt = r.find("nvt")
                oid = nvt.get("oid") if nvt is not None else ""
                aid = f"ip:{host}" if host else f"scan:{scan_id}"
                c.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                          (scan_id, aid, sev, (r.findtext("name") or "?")[:200], "openvas",
                           (r.findtext("description") or "")[:1000],
                           f"Zob. szczegóły NVT {oid} w raporcie GVM."))
                n += 1
        _bump_score(scan_id)
        log(f"OpenVAS: zakończono, {n} nowych ustaleń")


def _bump_score(scan_id):
    from .scanner import risk_score  # import lokalny - unikamy cyklu modułów na starcie
    with db.conn() as c:
        sevs = [row["severity"] for row in
                c.execute("SELECT severity FROM findings WHERE scan_id=?", (scan_id,))]
        c.execute("UPDATE scans SET score=? WHERE id=?", (risk_score(sevs), scan_id))
