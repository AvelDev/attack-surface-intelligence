"""Wykrywanie zewnętrznych narzędzi (Kali/Ubuntu) i integracji. Każde jest opcjonalne - etapy mają fallback w Pythonie.

Szukamy w PATH oraz w ~/go/bin (narzędzia Go) i katalogu interpretera (narzędzia pip z venv), bez modyfikowania
globalnego os.environ - ścieżkę dostaje tylko uruchamiany proces.
"""
import os
import shutil
import subprocess
import sys
from urllib.parse import urlparse

from .. import defectdojo, gvm_scan

TOOLS = ["subfinder", "dnsx", "naabu", "nmap", "httpx", "nuclei",
         "amass", "assetfinder", "dnsrecon", "sslyze", "testssl", "wafw00f", "whatweb", "katana", "gau", "waybackurls"]
TOOL_BIN = {"testssl": ("testssl.sh", "testssl")}  # nazwa narzędzia -> możliwe nazwy pliku
_NAABU_SYN_CACHE = {}


def search_path():
    return os.pathsep.join([os.environ.get("PATH", ""), os.path.expanduser("~/go/bin"), os.path.dirname(sys.executable)])


def which(binary):
    return shutil.which(binary, path=search_path())


def _is_projectdiscovery_httpx(path):
    """Odróżnia httpx ProjectDiscovery od CLI pythonowej biblioteki httpx o tej samej nazwie."""
    try:
        r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    txt = (r.stdout + r.stderr).lower()
    return "projectdiscovery" in txt or "current version" in txt


def naabu_can_syn(path):
    """SYN scan (-s s) jest dużo szybszy niż domyślny connect scan (-s c), ale wymaga cap_net_raw - naabu NIE robi
    tego automatycznie nawet z uprawnieniami, trzeba podać -s jawnie. Dwie drogi do tej capability: setcap na binarce
    (WSL/Kali, zob. scripts/install_tools.sh) albo root w kontenerze Docker z cap_add: [NET_RAW, NET_ADMIN] (wtedy
    getcap na pliku nic nie pokaże, bo capability jest przyznana procesowi, nie plikowi - stąd check na euid).
    Bezpieczny fallback do connect scan, gdy żadnego z tego nie da się potwierdzić."""
    if path in _NAABU_SYN_CACHE:
        return _NAABU_SYN_CACHE[path]
    ok = hasattr(os, "geteuid") and os.geteuid() == 0
    if not ok:
        try:
            r = subprocess.run(["getcap", path], capture_output=True, text=True, timeout=5, check=False)
            ok = "cap_net_raw" in r.stdout.lower()
        except (OSError, subprocess.SubprocessError):
            ok = False
    _NAABU_SYN_CACHE[path] = ok
    return ok


def host_only(url):
    """Do pokazania w /api/tools (widocznym dla każdej roli, nawet 'read') - bez userinfo, na wypadek gdyby ktoś wpisał
    dane logowania wprost w ASI_DEFECTDOJO_URL."""
    if not url:
        return None
    p = urlparse(url)
    netloc = p.hostname or ""
    if p.port:
        netloc += f":{p.port}"
    return f"{p.scheme}://{netloc}" if p.scheme else netloc


def status():
    """{nazwa: {"installed": bool, "path": str|None}} dla narzędzi oraz integracji (openvas, defectdojo)."""
    out = {}
    for name in TOOLS:
        path = next(filter(None, (which(b) for b in TOOL_BIN.get(name, (name,)))), None)
        ok = bool(path) and (name != "httpx" or _is_projectdiscovery_httpx(path))
        out[name] = {"installed": ok, "path": path if ok else None}
    if out["naabu"]["installed"]:
        out["naabu"]["syn"] = naabu_can_syn(out["naabu"]["path"])
    gs = gvm_scan.status()
    gvm_host, gvm_port, _user, _pass = gvm_scan.get_config()
    out["openvas"] = {"installed": gs["reachable"], "path": f"{gvm_host}:{gvm_port}" if gs["configured"] else None}
    out["defectdojo"] = {"installed": defectdojo.configured(), "path": host_only(defectdojo.get_config()[0])}
    return out
