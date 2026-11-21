"""Wykrywanie zewnętrznych narzędzi (Kali/Ubuntu). Każde jest opcjonalne - etapy mają fallback w Pythonie.

Szukamy w PATH oraz w ~/go/bin (narzędzia Go) i katalogu interpretera (narzędzia pip z venv), bez modyfikowania
globalnego os.environ - ścieżkę dostaje tylko uruchamiany proces.
"""
import os
import shutil
import subprocess
import sys

TOOLS = ["subfinder", "dnsx", "naabu", "nmap", "httpx", "nuclei",
         "amass", "assetfinder", "dnsrecon", "sslyze", "testssl", "wafw00f", "whatweb", "katana", "gau", "waybackurls"]
TOOL_BIN = {"testssl": ("testssl.sh", "testssl")}  # nazwa narzędzia -> możliwe nazwy pliku


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


def status():
    """{nazwa: {"installed": bool, "path": str|None}} dla każdego znanego narzędzia."""
    out = {}
    for name in TOOLS:
        path = next(filter(None, (which(b) for b in TOOL_BIN.get(name, (name,)))), None)
        ok = bool(path) and (name != "httpx" or _is_projectdiscovery_httpx(path))
        out[name] = {"installed": ok, "path": path if ok else None}
    return out
