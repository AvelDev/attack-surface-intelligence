"""Katalog skryptów NSE z pliku script.db zainstalowanego nmapa."""
import functools
import os
import re
import shutil
from pathlib import Path

ENTRY = re.compile(r'filename\s*=\s*"([^"]+)\.nse"\s*,\s*categories\s*=\s*\{([^}]*)\}')


def parse_db(text):
    return {name: sorted(re.findall(r'"([^"]+)"', cats)) for name, cats in ENTRY.findall(text)}


def _data_dirs():
    if os.environ.get("NMAPDIR"):
        yield Path(os.environ["NMAPDIR"])
    binary = shutil.which("nmap")
    if binary:  # na Windows katalog skryptów leży obok binarki, na Linuksie w ../share/nmap
        here = Path(binary).resolve().parent
        yield here
        yield here.parent / "share" / "nmap"
    yield Path("/usr/share/nmap")


@functools.lru_cache(maxsize=1)
def catalog():
    """{nazwa: [kategorie]}; puste, gdy nmapa nie ma."""
    for base in _data_dirs():
        db = base / "scripts" / "script.db"
        if db.is_file():
            return parse_db(db.read_text(encoding="utf-8", errors="ignore"))
    return {}
