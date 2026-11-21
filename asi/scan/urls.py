"""Etap: odkrywanie adresów URL z archiwów (gau / waybackurls / Wayback CDX) i crawling (katana, tryb dokładny).

Sprawdzane aktywnie są tylko adresy z zakresu celu (domena i jej subdomeny), najwyżej MAX_PROBES.
"""
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .. import net
from ..targets import in_scope
from . import checks
from .proc import run_cmd

INTERESTING_EXT = {  # rozszerzenie -> severity
    "sql": "high", "env": "high", "pem": "high", "key": "high", "sqlite": "high", "db": "high", "dump": "high",
    "bak": "medium", "old": "medium", "zip": "medium", "tar": "medium", "gz": "medium", "7z": "medium", "rar": "medium",
    "log": "medium", "conf": "medium", "config": "medium", "ini": "medium", "swp": "medium",
}
URL_RE = re.compile(r"\.([a-z0-9]{2,6})(?:\?|#|$)", re.I)
MAX_URLS = 3000
MAX_PROBES = 25


def discover_urls(ctx, root, web_roots, tools):
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
            urls |= set(net.get_text("http://web.archive.org/cdx/search/cdx?" + q, timeout=40).split())
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  Wayback CDX niedostępny: {type(e).__name__}")
    if ctx.deep and tools["katana"]["installed"] and web_roots:
        urls |= set(run_cmd(ctx, ["katana", "-silent", "-nc", "-jc", "-d", "3", "-c", "5", "-rl", "40", "-ct", "90", "-timeout", "8"],
                            400, stdin="\n".join(web_roots[:5])).split())
    elif ctx.deep:
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
        r = net.fetch(u, limit=1024, timeout=6)
        return c, r

    with ThreadPoolExecutor(5) as ex:
        for (u, ext), r in ex.map(probe, cands[:MAX_PROBES]):
            if r and r.status == 200 and r.body and not checks.is_html(r.headers, r.body):
                p = urllib.parse.urlparse(u)
                wid = f"web:{p.scheme}://{p.netloc}"
                ctx.finding(wid if wid in known_webs else root_asset, INTERESTING_EXT.get(ext, "high"),
                            f"Dostępny plik, który nie powinien być publiczny (.{ext or 'git'})", "builtin", u,
                            "Usuń plik z serwera lub zablokuj dostęp; jeśli zawierał hasła lub dane, uznaj je za ujawnione.")
