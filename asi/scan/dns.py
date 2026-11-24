"""Etapy DNS: wyszukiwanie subdomen, transfer strefy (AXFR), rozwiązywanie nazw i wiszące rekordy."""
import json
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from .. import net
from ..targets import is_domain
from . import checks
from .proc import jsonl, run_cmd

TAKEOVER_SUFFIXES = ("github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
                     "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
                     "netlify.app", "readme.io", "zendesk.com", "myshopify.com", "pantheonsite.io",
                     "surge.sh", "ghost.io", "wordpress.com", "fastly.net", "bitbucket.io", "statuspage.io")
AXFR_FINDING = ("high", "Serwer DNS pozwala każdemu pobrać całą strefę (AXFR)",
                "Ogranicz transfer stref (allow-transfer) tylko do uprawnionych serwerów pomocniczych.")


# ---------- subdomeny ----------
def _passive_fallback(ctx, root):
    """Darmowe źródła pasywne, gdy brak amass/assetfinder."""
    found = set()
    sources = (
        ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={root}", lambda t: [x.split(",")[0] for x in t.splitlines()]),
        ("Anubis", f"https://jldc.me/anubis/subdomains/{root}", json.loads),
    )
    for name, url, parse in sources:
        try:
            found |= {n.strip().lower() for n in parse(net.get_text(url)) if isinstance(n, str)}
        except Exception as e:  # noqa: BLE001 - niedostępne źródło nie przerywa skanu
            ctx.log(f"  {name} niedostępne: {type(e).__name__}")
    return found


def _crtsh(ctx, root):
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    ctx.log(f"GET {url}")
    try:
        return {n.strip().lower().lstrip("*.") for row in net.get_json(url, timeout=30)
                for n in row.get("name_value", "").split("\n")}
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  crt.sh niedostępne: {e}")
        return set()


def enum_subdomains(ctx, root, tools):
    """Zbiór nazw w zakresie celu (root i jego poprawne subdomeny) ze wszystkich dostępnych źródeł."""
    found = set()
    if tools["subfinder"]["installed"]:
        out = run_cmd(ctx, ["subfinder", "-d", root, "-silent", "-timeout", "20", "-max-time", "3"], 240)
        found |= {x.strip().lower() for x in out.splitlines() if x.strip()}
    have_extra = False
    if tools["amass"]["installed"]:
        have_extra = True
        cmd = (["amass", "enum", "-d", root, "-timeout", "5", "-silent"] if ctx.deep else
               ["amass", "enum", "-passive", "-d", root, "-timeout", "3", "-silent"])
        found |= {x.split()[0].lower() for x in run_cmd(ctx, cmd, 420 if ctx.deep else 240).splitlines() if x.strip()}
    if tools["assetfinder"]["installed"]:
        have_extra = True
        found |= {x.strip().lower() for x in run_cmd(ctx, ["assetfinder", "--subs-only", root], 120).splitlines() if x.strip()}
    if not have_extra:
        found |= _passive_fallback(ctx, root)
    found |= _crtsh(ctx, root)
    return {n for n in found if n == root or (n.endswith("." + root) and is_domain(n))}


# ---------- transfer strefy DNS (AXFR) ----------
def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def axfr_query(domain):
    """Zapytanie DNS AXFR w formacie TCP (bez prefiksu długości)."""
    q = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00" + struct.pack(">HH", 252, 1)
    return struct.pack(">HHHHHH", 0x4153, 0, 1, 0, 0, 0) + q


def axfr_response_ok(resp):
    """Odpowiedź bez błędu (RCODE=0) z co najmniej jednym rekordem = transfer dozwolony."""
    return len(resp) >= 12 and (resp[3] & 0x0F) == 0 and struct.unpack(">H", resp[6:8])[0] > 0


def _axfr_allowed(ns_ip, domain):
    msg = axfr_query(domain)
    try:
        with socket.create_connection((ns_ip, 53), timeout=6) as s:
            s.settimeout(6)
            s.sendall(struct.pack(">H", len(msg)) + msg)
            ln = _recvn(s, 2)
            if len(ln) < 2:
                return False
            return axfr_response_ok(_recvn(s, min(struct.unpack(">H", ln)[0], 1024)))
    except OSError:
        return False


def zone_transfer(ctx, root, tools):
    """Lista ustaleń (0 lub 1). dnsrecon, jeśli jest; w przeciwnym razie własna implementacja AXFR."""
    sev, title, fix = AXFR_FINDING
    if tools["dnsrecon"]["installed"]:
        out = run_cmd(ctx, ["dnsrecon", "-d", root, "-t", "axfr"], 120)
        return [(sev, title, root, fix)] if re.search(r"zone transfer was successful", out, re.I) else []
    try:
        ns = checks.doh(root, "NS")
    except Exception as e:  # noqa: BLE001
        ctx.log(f"  AXFR pominięty (DoH niedostępne: {type(e).__name__})")
        return []
    for n in ns[:4]:
        try:
            ip = socket.gethostbyname(n.rstrip("."))
        except OSError:
            continue
        if _axfr_allowed(ip, root):
            return [(sev, title, f"{n} ({ip})", fix)]
    return []


# ---------- rozwiązywanie nazw ----------
def resolve(ctx, names, tools):
    """Zwraca (host -> [ip], host -> [cname])."""
    res, cnames = {}, {}
    if tools["dnsx"]["installed"]:
        out = run_cmd(ctx, ["dnsx", "-silent", "-a", "-cname", "-resp", "-json", "-retry", "1"], 180, stdin="\n".join(names))
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


def dangling_finding(name, cnames, resolves, is_root):
    """Czysta reguła dla nazwy bez adresu IP: (severity, tytuł, detail, zalecenie) albo None."""
    if resolves:
        return None
    takeover = [c for c in cnames if c.endswith(TAKEOVER_SUFFIXES)]
    if takeover:
        return ("high", "Możliwy subdomain takeover (CNAME do usługi zewnętrznej bez celu)", f"{name} -> {takeover[0]}",
                "Usuń wpis CNAME albo odzyskaj zasób u dostawcy; sprawdź szablony nuclei 'takeovers'.")
    if not is_root:
        return ("low", "Subdomena nie rozwiązuje się w DNS (możliwy dangling record)", name,
                "Usuń nieużywany wpis DNS lub zweryfikuj podatność na subdomain takeover.")
    return None
