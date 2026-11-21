"""Orkiestrator skanowania powierzchni ataku: jawna lista etapów i wspólny stan.

Każdy etap używa narzędzia z Kali/Ubuntu (subfinder, dnsx, naabu/nmap, httpx, nuclei...), a gdy go brak -
czystego Pythona (fallback), więc aplikacja działa także bez zainstalowanych narzędzi.
Etapy wymagane (required=True) budują model zasobów - ich błąd kończy skan statusem 'failed'.
Etapy opcjonalne tylko wzbogacają wynik - ich błąd trafia do logu, a skan idzie dalej.
Tytuły etapów są widoczne w UI (frontend/src/api.js: STEPS dopasowuje je wyrażeniami regularnymi).
"""
import os
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlparse

from .. import config, domain, targets
from . import checks, dns, intel, ports, urls, web
from .proc import jsonl, run_cmd

MAX_EXTRA_WEBS = 15  # limit hostów dla kontroli plików/TLS, żeby skan nie rozrastał się w nieskończoność


class WebItem(NamedTuple):
    wid: str
    url: str
    host: str
    port: int


@dataclass
class State:
    target: str
    tools: dict
    ip_target: bool
    root: str  # id zasobu głównego
    names: list = field(default_factory=list)
    ip_of: dict = field(default_factory=dict)  # host -> [ip]
    ips: list = field(default_factory=list)
    ports: dict = field(default_factory=dict)  # ip -> [port]
    port_id: dict = field(default_factory=dict)  # (ip, port) -> id zasobu
    webs: list = field(default_factory=list)
    web_items: list = field(default_factory=list)


@dataclass(frozen=True)
class Stage:
    title: str | Callable  # tekst albo funkcja(State) -> tekst
    run: Callable  # funkcja(ctx, State)
    required: bool = True
    applies: Callable = lambda ctx, st: True  # True = uruchom, str = pomiń z tym komunikatem, False = pomiń po cichu


# ---------- etapy ----------
def enumerate_names(ctx, st):
    st.names = sorted(dns.enum_subdomains(ctx, st.target, st.tools) | {st.target})
    ctx.log(f"Znaleziono nazw: {len(st.names)}")
    for f in dns.zone_transfer(ctx, st.target, st.tools):
        ctx.finding(st.root, f[0], f[1], "builtin", f[2], f[3])


def resolve_names(ctx, st):
    st.ip_of, cnames = dns.resolve(ctx, st.names, st.tools)
    for n in st.names:
        is_root = n == st.target
        nid = st.root if is_root else ctx.asset("subdomain", n, {"cname": cnames.get(n, [])})
        if not is_root:
            ctx.edge(st.root, nid)
        f = dns.dangling_finding(n, cnames.get(n, []), bool(st.ip_of.get(n)), is_root)
        if f:
            ctx.finding(nid, f[0], f[1], "builtin", f[2], f[3])
        for ip in st.ip_of.get(n, []):
            ctx.edge(nid, ctx.asset("ip", ip))
    ips = sorted({ip for v in st.ip_of.values() for ip in v})
    if not config.load().allow_private:
        private = [i for i in ips if not targets.is_public(i)]
        if private:
            ctx.log(f"Pomijam adresy nieglobalne (ASI_ALLOW_PRIVATE=1 aby skanować): {private}")
            ips = [i for i in ips if i not in private]
    st.ips = ips


def scan_ports(ctx, st):
    st.ports = ports.scan_ports(ctx, st.ips, st.tools)
    for ip, plist in st.ports.items():
        for p in plist:
            pid = ctx.asset("port", f"{ip}:{p['port']}", p)
            st.port_id[(ip, p["port"])] = pid
            ctx.edge(f"ip:{ip}", pid)
            if p["port"] in ports.RISKY and p.get("service") != "tcpwrapped":
                sev, title, fix = ports.RISKY[p["port"]]
                ctx.finding(pid, sev, title, "builtin", f"{ip}:{p['port']} {p['service']} {p['version']}", fix)


def probe_http(ctx, st):
    cand = {}
    for host, hips in st.ip_of.items():
        for ip in hips:
            for p in st.ports.get(ip, []):
                sch = ports.web_scheme(p)
                if sch:
                    default = (sch, p["port"]) in (("http", 80), ("https", 443))
                    cand[f"{sch}://{host}" + ("" if default else f":{p['port']}")] = (host, ip, p["port"])
    st.webs = web.probe_web(ctx, sorted(cand), st.tools)
    ctx.log(f"Odpowiadające usługi HTTP: {len(st.webs)}")
    for w in st.webs:
        url = (w["url"] or "").rstrip("/")
        meta = cand.get(url) or cand.get(w["url"])
        if not meta:
            continue
        host, ip, port = meta
        hdr = w.pop("headers", {})
        wid = ctx.asset("web", url, w)
        st.web_items.append(WebItem(wid, url, host, port))
        ctx.edge(st.port_id.get((ip, port), st.root if host == st.target else f"subdomain:{host}"), wid)
        if url.startswith("https://"):
            cert = web.tls_check(host, port)
            if cert:
                ctx.finding(wid, cert[0], cert[1], "builtin", cert[2], "Odnów/napraw certyfikat (np. Let's Encrypt + automatyzacja).")
        for sev, title, detail, fix in web.header_findings(url, w["status"], hdr, w.get("server", ""), w.get("title", "")):
            ctx.finding(wid, sev, title, "builtin", detail, fix)


def extra_checks(ctx, st):
    """Ukryte pliki, stary TLS, security.txt, SPF/DMARC. Błąd jednej kontroli nie przerywa pozostałych."""
    items = st.web_items[:MAX_EXTRA_WEBS]
    tls_set = [i for i in items if i.url.startswith("https://")][:MAX_EXTRA_WEBS if ctx.deep else 3]
    if len(st.web_items) > len(items):
        ctx.log(f"Dodatkowe kontrole tylko dla {len(items)} z {len(st.web_items)} usług WWW")

    def per_web(item):
        found = []
        try:
            found += checks.sensitive_files(item.url)
            if item in tls_set:
                found += web.tls_findings(ctx, item.host, item.port, st.tools)
            if item.host == st.target and not st.ip_target and item.url.startswith("https://"):
                found += checks.security_txt(item.url)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  kontrola {item.url}: {e}")
        return item.wid, found

    with ThreadPoolExecutor(4) as ex:
        for wid, found in ex.map(per_web, items):
            for sev, title, detail, fix in found:
                ctx.finding(wid, sev, title, "builtin", detail, fix)

    if not st.ip_target:
        found, err = checks.email_auth(st.target)
        if err:
            ctx.log("  " + err)
        for sev, title, detail, fix in found:
            ctx.finding(st.root, sev, title, "builtin", detail, fix)


def web_intel(ctx, st):
    """WAF, technologie oraz historyczne/crawlowane adresy URL."""
    items = st.web_items[:MAX_EXTRA_WEBS if ctx.deep else 5]

    def one(item):
        try:
            return item, web.waf_and_tech(ctx, item.url, st.tools)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  WAF/technologie {item.url}: {e}")
            return item, (None, [])

    with ThreadPoolExecutor(4) as ex:
        for item, (waf, tech) in ex.map(one, items):
            if tech:
                ctx.add_tech(item.wid, tech)
            if waf:
                ctx.finding(item.wid, "info", f"Wykryto zaporę aplikacyjną (WAF): {waf}", "builtin", item.url,
                            "Brak działań, to dobre zabezpieczenie.")
            elif item.host == st.target:
                ctx.finding(item.wid, "info", "Nie wykryto zapory aplikacyjnej (WAF)", "builtin", item.url,
                            "Rozważ WAF (usługa dostawcy hostingu lub ModSecurity) jako dodatkową warstwę ochrony.")
    if not st.ip_target:
        found = urls.discover_urls(ctx, st.target, [w.url for w in st.web_items], st.tools)
        urls.analyze_urls(ctx, found, {w.wid for w in st.web_items}, st.root)


def external_intel(ctx, st):
    intel.enrich(ctx, st.ips, st.root, st.target, st.ip_target)


def nuclei_applies(ctx, st):
    if not ctx.opts.get("nuclei"):
        return False
    if not st.tools["nuclei"]["installed"]:
        return "Pomijam nuclei: narzędzie niezainstalowane"
    return True if st.webs else "Pomijam nuclei: brak usług HTTP do przeskanowania"


def run_nuclei(ctx, st):
    if not os.path.isdir(os.path.expanduser("~/nuclei-templates")):
        ctx.log("Brak szablonów nuclei - pobieram (jednorazowo)")
        run_cmd(ctx, ["nuclei", "-update-templates", "-nc"], 600)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(w["url"] for w in st.webs if w.get("url")))
    try:
        out = run_cmd(ctx, ["nuclei", "-l", f.name, "-jsonl", "-silent", "-nc", "-duc", "-severity", "low,medium,high,critical",
                            "-rate-limit", "50", "-timeout", "6"], 900)
    finally:
        os.unlink(f.name)
    known = {w["url"].rstrip("/") for w in st.webs if w.get("url")}
    for j in jsonl(out):
        at = (j.get("matched-at") or j.get("host") or "").rstrip("/")
        info = j.get("info", {})
        base = urlparse(at)
        wid = f"web:{base.scheme}://{base.netloc}"
        sev = info.get("severity", "info")
        ctx.finding(wid if wid[4:] in known else st.root, sev if domain.is_severity(sev) else "info",
                    info.get("name", j.get("template-id", "?")), "nuclei", f"{j.get('template-id')} @ {at}",
                    "; ".join(info.get("remediation", "").split("\n"))[:300] or "Zob. referencje szablonu nuclei.")


def _domain_only(ctx, st):
    return not st.ip_target


STAGES = [
    Stage("Enumeracja subdomen", enumerate_names, applies=_domain_only),
    Stage("Rozwiązywanie DNS", resolve_names, applies=_domain_only),
    Stage(lambda st: f"Skan portów ({len(st.ips)} adresów IP)", scan_ports),
    Stage("Sondowanie usług HTTP", probe_http),
    Stage("Dodatkowe kontrole (pliki, poczta, szyfrowanie)", extra_checks, required=False),
    Stage("Analiza adresów URL i technologii", web_intel, required=False),
    Stage("Wywiad zewnętrzny (CVE, wycieki)", external_intel, required=False),
    Stage("Skan podatności (nuclei)", run_nuclei, required=False, applies=nuclei_applies),
]


def initial_state(ctx, tools):
    ip_target = targets.is_ip(ctx.target)
    root = ctx.asset("ip" if ip_target else "domain", ctx.target)
    st = State(target=ctx.target, tools=tools, ip_target=ip_target, root=root)
    if ip_target:
        st.ip_of, st.ips = {ctx.target: [ctx.target]}, [ctx.target]
    return st


def run(ctx, tools, stages=STAGES):
    ctx.log("Narzędzia: " + ", ".join(f"{k}={'OK' if v['installed'] else 'brak (fallback)'}" for k, v in tools.items()))
    st = initial_state(ctx, tools)
    for stage in stages:
        verdict = stage.applies(ctx, st)
        if verdict is not True:
            if verdict:
                ctx.log(verdict)
            continue
        ctx.stage(stage.title(st) if callable(stage.title) else stage.title)
        if stage.required:
            stage.run(ctx, st)
            continue
        try:
            stage.run(ctx, st)
        except Exception as e:  # noqa: BLE001 - etap opcjonalny nie może zepsuć skanu
            ctx.log(f"  etap przerwany: {type(e).__name__}: {e}")
    return st
