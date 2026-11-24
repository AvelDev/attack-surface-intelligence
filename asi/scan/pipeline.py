"""Orkiestrator skanowania powierzchni ataku: jawna lista etapów i wspólny stan.

Skan obejmuje jeden lub wiele celów (domeny, adresy IP, rozwinięte zakresy CIDR). Każdy etap używa narzędzia
z Kali/Ubuntu (subfinder, dnsx, naabu/nmap, httpx, nuclei...), a gdy go brak - czystego Pythona (fallback), więc
aplikacja działa także bez zainstalowanych narzędzi.

Etapy wymagane (required=True) budują model zasobów - ich błąd kończy skan statusem 'failed'. Etapy opcjonalne tylko
wzbogacają wynik - ich błąd trafia do logu, a skan idzie dalej.

Wznowienie po oknie czasowym: punkt wznowienia (checkpoint) przechowuje mapowanie host -> IP, id zasobów celów i listę
adresów, które zostały do przeskanowania. Wznowiony skan pomija enumerację subdomen i DNS (już zrobione i zapisane)
oraz kontynuuje skan portów od miejsca przerwania.

Tytuły etapów są widoczne w UI (frontend/src/api.js dopasowuje je wyrażeniami regularnymi).
"""
import os
import tempfile
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlparse

from .. import config, domain, gvm_scan, signatures, targets
from . import checks, dns, intel, nmap_scan, ports, urls, web
from .context import ScanStopped, WindowExceeded
from .proc import jsonl, run_cmd

MAX_EXTRA_WEBS = 15  # limit hostów dla kontroli plików/TLS, żeby skan nie rozrastał się w nieskończoność
NUCLEI_TEMPLATES_LOCK = threading.Lock()  # dwa równoległe skany nie ściągają szablonów naraz


class WebItem(NamedTuple):
    wid: str
    url: str
    host: str
    port: int


@dataclass
class State:
    targets: list
    tools: dict
    domains: list  # cele będące domenami
    root_id: dict = field(default_factory=dict)  # cel wejściowy -> id zasobu
    name_to_domain: dict = field(default_factory=dict)  # nazwa (domena lub subdomena) -> domena-cel
    ip_of: dict = field(default_factory=dict)  # host -> [ip]
    pending_ips: list = field(default_factory=list)  # adresy do przeskanowania (przy wznowieniu: tylko reszta)
    done_offset: int = 0  # ile adresów policzono już w poprzednich posiedzeniach
    resumed: bool = False
    ports: dict = field(default_factory=dict)  # ip -> [port]
    webs: list = field(default_factory=list)
    web_items: list = field(default_factory=list)
    sigs: list = field(default_factory=list)


@dataclass(frozen=True)
class Stage:
    title: str | Callable | None  # tekst, funkcja(State) -> tekst albo None (krok bez własnego etapu w UI)
    run: Callable  # funkcja(ctx, State)
    required: bool = True
    applies: Callable = lambda ctx, st: True  # True = uruchom, str = pomiń z tym komunikatem, False = pomiń po cichu


# ---------- etapy ----------
def enumerate_names(ctx, st):
    for d in st.domains:
        st.root_id[d] = ctx.asset("domain", d)
        for n in dns.enum_subdomains(ctx, d, st.tools) | {d}:
            st.name_to_domain.setdefault(n, d)
        for f in dns.zone_transfer(ctx, d, st.tools):
            ctx.finding(st.root_id[d], f[0], f[1], "builtin", f[2], f[3])
    ctx.log(f"Znaleziono nazw: {len(st.name_to_domain)}")


def resolve_names(ctx, st):
    names = sorted(st.name_to_domain)
    resolved, cnames = dns.resolve(ctx, names, st.tools)
    for n in names:
        d = st.name_to_domain[n]
        is_root = n == d
        nid = st.root_id[d] if is_root else ctx.asset("subdomain", n, {"cname": cnames.get(n, [])})
        if not is_root:
            ctx.edge(st.root_id[d], nid)
        f = dns.dangling_finding(n, cnames.get(n, []), bool(resolved.get(n)), is_root)
        if f:
            ctx.finding(nid, f[0], f[1], "builtin", f[2], f[3])
        st.ip_of[n] = resolved.get(n, [])
        for ip in st.ip_of[n]:
            ctx.edge(nid, ctx.asset("ip", ip))


def prepare_scope(ctx, st):
    """Ustala listę adresów do przeskanowania, zapisuje punkt wznowienia i (opcjonalnie) zleca głęboki skan OpenVAS."""
    for t in st.targets:
        if targets.is_ip(t):
            st.root_id[t] = ctx.asset("ip", t)
            st.ip_of[t] = [t]
    # IP podane wprost (cel lub CIDR) nie podlegają filtrowi prywatności - to świadomy wybór użytkownika (np. skan
    # wewnętrznej sieci 10.0.0.0/8). Filtr dotyczy tylko adresów odkrytych przez DNS z domen - nieoczekiwana prywatna
    # odpowiedź bywa tam podejrzana.
    direct = {t for t in st.targets if targets.is_ip(t)}
    resolved = {ip for host, v in st.ip_of.items() if host not in direct for ip in v}
    if not config.load().allow_private:
        private = [i for i in resolved if not targets.is_public(i)]
        if private:
            ctx.log(f"Pomijam adresy nieglobalne z DNS (ASI_ALLOW_PRIVATE=1 aby skanować): {private}")
            resolved -= set(private)
    st.pending_ips = sorted(direct | resolved)
    ctx.hosts_total(len(st.pending_ips))
    ctx.save_checkpoint(ip_of=st.ip_of, root_id=st.root_id, pending_ips=st.pending_ips, hosts_total=len(st.pending_ips))
    if ctx.opts.get("gvm"):
        if gvm_scan.configured():
            ctx.log(f"OpenVAS: zlecam głęboki skan w tle dla {len(st.pending_ips)} adresów "
                    "(wolny, nie blokuje kolejki ani wyniku tego skanu)")
            threading.Thread(target=gvm_scan.run, args=(ctx.id, st.pending_ips, ctx.log), daemon=True).start()
        else:
            ctx.log("OpenVAS: pomijam - nieskonfigurowany (ASI_GVM_HOST / ASI_GVM_PASSWORD)")


def scan_ports(ctx, st):
    rate = ctx.opts.get("rate_limit")
    if st.pending_ips:
        nmap_scan.announce(ctx, st.tools)
        found, answered = ports.batched_port_scan(ctx, st.pending_ips, st.tools, rate=rate, done_offset=st.done_offset)
        if nmap_scan.seeks_open_tcp(ctx, st.tools):
            # powtórka sonduje porty TCP - przy wykrywaniu hostów, UDP i badaniu zapory nic by nie wniosła
            ports.retry_silent_hosts(ctx, found, answered, st.tools, rate=rate)
    else:
        ctx.log("Skan portów zakończony w poprzednim przebiegu")
    # Zawsze z bazy, nie z lokalnego dict-a - poprawne i dla świeżego przebiegu, i dla wznowienia (porty hostów
    # doskanowanych PRZED przerwaniem już tam są, więc etap HTTP obejmie też ich, nie tylko tę resztę).
    st.ports = ports.reload_scanned_ports(ctx)


def probe_http(ctx, st):
    cand = {}
    for host, hips in st.ip_of.items():
        for ip in hips:
            for p in st.ports.get(ip, []):
                sch = ports.web_scheme(p)
                if sch:
                    default = (sch, p["port"]) in (("http", 80), ("https", 443))
                    cand[f"{sch}://{host}" + ("" if default else f":{p['port']}")] = (host, ip, p["port"])
    st.sigs = signatures.list_all()  # raz na skan, nie per zasób
    st.webs = web.probe_web(ctx, sorted(cand), st.tools)
    ctx.log(f"Odpowiadające usługi HTTP: {len(st.webs)}")
    for w in st.webs:
        url = (w["url"] or "").rstrip("/")
        meta = cand.get(url) or cand.get(w["url"])
        if not meta:
            continue
        host, ip, port = meta
        hdr = w.pop("headers", {})
        body = w.pop("body", "")
        wid = ctx.asset("web", url, w)
        st.web_items.append(WebItem(wid, url, host, port))
        ctx.edge(f"port:{ip}:{port}", wid)
        if url.startswith("https://"):
            cert = web.tls_check(host, port)
            if cert:
                ctx.finding(wid, cert[0], cert[1], "builtin", cert[2], "Odnów/napraw certyfikat (np. Let's Encrypt + automatyzacja).")
        for sev, title, detail, fix in web.header_findings(url, w["status"], hdr, w.get("server", ""), w.get("title", "")):
            ctx.finding(wid, sev, title, "builtin", detail, fix)
        signatures.apply(ctx, url, hdr, body, st.sigs)


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
            if item.host in st.domains and item.url.startswith("https://"):
                found += checks.security_txt(item.url)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  kontrola {item.url}: {e}")
        return item.wid, found

    with ThreadPoolExecutor(4) as ex:
        for wid, found in ex.map(per_web, items):
            for sev, title, detail, fix in found:
                ctx.finding(wid, sev, title, "builtin", detail, fix)

    for d in st.domains:
        found, err = checks.email_auth(d)
        if err:
            ctx.log("  " + err)
        for sev, title, detail, fix in found:
            ctx.finding(st.root_id[d], sev, title, "builtin", detail, fix)


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
            elif item.host in st.domains:
                ctx.finding(item.wid, "info", "Nie wykryto zapory aplikacyjnej (WAF)", "builtin", item.url,
                            "Rozważ WAF (usługa dostawcy hostingu lub ModSecurity) jako dodatkową warstwę ochrony.")
    known = {w.wid for w in st.web_items}
    for d in st.domains:
        found = urls.discover_urls(ctx, d, [w.url for w in st.web_items if targets.in_scope(w.host, d)], st.tools)
        urls.analyze_urls(ctx, found, known, st.root_id[d])


def intel_applies(ctx, st):
    """Wywiad zewnętrzny wysyła publiczne adresy skanowanych celów do osób trzecich (Shodan, NVD, Censys), więc jest
    opt-in: opcja skanu `intel` albo ASI_EXTERNAL_INTEL=1. Adresy prywatne nigdy nie opuszczają aplikacji."""
    if not (ctx.opts.get("intel") or config.load().external_intel):
        return False
    return True if _public_ips(st) or st.domains else "Wywiad zewnętrzny: brak publicznych adresów ani domen"


def _public_ips(st):
    return sorted({ip for v in st.ip_of.values() for ip in v if targets.is_public(ip)})


def external_intel(ctx, st):
    intel.enrich(ctx, _public_ips(st), {d: st.root_id[d] for d in st.domains})


def nuclei_applies(ctx, st):
    if not ctx.opts.get("nuclei"):
        return False
    if not st.tools["nuclei"]["installed"]:
        return "Pomijam nuclei: narzędzie niezainstalowane"
    return True if st.webs else "Pomijam nuclei: brak usług HTTP do przeskanowania"


def run_nuclei(ctx, st):
    with NUCLEI_TEMPLATES_LOCK:
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
    fallback = next(iter(st.root_id.values()), f"scan:{ctx.id}")
    for j in jsonl(out):
        at = (j.get("matched-at") or j.get("host") or "").rstrip("/")
        info = j.get("info", {})
        base = urlparse(at)
        wid = f"web:{base.scheme}://{base.netloc}"
        sev = info.get("severity", "info")
        ctx.finding(wid if wid[4:] in known else fallback, sev if domain.is_severity(sev) else "info",
                    info.get("name", j.get("template-id", "?")), "nuclei", f"{j.get('template-id')} @ {at}",
                    "; ".join(info.get("remediation", "").split("\n"))[:300] or "Zob. referencje szablonu nuclei.")


def _fresh_domains(ctx, st):
    return bool(st.domains) and not st.resumed


STAGES = [
    Stage(lambda st: f"Enumeracja subdomen ({len(st.domains)} domen)", enumerate_names, applies=_fresh_domains),
    Stage("Rozwiązywanie DNS", resolve_names, applies=_fresh_domains),
    Stage(None, prepare_scope, applies=lambda ctx, st: not st.resumed),
    Stage(lambda st: f"Skan portów ({len(st.pending_ips)} adresów IP)" if st.pending_ips else "Skan portów (zakończony w poprzednim przebiegu)",
          scan_ports),
    Stage("Sondowanie usług HTTP", probe_http),
    Stage("Dodatkowe kontrole (pliki, poczta, szyfrowanie)", extra_checks, required=False),
    Stage("Analiza adresów URL i technologii", web_intel, required=False),
    Stage("Wywiad zewnętrzny (CVE, wycieki)", external_intel, required=False, applies=intel_applies),
    Stage("Skan podatności (nuclei)", run_nuclei, required=False, applies=nuclei_applies),
]


def initial_state(ctx, tools):
    st = State(targets=ctx.targets, tools=tools, domains=[t for t in ctx.targets if not targets.is_ip(t)])
    cp = ctx.load_checkpoint()
    if cp:
        st.resumed = True
        st.ip_of, st.root_id = cp["ip_of"], cp["root_id"]
        st.pending_ips = cp.get("pending_ips") or []
        # Pochodna z hosts_total zapisanego RAZ przy pierwszym przebiegu, nie osobny licznik - inaczej przy drugim
        # i kolejnym wznowieniu offset zostałby z poprzedniego przebiegu i pasek postępu cofnąłby się.
        total = cp.get("hosts_total", len(st.pending_ips))
        st.done_offset = total - len(st.pending_ips)
        ctx.log(f"Wznowienie po oknie czasowym - pomijam ponowną enumerację subdomen/DNS "
                f"({st.done_offset} z {total} adresów już doskanowanych wcześniej)")
    return st


def run(ctx, tools, stages=STAGES):
    ctx.log("Narzędzia: " + ", ".join(f"{k}={'OK' if v['installed'] else 'brak (fallback)'}" for k, v in tools.items()))
    ctx.log(f"Cele: {len(ctx.targets)}")
    st = initial_state(ctx, tools)
    for stage in stages:
        verdict = stage.applies(ctx, st)
        if verdict is not True:
            if verdict:
                ctx.log(verdict)
            continue
        if stage.title is not None:
            ctx.stage(stage.title(st) if callable(stage.title) else stage.title)
        if stage.required:
            stage.run(ctx, st)
            continue
        try:
            stage.run(ctx, st)
        except (ScanStopped, WindowExceeded):  # zatrzymanie i okno czasowe nigdy nie są "błędem opcjonalnego etapu"
            raise
        except Exception as e:  # noqa: BLE001 - etap opcjonalny nie może zepsuć skanu
            ctx.log(f"  etap przerwany: {type(e).__name__}: {e}")
    return st

