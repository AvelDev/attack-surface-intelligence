"""Uruchomienie nmapa dla paczki adresów: komenda z opcji, postęp na żywo, zapis surowego XML i danych o hostach."""
import contextlib
import os
import re
import tempfile
import time

from .. import config
from ..nmap import command, options, parser, policy, rules
from .proc import run_stream
from .tools import nmap_capabilities

TIMEOUT_S = int(os.environ.get("ASI_NMAP_TIMEOUT", "14400"))  # twardy limit jednego uruchomienia, niezależny od --host-timeout
STATS_EVERY = "10s"
PROGRESS = re.compile(r"About ([\d.]+)% done")
# Wiersze, które operator ma zobaczyć w dzienniku; reszta tekstu nmapa dubluje XML.
NOTABLE = re.compile(r"^(?!\||SF)(?:.*QUITTING|warning|error|failed|skipping host|.*giving up|.*requires root)", re.I)
HOST_FIELDS = ("state", "reason", "hostnames", "mac", "vendor", "os", "uptime_s", "distance", "trace", "scripts", "states", "timed_out")


def external_allowed(scan_opts):
    """Skrypty wysyłające dane o celach na zewnątrz: tylko z wywiadem zewnętrznym (opcja skanu albo ustawienie serwera)."""
    return bool(scan_opts.get("intel") or config.load().external_intel)


def for_scan(ctx, tools):
    """Opcje nmap tego skanu albo None (skan bez nmapa lub brak narzędzia)."""
    raw = ctx.opts.get("nmap")
    return _permitted(ctx, raw)[0] if raw and tools["nmap"]["installed"] else None


def _permitted(ctx, raw):
    return policy.restrict(options.parse(raw), gated=config.load().nmap_intrusive, external=external_allowed(ctx.opts))


def announce(ctx, tools):
    """Raz na skan: co z zapisanych opcji nie zostanie wykonane na tym serwerze."""
    raw = ctx.opts.get("nmap")
    if not raw:
        return
    if not tools["nmap"]["installed"]:
        ctx.log("Pomijam opcje nmap: narzędzie niezainstalowane, skanuję zamiennikiem")
        return
    dropped = _permitted(ctx, raw)[1]
    if dropped:
        ctx.log(f"NSE: pomijam niedozwolone na tym serwerze: {', '.join(dropped)}")


def seeks_open_tcp(ctx, tools):
    opts = for_scan(ctx, tools)
    return opts is None or (opts.mode == "ports" and bool(set(opts.techniques) & options.OPEN_TCP))


def batch_bounds(ctx, tools):
    """(wielkość pierwszej paczki, najmniejsza paczka) dla skanu."""
    opts = for_scan(ctx, tools)
    if opts is None:
        return 200, 50
    start = command.start_batch(opts)
    return start, min(50, start)


def run(ctx, ips, opts, tools, rate, only_ports=None):
    """Skanuje adresy i zapisuje dane hostów. Zwraca listę hostów (parser.parse); przerwany skan daje hosty, które zdążył."""
    caps, _version = nmap_capabilities(tools["nmap"]["path"])
    opts, dropped = command.adapt(opts, caps)
    if dropped:
        ctx.log(f"nmap bez uprawnień do gniazd surowych, pomijam: {' '.join(dropped)}")
    args = command.build(opts, caps, rate, only_ports)
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="asi-nmap-")
    os.close(fd)
    started = time.time()
    try:
        try:
            code = run_stream(ctx, ["nmap", *args, "--stats-every", STATS_EVERY, "-oX", path, "-iL", "-"], TIMEOUT_S,
                              stdin="\n".join(ips) + "\n", on_line=_progress(ctx))
        finally:
            # Także po zatrzymaniu i oknie czasowym: surowy wynik tego, co nmap zdążył, zostaje przy skanie.
            result = _collect(ctx, path, ["nmap", *args], started, len(ips))
        if code:
            ctx.log(f"  nmap zakończył się kodem {code}")
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)
    hosts = [h for h in result if h["ip"] in set(ips)]
    for h in hosts:
        persist_host(ctx, h)
    return hosts


def _collect(ctx, path, cmd, started, total):
    with open(path, encoding="utf-8", errors="replace") as f:
        xml = f.read()
    try:
        parsed = parser.parse(xml)
    except parser.BadXml as e:
        ctx.log(f"  nmap: brak wyniku ({e})")
        return []
    ctx.db.add_nmap_run(display(cmd), started, time.time() - started, parsed["complete"], total,
                        sum(1 for h in parsed["hosts"] if responded(h)), xml)
    return parsed["hosts"]


def display(cmd):
    """Komenda do pokazania: cudzysłów tylko tam, gdzie argument ma spacje."""
    return " ".join(f'"{a}"' if " " in a or "(" in a else a for a in cmd)


def _progress(ctx):
    last = {"pct": None}

    def on_line(line):
        m = PROGRESS.search(line)
        if m and m[1] != last["pct"]:
            last["pct"] = m[1]
            ctx.log(f"  nmap: {float(m[1]):.0f}%")
        elif not m and NOTABLE.search(line):
            ctx.log(f"  nmap: {line[:200]}")

    return on_line


def host_data(h):
    """Pola hosta zapisywane w danych zasobu `ip`."""
    return {k: h[k] for k in HOST_FIELDS if h.get(k)}


def persist_host(ctx, h):
    if responded(h):  # -Pn: host "up" z założenia i bez żadnej odpowiedzi to nie jest informacja o hoście
        aid = ctx.merge_asset("ip", h["ip"], host_data(h))
        for f in rules.findings(h.get("scripts")):
            ctx.finding(aid, *f)


def responded(h):
    """Czy host naprawdę się odezwał: odkrycie z konkretnym powodem albo jakakolwiek odpowiedź na sondę portu."""
    if h["ports"]:
        return True
    if h["state"] != "up":
        return False
    return h["reason"] != "user-set" or any(s["state"] in ("closed", "unfiltered") for s in h["states"])
