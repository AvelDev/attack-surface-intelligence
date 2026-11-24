"""Opcje -> argumenty nmap. Ta sama funkcja buduje komendę skanu i jej podgląd w interfejsie."""
from dataclasses import dataclass

from ..errors import InvalidInput
from .options import MAX_PORT, MAX_PROTOCOL, NMAP_DEFAULT_PORTS, OPEN_TCP, PING_FLAG, PING_WITH_PORTS, TECHNIQUE_FLAG, count_ports
from .policy import script_expression

UNPRIVILEGED_PING = frozenset({"syn"})  # bez gniazd surowych nmap umie tylko ping przez connect()
# pole -> (flaga, wartość "wyłączone"): opcje, których nmap nie wykona bez gniazd surowych
_RAW_ONLY = {"os": ("-O", False), "traceroute": ("--traceroute", False), "fragment": ("-f", False), "mtu": ("--mtu", None),
             "badsum": ("--badsum", False), "scanflags": ("--scanflags", []), "ttl": ("--ttl", None),
             "data_length": ("--data-length", None), "source_port": ("--source-port", None)}


@dataclass(frozen=True)
class Capabilities:
    """Co potrafi nmap w tym środowisku."""

    raw: bool = False  # gniazda surowe (SYN, UDP, wykrywanie OS...)
    force_privileged: bool = False  # uprawnienie z setcap, nie root: nmapowi trzeba to powiedzieć


def adapt(opts, caps):
    """Dopasowuje opcje do uprawnień: (opcje, [pominięte flagi]). InvalidInput, gdy nie zostaje żadna technika."""
    if caps.raw:
        return opts, []
    update, dropped = {}, []
    if opts.mode == "ports":
        lost = [t for t in opts.techniques if t != "connect"]
        if not set(opts.techniques) & OPEN_TCP:
            raise InvalidInput(f"Opcje nmap: {' '.join(TECHNIQUE_FLAG[t] for t in lost)} wymaga uprawnień do gniazd surowych "
                               "(root albo NET_RAW), których serwer nie ma.")
        if lost:
            update["techniques"] = ["connect"]
            dropped += [TECHNIQUE_FLAG[t] for t in lost]
    if opts.discovery == "custom":
        keep = [p for p in opts.ping if p in UNPRIVILEGED_PING]
        dropped += [PING_FLAG[p] for p in opts.ping if p not in keep]
        update |= {"ping": keep, "discovery": "custom" if keep else "default"}
    for name, (flag, off) in _RAW_ONLY.items():
        if getattr(opts, name):
            update[name] = off
            dropped.append(flag)
    return opts.model_copy(update=update), dropped


def _discovery(opts):
    if opts.discovery == "skip":
        return ["-Pn"]
    if opts.discovery == "default":
        return []
    return [PING_FLAG[p] + (opts.ping_ports if p in PING_WITH_PORTS else "") for p in opts.ping]


def _ports(opts, only_ports):
    if only_ports is not None:
        return ["-p", ",".join(str(p) for p in sorted(only_ports))]
    out = {"top": ["--top-ports", str(opts.top_ports)], "default": [], "range": ["-p", opts.ports], "all": ["-p-"]}[opts.port_mode]
    return out + (["--exclude-ports", opts.exclude_ports] if opts.exclude_ports else []) + ["-r"] * opts.sequential


def _port_scan(opts, only_ports):
    args = ["-Pn"] if only_ports is not None else _discovery(opts)
    args += [TECHNIQUE_FLAG[t] for t in opts.techniques]
    if opts.scanflags:
        args += ["--scanflags", "".join(opts.scanflags)]
    args += _ports(opts, only_ports)
    if opts.version:
        args.append("-sV")
        if opts.version_intensity is not None:
            args += ["--version-intensity", str(opts.version_intensity)]
    if opts.os:
        args += ["-O"] + ["--osscan-limit"] * opts.os_limit + ["--osscan-guess"] * opts.os_guess
    return args


def build(opts, caps, rate, only_ports=None):
    """Argumenty bez celów i pliku wyniku. `only_ports`: porty TCP znalezione przez naabu. Opcje muszą być po adapt()."""
    args = ["--privileged"] if caps.force_privileged else []
    args += ["-sn", *_discovery(opts)] if opts.mode == "hosts" else _port_scan(opts, only_ports)
    args += ["--disable-arp-ping"] * opts.disable_arp_ping + ["--traceroute"] * opts.traceroute
    args += {"never": ["-n"], "auto": [], "always": ["-R"]}[opts.dns]
    if opts.has_scripts:
        args += ["--script", script_expression(opts)]
        if opts.script_args:
            args += ["--script-args", ",".join(f"{k}='{v}'" for k, v in opts.script_args.items())]
        if opts.script_timeout_s:
            args += ["--script-timeout", f"{opts.script_timeout_s}s"]
    args += [f"-T{opts.timing}", "--max-rate", str(rate)]
    if opts.min_rate:
        args += ["--min-rate", str(min(opts.min_rate, rate))]  # nigdy ponad limit tempa skanu
    for value, flag, unit in ((opts.max_retries, "--max-retries", ""), (opts.host_timeout_s, "--host-timeout", "s"),
                              (opts.scan_delay_ms, "--scan-delay", "ms"), (opts.max_parallelism, "--max-parallelism", ""),
                              (opts.mtu, "--mtu", ""), (opts.source_port, "--source-port", ""),
                              (opts.data_length, "--data-length", ""), (opts.ttl, "--ttl", "")):
        if value is not None:
            args += [flag, f"{value}{unit}"]
    return args + ["-f"] * opts.fragment + ["--badsum"] * opts.badsum


def naabu_ports(opts):
    """Zakres portów wstępnego skanu naabu odpowiadający opcjom (naabu zna rankingi 100 i 1000)."""
    if opts.port_mode == "all":
        out = ["-p", "-"]
    elif opts.port_mode == "range":
        out = ["-p", opts.ports.replace("T:", "")]
    else:
        top = opts.top_ports if opts.port_mode == "top" else NMAP_DEFAULT_PORTS
        out = ["-top-ports", "100" if top <= 100 else "1000"]
    return out + (["-exclude-ports", opts.exclude_ports] if opts.exclude_ports else [])


def probes_per_host(opts):
    """Ile sond (bez ponowień) przypada na host - do szacowania czasu i wielkości paczki."""
    if opts.mode == "hosts":
        return 4 if opts.discovery == "default" else sum(max(1, count_ports(opts.ping_ports)) if p in PING_WITH_PORTS else 1 for p in opts.ping)
    everything = MAX_PROTOCOL + 1 if "protocol" in opts.techniques else MAX_PORT
    ports = {"top": opts.top_ports, "default": NMAP_DEFAULT_PORTS, "range": count_ports(opts.ports), "all": everything}[opts.port_mode]
    return min(ports, everything) * len(opts.techniques)


def start_batch(opts):
    """Ile hostów w pierwszej paczce: ciężki skan dostaje małe paczki, żeby postęp i zatrzymanie działały na bieżąco."""
    weight = 4 if opts.has_scripts or opts.os else 1
    return max(4, min(200, 200_000 // max(1, probes_per_host(opts) * weight)))
