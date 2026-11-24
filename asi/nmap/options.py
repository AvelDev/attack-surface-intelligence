"""Opcje skanu nmap: jeden zwalidowany model zamiast dowolnego ciągu argumentów.

Każde pole ma zamknięty zbiór wartości albo ścisłą gramatykę, więc z opcji nie da się złożyć argumentu spoza tej listy
(plik wyjściowy, skrypt z dysku, dodatkowy cel). Celowo nie ma trybów, które angażują osoby trzecie nieobjęte zgodą na
skan: -D (wabiki), -S (podszycie adresu), -sI (idle scan), -b (FTP bounce).
"""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..errors import InvalidInput

Technique = Literal["syn", "connect", "ack", "window", "maimon", "null", "fin", "xmas", "udp", "sctp_init", "sctp_cookie", "protocol"]
Ping = Literal["echo", "timestamp", "netmask", "syn", "ack", "udp", "sctp", "protocol"]
Flag = Literal["URG", "ACK", "PSH", "RST", "SYN", "FIN"]

TECHNIQUE_FLAG = {"syn": "-sS", "connect": "-sT", "ack": "-sA", "window": "-sW", "maimon": "-sM", "null": "-sN", "fin": "-sF",
                  "xmas": "-sX", "udp": "-sU", "sctp_init": "-sY", "sctp_cookie": "-sZ", "protocol": "-sO"}
PING_FLAG = {"echo": "-PE", "timestamp": "-PP", "netmask": "-PM", "syn": "-PS", "ack": "-PA", "udp": "-PU", "sctp": "-PY",
             "protocol": "-PO"}
PING_WITH_PORTS = frozenset({"syn", "ack", "udp", "sctp"})
TCP_TECHNIQUES = frozenset({"syn", "connect", "ack", "window", "maimon", "null", "fin", "xmas"})
SCTP_TECHNIQUES = frozenset({"sctp_init", "sctp_cookie"})
OPEN_TCP = frozenset({"syn", "connect"})  # techniki TCP potwierdzające otwarty port (pozostałe badają filtrowanie)
MAX_PORT = 65535
MAX_PROTOCOL = 255
NMAP_DEFAULT_PORTS = 1000
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,60}")
ARG_VALUE_RE = re.compile(r"[A-Za-z0-9 ._:@/-]{1,120}")
# Argumenty NSE to lista dozwolonych, nie zakazanych: wśród kilkuset istniejących są takie, które czytają lub zapisują
# pliki na serwerze (userdb, http-fetch.destination) albo dokładają cele spoza zgody (newtargets).
SCRIPT_ARGS = ("http.useragent", "http.host", "http-enum.basepath", "http-methods.url-path", "http-title.url",
               "http-vhosts.domain", "ssh-auth-methods.user", "ssh_hostkey", "snmpcommunity", "smbdomain",
               "dns-recursion.domain", "dns-zone-transfer.domain", "tls.servername", "vulns.showall", "vulns.short",
               "vulners.mincvss", "mssql.instance-port")
_NOT_TCP = re.compile(r"[US]:")
_PORT_ITEM = re.compile(r"(?:([TUS]):)?(\d{1,5})?(-)?(\d{1,5})?")


def _check_ports(spec, limit=MAX_PORT, prefixes=True):
    """Gramatyka `-p`: 22,80-90,T:443,U:53,1000-. Zwraca postać bez spacji; ValueError przy błędzie."""
    spec = spec.replace(" ", "")
    for item in spec.split(",") if spec else ():
        m = _PORT_ITEM.fullmatch(item)
        if not m or not (m[2] or m[3]) or (m[4] and not m[3]) or (m[1] and not prefixes):
            raise ValueError(f"nieprawidłowy zakres portów: {item or 'pusty wpis'}")
        lo = int(m[2] or 0)
        hi = int(m[4]) if m[4] else (limit if m[3] else lo)
        if lo > hi or hi > limit:
            raise ValueError(f"zakres portów poza 0-{limit}: {item}")
    return spec


def count_ports(spec):
    """Ile pozycji opisuje (zwalidowana) lista portów."""
    total = 0
    for item in filter(None, spec.split(",")):
        lo, sep, hi = item.split(":")[-1].partition("-")
        total += int(hi or MAX_PORT) - int(lo or 1) + 1 if sep else 1
    return total


class NmapOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: str = Field("custom", pattern=r"^[a-z]{2,20}$")
    prescan: bool = False  # naabu szybko znajduje otwarte porty TCP, nmap bada już tylko je

    # hosty
    mode: Literal["ports", "hosts"] = "ports"  # hosts = -sn
    discovery: Literal["skip", "default", "custom"] = "skip"
    ping: list[Ping] = Field(default=[], max_length=len(PING_FLAG))
    ping_ports: str = Field("", max_length=200)
    disable_arp_ping: bool = False
    traceroute: bool = False
    dns: Literal["never", "auto", "always"] = "never"

    # porty
    port_mode: Literal["top", "default", "range", "all"] = "top"
    top_ports: int = Field(100, ge=1, le=MAX_PORT)
    ports: str = Field("", max_length=600)
    exclude_ports: str = Field("", max_length=300)
    sequential: bool = False

    # technika
    techniques: list[Technique] = Field(default=["syn"], min_length=1, max_length=3)
    scanflags: list[Flag] = Field(default=[], max_length=6)

    # usługi i system
    version: bool = False
    version_intensity: int | None = Field(None, ge=0, le=9)
    os: bool = False
    os_limit: bool = False
    os_guess: bool = False

    # NSE
    script_categories: list[str] = Field(default=[], max_length=14)
    scripts: list[str] = Field(default=[], max_length=40)
    script_args: dict[str, str] = Field(default={}, max_length=len(SCRIPT_ARGS))
    script_timeout_s: int | None = Field(None, ge=1, le=3600)

    # tempo (górny limit pakietów/s to rate_limit skanu, nie opcja nmap)
    timing: int = Field(3, ge=0, le=5)
    min_rate: int | None = Field(None, ge=1, le=10000)
    max_retries: int | None = Field(None, ge=0, le=20)
    host_timeout_s: int | None = Field(None, ge=10, le=86400)
    scan_delay_ms: int | None = Field(None, ge=1, le=60000)
    max_parallelism: int | None = Field(None, ge=1, le=1000)

    # pakiety (test reguł zapory)
    fragment: bool = False
    mtu: int | None = Field(None, ge=8, le=1496, multiple_of=8)
    source_port: int | None = Field(None, ge=1, le=MAX_PORT)
    data_length: int | None = Field(None, ge=1, le=1400)
    ttl: int | None = Field(None, ge=1, le=255)
    badsum: bool = False

    @field_validator("ping", "techniques", "scanflags", "script_categories", "scripts")
    @classmethod
    def _unique(cls, v):
        return list(dict.fromkeys(v))

    @field_validator("exclude_ports", "ping_ports")
    @classmethod
    def _plain_ports(cls, v):
        return _check_ports(v, prefixes=False)

    @field_validator("ports")
    @classmethod
    def _no_spaces(cls, v):
        return v.replace(" ", "")

    @field_validator("scripts", "script_categories")
    @classmethod
    def _names(cls, v):
        for name in v:
            if not NAME_RE.fullmatch(name):
                raise ValueError(f"nieprawidłowa nazwa skryptu lub kategorii NSE: {name[:60]}")
        return v

    @field_validator("script_args")
    @classmethod
    def _args(cls, v):
        for key, value in v.items():
            if key not in SCRIPT_ARGS:
                raise ValueError(f"niedozwolony argument NSE: {key[:60]}")
            if not ARG_VALUE_RE.fullmatch(value):
                raise ValueError(f"niedozwolone znaki w wartości argumentu NSE {key}")
        return v

    @model_validator(mode="after")
    def _consistent(self):
        tech = set(self.techniques)
        protocol = "protocol" in tech
        if protocol and len(tech) > 1:
            raise ValueError("skan protokołów IP (-sO) nie łączy się z inną techniką")
        if len(tech & TCP_TECHNIQUES) > 1 or len(tech & SCTP_TECHNIQUES) > 1:
            raise ValueError("wybierz najwyżej jedną technikę TCP i jedną SCTP")
        if self.mode == "hosts" and self.discovery == "skip":
            raise ValueError("samo wykrywanie hostów (-sn) wymaga włączonego wykrywania")
        if self.discovery == "custom" and not self.ping:
            raise ValueError("wybierz co najmniej jedną metodę wykrywania hostów")
        if self.port_mode == "range" and not self.ports:
            raise ValueError("podaj listę portów")
        _check_ports(self.ports, MAX_PROTOCOL if protocol else MAX_PORT, prefixes=not protocol)
        if protocol and self.port_mode == "top":
            raise ValueError("skan protokołów IP (-sO) nie ma rankingu: wybierz domyślne, zakres albo wszystkie")
        if self.scanflags and not tech & (TCP_TECHNIQUES - {"connect"}):
            raise ValueError("własne flagi TCP wymagają techniki TCP innej niż connect")
        if self.prescan and (self.mode == "hosts" or not tech <= OPEN_TCP):
            raise ValueError("wstępny skan naabu działa tylko z techniką SYN albo connect")
        if self.prescan and _NOT_TCP.search(self.ports):
            raise ValueError("wstępny skan naabu bada tylko porty TCP: usuń prefiksy U: i S:")
        if protocol and self.version:
            raise ValueError("wykrywanie wersji (-sV) nie działa ze skanem protokołów IP (-sO)")
        if self.fragment and self.mtu:
            raise ValueError("wybierz fragmentację (-f) albo własne MTU, nie oba")
        return self

    @property
    def has_scripts(self):
        return bool(self.script_categories or self.scripts)


def parse(raw):
    """Słownik (z API albo z bazy) -> NmapOptions. Błąd walidacji jako InvalidInput z czytelnym tekstem.

    Etykieta profilu jest prawdziwa tylko, gdy opcje są dokładnie opcjami profilu - inaczej to "custom"."""
    try:
        opts = NmapOptions.model_validate(raw)
    except ValidationError as e:
        raise InvalidInput("Opcje nmap: " + "; ".join(_message(x) for x in e.errors()[:3]) + ".") from e
    return opts if PROFILES.get(opts.profile) == opts else opts.model_copy(update={"profile": "custom"})


def _message(err):
    if err["type"] == "value_error":
        return err["msg"].removeprefix("Value error, ")
    ctx = err.get("ctx") or {}
    known = {"greater_than_equal": f"co najmniej {ctx.get('ge')}", "less_than_equal": f"najwyżej {ctx.get('le')}",
             "multiple_of": f"wielokrotność {ctx.get('multiple_of')}", "extra_forbidden": "nieznana opcja"}
    return f"{'.'.join(str(x) for x in err['loc']) or 'opcje'}: {known.get(err['type'], 'nieprawidłowa wartość')}"


def dump(opts):
    """Postać do zapisu w bazie: tylko to, co różni się od wartości domyślnych."""
    return opts.model_dump(exclude_defaults=True)


def _profile(name, **kw):
    return NmapOptions(profile=name, **kw)


# Kolejność = kolejność w interfejsie. Profilu "szybkiego" (samo naabu) tu nie ma: to skan bez opcji nmap.
PROFILES = {p.profile: p for p in (
    _profile("service", prescan=True, top_ports=1000, version=True, version_intensity=5, host_timeout_s=900),
    _profile("discovery", mode="hosts", discovery="custom", ping=["echo", "timestamp", "syn", "ack"], ping_ports="22,80,443,3389",
             dns="auto", timing=4),
    _profile("full", port_mode="all", version=True, os=True, os_guess=True, script_categories=["default"], traceroute=True,
             dns="auto", timing=4, max_retries=2, host_timeout_s=3600),
    _profile("udp", techniques=["udp"], version=True, version_intensity=2, max_retries=2, host_timeout_s=1800),
    _profile("vuln", prescan=True, top_ports=1000, version=True, script_categories=["vuln"], script_timeout_s=120,
             host_timeout_s=1800),
    _profile("careful", top_ports=1000, timing=2, max_retries=1, sequential=True, host_timeout_s=3600),
    _profile("firewall", techniques=["ack"], top_ports=1000, max_retries=2, host_timeout_s=1800),
)}
# Bez wybranego profilu, gdy w systemie nie ma naabu (zachowanie sprzed profili).
FALLBACK = NmapOptions(techniques=["connect"], version=True, version_intensity=2)
