"""Walidacja i zakres celów skanowania. Każdy cel przechodzi przez normalize() zanim trafi do narzędzi.

Jeden wpis (z formularza, CSV lub JSON) może rozwinąć się w wiele adresów IP (CIDR) - robi to expand(), z twardym
limitem bezpieczeństwa (ASI_MAX_TARGETS), bo skala zadania to ponad 10 000 adresów."""
import csv
import hashlib
import io
import ipaddress
import json
import re

from . import config
from .errors import InvalidInput

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def is_ip(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_domain(value):
    return bool(DOMAIN_RE.match(value))


def in_scope(host, root):
    """Czy host (opcjonalnie z portem) to root albo jego subdomena."""
    host = (host or "").lower().split(":")[0]
    return host == root or host.endswith("." + root)


def is_public(ip):
    return ipaddress.ip_address(ip).is_global


def normalize(raw):
    """Zwraca domenę lub IPv4 w postaci kanonicznej; InvalidInput dla niepoprawnego lub niedozwolonego celu."""
    t = (raw or "").strip().lower()
    t = re.sub(r"^[a-z]+://", "", t).split("/")[0].split(":")[0].strip(".")
    if is_ip(t):
        return t
    if not is_domain(t):
        raise InvalidInput("Nieprawidłowy cel - podaj domenę (example.com) lub adres IPv4.")
    allowed = config.load().allowed_targets
    if allowed and not any(in_scope(t, a) for a in allowed):
        raise InvalidInput("Cel poza dozwoloną listą (ASI_ALLOWED_TARGETS).")
    return t


def _allowed_networks():
    nets = []
    for a in config.load().allowed_targets:
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            pass  # to wpis domenowy - obsługuje go normalize()
    return nets


def _ip_allowed(ip):
    nets = _allowed_networks()
    if not nets:
        return True
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in nets)


def expand(raw_items):
    """Zwraca (targets, errors). targets: płaska, zwalidowana, zdeduplikowana lista
    pojedynczych celów (IP lub domen). errors: lista (wpis, powód) dla odrzuconych."""
    out, errors, seen = [], [], set()
    limit = config.load().max_targets
    for raw in raw_items:
        raw = (raw or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            net = None
        if net is not None:
            # num_addresses jest O(1) (z długości prefiksu) - sprawdzamy PRZED materializacją
            # listy hostów, inaczej np. "10.0.0.0/8" albo dowolny duży prefiks IPv6 zaalokowałby
            # miliony/miliardy obiektów zanim limit w ogóle zadziała (DoS pojedynczym wpisem).
            if net.num_addresses > limit - len(out):
                errors.append((raw, f"za duży zakres - limit {limit} celów na skan (ASI_MAX_TARGETS)"))
                continue
            hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts())
            for ip in hosts:
                ip = str(ip)
                if ip in seen:
                    continue
                if not _ip_allowed(ip):
                    errors.append((ip, "poza dozwoloną siecią (ASI_ALLOWED_TARGETS)"))
                    continue
                seen.add(ip)
                out.append(ip)
            continue
        try:
            t = normalize(raw)
        except InvalidInput as e:
            errors.append((raw, str(e)))
            continue
        if t in seen:
            continue
        if len(out) >= limit:
            errors.append((raw, f"przekroczono limit {limit} celów na skan"))
            break
        seen.add(t)
        out.append(t)
    return out, errors


def parse_text(text):
    """Formularz: jeden cel na linię lub oddzielone przecinkami."""
    items = []
    for line in (text or "").splitlines():
        items.extend(x.strip() for x in line.split(",") if x.strip())
    return items


def parse_csv(text):
    rows = list(csv.reader(io.StringIO(text or "")))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    if "target" in header or "host" in header:
        idx = header.index("target") if "target" in header else header.index("host")
        return [r[idx] for r in rows[1:] if len(r) > idx]
    return [cell for row in rows for cell in row]


def parse_json(text):
    data = json.loads(text or "[]")
    if isinstance(data, dict):
        data = data.get("targets") or data.get("hosts") or []
    out = []
    for item in data:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            out.append(item.get("target") or item.get("host") or "")
    return out


def display_name(raw_items, resolved):
    if len(resolved) == 1:
        return resolved[0]
    preview = ", ".join(raw_items[:3])
    more = f" (+{len(raw_items) - 3})" if len(raw_items) > 3 else ""
    return f"{len(resolved)} celów: {preview}{more}"


def range_hash(resolved):
    """Identyfikator zakresu: te same cele w dowolnej kolejności dają ten sam hash (grupuje kolejne przebiegi do porównań)."""
    return hashlib.sha256("\n".join(sorted(resolved)).encode()).hexdigest()
