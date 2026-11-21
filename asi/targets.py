"""Parsowanie i walidacja listy celów (host/CIDR/domena) z formularza, CSV lub JSON.

Jeden wpis może rozwinąć się w wiele adresów IP (CIDR) - stąd osobny moduł od
`scanner.normalize_target`, który waliduje pojedynczy host/domenę. Obsługuje
skalę wymaganą w zadaniu (>10 000 adresów) z twardym limitem bezpieczeństwa.
"""
import csv
import io
import ipaddress
import json
import os

from . import scanner

MAX_TARGETS = int(os.environ.get("ASI_MAX_TARGETS", "20000"))


def _allowed_networks():
    nets = []
    for a in os.environ.get("ASI_ALLOWED_TARGETS", "").split(","):
        a = a.strip()
        if not a:
            continue
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            pass  # to wpis domenowy - obsługuje go scanner.normalize_target
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
            if net.num_addresses > MAX_TARGETS - len(out):
                errors.append((raw, f"za duży zakres - limit {MAX_TARGETS} celów na skan (ASI_MAX_TARGETS)"))
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
            t = scanner.normalize_target(raw)
        except ValueError as e:
            errors.append((raw, str(e)))
            continue
        if t in seen:
            continue
        if len(out) >= MAX_TARGETS:
            errors.append((raw, f"przekroczono limit {MAX_TARGETS} celów na skan"))
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
