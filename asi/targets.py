"""Walidacja i zakres celu skanowania. Każdy cel przechodzi przez normalize() zanim trafi do narzędzi."""
import ipaddress
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
