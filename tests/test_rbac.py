"""RBAC: hierarchia ról i hash/weryfikacja hasła (asi/auth.py).

Nie dotyka bazy danych - testuje tylko czystą logikę (hash, porządek rang, zależność
FastAPI `require()` wołana jak normalna funkcja Pythona).
"""
import pytest
from fastapi import HTTPException

from asi import auth


def test_role_order_is_strictly_increasing():
    assert auth.ROLES == ("read", "read_modify", "add_remove_modify", "admin")
    ranks = [auth.RANK[r] for r in auth.ROLES]
    assert ranks == sorted(ranks)


def test_require_allows_equal_or_higher_role():
    dep = auth.require("read_modify")
    for role in ("read_modify", "add_remove_modify", "admin"):
        assert dep(user={"role": role}) == {"role": role}


def test_require_rejects_lower_role():
    dep = auth.require("add_remove_modify")
    with pytest.raises(HTTPException) as exc:
        dep(user={"role": "read"})
    assert exc.value.status_code == 403


def test_require_admin_only_rejects_add_remove_modify():
    """Regresja: ustawienie DefectDojo musi być admin-only, nie add_remove_modify
    (zob. docs/architektura.md §5 - była to realna furtka SSRF/eksfiltracji)."""
    dep = auth.require("admin")
    with pytest.raises(HTTPException):
        dep(user={"role": "add_remove_modify"})
    assert dep(user={"role": "admin"}) == {"role": "admin"}


def test_password_hash_roundtrip_and_salted():
    h1, salt1 = auth.hash_password("correct horse battery staple")
    h2, salt2 = auth.hash_password("correct horse battery staple")
    assert salt1 != salt2, "każde hashowanie musi użyć nowej losowej soli"
    assert h1 != h2, "ta sama sól nigdy nie jest ponownie użyta -> różne hashe"
    assert auth.verify_password("correct horse battery staple", salt1, h1)


def test_password_verify_rejects_wrong_password():
    h, salt = auth.hash_password("correct horse battery staple")
    assert not auth.verify_password("wrong password", salt, h)
