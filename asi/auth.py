"""RBAC: 4 role (odczyt / modyfikacja+odczyt / dodawanie-usuwanie-modyfikacja / admin),
sesje po ciasteczku (HttpOnly, SameSite=Strict - mitygacja CSRF, bo stanowe endpointy
API nie sprawdzają nic poza sesją). Hasła: pbkdf2_hmac ze stdlib (bez nowej zależności).
"""
import hashlib
import os
import secrets
import time

from fastapi import Cookie, Depends, HTTPException

from . import db

COOKIE = "asi_session"
SESSION_DAYS = 7
# domyślnie wyłączone, bo PoC chodzi lokalnie po zwykłym HTTP (127.0.0.1) - ustaw
# ASI_COOKIE_SECURE=1, gdy aplikacja stoi za reverse proxy terminującym TLS.
COOKIE_SECURE = os.environ.get("ASI_COOKIE_SECURE") == "1"
ITERATIONS = 200_000
ROLES = ("read", "read_modify", "add_remove_modify", "admin")
RANK = {r: i for i, r in enumerate(ROLES)}


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return h.hex(), salt.hex()


def verify_password(password, salt_hex, hash_hex):
    h, _ = hash_password(password, salt_hex)
    return secrets.compare_digest(h, hash_hex)


def create_user(username, password, role):
    if role not in ROLES:
        raise ValueError(f"Nieznana rola: {role}")
    h, salt = hash_password(password)
    with db.conn() as c:
        c.execute("INSERT INTO users(username,password_hash,salt,role,created) VALUES(?,?,?,?,?)",
                  (username, h, salt, role, time.time()))


def list_users():
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT id, username, role, created FROM users ORDER BY id")]


def delete_user(uid):
    with db.conn() as c:
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))


def bootstrap_admin():
    """Przy pierwszym uruchomieniu (brak userów) tworzy admina z losowym hasłem,
    wypisanym raz w logu - analogicznie do procedury ustawiania hasła GVM."""
    with db.conn() as c:
        n = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if n:
        return
    password = secrets.token_urlsafe(12)
    create_user("admin", password, "admin")
    print(f"[asi] utworzono pierwszego użytkownika: admin / {password}  (zapisz to hasło - nie pokaże się ponownie)")


def authenticate(username, password):
    with db.conn() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not verify_password(password, u["salt"], u["password_hash"]):
        return None
    return dict(u)


def create_session(user_id):
    token = secrets.token_hex(32)
    now = time.time()
    with db.conn() as c:
        c.execute("INSERT INTO sessions(token,user_id,created,expires) VALUES(?,?,?,?)",
                  (token, user_id, now, now + SESSION_DAYS * 86400))
    return token


def destroy_session(token):
    with db.conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


def set_session_cookie(response, token):
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", secure=COOKIE_SECURE,
                        max_age=SESSION_DAYS * 86400, path="/")


def clear_session_cookie(response):
    response.delete_cookie(COOKIE, path="/")


def _user_for_token(token):
    if not token:
        return None
    with db.conn() as c:
        row = c.execute(
            "SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires>?", (token, time.time())).fetchone()
    return dict(row) if row else None


def current_user_dep(asi_session: str | None = Cookie(default=None)):
    user = _user_for_token(asi_session)
    if not user:
        raise HTTPException(401, "Wymagane logowanie.")
    return user


def require(min_role):
    """Zwraca zależność FastAPI wymagającą roli >= min_role w hierarchii RANK."""
    def dependency(user: dict = Depends(current_user_dep)):
        if RANK[user["role"]] < RANK[min_role]:
            raise HTTPException(403, f"Wymagana rola co najmniej '{min_role}'.")
        return user
    return dependency
