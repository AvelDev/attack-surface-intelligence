"""Szyfrowanie wrażliwych pól w spoczynku (Encryption At Rest).

Klucz z ASI_SECRET_KEY, a jeśli brak - generowany raz i trzymany w data/secret.key
(0600, poza repo jak baza), żeby działało "od ręki" bez ręcznej konfiguracji.
Szyfrowane są tylko kolumny z surowymi danymi ze skanowanych hostów (banery,
nagłówki, logi narzędzi) - identyfikatory/tytuły/severity zostają jawne, bo na
nich operują diff/sortowanie (zob. main._diff, main.get_scan).
"""
import os

from cryptography.fernet import Fernet, InvalidToken

from . import db

KEY_PATH = os.environ.get("ASI_SECRET_KEY_FILE", os.path.join(db.ROOT, "data", "secret.key"))


def _load_key():
    env = os.environ.get("ASI_SECRET_KEY")
    if env:
        return env.encode()
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


_fernet = Fernet(_load_key())


def enc(s):
    if s is None:
        return s
    return _fernet.encrypt(str(s).encode()).decode()


def dec(s):
    if not s:
        return s
    try:
        return _fernet.decrypt(s.encode()).decode()
    except (InvalidToken, ValueError):
        return s  # dane sprzed włączenia szyfrowania albo inny klucz - zwróć jak jest
