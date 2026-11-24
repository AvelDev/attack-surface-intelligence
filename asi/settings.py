"""Ustawienia i klucze API zapisywane na serwerze (tabela settings).

Wartości kluczy NIGDY nie wracają przez API - interfejs widzi tylko informację "zapisany" i gwiazdki.
Zmienna środowiskowa ASI_<NAZWA> (np. ASI_NVD_API_KEY) ma pierwszeństwo przed bazą.
W bazie leżą zaszyfrowane (crypto.py); mimo to chroń plik bazy (uprawnienia 600) i dostęp do API.
"""
import os
import re

from . import crypto
from .errors import InvalidInput, NotFound
from .repo import settings as repo

KEYS = {
    "nvd_api_key": {"label": "NVD (baza podatności NIST)", "free": True,
                    "help": "Zwiększa limit zapytań o podatności z 5 do 50 na 30 s. Bez klucza też działa, wolniej.",
                    "url": "https://nvd.nist.gov/developers/request-an-api-key"},
    "shodan_api_key": {"label": "Shodan", "free": False,
                       "help": "Dokładniejsze dane o tym, co o Waszych adresach IP widzi internet. Bez klucza używamy darmowego Shodan InternetDB.",
                       "url": "https://account.shodan.io/"},
    "censys_token": {"label": "Censys, osobisty token dostępu (PAT)", "free": True,
                     "help": "Druga, niezależna perspektywa: jakie usługi widzi Censys. Token z konta Censys Platform.",
                     "url": "https://platform.censys.io/"},
    "censys_org_id": {"label": "Censys, identyfikator organizacji (opcjonalnie)", "free": True,
                      "help": "Tylko jeśli korzystasz z płatnej organizacji. Bez niego użyjemy darmowych limitów konta.",
                      "url": "https://platform.censys.io/"},
    "hibp_api_key": {"label": "Have I Been Pwned (wycieki)", "free": False,
                     "help": "Sprawdza, czy adresy e-mail Waszej domeny są w znanych wyciekach. Wymaga płatnego klucza i domeny zweryfikowanej na koncie HIBP.",
                     "url": "https://haveibeenpwned.com/API/Key"},
}
VALUE_RE = re.compile(r"^[A-Za-z0-9_\-:.=+/]{6,300}$")  # bez spacji i znaków nowej linii (ochrona nagłówków HTTP)


def _env(key):
    return os.environ.get("ASI_" + key.upper(), "").strip()


def get(key):
    if key not in KEYS:
        return ""
    stored = repo.get(key)
    return _env(key) or (crypto.dec(stored) if stored else "")


def put(key, value):
    if key not in KEYS:
        raise InvalidInput("Nieznane ustawienie.")
    value = (value or "").strip()
    if not value:
        return delete(key)
    if not VALUE_RE.match(value):
        raise InvalidInput("Klucz zawiera niedozwolone znaki (spacje, polskie litery) albo ma nieprawidłową długość.")
    repo.put(key, crypto.enc(value))


def delete(key):
    if key not in KEYS:
        raise NotFound("Nieznane ustawienie.")
    repo.delete(key)


def status():
    """Bez wartości: tylko czy ustawiony i skąd (baza / zmienna środowiskowa)."""
    stored = repo.stored_keys()
    out = []
    for k, meta in KEYS.items():
        env = bool(_env(k))
        out.append({"key": k, **meta, "set": env or k in stored, "source": "env" if env else ("db" if k in stored else None),
                    "masked": "************" if (env or k in stored) else ""})
    return out
