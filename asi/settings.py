"""Ustawienia i klucze API zapisywane na serwerze (tabela settings).

Wartości kluczy NIGDY nie wracają przez API - interfejs widzi tylko informację "zapisany" i gwiazdki.
Zmienna środowiskowa ASI_<NAZWA> (np. ASI_NVD_API_KEY) ma pierwszeństwo przed bazą.
Uwaga: klucze leżą w bazie SQLite jako zwykły tekst - chroń plik bazy (uprawnienia 600) i dostęp do API.
"""
import os
import re

from . import db

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


def get(key):
    if key not in KEYS:
        return ""
    env = os.environ.get("ASI_" + key.upper(), "").strip()
    if env:
        return env
    with db.conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else ""


def put(key, value):
    if key not in KEYS:
        raise ValueError("Nieznane ustawienie.")
    value = (value or "").strip()
    if not value:
        return delete(key)
    if not VALUE_RE.match(value):
        raise ValueError("Klucz zawiera niedozwolone znaki (spacje, polskie litery) albo ma nieprawidłową długość.")
    with db.conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, value))


def delete(key):
    with db.conn() as c:
        c.execute("DELETE FROM settings WHERE key=?", (key,))


def status():
    """Bez wartości: tylko czy ustawiony i skąd (baza / zmienna środowiskowa)."""
    with db.conn() as c:
        stored = {r["key"] for r in c.execute("SELECT key FROM settings")}
    out = []
    for k, meta in KEYS.items():
        env = bool(os.environ.get("ASI_" + k.upper(), "").strip())
        out.append({"key": k, **meta, "set": env or k in stored, "source": "env" if env else ("db" if k in stored else None),
                    "masked": "************" if (env or k in stored) else ""})
    return out
