"""Regresja: zaimportowany skan (POST /api/scans/import-results) nie może zatruć
baseline diffa realnego celu (asi/main.py, zob. docs/architektura.md §5).

target_hash normalnego skanu to goły sha256-hexdigest (64 znaki [0-9a-f]) policzony
z ROZWIĄZANYCH celów po stronie serwera. target_hash importu ma prefiks "import:" -
strukturalnie nie może nigdy pokrewnie zrównać się z prawdziwym hashem, bo "i" nie
jest cyfrą szesnastkową. Ten test nie woła endpointu (to by wymagało DB/HTTP), tylko
odtwarza obie formuły z main.py i sprawdza niezmiennik, który ma gwarantować separację.
"""
import hashlib
import re

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def real_scan_target_hash(resolved_targets):
    """Kopia formuły z asi/main.py (ścieżka normalnego /api/scans)."""
    return hashlib.sha256("\n".join(sorted(resolved_targets)).encode()).hexdigest()


def imported_scan_target_hash(target):
    """Kopia formuły z asi/main.py (ścieżka /api/scans/import-results)."""
    return "import:" + hashlib.sha256(target.encode()).hexdigest()


def test_imported_hash_never_collides_with_real_hash_format():
    imported = imported_scan_target_hash("scanme.nmap.org")
    assert not HEX64.match(imported), "import: prefix musi wypadać z formatu realnego hasha"


def test_real_hash_is_always_plain_hex64():
    real = real_scan_target_hash(["scanme.nmap.org"])
    assert HEX64.match(real)


def test_attacker_cannot_forge_import_to_look_like_target():
    """Nawet gdyby ktoś spreparował plik importu z polem 'target' równym realnemu
    sha256 celu, wynikowy target_hash i tak dostaje prefiks "import:" - bo liczy go
    serwer z nazwy celu w pliku, NIE kopiuje go z przesłanego JSON-a."""
    real = real_scan_target_hash(["scanme.nmap.org"])
    forged = imported_scan_target_hash(real)  # próba podszycia się pod sam hash jako "target"
    assert forged != real
    assert forged.startswith("import:")
