"""Regresja: zaimportowany skan (POST /api/scans/import-results) nie może zatruć baseline'u porównań realnego zakresu
(asi/importer.py, zob. docs/architektura.md §5).

target_hash normalnego skanu to goły sha256-hexdigest (64 znaki [0-9a-f]) policzony z ROZWIĄZANYCH celów po stronie
serwera (targets.range_hash). target_hash importu ma prefiks "import:" - strukturalnie nie może nigdy zrównać się
z prawdziwym hashem, bo "i" nie jest cyfrą szesnastkową.
"""
import json
import re

from asi import importer, targets
from asi.repo import scans as repo

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _import(payload):
    sid = importer.import_results(json.dumps(payload), "wyniki.json")["id"]
    return repo.load(sid)[0]["target_hash"]


def test_imported_hash_never_collides_with_real_hash_format(temp_db):
    imported = _import({"scan": {"target": "scanme.nmap.org"}, "findings": [{"asset": "a", "title": "t"}]})
    assert imported.startswith("import:")
    assert not HEX64.match(imported)


def test_real_hash_is_always_plain_hex64():
    assert HEX64.match(targets.range_hash(["scanme.nmap.org"]))
    assert targets.range_hash(["b.example.com", "a.example.com"]) == targets.range_hash(["a.example.com", "b.example.com"])


def test_attacker_cannot_forge_import_to_look_like_target(temp_db):
    """Plik importu z polem 'target' równym realnemu hashowi zakresu i tak dostaje prefiks "import:" - serwer liczy
    hash z nazwy celu w pliku, a nie kopiuje go z przesłanego JSON-a."""
    real = targets.range_hash(["scanme.nmap.org"])
    forged = _import({"scan": {"target": real, "target_hash": real}, "findings": [{"asset": "a", "title": "t"}]})
    assert forged != real
    assert forged.startswith("import:")
