"""Reguły domenowe: ważność ustaleń, ocena ryzyka i werdykt.

Jedyne źródło tej wiedzy to `domain.json` - ten sam plik importuje frontend (frontend/src/api.js),
więc etykiety i progi nie mogą się rozjechać między interfejsem a raportem.
"""
import json
from pathlib import Path

_SPEC = json.loads((Path(__file__).with_name("domain.json")).read_text(encoding="utf-8"))

SEVERITIES = [s["id"] for s in _SPEC["severities"]]
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
SEV_WEIGHT = {s["id"]: s["weight"] for s in _SPEC["severities"]}
SEV_LABEL = {s["id"]: s["label"] for s in _SPEC["severities"]}
SEV_WHEN = {s["id"]: s["when"] for s in _SPEC["severities"]}
URGENT = frozenset(_SPEC["urgent"])
_VERDICT = _SPEC["verdict"]


def is_severity(sev):
    return sev in SEV_ORDER


def sort_findings(findings):
    """Najpilniejsze najpierw; nieznana ważność na końcu."""
    return sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], len(SEVERITIES)))


def count_by_severity(findings):
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def risk_score(severities, host_count=None):
    """0-100, malejące przyrosty. Liczymy dwa sygnały: `worst` (najcięższe pojedyncze ustalenie - jeden critical
    w ogromnej sieci wciąż ma znaczenie) i `density` (suma wag przypadająca NA HOST). Suma wag bez normalizacji
    nasycała się do 100 przy każdym większym skanie: 182 ustaleń "medium" i 794 "low" rozsianych po 254 hostach
    (żadnego critical/high) dawało 100, choć sieć nie miała ani jednego poważnego problemu.
    Bez `host_count` (np. import CSV bez grafu zasobów) gęstość to surowa suma wag."""
    if not severities:
        return 0
    weights = [SEV_WEIGHT.get(s, 0) for s in severities]
    density = sum(weights) / max(1, host_count) if host_count else sum(weights)
    score = min(100, int(100 * (1 - 0.985 ** (max(weights) + density))))
    assert 0 <= score <= 100
    return score


def verdict(score, counts):
    """Ocena ogólna dla osoby nietechnicznej: {"tone": bad|warn|good, "title", "text"}."""
    urgent = sum(counts.get(s, 0) for s in URGENT)
    if score >= _VERDICT["bad_score"] or counts.get("critical", 0):
        tone = "bad"
    elif score >= _VERDICT["warn_score"] or urgent:
        tone = "warn"
    else:
        tone = "good"
    return {"tone": tone, **_VERDICT[tone]}
