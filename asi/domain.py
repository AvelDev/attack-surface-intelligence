"""Reguły domenowe: ważność ustaleń, ocena ryzyka i werdykt.

Jedyne źródło tej wiedzy to `domain.json` - ten sam plik importuje frontend (frontend/src/api.js),
więc etykiety, progi i odstępy harmonogramu nie mogą się rozjechać między interfejsem a raportem.
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
INTERVALS = {int(h): label for h, label in _SPEC["intervals"].items()}
DEFAULT_INTERVAL = _SPEC["default_interval"]
_VERDICT = _SPEC["verdict"]

assert DEFAULT_INTERVAL in INTERVALS, "domain.json: default_interval musi być jednym z intervals"


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


def risk_score(severities):
    """0-100, malejące przyrosty: kilka krytycznych szybko wyciąga wynik w górę."""
    total = sum(SEV_WEIGHT.get(s, 0) for s in severities)
    score = min(100, int(100 * (1 - 0.985**total)))
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
