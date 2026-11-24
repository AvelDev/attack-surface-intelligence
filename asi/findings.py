"""Ręczna edycja ustaleń i triage (decyzje operatora, które przetrwają kolejne skany)."""
from . import domain
from .errors import InvalidInput, NotFound
from .repo import findings as repo

FALSE_POSITIVE_PREFIX = "[False Positive] "
TRIAGE_STATUSES = ("open", "ok", "accepted", "false_positive")


def edit(rowid, fix=None, severity=None, false_positive=None, persist_future=True):
    """Edycja ustalenia niezależna od stanu skanu oraz (opcjonalnie) trwały override stosowany w kolejnych skanach."""
    row = repo.get(rowid)
    if row is None:
        raise NotFound("Nie ma takiego ustalenia.")
    sev = severity or row["severity"]
    if not domain.is_severity(sev):
        raise InvalidInput("Nieprawidłowa waga.")
    fix = fix if fix is not None else row["fix"]
    title = row["title"]
    if false_positive:
        sev = "info"
        if not title.startswith(FALSE_POSITIVE_PREFIX):
            title = FALSE_POSITIVE_PREFIX + title
    elif false_positive is False and title.startswith(FALSE_POSITIVE_PREFIX):
        title = title.removeprefix(FALSE_POSITIVE_PREFIX)
    repo.update(rowid, sev, fix, title)
    if persist_future:
        repo.save_override(row["asset"], row["title"].removeprefix(FALSE_POSITIVE_PREFIX), sev, fix, bool(false_positive))


def triage(asset, key, status, note, username, finding_rowid=None):
    """Triage zmiany lub ustalenia - kluczowany (zasób, rodzaj zmiany/tytuł), nie skanem, więc decyzja przetrwa kolejne przebiegi."""
    if status not in TRIAGE_STATUSES:
        raise InvalidInput(f"Status musi być jednym z: {', '.join(TRIAGE_STATUSES)}")
    if not (0 < len(asset) <= 600 and 0 < len(key) <= 600) or len(note) > 2000:
        raise InvalidInput("Za długie pole.")
    repo.set_triage(asset, key, status, note, username)
    if finding_rowid is not None and status in ("false_positive", "open"):
        edit(finding_rowid, false_positive=status == "false_positive")


def threat_map(findings):
    """{zasób: najwyższa ważność ustalenia}."""
    out = {}
    for f in findings:
        if domain.SEV_ORDER.get(f["severity"], 9) < domain.SEV_ORDER.get(out.get(f["asset"], "info"), 9):
            out[f["asset"]] = f["severity"]
    return out
