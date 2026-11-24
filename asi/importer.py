"""Import gotowych wyników (nie celów do skanowania) - format symetryczny do /api/scans/{id}/export.json.

CSV (format export.csv) importuje same ustalenia, bez grafu zasobów."""
import csv
import hashlib
import io
import json

from . import domain
from .errors import InvalidInput
from .repo import scans as repo


def _parse(text, filename):
    name = (filename or "").lower()
    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise InvalidInput(f"Nieprawidłowy JSON: {e}") from e
        assets = [a for a in (data.get("assets") or []) if a.get("id") and a.get("kind") and "value" in a]
        edges = [e for e in (data.get("edges") or []) if e.get("src") and e.get("dst")]
        return data.get("scan") or {}, assets, edges, data.get("findings") or []
    if name.endswith(".csv"):
        return {}, [], [], list(csv.DictReader(io.StringIO(text)))
    raise InvalidInput("Obsługiwane formaty pliku: .json, .csv")


def _clean_findings(raw, sid_hint="import"):
    out = []
    for f in raw:
        sev = f.get("severity") or "info"
        asset = str(f.get("asset") or f"scan:{sid_hint}")
        title = str(f.get("title") or "?")[:200]
        if not asset.strip() or not title.strip("?"):
            continue
        out.append({"asset": asset, "severity": sev if domain.is_severity(sev) else "info", "title": title,
                    "source": str(f.get("source") or "import"), "detail": str(f.get("detail") or "")[:1000],
                    "fix": str(f.get("fix") or "")})
    return out


def import_results(text, filename):
    """Zwraca {"id", "assets", "findings"}. InvalidInput dla pliku, którego nie da się zaimportować."""
    meta, assets, edges, raw_findings = _parse(text, filename)
    if not assets and not raw_findings:
        raise InvalidInput("Plik nie zawiera żadnych wyników do zaimportowania.")
    target = str(meta.get("target") or filename or "zaimportowany skan")[:500]
    findings = _clean_findings(raw_findings)
    # target_hash NIE jest brany z pliku (mógłby podszyć się pod realny zakres i zatruć porównania) - własna przestrzeń
    # nazw z prefiksem, strukturalnie nigdy nie koliduje z hashem zakresu (targets.range_hash to surowy hex).
    score = int(meta.get("score") or 0)
    if not assets:
        score = domain.risk_score([f["severity"] for f in findings])
    sid, n = repo.create_imported(target, "import:" + hashlib.sha256(target.encode()).hexdigest(), score, assets, edges, findings)
    return {"id": sid, "assets": len(assets), "findings": n}
