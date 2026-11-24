"""Import gotowych wyników (nie celów do skanowania) - format symetryczny do /api/scans/{id}/export.json.

CSV (format export.csv) importuje same ustalenia, bez grafu zasobów; XML to wynik nmap -oX."""
import csv
import hashlib
import io
import json

from . import domain, targets
from .errors import InvalidInput
from .nmap import parser as nmap_parser
from .nmap import rules
from .repo import scans as repo
from .scan import nmap_scan, ports


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
    if name.endswith(".xml"):
        return _parse_nmap(text)
    raise InvalidInput("Obsługiwane formaty pliku: .json, .csv, .xml (nmap -oX)")


def _parse_nmap(text):
    """Wynik nmap -oX uruchomionego poza ASI: te same zasoby i ustalenia, które zapisałby skan."""
    run = nmap_parser.parse(text)
    assets, edges, found = [], [], []
    for h in run["hosts"]:
        if not nmap_scan.responded(h):
            continue
        host_id = f"ip:{h['ip']}"
        assets.append({"id": host_id, "kind": "ip", "value": h["ip"], "data": nmap_scan.host_data(h)})
        rows = [(host_id, f) for f in rules.findings(h.get("scripts"))]
        for p in h["ports"]:
            value = ports.port_value(h["ip"], p)
            assets.append({"id": f"port:{value}", "kind": "port", "value": value, "data": p})
            edges.append({"src": host_id, "dst": f"port:{value}"})
            rows += [(f"port:{value}", f) for f in ports.port_findings(h["ip"], p)]
        found += [dict(zip(("asset", "severity", "title", "source", "detail", "fix"), (aid, *f), strict=True)) for aid, f in rows]
    if not assets:
        raise InvalidInput("Plik nmap nie zawiera hostów, które odpowiedziały.")
    hosts = [a["value"] for a in assets if a["kind"] == "ip"]
    meta = {"target": f"nmap: {targets.display_name(hosts, hosts)}", "score": domain.risk_score([f["severity"] for f in found], len(hosts))}
    return meta, assets, edges, found


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
