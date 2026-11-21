"""Historia celu: odczyt skanu, porównanie z poprzednim skanem i trend oceny (API i alerty)."""
from . import domain
from .errors import NotFound
from .repo import scans as repo


def load(sid):
    """(scan, assets, edges, findings) z ustaleniami od najpilniejszych. NotFound, gdy skanu nie ma."""
    r = repo.load(sid)
    if r is None:
        raise NotFound("Nie ma takiego skanu")
    s, assets, edges, findings = r
    return s, assets, edges, domain.sort_findings(findings)


def compare(current_assets, current_findings, previous_assets, previous_findings):
    """Czysta funkcja: co się pojawiło i co zniknęło między dwoma skanami."""
    cur, old = {a["id"] for a in current_assets}, {a["id"] for a in previous_assets}
    cf = {(f["asset"], f["title"]) for f in current_findings}
    of = {(f["asset"], f["title"]) for f in previous_findings}
    return {"new_assets": sorted(cur - old), "removed_assets": sorted(old - cur),
            "new_findings": [{"asset": a, "title": t} for a, t in sorted(cf - of)],
            "resolved_findings": [{"asset": a, "title": t} for a, t in sorted(of - cf)]}


def diff(sid, target, assets, findings):
    """Porównanie z poprzednim zakończonym skanem celu albo None, gdy to pierwszy skan."""
    prev = repo.previous_done(target, sid)
    if not prev:
        return None
    _, passets, _, pfind = repo.load(prev["id"])
    return {"against": prev["id"], "against_score": prev["score"], **compare(assets, findings, passets, pfind)}


trend = repo.trend
