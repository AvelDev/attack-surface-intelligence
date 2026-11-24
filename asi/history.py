"""Historia zakresu: odczyt skanu, porównanie z poprzednimi skanami (zmiany, flapping, potwierdzony brak) i trend oceny."""
from . import domain
from .errors import NotFound
from .repo import scans as repo

HISTORY_DEPTH = 4  # tyle ostatnich skanów zakresu bierze udział w analizie stabilności hostów


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


def flapping(current, previous, older_sets):
    """Czysta funkcja: zasoby, które raz odpowiadają, a raz nie (adres może odpowiadać zależnie od pory).

    current i previous to zbiory id zasobów z dwóch ostatnich skanów, older_sets - zbiory ze starszych."""
    out = set()
    for aid in current:
        if aid not in previous and any(aid in hs for hs in older_sets):
            out.add(aid)  # zniknął, wrócił
        elif aid in previous and any(aid not in hs for hs in older_sets):
            out.add(aid)  # jest teraz i poprzednio, ale w starszych go nie było
    return sorted(out)


def confirmed_offline(current, previous, older_sets):
    """Czysta funkcja: zasoby, których nie ma w bieżącym skanie ani w dwóch kolejnych poprzednich - potwierdzony brak
    odpowiedzi po sukcesywnych skanach."""
    if len(older_sets) < 2:
        return []
    return sorted(aid for aid in previous - current if all(aid not in hs for hs in older_sets[:2]))


def diff(sid, target_hash, assets, findings):
    """Porównanie z poprzednim zakończonym skanem tego samego zakresu albo None, gdy to pierwszy skan."""
    hist = repo.previous_done(target_hash, sid, HISTORY_DEPTH)
    if not hist:
        return None
    prev = hist[0]
    _, passets, _, pfind = repo.load(prev["id"])
    older = []
    for h in hist[1:]:
        loaded = repo.load(h["id"])
        if loaded:
            older.append({a["id"] for a in loaded[1]})
    cur, old = {a["id"] for a in assets}, {a["id"] for a in passets}
    return {"against": prev["id"], "against_score": prev["score"], **compare(assets, findings, passets, pfind),
            "flapping_assets": flapping(cur, old, older), "confirmed_offline": confirmed_offline(cur, old, older)}


trend = repo.trend
