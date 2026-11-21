"""Odczyt skanów z bazy, diff względem poprzedniego skanu i trend oceny (współdzielone przez API i alerty)."""
import json

from . import db, domain


def load(sid):
    """Zwraca (scan, assets, edges, findings) albo None, gdy skanu nie ma."""
    with db.conn() as c:
        s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s:
            return None
        assets = [dict(r, data=json.loads(r["data"])) for r in
                  c.execute("SELECT id,kind,value,data FROM assets WHERE scan_id=?", (sid,))]
        edges = [dict(r) for r in c.execute("SELECT src,dst FROM edges WHERE scan_id=?", (sid,))]
        findings = [dict(r) for r in c.execute("SELECT * FROM findings WHERE scan_id=?", (sid,))]
    return dict(s), assets, edges, domain.sort_findings(findings)


def diff(sid, target, assets, findings):
    with db.conn() as c:
        prev = c.execute("SELECT id,score FROM scans WHERE target=? AND status='done' AND id<? "
                         "ORDER BY id DESC LIMIT 1", (target, sid)).fetchone()
    if not prev:
        return None
    _, passets, _, pfind = load(prev["id"])
    cur, old = {a["id"] for a in assets}, {a["id"] for a in passets}
    cf = {(f["asset"], f["title"]) for f in findings}
    of = {(f["asset"], f["title"]) for f in pfind}
    return {"against": prev["id"], "against_score": prev["score"],
            "new_assets": sorted(cur - old), "removed_assets": sorted(old - cur),
            "new_findings": [{"asset": a, "title": t} for a, t in sorted(cf - of)],
            "resolved_findings": [{"asset": a, "title": t} for a, t in sorted(of - cf)]}


def trend(target, upto_id, limit=12):
    """Ostatnie zakończone skany celu (rosnąco po czasie): do wykresu oceny w czasie."""
    with db.conn() as c:
        rows = c.execute("SELECT id,score,created,"
                         "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS findings "
                         "FROM scans s WHERE target=? AND status='done' AND id<=? "
                         "ORDER BY id DESC LIMIT ?", (target, upto_id, limit)).fetchall()
    return [dict(r) for r in reversed(rows)]
