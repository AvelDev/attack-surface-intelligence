"""Ustalenia edytowane przez operatora: ich bieżąca treść, trwałe decyzje (overrides), triage i notatki zakresów."""
import time

from .. import crypto, db


def get(rowid, scan_id=None):
    """Ustalenie po rowid (z odszyfrowanym detail) albo None. Z scan_id dodatkowo musi należeć do tego skanu."""
    sql, args = "SELECT rowid, * FROM findings WHERE rowid=?", [rowid]
    if scan_id is not None:
        sql += " AND scan_id=?"
        args.append(scan_id)
    with db.conn() as c:
        r = c.execute(sql, args).fetchone()
    return None if r is None else {**dict(r), "detail": crypto.dec(r["detail"])}


def update(rowid, severity, fix, title):
    with db.conn() as c:
        c.execute("UPDATE findings SET severity=?, fix=?, title=? WHERE rowid=?", (severity, fix, title, rowid))


def save_override(asset, title, severity, fix, false_positive):
    """Decyzja przetrwa kolejne skany: Ctx.finding stosuje ją do każdego nowego ustalenia o tym samym (zasób, tytuł)."""
    with db.conn() as c:
        c.execute("INSERT OR REPLACE INTO finding_overrides(asset, title, severity, fix, false_positive, updated) "
                  "VALUES(?,?,?,?,?,?)", (asset, title, severity, fix, int(false_positive), time.time()))


def set_triage(asset, key, status, note, username):
    with db.conn() as c:
        if status == "open":
            c.execute("DELETE FROM triage WHERE asset=? AND key=?", (asset, key))
        else:
            c.execute("INSERT OR REPLACE INTO triage(asset,key,status,note,username,updated) VALUES(?,?,?,?,?,?)",
                      (asset, key, status, note, username, time.time()))


def set_range_note(target_hash, note, username):
    with db.conn() as c:
        c.execute("INSERT OR REPLACE INTO range_notes(target_hash,note,username,updated) VALUES(?,?,?,?)",
                  (target_hash, note, username, time.time()))
