"""Harmonogramy cyklicznych skanów."""
import sqlite3

from .. import db


def list_with_last_result():
    with db.conn() as c:
        rows = c.execute(
            "SELECT h.*,"
            "(SELECT id FROM scans s WHERE s.target=h.target AND s.status='done' ORDER BY id DESC LIMIT 1) AS last_scan,"
            "(SELECT score FROM scans s WHERE s.target=h.target AND s.status='done' ORDER BY id DESC LIMIT 1) AS last_score "
            "FROM schedules h ORDER BY h.id DESC").fetchall()
    return [dict(r) for r in rows]


def create(target, nuclei, deep, interval_hours, now):
    """Zwraca id albo None, gdy cel ma już harmonogram (UNIQUE na target - bez wyścigu sprawdź-i-wstaw)."""
    try:
        with db.conn() as c:
            return c.execute("INSERT INTO schedules(target,nuclei,deep,interval_hours,created,last_run,next_run) "
                             "VALUES(?,?,?,?,?,?,?)",
                             (target, int(nuclei), int(deep), interval_hours, now, now, now + interval_hours * 3600)).lastrowid
    except sqlite3.IntegrityError:
        return None


def set_enabled(hid, enabled):
    with db.conn() as c:
        return c.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(enabled), hid)).rowcount > 0


def delete(hid):
    with db.conn() as c:
        return c.execute("DELETE FROM schedules WHERE id=?", (hid,)).rowcount > 0


def due(now):
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,))]


def mark_run(hid, now, next_run):
    with db.conn() as c:
        c.execute("UPDATE schedules SET last_run=?, next_run=? WHERE id=?", (now, next_run, hid))
