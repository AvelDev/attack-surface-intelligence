"""Harmonogramy cyklicznych skanów."""
from .. import db


def list_all():
    with db.conn() as c:
        rows = c.execute("SELECT id, target, opts, interval_hours, time_window_mins, last_run, next_run, enabled "
                         "FROM schedules ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def create(target, opts_json, interval_hours, time_window_mins, next_run):
    with db.conn() as c:
        return c.execute("INSERT INTO schedules(target, opts, interval_hours, time_window_mins, next_run, enabled) "
                         "VALUES(?,?,?,?,?,1)", (target, opts_json, interval_hours, time_window_mins, next_run)).lastrowid


def set_enabled(hid, enabled):
    with db.conn() as c:
        return c.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(enabled), hid)).rowcount > 0


def delete(hid):
    with db.conn() as c:
        return c.execute("DELETE FROM schedules WHERE id=?", (hid,)).rowcount > 0


def due(now):
    with db.conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT id, target, opts, interval_hours, time_window_mins, last_scan_id FROM schedules "
            "WHERE enabled=1 AND next_run <= ?", (now,))]


def defer(hid, next_run):
    """Odhacza next_run od razu po wystartowaniu: skan trwa minuty/godziny, a kolejne tyknięcie nie może go powtórzyć."""
    with db.conn() as c:
        c.execute("UPDATE schedules SET next_run=? WHERE id=?", (next_run, hid))


def mark_run(hid, scan_id, last_run, next_run):
    with db.conn() as c:
        c.execute("UPDATE schedules SET last_run=?, next_run=?, last_scan_id=? WHERE id=?", (last_run, next_run, scan_id, hid))
