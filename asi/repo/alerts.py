"""Powiadomienia po skanach."""
import time

from .. import db


def add(scan_id, target, level, message):
    with db.conn() as c:
        c.execute("INSERT INTO alerts(scan_id,target,level,message,created) VALUES(?,?,?,?,?)",
                  (scan_id, target, level, message, time.time()))


def recent(limit=30):
    with db.conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]


def unread_count():
    with db.conn() as c:
        return c.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0]


def mark_all_read():
    with db.conn() as c:
        c.execute("UPDATE alerts SET read=1 WHERE read=0")
