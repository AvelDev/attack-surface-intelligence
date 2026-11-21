"""Magazyn klucz-wartość dla ustawień (klucze API)."""
from .. import db


def get(key):
    with db.conn() as c:
        r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def put(key, value):
    with db.conn() as c:
        c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def delete(key):
    with db.conn() as c:
        c.execute("DELETE FROM settings WHERE key=?", (key,))


def stored_keys():
    with db.conn() as c:
        return {r["key"] for r in c.execute("SELECT key FROM settings")}
