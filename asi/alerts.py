"""Alerty: po zakończeniu skanu porównujemy wynik z poprzednim i zapisujemy ostrzeżenie (+ opcjonalny webhook).

Webhook: ASI_WEBHOOK_URL (JSON {"text": "..."} - zgodny ze Slack/Mattermost/Teams incoming webhook).
"""
import json
import os
import time
import urllib.request

from . import db, store

URGENT = ("critical", "high")
SCORE_JUMP = 10  # o tyle punktów gorsza ocena = alert, nawet bez nowych pilnych uwag


def _webhook(text):
    url = os.environ.get("ASI_WEBHOOK_URL", "").strip()
    if not url.startswith(("http://", "https://")):
        return
    try:
        req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:  # noqa: BLE001 - webhook nie może wywrócić skanu
        pass


def add(scan_id, target, level, message):
    with db.conn() as c:
        c.execute("INSERT INTO alerts(scan_id,target,level,message,created) VALUES(?,?,?,?,?)",
                  (scan_id, target, level, message, time.time()))
    _webhook(f"[ASI] {target}: {message}")


def after_scan(sid):
    loaded = store.load(sid)
    if not loaded:
        return
    s, assets, _, findings = loaded
    d = store.diff(sid, s["target"], assets, findings)
    sev = {(f["asset"], f["title"]): f["severity"] for f in findings}
    urgent_now = [f for f in findings if f["severity"] in URGENT]
    if d is None:
        if urgent_now:
            add(sid, s["target"], "bad", f"Pierwsze sprawdzenie wykryło {len(urgent_now)} pilnych uwag.")
        return
    new_urgent = [x for x in d["new_findings"] if sev.get((x["asset"], x["title"])) in URGENT]
    worse = (s["score"] or 0) - (d["against_score"] or 0)
    if new_urgent:
        add(sid, s["target"], "bad",
            f"Pojawiły się nowe pilne problemy ({len(new_urgent)}): " + "; ".join(x["title"] for x in new_urgent[:3]))
    elif worse >= SCORE_JUMP:
        add(sid, s["target"], "warn", f"Ocena ryzyka pogorszyła się o {worse} pkt (do {s['score']}/100).")
    elif d["new_assets"]:
        add(sid, s["target"], "warn", f"Pojawiły się nowe adresy lub usługi widoczne z internetu ({len(d['new_assets'])}).")
