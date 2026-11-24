"""Alerty: po zakończeniu skanu porównujemy wynik z poprzednim i zapisujemy ostrzeżenie (+ opcjonalny webhook).

Webhook: ASI_WEBHOOK_URL (JSON {"text": "..."} - zgodny ze Slack/Mattermost/Teams incoming webhook).
"""
import logging

from . import config, history, net
from .domain import URGENT
from .repo import alerts as repo

log = logging.getLogger(__name__)
SCORE_JUMP = 10  # o tyle punktów gorsza ocena = alert, nawet bez nowych pilnych uwag


def _webhook(text):
    url = config.load().webhook_url
    if not url.startswith(("http://", "https://")):
        return
    try:
        net.post_json(url, {"text": text})
    except Exception as e:  # noqa: BLE001 - webhook nie może wywrócić skanu
        log.warning("webhook nie dostarczony: %s", type(e).__name__)


def add(scan_id, target, level, message):
    assert level in ("bad", "warn"), level
    repo.add(scan_id, target, level, message)
    _webhook(f"[ASI] {target}: {message}")


def evaluate(score, findings, diff):
    """Czysta reguła: (poziom, komunikat) albo None. diff=None oznacza pierwszy skan celu."""
    urgent_now = [f for f in findings if f["severity"] in URGENT]
    if diff is None:
        return ("bad", f"Pierwsze sprawdzenie wykryło {len(urgent_now)} pilnych uwag.") if urgent_now else None
    sev = {(f["asset"], f["title"]): f["severity"] for f in findings}
    new_urgent = [x for x in diff["new_findings"] if sev.get((x["asset"], x["title"])) in URGENT]
    worse = (score or 0) - (diff["against_score"] or 0)
    if new_urgent:
        return "bad", f"Pojawiły się nowe pilne problemy ({len(new_urgent)}): " + "; ".join(x["title"] for x in new_urgent[:3])
    if worse >= SCORE_JUMP:
        return "warn", f"Ocena ryzyka pogorszyła się o {worse} pkt (do {score}/100)."
    if diff["new_assets"]:
        return "warn", f"Pojawiły się nowe adresy lub usługi widoczne z internetu ({len(diff['new_assets'])})."
    return None


def after_scan(sid):
    s, assets, _, findings = history.load(sid)
    alert = evaluate(s["score"], findings, history.diff(sid, s["target_hash"], assets, findings))
    if alert:
        add(sid, s["target"], *alert)


def recent(limit=30):
    return {"unread": repo.unread_count(), "items": repo.recent(limit)}


mark_all_read = repo.mark_all_read
