"""Agregat dla ekranu Przegląd: stan wszystkich monitorowanych zakresów, zmiany od ostatniego
przebiegu z pewnością (ile przebiegów je potwierdza), kolejka triage i dane mapy adresów.

Zakres = wszystkie skany o tym samym target_hash (ten sam rozwinięty zbiór celów), czyli
dokładnie to, co porównuje _diff w main.py. Skany zakończone są niezmienne, więc ich zasoby
(odszyfrowane) trzymamy w małym cache w pamięci procesu - inaczej polling dashboardu
odszyfrowywałby dziesiątki tysięcy wierszy co kilka sekund.
"""
import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict
from urllib.parse import urlparse

from . import config, crypto, db

HISTORY = 10            # ile ostatnich przebiegów zakresu bierzemy pod uwagę (pewność, flapping, historia)
DETAIL_HOSTS = 16       # do tylu hostów mapa pokazuje porty zamiast płytek /24
CMP_FIELDS = ("service", "version", "status", "title", "server", "tech")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_W = {"critical": 100, "high": 60, "medium": 25, "low": 8, "info": 0}
CLOSED = {"ok", "accepted", "false_positive"}
# "Ciekawość" (priorytet analityczny ze specyfikacji): cechy, które warto obejrzeć ręcznie.
INTEREST = [
    (re.compile(r"phpmyadmin|adminer|wp-admin|/admin|administrat|jenkins|traefik|grafana|kibana|"
                r"portainer|rabbitmq|management|dashboard|proxy manager|webmin|cpanel|login", re.I),
     40, "admin"),
    (re.compile(r"\b(staging|stage|test|dev|demo|uat|preprod|sandbox)\b", re.I), 30, "staging"),
    (re.compile(r"dvwa|vulnerable|wordpress 4\.|wordpress/4\.|php/5\.|openssh[_ ]?[4-6]\.|apache/2\.2", re.I),
     35, "outdated"),
    (re.compile(r"\b(ftp|telnet|redis|mongodb|elasticsearch|memcached|postgres|mysql|mssql|vnc|rdp)\b", re.I),
     20, "exposed-service"),
]

_cache = OrderedDict()
_cache_lock = threading.Lock()
_CACHE_MAX = 40


def _scan_assets(c, scan_id, immutable):
    if immutable:
        with _cache_lock:
            if scan_id in _cache:
                _cache.move_to_end(scan_id)
                return _cache[scan_id]
    out = {}
    for r in c.execute("SELECT id, kind, value, data FROM assets WHERE scan_id=?", (scan_id,)):
        try:
            data = json.loads(crypto.dec(r["data"])) if r["kind"] in ("port", "web") else {}
        except Exception:  # noqa: BLE001 - uszkodzony wiersz nie może położyć całego dashboardu
            data = {}
        out[r["id"]] = (r["kind"], r["value"], data)
    if immutable:
        with _cache_lock:
            _cache[scan_id] = out
            while len(_cache) > _CACHE_MAX:
                _cache.popitem(last=False)
    return out


def _cmp_value(d, k):
    v = d.get(k)
    if isinstance(v, list):
        return ",".join(sorted(str(x) for x in v))
    return "" if v is None else str(v)


def _changed_fields(a, b):
    out = []
    for k in CMP_FIELDS:
        va, vb = _cmp_value(a, k), _cmp_value(b, k)
        if va != vb and (va or vb):
            out.append({"field": k, "old": va[:120], "new": vb[:120]})
    return out


def _ip_of(kind, value):
    if kind == "ip":
        return value
    if kind == "port":
        return value.rsplit(":", 1)[0]
    return None


def _port_label(text):
    """TCP jako liczba, inne protokoły z przyrostkiem: "53/udp" (ports.port_value)."""
    return int(text) if text.isdigit() else text


def _port_sort(label):
    number, _, proto = str(label).partition("/")
    return int(number), proto


def _describe(kind, value, data):
    if kind == "port":
        bits = [data.get("service") or "", data.get("version") or ""]
        return " ".join(b for b in bits if b).strip() or f"port {value.rsplit(':', 1)[-1]}"
    if kind == "web":
        tech = data.get("tech") or []
        tech = ", ".join(tech[:3]) if isinstance(tech, list) else str(tech)
        bits = [str(data.get("status") or ""), data.get("title") or "", tech]
        return " · ".join(b for b in bits if b) or value
    return value


def _interest(text):
    score, tags = 0, []
    for rx, w, tag in INTEREST:
        if rx.search(text or ""):
            score += w
            tags.append(tag)
    return score, tags


def _block_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None, None
    if a.version == 4:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net), int(a) & 0xFF
    net = ipaddress.ip_network(f"{ip}/120", strict=False)
    return str(net), int(a) & 0xFF


def _presence(aid, hist_sets):
    """hist_sets: od najstarszego do najnowszego przebiegu. Zwraca (obecny_w, z_ilu, przejścia)."""
    seq = [aid in s for s in hist_sets]
    flips = sum(1 for x, y in zip(seq, seq[1:], strict=False) if x != y)
    return sum(seq), len(seq), flips


def build(range_hash=None, scan_id=None, at=None):
    now = time.time()
    with db.conn() as c:
        scans = [dict(r) for r in c.execute(
            "SELECT id, target, target_hash, opts, status, stage, hosts_total, hosts_done, duration_s, "
            "created, finished FROM scans WHERE target_hash!='' AND stage!='zaimportowany' "
            "AND target_hash NOT LIKE 'import:%' ORDER BY id DESC")]
        notes = {r["target_hash"]: dict(r) for r in c.execute("SELECT * FROM range_notes")}
        triage = {(r["asset"], r["key"]): dict(r) for r in c.execute("SELECT * FROM triage")}
        schedules = [dict(r) for r in c.execute(
            "SELECT target, interval_hours, time_window_mins, next_run, enabled FROM schedules")]

        groups = OrderedDict()
        for s in scans:
            groups.setdefault(s["target_hash"], []).append(s)

        ranges, queue, map_ranges = [], [], []
        totals = {"hosts": 0, "services": 0, "new": 0, "removed": 0, "changed": 0, "flapping": 0,
                  "critical": 0, "high": 0, "offline": 0}
        for thash, runs in groups.items():
            if range_hash and not thash.startswith(range_hash):
                continue
            r = _range(c, thash, runs, notes, triage, schedules, now,
                       scan_id if range_hash else None, at)
            ranges.append(r["meta"])
            queue.extend(r["queue"])
            map_ranges.append(r["map"])
            for k in totals:
                totals[k] += r["meta"]["counts"].get(k, 0)

    queue.sort(key=lambda q: (q["triage"] in CLOSED, -q["priority"], q["asset"]))
    history = _merge_history([r["history"] for r in ranges])
    last_pass = max((r["last_pass"] or 0 for r in ranges), default=0) or None
    return {
        "generated": now,
        "totals": totals,
        "history": history,
        "ranges": ranges,
        "queue": queue[:400],
        "queue_total": len(queue),
        "map": {"ranges": map_ranges,
                "detail": sum(m["host_count"] for m in map_ranges) <= DETAIL_HOSTS},
        "meta": {"rate_default": config.load().scan_rate, "encryption": True, "last_pass": last_pass,
                 "running": sum(1 for r in ranges if r["state"]["status"] in ("running", "queued"))},
    }


def _merge_history(hists):
    """Historia liczby zmian: przy jednym zakresie per przebieg, przy wielu zsumowana per dzień
    (przebiegi różnych zakresów nie są porównywalne punkt w punkt). Do 14 punktów."""
    hists = [h for h in hists if h]
    if len(hists) == 1:
        return hists[0][-14:]
    days = {}
    for h in hists:
        for p in h:
            d = int(p["t"] // 86400)
            e = days.setdefault(d, {"t": d * 86400 + 43200, "scan_id": None, "changes": 0})
            e["changes"] += p["changes"]
    return [days[d] for d in sorted(days)][-14:]


def _range(c, thash, runs, notes, triage, schedules, now, pick_scan, at=None):
    done = [s for s in runs if s["status"] == "done"]
    active = next((s for s in runs if s["status"] in ("running", "queued")), None)
    last = runs[0]
    base = None
    if pick_scan:
        base = next((s for s in done if s["id"] == int(pick_scan)), None)
    elif at and done:
        # suwak w widoku wszystkich zakresów: każdy zakres pokazuje ostatni przebieg sprzed `at`
        base = next((s for s in done if (s["finished"] or s["created"]) <= at), done[-1])
    base = base or (done[0] if done else None)

    hist_runs = []
    if base:
        older = [s for s in done if s["id"] <= base["id"]]
        hist_runs = list(reversed(older[:HISTORY]))  # od najstarszego
    hist_assets = [_scan_assets(c, s["id"], True) for s in hist_runs]
    hist_sets = [set(a) for a in hist_assets]

    cur = hist_assets[-1] if hist_assets else {}
    prev = hist_assets[-2] if len(hist_assets) > 1 else None
    first_pass = prev is None

    tracked = ("ip", "port", "web")
    changes = []  # (aid, kind_of_change, detail)
    if prev is not None:
        for aid in cur.keys() - prev.keys():
            if cur[aid][0] in tracked:
                changes.append((aid, "new", None))
        for aid in prev.keys() - cur.keys():
            if prev[aid][0] in tracked:
                changes.append((aid, "removed", None))
        for aid in cur.keys() & prev.keys():
            if cur[aid][0] in ("port", "web"):
                diff = _changed_fields(prev[aid][2], cur[aid][2])
                if diff:
                    changes.append((aid, "changed", diff))

    # flapping: zasób, który w oknie historii co najmniej dwa razy zmienił obecność
    flapping, offline = set(), set()
    if len(hist_sets) >= 3:
        universe = set().union(*hist_sets)
        for aid in universe:
            kind = (cur.get(aid) or (prev or {}).get(aid) or next(h[aid] for h in hist_assets if aid in h))[0]
            if kind not in tracked:
                continue
            seen, n, flips = _presence(aid, hist_sets)
            if flips >= 2:
                flapping.add(aid)
            elif aid not in hist_sets[-1] and aid not in hist_sets[-2] and seen:
                offline.add(aid)

    # Jedna zmiana = jedna pozycja: host, który zniknął, nie generuje osobnej pozycji per port,
    # a port z usługą web jest reprezentowany przez bogatszy zasób web.
    def _hostport(aid):
        if aid.startswith("port:"):
            return aid[5:]
        if aid.startswith("web:"):
            u = urlparse(aid[4:])
            if u.hostname:
                return f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
        return None

    folded = {}  # aid rodzica -> lista złożonych w niego zasobów potomnych

    def _collapse(items):
        """items: lista (aid, kind). Zwraca zbiór aid do pominięcia (złożonych w rodzica)."""
        ip_kind = {aid[3:]: k for aid, k in items if aid.startswith("ip:")}
        web_kind = {(_hostport(aid), k): aid for aid, k in items if aid.startswith("web:")}
        drop = set()
        for aid, k in items:
            if aid.startswith(("port:", "web:")):
                hp = _hostport(aid)
                ip = hp.rsplit(":", 1)[0] if hp else None
                if ip and ip_kind.get(ip) == k:
                    drop.add(aid)
                    folded.setdefault(f"ip:{ip}", []).append(aid)
                elif aid.startswith("port:") and (hp, k) in web_kind:
                    drop.add(aid)
        return drop

    # zasób niestabilny pokazujemy jako flapping, nie dodatkowo jako nowy/zniknięty
    changes = [x for x in changes if not (x[1] in ("new", "removed") and x[0] in flapping)]
    drop = _collapse([(a, k) for a, k, _ in changes])
    changes = [x for x in changes if x[0] not in drop]
    drop = _collapse([(a, "flapping") for a in flapping] + [(a, "offline") for a in offline])
    flapping -= drop
    offline -= drop

    # ustalenia bieżącego i poprzedniego przebiegu
    findings, prev_keys = [], set()
    if base:
        findings = [dict(r) for r in c.execute(
            "SELECT rowid, asset, severity, title, source, fix FROM findings WHERE scan_id=?", (base["id"],))]
    if len(hist_runs) > 1:
        prev_keys = {(r["asset"], r["title"]) for r in c.execute(
            "SELECT asset, title FROM findings WHERE scan_id=?", (hist_runs[-2]["id"],))}
    sev_by_asset = {}
    for f in findings:
        if SEV_ORDER.get(f["severity"], 9) < SEV_ORDER.get(sev_by_asset.get(f["asset"], "info"), 9):
            sev_by_asset[f["asset"]] = f["severity"]

    # web:http://host:port -> najgorsza waga, przypisana też do portu host:port
    port_sev = {}
    for k, v in sev_by_asset.items():
        if not k.startswith("web:"):
            continue
        u = urlparse(k[4:])
        if not u.hostname:
            continue
        hp = f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"
        if SEV_ORDER.get(v, 9) < SEV_ORDER.get(port_sev.get(hp, "info"), 9):
            port_sev[hp] = v

    def asset_sev(aid):
        best = sev_by_asset.get(aid, "info")
        if aid.startswith("port:"):
            v = port_sev.get(aid[5:], "info")
            if SEV_ORDER.get(v, 9) < SEV_ORDER.get(best, 9):
                best = v
        for child in folded.get(aid, ()):
            v = asset_sev(child)
            if SEV_ORDER.get(v, 9) < SEV_ORDER.get(best, 9):
                best = v
        return best

    def describe(aid):
        info = cur.get(aid) or (prev or {}).get(aid) or next((h[aid] for h in reversed(hist_assets) if aid in h), None)
        if not info:
            return aid.split(":", 1)[-1]
        kids = folded.get(aid)
        if kids:
            parts = []
            for k in sorted(kids, key=lambda a: (not a.startswith("web:"), a)):
                ki = cur.get(k) or (prev or {}).get(k) or next((h[k] for h in reversed(hist_assets) if k in h), None)
                if ki:
                    port = (_hostport(k) or "").rsplit(":", 1)[-1]
                    parts.append(f":{port} {_describe(*ki)}".strip())
            seen_ports, uniq = set(), []
            for ptxt in parts:
                pk = ptxt.split(" ", 1)[0]
                if pk not in seen_ports:
                    seen_ports.add(pk)
                    uniq.append(ptxt)
            return " · ".join(uniq[:3]) + (f" · +{len(uniq) - 3}" if len(uniq) > 3 else "")
        return _describe(*info)

    rid = thash[:12]
    queue = []

    def push(aid, kind, title, sev, detail=None, rowid=None, key=None, extra_text=""):
        info = cur.get(aid) or (prev or {}).get(aid) or ("", aid.split(":", 1)[-1], {})
        akind, value, data = info
        text = f"{value} {title} {extra_text}"
        iscore, tags = _interest(text)
        seen, n, _ = _presence(aid, hist_sets) if hist_sets else (0, 0, 0)
        key = key or kind
        t = triage.get((aid, key))
        prio = SEV_W.get(sev, 0) + iscore + {"new": 15, "changed": 10, "flapping": 8, "removed": 6,
                                             "offline": 5, "finding": 0}.get(kind, 0)
        queue.append({
            "id": f"{rid}|{aid}|{key}", "range": rid, "scan_id": base["id"] if base else None,
            "asset": aid, "asset_kind": akind, "value": value, "kind": kind, "title": title,
            "severity": sev, "detail": detail, "finding_rowid": rowid, "key": key,
            "tags": tags, "priority": prio, "confidence": [seen, n],
            "triage": t["status"] if t else "open", "triage_note": t["note"] if t else "",
            "triage_by": t["username"] if t else "",
        })

    counts = {"new": 0, "removed": 0, "changed": 0, "flapping": len(flapping), "offline": len(offline),
              "critical": 0, "high": 0}
    change_map = {}
    for aid, kind, detail in changes:
        counts[kind] += 1
        title = describe(aid)
        if kind == "changed":
            title = "; ".join(f"{d['field']}: {d['old'] or '∅'} → {d['new'] or '∅'}" for d in detail[:2])
        push(aid, kind, title, asset_sev(aid) if kind != "removed" else "info", detail,
             extra_text=title)
        change_map[aid] = kind
    for aid in flapping:
        push(aid, "flapping", describe(aid), asset_sev(aid))
        change_map.setdefault(aid, "flapping")
    for aid in offline:
        push(aid, "offline", describe(aid), "info")
        change_map.setdefault(aid, "offline")
    for f in findings:
        if f["title"].startswith("[False Positive] "):
            continue
        is_new = not first_pass and (f["asset"], f["title"]) not in prev_keys
        if f["severity"] == "critical":
            counts["critical"] += 1
        elif f["severity"] == "high":
            counts["high"] += 1
        # kolejka: wszystko, co nowe, plus krytyczne niezależnie od wieku; znane, niezmienione
        # ustalenia niższej wagi to stan, nie zmiana - żyją w widoku skanu
        if is_new or f["severity"] == "critical":
            push(f["asset"], "finding", f["title"], f["severity"], rowid=f["rowid"], key=f["title"],
                 extra_text=f["source"])

    hp_state_early = {}
    for aid, st in change_map.items():
        hp = _hostport(aid) if aid.startswith("web:") else None
        if hp:
            hp_state_early.setdefault(hp, st)

    # mapa: hosty (IP) z portami
    hosts = {}
    for src in ([prev] if prev else []) + [cur]:
        for aid, (kind, value, _data) in src.items():
            ip = _ip_of(kind, value)
            if not ip:
                continue
            h = hosts.setdefault(ip, {"ip": ip, "ports": {}, "alive": False})
            if src is cur:
                h["alive"] = True
            if kind == "port":
                h["ports"][value.rsplit(":", 1)[-1]] = aid
    map_hosts = []
    for ip, h in hosts.items():
        hid = f"ip:{ip}"
        port_ids = list(h["ports"].values())
        states = [st for st in ([change_map.get(hid)] + [change_map.get(a) or hp_state_early.get(a[5:]) for a in port_ids]) if st]
        sev = min((asset_sev(a) for a in [hid] + port_ids), key=lambda s: SEV_ORDER.get(s, 9), default="info")
        block, octet = _block_of(ip)
        entry = {"ip": ip, "block": block, "octet": octet, "alive": h["alive"],
                 "state": _dominant(states, change_map.get(hid)),
                 "changes": len(states), "severity": sev, "services": len(port_ids)}
        map_hosts.append(entry)
        entry["_ports"] = sorted(((_port_label(p), a) for p, a in h["ports"].items()), key=lambda x: _port_sort(x[0]))
    detail_mode = len(map_hosts) <= DETAIL_HOSTS
    # stan portu w mapie: zmiana mogła zostać zgłoszona na bogatszym zasobie web tego portu
    hp_state = {}
    for aid, st in change_map.items():
        hp = _hostport(aid) if aid.startswith("web:") else None
        if hp:
            hp_state.setdefault(hp, st)

    def port_state(a):
        return change_map.get(a) or hp_state.get(a[5:])
    for e in map_hosts:
        ports = e.pop("_ports")
        if detail_mode:
            e["ports"] = [{"port": p, "asset": a, "state": port_state(a),
                           "alive": a in cur, "severity": asset_sev(a),
                           "label": _describe(*(cur.get(a) or prev.get(a)))} for p, a in ports]
    blocks = OrderedDict()
    for e in sorted(map_hosts, key=lambda e: _ip_sort(e["ip"])):
        blocks.setdefault(e["block"] or "inne", []).append(e)

    domains = sorted({v for (k, v, _) in cur.values() if k in ("domain", "subdomain")})
    history = []
    for _prev_s, cur_s, pa, ca in zip(hist_runs, hist_runs[1:], hist_assets, hist_assets[1:], strict=False):
        n = len({a for a in ca.keys() ^ pa.keys() if (ca.get(a) or pa.get(a))[0] in tracked})
        history.append({"t": cur_s["finished"] or cur_s["created"], "scan_id": cur_s["id"], "changes": n})

    opts = json.loads(last["opts"] or "{}")
    sched = next((s for s in schedules if s["target"].strip() == last["target"].strip()), None)
    window = opts.get("time_window_mins") or (sched or {}).get("time_window_mins")
    st = active or last
    elapsed = (now - st["created"]) if st["status"] in ("running", "queued") else (st["duration_s"] or 0)
    last_change = next((p["t"] for p in reversed(history) if p["changes"]), None)
    note = notes.get(thash)

    meta = {
        "id": rid, "hash": thash, "name": last["target"],
        "hosts_alive": sum(1 for h in map_hosts if h["alive"]),
        "services": sum(1 for v in cur.values() if v[0] == "port"),
        "web": sum(1 for v in cur.values() if v[0] == "web"),
        "domains": len(domains),
        "counts": {**counts, "hosts": sum(1 for h in map_hosts if h["alive"]),
                   "services": sum(1 for v in cur.values() if v[0] == "port")},
        "first_pass": first_pass, "has_data": bool(base),
        "base_scan": base["id"] if base else None,
        "prev_scan": hist_runs[-2]["id"] if len(hist_runs) > 1 else None,
        "passes": [{"id": s["id"], "t": s["finished"] or s["created"]} for s in hist_runs]
                  + ([{"id": d["id"], "t": d["finished"] or d["created"]} for d in done if base and d["id"] > base["id"]]),
        "state": {"status": st["status"], "stage": st["stage"], "scan_id": st["id"],
                  "hosts_total": st["hosts_total"], "hosts_done": st["hosts_done"],
                  "started": st["created"], "elapsed": elapsed},
        "window_mins": window,
        "schedule": {"interval_hours": sched["interval_hours"], "next_run": sched["next_run"],
                     "enabled": bool(sched["enabled"])} if sched else None,
        "first_seen": min(s["created"] for s in runs),
        "last_change": last_change,
        "last_pass": (base["finished"] if base else None),
        "note": note["note"] if note else "", "note_by": note["username"] if note else "",
        "history": history,
    }
    meta["passes"].sort(key=lambda p: p["id"])
    return {
        "meta": meta, "queue": queue, "history": history,
        "map": {"range": rid, "name": last["target"], "host_count": len(map_hosts),
                "blocks": [{"prefix": k, "hosts": v} for k, v in blocks.items()],
                "domains": domains[:200]},
    }


def _dominant(states, own):
    if own:
        return own
    if any(x in ("new", "removed", "changed") for x in states):
        return "changed"
    for x in ("flapping", "offline"):
        if x in states:
            return x
    return None


def _ip_sort(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)
