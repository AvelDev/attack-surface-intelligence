"""Wynik `nmap -oX` -> słowniki hostów. Przyjmuje też urwany plik (przerwany skan): oddaje hosty, które zdążyły się zapisać."""
import xml.etree.ElementTree as ET

from ..errors import InvalidInput

MAX_SCRIPT_OUTPUT = 4000
MAX_SCRIPTS = 60
MAX_OS = 5
MAX_PORTS_LISTED = 200


class BadXml(InvalidInput):
    """To nie jest wynik nmap -oX."""


def _number(cast, value):
    try:
        return cast(value)
    except (TypeError, ValueError):
        return None


def _table(el):
    """Zagnieżdżone <table>/<elem> skryptu NSE jako słownik (klucze) albo lista (bez kluczy)."""
    items = [(c.get("key"), _table(c) if c.tag == "table" else (c.text or "").strip()) for c in el if c.tag in ("table", "elem")]
    if items and all(k is None for k, _ in items):
        return [v for _, v in items]
    return {k if k is not None else str(i): v for i, (k, v) in enumerate(items)}


def _scripts(parent):
    out = []
    for el in parent.findall("script")[:MAX_SCRIPTS] if parent is not None else ():
        data = _table(el)
        script = {"id": el.get("id", ""), "output": (el.get("output") or "").strip()[:MAX_SCRIPT_OUTPUT]}
        out.append({**script, "data": data} if data else script)
    return out


def _port(el):
    state, svc = el.find("state"), el.find("service")
    st = state.attrib if state is not None else {}
    s = svc.attrib if svc is not None else {}
    out = {"port": int(el.get("portid")), "proto": el.get("protocol", "tcp"), "state": st.get("state", ""), "reason": st.get("reason", ""),
           "service": (s.get("tunnel", "") + "/" if s.get("tunnel") else "") + s.get("name", ""),
           "version": " ".join(x for x in (s.get("product"), s.get("version")) if x), "probed": s.get("method") == "probed"}
    optional = {"info": s.get("extrainfo"), "os_type": s.get("ostype"), "device": s.get("devicetype"),
                "cpe": [c.text for c in svc.findall("cpe") if c.text] if svc is not None else [], "scripts": _scripts(el)}
    return out | {k: v for k, v in optional.items() if v}


def _states(ports_el, ports):
    """Porty inne niż otwarte, zebrane po (protokół, stan): liczba, powód i lista (o ile nmap je wymienił)."""
    groups = {}

    def group(proto, state, reason, count):
        g = groups.setdefault((proto, state), {"proto": proto, "state": state, "count": 0, "reason": reason, "ports": []})
        g["count"] += count
        return g

    for p in ports:
        g = group(p["proto"], p["state"], p["reason"], 1)
        if len(g["ports"]) < MAX_PORTS_LISTED:
            g["ports"].append(p["port"])
    for extra in ports_el.findall("extraports") if ports_el is not None else ():
        why = extra.find("extrareasons")
        why = why.attrib if why is not None else {}
        group(why.get("proto") or "tcp", extra.get("state", ""), why.get("reason", ""), _number(int, extra.get("count")) or 0)
    return sorted(groups.values(), key=lambda g: -g["count"])


def _os(host):
    out = []
    for m in host.findall("os/osmatch")[:MAX_OS]:
        classes = m.findall("osclass")
        first = classes[0].attrib if classes else {}
        out.append({"name": m.get("name", ""), "accuracy": _number(int, m.get("accuracy")) or 0, "family": first.get("osfamily", ""),
                    "type": first.get("type", ""), "cpe": sorted({c.text for k in classes for c in k.findall("cpe") if c.text})})
    return out


def _trace(host):
    return [{"ttl": _number(int, h.get("ttl")), "ip": h.get("ipaddr", ""), "rtt": _number(float, h.get("rtt")), "host": h.get("host", "")}
            for h in host.findall("trace/hop")]


def _attr(el, name):
    return el.get(name) if el is not None else None


def _host(el):
    """Jeden <host> -> słownik albo None (host bez adresu IPv4)."""
    addr = {a.get("addrtype"): a for a in el.findall("address")}
    if "ipv4" not in addr:
        return None
    ports_el = el.find("ports")
    everything = [_port(p) for p in ports_el.findall("port")] if ports_el is not None else []
    # tcpwrapped: połączenie zamykane od razu, port w rzeczywistości nie świadczy usługi
    open_ports = [p for p in everything if p["state"] == "open" and p["service"] != "tcpwrapped"]
    out = {"ip": addr["ipv4"].get("addr"), "state": _attr(el.find("status"), "state") or "", "reason": _attr(el.find("status"), "reason") or "",
           "ports": open_ports, "states": _states(ports_el, [p for p in everything if p["state"] != "open"])}
    optional = {"hostnames": sorted({h.get("name") for h in el.findall("hostnames/hostname") if h.get("name")}),
                "mac": _attr(addr.get("mac"), "addr"), "vendor": _attr(addr.get("mac"), "vendor"), "os": _os(el),
                "uptime_s": _number(int, _attr(el.find("uptime"), "seconds")),
                "distance": _number(int, _attr(el.find("distance"), "value")), "trace": _trace(el),
                "scripts": _scripts(el.find("hostscript")), "timed_out": el.get("timedout") == "true"}
    return out | {k: v for k, v in optional.items() if v}


def merge(xmls):
    """Wyniki kolejnych paczek jako jeden dokument nmaprun (nagłówek z pierwszej, hosty ze wszystkich). None, gdy nic nie ma."""
    root = None
    for xml in xmls:
        run = _recover(xml)
        if run is None:
            continue
        if root is None:
            root = ET.Element("nmaprun", run.attrib)
            root.extend(run.findall("scaninfo"))
        root.extend(run.findall("host"))
    if root is None:
        return None
    up = sum(1 for s in root.iterfind("host/status") if s.get("state") == "up")
    total = len(root.findall("host"))
    stats = ET.SubElement(root, "runstats")
    ET.SubElement(stats, "finished", {"exit": "success", "time": root.get("start", "0"), "elapsed": "0"})
    ET.SubElement(stats, "hosts", {"up": str(up), "down": str(total - up), "total": str(total)})
    return b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n' + ET.tostring(root, encoding="utf-8")


def _recover(xml):
    """Drzewo nmaprun z kompletnymi hostami, także z urwanego pliku."""
    pull = ET.XMLPullParser(("start", "end"))
    try:
        pull.feed(xml)
    except ET.ParseError:
        pass
    root, kept = None, []
    for event, el in _events(pull.read_events()):
        if event == "start" and root is None:
            root = el
        elif event == "end" and el.tag in ("scaninfo", "host"):
            kept.append(el)
    if root is None or root.tag != "nmaprun":
        return None
    out = ET.Element("nmaprun", root.attrib)
    out.extend(kept)
    return out


def _events(reader):
    """Zdarzenia do końca albo do miejsca urwania pliku."""
    seen = False
    while True:
        try:
            event = next(reader)
        except StopIteration:
            return
        except ET.ParseError as e:
            if not seen:
                raise BadXml(f"Nieprawidłowy plik XML: {e}") from e
            return  # przerwany skan: mamy kompletne hosty sprzed urwania
        seen = True
        yield event


def parse(xml):
    """{"args", "version", "started", "elapsed", "complete", "hosts": [...]}. BadXml, gdy to nie wynik nmap."""
    text = xml.decode("utf-8", "replace") if isinstance(xml, bytes) else xml
    if "<!ENTITY" in text:
        raise BadXml("Plik XML definiuje encje - odrzucony.")
    pull = ET.XMLPullParser(("start", "end"))
    try:
        pull.feed(text)
    except ET.ParseError:
        pass  # błąd oddaje też read_events, po zdarzeniach sprzed niego
    out = {"args": "", "version": "", "started": None, "elapsed": None, "complete": False, "hosts": []}
    root = None
    for event, el in _events(pull.read_events()):
        if event == "start" and root is None:
            root = el
            if el.tag != "nmaprun":
                break
            out |= {"args": el.get("args", ""), "version": el.get("version", ""), "started": _number(int, el.get("start"))}
        elif event == "end" and el.tag == "host":
            host = _host(el)
            if host:
                out["hosts"].append(host)
            el.clear()  # duży skan: nie trzymamy drzewa wszystkich hostów
        elif event == "end" and el.tag == "finished":
            out |= {"elapsed": _number(float, el.get("elapsed")), "complete": el.get("exit") == "success"}
    if root is None or root.tag != "nmaprun":
        raise BadXml("To nie jest plik XML programu nmap (nmap -oX).")
    return out
