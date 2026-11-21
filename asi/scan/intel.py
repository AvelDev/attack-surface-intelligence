"""Wywiad zewnętrzny: co o Waszych adresach wie internet i jakie znane podatności pasują do wykrytego oprogramowania.

Źródła (wszystkie opcjonalne, błąd jednego nie przerywa skanu):
  - Shodan InternetDB (bez klucza) lub Shodan API (z kluczem): porty, CPE, CVE
  - Censys Platform API (token): porty widziane przez Censys
  - CISA KEV: lista podatności aktywnie wykorzystywanych (cache 24 h w data/kev.json)
  - NVD 2.0: podatności dla CPE (ważność z CVSS)
  - Have I Been Pwned: wycieki adresów e-mail domeny
Klucze pochodzą z settings.py i nie trafiają do logów (logujemy tylko nazwę źródła i ogólny błąd).
"""
import json
import os
import re
import time
import urllib.error
import urllib.parse

from .. import config, net, settings
from .ports import SENSITIVE_PORTS

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_CVE_PER_IP = 8


def _get(url, headers=None, timeout=15):
    return net.get_json(url, timeout=timeout, headers=headers)


def kev_set():
    path = os.path.join(os.path.dirname(config.load().db_path), "kev.json")
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < 86400:
            with open(path, encoding="utf-8") as f:
                return set(json.load(f))
    except (OSError, ValueError):
        pass
    try:
        ids = [v["cveID"] for v in _get(KEV_URL, timeout=30)["vulnerabilities"]]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ids, f)
        return set(ids)
    except Exception:  # noqa: BLE001
        try:  # nieaktualny cache lepszy niż nic
            with open(path, encoding="utf-8") as f:
                return set(json.load(f))
        except (OSError, ValueError):
            return set()


# ---------- źródła o hostach ----------
def internetdb(ip):
    try:
        j = _get(f"https://internetdb.shodan.io/{ip}")
        return {"ports": j.get("ports", []), "cpes": j.get("cpes", []), "vulns": j.get("vulns", [])}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ports": [], "cpes": [], "vulns": []}  # brak danych o tym IP
        raise


def shodan_host(ip, key):
    try:
        j = _get(f"https://api.shodan.io/shodan/host/{ip}?" + urllib.parse.urlencode({"key": key}))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ports": [], "cpes": [], "vulns": []}
        raise
    cpes = sorted({c for d in j.get("data", []) for c in d.get("cpe", [])})
    return {"ports": j.get("ports", []), "cpes": cpes, "vulns": j.get("vulns", [])}


def censys_host(ip, token, org=""):
    h = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if org:
        h["X-Organization-ID"] = org
    try:
        j = _get(f"https://api.platform.censys.io/v3/global/asset/host/{ip}", headers=h)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ports": []}
        raise
    svc = (j.get("result", {}).get("resource", {}) or {}).get("services", []) or []
    return {"ports": sorted({s["port"] for s in svc if "port" in s})}


# ---------- NVD ----------
def cpe22_to_23(cpe):
    """cpe:/a:apache:http_server:2.4.49 -> cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    m = re.match(r"^cpe:/([aoh]):([^:]+):([^:]+)(?::([^:]+))?", cpe)
    if not m or not m.group(4):
        return None  # bez wersji nie da się wiarygodnie dopasować
    return f"cpe:2.3:{m.group(1)}:{m.group(2)}:{m.group(3)}:{m.group(4)}:*:*:*:*:*:*:*"


def nvd_for_cpe(cpe23, key):
    q = urllib.parse.urlencode({"virtualMatchString": cpe23, "noRejected": "", "resultsPerPage": 20})
    headers = {"apiKey": key} if key else {}
    out = []
    for v in _get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, headers=headers, timeout=30).get("vulnerabilities", []):
        c = v["cve"]
        score = 0.0
        for m in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(m):
                score = c["metrics"][m][0]["cvssData"]["baseScore"]
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": c["id"], "score": score, "desc": desc[:300]})
    return out


def sev_for(cve_id, score, kev):
    if cve_id in kev:
        return "critical"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


# ---------- HIBP ----------
def hibp_domain(domain, key):
    """Zwraca {alias: [wycieki]} lub None, gdy brak wycieków. Wyjątek przy błędzie (401/403)."""
    try:
        return _get("https://haveibeenpwned.com/api/v3/breacheddomain/" + urllib.parse.quote(domain),
                    headers={"hibp-api-key": key}) or None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


# ---------- główny etap ----------
def enrich(ctx, ips, root, target, ip_target):
    """Dodaje ustalenia z zewnętrznych baz. Nic nie jest wysyłane do sprawdzanej strony."""
    shodan_key, censys_tok = settings.get("shodan_api_key"), settings.get("censys_token")
    nvd_key, hibp_key = settings.get("nvd_api_key"), settings.get("hibp_api_key")
    kev = kev_set()
    ctx.log(f"Źródła: {'Shodan API' if shodan_key else 'Shodan InternetDB'}"
            f"{', Censys' if censys_tok else ''}, CISA KEV ({len(kev)} wpisów), NVD{' (z kluczem)' if nvd_key else ''}"
            f"{', HIBP' if hibp_key else ''}")
    cpes_seen = {}  # cpe23 -> [ip]
    for ip in ips:
        try:
            info = shodan_host(ip, shodan_key) if shodan_key else internetdb(ip)
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  {'Shodan' if shodan_key else 'InternetDB'} {ip}: {type(e).__name__}")
            continue
        ip_id = f"ip:{ip}"
        for cve in [c for c in info["vulns"] if CVE_RE.match(c)][:MAX_CVE_PER_IP]:
            sev = "critical" if cve in kev else "high"
            ctx.finding(ip_id, sev, f"Znana podatność {cve} (wg Shodan){' - aktywnie wykorzystywana' if cve in kev else ''}",
                        "shodan", f"{ip}: {cve}" + (" (CISA KEV)" if cve in kev else ""),
                        "Zaktualizuj oprogramowanie na tym serwerze lub zablokuj dostęp do usługi; zob. https://nvd.nist.gov/vuln/detail/" + cve)
        for c in info["cpes"]:
            c23 = cpe22_to_23(c)
            if c23:
                cpes_seen.setdefault(c23, []).append(ip)
        if censys_tok:
            try:
                cp = censys_host(ip, censys_tok, settings.get("censys_org_id"))
                ctx.log(f"  Censys {ip}: porty {cp['ports']}")
                for port in cp["ports"]:
                    aid = f"port:{ip}:{port}"
                    if not ctx.has_asset(aid) and port in SENSITIVE_PORTS:
                        ctx.finding(ip_id, "medium", f"Censys widzi otwarty port {port}, którego nie potwierdził skan",
                                    "censys", f"{ip}:{port}", "Sprawdź, czy usługa jest dostępna z innych lokalizacji (firewall geograficzny, "
                                    "reguły czasowe) i zamknij ją, jeśli nie jest potrzebna.")
            except Exception as e:  # noqa: BLE001
                ctx.log(f"  Censys {ip}: {type(e).__name__}")

    # NVD: tylko dla CPE z wersją, z limitem i opóźnieniem zgodnym z limitami API
    delay = 0.7 if nvd_key else 6.5
    for n, (c23, owners) in enumerate(list(cpes_seen.items())[:6]):
        try:
            if n:
                time.sleep(delay)
            hits = sorted(nvd_for_cpe(c23, nvd_key), key=lambda x: -x["score"])
            hits = [h for h in hits if h["score"] >= 7 or h["id"] in kev][:3]
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  NVD {c23}: {type(e).__name__}")
            continue
        for h in hits:
            for ip in owners:
                ctx.finding(f"ip:{ip}", sev_for(h["id"], h["score"], kev),
                            f"Oprogramowanie z podatnością {h['id']} (CVSS {h['score']})"
                            f"{' - aktywnie wykorzystywana' if h['id'] in kev else ''}",
                            "nvd", f"{c23.split(':')[4]} {c23.split(':')[5]} - {h['desc']}",
                            "Zaktualizuj to oprogramowanie do wersji, która nie jest podatna. Szczegóły: https://nvd.nist.gov/vuln/detail/" + h["id"])

    if hibp_key and not ip_target:
        try:
            r = hibp_domain(target, hibp_key)
            if r:
                names = sorted({b for v in r.values() for b in v})
                ctx.finding(root, "high", "Adresy e-mail domeny pojawiły się w znanych wyciekach danych", "hibp",
                            f"{len(r)} adresów w {len(names)} wyciekach: {', '.join(names[:8])}",
                            "Wymuś zmianę haseł dla tych kont, włącz uwierzytelnianie dwuskładnikowe. Listę adresów pobierzesz w panelu Have I Been Pwned.")
        except urllib.error.HTTPError as e:
            ctx.log("  HIBP: " + {401: "nieprawidłowy klucz", 403: "domena niezweryfikowana na koncie HIBP"}.get(e.code, f"błąd HTTP {e.code}"))
        except Exception as e:  # noqa: BLE001
            ctx.log(f"  HIBP: {type(e).__name__}")
