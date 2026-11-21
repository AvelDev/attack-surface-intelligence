"""Eksport findingów skanu do DefectDojo przez /api/v2/import-scan/ (scan_type
"Generic Findings Import"). Format zweryfikowany względem realnego OpenAPI
(demo.defectdojo.org) i dokumentacji parsera - nieudokumentowane pola w pliku
powodują odrzucenie CAŁEGO importu ("Not allowed fields are present"), więc
wysyłamy tylko ściśle udokumentowany zestaw: title/severity/description/
mitigation/references.
"""
import json
import os
import urllib.error
import urllib.request
import uuid

from . import db

ENV_URL = os.environ.get("ASI_DEFECTDOJO_URL", "").rstrip("/")
ENV_API_KEY = os.environ.get("ASI_DEFECTDOJO_API_KEY", "")
URL = ENV_URL
API_KEY = ENV_API_KEY
PRODUCT_NAME = os.environ.get("ASI_DEFECTDOJO_PRODUCT", "Attack Surface Intelligence")
PRODUCT_TYPE = os.environ.get("ASI_DEFECTDOJO_PRODUCT_TYPE", "Attack Surface Intelligence")
SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def get_config():
    url, key = ENV_URL, ENV_API_KEY
    if not (url and key):
        try:
            with db.conn() as c:
                row_url = c.execute("SELECT value FROM settings WHERE key='defectdojo_url'").fetchone()
                row_key = c.execute("SELECT value FROM settings WHERE key='defectdojo_api_key'").fetchone()
                if row_url and row_url["value"]:
                    url = row_url["value"].rstrip("/")
                if row_key and row_key["value"]:
                    key = row_key["value"].strip()
        except Exception:
            pass
    return url, key


def configured():
    url, key = get_config()
    return bool(url and key)


def _multipart(fields, filename, file_bytes):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        if v is None:
            continue
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f'Content-Type: application/json\r\n\r\n'.encode() + file_bytes + b"\r\n")
    parts.append(f'--{boundary}--\r\n'.encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def export_scan(target, findings, engagement_name=None, timeout=30):
    """Wysyła findingi jednego skanu jako Generic Findings Import. Zwraca odpowiedź DefectDojo
    (zdekodowany JSON) albo rzuca RuntimeError z treścią błędu serwera."""
    url, api_key = get_config()
    if not (url and api_key):
        raise RuntimeError("DefectDojo nieskonfigurowany (podaj URL i API Key w Ustawieniach lub ASI_DEFECTDOJO_*)")
    report = {"findings": [
        {
            "title": str(f["title"])[:511],
            "severity": SEV_MAP.get(f["severity"], "Info"),
            "description": str(f.get("detail") or f["title"]),
            "mitigation": str(f.get("fix") or ""),
            "references": str(f.get("source") or ""),
        }
        for f in findings
    ]}
    fields = {
        "scan_type": "Generic Findings Import",
        "product_name": PRODUCT_NAME,
        "product_type_name": PRODUCT_TYPE,
        "engagement_name": engagement_name or f"ASI - {target}",
        "test_title": f"ASI scan: {target}",
        "auto_create_context": "true",
        "minimum_severity": "Info",
    }
    body, content_type = _multipart(fields, "findings.json", json.dumps(report).encode())
    req = urllib.request.Request(
        f"{url}/api/v2/import-scan/", data=body, method="POST",
        headers={"Authorization": f"Token {api_key}", "Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"DefectDojo zwrócił {e.code}: {e.read().decode(errors='ignore')[:500]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Nie udało się połączyć z DefectDojo: {e.reason}") from e
