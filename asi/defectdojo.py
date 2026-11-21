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

URL = os.environ.get("ASI_DEFECTDOJO_URL", "").rstrip("/")
API_KEY = os.environ.get("ASI_DEFECTDOJO_API_KEY", "")
PRODUCT_NAME = os.environ.get("ASI_DEFECTDOJO_PRODUCT", "Attack Surface Intelligence")
PRODUCT_TYPE = os.environ.get("ASI_DEFECTDOJO_PRODUCT_TYPE", "Attack Surface Intelligence")
SEV_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def configured():
    return bool(URL and API_KEY)


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
    if not configured():
        raise RuntimeError("DefectDojo nieskonfigurowany (ASI_DEFECTDOJO_URL / ASI_DEFECTDOJO_API_KEY)")
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
        f"{URL}/api/v2/import-scan/", data=body, method="POST",
        headers={"Authorization": f"Token {API_KEY}", "Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"DefectDojo zwrócił {e.code}: {e.read().decode(errors='ignore')[:500]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Nie udało się połączyć z DefectDojo: {e.reason}") from e
