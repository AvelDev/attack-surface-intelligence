from fastapi import APIRouter

from .. import db
from ..scan import tools

router = APIRouter(tags=["system"])


@router.get("/tools")
def tool_status():
    return tools.status()


@router.get("/health")
def health():
    """Dla healthchecka kontenera i weryfikacji po wdrożeniu/wycofaniu: czy baza ma oczekiwaną wersję schematu."""
    version = db.schema_version()
    return {"status": "ok" if version == db.SCHEMA_VERSION else "degraded",
            "schema": version, "expected_schema": db.SCHEMA_VERSION}
