"""Stan systemu: dostępność narzędzi i zdrowie aplikacji."""
from fastapi import APIRouter, Depends

from .. import auth, db
from ..scan import tools

router = APIRouter(tags=["system"])


@router.get("/tools")
def tool_status(user: dict = Depends(auth.require("read"))):
    return tools.status()


@router.get("/health")
def health():
    """Dla healthchecka kontenera i weryfikacji po wdrożeniu/wycofaniu: czy baza ma oczekiwaną wersję schematu.
    Bez uwierzytelniania - nie ujawnia nic poza numerem wersji schematu."""
    version = db.schema_version()
    return {"status": "ok" if version == db.SCHEMA_VERSION else "degraded",
            "schema": version, "expected_schema": db.SCHEMA_VERSION}
