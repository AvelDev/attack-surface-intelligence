"""Konfiguracja aplikacji ze zmiennych środowiskowych - jedno miejsce, które zna ich nazwy.

Czytana przy każdym wywołaniu `load()` (koszt pomijalny), więc zmiana środowiska w testach
lub po restarcie usługi działa bez przeładowywania modułów. Klucze API (ASI_<NAZWA>_API_KEY)
obsługuje settings.py, bo mają też wariant zapisany w bazie.
"""
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _flag(name, default=False):
    v = os.environ.get(name, "").strip().lower()
    return default if not v else v in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    db_path: str
    allowed_targets: tuple
    allow_private: bool
    webhook_url: str
    scheduler_enabled: bool
    static_dir: str
    frontend_dist: str
    secret_key_file: str
    max_workers: int  # ile skanów (jobów) naraz
    scan_rate: int  # pakiety/s dla naabu/nmap (per paczka)
    max_targets: int  # twardy limit celów na skan (rozwinięty CIDR)
    nmap_intrusive: bool  # czy rola admin może uruchamiać skrypty NSE z kategorii brute/exploit/dos/fuzzer
    external_intel: bool  # czy wysyłać publiczne adresy skanowanych celów do zewnętrznych baz (Shodan, NVD, Censys)


def load():
    return Config(
        db_path=os.environ.get("ASI_DB") or str(ROOT / "data" / "asi.db"),
        allowed_targets=tuple(x.strip().lower() for x in os.environ.get("ASI_ALLOWED_TARGETS", "").split(",") if x.strip()),
        allow_private=_flag("ASI_ALLOW_PRIVATE"),
        webhook_url=os.environ.get("ASI_WEBHOOK_URL", "").strip(),
        scheduler_enabled=_flag("ASI_SCHEDULER", default=True),
        static_dir=str(ROOT / "static"),
        frontend_dist=os.environ.get("ASI_FRONTEND_DIST") or str(ROOT / "frontend" / "dist"),
        secret_key_file=os.environ.get("ASI_SECRET_KEY_FILE") or str(ROOT / "data" / "secret.key"),
        max_workers=int(os.environ.get("ASI_MAX_WORKERS", "4")),
        scan_rate=int(os.environ.get("ASI_SCAN_RATE", "300")),
        max_targets=int(os.environ.get("ASI_MAX_TARGETS", "20000")),
        nmap_intrusive=_flag("ASI_NMAP_INTRUSIVE"),
        external_intel=_flag("ASI_EXTERNAL_INTEL"),
    )
