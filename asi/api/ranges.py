"""Zakresy: grupy skanów o tych samych celach (target_hash) - notatka i ponowne uruchomienie."""
import json

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth
from ..errors import Conflict, InvalidInput, NotFound
from ..repo import findings as findings_repo
from ..repo import scans as repo
from ..scan import runner
from .scans import authorized_nmap

router = APIRouter(tags=["ranges"])
MAX_NOTE = 500


class NoteReq(BaseModel):
    note: str


def check_range_id(rid):
    if not (1 <= len(rid) <= 64 and all(ch in "0123456789abcdef" for ch in rid)):
        raise InvalidInput("Nieprawidłowy identyfikator zakresu.")


def _runs(rid):
    check_range_id(rid)
    rows = repo.range_runs(rid)
    if not rows:
        raise NotFound("Nie ma takiego zakresu.")
    if len({r["target_hash"] for r in rows}) > 1:
        raise Conflict("Niejednoznaczny identyfikator zakresu.")
    return rows


@router.put("/ranges/{rid}/note")
def set_range_note(rid: str, req: NoteReq, user: dict = Depends(auth.require("read_modify"))):
    if len(req.note) > MAX_NOTE:
        raise InvalidInput(f"Notatka może mieć najwyżej {MAX_NOTE} znaków.")
    findings_repo.set_range_note(_runs(rid)[0]["target_hash"], req.note.strip(), user["username"])
    return {"ok": True}


@router.post("/ranges/{rid}/run")
def run_range(rid: str, user: dict = Depends(auth.require("add_remove_modify"))):
    """Nowy przebieg zakresu z tymi samymi celami i opcjami co ostatni (zgoda na skan została potwierdzona przy pierwszym
    uruchomieniu tego zakresu)."""
    rows = _runs(rid)
    if any(r["status"] in repo.ACTIVE for r in rows):
        raise Conflict("Ten zakres jest właśnie skanowany.")
    targets = repo.targets_of(rows[0]["id"])
    if not targets:
        raise InvalidInput("Brak zapisanych celów dla tego zakresu.")
    opts = json.loads(rows[0]["opts"] or "{}")
    if opts.get("nmap"):  # opcje mógł zapisać admin; uruchamiający musi mieć do nich prawo
        authorized_nmap(opts["nmap"], user, opts)
    sid, _ = runner.start_scan(targets, opts)
    return {"id": sid}
