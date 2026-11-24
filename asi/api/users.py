"""Zarządzanie użytkownikami (tylko admin)."""
import sqlite3

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import auth
from ..errors import Conflict, InvalidInput

router = APIRouter(tags=["users"])


class UserCreate(BaseModel):
    username: str
    password: str
    role: str


@router.get("/users")
def list_users(user: dict = Depends(auth.require("admin"))):
    return auth.list_users()


@router.post("/users")
def create_user(req: UserCreate, user: dict = Depends(auth.require("admin"))):
    if req.role not in auth.ROLES:
        raise InvalidInput(f"Rola musi być jedną z: {', '.join(auth.ROLES)}")
    try:
        auth.create_user(req.username, req.password, req.role)
    except sqlite3.IntegrityError as e:
        raise Conflict("Taki użytkownik już istnieje.") from e
    return {"ok": True}


@router.delete("/users/{uid}")
def delete_user(uid: int, user: dict = Depends(auth.require("admin"))):
    if uid == user["id"]:
        raise InvalidInput("Nie możesz usunąć samego siebie.")
    auth.delete_user(uid)
    return {"ok": True}
