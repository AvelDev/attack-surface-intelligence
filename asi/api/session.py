"""Logowanie, wylogowanie i bieżący użytkownik."""
from fastapi import APIRouter, Cookie, Depends, HTTPException
from fastapi import Response as FastAPIResponse
from pydantic import BaseModel

from .. import auth

router = APIRouter(tags=["session"])


class LoginReq(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginReq, response: FastAPIResponse):
    user = auth.authenticate(req.username, req.password)
    if not user:
        raise HTTPException(401, "Nieprawidłowy login lub hasło.")
    auth.set_session_cookie(response, auth.create_session(user["id"]))
    return {"username": user["username"], "role": user["role"]}


@router.post("/logout")
def logout(response: FastAPIResponse, asi_session: str | None = Cookie(default=None)):
    if asi_session:
        auth.destroy_session(asi_session)
    auth.clear_session_cookie(response)
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(auth.current_user_dep)):
    return {"username": user["username"], "role": user["role"]}
