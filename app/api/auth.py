import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .. import config
from ..db import Db, get_db
from ..security import COOKIE, current_user, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


class Login(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: Login, response: Response, db: Db = Depends(get_db)):
    user = db.one(
        """
        SELECT u.UserID, u.Username, u.FullName, u.PasswordHash, r.Code AS Role, r.Name AS RoleName
        FROM dbo.AppUser AS u
        JOIN dbo.Role AS r ON r.RoleID = u.RoleID
        WHERE u.Username = ? AND u.IsActive = 1;
        """, (body.username.strip(),), trace=False)
    if not user or not verify_password(body.password, user.pop("PasswordHash")):
        raise HTTPException(401, "Kullanıcı adı veya parola hatalı.")

    token = secrets.token_hex(32)
    with db.transaction():
        db.execute("DELETE FROM dbo.UserSession WHERE ExpiresAt < SYSUTCDATETIME();", trace=False)
        db.execute(
            "INSERT INTO dbo.UserSession (Token, UserID, ExpiresAt) VALUES (?, ?, DATEADD(HOUR, ?, SYSUTCDATETIME()));",
            (token, user["UserID"], config.SESSION_HOURS), trace=False)
        db.execute("UPDATE dbo.AppUser SET LastLoginAt = SYSUTCDATETIME() WHERE UserID = ?;", (user["UserID"],), trace=False)
    db.statements.clear()
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax", max_age=config.SESSION_HOURS * 3600)
    return user


@router.post("/logout")
def logout(request: Request, response: Response, db: Db = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if token:
        db.execute("DELETE FROM dbo.UserSession WHERE Token = ?;", (token,), trace=False)
    response.delete_cookie(COOKIE)
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user
