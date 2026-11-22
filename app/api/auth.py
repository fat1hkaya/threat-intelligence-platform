"""Giriş, çıkış, oturum ve parola değiştirme.

Kimlik doğrulama adımları (parola özetini okuma, oturum yazma, deneme kaydı) uygulama rolü etkinleştirilmeden,
kimlik doğrulama hizmetinin bağlantısıyla yapılır: parola özeti sütunu tüm uygulama rollerine kapalıdır (DENY).
Kimlik doğrulandıktan sonraki tüm istekler kullanıcının rolüyle (sp_setapprole) çalışır.
"""
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .. import config
from ..db import Db, get_db
from ..security import COOKIE, current_user, hash_password, token_hash, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILURES, WINDOW_MINUTES = 5, 15     # 15 dakikada 5 hatalı deneme -> geçici kilit


class Login(BaseModel):
    username: str = Field(max_length=50)
    password: str = Field(max_length=200)


def _attempt(db: Db, username: str, user_id: int | None, ok: bool, ip: str | None, reason: str | None) -> None:
    db.execute("INSERT INTO dbo.LoginAttempt (Username, UserID, Success, ClientIP, Reason) VALUES (?, ?, ?, ?, ?);",
               (username[:50], user_id, int(ok), (ip or "")[:45] or None, reason), trace=False)


@router.post("/login")
def login(body: Login, request: Request, response: Response, db: Db = Depends(get_db)):
    username, ip = body.username.strip(), request.client.host if request.client else None
    lock = db.one("SELECT RecentFailures, LockedUntil FROM dbo.fn_LoginLock(?, ?, ?);", (username, MAX_FAILURES, WINDOW_MINUTES), trace=False)
    if lock and lock["LockedUntil"]:
        _attempt(db, username, None, False, ip, "locked")
        raise HTTPException(429, f"Çok fazla hatalı deneme. Bu hesap {WINDOW_MINUTES} dakika boyunca geçici olarak kilitlendi; daha sonra tekrar deneyin.")
    user = db.one(
        """
        SELECT u.UserID, u.Username, u.FullName, u.PasswordHash, u.IsActive, r.Code AS Role, r.Name AS RoleName
        FROM dbo.AppUser AS u
        JOIN dbo.Role AS r ON r.RoleID = u.RoleID
        WHERE u.Username = ?;
        """, (username,), trace=False)
    if not user:
        verify_password(body.password, hash_password("zamanlama-esitleme"))   # var olmayan kullanıcıda da aynı süre
        _attempt(db, username, None, False, ip, "unknown_user")
        raise HTTPException(401, "Kullanıcı adı veya parola hatalı.")
    if not verify_password(body.password, user.pop("PasswordHash")):
        _attempt(db, username, user["UserID"], False, ip, "bad_password")
        left = MAX_FAILURES - (lock["RecentFailures"] if lock else 0) - 1
        raise HTTPException(401, "Kullanıcı adı veya parola hatalı." + (f" Kalan deneme hakkı: {left}." if 0 < left <= 2 else ""))
    if not user.pop("IsActive"):
        _attempt(db, username, user["UserID"], False, ip, "inactive")
        raise HTTPException(401, "Bu hesap devre dışı bırakılmış.")

    token = secrets.token_hex(32)
    with db.transaction():
        db.execute("DELETE FROM dbo.UserSession WHERE ExpiresAt < SYSUTCDATETIME();", trace=False)
        db.execute("INSERT INTO dbo.UserSession (Token, UserID, ExpiresAt) VALUES (?, ?, DATEADD(HOUR, ?, SYSUTCDATETIME()));",
                   (token_hash(token), user["UserID"], config.SESSION_HOURS), trace=False)     # veritabanında yalnızca özet
        db.execute("UPDATE dbo.AppUser SET LastLoginAt = SYSUTCDATETIME() WHERE UserID = ?;", (user["UserID"],), trace=False)
        _attempt(db, username, user["UserID"], True, ip, None)
    db.statements.clear()
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax", secure=config.COOKIE_SECURE,
                        max_age=config.SESSION_HOURS * 3600)
    return user


@router.post("/logout")
def logout(request: Request, response: Response, db: Db = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if token:
        db.execute("DELETE FROM dbo.UserSession WHERE Token = ?;", (token_hash(token),), trace=False)
    response.delete_cookie(COOKIE)
    return {"ok": True}


@router.get("/me")
def me(user: dict = Depends(current_user)):
    return user


class PasswordChange(BaseModel):
    current: str = Field(max_length=200)
    new: str = Field(min_length=10, max_length=200)


@router.post("/password")
def change_password(body: PasswordChange, request: Request, user: dict = Depends(current_user)):
    """Kendi parolasını değiştirme. Mevcut parola doğrulanır; diğer cihazlardaki oturumlar kapatılır."""
    if body.new == body.current:
        raise HTTPException(400, "Yeni parola eskisiyle aynı olamaz.")
    if body.new.lower() in (user["Username"].lower(), "threatlens2026!") or body.new.isalpha() or body.new.isdigit():
        raise HTTPException(400, "Daha güçlü bir parola seçin: kullanıcı adınızdan farklı, harf ve rakam/sembol içeren en az 10 karakter.")
    auth = Db()             # kimlik doğrulama bağlantısı (rolsüz): parola özeti uygulama rollerine kapalı
    try:
        stored = auth.scalar("SELECT PasswordHash FROM dbo.AppUser WHERE UserID = ?;", (user["UserID"],), trace=False)
        if not stored or not verify_password(body.current, stored):
            raise HTTPException(400, "Mevcut parola hatalı.")
        current = token_hash(request.cookies.get(COOKIE, ""))
        with auth.transaction():
            auth.execute("UPDATE dbo.AppUser SET PasswordHash = ? WHERE UserID = ?;", (hash_password(body.new), user["UserID"]), trace=False)
            ended = auth.execute("DELETE FROM dbo.UserSession WHERE UserID = ? AND Token <> ?;", (user["UserID"], current), trace=False)
    finally:
        auth.close()
    return {"ok": True, "endedSessions": ended}
