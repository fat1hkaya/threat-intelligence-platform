"""Parola özeti (PBKDF2-SHA256) ve oturum/rol denetimi."""
import hashlib
import hmac
import secrets

from fastapi import Depends, HTTPException, Request

from .db import Db, get_db

COOKIE = "tl_session"
_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS).hex()
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
        return hmac.compare_digest(check, digest)
    except (ValueError, TypeError):
        return False


def current_user(request: Request, db: Db = Depends(get_db)) -> dict:
    token = request.cookies.get(COOKIE)
    user = None
    if token:
        user = db.one(_USER_SQL, (token,), trace=False)
    if not user:
        raise HTTPException(401, "Oturum açmanız gerekiyor.")
    db.activate_role(user["Role"])          # bundan sonraki tüm sorgular rolün GRANT/DENY sınırları içinde
    db.set_user(user["UserID"])             # tetikleyiciler "kim değiştirdi" bilgisini bu bağlamdan okur
    return user


def require_analyst(user: dict = Depends(current_user)) -> dict:
    if user["Role"] not in ("analyst", "admin"):
        raise HTTPException(403, "Bu işlem için analist yetkisi gerekir.")
    return user


def require_admin(user: dict = Depends(current_user)) -> dict:
    if user["Role"] != "admin":
        raise HTTPException(403, "Bu işlem için yönetici yetkisi gerekir.")
    return user


_USER_SQL = """
    SELECT u.UserID, u.Username, u.FullName, r.Code AS Role, r.Name AS RoleName
    FROM dbo.UserSession AS s
    JOIN dbo.AppUser AS u ON u.UserID = s.UserID
    JOIN dbo.Role AS r ON r.RoleID = u.RoleID
    WHERE s.Token = ? AND s.ExpiresAt > SYSUTCDATETIME() AND u.IsActive = 1;
"""


def page_user(request: Request) -> dict | None:
    """HTML sayfaları için: oturum varsa kullanıcıyı döndürür, yoksa None (sayfa /login'e yönlendirir).
    Veritabanına ulaşılamazsa {'_db_error': ...} döner ki arayüz anlamlı bir hata gösterebilsin."""
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    try:
        db = Db()
    except Exception as exc:  # pyodbc.Error
        return {"_db_error": str(exc)}
    try:
        return db.one(_USER_SQL, (token,), trace=False)
    finally:
        db.close()
