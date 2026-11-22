"""Veritabanı erişim katmanı.

ORM yoktur: her sorgu elle yazılmış, parametreli T-SQL'dir. Bu sınıf yalnızca
bağlantıyı açar, satırları sözlüğe çevirir ve çalıştırılan sorguları kaydeder.
Kaydedilen sorgular arayüzdeki "SQL" çekmecesinde gösterilir.
"""
import queue
import re
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from decimal import Decimal

import logging

import pyodbc
from fastapi import HTTPException, Request, Response

from . import config

# ODBC sürücü havuzu kapalı: sürücünün bağlantı sıfırlaması (sp_reset_connection) Application Role ile uyumsuz.
pyodbc.pooling = False
log = logging.getLogger("threatlens.db")

# Uygulama rolü -> SQL Server Application Role. Her istekte kullanıcının rolü etkinleştirilir; bundan sonra
# bağlantı, Windows hesabının (sysadmin) değil, yalnızca bu rolün (tip_reader/analyst/admin) yetkileriyle çalışır.
APP_ROLES = {"viewer": "app_viewer", "analyst": "app_analyst", "admin": "app_admin"}

# Rol bazlı bağlantı havuzları. sp_setapprole parola doğrulaması pahalıdır (~150 ms, SQL Server 2025), bu yüzden
# rolü etkinleştirilmiş bağlantı kapatılmadan YALNIZCA aynı rolün havuzuna döner ve o rolün isteklerinde tekrar
# kullanılır. None anahtarı: rol etkinleştirilmemiş (giriş/oturum denetimi için) bağlantılar.
_POOLS: dict = {None: queue.LifoQueue(maxsize=6), **{r: queue.LifoQueue(maxsize=6) for r in APP_ROLES.values()}}


def _new_connection() -> pyodbc.Connection:
    conn = pyodbc.connect(config.connection_string(), autocommit=True)
    conn.set_attr(2, 1)        # SQL_ATTR_NOSCAN: ODBC escape ({…}) taraması kapalı, T-SQL olduğu gibi gider
    return conn


def _acquire(role: str | None) -> pyodbc.Connection | None:
    try:
        return _POOLS[role].get_nowait()
    except queue.Empty:
        return None


def _release(conn: pyodbc.Connection, role: str | None) -> None:
    """Bağlantıyı temizleyip kendi rolünün havuzuna koyar; temizlik başarısızsa kapatır."""
    try:
        if not conn.autocommit:
            conn.rollback()
            conn.autocommit = True
        conn.cursor().execute("EXEC sys.sp_set_session_context @key = N'user_id', @value = NULL; "
                              "EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;")
        _POOLS[role].put_nowait(conn)
    except (pyodbc.Error, queue.Full):
        try:
            conn.close()
        except pyodbc.Error:
            pass


class Db:
    def __init__(self) -> None:
        self.approle: str | None = None
        self.conn = _acquire(None) or _new_connection()
        self.statements: list[dict] = []

    def close(self) -> None:
        _release(self.conn, self.approle)

    # -- çalıştırma ---------------------------------------------------
    def _run(self, sql: str, params: tuple, trace: bool):
        started = time.perf_counter()
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params)
        except pyodbc.Error as exc:
            raise to_http_error(exc) from exc
        if trace:
            self.statements.append({
                "sql": _dedent(sql), "params": [_show(p) for p in params],
                "ms": round((time.perf_counter() - started) * 1000, 1), "rows": None,
            })
        return cur

    @staticmethod
    def _rows(cur) -> list[dict]:
        if cur.description is None:
            return []
        cols = [c[0] for c in cur.description]
        return [{c: (float(v) if isinstance(v, Decimal) else v) for c, v in zip(cols, row)} for row in cur.fetchall()]

    def query(self, sql: str, params: tuple = (), trace: bool = True) -> list[dict]:
        cur = self._run(sql, params, trace)
        rows = self._rows(cur)
        if trace:
            self.statements[-1]["rows"] = len(rows)
        return rows

    def one(self, sql: str, params: tuple = (), trace: bool = True) -> dict | None:
        rows = self.query(sql, params, trace)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: tuple = (), trace: bool = True):
        row = self.one(sql, params, trace)
        return next(iter(row.values())) if row else None

    def execute(self, sql: str, params: tuple = (), trace: bool = True) -> int:
        cur = self._run(sql, params, trace)
        count = cur.rowcount
        if trace:
            self.statements[-1]["rows"] = count
        return count

    def insert_id(self, sql: str, params: tuple = ()):
        """INSERT ... OUTPUT inserted.<kimlik> ifadesini çalıştırıp yeni kimliği döndürür.
        Tetikleyicisi olan tablolarda INTO'suz OUTPUT yasaktır (hata 334); bu yüzden çıktı bir tablo değişkenine yazılır."""
        wrapped = re.sub(r"OUTPUT\s+(inserted\.\w+)", r"OUTPUT \1 INTO @new", sql, count=1, flags=re.I)
        body = wrapped.strip().rstrip(";")
        return self.scalar("SET NOCOUNT ON; DECLARE @new TABLE (ID BIGINT);\n" + body + ";\nSELECT ID FROM @new;", params)

    def query_sets(self, sql: str, params: tuple = ()) -> list[list[dict]]:
        """Birden çok sonuç kümesi döndüren saklı yordamlar için."""
        cur = self._run(sql, params, True)
        sets = []
        while True:
            if cur.description is not None:
                sets.append(self._rows(cur))
            try:
                if not cur.nextset():
                    break
            except pyodbc.Error as exc:
                raise to_http_error(exc) from exc
        self.statements[-1]["rows"] = sum(len(s) for s in sets)
        return sets

    @contextmanager
    def transaction(self):
        self.conn.autocommit = False
        self.statements.append({"sql": "BEGIN TRANSACTION;", "params": [], "ms": 0, "rows": None})
        try:
            yield
            self.conn.commit()
            self.statements.append({"sql": "COMMIT TRANSACTION;", "params": [], "ms": 0, "rows": None})
        except Exception:
            self.conn.rollback()
            self.statements.append({"sql": "ROLLBACK TRANSACTION;", "params": [], "ms": 0, "rows": None})
            raise
        finally:
            self.conn.autocommit = True

    def activate_role(self, role_code: str) -> None:
        """Bağlantıyı kullanıcının rolüne indirger (sp_setapprole). Rol havuzunda hazır bağlantı varsa o kullanılır,
        yoksa yeni bağlantıda rol bir kez etkinleştirilir. Rol adı sabit listeden, parola uygulama sırrından gelir
        (sp_setapprole parametreli/sp_executesql içinde çağrılamaz)."""
        name = APP_ROLES[role_code]
        pooled = _acquire(name)
        _release(self.conn, None)                      # rolsüz bağlantı rolsüz havuza döner
        if pooled is not None:
            self.conn = pooled
            note = "-- havuzdan, rolü zaten etkin bağlantı"
        else:
            self.conn = _new_connection()
            pwd = config.approle_password(name).replace("'", "''")
            self.conn.cursor().execute(f"EXEC sys.sp_setapprole @rolename = N'{name}', @password = N'{pwd}';")
            note = "-- yeni bağlantı"
        self.approle = name
        self.statements.append({"sql": f"EXEC sys.sp_setapprole @rolename = N'{name}', @password = N'***';  {note}",
                                "params": [], "ms": 0, "rows": None})

    def set_user(self, user_id: int) -> None:
        """Tetikleyiciler 'değişikliği kim yaptı' bilgisini buradan okur."""
        self.execute("EXEC sys.sp_set_session_context @key = N'user_id', @value = ?;", (user_id,), trace=False)


# -- hata çevirisi ----------------------------------------------------
_MSG = re.compile(r"\[SQL Server\](.*?)\s*\((\d+)\)\s*\(SQL", re.S)


def to_http_error(exc: pyodbc.Error) -> HTTPException:
    text = " ".join(str(a) for a in exc.args)
    match = _MSG.search(text)
    message, code = (match.group(1).strip(), int(match.group(2))) if match else (text, 0)
    if 50000 <= code < 50100:                       # iş kuralı: THROW ile verilen mesaj
        return HTTPException(400, message)
    if code in (2601, 2627):
        return HTTPException(409, "Aynı değere sahip bir kayıt zaten var.")
    if code == 547:
        if "CHECK" in message:
            return HTTPException(400, "Girilen değer veritabanındaki bir iş kuralını (CHECK kısıtı) ihlal ediyor.")
        return HTTPException(409, "Bu kayıt başka kayıtlarla ilişkili olduğu için işlem yapılamadı (yabancı anahtar kısıtı).")
    if code in (8152, 2628):
        return HTTPException(400, "Girilen metin bu alan için çok uzun.")
    ref = uuid.uuid4().hex[:8]
    log.error("Veritabanı hatası [%s] kod=%s: %s", ref, code, message)
    return HTTPException(500, f"Beklenmeyen bir veritabanı hatası oluştu. Yöneticiye bu kodu iletin: {ref}")


def _dedent(sql: str) -> str:
    lines = sql.strip("\n").splitlines()
    pad = min((len(l) - len(l.lstrip()) for l in lines if l.strip()), default=0)
    return "\n".join(l[pad:].rstrip() for l in lines).strip()


def _show(value):
    if isinstance(value, str) and len(value) > 300:
        return value[:300] + f"… ({len(value)} karakter)"
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bayt>"
    return value if isinstance(value, (int, float, str, bool, type(None))) else str(value)


# -- sorgu izi --------------------------------------------------------
class TraceStore:
    """Son isteklerde çalışan SQL'leri bellekte tutar (kalıcı değildir)."""

    def __init__(self, capacity: int = 300) -> None:
        self.items: OrderedDict[str, dict] = OrderedDict()
        self.capacity = capacity

    def add(self, trace_id: str, method: str, path: str, statements: list[dict]) -> None:
        self.items[trace_id] = {"id": trace_id, "method": method, "path": path, "statements": statements,
                                "ms": round(sum(s["ms"] for s in statements), 1)}
        while len(self.items) > self.capacity:
            self.items.popitem(last=False)

    def get(self, trace_id: str) -> dict | None:
        return self.items.get(trace_id)


TRACES = TraceStore()


def get_db(request: Request, response: Response):
    """FastAPI bağımlılığı: istek başına bir bağlantı (ODBC havuzundan)."""
    try:
        db = Db()
    except pyodbc.Error as exc:
        raise HTTPException(503, "SQL Server'a bağlanılamadı. Sunucunun çalıştığını ve .env ayarlarını kontrol edin.") from exc
    trace_id = uuid.uuid4().hex[:12]
    response.headers["X-Trace-Id"] = trace_id
    try:
        yield db
    finally:
        if db.statements:
            TRACES.add(trace_id, request.method, request.url.path, db.statements)
        db.close()
