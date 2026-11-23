"""Veri kaynakları, içe aktarma işleri, denetim kayıtları, kullanıcılar ve sistem/şema durumu."""
import json
import logging
import os
import threading

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from .. import config
from ..db import Db, get_db
from ..security import current_user, hash_password, require_admin, require_analyst
from ..services.importer import parse_file, run_import

router = APIRouter(prefix="/api", tags=["admin"], dependencies=[Depends(current_user)])

MAX_UPLOAD = 5 * 1024 * 1024   # 5 MB


# ============================== Kaynaklar =============================

@router.get("/sources")
def sources(db: Db = Depends(get_db)):
    """Kaynak sağlığı (vw_SourceHealth) ve son 7 günün iş özeti."""
    items = db.query("""SELECT h.*, u.UnitLabel, u.UnitCount, u.UnitDetail
                        FROM dbo.vw_SourceHealth AS h JOIN dbo.vw_SourceUnit AS u ON u.SourceID = h.SourceID
                        ORDER BY h.IndicatorCount DESC, h.Name;""")
    totals = db.one(
        """
        SELECT COUNT(*) AS Sources,
               SUM(CASE WHEN IsActive = 1 THEN 1 ELSE 0 END) AS ActiveSources,
               (SELECT MAX(StartedAt) FROM dbo.ImportJob) AS LastJobAt,
               (SELECT COUNT(*) FROM dbo.ImportJob WHERE StartedAt >= DATEADD(DAY, -7, SYSUTCDATETIME()) AND Status = 'success') AS Success7d,
               (SELECT COUNT(*) FROM dbo.ImportJob WHERE StartedAt >= DATEADD(DAY, -7, SYSUTCDATETIME()) AND Status IN ('failed', 'partial')) AS Problem7d,
               (SELECT COUNT(*) FROM dbo.ImportJob WHERE StartedAt >= DATEADD(DAY, -7, SYSUTCDATETIME())) AS Jobs7d
        FROM dbo.Source;
        """)
    feeds = {"abuse.ch ThreatFox": "threatfox", "abuse.ch MalwareBazaar": "malwarebazaar", "abuse.ch URLhaus": "urlhaus",
             "abuse.ch Feodo Tracker": "feodo", "CISA KEV": "kev", "MITRE ATT&CK": "attack", "Malpedia": "malpedia", "iptoasn.com": "ip2asn"}
    needs_key = {"threatfox", "malwarebazaar", "urlhaus"}
    has_key = bool(os.getenv("ABUSECH_AUTH_KEY", "").strip())
    for s in items:
        s["Feed"] = feeds.get(s["Name"])
        s["NeedsKey"] = s["Feed"] in needs_key
        s["Ready"] = bool(s["Feed"]) and bool(s["IsActive"]) and (has_key or s["Feed"] not in needs_key)
    return {"sources": items, "totals": totals, "abusechKey": has_key}


class SourceUpdate(BaseModel):
    isActive: bool


@router.patch("/sources/{source_id}", dependencies=[Depends(require_admin)])
def update_source(source_id: int, body: SourceUpdate, db: Db = Depends(get_db)):
    """Kaynağı devre dışı bırakır ya da yeniden etkinleştirir. Kayıtlar silinmez; kapalı kaynak senkronize edilmez."""
    if not db.execute("UPDATE dbo.Source SET IsActive = ? WHERE SourceID = ?;", (int(body.isActive), source_id)):
        raise HTTPException(404, "Kaynak bulunamadı.")
    return {"ok": True}


# ============================== İçe aktarma ============================

@router.get("/imports")
def list_imports(source: int | None = None, status: str = "", page: int = Query(1, ge=1),
                 size: int = Query(15, ge=5, le=100), changed: bool = False, db: Db = Depends(get_db)):
    """changed=true: yalnızca değişiklik getiren (yeni/güncellenen/hatalı satırı olan) ya da başarısız/kısmi işler."""
    where, params = ["1 = 1"], []
    if changed:
        where.append("(j.RowsInserted + j.RowsUpdated + j.RowsFailed > 0 OR j.Status <> 'success')")
    if source:
        where.append("j.SourceID = ?"); params.append(source)
    if status:
        where.append("j.Status = ?"); params.append(status)
    clause = " AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.ImportJob AS j WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT j.JobID, j.SourceID, s.Name AS SourceName, j.JobType, j.FileName, j.IsStrict, j.StartedAt, j.FinishedAt,
               j.Status, j.RowsRead, j.RowsInserted, j.RowsUpdated, j.RowsSkipped, j.RowsFailed, j.ErrorMessage,
               u.FullName AS StartedBy, DATEDIFF(SECOND, j.StartedAt, j.FinishedAt) AS DurationSec
        FROM dbo.ImportJob AS j
        JOIN dbo.Source AS s ON s.SourceID = j.SourceID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = j.StartedBy
        WHERE {clause}
        ORDER BY j.StartedAt DESC, j.JobID DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + ((page - 1) * size, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/imports/{job_id}")
def get_import(job_id: int, db: Db = Depends(get_db)):
    job = db.one(
        """
        SELECT j.*, s.Name AS SourceName, u.FullName AS StartedByName
        FROM dbo.ImportJob AS j JOIN dbo.Source AS s ON s.SourceID = j.SourceID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = j.StartedBy
        WHERE j.JobID = ?;
        """, (job_id,))
    if not job:
        raise HTTPException(404, "İçe aktarma işi bulunamadı.")
    errors = db.query("SELECT TOP (500) RowNo, RawValue, Reason FROM dbo.ImportJobError WHERE JobID = ? ORDER BY RowNo;", (job_id,))
    return {"job": job, "errors": errors}


@router.post("/imports", status_code=201)
def upload_import(file: UploadFile = File(...), sourceId: int | None = Form(None), strict: bool = Form(False),
                        user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """CSV/JSON dosyasından gösterge içe aktarma. Katı modda (strict) tek hatalı satır tüm dosyayı geri alır."""
    name = file.filename or "upload"
    if not name.lower().endswith((".csv", ".json", ".txt")):
        raise HTTPException(400, "Yalnızca .csv, .json veya .txt dosyası yüklenebilir.")
    content = file.file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD:
        raise HTTPException(400, "Dosya 5 MB sınırını aşıyor.")
    try:
        items = parse_file(name, content)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"Dosya okunamadı: {exc}") from exc
    if not items:
        raise HTTPException(400, "Dosyada satır bulunamadı.")
    source_id = sourceId or db.scalar("SELECT SourceID FROM dbo.Source WHERE Name = N'Analist girişi';")
    result = run_import(db.conn, source_id, items, job_type="file", file_name=name[:200], strict=strict,
                        user_id=user["UserID"])
    db.statements.append({"sql": "EXEC dbo.sp_StartImportJob ...; EXEC dbo.sp_BulkImportIndicators @Strict = ?; EXEC dbo.sp_FinishImportJob ...;",
                          "params": [int(strict)], "ms": 0, "rows": result.read})
    return result.as_dict()


class FeedRun(BaseModel):
    feed: str


log = logging.getLogger("threatlens.feeds")
_RUNNING: set[str] = set()
_RUNNING_LOCK = threading.Lock()
ADMIN_FEEDS = {"attack": "ATT&CK yeniden yüklemesi", "ip2asn": "IP aralığı verisini yüklemek"}


def _execute_feed(feed: str, user: dict, db: Db) -> dict:
    from importers import abusech, cisa_kev, ip2asn, malpedia, mitre_attack

    if feed == "attack":
        res = mitre_attack.run(db.conn)
        db.conn.cursor().execute("EXEC dbo.sp_RefreshActorSimilarity;")
        return res
    if feed == "kev":
        return cisa_kev.run(db.conn)
    if feed == "malpedia":
        return malpedia.run(db.conn)
    if feed == "ip2asn":                                        # ~500 bin aralığın tamamı değiştirilir
        return ip2asn.run(db.conn)
    source, items = abusech.FEEDS[feed]()
    source_id = db.scalar("SELECT SourceID FROM dbo.Source WHERE Name = ?;", (source,))
    result = run_import(db.conn, source_id, items, job_type="feed", user_id=user["UserID"])
    db.conn.cursor().execute("EXEC dbo.sp_RefreshActorSimilarity;")
    return result.as_dict()


def _feed_worker(feed: str, user: dict) -> None:
    """Arka plan iş parçacığı: kendi bağlantısı, kullanıcının rolü ve kimliğiyle (denetim kaydı doğru kişiye yazılır)."""
    db = Db()
    try:
        db.activate_role(user["Role"])
        db.set_user(user["UserID"])
        res = _execute_feed(feed, user, db)
        log.info("besleme %s bitti (%s): %s", feed, user["Username"], {k: v for k, v in res.items() if k != "errors"})
    except Exception as exc:  # noqa: BLE001 - besleme hatası iş parçacığını düşürmemeli
        log.exception("besleme %s başarısız: %s", feed, exc)
    finally:
        db.close()
        with _RUNNING_LOCK:
            _RUNNING.discard(feed)


@router.post("/imports/feed", status_code=202)
def run_feed(body: FeedRun, user: dict = Depends(require_analyst)):
    """Bir beslemeyi arka planda senkronize eder; istek hemen döner (202). Durum: GET /api/imports/feed/status
    ve içe aktarma işleri listesi. Aynı besleme aynı anda iki kez çalıştırılamaz (409)."""
    from importers import abusech

    known = {"attack", "kev", "malpedia", "ip2asn", *abusech.FEEDS}
    if body.feed not in known:
        raise HTTPException(400, "Bilinmeyen besleme.")
    if body.feed in ADMIN_FEEDS and user["Role"] != "admin":
        raise HTTPException(403, f"{ADMIN_FEEDS[body.feed]} için yönetici yetkisi gerekir.")
    if body.feed in ("threatfox", "malwarebazaar", "urlhaus") and not os.getenv("ABUSECH_AUTH_KEY", "").strip():
        raise HTTPException(400, "Bu besleme için .env dosyasında ABUSECH_AUTH_KEY gerekir.")
    with _RUNNING_LOCK:
        if body.feed in _RUNNING:
            raise HTTPException(409, "Bu besleme zaten çalışıyor.")
        _RUNNING.add(body.feed)
    threading.Thread(target=_feed_worker, args=(body.feed, dict(user)), name=f"feed-{body.feed}", daemon=True).start()
    return {"started": True, "feed": body.feed}


@router.get("/imports/feed/status")
def feed_status():
    with _RUNNING_LOCK:
        return {"running": sorted(_RUNNING)}


# ============================== Denetim ================================

# Otomasyon (test) kayıtları: testler ayrı veritabanına taşınmadan önce canlı denetim kaydına yazılmış satırlar.
# AuditLog silinemez (trg_AuditLog_Protect); bu kayıtlar varsayılan olarak yalnızca GÖRÜNÜMDEN çıkarılır.
# Desenler test verisinin içeriğine göredir (l = AuditLog, u = AppUser).
#   1) test verisi desenleri; RFC 5737 belgeleme IP blokları (192.0.2/24, 198.51.100/24, 203.0.113/24) yalnızca
#      testlerde kullanılır, gerçek trafikte yönlendirilmez
#   2) kısa ömürlü kayıt: 5 dakika içinde eklenip silinen kayıt (testler kaydı oluşturup hemen siler)
_AUTOMATION_PATTERNS = ("pytest", '.example"', '.test"', "CVE-2099-", "namekey-", "Parola Testi", "UI kontrol vakas",
                        '"192.0.2.', '"198.51.100.', '"203.0.113.', "demo4")
AUTOMATION_AUDIT = "(" + " OR ".join(
    # ISNULL: ekleme kaydında OldValues NULL'dır; NULL LIKE ... UNKNOWN döner ve NOT (...) satırı yanlışlıkla eler
    f"ISNULL(l.NewValues, N'') LIKE N'%{p}%' OR ISNULL(l.OldValues, N'') LIKE N'%{p}%'" for p in _AUTOMATION_PATTERNS) \
    + " OR ISNULL(u.Username, N'') LIKE N'pyt%'" \
    + """ OR EXISTS (SELECT 1 FROM dbo.AuditLog AS ai JOIN dbo.AuditLog AS ad
                      ON ad.TableName = ai.TableName AND ad.RecordID = ai.RecordID AND ad.Action = 'D'
                     WHERE ai.TableName = l.TableName AND ai.RecordID = l.RecordID AND ai.Action = 'I'
                       AND ad.ChangedAt >= ai.ChangedAt AND ad.ChangedAt < DATEADD(MINUTE, 5, ai.ChangedAt)))"""


@router.get("/audit-logs")
def audit_logs(table: str = "", action: str = "", user: int | None = None, record: int | None = None,
               dateFrom: str | None = None, dateTo: str | None = None, hideAutomation: bool = True,
               page: int = Query(1, ge=1), size: int = Query(25, ge=5, le=200), db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if hideAutomation:
        where.append(f"NOT {AUTOMATION_AUDIT}")
    if table:
        where.append("l.TableName = ?"); params.append(table)
    if action in ("I", "U", "D"):
        where.append("l.Action = ?"); params.append(action)
    if user:
        where.append("l.ChangedBy = ?"); params.append(user)
    if record:
        where.append("l.RecordID = ?"); params.append(record)
    if dateFrom:
        where.append("l.ChangedAt >= ?"); params.append(dateFrom)
    if dateTo:
        where.append("l.ChangedAt < DATEADD(DAY, 1, CAST(? AS DATE))"); params.append(dateTo)
    clause = " AND ".join(where)
    total = db.scalar(f"""SELECT COUNT(*) AS Total FROM dbo.AuditLog AS l LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
                          WHERE {clause};""", tuple(params))
    items = db.query(
        f"""
        SELECT l.AuditID, l.TableName, l.RecordID, l.Action, l.ChangedAt, l.OldValues, l.NewValues,
               l.ChangedBy AS UserID, u.Username, u.FullName AS ChangedBy, r.Name AS RoleName
        FROM dbo.AuditLog AS l
        LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
        LEFT JOIN dbo.Role AS r ON r.RoleID = u.RoleID
        WHERE {clause}
        ORDER BY l.ChangedAt DESC, l.AuditID DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + ((page - 1) * size, size))
    for item in items:
        item["OldValues"] = json.loads(item["OldValues"]) if item["OldValues"] else None
        item["NewValues"] = json.loads(item["NewValues"]) if item["NewValues"] else None
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/audit-logs/logins", dependencies=[Depends(require_admin)])
def login_attempts(hideAutomation: bool = True, db: Db = Depends(get_db)):
    """Giriş denemeleri (yalnızca yönetici; tabloya doğrudan erişim kapalı, sp_LoginAttempts üzerinden)."""
    items, totals = (db.query_sets("EXEC dbo.sp_LoginAttempts @Top = ?, @HideAutomation = ?;", (500, int(hideAutomation)))
                     + [[], [{}]])[:2]
    return {"items": items, "totals": totals[0] if totals else {}}


@router.get("/audit-logs/stats")
def audit_stats(hideAutomation: bool = True, days: int = Query(30, ge=7, le=90), db: Db = Depends(get_db)):
    vis = f"NOT {AUTOMATION_AUDIT}" if hideAutomation else "1 = 1"
    src = f"(SELECT l.* FROM dbo.AuditLog AS l LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy WHERE {vis})"
    totals = db.one(
        f"""
        SELECT COUNT(*) AS Total,
               SUM(CASE WHEN ChangedAt >= DATEADD(HOUR, -24, SYSUTCDATETIME()) THEN 1 ELSE 0 END) AS Last24h,
               SUM(CASE WHEN Action = 'I' THEN 1 ELSE 0 END) AS Inserts,
               SUM(CASE WHEN Action = 'U' THEN 1 ELSE 0 END) AS Updates,
               SUM(CASE WHEN Action = 'D' THEN 1 ELSE 0 END) AS Deletes,
               COUNT(DISTINCT ChangedBy) AS Users,
               (SELECT COUNT(*) FROM dbo.AuditLog AS l LEFT JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
                 WHERE {AUTOMATION_AUDIT}) AS AutomationRows
        FROM {src} AS a;
        """)
    daily = db.query(
        """
        -- Son N gün, işlem türüne göre (ekleme / güncelleme / silme); kaydı olmayan günler 0
        WITH days AS (
            SELECT CAST(DATEADD(DAY, 1 - ?, SYSUTCDATETIME()) AS DATE) AS [Day]
            UNION ALL SELECT DATEADD(DAY, 1, [Day]) FROM days WHERE [Day] < CAST(SYSUTCDATETIME() AS DATE)
        )
        SELECT d.[Day], COUNT(l.AuditID) AS Total,
               SUM(CASE WHEN l.Action = 'I' THEN 1 ELSE 0 END) AS Inserts,
               SUM(CASE WHEN l.Action = 'U' THEN 1 ELSE 0 END) AS Updates,
               SUM(CASE WHEN l.Action = 'D' THEN 1 ELSE 0 END) AS Deletes
        FROM days AS d
        LEFT JOIN """ + src + """ AS l ON l.ChangedAt >= d.[Day] AND l.ChangedAt < DATEADD(DAY, 1, d.[Day])
        GROUP BY d.[Day] ORDER BY d.[Day]
        OPTION (MAXRECURSION 100);
        """, (days,))
    by_table = db.query(f"SELECT TableName, COUNT(*) AS Total FROM {src} AS a GROUP BY TableName ORDER BY Total DESC;")
    users = db.query(
        """SELECT DISTINCT u.UserID, u.FullName FROM dbo.AuditLog AS l JOIN dbo.AppUser AS u ON u.UserID = l.ChangedBy
           ORDER BY u.FullName;""")
    return {"totals": totals, "daily": daily, "byTable": by_table, "users": users}


# ============================== Kullanıcılar ===========================

@router.get("/users", dependencies=[Depends(require_admin)])
def users(db: Db = Depends(get_db)):
    return db.query(
        """
        SELECT u.UserID, u.Username, u.FullName, u.Email, r.Code AS Role, r.Name AS RoleName, u.IsActive, u.CreatedAt, u.LastLoginAt,
               (SELECT COUNT(*) FROM dbo.AuditLog AS l WHERE l.ChangedBy = u.UserID) AS AuditCount
        FROM dbo.AppUser AS u JOIN dbo.Role AS r ON r.RoleID = u.RoleID
        ORDER BY u.RoleID DESC, u.Username;
        """)


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9._-]+$")
    fullName: str = Field(min_length=2, max_length=100)
    email: str | None = Field(None, max_length=150)
    role: str
    password: str = Field(min_length=8, max_length=100)


@router.post("/users", status_code=201, dependencies=[Depends(require_admin)])
def create_user(body: UserIn, db: Db = Depends(get_db)):
    role_id = db.scalar("SELECT RoleID FROM dbo.Role WHERE Code = ?;", (body.role,))
    if not role_id:
        raise HTTPException(400, "Geçersiz rol.")
    user_id = db.insert_id(
        "INSERT INTO dbo.AppUser (Username, FullName, Email, PasswordHash, RoleID) OUTPUT inserted.UserID VALUES (?, ?, ?, ?, ?);",
        (body.username.strip(), body.fullName.strip(), body.email or None, hash_password(body.password), role_id))
    db.statements[-1]["params"][3] = "<parola özeti>"
    return {"UserID": user_id}


class UserUpdate(BaseModel):
    role: str | None = None
    isActive: bool | None = None
    fullName: str | None = Field(None, min_length=2, max_length=100)
    password: str | None = Field(None, min_length=10, max_length=200, description="Yönetici parola sıfırlaması")


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, me: dict = Depends(require_admin), db: Db = Depends(get_db)):
    if user_id == me["UserID"] and (body.isActive is False or (body.role and body.role != "admin")):
        raise HTTPException(400, "Kendi hesabınızı devre dışı bırakamaz veya yönetici rolünü kaldıramazsınız.")
    with db.transaction():
        if body.role:
            role_id = db.scalar("SELECT RoleID FROM dbo.Role WHERE Code = ?;", (body.role,))
            if not role_id:
                raise HTTPException(400, "Geçersiz rol.")
            db.execute("UPDATE dbo.AppUser SET RoleID = ? WHERE UserID = ?;", (role_id, user_id))
        if body.fullName:
            db.execute("UPDATE dbo.AppUser SET FullName = ? WHERE UserID = ?;", (body.fullName.strip(), user_id))
        if body.isActive is not None:
            db.execute("UPDATE dbo.AppUser SET IsActive = ? WHERE UserID = ?;", (int(body.isActive), user_id))
            if not body.isActive:
                db.execute("EXEC dbo.sp_EndUserSessions @UserID = ?;", (user_id,))
        if body.password:
            # tip_admin AppUser'a UPDATE yetkisine sahiptir; özet okunmaz, yalnızca yazılır
            db.execute("UPDATE dbo.AppUser SET PasswordHash = ? WHERE UserID = ?;", (hash_password(body.password), user_id))
            db.statements[-1]["params"][0] = "<parola özeti>"
            db.execute("EXEC dbo.sp_EndUserSessions @UserID = ?;", (user_id,))
    return {"ok": True}


# ============================== Sistem ==================================

@router.get("/system")
def system_status(db: Db = Depends(get_db)):
    """Ayarlar ekranı: sunucu sürümü, veritabanı nesne sayıları, graf tutarlılığı, entegrasyon durumu."""
    server = db.one(
        """
        SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(30)) AS Version,
               CAST(SERVERPROPERTY('Edition') AS NVARCHAR(100)) AS Edition,
               DB_NAME() AS DatabaseName, CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS NVARCHAR(100)) AS Collation,
               CAST(DATABASEPROPERTYEX(DB_NAME(), 'Recovery') AS NVARCHAR(20)) AS RecoveryModel,
               (SELECT CAST(SUM(size) * 8 / 1024.0 AS DECIMAL(10,1)) FROM sys.database_files) AS SizeMB;
        """)
    objects = db.query(
        """
        SELECT CASE WHEN o.type = 'U' AND t.is_node = 1 THEN 'GRAPH_NODE'
                    WHEN o.type = 'U' AND t.is_edge = 1 THEN 'GRAPH_EDGE'
                    ELSE o.type_desc END AS Kind, COUNT(*) AS Total
        FROM sys.objects AS o
        LEFT JOIN sys.tables AS t ON t.object_id = o.object_id
        WHERE o.is_ms_shipped = 0 AND o.type IN ('U', 'V', 'P', 'FN', 'IF', 'TF', 'TR', 'PK', 'F', 'C', 'UQ', 'D', 'EC')
        GROUP BY CASE WHEN o.type = 'U' AND t.is_node = 1 THEN 'GRAPH_NODE'
                      WHEN o.type = 'U' AND t.is_edge = 1 THEN 'GRAPH_EDGE'
                      ELSE o.type_desc END
        ORDER BY Total DESC;
        """)
    indexes = db.scalar("SELECT COUNT(*) AS N FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id WHERE i.type > 0 AND t.is_ms_shipped = 0;")
    roles = db.query(
        """SELECT p.name AS RoleName, (SELECT COUNT(*) FROM sys.database_permissions AS dp WHERE dp.grantee_principal_id = p.principal_id AND dp.state = 'G') AS Grants,
                  (SELECT COUNT(*) FROM sys.database_permissions AS dp WHERE dp.grantee_principal_id = p.principal_id AND dp.state = 'D') AS Denies
           FROM sys.database_principals AS p WHERE p.type = 'R' AND p.name LIKE 'tip[_]%' ORDER BY p.name;""")
    graph = db.query("EXEC dbo.sp_CheckGraphConsistency;")
    return {"server": server, "objects": objects, "indexCount": indexes, "dbRoles": roles, "graph": graph,
            "integrations": {"abusechKey": bool(os.getenv("ABUSECH_AUTH_KEY", "").strip()),
                             "odbcDriver": config.pick_driver(), "dbServer": config.DB_SERVER}}


# SSMS, Query Store ve sistem kataloğu sorguları ThreatLens'in kendi sorguları değildir: listeden çıkarılır
_FOREIGN_QUERY = ("sys.", "sm.is_inlineable", "INFORMATION_SCHEMA", "SERVERPROPERTY", "@@", "msdb.", "master.", "tempdb.",
                  "query_store", "dm_exec", "DBCC", "SET SHOWPLAN", "fn_listextendedproperty")


@router.get("/system/queries", dependencies=[Depends(require_admin)])
def top_queries(db: Db = Depends(get_db)):
    """Query Store: ortalama süreye göre en pahalı sorgular (sp_TopQueries; VIEW DATABASE STATE).
    Yalnızca uygulamanın kendi tablolarına (dbo.) dokunan sorgular; araç ve sistem sorguları süzülür."""
    rows = db.query("EXEC dbo.sp_TopQueries @Top = ?;", (60,))
    own = [r for r in rows if "dbo." in (r.get("QueryText") or "")
           and not any(p.lower() in (r.get("QueryText") or "").lower() for p in _FOREIGN_QUERY)]
    return own[:10]


# ============================== Entegrasyonlar ==========================

FEED_OF = {"abuse.ch ThreatFox": "threatfox", "abuse.ch MalwareBazaar": "malwarebazaar", "abuse.ch URLhaus": "urlhaus",
           "abuse.ch Feodo Tracker": "feodo", "CISA KEV": "kev", "MITRE ATT&CK": "attack", "Malpedia": "malpedia", "iptoasn.com": "ip2asn"}
TEST_URL = {"threatfox": "https://threatfox-api.abuse.ch/api/v1/", "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
            "urlhaus": "https://urlhaus-api.abuse.ch/v1/", "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/api/get/families", "ip2asn": "https://iptoasn.com/data/ip2asn-v4.tsv.gz"}
KEY_FEEDS = {"threatfox", "malwarebazaar", "urlhaus"}


@router.get("/integrations")
def integrations(db: Db = Depends(get_db)):
    """Tüm kaynaklar: durum, anahtar gerekli mi / tanımlı mı, son başarılı senkron."""
    has_key = bool(os.getenv("ABUSECH_AUTH_KEY", "").strip())
    rows = db.query(
        """
        SELECT s.SourceID, s.Name, s.Url, s.IsActive,
               (SELECT MAX(j.FinishedAt) FROM dbo.ImportJob AS j WHERE j.SourceID = s.SourceID AND j.Status = 'success') AS LastSuccessAt,
               (SELECT TOP (1) j.Status FROM dbo.ImportJob AS j WHERE j.SourceID = s.SourceID ORDER BY j.StartedAt DESC) AS LastStatus
        FROM dbo.Source AS s ORDER BY s.Name;
        """)
    for r in rows:
        feed = FEED_OF.get(r["Name"])
        r["Feed"], r["NeedsKey"] = feed, feed in KEY_FEEDS
        r["KeyDefined"] = has_key if feed in KEY_FEEDS else None
        r["Testable"] = feed in TEST_URL or feed == "attack"
    return rows


@router.post("/integrations/{feed}/test", dependencies=[Depends(require_admin)])
def test_integration(feed: str):
    """Kaynağa erişimi dener (HEAD; veri indirilmez). ATT&CK yerel anlık görüntüden yüklenir: dosya denetlenir."""
    import time
    import urllib.error
    import urllib.request
    if feed == "attack":
        p = config.ROOT / "database" / "seed" / "attack_snapshot.json"
        return {"ok": p.exists(), "message": "Yerel ATT&CK anlık görüntüsü bulundu." if p.exists() else "attack_snapshot.json bulunamadı."}
    url = TEST_URL.get(feed)
    if not url:
        raise HTTPException(400, "Bu kaynak için bağlantı testi yok (elle ya da dosyayla beslenir).")
    t0 = time.monotonic()
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "ThreatLens/1.0 (baglanti testi)"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            code = r.status
    except urllib.error.HTTPError as e:      # sunucuya ulaşıldı; HEAD'e 4xx/405 yanıtı da erişim sayılır
        code = e.code
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "message": f"Bağlantı kurulamadı: {getattr(e, 'reason', e)}"}
    ms = round((time.monotonic() - t0) * 1000)
    note = " Bu kaynak ayrıca ABUSECH_AUTH_KEY ister." if feed in KEY_FEEDS and not os.getenv("ABUSECH_AUTH_KEY", "").strip() else ""
    return {"ok": code < 500, "status": code, "ms": ms,
            "message": (f"Sunucuya ulaşıldı (HTTP {code}, {ms} ms)." if code < 500 else f"Sunucu hata döndü (HTTP {code}).") + note}


# ============================== Yaşam döngüsü ===========================

@router.get("/retention")
def retention(db: Db = Depends(get_db)):
    """IOC geçerlilik süresi politikaları, son bakım işleri (SQL Server Agent) ve yaklaşan süre dolumları."""
    policies = db.query(
        """
        WITH applied AS (   -- her IOC için geçerli politika (en özel olan, fn_LifetimeDays), tek geçişte gruplanır
            SELECT lp.PolicyID, COUNT(*) AS AppliesTo
            FROM dbo.Indicator AS i CROSS APPLY dbo.fn_LifetimeDays(i.SourceID, i.TypeID) AS lp
            GROUP BY lp.PolicyID
        )
        SELECT p.PolicyID, p.SourceID, s.Name AS SourceName, p.TypeID, t.Code AS TypeCode, t.Name AS TypeName, p.LifetimeDays, p.Note,
               ISNULL(a.AppliesTo, 0) AS AppliesTo
        FROM dbo.RetentionPolicy AS p
        LEFT JOIN applied AS a ON a.PolicyID = p.PolicyID
        LEFT JOIN dbo.Source AS s ON s.SourceID = p.SourceID
        LEFT JOIN dbo.IndicatorType AS t ON t.TypeID = p.TypeID
        ORDER BY CASE WHEN p.SourceID IS NULL THEN 1 ELSE 0 END, s.Name, CASE WHEN p.TypeID IS NULL THEN 1 ELSE 0 END, p.TypeID;
        """)
    runs = db.query("SELECT TOP (10) RunID, Task, StartedAt, FinishedAt, RowsAffected, Status, Message FROM dbo.MaintenanceRun ORDER BY RunID DESC;")
    upcoming = db.query(
        """
        -- Önümüzdeki 7 gün içinde süresi dolacak aktif IOC'ler, güne göre
        SELECT CAST(ExpiresAt AS DATE) AS [Day], COUNT(*) AS Total
        FROM dbo.Indicator
        WHERE Status = 'active' AND ExpiresAt >= SYSUTCDATETIME() AND ExpiresAt < DATEADD(DAY, 7, SYSUTCDATETIME())
        GROUP BY CAST(ExpiresAt AS DATE) ORDER BY [Day];
        """)
    return {"policies": policies, "runs": runs, "upcoming": upcoming}


@router.get("/maintenance/runs")
def maintenance_runs(limit: int = Query(100, ge=10, le=500), db: Db = Depends(get_db)):
    """Zamanlanmış bakım işlerinin (SQL Server Agent / Görev Zamanlayıcı) son çalışmaları; arayüz iş türüne göre gruplar."""
    return db.query("""SELECT TOP (?) RunID, Task, StartedAt, FinishedAt, RowsAffected, Status, Message,
                              DATEDIFF(SECOND, StartedAt, FinishedAt) AS DurationSec
                       FROM dbo.MaintenanceRun ORDER BY RunID DESC;""", (limit,))


class PolicyUpdate(BaseModel):
    lifetimeDays: int = Field(ge=1, le=3650)


@router.put("/retention/{policy_id}", dependencies=[Depends(require_admin)])
def update_retention(policy_id: int, body: PolicyUpdate, db: Db = Depends(get_db)):
    """Süre değişikliği yeni içe aktarmalara ve yeniden görülen IOC'lere uygulanır; mevcut bitiş tarihleri korunur."""
    if not db.execute("UPDATE dbo.RetentionPolicy SET LifetimeDays = ? WHERE PolicyID = ?;", (body.lifetimeDays, policy_id)):
        raise HTTPException(404, "Politika bulunamadı.")
    return {"ok": True}
