"""İçe aktarıcıların ortak yardımcıları: bağlantı, kaynak kimliği, .sql dosyasını GO satırlarından yığınlara bölme."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pyodbc  # noqa: E402

# Havuzlama kapalı (app/db.py ile aynı): Application Role etkin bağlantı havuza dönmemeli. İlk bağlantıdan önce ayarlanmalı.
pyodbc.pooling = False

from app import config  # noqa: E402

GO = re.compile(r"^\s*GO\s*;?\s*$", re.I | re.M)

# ---- veritabanı adını yönlendirme --------------------------------------------
# database/ altındaki betikler canlı veritabanı adını (ThreatLens) içerir: USE ThreatLens, CREATE DATABASE ThreatLens,
# ThreatLens.dbo.X, yedekte MOVE N'ThreatLens'. Testler ayrı bir veritabanında (ThreatLens_Test) çalışırken aynı
# betikler bu adlara çevrilerek çalıştırılır. SQL Server Agent işleri (msdb) sunucu geneldir: test veritabanı kurulurken
# canlı işlerin üzerine yazılmasın diye msdb yığınları atlanır.
DEFAULT_DB = "ThreatLens"
_NAME = r"ThreatLens(?![A-Za-z0-9_])"
_RULES = [
    (re.compile(r"\bUSE\s+\[?" + _NAME + r"\]?", re.I), lambda db: f"USE [{db}]"),
    (re.compile(r"\bDATABASE\s+\[?" + _NAME + r"\]?", re.I), lambda db: f"DATABASE [{db}]"),
    (re.compile(r"DB_ID\(\s*N?'" + _NAME + r"'\s*\)", re.I), lambda db: f"DB_ID(N'{db}')"),
    (re.compile(r"\b" + _NAME + r"\.dbo\.", re.I), lambda db: f"[{db}].dbo."),
    (re.compile(r"MOVE\s+N'ThreatLens_log'", re.I), lambda db: f"MOVE N'{db}_log'"),
    (re.compile(r"MOVE\s+N'" + _NAME + r"'", re.I), lambda db: f"MOVE N'{db}'"),
]
USE_MSDB = re.compile(r"^\s*USE\s+\[?msdb\]?", re.I)
USE_ANY = re.compile(r"^\s*USE\s+", re.I)
_COMMENTS = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)


def retarget(sql: str, db: str | None = None) -> str:
    """Betikteki canlı veritabanı adını hedef veritabanı adına çevirir (hedef canlı ise metin değişmez)."""
    db = db or config.DB_NAME
    if db == DEFAULT_DB:
        return sql
    for rx, repl in _RULES:
        sql = rx.sub(lambda m, r=repl: r(db), sql)
    return sql


def batches_for(text: str, db: str | None = None) -> list[str]:
    """Dosyayı GO'dan böler ve yönlendirir. Hedef canlı veritabanı değilse msdb (Agent işleri) yığınları atlanır."""
    db = db or config.DB_NAME
    out, in_msdb = [], False
    for batch in (b.strip() for b in GO.split(text)):
        if not batch:
            continue
        if db != DEFAULT_DB:
            code = _COMMENTS.sub("", batch)               # yığın açıklamayla başlayabilir
            if USE_MSDB.match(code):
                in_msdb = True
                continue
            if in_msdb and USE_ANY.match(code):
                in_msdb = False
            if in_msdb:
                continue
        out.append(retarget(batch, db))
    return out


SQL_ATTR_NOSCAN, SQL_NOSCAN_ON = 2, 1


def connect(database: str | None = None) -> pyodbc.Connection:
    conn = pyodbc.connect(config.connection_string(database), autocommit=True)
    # ODBC sürücüsü {…} dizilerini "escape" sanmasın: SHORTEST_PATH(... {1,6}) gibi T-SQL sözdizimi bozulmadan gitsin
    conn.set_attr(SQL_ATTR_NOSCAN, SQL_NOSCAN_ON)
    return conn


def source_id(conn: pyodbc.Connection, name: str) -> int:
    row = conn.cursor().execute("SELECT SourceID FROM dbo.Source WHERE Name = ?;", name).fetchone()
    if not row:
        raise SystemExit(f"Kaynak bulunamadı: {name}. Önce 'python scripts/setup_db.py' çalıştırın.")
    return row[0]

