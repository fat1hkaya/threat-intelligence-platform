"""İçe aktarıcıların ortak yardımcıları: bağlantı, kaynak kimliği, GO ile ayrılmış .sql çalıştırma."""
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


def run_sql_file(conn: pyodbc.Connection, path: Path) -> int:
    """SSMS'teki gibi: dosyayı GO satırlarından yığınlara böler ve sırayla çalıştırır."""
    batches = [b.strip() for b in GO.split(path.read_text(encoding="utf-8")) if b.strip()]
    cur = conn.cursor()
    for number, batch in enumerate(batches, start=1):
        try:
            cur.execute(batch)
            while cur.nextset():
                pass
        except pyodbc.Error as exc:
            first = next((l for l in batch.splitlines() if l.strip() and not l.strip().startswith(("--", "/*", "*"))), "")
            raise SystemExit(f"\n{path.relative_to(ROOT)} dosyasının {number}. yığını hata verdi:\n  {first.strip()[:140]}\n  {exc}") from exc
    return len(batches)
