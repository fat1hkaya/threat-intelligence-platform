"""Ortak test ayarları.

Testler CANLI veritabanına (ThreatLens) dokunmaz: ayrı bir test veritabanında çalışır.
    TL_DB_NAME_TEST   test veritabanının adı (varsayılan ThreatLens_Test)
    TL_DB_NAME_LIVE   korunan canlı veritabanı (varsayılan ThreatLens); oturum başında ve sonunda satır sayıları
                      karşılaştırılır (tests/test_zz_live_guard.py)
Test veritabanı oturum başında scripts/setup_db.py ile kurulur ya da güncellenir (beslemeler çekilmez, yalnızca
ATT&CK anlık görüntüsü yüklenir). SQL Server'a ulaşılamazsa veritabanı testleri atlanır (skip).
"""
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

LIVE_DB = os.getenv("TL_DB_NAME_LIVE", "ThreatLens")
TEST_DB = os.getenv("TL_DB_NAME_TEST", "ThreatLens_Test")
if TEST_DB.lower() == LIVE_DB.lower():
    raise SystemExit(f"TL_DB_NAME_TEST canlı veritabanıyla ({LIVE_DB}) aynı olamaz.")
# app.config ve importers bu değişkeni içe aktarıldıkları anda okur: her şeyden önce ayarlanmalı
os.environ["TL_DB_NAME"] = TEST_DB

PASSWORD = "ThreatLens2026!"
SETUP_ERROR = ""


def _setup_test_db() -> None:
    """Test veritabanını kurar ya da migration'ları uygular (tekrar çalıştırılabilir, ~10 sn)."""
    global SETUP_ERROR
    env = {**os.environ, "TL_DB_NAME": TEST_DB, "PYTHONUTF8": "1"}
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "setup_db.py"), "--no-feeds"], cwd=ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    if r.returncode != 0:
        SETUP_ERROR = (r.stdout + r.stderr).strip().splitlines()[-1:] or ["bilinmeyen hata"]
        SETUP_ERROR = SETUP_ERROR[0][:300]


def _db_ok() -> bool:
    try:
        from importers._db import connect
        conn = connect()
        ok = conn.cursor().execute("SELECT DB_NAME(), COUNT(*) FROM dbo.Technique;").fetchone()
        conn.close()
        return ok[0] == TEST_DB and ok[1] > 0
    except Exception:
        return False


def live_row_counts() -> dict[str, int] | None:
    """Canlı veritabanındaki tabloların satır sayıları (sys.partitions; tablo taramadan). Yoksa None."""
    try:
        from importers._db import connect
        c = connect("master")
        if c.cursor().execute("SELECT DB_ID(?);", LIVE_DB).fetchone()[0] is None:
            c.close()
            return None
        rows = c.cursor().execute(f"""
            SELECT s.name + '.' + t.name, SUM(p.rows)
            FROM [{LIVE_DB}].sys.tables AS t
            JOIN [{LIVE_DB}].sys.schemas AS s ON s.schema_id = t.schema_id
            JOIN [{LIVE_DB}].sys.partitions AS p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
            GROUP BY s.name, t.name;""").fetchall()
        c.close()
        return {name: int(n) for name, n in rows}
    except Exception:
        return None


LIVE_BEFORE = live_row_counts()
_setup_test_db()
DB_OK = _db_ok()
needs_db = pytest.mark.skipif(not DB_OK, reason=f"Test veritabanı ({TEST_DB}) kurulamadı: {SETUP_ERROR or 'SQL Server yok'}")


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_import_jobs():
    """Testlerin açtığı içe aktarma işleri (kasıtlı ROLLBACK senaryoları dahil) oturum sonunda silinir
    (test veritabanında; canlı veritabanına zaten yazılmaz)."""
    yield
    if not DB_OK:
        return
    from importers._db import connect
    c = connect()
    c.cursor().execute("DELETE FROM dbo.ImportJob WHERE FileName LIKE 'pytest-%' OR FileName = 'demo4.json';")
    c.close()


@pytest.fixture(scope="session")
def conn():
    if not DB_OK:
        pytest.skip("Veritabanı yok")
    from importers._db import connect
    c = connect()
    yield c
    c.close()


def _client(username: str):
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture(scope="session")
def admin():
    if not DB_OK:
        pytest.skip("Veritabanı yok")
    return _client("fatih")


@pytest.fixture(scope="session")
def analyst():
    if not DB_OK:
        pytest.skip("Veritabanı yok")
    return _client("analist")


@pytest.fixture(scope="session")
def viewer():
    if not DB_OK:
        pytest.skip("Veritabanı yok")
    return _client("izleyici")


@pytest.fixture
def unique() -> str:
    return uuid.uuid4().hex[:10]


@pytest.fixture(scope="session")
def linked_ioc(analyst):
    """Testlerin kendi verisi: rastgele bir SHA-256 IOC'si oluşturulur ve kanıtla 'Cobalt Strike'a bağlanır.
    ATT&CK'e göre bu aracı birçok aktör kullandığı için IOC -> zararlı -> aktör -> teknik zinciri oluşur.
    Oturum sonunda silinir (graf düğümü/kenarları tetikleyiciyle birlikte gider)."""
    value = uuid.uuid4().hex + uuid.uuid4().hex
    r = analyst.post("/api/iocs", json={"type": "sha256", "value": value, "sourceId": 7, "severity": "high", "confidence": 80,
                                        "description": "pytest test verisi"})
    assert r.status_code == 201, r.text
    iid = r.json()["IndicatorID"]
    mal = analyst.get("/api/malware", params={"q": "Cobalt Strike"}).json()["items"][0]
    link = analyst.post("/api/links", json={"kind": "malware-indicator", "a": mal["MalwareID"], "b": iid, "role": "payload",
                                            "confidence": 70, "evidence": "pytest: test için kurulan ilişki"})
    assert link.status_code == 201, link.text
    yield {"IndicatorID": iid, "Value": value, "MalwareID": mal["MalwareID"], "MalwareName": mal["Name"]}
    analyst.delete(f"/api/iocs/{iid}")
