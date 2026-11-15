"""Ortak test ayarları. Veritabanı testleri SQL Server'a ulaşılamazsa atlanır (skip), başarısız sayılmaz."""
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASSWORD = "ThreatLens2026!"


def _db_ok() -> bool:
    try:
        from importers._db import connect
        conn = connect()
        ok = conn.cursor().execute("SELECT COUNT(*) FROM dbo.Technique;").fetchone()[0] > 0
        conn.close()
        return ok
    except Exception:
        return False


DB_OK = _db_ok()
needs_db = pytest.mark.skipif(not DB_OK, reason="SQL Server/ThreatLens veritabanı yok (python scripts/setup_db.py)")


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
