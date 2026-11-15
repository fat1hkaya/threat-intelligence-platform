"""Ayarlar. Değerler ortam değişkenlerinden veya proje kökündeki .env dosyasından okunur."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # proje kökü (app/ klasörünün bir üstü)
APP_DIR = ROOT / "app"
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"


def _load_env() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


_load_env()

DB_SERVER = os.getenv("TL_DB_SERVER", "localhost")
DB_NAME = os.getenv("TL_DB_NAME", "ThreatLens")
DB_USER = os.getenv("TL_DB_USER", "")          # boşsa Windows kimlik doğrulaması kullanılır
DB_PASSWORD = os.getenv("TL_DB_PASSWORD", "")
DB_DRIVER = os.getenv("TL_DB_DRIVER", "")      # boşsa kurulu en yeni ODBC sürücüsü seçilir
SESSION_HOURS = int(os.getenv("TL_SESSION_HOURS", "12"))
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")


def pick_driver() -> str:
    if DB_DRIVER:
        return DB_DRIVER
    import pyodbc

    installed = pyodbc.drivers()
    for name in ("ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server"):
        if name in installed:
            return name
    raise RuntimeError(
        "SQL Server ODBC sürücüsü bulunamadı. 'ODBC Driver 18 for SQL Server' kurun: "
        "https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server")


def connection_string(database: str | None = None) -> str:
    parts = [f"DRIVER={{{pick_driver()}}}", f"SERVER={DB_SERVER}", f"DATABASE={database or DB_NAME}",
             "Encrypt=no", "TrustServerCertificate=yes", "APP=ThreatLens"]
    if DB_USER:
        parts += [f"UID={DB_USER}", f"PWD={DB_PASSWORD}"]
    else:
        parts.append("Trusted_Connection=yes")
    return ";".join(parts)
