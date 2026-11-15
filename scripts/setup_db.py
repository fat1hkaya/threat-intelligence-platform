"""ThreatLens veritabanını kurar.

    python scripts/setup_db.py            # kur; veritabanı varsa tablolara dokunmaz, nesneleri (görünüm, yordam,
                                          # tetikleyici, yetki) günceller, eksik veriyi yükler
    python scripts/setup_db.py --reset    # VERİTABANINI SİLİP baştan kurar (yalnızca bilerek kullanın)
    python scripts/setup_db.py --no-feeds # internet beslemelerini çekme (yalnızca yerel ATT&CK verisi)

Sıra: database/<klasör>/NN_*.sql dosyaları numaraya göre (01 tablolar ... 09 sözlük verisi)
-> kullanıcılar -> MITRE ATT&CK anlık görüntüsü -> gerçek beslemeler (CISA KEV, Feodo Tracker; .env'de
ABUSECH_AUTH_KEY varsa ThreatFox, MalwareBazaar, URLhaus) -> graf tutarlılık denetimi.
Sentetik (demo) veri YÜKLENMEZ: veritabanındaki her IOC gerçek bir kaynaktan gelir.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pyodbc  # noqa: E402

from app import config  # noqa: E402
from app.security import hash_password  # noqa: E402
from importers._db import GO, ROOT, connect  # noqa: E402

DEMO_PASSWORD = "ThreatLens2026!"
USERS = [  # (kullanıcı adı, ad soyad, e-posta, rol)
    ("fatih", "Fatih Kaya", None, 3),
    ("analist", "SOC Analisti", None, 2),
    ("izleyici", "Salt Okunur Kullanıcı", None, 1),
]
# Var olan veritabanında yeniden çalıştırılmaması gereken yığınlar (tablo ve indeks oluşturma)
SCHEMA_BATCH = re.compile(r"^\s*CREATE\s+(TABLE|(UNIQUE\s+)?(NONCLUSTERED\s+|CLUSTERED\s+)?INDEX)\b", re.I)
COMMENTS = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)


def sql_files() -> list[Path]:
    files = [p for p in (ROOT / "database").glob("*/[0-9][0-9]_*.sql")]
    return sorted(files, key=lambda p: p.name)


def run_file(conn: pyodbc.Connection, path: Path, skip_schema: bool) -> tuple[int, int]:
    batches = [b.strip() for b in GO.split(path.read_text(encoding="utf-8")) if b.strip()]
    cur = conn.cursor()
    ran = skipped = 0
    for number, batch in enumerate(batches, start=1):
        if skip_schema and SCHEMA_BATCH.match(COMMENTS.sub("", batch)):
            skipped += 1
            continue
        try:
            cur.execute(batch)
            while cur.nextset():
                pass
        except pyodbc.Error as exc:
            first = next((l for l in batch.splitlines() if l.strip() and not l.strip().startswith(("--", "/*", "*"))), "")
            raise SystemExit(f"\n{path.relative_to(ROOT)} dosyasının {number}. yığını hata verdi:\n  {first.strip()[:140]}\n  {exc}") from exc
        ran += 1
    return ran, skipped


APP_ROLE_MEMBERSHIP = {"app_viewer": "tip_reader", "app_analyst": "tip_analyst", "app_admin": "tip_admin"}


def ensure_app_roles(conn) -> None:
    """SQL Server Application Role'leri. Parolalar depoda değil, .env'deki TL_APPROLE_SECRET'tan türetilir."""
    import secrets as _secrets

    if not config.APPROLE_SECRET:
        secret = _secrets.token_urlsafe(32)
        env = ROOT / ".env"
        text = env.read_text(encoding="utf-8") if env.exists() else ""
        line = f"# Application Role parolalarının türetildiği sır (setup_db.py üretti; paylaşmayın)\nTL_APPROLE_SECRET={secret}\n"
        env.write_text(text.rstrip("\n") + "\n" + line, encoding="utf-8")
        config.APPROLE_SECRET = secret
        print("  TL_APPROLE_SECRET üretildi ve .env dosyasına yazıldı.")
    cur = conn.cursor()
    for role, db_role in APP_ROLE_MEMBERSHIP.items():
        pwd = config.approle_password(role).replace("'", "''")
        verb = "ALTER" if cur.execute("SELECT DATABASE_PRINCIPAL_ID(?);", role).fetchone()[0] else "CREATE"
        cur.execute(f"{verb} APPLICATION ROLE {role} WITH PASSWORD = N'{pwd}'" + (", DEFAULT_SCHEMA = dbo;" if verb == "CREATE" else ";"))
        if not cur.execute("SELECT IS_ROLEMEMBER(?, ?);", db_role, role).fetchone()[0]:
            cur.execute(f"ALTER ROLE {db_role} ADD MEMBER {role};")
    print("  Application Role'ler hazır: app_viewer ⊂ tip_reader, app_analyst ⊂ tip_analyst, app_admin ⊂ tip_admin")


def load_feeds(conn) -> None:
    """Gerçek beslemeler. Biri başarısız olursa (internet yok, anahtar yok) kurulum durmaz, nedeni yazılır."""
    import os

    from app.services.importer import run_import
    from importers import abusech, cisa_kev
    from importers._db import source_id

    try:
        r = cisa_kev.run(conn)
        print(f"  CISA KEV: {r['status']}" + (f", {r.get('inserted', 0)} zafiyet eklendi" if r["status"] == "success" else f" ({r.get('message')})"))
    except Exception as exc:  # ağ hatası vb.
        print(f"  CISA KEV: atlandı - {exc}")
    from importers import malpedia
    names = ["feodo"] + (["threatfox", "malwarebazaar", "urlhaus"] if os.getenv("ABUSECH_AUTH_KEY", "").strip() else [])
    for name in names:
        try:
            source, items = abusech.FEEDS[name]()
            res = run_import(conn, source_id(conn, source), items, job_type="feed")
            print(f"  {source}: {res.status}, okunan {res.read}, eklenen {res.inserted}, güncellenen {res.updated}, hatalı {res.failed}")
        except abusech.FeedError as exc:
            print(f"  {name}: atlandı - {exc}")
    if len(names) == 1:
        print("  ThreatFox / MalwareBazaar / URLhaus atlandı: .env dosyasında ABUSECH_AUTH_KEY yok (https://auth.abuse.ch).")
    r = malpedia.run(conn)   # besleme ailelerini adlandırır ve aktörlere bağlar; abuse.ch'den SONRA çalışmalı
    print(f"  Malpedia: {r['status']}" + (f", {r['merged']} tekrar birleştirildi, {r['aliases']} takma ad, {r['actor_links']} aile-aktör ilişkisi"
                                          if r["status"] == "success" else f" ({r.get('message')})"))
    conn.cursor().execute("EXEC dbo.sp_RefreshActorSimilarity;")


def main() -> None:
    # Çıktı dosyaya/boruya yönlendirildiğinde Windows kod sayfası (cp1254) bazı simgeleri yazamaz
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    reset, feeds = "--reset" in sys.argv, "--no-feeds" not in sys.argv
    print(f"Sunucu: {config.DB_SERVER} | Veritabanı: {config.DB_NAME} | Sürücü: {config.pick_driver()}")
    try:
        master = connect("master")
    except pyodbc.Error as exc:
        raise SystemExit(
            f"SQL Server'a bağlanılamadı ({config.DB_SERVER}).\n"
            "  - SQL Server hizmetinin çalıştığını kontrol edin (services.msc -> SQL Server (MSSQLSERVER)).\n"
            "  - Express kullanıyorsanız .env dosyasına TL_DB_SERVER=localhost\\SQLEXPRESS yazın.\n"
            f"  Ayrıntı: {exc}") from exc

    version = master.cursor().execute("SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS INT), @@VERSION;").fetchone()
    print("SQL Server:", version[1].splitlines()[0])
    if version[0] < 15:
        raise SystemExit("SQL Server 2019 veya üzeri gerekir (kenar kısıtı ve SHORTEST_PATH).")

    exists = master.cursor().execute("SELECT DB_ID(?);", config.DB_NAME).fetchone()[0] is not None
    if exists and reset:
        print(f"{config.DB_NAME} siliniyor (--reset)...")
        master.cursor().execute(f"ALTER DATABASE [{config.DB_NAME}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;")
        master.cursor().execute(f"DROP DATABASE [{config.DB_NAME}];")
        exists = False
    has_tables = exists and master.cursor().execute(
        f"SELECT OBJECT_ID(N'[{config.DB_NAME}].dbo.Indicator');").fetchone()[0] is not None
    if has_tables:
        print("Tablolar zaten var: tablo/indeks yığınları atlanacak, diğer nesneler güncellenecek.")

    for path in sql_files():
        started = time.perf_counter()
        ran, skipped = run_file(master, path, has_tables)
        note = f" ({skipped} şema yığını atlandı)" if skipped else ""
        print(f"  {str(path.relative_to(ROOT / 'database')):<34} {ran:>3} yığın  {time.perf_counter() - started:5.1f} sn{note}")
    master.close()

    conn = connect()
    cur = conn.cursor()
    ensure_app_roles(conn)
    for username, full_name, email, role_id in USERS:
        if not cur.execute("SELECT 1 FROM dbo.AppUser WHERE Username = ?;", username).fetchone():
            cur.execute("INSERT INTO dbo.AppUser (Username, FullName, Email, PasswordHash, RoleID) VALUES (?, ?, ?, ?, ?);",
                        username, full_name, email, hash_password(DEMO_PASSWORD), role_id)
            print(f"  Kullanıcı eklendi: {username} ({full_name})")

    from importers import mitre_attack

    if not cur.execute("SELECT COUNT(*) FROM dbo.Technique;").fetchone()[0]:
        res = mitre_attack.run(conn)
        print(f"  MITRE ATT&CK: {res['tactics']} taktik, {res['techniques']} teknik, {res['actors']} aktör, "
              f"{res['malware']} yazılım, {res['campaigns']} kampanya, {res['evidence']} kanıt ({res['seconds']} sn)")
    else:
        print("  MITRE ATT&CK zaten yüklü (güncellemek için: python -m importers attack)")

    if feeds:
        load_feeds(conn)

    print("\nGraf tutarlılık denetimi (sp_CheckGraphConsistency):")
    bad = 0
    for row in cur.execute("EXEC dbo.sp_CheckGraphConsistency;").fetchall():
        bad += 0 if row.IsConsistent else 1
        print(f"  {row.ObjectName:<30} {row.Kind:<5} ilişkisel={row.Relational:<7} graf={row.Graph:<7} {'OK' if row.IsConsistent else 'TUTARSIZ'}")
    conn.close()
    if bad:
        raise SystemExit(f"{bad} graf nesnesi tutarsız. 'EXEC dbo.sp_SyncGraph;' ile onarın.")

    print("\nKurulum tamam. Başlatmak için:  python run.py   ->  http://127.0.0.1:8000")
    print(f"Kullanıcılar: fatih (yönetici) / analist / izleyici   Parola: {DEMO_PASSWORD}  (yalnızca yerel kullanım içindir)")


if __name__ == "__main__":
    main()
