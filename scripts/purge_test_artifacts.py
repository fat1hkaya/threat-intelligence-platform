"""Canlı veritabanından test artıklarını temizler.

    python scripts/purge_test_artifacts.py            # yalnızca rapor (varsayılan, --dry-run)
    python scripts/purge_test_artifacts.py --apply    # siler (tek işlem; hata olursa hiçbir şey silinmez)

Testler artık ayrı bir veritabanında çalışır (tests/conftest.py, ThreatLens_Test). Bu betik, o ayrımdan ÖNCE canlı
veritabanında kalmış kayıtlar içindir. Yalnızca test desenlerine uyan satırları hedefler; kapsam:
  kullanıcılar (pyt*, pytest*, "Parola Testi"), test istemcisinin giriş denemeleri (IP 'testclient', pytest-*),
  konumu 'pytest' olan log avları ve görülmeler, pytest adlı zararlı/aktör/kampanya/zafiyet (CVE-2099-*),
  pytest vakaları, test IOC'leri (yalnızca 'Analist girişi' kaynağında: *.test, *.example, namekey-*,
  "pytest test verisi"), hiçbir yerden başvurulmayan pytest kanıtları, kullanılmayan 'pytest' etiketi,
  test içe aktarma işleri, pytest kapsama kayıtları.
dbo.AuditLog'a DOKUNULMAZ: denetim izi değiştirilemez ve silinemez (bkz. docs/sunum_oncesi_kontrol.md).
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from importers._db import connect  # noqa: E402

ANALYST_SOURCE = "(SELECT SourceID FROM dbo.Source WHERE Name = N'Analist girişi')"

# (etiket, sayım/silme için FROM + WHERE). Sıra önemlidir: önce bağımlı kayıtlar.
TARGETS = [
    ("Test görülmeleri (konum pytest)", "dbo.Sighting WHERE Location LIKE N'pytest%'"),
    ("Log avları (konum pytest)", "dbo.HuntRun WHERE Location LIKE N'pytest%'"),
    ("Giriş denemeleri (test istemcisi)", "dbo.LoginAttempt WHERE ClientIP = 'testclient' OR Username LIKE N'pytest-%'"),
    ("Test vakaları", "dbo.Investigation WHERE Title LIKE N'pytest %' OR Title LIKE N'UI kontrol vakası%'"),
    ("Test IOC'leri (Analist girişi)", f"""dbo.Indicator WHERE SourceID = {ANALYST_SOURCE}
        AND (NormalizedValue LIKE N'%.test' OR NormalizedValue LIKE N'%.example' OR NormalizedValue LIKE N'namekey-%'
             OR Description = N'pytest test verisi')"""),
    ("Test kampanyaları", "dbo.Campaign WHERE Name LIKE N'Pytest Camp %'"),
    ("Test aktörleri", "dbo.ThreatActor WHERE Name LIKE N'Pytest Actor %'"),
    ("Test zararlıları", "dbo.Malware WHERE Name LIKE N'Pytest Mal %' OR Name LIKE N'PytestKeep%' OR Name LIKE N'pytest-%'"),
    ("Test zafiyetleri (CVE-2099)", "dbo.Vulnerability WHERE CveID LIKE 'CVE-2099-%'"),
    ("Test kapsama kayıtları", "dbo.DetectionCoverage WHERE DataSource = N'pytest'"),
    ("Test içe aktarma işleri", "dbo.ImportJob WHERE FileName LIKE 'pytest-%' OR FileName IN ('bad.csv', 'mix.csv', 'old.csv', 'k.csv', 'demo4.json')"),
    ("Test kullanıcıları", "dbo.AppUser WHERE Username LIKE N'pyt%' OR (Username LIKE N'pw%' AND FullName = N'Parola Testi')"),
    ("Kullanılmayan 'pytest' etiketi", "dbo.Tag WHERE Name = N'pytest' AND NOT EXISTS (SELECT 1 FROM dbo.IndicatorTag AS it WHERE it.TagID = Tag.TagID)"),
]


def evidence_target(cur) -> tuple[str, str]:
    """pytest kanıtları: yalnızca hiçbir tablodan (graf kenarları dahil) başvurulmayanlar."""
    tables = [r[0] for r in cur.execute("""
        SELECT QUOTENAME(s.name) + '.' + QUOTENAME(t.name) FROM sys.columns AS c
        JOIN sys.tables AS t ON t.object_id = c.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id
        WHERE c.name IN ('EvidenceID', 'AttributionEvidenceID') AND t.name <> 'Evidence' AND t.temporal_type <> 1;""").fetchall()]
    cols = {r[0]: r[1] for r in cur.execute("""
        SELECT QUOTENAME(s.name) + '.' + QUOTENAME(t.name), c.name FROM sys.columns AS c
        JOIN sys.tables AS t ON t.object_id = c.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id
        WHERE c.name IN ('EvidenceID', 'AttributionEvidenceID') AND t.name <> 'Evidence' AND t.temporal_type <> 1;""").fetchall()}
    refs = " AND ".join(f"NOT EXISTS (SELECT 1 FROM {t} AS x WHERE x.{cols[t]} = Evidence.EvidenceID)" for t in tables)
    return ("Başvurulmayan pytest kanıtları", f"dbo.Evidence WHERE Summary LIKE N'%pytest%' AND {refs}")


def count(cur, target: str) -> int:
    return cur.execute(f"SELECT COUNT(*) FROM {target};").fetchone()[0]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Canlı veritabanından test artıklarını temizler (varsayılan: yalnızca rapor).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--dry-run", action="store_true", help="yalnızca rapor (varsayılan)")
    g.add_argument("--apply", action="store_true", help="sil")
    ap.add_argument("--database", default="ThreatLens", help="hedef veritabanı (varsayılan ThreatLens)")
    a = ap.parse_args()

    conn = connect(a.database)
    cur = conn.cursor()
    targets = TARGETS[:-1] + [evidence_target(cur), TARGETS[-1]]
    print(f"Veritabanı: {a.database}  |  kip: {'SİL (--apply)' if a.apply else 'yalnızca rapor (--dry-run)'}\n")
    before = {label: count(cur, t) for label, t in targets}
    for label, n in before.items():
        print(f"  {label:<38} {n:>6}")
    total = sum(before.values())
    print(f"  {'Toplam':<38} {total:>6}")
    if not a.apply:
        print("\nHiçbir şey silinmedi. Silmek için: python scripts/purge_test_artifacts.py --apply")
        return 0
    if not total:
        print("\nSilinecek kayıt yok.")
        return 0
    conn.autocommit = False
    try:
        for label, t in targets:
            if before[label]:
                cur.execute(f"DELETE FROM {t};")
        conn.commit()
    except Exception as exc:  # noqa: BLE001 - tek işlem: hata olursa hiçbir şey silinmez
        conn.rollback()
        print(f"\nHATA, hiçbir şey silinmedi: {exc}")
        return 1
    finally:
        conn.autocommit = True
    print("\nSilme sonrası kalan:")
    for label, t in targets:
        print(f"  {label:<38} {count(cur, t):>6}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
