"""database/ altındaki demo betiklerini gerçek SQL Server'da çalıştırır ve beklenen sonuçları doğrular.
SSMS'te yapılacak sunum adımlarının hata vermediğinin kanıtıdır."""
import re
import threading
import time
from pathlib import Path

import pyodbc
import pytest

from conftest import ROOT, needs_db

pytestmark = needs_db
GO = re.compile(r"^\s*GO\s*;?\s*$", re.I | re.M)


def run_script(_conn, path: Path) -> list[list[tuple]]:
    """Dosyayı GO'dan böler, her yığını AYRI bir oturumda (SSMS penceresi gibi) çalıştırır, sonuç kümelerini döndürür."""
    from importers._db import connect
    conn = connect()
    sets = []
    cur = conn.cursor()
    for batch in [b for b in GO.split(path.read_text(encoding="utf-8")) if b.strip()]:
        cur.execute(batch)
        while True:
            if cur.description:
                sets.append([tuple(r) for r in cur.fetchall()])
            if not cur.nextset():
                break
    conn.close()
    return sets


def test_demo1_hash_investigation(conn, linked_ioc):
    sets = run_script(conn, ROOT / "database/demos/demo1_hash_investigation.sql")
    assert len(sets[0][0][0]) == 64                         # seçilen SHA-256
    assert sets[2], "atıf zinciri (vw_IndicatorAttribution) boş"
    assert sets[3], "sp_IndicatorKillChain satır döndürmedi"
    assert sets[4] and sets[5], "sp_GetNeighborhood düğüm/kenar döndürmedi"


def test_demo2_actor_techniques(conn):
    sets = run_script(conn, ROOT / "database/demos/demo2_actor_techniques.sql")
    tvf, by_tactic, match_rows, matrix = sets[0], sets[1], sets[2], sets[3]
    assert len(tvf) > 50 and len(by_tactic) >= 10
    assert len({r[0] for r in match_rows}) == len(match_rows) and match_rows
    assert any(r[-1] for r in matrix)                       # Highlighted sütunu


def test_demo3_analyst_audit_and_protect(conn):
    try:
        sets = run_script(conn, ROOT / "database/demos/demo3_analyst_audit.sql")
        audit = sets[-2]
        assert [r[0] for r in audit] == ["I", "U"] and audit[0][1] == "SOC Analisti"
        assert sets[-1][0][0] == 50020                      # denetim kaydı silinemedi
    finally:
        conn.cursor().execute("DELETE FROM dbo.Indicator WHERE NormalizedValue = N'login-verify.example';")


def test_demo4_strict_and_lenient_import(conn):
    cleanup = "DELETE FROM dbo.Indicator WHERE NormalizedValue IN (N'192.0.2.201', N'demo4-a.example', N'http://demo4-b.example/x');"
    conn.cursor().execute(cleanup)
    try:
        sets = run_script(conn, ROOT / "database/demos/demo4_import_rollback.sql")
        flat = [s for s in sets if s and len(s[0]) == 2 and isinstance(s[0][0], int) and isinstance(s[0][1], int)]
        strict, lenient = flat[0][0], flat[1][0]
        assert strict[0] == strict[1], "katı modda gösterge sayısı değişmemeli"
        assert lenient[1] - lenient[0] == 3, "esnek modda 3 geçerli satır eklenmeli"
        errors = next(s for s in sets if s and len(s[0]) == 3 and s[0][0] == 3)
        assert [r[0] for r in errors] == [3, 4]
    finally:
        conn.cursor().execute(cleanup)


def test_demo5_index_seek_vs_scan(conn):
    run_script(conn, ROOT / "database/demos/demo5_index_performance.sql")   # hata vermemeli; tablo sonunda düşürülür
    assert conn.cursor().execute("SELECT OBJECT_ID('dbo.PerfIndicator');").fetchone()[0] is None


def test_demo7_match_and_shortest_path(conn):
    sets = run_script(conn, ROOT / "database/demos/demo7_graph_match.sql")
    match_rows, join_rows, path, reach = sets[0], sets[1], sets[2], sets[3]
    assert match_rows and len(match_rows) == len(join_rows)
    # TOP (30) eşitlikte belirsiz olduğundan tam kümeler ayrıca karşılaştırılır: MATCH deseni = 6 JOIN
    cur = conn.cursor()
    full_match = set(map(tuple, cur.execute("""
        SELECT c.CampaignID, m.MalwareID, a.ActorID, t.TechniqueID
        FROM dbo.CampaignNode AS cn, dbo.CampaignUsesMalware AS e1, dbo.MalwareNode AS mn, dbo.ActorUsesMalware AS e2,
             dbo.ActorNode AS an, dbo.ActorUsesTechnique AS e3, dbo.TechniqueNode AS tn,
             dbo.Campaign AS c, dbo.Malware AS m, dbo.ThreatActor AS a, dbo.Technique AS t
        WHERE MATCH(cn-(e1)->mn<-(e2)-an-(e3)->tn) AND c.CampaignID = cn.CampaignID AND m.MalwareID = mn.MalwareID
          AND a.ActorID = an.ActorID AND t.TechniqueID = tn.TechniqueID AND t.ExternalID LIKE 'T1059%';""").fetchall()))
    full_join = set(map(tuple, cur.execute("""
        SELECT c.CampaignID, m.MalwareID, a.ActorID, t.TechniqueID
        FROM dbo.Campaign AS c JOIN dbo.CampaignMalware AS cm ON cm.CampaignID = c.CampaignID JOIN dbo.Malware AS m ON m.MalwareID = cm.MalwareID
        JOIN dbo.ActorMalware AS am ON am.MalwareID = m.MalwareID JOIN dbo.ThreatActor AS a ON a.ActorID = am.ActorID
        JOIN dbo.ActorTechnique AS x ON x.ActorID = a.ActorID JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
        WHERE t.ExternalID LIKE 'T1059%';""").fetchall()))
    assert full_match and full_match == full_join, "MATCH ile 6 JOIN aynı sonucu vermeli"
    assert path and path[0][2] == 1                         # APT29 -> FIN7 tek adım
    assert reach and {r[2] for r in reach} <= {1, 2}


def test_sample_queries_run(conn):
    sets = run_script(conn, ROOT / "database/demos/sample_queries.sql")
    assert len(sets) >= 15


def test_backup_and_restore(conn):
    sets = run_script(conn, ROOT / "database/backup/backup_restore.sql")
    counts = sets[-1][0]
    assert counts[0] == counts[1] == counts[2], "yedekten geri yüklenen kopya canlı veriyle aynı olmalı"
    assert conn.cursor().execute("SELECT DB_ID('ThreatLens_Restore');").fetchone()[0] is None


def test_demo6_dirty_read_and_blocking(conn, linked_ioc):
    """İki oturum: 1. oturum COMMIT etmeden günceller. READ UNCOMMITTED kirli değeri görür,
    READ COMMITTED bekler (kilit zaman aşımı), ROLLBACK sonrası eski değer okunur."""
    from importers._db import connect
    iid = linked_ioc["IndicatorID"]
    original = conn.cursor().execute("SELECT Confidence FROM dbo.Indicator WHERE IndicatorID = ?;", iid).fetchone()[0]
    s1, s2 = connect(), connect()
    try:
        s1.autocommit = False
        s1.cursor().execute("UPDATE dbo.Indicator SET Confidence = 11 WHERE IndicatorID = ?;", iid)
        c2 = s2.cursor()
        c2.execute("SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;")
        assert c2.execute("SELECT Confidence FROM dbo.Indicator WHERE IndicatorID = ?;", iid).fetchone()[0] == 11   # kirli okuma
        c2.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCK_TIMEOUT 500;")
        with pytest.raises(pyodbc.Error, match="1222"):      # Lock request time out period exceeded
            c2.execute("SELECT Confidence FROM dbo.Indicator WHERE IndicatorID = ?;", iid).fetchone()
        s1.rollback()
        assert c2.execute("SELECT Confidence FROM dbo.Indicator WHERE IndicatorID = ?;", iid).fetchone()[0] == original
    finally:
        s1.close(); s2.close()


def test_rowversion_lost_update_prevented(conn, linked_ioc):
    """İki oturum aynı RowVer'i okur; ilki kaydeder, ikincisi 50009 hatası alır."""
    cur = conn.cursor()
    row = cur.execute("""SELECT TOP (1) v.IndicatorID, v.TypeCode, v.OriginalValue, v.Value, v.Confidence, v.SeverityCode, v.TLPCode, v.SourceID, v.RowVer
                         FROM dbo.vw_Indicator AS v WHERE v.IndicatorID = ?;""", linked_ioc["IndicatorID"]).fetchone()
    sql = """EXEC dbo.sp_SaveIndicator @IndicatorID = ?, @TypeCode = ?, @Value = ?, @NormalizedValue = ?, @Confidence = ?,
             @SeverityCode = ?, @TLPCode = ?, @SourceID = ?, @RowVer = ?;"""
    args = (row.IndicatorID, row.TypeCode, row.OriginalValue, row.Value, row.Confidence, row.SeverityCode, row.TLPCode, row.SourceID, row.RowVer)
    cur.execute(sql, *args).fetchall()                      # 1. oturum: aynı değerlerle kaydet (RowVer değişir)
    with pytest.raises(pyodbc.Error, match="50009"):
        cur.execute(sql, *args).fetchall()                  # 2. oturum: eski RowVer


def test_db_role_permissions(conn):
    """GRANT/DENY: izleyici rolü IOC silemez, analist silebilir (EXECUTE AS ile denenir, ROLLBACK edilir)."""
    cur = conn.cursor()
    cur.execute("IF DATABASE_PRINCIPAL_ID('tl_test_viewer') IS NULL CREATE USER tl_test_viewer WITHOUT LOGIN; ALTER ROLE tip_reader ADD MEMBER tl_test_viewer;")
    def as_viewer(sql):
        try:
            cur.execute(f"EXECUTE AS USER = 'tl_test_viewer'; {sql}")
            return cur.fetchall() if cur.description else None
        finally:
            cur.execute("IF USER_NAME() = 'tl_test_viewer' REVERT;")
    try:
        with pytest.raises(pyodbc.Error, match="229"):      # The DELETE permission was denied
            as_viewer("DELETE FROM dbo.Indicator WHERE IndicatorID = -1;")
        with pytest.raises(pyodbc.Error, match="230"):      # kolon düzeyi DENY: PasswordHash okunamaz
            as_viewer("SELECT PasswordHash FROM dbo.AppUser;")
        assert as_viewer("SELECT COUNT(*) FROM dbo.Indicator;")[0][0] > 0      # okuma serbest
    finally:
        cur.execute("ALTER ROLE tip_reader DROP MEMBER tl_test_viewer; DROP USER tl_test_viewer;")


def test_cisa_kev_merge_sql_runs(conn):
    """CISA KEV içe aktarıcısının MERGE sorgusu ağa çıkmadan, boş girdiyle derlenip çalışabilmeli."""
    from importers.cisa_kev import MERGE_SQL
    assert tuple(conn.cursor().execute(MERGE_SQL, "[]").fetchone()) == (0, 0)
