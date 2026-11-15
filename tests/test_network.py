"""IP ağ zenginleştirme: dönüşüm fonksiyonu, tetikleyici, aralık araması, altyapı örtüşmesi, ip2asn ayrıştırıcı."""
import pytest

from conftest import needs_db
from importers.ip2asn import parse

TAB = "\t"


def test_ip2asn_parse_skips_unrouted_and_bad_lines():
    lines = [TAB.join(["1.0.0.0", "1.0.0.255", "13335", "US", "CLOUDFLARENET"]) + "\n",
             TAB.join(["1.0.1.0", "1.0.3.255", "0", "None", "Not routed"]) + "\n",
             "bozuk satir\n",
             TAB.join(["2.2.2.0", "2.2.2.255", "64500", "None", ""]) + "\n"]
    assert parse(lines) == [(16777216, 16777471, 13335, "US", "CLOUDFLARENET"), (33686016, 33686271, 64500, None, "AS64500")]


@needs_db
@pytest.mark.parametrize("ip,expected", [("0.0.0.0", 0), ("1.2.3.4", 16909060), ("255.255.255.255", 4294967295),
                                         ("256.1.1.1", None), ("1.2.3", None), ("a.b.c.d", None), ("1.2.3.4.5", None)])
def test_ipv4_to_bigint(conn, ip, expected):
    assert conn.cursor().execute("SELECT dbo.fn_Ipv4ToBigint(?);", ip).fetchone()[0] == expected


@needs_db
def test_trigger_enriches_new_ip_ioc_with_range_lookup(analyst, viewer, conn, unique):
    cur = conn.cursor()
    start = 3405803776                                   # 203.0.113.0 (TEST-NET-3, belgeleme bloğu)
    if cur.execute("SELECT COUNT(*) FROM dbo.IpRange WHERE StartIP = ?;", start).fetchone()[0]:
        pytest.skip("Gerçek veri bu aralığı içeriyor")
    asn = 4200000000 + int(unique[:6], 16) % 90000000    # özel kullanım ASN aralığı
    cur.execute("INSERT INTO dbo.AutonomousSystem (ASN, Name, CountryCode) VALUES (?, ?, 'TR');", asn, f"pytest-{unique}")
    cur.execute("INSERT INTO dbo.IpRange (StartIP, EndIP, ASN, CountryCode) VALUES (?, ?, ?, 'TR');", start, start + 255, asn)
    ids = []
    try:
        for host in (7, 9):
            r = analyst.post("/api/iocs", json={"value": f"203.0.113.{host}", "sourceId": 7})
            assert r.status_code == 201, r.text
            ids.append(r.json()["IndicatorID"])
        row = cur.execute("SELECT IpNum, ASN, CountryCode FROM dbo.IndicatorNetwork WHERE IndicatorID = ?;", ids[0]).fetchone()
        assert (row.IpNum, row.ASN, row.CountryCode) == (start + 7, asn, "TR")          # tetikleyici + TOP(1) aralık araması
        d = viewer.get(f"/api/infrastructure/indicator/{ids[0]}").json()
        assert d["network"]["Subnet24"] == "203.0.113.0/24" and d["network"]["SameASN"] == 2
        assert [n["IndicatorID"] for n in d["subnetNeighbours"]] == [ids[1]]
        assert cur.execute("SELECT COUNT(*) FROM dbo.vw_IndicatorNetwork WHERE Subnet24 = '203.0.113.0/24';").fetchone()[0] == 2
        ov = viewer.get("/api/infrastructure").json()
        assert ov["summary"]["Ranges"] >= 1 and ov["summary"]["Enriched"] >= 2
        # aralık dışındaki adres ASN almaz, ama sayısal adresi yine tutulur
        out = analyst.post("/api/iocs", json={"value": "198.51.100.200", "sourceId": 7}).json()["IndicatorID"]
        ids.append(out)
        row = cur.execute("SELECT IpNum, ASN FROM dbo.IndicatorNetwork WHERE IndicatorID = ?;", out).fetchone()
        assert row.IpNum == 3325256904 and row.ASN is None
    finally:
        for i in ids:
            analyst.delete(f"/api/iocs/{i}")
        cur.execute("DELETE FROM dbo.IpRange WHERE StartIP = ?;", start)
        cur.execute("UPDATE dbo.IndicatorNetwork SET ASN = NULL WHERE ASN = ?;", asn)
        cur.execute("DELETE FROM dbo.AutonomousSystem WHERE ASN = ?;", asn)
    # IOC silinince ağ kaydı da gider (ON DELETE CASCADE)
    assert cur.execute(f"SELECT COUNT(*) FROM dbo.IndicatorNetwork WHERE IndicatorID IN ({','.join(map(str, ids))});").fetchone()[0] == 0


@needs_db
def test_non_ip_ioc_has_no_network_row(analyst, viewer, unique):
    iid = analyst.post("/api/iocs", json={"value": f"ag-{unique}.example", "sourceId": 7}).json()["IndicatorID"]
    try:
        assert viewer.get(f"/api/infrastructure/indicator/{iid}").status_code == 404
    finally:
        analyst.delete(f"/api/iocs/{iid}")


@needs_db
def test_ip2asn_load_requires_admin(analyst):
    assert analyst.post("/api/imports/feed", json={"feed": "ip2asn"}).status_code == 403
