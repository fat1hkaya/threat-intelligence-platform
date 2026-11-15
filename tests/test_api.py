"""API ve veritabanı davranış testleri (gerçek SQL Server üzerinde).
Oluşturulan test IOC'leri test sonunda silinir; AuditLog ve ImportJob satırları tasarım gereği kalır (yalnızca eklenebilir)."""
import pytest

from conftest import needs_db

pytestmark = needs_db


def _ioc(client, value, **kw):
    body = {"value": value, "sourceId": 7, "severity": "medium", "confidence": 60, **kw}
    return client.post("/api/iocs", json=body)


# ------------------------------------------------------------------ kimlik ve yetki
def test_login_wrong_password_is_401():
    from fastapi.testclient import TestClient
    from app.main import app
    r = TestClient(app).post("/api/auth/login", json={"username": "fatih", "password": "yanlis-parola"})
    assert r.status_code == 401


def test_me_returns_fatih_kaya(admin):
    me = admin.get("/api/auth/me").json()
    assert me["FullName"] == "Fatih Kaya" and me["Role"] == "admin"


def test_unauthenticated_api_401_and_page_redirects():
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    assert c.get("/api/iocs").status_code == 401
    r = c.get("/iocs", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_viewer_cannot_write_or_manage_users(viewer):
    assert _ioc(viewer, "viewer-test.example").status_code == 403
    assert viewer.get("/api/users").status_code == 403
    assert viewer.get("/api/iocs?size=5").status_code == 200       # okuma serbest


def test_analyst_cannot_manage_users(analyst):
    assert analyst.get("/api/users").status_code == 403


# ------------------------------------------------------------------ IOC yaşam döngüsü
def test_ioc_create_normalizes_audits_and_deletes(analyst, admin, unique):
    r = _ioc(analyst, f"hxxps://Pytest-{unique}[.]example:443/A?b=1", tags=["pytest"])
    assert r.status_code == 201, r.text
    new = r.json()
    assert new["type"] == "url" and new["normalized"] == f"https://pytest-{unique}.example/A?b=1"
    iid = new["IndicatorID"]
    try:
        # Denetim kaydı tetikleyiciyle yazıldı ve kullanıcıyı (SESSION_CONTEXT) taşıyor
        logs = admin.get("/api/audit-logs", params={"table": "Indicator", "record": iid}).json()["items"]
        assert [l["Action"] for l in logs] == ["I"] and logs[0]["Username"] == "analist"
        # Graf düğümü aynı transaction'da oluştu
        assert analyst.get(f"/api/graph/node?type=indicator&id={iid}").status_code == 200
        # Aynı değerin farklı yazımı tekrar sayılır (UNIQUE TypeID + NormalizedValue)
        dup = _ioc(analyst, f"https://PYTEST-{unique}.example/A?b=1")
        assert dup.status_code == 400 and "zaten kayıtlı" in dup.json()["detail"]
    finally:
        assert analyst.delete(f"/api/iocs/{iid}").status_code == 200
    assert analyst.get(f"/api/iocs/{iid}").status_code == 404
    assert analyst.get(f"/api/graph/node?type=indicator&id={iid}").status_code == 404   # düğüm de silindi
    assert [l["Action"] for l in admin.get("/api/audit-logs", params={"table": "Indicator", "record": iid}).json()["items"]] == ["D", "I"]


@pytest.mark.parametrize("type_,value", [("sha256", "abc123"), ("md5", "z" * 32), ("ipv4", "300.1.2.3"), ("domain", "no_tld")])
def test_invalid_values_rejected(analyst, type_, value):
    r = _ioc(analyst, value, type=type_)
    assert r.status_code == 400


def test_confidence_out_of_range_is_422(analyst):
    assert _ioc(analyst, "conf-test.example", confidence=150).status_code == 422


def test_optimistic_concurrency_rowversion(analyst, unique):
    iid = _ioc(analyst, f"rowver-{unique}.test").json()["IndicatorID"]
    try:
        ind = analyst.get(f"/api/iocs/{iid}").json()["indicator"]
        body = {"type": "domain", "value": ind["OriginalValue"], "sourceId": 7, "severity": "high", "confidence": 70, "rowVer": ind["RowVer"]}
        assert analyst.put(f"/api/iocs/{iid}", json=body).status_code == 200          # 1. oturum kaydeder
        stale = analyst.put(f"/api/iocs/{iid}", json={**body, "confidence": 90})       # 2. oturum eski RowVer ile
        assert stale.status_code == 400 and "başka bir kullanıcı" in stale.json()["detail"]
        assert analyst.get(f"/api/iocs/{iid}").json()["indicator"]["Confidence"] == 70
    finally:
        analyst.delete(f"/api/iocs/{iid}")


def test_graph_examples_are_real_attributed_iocs(admin, linked_ioc):
    ex = admin.get("/api/iocs/examples").json()
    assert ex and all(e["ActorName"] and e["MalwareName"] for e in ex)


def test_sql_injection_attempt_is_harmless(analyst, linked_ioc):
    r = analyst.get("/api/iocs", params={"q": "' OR 1=1; DROP TABLE dbo.Indicator; --", "sort": "value; DROP TABLE x"})
    assert r.status_code == 200 and r.json()["total"] == 0
    assert analyst.get("/api/iocs?size=5").json()["total"] > 0


def test_sighting_moves_last_seen(analyst, unique):
    iid = _ioc(analyst, f"sighting-{unique}.test").json()["IndicatorID"]
    try:
        before = analyst.get(f"/api/iocs/{iid}").json()["indicator"]["SightingCount"]
        assert analyst.post(f"/api/iocs/{iid}/sightings", json={"quantity": 3, "location": "pytest"}).status_code == 201
        assert analyst.get(f"/api/iocs/{iid}").json()["indicator"]["SightingCount"] == before + 3
    finally:
        analyst.delete(f"/api/iocs/{iid}")


# ------------------------------------------------------------------ içe aktarma
def test_strict_import_rolls_back_everything(analyst, unique):
    total = analyst.get("/api/iocs?size=5").json()["total"]
    csv = f"type,value\ndomain,strict-{unique}.example\nsha256,not-a-hash\nipv4,192.0.2.254\n".encode()
    r = analyst.post("/api/imports", files={"file": ("bad.csv", csv, "text/csv")}, data={"strict": "true"}).json()
    assert r["status"] == "failed" and r["inserted"] == 0 and r["failed"] == 1
    assert analyst.get("/api/iocs?size=5").json()["total"] == total                     # ROLLBACK: sayı değişmedi
    job = analyst.get(f"/api/imports/{r['job_id']}").json()
    assert job["job"]["IsStrict"] and [e["RowNo"] for e in job["errors"]] == [2]


def test_lenient_import_keeps_valid_rows(analyst, conn, unique):
    csv = f"type,value,malware\ndomain,lenient-{unique}.example,Emotet\nsha256,not-a-hash,\n".encode()
    r = analyst.post("/api/imports", files={"file": ("mix.csv", csv, "text/csv")}, data={"strict": "false"}).json()
    assert r["status"] == "partial" and r["inserted"] == 1 and r["failed"] == 1
    hit = analyst.get("/api/iocs", params={"q": f"lenient-{unique}.example"}).json()["items"]
    assert hit and hit[0]["MalwareName"] == "Emotet"                                    # kanıtlı zararlı bağlantısı da yazıldı
    analyst.delete(f"/api/iocs/{hit[0]['IndicatorID']}")


# ------------------------------------------------------------------ graf
def test_graph_consistency_all_true(admin):
    rows = admin.get("/api/graph/stats").json()
    assert rows and all(r["IsConsistent"] for r in rows)


def test_neighborhood_edges_only_between_returned_nodes(admin, linked_ioc):
    d = admin.get("/api/graph/neighborhood", params={"type": "indicator", "id": linked_ioc["IndicatorID"], "depth": 2}).json()
    keys = {(n["NodeType"], n["NodeID"]) for n in d["nodes"]}
    assert d["edges"] and all((e["SourceType"], e["SourceID"]) in keys and (e["TargetType"], e["TargetID"]) in keys for e in d["edges"])


def test_relationships_use_match_attribution(admin, linked_ioc):
    rel = admin.get(f"/api/iocs/{linked_ioc['IndicatorID']}/relationships").json()
    assert any(a["ViaType"] == "malware" and a["ViaName"] == linked_ioc["MalwareName"] and a["ActorName"] for a in rel["attribution"])
    assert rel["killchain"] and rel["malwareTechniques"]                                   # çok adımlı MATCH sonuç verdi
    assert all(a["Evidence"] for a in rel["attribution"] if a["ViaType"] == "malware")    # her bağlantının kanıtı var


def test_edge_detail_has_evidence_source(admin, linked_ioc):
    d = admin.get("/api/graph/neighborhood", params={"type": "indicator", "id": linked_ioc["IndicatorID"], "depth": 1}).json()
    e = d["edges"][0]
    r = admin.get("/api/graph/edge", params={"sourceType": e["SourceType"], "sourceId": e["SourceID"], "targetType": e["TargetType"],
                                             "targetId": e["TargetID"], "relation": e["Relation"]}).json()
    assert r["EdgeTable"] == "dbo.IndicatesMalware" and r["EvidenceSource"] and r["Evidence"]


def test_shortest_path_apt29_fin7(admin):
    ids = {a["Name"]: a["ActorID"] for a in admin.get("/api/actors", params={"size": 200}).json()["items"]}
    r = admin.get("/api/graph/path", params={"fromActor": ids["APT29"], "toActor": ids["FIN7"]}).json()
    assert r["found"] and r["hops"] == 1 and r["steps"][0]["shared"]
    # hiç aracı olmayan bir aktöre yol olamaz (veri zenginleştikçe değişmeyen bir durum)
    loner = next(a["ActorID"] for a in admin.get("/api/actors", params={"size": 200}).json()["items"] if a["MalwareCount"] == 0)
    assert admin.get("/api/graph/path", params={"fromActor": ids["APT29"], "toActor": loner}).json()["found"] is False


def test_link_requires_evidence_and_creates_edge(analyst, unique):
    iid = _ioc(analyst, f"link-{unique}.test").json()["IndicatorID"]
    try:
        mal = analyst.get("/api/malware", params={"q": "Cobalt Strike"}).json()["items"][0]["MalwareID"]
        assert analyst.post("/api/links", json={"kind": "malware-indicator", "a": mal, "b": iid}).status_code == 422   # kanıt zorunlu
        ok = analyst.post("/api/links", json={"kind": "malware-indicator", "a": mal, "b": iid, "role": "c2", "confidence": 55,
                                              "evidence": "pytest: test amaçlı kanıt metni"})
        assert ok.status_code == 201
        rel = analyst.get(f"/api/iocs/{iid}/relationships").json()["attribution"]
        assert any(a["ViaID"] == mal and a["Evidence"].startswith("pytest") for a in rel)
    finally:
        analyst.delete(f"/api/iocs/{iid}")


# ------------------------------------------------------------------ ekranlar ve özet
def test_dashboard_counts_match_database(admin, conn):
    k = admin.get("/api/dashboard/summary").json()["kpi"]
    assert k["TotalIOCs"] == conn.cursor().execute("SELECT COUNT(*) FROM dbo.Indicator;").fetchone()[0]
    assert k["Actors"] == conn.cursor().execute("SELECT COUNT(*) FROM dbo.ThreatActor;").fetchone()[0]


@pytest.mark.parametrize("path", ["/", "/iocs", "/graph", "/actors", "/campaigns", "/malware", "/attack", "/sources", "/audit", "/settings"])
def test_pages_render(admin, path):
    r = admin.get(path)
    assert r.status_code == 200 and "Fatih Kaya" in r.text


def test_sql_trace_records_parameterized_queries(admin):
    r = admin.get("/api/iocs", params={"q": "example", "size": 5})
    trace = admin.get(f"/api/trace/{r.headers['X-Trace-Id']}").json()
    assert any("LIKE ?" in s["sql"] for s in trace["statements"])


# ------------------------------------------------------------------ Application Role
@pytest.mark.parametrize("role,can_delete", [("viewer", False), ("analyst", True), ("admin", True)])
def test_application_role_limits_connection(role, can_delete):
    """Uygulama bağlantısı sp_setapprole ile kullanıcının rolüne indirgenir: sysadmin yetkisi kalmaz,
    izleyici rolünde DELETE ve parola özetini okuma veritabanı tarafından reddedilir (hata 229/230)."""
    import pyodbc
    from app.db import Db
    db = Db()
    try:
        db.activate_role(role)
        cur = db.conn.cursor()
        user, sysadmin = cur.execute("SELECT USER_NAME(), IS_SRVROLEMEMBER('sysadmin');").fetchone()
        assert user == f"app_{role}" and sysadmin == 0
        if can_delete:
            cur.execute("DELETE FROM dbo.Indicator WHERE IndicatorID = -1;")
        else:
            with pytest.raises(pyodbc.Error, match="229"):
                cur.execute("DELETE FROM dbo.Indicator WHERE IndicatorID = -1;")
        with pytest.raises(pyodbc.Error, match="230"):
            cur.execute("SELECT TOP (1) PasswordHash FROM dbo.AppUser;")
    finally:
        db.close()
    fresh = Db()                                   # rolsüz havuzdan gelen bağlantıda rol etkin olmamalı
    assert fresh.conn.cursor().execute("SELECT USER_NAME();").fetchone()[0] not in ("app_viewer", "app_analyst", "app_admin")
    fresh.close()


def test_requests_run_under_application_role(viewer):
    r = viewer.get("/api/iocs?size=5")
    trace = viewer.get(f"/api/trace/{r.headers['X-Trace-Id']}").json()
    assert any("sp_setapprole" in s["sql"] and "app_viewer" in s["sql"] for s in trace["statements"])


def test_audit_records_user_under_application_role(analyst, admin, unique):
    iid = analyst.post("/api/iocs", json={"value": f"approle-{unique}.test", "sourceId": 7}).json()["IndicatorID"]
    try:
        log = admin.get("/api/audit-logs", params={"table": "Indicator", "record": iid}).json()["items"][0]
        assert log["Username"] == "analist"          # SESSION_CONTEXT rol bağlantısında ayarlandı
    finally:
        analyst.delete(f"/api/iocs/{iid}")


# ------------------------------------------------------------------ yaşam döngüsü
def test_new_ioc_gets_expiry_from_policy(analyst, unique):
    iid = analyst.post("/api/iocs", json={"type": "ipv4", "value": "203.0.113." + str(int(unique, 16) % 200 + 20), "sourceId": 7}).json()
    if "IndicatorID" not in iid:                                                       # adres zaten kayıtlıysa domain ile dene
        iid = analyst.post("/api/iocs", json={"value": f"ttl-{unique}.test", "sourceId": 7}).json()
    iid = iid["IndicatorID"]
    try:
        ind = analyst.get(f"/api/iocs/{iid}").json()["indicator"]
        assert ind["ExpiresAt"] is not None                                            # Analist girişi politikası: 180 gün
    finally:
        analyst.delete(f"/api/iocs/{iid}")


def test_retention_policy_and_admin_only_edit(admin, analyst):
    d = admin.get("/api/retention").json()
    assert d["policies"] and sum(p["AppliesTo"] for p in d["policies"]) == admin.get("/api/iocs?size=5").json()["total"]
    pid, days = d["policies"][0]["PolicyID"], d["policies"][0]["LifetimeDays"]
    assert analyst.put(f"/api/retention/{pid}", json={"lifetimeDays": 10}).status_code == 403
    assert admin.put(f"/api/retention/{pid}", json={"lifetimeDays": days}).status_code == 200
    assert admin.put(f"/api/retention/{pid}", json={"lifetimeDays": 0}).status_code == 422


def test_expire_procedure_logs_run(conn):
    row = conn.cursor().execute("EXEC dbo.sp_ExpireIndicators;").fetchone()
    assert row[0] >= 0
    last = conn.cursor().execute("SELECT TOP (1) Task, Status FROM dbo.MaintenanceRun ORDER BY RunID DESC;").fetchone()
    assert tuple(last) == ("expire-indicators", "success")


def test_stale_import_is_stored_as_expired(analyst, unique):
    """Kaynak aylar önce görülmüş bir IOC bildirirse bitiş tarihi geçmişte kalır: kayıt 'expired' eklenir ve
    yeniden içe aktarıldığında etkinleşmez (aktif/pasif arasında gidip gelmez)."""
    csv = f"type,value,first_seen,last_seen\ndomain,stale-{unique}.test,2020-01-01T00:00:00,2020-01-02T00:00:00\n".encode()
    for _ in range(2):
        r = analyst.post("/api/imports", files={"file": ("old.csv", csv, "text/csv")}, data={"strict": "false"}).json()
        assert r["status"] == "success"
    hit = analyst.get("/api/iocs", params={"q": f"stale-{unique}.test"}).json()["items"][0]
    try:
        assert hit["Status"] == "expired"
    finally:
        analyst.delete(f"/api/iocs/{hit['IndicatorID']}")


# ------------------------------------------------------------------ varlık ekleme uçları (tetikleyicili tablolar)
def test_create_entities_on_tables_with_triggers(analyst, admin, unique):
    """ThreatActor, Malware, Campaign, Vulnerability ve AppUser tablolarında tetikleyici var: INSERT ... OUTPUT INTO ile çalışmalı."""
    actor = analyst.post("/api/actors", json={"name": f"Pytest Actor {unique}", "aliases": [f"pta-{unique}"]})
    assert actor.status_code == 200, actor.text
    mal = analyst.post("/api/malware", json={"name": f"Pytest Mal {unique}", "malwareTypeId": 1})
    assert mal.status_code == 200, mal.text
    camp = analyst.post("/api/campaigns", json={"name": f"Pytest Camp {unique}", "actorId": actor.json()["ActorID"]})
    assert camp.status_code == 200, camp.text
    cve = f"CVE-2099-{int(unique, 16) % 90000 + 10000}"
    vuln = analyst.post("/api/vulnerabilities", json={"cveId": cve, "title": "pytest zafiyeti"})
    assert vuln.status_code == 200, vuln.text
    user = admin.post("/api/users", json={"username": f"pyt{unique}", "fullName": "Pytest Kullanıcı", "role": "viewer", "password": "Gecici-Parola-123"})
    assert user.status_code == 201, user.text
    graph = admin.get("/api/graph/stats").json()
    assert all(r["IsConsistent"] for r in graph)
    analyst.delete(f"/api/campaigns/{camp.json()['CampaignID']}")
    analyst.delete(f"/api/actors/{actor.json()['ActorID']}")
    analyst.delete(f"/api/malware/{mal.json()['MalwareID']}")
    analyst.delete(f"/api/vulnerabilities/{vuln.json()['VulnerabilityID']}")
    admin.patch(f"/api/users/{user.json()['UserID']}", json={"isActive": False})


# ------------------------------------------------------------------ kimlik doğrulama güvenliği
def _fresh_client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_session_token_stored_only_as_hash(conn):
    import hashlib
    c = _fresh_client()
    assert c.post("/api/auth/login", json={"username": "izleyici", "password": "ThreatLens2026!"}).status_code == 200
    raw = c.cookies.get("tl_session")
    cur = conn.cursor()
    assert cur.execute("SELECT COUNT(*) FROM dbo.UserSession WHERE Token = ?;", raw).fetchone()[0] == 0
    assert cur.execute("SELECT COUNT(*) FROM dbo.UserSession WHERE Token = ?;", hashlib.sha256(raw.encode()).hexdigest()).fetchone()[0] == 1
    c.post("/api/auth/logout")


def test_login_lockout_after_five_failures(unique):
    c = _fresh_client()
    name = f"pytest-lock-{unique}"
    codes = [c.post("/api/auth/login", json={"username": name, "password": "yanlis"}).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_password_change_and_admin_reset(admin, unique):
    uname = f"pw{unique}"
    uid = admin.post("/api/users", json={"username": uname, "fullName": "Parola Testi", "role": "viewer", "password": "Ilk-Parola-123"}).json()["UserID"]
    try:
        c = _fresh_client()
        assert c.post("/api/auth/login", json={"username": uname, "password": "Ilk-Parola-123"}).status_code == 200
        assert c.post("/api/auth/password", json={"current": "yanlis-parola", "new": "Yeni-Parola-456"}).status_code == 400
        assert c.post("/api/auth/password", json={"current": "Ilk-Parola-123", "new": "kisa"}).status_code == 422
        assert c.post("/api/auth/password", json={"current": "Ilk-Parola-123", "new": "Yeni-Parola-456"}).status_code == 200
        c2 = _fresh_client()
        assert c2.post("/api/auth/login", json={"username": uname, "password": "Ilk-Parola-123"}).status_code == 401
        assert c2.post("/api/auth/login", json={"username": uname, "password": "Yeni-Parola-456"}).status_code == 200
        assert admin.patch(f"/api/users/{uid}", json={"password": "Sifirlanan-789"}).status_code == 200
        assert c2.get("/api/auth/me").status_code == 401                       # sıfırlama tüm oturumları kapatır
        assert _fresh_client().post("/api/auth/login", json={"username": uname, "password": "Sifirlanan-789"}).status_code == 200
    finally:
        admin.patch(f"/api/users/{uid}", json={"isActive": False})


def test_login_attempts_visible_only_to_admin(admin, analyst):
    assert analyst.get("/api/audit-logs/logins").status_code == 403
    d = admin.get("/api/audit-logs/logins").json()
    assert d["items"] and d["totals"]["Total"] >= len(d["items"])


def test_risk_breakdown_matches_score(admin, linked_ioc):
    d = admin.get(f"/api/iocs/{linked_ioc['IndicatorID']}").json()
    r = d["risk"]
    raw = float(r["BasePoints"]) * float(r["ReliabilityFactor"]) * float(r["FreshnessFactor"]) * float(r["StatusFactor"])
    from decimal import ROUND_HALF_UP, Decimal                                         # SQL ROUND: yarımı yukarı
    assert r["Score"] == d["indicator"]["RiskScore"] == max(0, min(100, int(Decimal(str(raw)).quantize(Decimal("1"), ROUND_HALF_UP))))
    assert abs(float(r["BasePoints"]) - (float(r["ConfidencePart"]) + float(r["SeverityPart"]) + float(r["SightingPart"]))) < 0.01
