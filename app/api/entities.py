"""Aktör, zararlı yazılım, kampanya, zafiyet uçları ve aralarındaki ilişkiler."""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..db import Db, get_db
from ..security import current_user, require_analyst

router = APIRouter(prefix="/api", tags=["entities"], dependencies=[Depends(current_user)])


def _page(page: int, size: int) -> tuple[int, int]:
    return (page - 1) * size, size


# ============================== Aktörler ==============================

@router.get("/actors")
def list_actors(q: str = "", country: str = "", motivation: str = "", sector: int | None = None, sort: str = "techniques",
                page: int = Query(1, ge=1), size: int = Query(24, ge=5, le=200), db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("""(v.Name LIKE ? OR v.ExternalID = ?
               OR EXISTS (SELECT 1 FROM dbo.ActorAlias AS al WHERE al.ActorID = v.ActorID AND al.Alias LIKE ?))""")
        params += [f"%{q.strip()}%", q.strip(), f"%{q.strip()}%"]
    if country:
        where.append("v.CountryCode = ?"); params.append(country)
    if motivation:
        where.append("v.Motivation = ?"); params.append(motivation)
    if sector:
        where.append("EXISTS (SELECT 1 FROM dbo.ActorTargetSector AS ts WHERE ts.ActorID = v.ActorID AND ts.SectorID = ?)")
        params.append(sector)
    clause = "\n          AND ".join(where)
    order = {"name": "v.Name", "malware": "v.MalwareCount DESC, v.Name", "iocs": "ISNULL(ioc.IndicatorCount, 0) DESC, v.Name",
             "campaigns": "v.CampaignCount DESC, v.Name"}.get(sort, "v.TechniqueCount DESC, v.Name")
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.vw_ActorSummary AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        WITH ioc AS (   -- aktöre atfedilen gösterge sayısı (MATCH tabanlı vw_IndicatorAttribution)
            SELECT ActorID, COUNT(DISTINCT IndicatorID) AS IndicatorCount
            FROM dbo.vw_IndicatorAttribution WHERE ActorID IS NOT NULL GROUP BY ActorID
        )
        SELECT v.ActorID, v.ExternalID, v.Name, v.Motivation, v.CountryCode, v.CountryName, v.IsActive,
               v.MalwareCount, v.TechniqueCount, v.CampaignCount, LEFT(v.Description, 220) AS Summary,
               ISNULL(ioc.IndicatorCount, 0) AS IndicatorCount,
               (SELECT STRING_AGG(x.Alias, ', ') FROM (SELECT TOP (4) al.Alias FROM dbo.ActorAlias AS al
                                                      WHERE al.ActorID = v.ActorID ORDER BY al.Alias) AS x) AS Aliases
        FROM dbo.vw_ActorSummary AS v
        LEFT JOIN ioc ON ioc.ActorID = v.ActorID
        WHERE {clause}
        ORDER BY {order}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + _page(page, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/actors/{actor_id}")
def get_actor(actor_id: int, db: Db = Depends(get_db)):
    actor = db.one("SELECT v.*, a.MotivationID FROM dbo.vw_ActorSummary AS v JOIN dbo.ThreatActor AS a ON a.ActorID = v.ActorID WHERE v.ActorID = ?;",
                   (actor_id,))
    if not actor:
        raise HTTPException(404, "Aktör bulunamadı.")
    return {
        "actor": actor,
        "aliases": [r["Alias"] for r in db.query("SELECT Alias FROM dbo.ActorAlias WHERE ActorID = ? ORDER BY Alias;", (actor_id,))],
        "sectors": db.query(
            "SELECT s.SectorID, s.Name FROM dbo.ActorTargetSector AS x JOIN dbo.Sector AS s ON s.SectorID = x.SectorID WHERE x.ActorID = ? ORDER BY s.Name;",
            (actor_id,)),
        "targetCountries": db.query(
            "SELECT c.CountryCode, c.Name FROM dbo.ActorTargetCountry AS x JOIN dbo.Country AS c ON c.CountryCode = x.CountryCode WHERE x.ActorID = ? ORDER BY c.Name;",
            (actor_id,)),
        "malware": db.query(
            """
            SELECT m.MalwareID, m.Name, m.TypeCode, m.TypeName, m.IndicatorCount
            FROM dbo.ActorMalware AS am
            JOIN dbo.vw_MalwareSummary AS m ON m.MalwareID = am.MalwareID
            WHERE am.ActorID = ?
            ORDER BY m.IndicatorCount DESC, m.Name;
            """, (actor_id,)),
        "campaigns": db.query(
            "SELECT CampaignID, Name, StartDate, EndDate, IndicatorCount FROM dbo.vw_CampaignSummary WHERE ActorID = ? ORDER BY StartDate DESC;",
            (actor_id,)),
        "techniques": db.query(
            "SELECT TechniqueID, ExternalID, Name, TacticID, TacticName, DisplayOrder FROM dbo.fn_ActorTechniques(?) ORDER BY DisplayOrder, ExternalID;",
            (actor_id,)),
        "indicators": db.query(
            """
            -- Aktöre atfedilen en riskli göstergeler (zararlı veya kampanya üzerinden)
            SELECT TOP (12) v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SightingCount, MIN(a.ViaName) AS ViaName
            FROM dbo.vw_IndicatorAttribution AS a
            JOIN dbo.vw_Indicator AS v ON v.IndicatorID = a.IndicatorID
            WHERE a.ActorID = ?
            GROUP BY v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SightingCount
            ORDER BY v.RiskScore DESC;
            """, (actor_id,)),
        "similar": db.query(
            """
            -- Benzer aktörler: ortak teknik sayısı / birleşim (Jaccard benzerliği)
            WITH mine AS (SELECT TechniqueID FROM dbo.ActorTechnique WHERE ActorID = ?),
            shared AS (
                SELECT o.ActorID, COUNT(*) AS Shared
                FROM dbo.ActorTechnique AS o
                JOIN mine ON mine.TechniqueID = o.TechniqueID
                WHERE o.ActorID <> ?
                GROUP BY o.ActorID
            )
            SELECT TOP (5) a.ActorID, a.Name, a.CountryCode, s.Shared,
                   CAST(100.0 * s.Shared / (v.TechniqueCount + (SELECT COUNT(*) FROM mine) - s.Shared) AS INT) AS Similarity
            FROM shared AS s
            JOIN dbo.ThreatActor AS a ON a.ActorID = s.ActorID
            JOIN dbo.vw_ActorSummary AS v ON v.ActorID = s.ActorID
            WHERE s.Shared >= 3
            ORDER BY Similarity DESC, s.Shared DESC;
            """, (actor_id, actor_id)),
    }


class ActorIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(None, max_length=2000)
    motivationId: int | None = None
    countryCode: str | None = None
    isActive: bool = True
    aliases: list[str] = []
    sectorIds: list[int] = []
    targetCountries: list[str] = []


def _sync_actor_lists(db: Db, actor_id: int, body: ActorIn) -> None:
    """Çok değerli nitelikleri (takma ad, hedef sektör/ülke) sil-yeniden-ekle ile eşitler."""
    db.execute("DELETE FROM dbo.ActorAlias WHERE ActorID = ?;", (actor_id,))
    for alias in sorted({a.strip() for a in body.aliases if a.strip() and a.strip() != body.name}):
        db.execute("INSERT INTO dbo.ActorAlias (ActorID, Alias) VALUES (?, ?);", (actor_id, alias[:100]))
    db.execute("DELETE FROM dbo.ActorTargetSector WHERE ActorID = ?;", (actor_id,))
    for sector in set(body.sectorIds):
        db.execute("INSERT INTO dbo.ActorTargetSector (ActorID, SectorID) VALUES (?, ?);", (actor_id, sector))
    db.execute("DELETE FROM dbo.ActorTargetCountry WHERE ActorID = ?;", (actor_id,))
    for code in set(body.targetCountries):
        db.execute("INSERT INTO dbo.ActorTargetCountry (ActorID, CountryCode) VALUES (?, ?);", (actor_id, code))


@router.post("/actors")
def create_actor(body: ActorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    with db.transaction():
        actor_id = db.scalar(
            """
            INSERT INTO dbo.ThreatActor (Name, Description, MotivationID, CountryCode, IsActive)
            OUTPUT inserted.ActorID
            VALUES (?, ?, ?, ?, ?);
            """, (body.name.strip(), body.description or None, body.motivationId, body.countryCode or None, int(body.isActive)))
        _sync_actor_lists(db, actor_id, body)
    return {"ActorID": actor_id}


@router.put("/actors/{actor_id}")
def update_actor(actor_id: int, body: ActorIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    with db.transaction():
        changed = db.execute(
            """
            UPDATE dbo.ThreatActor
            SET Name = ?, Description = ?, MotivationID = ?, CountryCode = ?, IsActive = ?, UpdatedAt = SYSUTCDATETIME()
            WHERE ActorID = ?;
            """, (body.name.strip(), body.description or None, body.motivationId, body.countryCode or None,
                  int(body.isActive), actor_id))
        if not changed:
            raise HTTPException(404, "Aktör bulunamadı.")
        _sync_actor_lists(db, actor_id, body)
    return {"ActorID": actor_id}


@router.delete("/actors/{actor_id}")
def delete_actor(actor_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM dbo.ThreatActor WHERE ActorID = ?;", (actor_id,)):
        raise HTTPException(404, "Aktör bulunamadı.")
    return {"ok": True}


# =========================== Zararlı yazılım ==========================

@router.get("/malware")
def list_malware(q: str = "", type: str = "", linked: bool | None = None, sort: str = "indicators",
                 page: int = Query(1, ge=1), size: int = Query(30, ge=5, le=200), db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("""(v.Name LIKE ? OR v.ExternalID = ?
               OR EXISTS (SELECT 1 FROM dbo.MalwareAlias AS al WHERE al.MalwareID = v.MalwareID AND al.Alias LIKE ?))""")
        params += [f"%{q.strip()}%", q.strip(), f"%{q.strip()}%"]
    if type:
        where.append("v.TypeCode = ?"); params.append(type)
    if linked:
        where.append("v.IndicatorCount > 0")
    clause = "\n          AND ".join(where)
    order = {"name": "v.Name", "actors": "v.ActorCount DESC, v.Name",
             "techniques": "v.TechniqueCount DESC, v.Name"}.get(sort, "v.IndicatorCount DESC, v.ActorCount DESC, v.Name")
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.vw_MalwareSummary AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT v.MalwareID, v.ExternalID, v.Name, v.TypeCode, v.TypeName, v.Platforms,
               v.ActorCount, v.TechniqueCount, v.IndicatorCount, LEFT(v.Description, 200) AS Summary
        FROM dbo.vw_MalwareSummary AS v
        WHERE {clause}
        ORDER BY {order}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + _page(page, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/malware/{malware_id}")
def get_malware(malware_id: int, db: Db = Depends(get_db)):
    malware = db.one("SELECT v.*, m.MalwareTypeID FROM dbo.vw_MalwareSummary AS v JOIN dbo.Malware AS m ON m.MalwareID = v.MalwareID WHERE v.MalwareID = ?;",
                     (malware_id,))
    if not malware:
        raise HTTPException(404, "Zararlı yazılım bulunamadı.")
    return {
        "malware": malware,
        "aliases": [r["Alias"] for r in db.query("SELECT Alias FROM dbo.MalwareAlias WHERE MalwareID = ? ORDER BY Alias;", (malware_id,))],
        "actors": db.query(
            """
            SELECT a.ActorID, a.Name, a.CountryCode, a.Motivation
            FROM dbo.ActorMalware AS am JOIN dbo.vw_ActorSummary AS a ON a.ActorID = am.ActorID
            WHERE am.MalwareID = ? ORDER BY a.Name;
            """, (malware_id,)),
        "campaigns": db.query(
            """
            SELECT c.CampaignID, c.Name, c.StartDate, c.EndDate
            FROM dbo.CampaignMalware AS cm JOIN dbo.Campaign AS c ON c.CampaignID = cm.CampaignID
            WHERE cm.MalwareID = ? ORDER BY c.StartDate DESC;
            """, (malware_id,)),
        "techniques": db.query(
            """
            SELECT t.TechniqueID, t.ExternalID, t.Name, ta.TacticID, ta.Name AS TacticName, ta.DisplayOrder
            FROM dbo.MalwareTechnique AS mt
            JOIN dbo.Technique AS t ON t.TechniqueID = mt.TechniqueID
            JOIN dbo.TechniqueTactic AS tt ON tt.TechniqueID = t.TechniqueID
            JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
            WHERE mt.MalwareID = ?
            ORDER BY ta.DisplayOrder, t.ExternalID;
            """, (malware_id,)),
        "vulnerabilities": db.query(
            """
            SELECT v.VulnerabilityID, v.CveID, v.Title, v.CvssScore, v.IsKnownExploited
            FROM dbo.MalwareVulnerability AS mv JOIN dbo.Vulnerability AS v ON v.VulnerabilityID = mv.VulnerabilityID
            WHERE mv.MalwareID = ? ORDER BY v.CvssScore DESC;
            """, (malware_id,)),
        "indicators": db.query(
            """
            SELECT TOP (40) v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SightingCount, v.LastSeen, v.IsActive, mi.Role
            FROM dbo.MalwareIndicator AS mi
            JOIN dbo.vw_Indicator AS v ON v.IndicatorID = mi.IndicatorID
            WHERE mi.MalwareID = ?
            ORDER BY v.RiskScore DESC, v.LastSeen DESC;
            """, (malware_id,)),
        "roles": db.query(
            "SELECT Role, COUNT(*) AS Total FROM dbo.MalwareIndicator WHERE MalwareID = ? GROUP BY Role ORDER BY Total DESC;",
            (malware_id,)),
    }


class MalwareIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    malwareTypeId: int
    description: str | None = Field(None, max_length=2000)
    platforms: str | None = Field(None, max_length=200)
    aliases: list[str] = []


def _sync_malware_aliases(db: Db, malware_id: int, body: MalwareIn) -> None:
    db.execute("DELETE FROM dbo.MalwareAlias WHERE MalwareID = ?;", (malware_id,))
    for alias in sorted({a.strip() for a in body.aliases if a.strip() and a.strip() != body.name}):
        db.execute("INSERT INTO dbo.MalwareAlias (MalwareID, Alias) VALUES (?, ?);", (malware_id, alias[:100]))


@router.post("/malware")
def create_malware(body: MalwareIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    with db.transaction():
        malware_id = db.scalar(
            "INSERT INTO dbo.Malware (Name, MalwareTypeID, Description, Platforms) OUTPUT inserted.MalwareID VALUES (?, ?, ?, ?);",
            (body.name.strip(), body.malwareTypeId, body.description or None, body.platforms or None))
        _sync_malware_aliases(db, malware_id, body)
    return {"MalwareID": malware_id}


@router.put("/malware/{malware_id}")
def update_malware(malware_id: int, body: MalwareIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    with db.transaction():
        changed = db.execute(
            "UPDATE dbo.Malware SET Name = ?, MalwareTypeID = ?, Description = ?, Platforms = ?, UpdatedAt = SYSUTCDATETIME() WHERE MalwareID = ?;",
            (body.name.strip(), body.malwareTypeId, body.description or None, body.platforms or None, malware_id))
        if not changed:
            raise HTTPException(404, "Zararlı yazılım bulunamadı.")
        _sync_malware_aliases(db, malware_id, body)
    return {"MalwareID": malware_id}


@router.delete("/malware/{malware_id}")
def delete_malware(malware_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM dbo.Malware WHERE MalwareID = ?;", (malware_id,)):
        raise HTTPException(404, "Zararlı yazılım bulunamadı.")
    return {"ok": True}


# ============================== Kampanyalar ===========================

@router.get("/campaigns")
def list_campaigns(q: str = "", ongoing: bool | None = None, actor: int | None = None, page: int = Query(1, ge=1),
                   size: int = Query(30, ge=5, le=200), db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("(v.Name LIKE ? OR v.ActorName LIKE ? OR v.ExternalID = ?)")
        params += [f"%{q.strip()}%", f"%{q.strip()}%", q.strip()]
    if ongoing is not None:
        where.append("v.IsOngoing = ?"); params.append(int(ongoing))
    if actor:
        where.append("v.ActorID = ?"); params.append(actor)
    clause = "\n          AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.vw_CampaignSummary AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT v.CampaignID, v.ExternalID, v.Name, v.StartDate, v.EndDate, v.IsOngoing, v.ActorID, v.ActorName,
               v.MalwareCount, v.TechniqueCount, v.IndicatorCount, LEFT(v.Description, 240) AS Summary
        FROM dbo.vw_CampaignSummary AS v
        WHERE {clause}
        ORDER BY ISNULL(v.StartDate, '19000101') DESC, v.Name
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + _page(page, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, db: Db = Depends(get_db)):
    campaign = db.one("SELECT * FROM dbo.vw_CampaignSummary WHERE CampaignID = ?;", (campaign_id,))
    if not campaign:
        raise HTTPException(404, "Kampanya bulunamadı.")
    return {
        "campaign": campaign,
        "attribution": db.one(
            """
            SELECT e.Summary AS Evidence, e.Url AS EvidenceUrl, s.Name AS EvidenceSource
            FROM dbo.Campaign AS c JOIN dbo.Evidence AS e ON e.EvidenceID = c.AttributionEvidenceID
            JOIN dbo.Source AS s ON s.SourceID = e.SourceID WHERE c.CampaignID = ?;
            """, (campaign_id,)),
        "malware": db.query(
            """
            SELECT m.MalwareID, m.Name, m.TypeCode, m.TypeName
            FROM dbo.CampaignMalware AS cm JOIN dbo.vw_MalwareSummary AS m ON m.MalwareID = cm.MalwareID
            WHERE cm.CampaignID = ? ORDER BY m.Name;
            """, (campaign_id,)),
        "techniques": db.query(
            """
            SELECT t.TechniqueID, t.ExternalID, t.Name, ta.TacticID, ta.Name AS TacticName, ta.DisplayOrder
            FROM dbo.CampaignTechnique AS ct
            JOIN dbo.Technique AS t ON t.TechniqueID = ct.TechniqueID
            JOIN dbo.TechniqueTactic AS tt ON tt.TechniqueID = t.TechniqueID
            JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
            WHERE ct.CampaignID = ?
            ORDER BY ta.DisplayOrder, t.ExternalID;
            """, (campaign_id,)),
        "indicators": db.query(
            """
            SELECT TOP (40) v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SightingCount, v.LastSeen, v.IsActive
            FROM dbo.CampaignIndicator AS ci JOIN dbo.vw_Indicator AS v ON v.IndicatorID = ci.IndicatorID
            WHERE ci.CampaignID = ? ORDER BY v.RiskScore DESC;
            """, (campaign_id,)),
    }


class CampaignIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    description: str | None = Field(None, max_length=2000)
    actorId: int | None = None
    startDate: str | None = None
    endDate: str | None = None


@router.post("/campaigns")
def create_campaign(body: CampaignIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    campaign_id = db.scalar(
        "INSERT INTO dbo.Campaign (Name, Description, ActorID, StartDate, EndDate) OUTPUT inserted.CampaignID VALUES (?, ?, ?, ?, ?);",
        (body.name.strip(), body.description or None, body.actorId, body.startDate or None, body.endDate or None))
    return {"CampaignID": campaign_id}


@router.put("/campaigns/{campaign_id}")
def update_campaign(campaign_id: int, body: CampaignIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    changed = db.execute(
        "UPDATE dbo.Campaign SET Name = ?, Description = ?, ActorID = ?, StartDate = ?, EndDate = ?, UpdatedAt = SYSUTCDATETIME() WHERE CampaignID = ?;",
        (body.name.strip(), body.description or None, body.actorId, body.startDate or None, body.endDate or None, campaign_id))
    if not changed:
        raise HTTPException(404, "Kampanya bulunamadı.")
    return {"CampaignID": campaign_id}


@router.delete("/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM dbo.Campaign WHERE CampaignID = ?;", (campaign_id,)):
        raise HTTPException(404, "Kampanya bulunamadı.")
    return {"ok": True}


# ============================== Zafiyetler ============================

@router.get("/vulnerabilities")
def list_vulnerabilities(q: str = "", kev: bool | None = None, page: int = Query(1, ge=1),
                         size: int = Query(30, ge=5, le=200), db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if q.strip():
        where.append("(v.CveID LIKE ? OR v.Title LIKE ? OR v.Vendor LIKE ? OR v.Product LIKE ?)")
        params += [f"%{q.strip()}%"] * 4
    if kev:
        where.append("v.IsKnownExploited = 1")
    clause = "\n          AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.Vulnerability AS v\n        WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        SELECT v.VulnerabilityID, v.CveID, v.Title, v.Vendor, v.Product, v.CvssScore, v.PublishedDate, v.IsKnownExploited,
               (SELECT COUNT(*) FROM dbo.MalwareVulnerability AS mv WHERE mv.VulnerabilityID = v.VulnerabilityID) AS MalwareCount
        FROM dbo.Vulnerability AS v
        WHERE {clause}
        ORDER BY MalwareCount DESC, v.PublishedDate DESC, v.CveID DESC
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + _page(page, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: int, db: Db = Depends(get_db)):
    vuln = db.one("SELECT * FROM dbo.Vulnerability WHERE VulnerabilityID = ?;", (vulnerability_id,))
    if not vuln:
        raise HTTPException(404, "Zafiyet bulunamadı.")
    return {
        "vulnerability": vuln,
        "malware": db.query(
            """
            SELECT m.MalwareID, m.Name, m.TypeCode, m.TypeName, m.ActorCount
            FROM dbo.MalwareVulnerability AS mv JOIN dbo.vw_MalwareSummary AS m ON m.MalwareID = mv.MalwareID
            WHERE mv.VulnerabilityID = ? ORDER BY m.Name;
            """, (vulnerability_id,)),
        "actors": db.query(
            """
            -- İki ara tablo üzerinden: zafiyet -> zararlı -> aktör
            SELECT DISTINCT a.ActorID, a.Name, a.CountryCode
            FROM dbo.MalwareVulnerability AS mv
            JOIN dbo.ActorMalware AS am ON am.MalwareID = mv.MalwareID
            JOIN dbo.ThreatActor AS a ON a.ActorID = am.ActorID
            WHERE mv.VulnerabilityID = ? ORDER BY a.Name;
            """, (vulnerability_id,)),
    }


class VulnerabilityIn(BaseModel):
    cveId: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str = Field(min_length=3, max_length=300)
    description: str | None = Field(None, max_length=2000)
    vendor: str | None = Field(None, max_length=100)
    product: str | None = Field(None, max_length=150)
    cvssScore: float | None = Field(None, ge=0, le=10)
    publishedDate: str | None = None
    isKnownExploited: bool = False


@router.post("/vulnerabilities")
def create_vulnerability(body: VulnerabilityIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    vuln_id = db.scalar(
        """
        INSERT INTO dbo.Vulnerability (CveID, Title, Description, Vendor, Product, CvssScore, PublishedDate, IsKnownExploited)
        OUTPUT inserted.VulnerabilityID
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (body.cveId, body.title.strip(), body.description or None, body.vendor or None, body.product or None,
              body.cvssScore, body.publishedDate or None, int(body.isKnownExploited)))
    return {"VulnerabilityID": vuln_id}


@router.put("/vulnerabilities/{vulnerability_id}")
def update_vulnerability(vulnerability_id: int, body: VulnerabilityIn, user: dict = Depends(require_analyst),
                         db: Db = Depends(get_db)):
    changed = db.execute(
        """
        UPDATE dbo.Vulnerability
        SET CveID = ?, Title = ?, Description = ?, Vendor = ?, Product = ?, CvssScore = ?, PublishedDate = ?, IsKnownExploited = ?
        WHERE VulnerabilityID = ?;
        """, (body.cveId, body.title.strip(), body.description or None, body.vendor or None, body.product or None,
              body.cvssScore, body.publishedDate or None, int(body.isKnownExploited), vulnerability_id))
    if not changed:
        raise HTTPException(404, "Zafiyet bulunamadı.")
    return {"VulnerabilityID": vulnerability_id}


@router.delete("/vulnerabilities/{vulnerability_id}")
def delete_vulnerability(vulnerability_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM dbo.Vulnerability WHERE VulnerabilityID = ?;", (vulnerability_id,)):
        raise HTTPException(404, "Zafiyet bulunamadı.")
    return {"ok": True}


# ============================== İlişkiler =============================
# Ara tablolar için izinli liste. Tablo ve sütun adları kullanıcıdan alınmaz, bu sözlükten gelir.
LINKS = {
    "actor-malware":         ("dbo.ActorMalware", "ActorID", "MalwareID"),
    "actor-technique":       ("dbo.ActorTechnique", "ActorID", "TechniqueID"),
    "malware-technique":     ("dbo.MalwareTechnique", "MalwareID", "TechniqueID"),
    "malware-vulnerability": ("dbo.MalwareVulnerability", "MalwareID", "VulnerabilityID"),
    "malware-indicator":     ("dbo.MalwareIndicator", "MalwareID", "IndicatorID"),
    "campaign-malware":      ("dbo.CampaignMalware", "CampaignID", "MalwareID"),
    "campaign-technique":    ("dbo.CampaignTechnique", "CampaignID", "TechniqueID"),
    "campaign-indicator":    ("dbo.CampaignIndicator", "CampaignID", "IndicatorID"),
}


class LinkIn(BaseModel):
    kind: str
    a: int
    b: int
    role: str | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    evidence: str = Field(min_length=5, max_length=1000, description="Bu ilişkiyi neye dayanarak kuruyorsunuz?")
    evidenceUrl: str | None = Field(None, max_length=400)


@router.post("/links", status_code=201)
def add_link(body: LinkIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """İlişki ekler. Kanıtsız ilişki kurulamaz: önce Evidence satırı, sonra ara tablo satırı yazılır (tek transaction).
    Ara tablodaki tetikleyici aynı transaction içinde SQL Graph kenarını oluşturur."""
    if body.kind not in LINKS:
        raise HTTPException(400, "Geçersiz ilişki türü.")
    table, col_a, col_b = LINKS[body.kind]
    if db.scalar(f"SELECT COUNT(*) AS N FROM {table} WHERE {col_a} = ? AND {col_b} = ?;", (body.a, body.b)):
        raise HTTPException(409, "Bu ilişki zaten kayıtlı.")
    with db.transaction():
        evidence_id = db.scalar(
            """
            INSERT INTO dbo.Evidence (SourceID, Summary, Url)
            OUTPUT inserted.EvidenceID
            SELECT SourceID, ?, ? FROM dbo.Source WHERE Name = N'Analist girişi';
            """, (body.evidence.strip(), body.evidenceUrl or None))
        if body.kind == "malware-indicator":
            db.execute(f"INSERT INTO {table} ({col_a}, {col_b}, Role, Confidence, EvidenceID) VALUES (?, ?, ?, ?, ?);",
                       (body.a, body.b, body.role or "other", body.confidence, evidence_id))
        else:
            db.execute(f"INSERT INTO {table} ({col_a}, {col_b}, Confidence, EvidenceID) VALUES (?, ?, ?, ?);",
                       (body.a, body.b, body.confidence, evidence_id))
    if body.kind == "actor-malware":
        db.execute("EXEC dbo.sp_RefreshActorSimilarity;")
    return {"ok": True, "EvidenceID": evidence_id}


@router.delete("/links")
def remove_link(kind: str, a: int, b: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if kind not in LINKS:
        raise HTTPException(400, "Geçersiz ilişki türü.")
    table, col_a, col_b = LINKS[kind]
    if not db.execute(f"DELETE FROM {table} WHERE {col_a} = ? AND {col_b} = ?;", (a, b)):
        raise HTTPException(404, "İlişki bulunamadı.")
    if kind == "actor-malware":
        db.execute("EXEC dbo.sp_RefreshActorSimilarity;")
    return {"ok": True}
