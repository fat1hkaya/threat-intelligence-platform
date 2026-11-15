"""Genel bakış, arama, sözlükler ve ATT&CK/graf uçları."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import Db, TRACES, get_db
from ..security import current_user

router = APIRouter(prefix="/api", tags=["overview"], dependencies=[Depends(current_user)])


@router.get("/meta")
def meta(db: Db = Depends(get_db)):
    return {
        "types": db.query("SELECT TypeID, Code, Name FROM dbo.IndicatorType ORDER BY TypeID;", trace=False),
        "severities": db.query("SELECT SeverityID, Code, Name, Weight FROM dbo.SeverityLevel ORDER BY SeverityID;", trace=False),
        "tlps": db.query("SELECT TLPID, Code, Description FROM dbo.TLPLevel ORDER BY TLPID;", trace=False),
        "sources": db.query("SELECT SourceID, Name, Reliability FROM dbo.Source WHERE IsActive = 1 ORDER BY Name;", trace=False),
        "motivations": db.query("SELECT MotivationID, Name FROM dbo.Motivation ORDER BY MotivationID;", trace=False),
        "malwareTypes": db.query("SELECT MalwareTypeID, Code, Name FROM dbo.MalwareType ORDER BY Name;", trace=False),
        "countries": db.query("SELECT CountryCode, Name FROM dbo.Country ORDER BY Name;", trace=False),
        "sectors": db.query("SELECT SectorID, Name FROM dbo.Sector ORDER BY Name;", trace=False),
        "tags": db.query("SELECT TagID, Name FROM dbo.Tag ORDER BY Name;", trace=False),
    }


@router.get("/dashboard")
def dashboard(db: Db = Depends(get_db)):
    counts = db.one(
        """
        -- Özet sayılar: skaler alt sorgular tek satırda birleştirilir
        SELECT
            (SELECT COUNT(*) FROM dbo.Indicator)                                   AS Indicators,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE IsActive = 1)                AS ActiveIndicators,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE FirstSeen >= DATEADD(DAY, -7, SYSUTCDATETIME()))  AS New7d,
            (SELECT COUNT(*) FROM dbo.Indicator WHERE FirstSeen >= DATEADD(DAY, -14, SYSUTCDATETIME())
                                                  AND FirstSeen <  DATEADD(DAY, -7, SYSUTCDATETIME()))  AS NewPrev7d,
            (SELECT ISNULL(SUM(Quantity), 0) FROM dbo.Sighting WHERE SightedAt >= DATEADD(DAY, -7, SYSUTCDATETIME())) AS Sightings7d,
            (SELECT COUNT(*) FROM dbo.ThreatActor)   AS Actors,
            (SELECT COUNT(*) FROM dbo.Malware)       AS Malware,
            (SELECT COUNT(*) FROM dbo.Campaign)      AS Campaigns,
            (SELECT COUNT(*) FROM dbo.Technique)     AS Techniques,
            (SELECT COUNT(*) FROM dbo.Vulnerability) AS Vulnerabilities;
        """)
    trend = db.query(
        """
        -- Son 30 gün: özyinelemeli CTE ile takvim üretilir, veri olmayan günler 0 görünür
        WITH days AS (
            SELECT CAST(DATEADD(DAY, -29, SYSUTCDATETIME()) AS DATE) AS [Day]
            UNION ALL
            SELECT DATEADD(DAY, 1, [Day]) FROM days WHERE [Day] < CAST(SYSUTCDATETIME() AS DATE)
        )
        SELECT d.[Day],
               (SELECT COUNT(*) FROM dbo.Indicator AS i
                 WHERE i.FirstSeen >= d.[Day] AND i.FirstSeen < DATEADD(DAY, 1, d.[Day])) AS Added,
               (SELECT ISNULL(SUM(s.Quantity), 0) FROM dbo.Sighting AS s
                 WHERE s.SightedAt >= d.[Day] AND s.SightedAt < DATEADD(DAY, 1, d.[Day])) AS Sightings
        FROM days AS d
        ORDER BY d.[Day]
        OPTION (MAXRECURSION 40);
        """)
    by_type = db.query(
        """
        SELECT t.Code, t.Name, COUNT(i.IndicatorID) AS Total
        FROM dbo.IndicatorType AS t
        LEFT JOIN dbo.Indicator AS i ON i.TypeID = t.TypeID AND i.IsActive = 1
        GROUP BY t.TypeID, t.Code, t.Name
        HAVING COUNT(i.IndicatorID) > 0
        ORDER BY Total DESC;
        """)
    by_severity = db.query(
        """
        SELECT s.Code, s.Name, COUNT(i.IndicatorID) AS Total
        FROM dbo.SeverityLevel AS s
        LEFT JOIN dbo.Indicator AS i ON i.SeverityID = s.SeverityID AND i.IsActive = 1
        GROUP BY s.SeverityID, s.Code, s.Name
        ORDER BY s.SeverityID DESC;
        """)
    top_risk = db.query(
        """
        -- Kurumda görülmüş (sighting) ve hâlâ aktif olan en riskli göstergeler
        SELECT TOP (7) v.IndicatorID, v.Value, v.TypeCode, v.RiskScore, v.SeverityCode, v.SightingCount, v.LastSeen,
               (SELECT TOP (1) a.ViaName FROM dbo.vw_IndicatorAttribution AS a WHERE a.IndicatorID = v.IndicatorID) AS ViaName,
               (SELECT TOP (1) a.ActorName FROM dbo.vw_IndicatorAttribution AS a
                 WHERE a.IndicatorID = v.IndicatorID AND a.ActorName IS NOT NULL) AS ActorName
        FROM dbo.vw_Indicator AS v
        WHERE v.IsActive = 1 AND v.SightingCount > 0
        ORDER BY v.RiskScore DESC, v.LastSeen DESC;
        """)
    top_actors = db.query(
        """
        -- Elimizdeki göstergelere en çok bağlanan aktörler (atıf zinciri üzerinden)
        SELECT TOP (6) a.ActorID, a.ActorName, COUNT(DISTINCT a.IndicatorID) AS IndicatorCount,
               COUNT(DISTINCT CASE WHEN s.IndicatorID IS NOT NULL THEN a.IndicatorID END) AS SightedCount
        FROM dbo.vw_IndicatorAttribution AS a
        LEFT JOIN (SELECT DISTINCT IndicatorID FROM dbo.Sighting) AS s ON s.IndicatorID = a.IndicatorID
        WHERE a.ActorID IS NOT NULL
        GROUP BY a.ActorID, a.ActorName
        ORDER BY SightedCount DESC, IndicatorCount DESC;
        """)
    top_malware = db.query(
        """
        SELECT TOP (6) m.MalwareID, m.Name, m.TypeName, m.IndicatorCount
        FROM dbo.vw_MalwareSummary AS m
        WHERE m.IndicatorCount > 0
        ORDER BY m.IndicatorCount DESC;
        """)
    recent_sightings = db.query(
        """
        SELECT TOP (6) s.SightingID, s.SightedAt, s.Quantity, s.Location, i.IndicatorID, i.Value, t.Code AS TypeCode
        FROM dbo.Sighting AS s
        JOIN dbo.Indicator AS i ON i.IndicatorID = s.IndicatorID
        JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID
        ORDER BY s.SightedAt DESC;
        """)
    sources = db.query("SELECT * FROM dbo.vw_SourceHealth WHERE IndicatorCount > 0 OR LastRunAt IS NOT NULL ORDER BY IndicatorCount DESC;")
    return {"counts": counts, "trend": trend, "byType": by_type, "bySeverity": by_severity, "topRisk": top_risk,
            "topActors": top_actors, "topMalware": top_malware, "recentSightings": recent_sightings, "sources": sources}


@router.get("/search")
def search(q: str = Query("", max_length=200), db: Db = Depends(get_db)):
    if len(q.strip()) < 2:
        return []
    return db.query("EXEC dbo.sp_GlobalSearch @Query = ?, @Top = ?;", (q, 6))


@router.get("/attack/matrix")
def attack_matrix(actor: int | None = None, malware: int | None = None, campaign: int | None = None,
                  db: Db = Depends(get_db)):
    rows = db.query("EXEC dbo.sp_AttackMatrix @ActorID = ?, @MalwareID = ?, @CampaignID = ?;", (actor, malware, campaign))
    tactics: dict[int, dict] = {}
    for r in rows:
        t = tactics.setdefault(r["TacticID"], {"TacticID": r["TacticID"], "ExternalID": r["TacticExternalID"],
                                               "Name": r["TacticName"], "techniques": []})
        t["techniques"].append({k: r[k] for k in ("TechniqueID", "ExternalID", "Name", "ActorCount", "MalwareCount",
                                                  "SubTechniqueCount", "Highlighted")})
    return list(tactics.values())


@router.get("/techniques/{technique_id}")
def technique(technique_id: int, db: Db = Depends(get_db)):
    tech = db.one(
        """
        SELECT t.TechniqueID, t.ExternalID, t.Name, t.Description, t.ParentTechniqueID,
               p.ExternalID AS ParentExternalID, p.Name AS ParentName
        FROM dbo.Technique AS t
        LEFT JOIN dbo.Technique AS p ON p.TechniqueID = t.ParentTechniqueID      -- self join
        WHERE t.TechniqueID = ?;
        """, (technique_id,))
    if not tech:
        raise HTTPException(404, "Teknik bulunamadı.")
    return {
        "technique": tech,
        "tactics": db.query(
            """
            SELECT ta.TacticID, ta.ExternalID, ta.Name
            FROM dbo.TechniqueTactic AS tt JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
            WHERE tt.TechniqueID = ? ORDER BY ta.DisplayOrder;
            """, (technique_id,)),
        "subTechniques": db.query(
            "SELECT TechniqueID, ExternalID, Name FROM dbo.Technique WHERE ParentTechniqueID = ? ORDER BY ExternalID;",
            (technique_id,)),
        "actors": db.query(
            """
            -- Bu tekniği (veya alt tekniklerinden birini) kullanan aktörler
            SELECT DISTINCT a.ActorID, a.Name, a.CountryCode
            FROM dbo.ActorTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID
            WHERE t.TechniqueID = ? OR t.ParentTechniqueID = ?
            ORDER BY a.Name;
            """, (technique_id, technique_id)),
        "malware": db.query(
            """
            SELECT DISTINCT m.MalwareID, m.Name, mt.Name AS TypeName
            FROM dbo.MalwareTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.Malware AS m ON m.MalwareID = x.MalwareID
            JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID
            WHERE t.TechniqueID = ? OR t.ParentTechniqueID = ?
            ORDER BY m.Name;
            """, (technique_id, technique_id)),
    }


NODE_TYPES = {"actor", "malware", "campaign", "technique", "vulnerability", "indicator"}


@router.get("/graph")
def graph(type: str, id: int, depth: int = Query(1, ge=1, le=3), techniques: bool = False,
          indicators: bool = True, limit: int = Query(120, ge=10, le=300), db: Db = Depends(get_db)):
    if type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz düğüm tipi.")
    sets = db.query_sets(
        "EXEC dbo.sp_GetNeighborhood @NodeType = ?, @NodeID = ?, @Depth = ?, @IncludeTechniques = ?, @IncludeIndicators = ?, @MaxNodes = ?;",
        (type, id, depth, int(techniques), int(indicators), limit))
    nodes, edges = (sets + [[], []])[:2]
    return {"nodes": nodes, "edges": edges}


@router.get("/trace/{trace_id}")
def trace(trace_id: str):
    item = TRACES.get(trace_id)
    if not item:
        raise HTTPException(404, "Sorgu izi bulunamadı (bellekten düşmüş olabilir).")
    return item
