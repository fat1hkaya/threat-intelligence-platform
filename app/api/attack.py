"""MITRE ATT&CK uçları: taktikler, teknik listesi, teknik detayı, matris."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import Db, get_db
from ..security import current_user

router = APIRouter(prefix="/api", tags=["attack"], dependencies=[Depends(current_user)])


@router.get("/tactics")
def tactics(db: Db = Depends(get_db)):
    """Taktik kartları: her taktikteki teknik sayısı ve bu tekniklerden en az bir aktörün kullandığı sayı."""
    return db.query(
        """
        -- used: en az bir aktörün kullandığı üst teknikler (alt teknik kullanımı üst tekniğe sayılır)
        WITH used AS (
            SELECT DISTINCT COALESCE(t.ParentTechniqueID, t.TechniqueID) AS TechniqueID
            FROM dbo.ActorTechnique AS x JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
        )
        SELECT ta.TacticID, ta.ExternalID, ta.ShortName, ta.Name, ta.DisplayOrder,
               COUNT(DISTINCT t.TechniqueID) AS TechniqueCount,
               COUNT(DISTINCT u.TechniqueID) AS UsedByActors
        FROM dbo.Tactic AS ta
        LEFT JOIN dbo.TechniqueTactic AS tt ON tt.TacticID = ta.TacticID
        LEFT JOIN dbo.Technique AS t ON t.TechniqueID = tt.TechniqueID AND t.ParentTechniqueID IS NULL
        LEFT JOIN used AS u ON u.TechniqueID = t.TechniqueID
        GROUP BY ta.TacticID, ta.ExternalID, ta.ShortName, ta.Name, ta.DisplayOrder
        ORDER BY ta.DisplayOrder;
        """)


SORTS = {"id": "t.ExternalID", "name": "t.Name", "actors": "ActorCount DESC, t.ExternalID",
         "campaigns": "CampaignCount DESC, t.ExternalID", "malware": "MalwareCount DESC, t.ExternalID"}


@router.get("/techniques")
def list_techniques(q: str = Query("", max_length=100), tactic: int | None = None, actor: int | None = None,
                    campaign: int | None = None, malware: int | None = None, subtechniques: bool = False,
                    sort: str = "actors", page: int = Query(1, ge=1), size: int = Query(20, ge=5, le=200),
                    db: Db = Depends(get_db)):
    where, params = ["1 = 1"], []
    if not subtechniques:
        where.append("t.ParentTechniqueID IS NULL")
    if q.strip():
        where.append("(t.ExternalID LIKE ? OR t.Name LIKE ?)"); params += [f"{q.strip()}%", f"%{q.strip()}%"]
    if tactic:
        where.append("EXISTS (SELECT 1 FROM dbo.TechniqueTactic AS tt WHERE tt.TechniqueID = t.TechniqueID AND tt.TacticID = ?)")
        params.append(tactic)
    # Aktör/kampanya/zararlı filtresi: alt tekniklerden biri kullanılmışsa üst teknik de sayılır
    for value, table, col in ((actor, "dbo.ActorTechnique", "ActorID"), (campaign, "dbo.CampaignTechnique", "CampaignID"),
                              (malware, "dbo.MalwareTechnique", "MalwareID")):
        if value:
            where.append(f"""EXISTS (SELECT 1 FROM {table} AS f JOIN dbo.Technique AS ft ON ft.TechniqueID = f.TechniqueID
                        WHERE f.{col} = ? AND (ft.TechniqueID = t.TechniqueID OR ft.ParentTechniqueID = t.TechniqueID))""")
            params.append(value)
    clause = "\n          AND ".join(where)
    total = db.scalar(f"SELECT COUNT(*) AS Total FROM dbo.Technique AS t WHERE {clause};", tuple(params))
    items = db.query(
        f"""
        WITH fam AS (   -- teknik + alt teknikleri (özyinelemeli FK, iki düzey)
            SELECT TechniqueID, COALESCE(ParentTechniqueID, TechniqueID) AS RootID FROM dbo.Technique
        )
        SELECT t.TechniqueID, t.ExternalID, t.Name,
               (SELECT STRING_AGG(ta.Name, ', ') WITHIN GROUP (ORDER BY ta.DisplayOrder)
                  FROM dbo.TechniqueTactic AS tt JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
                 WHERE tt.TechniqueID = t.TechniqueID) AS Tactics,
               (SELECT COUNT(DISTINCT x.ActorID) FROM dbo.ActorTechnique AS x JOIN fam ON fam.TechniqueID = x.TechniqueID
                 WHERE fam.RootID = t.TechniqueID OR x.TechniqueID = t.TechniqueID) AS ActorCount,
               (SELECT COUNT(DISTINCT x.CampaignID) FROM dbo.CampaignTechnique AS x JOIN fam ON fam.TechniqueID = x.TechniqueID
                 WHERE fam.RootID = t.TechniqueID OR x.TechniqueID = t.TechniqueID) AS CampaignCount,
               (SELECT COUNT(DISTINCT x.MalwareID) FROM dbo.MalwareTechnique AS x JOIN fam ON fam.TechniqueID = x.TechniqueID
                 WHERE fam.RootID = t.TechniqueID OR x.TechniqueID = t.TechniqueID) AS MalwareCount,
               (SELECT COUNT(*) FROM dbo.Technique AS s WHERE s.ParentTechniqueID = t.TechniqueID) AS SubCount
        FROM dbo.Technique AS t
        WHERE {clause}
        ORDER BY {SORTS.get(sort, SORTS['actors'])}
        OFFSET ? ROWS FETCH NEXT ? ROWS ONLY;
        """, tuple(params) + ((page - 1) * size, size))
    return {"items": items, "total": total, "page": page, "size": size}


@router.get("/techniques/{technique_id}")
def technique_detail(technique_id: int, db: Db = Depends(get_db)):
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
    scope = "(t.TechniqueID = ? OR t.ParentTechniqueID = ?)"
    return {
        "technique": tech,
        "tactics": db.query(
            """SELECT ta.TacticID, ta.ExternalID, ta.Name FROM dbo.TechniqueTactic AS tt
               JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID WHERE tt.TechniqueID = ? ORDER BY ta.DisplayOrder;""",
            (technique_id,)),
        "subTechniques": db.query(
            "SELECT TechniqueID, ExternalID, Name FROM dbo.Technique WHERE ParentTechniqueID = ? ORDER BY ExternalID;", (technique_id,)),
        "actors": db.query(
            f"""
            -- Bu tekniği (veya alt tekniklerinden birini) kullanan aktörler
            SELECT DISTINCT a.ActorID, a.Name, a.CountryCode
            FROM dbo.ActorTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID
            WHERE {scope} ORDER BY a.Name;
            """, (technique_id, technique_id)),
        "campaigns": db.query(
            f"""
            SELECT DISTINCT c.CampaignID, c.Name, c.StartDate
            FROM dbo.CampaignTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.Campaign AS c ON c.CampaignID = x.CampaignID
            WHERE {scope} ORDER BY c.StartDate DESC;
            """, (technique_id, technique_id)),
        "malware": db.query(
            f"""
            SELECT DISTINCT m.MalwareID, m.Name, mt.Name AS TypeName
            FROM dbo.MalwareTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.Malware AS m ON m.MalwareID = x.MalwareID
            JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID
            WHERE {scope} ORDER BY m.Name;
            """, (technique_id, technique_id)),
        "indicatorCount": db.scalar(
            f"""
            -- Bu tekniği kullanan zararlılara bağlı gösterge sayısı (gösterge -> zararlı -> teknik)
            SELECT COUNT(DISTINCT mi.IndicatorID) AS N
            FROM dbo.MalwareTechnique AS x
            JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID
            JOIN dbo.MalwareIndicator AS mi ON mi.MalwareID = x.MalwareID
            WHERE {scope};
            """, (technique_id, technique_id)),
    }


@router.get("/attack/matrix")
def attack_matrix(actor: int | None = None, malware: int | None = None, campaign: int | None = None,
                  db: Db = Depends(get_db)):
    rows = db.query("EXEC dbo.sp_AttackMatrix @ActorID = ?, @MalwareID = ?, @CampaignID = ?;", (actor, malware, campaign))
    result: dict[int, dict] = {}
    for r in rows:
        t = result.setdefault(r["TacticID"], {"TacticID": r["TacticID"], "ExternalID": r["TacticExternalID"],
                                              "Name": r["TacticName"], "techniques": []})
        t["techniques"].append({k: r[k] for k in ("TechniqueID", "ExternalID", "Name", "ActorCount", "MalwareCount",
                                                  "SubTechniqueCount", "Highlighted")})
    return list(result.values())
