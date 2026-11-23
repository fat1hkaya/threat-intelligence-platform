"""Tespit kapsama haritası: kurumun hangi ATT&CK tekniklerini tespit edebildiği ve aktörlere göre kör noktalar."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..db import Db, get_db
from ..security import current_user, require_analyst

router = APIRouter(prefix="/api/coverage", tags=["coverage"], dependencies=[Depends(current_user)])


@router.get("")
def overview(db: Db = Depends(get_db)):
    gaps, tactics, actors, fully, totals = (db.query_sets("EXEC dbo.sp_CoverageOverview;") + [[]] * 5)[:5]
    return {"gaps": gaps, "tactics": tactics, "actors": actors, "fullyCovered": fully, "totals": totals[0] if totals else {}}


@router.get("/levels")
def levels(db: Db = Depends(get_db)):
    """Matris görünümü için: işaretlenmiş (ve üstten devralınan) düzeyler."""
    return db.query(
        """
        SELECT ec.TechniqueID, ec.Level, ec.Inherited, ec.DataSource
        FROM dbo.fn_EffectiveCoverage() AS ec
        WHERE ec.Level > 0 OR EXISTS (SELECT 1 FROM dbo.DetectionCoverage AS c WHERE c.TechniqueID = ec.TechniqueID);
        """)


@router.get("/actor/{actor_id}")
def actor_coverage(actor_id: int, db: Db = Depends(get_db)):
    rows, summary = (db.query_sets("EXEC dbo.sp_ActorCoverage @ActorID = ?;", (actor_id,)) + [[], [{}]])[:2]
    if not rows:
        name = db.scalar("SELECT Name FROM dbo.ThreatActor WHERE ActorID = ?;", (actor_id,))
        if name is None:
            raise HTTPException(404, "Aktör bulunamadı.")
    return {"techniques": rows, "summary": summary[0] if summary else {}}


@router.get("/technique/{technique_id}")
def technique_coverage(technique_id: int, db: Db = Depends(get_db)):
    row = db.one(
        """
        SELECT t.TechniqueID, t.ExternalID, t.Name, c.Level, c.DataSource, c.Note, c.UpdatedAt, u.FullName AS UpdatedBy,
               ec.Level AS EffectiveLevel, ec.Inherited
        FROM dbo.Technique AS t
        JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
        LEFT JOIN dbo.DetectionCoverage AS c ON c.TechniqueID = t.TechniqueID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = c.UpdatedBy
        WHERE t.TechniqueID = ?;
        """, (technique_id,))
    if not row:
        raise HTTPException(404, "Teknik bulunamadı.")
    return row


class CoverageIn(BaseModel):
    level: int = Field(ge=0, le=2, description="0 yok, 1 kısmi, 2 tam")
    dataSource: str | None = Field(None, max_length=100)
    note: str | None = Field(None, max_length=400)


@router.put("/technique/{technique_id}")
def set_coverage(technique_id: int, body: CoverageIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """MERGE: kayıt varsa günceller, yoksa ekler (upsert). Değişiklik trg_DetectionCoverage_Audit ile denetlenir."""
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.Technique WHERE TechniqueID = ?;", (technique_id,)):
        raise HTTPException(404, "Teknik bulunamadı.")
    db.execute(
        """
        MERGE dbo.DetectionCoverage AS t
        USING (SELECT ? AS TechniqueID, ? AS Level, ? AS DataSource, ? AS Note, ? AS UserID) AS s ON t.TechniqueID = s.TechniqueID
        WHEN MATCHED THEN UPDATE SET Level = s.Level, DataSource = s.DataSource, Note = s.Note, UpdatedBy = s.UserID, UpdatedAt = SYSUTCDATETIME()
        WHEN NOT MATCHED THEN INSERT (TechniqueID, Level, DataSource, Note, UpdatedBy) VALUES (s.TechniqueID, s.Level, s.DataSource, s.Note, s.UserID);
        """, (technique_id, body.level, body.dataSource or None, body.note or None, user["UserID"]))
    return {"ok": True}


@router.delete("/technique/{technique_id}")
def clear_coverage(technique_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """İşareti kaldırır; teknik üst tekniğin düzeyini devralır (yoksa 0)."""
    db.execute("DELETE FROM dbo.DetectionCoverage WHERE TechniqueID = ?;", (technique_id,))
    return {"ok": True}


# Navigator katmanı içe aktarma: bizim dışa aktardığımız renkler (yeşil tam, sarı kısmi) doğrudan düzeye çevrilir;
# başka araçların katmanlarında 0-100 skor kullanılır (>= 67 tam, >= 34 kısmi). Kırmızı/düşük skorlu teknikler
# "işaretlenmemiş" kalır: kör noktayı kurum beyan etmemişse uydurulmaz.
NAV_COLOR_LEVEL = {"#34d399": 2, "#fbbf24": 1}


class NavigatorTechnique(BaseModel):
    techniqueID: str = Field(max_length=12)
    enabled: bool = True
    score: float | None = None
    color: str | None = Field(None, max_length=20)


class NavigatorLayer(BaseModel):
    name: str | None = Field(None, max_length=200)
    techniques: list[NavigatorTechnique] = Field(max_length=5000)


def _nav_level(t: NavigatorTechnique) -> int | None:
    if not t.enabled:
        return None
    if t.color and t.color.lower() in NAV_COLOR_LEVEL:
        return NAV_COLOR_LEVEL[t.color.lower()]
    if t.score is not None:
        return 2 if t.score >= 67 else 1 if t.score >= 34 else None
    return None


@router.post("/import-navigator")
def import_navigator(layer: NavigatorLayer, dryRun: bool = False, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """ATT&CK Navigator katmanından tam/kısmi tespit düzeylerini tek MERGE ile yazar. dryRun=true yalnızca sayar."""
    import json
    rows = [{"x": t.techniqueID.upper(), "l": lvl} for t in layer.techniques if (lvl := _nav_level(t)) is not None]
    if not rows:
        return {"matched": 0, "applied": 0, "skipped": len(layer.techniques), "dryRun": dryRun}
    js = json.dumps(rows)
    matched = db.scalar(
        """SELECT COUNT(DISTINCT t.TechniqueID) FROM OPENJSON(?) WITH (x VARCHAR(12) '$.x', l TINYINT '$.l') AS j
           JOIN dbo.Technique AS t ON t.ExternalID = j.x;""", (js,))
    applied = 0
    if not dryRun and matched:
        applied = db.execute(
            """
            -- Navigator katmanından kapsama: teknik kodu (T1059.001) ile eşlenir, aynı kod birden çok kez geçerse en yüksek düzey
            MERGE dbo.DetectionCoverage AS t
            USING (SELECT te.TechniqueID, MAX(j.l) AS Level
                   FROM OPENJSON(?) WITH (x VARCHAR(12) '$.x', l TINYINT '$.l') AS j
                   JOIN dbo.Technique AS te ON te.ExternalID = j.x GROUP BY te.TechniqueID) AS s ON t.TechniqueID = s.TechniqueID
            WHEN MATCHED THEN UPDATE SET Level = s.Level, DataSource = COALESCE(t.DataSource, N'Navigator katmanı'), UpdatedBy = ?, UpdatedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (TechniqueID, Level, DataSource, UpdatedBy) VALUES (s.TechniqueID, s.Level, N'Navigator katmanı', ?);
            """, (js, user["UserID"], user["UserID"]))
    return {"matched": matched, "applied": applied, "skipped": len(layer.techniques) - len(rows), "dryRun": dryRun}
