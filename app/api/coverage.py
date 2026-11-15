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
