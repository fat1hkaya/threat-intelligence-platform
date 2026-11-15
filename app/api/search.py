"""Birleşik arama: ad/kimlik eşleşmeleri (sp_GlobalSearch) + tam metin arama (sp_TextSearch, Full-Text yoksa LIKE)."""
from fastapi import APIRouter, Depends, Query

from ..db import Db, get_db
from ..security import current_user
from ..services.normalize import InvalidIndicator, guess_type, normalize

router = APIRouter(prefix="/api/search", tags=["search"], dependencies=[Depends(current_user)])


@router.get("/full")
def full_search(q: str = Query(..., min_length=2, max_length=200), db: Db = Depends(get_db)):
    term = q.strip()
    kind = guess_type(term)
    if kind:
        try:
            term = normalize(kind, term)
        except InvalidIndicator:
            pass
    names = db.query("EXEC dbo.sp_GlobalSearch @Query = ?, @Top = ?;", (term, 8))
    has_fts = db.scalar("SELECT CASE WHEN OBJECT_ID(N'dbo.sp_TextSearch') IS NOT NULL AND FULLTEXTSERVICEPROPERTY('IsFulltextInstalled') = 1 THEN 1 ELSE 0 END AS F;")
    if kind or len(term) < 3:          # IOC değeri aranıyorsa metin araması anlamsız
        return {"names": names, "entities": [], "evidence": [], "engine": None}
    if has_fts:
        entities, evidence = (db.query_sets("EXEC dbo.sp_TextSearch @Query = ?, @Top = ?;", (q.strip(), 8)) + [[], []])[:2]
        return {"names": names, "entities": entities, "evidence": evidence, "engine": "fulltext"}
    like = f"%{q.strip()}%"
    entities = db.query(
        """
        -- Full-Text kurulu değil: LIKE ile (her satırı tarar, kelime biçimlerini bilmez)
        SELECT TOP (16) x.EntityType, x.EntityID, x.Title, x.Sub, 0 AS Rnk, x.Snippet FROM (
            SELECT 'actor' AS EntityType, CAST(ActorID AS BIGINT) AS EntityID, Name AS Title, ExternalID AS Sub, LEFT(Description, 240) AS Snippet FROM dbo.ThreatActor WHERE Description LIKE ?
            UNION ALL SELECT 'malware', MalwareID, Name, ExternalID, LEFT(Description, 240) FROM dbo.Malware WHERE Description LIKE ?
            UNION ALL SELECT 'technique', TechniqueID, Name, ExternalID, LEFT(Description, 240) FROM dbo.Technique WHERE Description LIKE ?
        ) AS x;
        """, (like, like, like))
    return {"names": names, "entities": entities, "evidence": [], "engine": "like"}
