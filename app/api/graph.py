"""İlişki grafı uçları. Düğüm ve kenarların tamamı veritabanındaki SQL Graph tablolarından gelir
(vw_GraphEdge görünümü MATCH ile okur); arayüz hiçbir ilişki üretmez."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..db import Db, get_db
from ..security import current_user
from ..services.normalize import InvalidIndicator, guess_type, normalize

router = APIRouter(prefix="/api/graph", tags=["graph"], dependencies=[Depends(current_user)])

NODE_TYPES = ("indicator", "malware", "campaign", "actor", "technique", "vulnerability")
# Kenar tipi -> (kenar tablosu, açıklama). Arayüzdeki "ilişki türü" metni buradan gelir.
RELATIONS = {
    ("indicator", "malware", "indicates"): ("dbo.IndicatesMalware", "Gösterge bu zararlı yazılımla ilişkili"),
    ("actor", "malware", "uses"): ("dbo.ActorUsesMalware", "Aktör bu zararlı yazılımı/aracı kullanıyor"),
    ("actor", "technique", "uses"): ("dbo.ActorUsesTechnique", "Aktör bu ATT&CK tekniğini kullanıyor"),
    ("malware", "technique", "uses"): ("dbo.MalwareUsesTechnique", "Zararlı yazılım bu tekniği uyguluyor"),
    ("malware", "vulnerability", "exploits"): ("dbo.MalwareExploitsVulnerability", "Zararlı yazılım bu zafiyeti istismar ediyor"),
    ("campaign", "actor", "attributed-to"): ("dbo.CampaignAttributedToActor", "Kampanya bu aktöre atfediliyor"),
    ("campaign", "malware", "uses"): ("dbo.CampaignUsesMalware", "Kampanyada bu zararlı yazılım kullanıldı"),
    ("campaign", "technique", "uses"): ("dbo.CampaignUsesTechnique", "Kampanyada bu teknik kullanıldı"),
    ("campaign", "indicator", "observed"): ("dbo.CampaignContainsIndicator", "Gösterge bu kampanyada gözlendi"),
}


@router.get("/search")
def graph_search(q: str = Query(..., min_length=2, max_length=400), db: Db = Depends(get_db)):
    """Aranan değeri graf düğümüne çözer. IOC'ye benziyorsa önce normalleştirilip birebir aranır;
    değilse global aramadaki adaylar döner. Tek eşleşme varsa arayüz grafı doğrudan açar."""
    term = q.strip()
    kind = guess_type(term)
    if kind:
        try:
            value = normalize(kind, term)
            hit = db.one(
                """
                SELECT i.IndicatorID AS NodeID, i.NormalizedValue AS Label, t.Code AS SubLabel
                FROM dbo.Indicator AS i JOIN dbo.IndicatorType AS t ON t.TypeID = i.TypeID
                WHERE t.Code = ? AND i.NormalizedValue = ?;      -- UQ (TypeID, NormalizedValue) indeksini kullanır
                """, (kind, value))
            if hit:
                return {"exact": {"type": "indicator", "id": hit["NodeID"], "label": hit["Label"]}, "candidates": []}
            term = value
        except InvalidIndicator:
            pass
    rows = db.query("EXEC dbo.sp_GlobalSearch @Query = ?, @Top = ?;", (term, 5))
    candidates = [{"type": r["EntityType"], "id": r["EntityID"], "label": r["Title"], "sub": r["Subtitle"]} for r in rows]
    exact = next((c for c in candidates if c["label"].lower() == term.lower()), None)
    return {"exact": exact, "candidates": candidates}


@router.get("/neighborhood")
def neighborhood(type: str, id: int, depth: int = Query(2, ge=1, le=3), limit: int = Query(80, ge=10, le=300),
                 techniques: bool = True, indicators: bool = True, db: Db = Depends(get_db)):
    """sp_GetNeighborhood: başlangıç düğümünden genişlik öncelikli gezinme (en çok `limit` düğüm)."""
    if type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz düğüm tipi.")
    sets = db.query_sets(
        "EXEC dbo.sp_GetNeighborhood @NodeType = ?, @NodeID = ?, @Depth = ?, @IncludeTechniques = ?, @IncludeIndicators = ?, @MaxNodes = ?;",
        (type, id, depth, int(techniques), int(indicators), limit))
    nodes, edges = (sets + [[], []])[:2]
    # Düğüm sınırına takılıp takılmadığını bildir: arayüz "genişlet" seçeneği sunar
    return {"nodes": nodes, "edges": edges, "truncated": len(nodes) >= limit, "limit": limit, "depth": depth}


@router.get("/node")
def node_detail(type: str, id: int, db: Db = Depends(get_db)):
    """Seçili düğümün özeti (sağ panel)."""
    if type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz düğüm tipi.")
    base = db.one("SELECT NodeType, NodeID, Label, SubLabel FROM dbo.vw_GraphNode WHERE NodeType = ? AND NodeID = ?;", (type, id))
    if not base:
        raise HTTPException(404, "Düğüm bulunamadı.")
    info: dict = {}
    if type == "indicator":
        info = db.one("""SELECT TypeName, SeverityCode, SeverityName, Confidence, RiskScore, SourceName, Reliability, Status,
                                FirstSeen, LastSeen, Description FROM dbo.vw_Indicator WHERE IndicatorID = ?;""", (id,)) or {}
    elif type == "malware":
        info = db.one("SELECT TypeName, Platforms, Description, ActorCount, TechniqueCount, IndicatorCount FROM dbo.vw_MalwareSummary WHERE MalwareID = ?;", (id,)) or {}
    elif type == "actor":
        info = db.one("SELECT Motivation, CountryName, Description, MalwareCount, TechniqueCount, CampaignCount FROM dbo.vw_ActorSummary WHERE ActorID = ?;", (id,)) or {}
    elif type == "campaign":
        info = db.one("SELECT ActorName, StartDate, EndDate, Description, MalwareCount, TechniqueCount, IndicatorCount FROM dbo.vw_CampaignSummary WHERE CampaignID = ?;", (id,)) or {}
    elif type == "technique":
        info = db.one(
            """SELECT t.Description, (SELECT STRING_AGG(ta.Name, ', ') FROM dbo.TechniqueTactic AS tt
                     JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID WHERE tt.TechniqueID = t.TechniqueID) AS Tactics
               FROM dbo.Technique AS t WHERE t.TechniqueID = ?;""", (id,)) or {}
    elif type == "vulnerability":
        info = db.one("SELECT Title, Vendor, Product, CvssScore, IsKnownExploited, Description FROM dbo.Vulnerability WHERE VulnerabilityID = ?;", (id,)) or {}
    degree = db.one(
        """
        SELECT (SELECT COUNT(*) FROM dbo.vw_GraphEdge WHERE SourceType = ? AND SourceID = ?) AS OutDegree,
               (SELECT COUNT(*) FROM dbo.vw_GraphEdge WHERE TargetType = ? AND TargetID = ?) AS InDegree;
        """, (type, id, type, id))
    return {**base, **info, **degree}


@router.get("/edge")
def edge_detail(sourceType: str, sourceId: int, targetType: str, targetId: int, relation: str, db: Db = Depends(get_db)):
    """Kenar detayı: ilişki türü, güven puanı, kanıt metni ve doğrulama kaynağı."""
    key = (sourceType, targetType, relation)
    if key not in RELATIONS:
        raise HTTPException(400, "Geçersiz ilişki türü.")
    row = db.one(
        """
        SELECT TOP (1) e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence, e.EvidenceID,
               a.Label AS SourceLabel, b.Label AS TargetLabel,
               ev.Summary AS Evidence, ev.Url AS EvidenceUrl, ev.ExternalRef, ev.CollectedAt,
               s.Name AS EvidenceSource, s.Reliability
        FROM dbo.vw_GraphEdge AS e
        JOIN dbo.vw_GraphNode AS a ON a.NodeType = e.SourceType AND a.NodeID = e.SourceID
        JOIN dbo.vw_GraphNode AS b ON b.NodeType = e.TargetType AND b.NodeID = e.TargetID
        LEFT JOIN dbo.Evidence AS ev ON ev.EvidenceID = e.EvidenceID
        LEFT JOIN dbo.Source AS s ON s.SourceID = ev.SourceID
        WHERE e.SourceType = ? AND e.SourceID = ? AND e.TargetType = ? AND e.TargetID = ? AND e.Relation = ?;
        """, (sourceType, sourceId, targetType, targetId, relation))
    if not row:
        raise HTTPException(404, "Kenar bulunamadı.")
    table, meaning = RELATIONS[key]
    if sourceType == "indicator" and targetType == "malware":
        row["Role"] = db.scalar("SELECT Role FROM dbo.MalwareIndicator WHERE IndicatorID = ? AND MalwareID = ?;", (sourceId, targetId))
    row["EdgeTable"], row["Meaning"] = table, meaning
    return row


@router.get("/path")
def shortest_path(fromActor: int, toActor: int, maxHops: int = Query(5, ge=1, le=6), db: Db = Depends(get_db)):
    """İki aktör arasındaki en kısa 'ortak araç' zinciri (SHORTEST_PATH, ağırlıksız)."""
    row = db.one("EXEC dbo.sp_ActorShortestPath @FromActorID = ?, @ToActorID = ?, @MaxHops = ?;", (fromActor, toActor, maxHops))
    if not row:
        return {"found": False, "path": [], "hops": None}
    ids = [fromActor] + [int(x) for x in str(row["PathIDs"]).split(",") if x.strip()]
    names = {r["ActorID"]: r["Name"] for r in db.query(
        "SELECT a.ActorID, a.Name FROM dbo.ThreatActor AS a JOIN OPENJSON(?) AS j ON a.ActorID = CAST(j.[value] AS INT);",
        (str(ids),))}
    steps = []
    for a, b in zip(ids, ids[1:]):
        shared = db.query(
            """
            SELECT m.MalwareID, m.Name
            FROM dbo.ActorMalware AS x JOIN dbo.ActorMalware AS y ON y.MalwareID = x.MalwareID
            JOIN dbo.Malware AS m ON m.MalwareID = x.MalwareID
            WHERE x.ActorID = ? AND y.ActorID = ? ORDER BY m.Name;
            """, (a, b))
        steps.append({"from": a, "to": b, "shared": shared})
    return {"found": True, "hops": row["Hops"], "path": [{"id": i, "name": names.get(i)} for i in ids], "steps": steps}


@router.get("/stats")
def graph_stats(db: Db = Depends(get_db)):
    """Graf tablolarının satır sayıları ve ilişkisel modelle tutarlılığı (sp_CheckGraphConsistency)."""
    return db.query("EXEC dbo.sp_CheckGraphConsistency;")
