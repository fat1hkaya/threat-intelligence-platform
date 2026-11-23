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


# Yönlü gezinme: IOC -> zararlı -> (kampanya, aktör) -> teknik/zafiyet. Teknik ve zafiyet "yaprak"tır: çok sayıda aktöre
# bağlı merkez düğümler olduklarından üzerlerinden genişlenirse ilgisiz aktörler grafa dolar ve asıl zincir kaybolur.
RANK = {"indicator": 0, "malware": 1, "campaign": 2, "actor": 2, "technique": 3, "vulnerability": 3}
LEAF = {"technique", "vulnerability"}
CAPS = {"actor": 12, "indicator": 20, "technique": 15, "malware": 15, "campaign": 12, "vulnerability": 10}   # düğüm başına, tip başına


def _edges_touching(db: Db, frontier: list[tuple[str, int]]) -> list[dict]:
    """Sınırdaki düğümlere değen tüm kenarlar (iki yönde); düğüm listesi JSON olarak tek parametreyle gider."""
    import json
    js = json.dumps([{"t": t, "i": i} for t, i in frontier])
    return db.query(
        """
        -- Yönlü komşuluk adımı: sınır düğümlerine değen kenarlar (vw_GraphEdge MATCH ile okur)
        WITH f AS (SELECT t, i FROM OPENJSON(?) WITH (t VARCHAR(15) '$.t', i BIGINT '$.i'))
        SELECT e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence, e.EvidenceID,
               f.t AS FromType, f.i AS FromID, e.TargetType AS OtherType, e.TargetID AS OtherID
        FROM dbo.vw_GraphEdge AS e JOIN f ON f.t = e.SourceType AND f.i = e.SourceID
        UNION ALL
        SELECT e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence, e.EvidenceID,
               f.t, f.i, e.SourceType, e.SourceID
        FROM dbo.vw_GraphEdge AS e JOIN f ON f.t = e.TargetType AND f.i = e.TargetID;
        """, (js,))


def _allowed(src: tuple[str, int], dst_type: str, start: tuple[str, int]) -> bool:
    """Başlangıç düğümünden her yöne gidilir; diğer düğümlerden yalnızca zincirde ileri (ya da kampanya <-> aktör)."""
    if src == start:
        return True
    a, b = RANK[src[0]], RANK[dst_type]
    return b > a or (a == b and {src[0], dst_type} == {"campaign", "actor"})


@router.get("/neighborhood")
def neighborhood(type: str, id: int, depth: int = Query(2, ge=1, le=3), limit: int = Query(80, ge=10, le=300),
                 techniques: bool = True, indicators: bool = True,
                 only: str | None = Query(None, description="Yalnızca bu tipteki komşular (küme düğümünü açarken)"),
                 offset: int = Query(0, ge=0), db: Db = Depends(get_db)):
    """Başlangıç düğümünden yönlü, genişlik öncelikli gezinme.

    - Teknik/zafiyet düğümleri yapraktır (başlangıç düğümü değilse genişletilmez).
    - Ters yöndeki bağlantılar (aynı zararlıyı kullanan diğer IOC'ler gibi) yalnızca başlangıç düğümünün komşularıdır.
    - Bir düğümün aynı tipteki komşuları CAPS ile sınırlıdır; fazlası tek bir küme olarak döner (clusters).
    - Kenarlarda Main=1: başlangıçtan geçen asıl yol (gezinme ağacı); Main=0: dahil düğümler arasındaki çapraz kenar.
    """
    if type not in NODE_TYPES or (only and only not in NODE_TYPES):
        raise HTTPException(400, "Geçersiz düğüm tipi.")
    start = (type, id)
    if not db.scalar("SELECT COUNT(*) FROM dbo.vw_GraphNode WHERE NodeType = ? AND NodeID = ?;", start):
        raise HTTPException(404, "Düğüm bulunamadı.")
    if only:
        depth = 1
    level: dict[tuple[str, int], int] = {start: 0}
    main: set[tuple] = set()
    edge_rows: dict[tuple, dict] = {}
    clusters, hidden = [], 0
    frontier = [start]
    for lvl in range(depth):
        if not frontier:
            break
        rows = _edges_touching(db, frontier)
        groups: dict[tuple, list[dict]] = {}
        for r in rows:
            src, other = (r["FromType"], r["FromID"]), (r["OtherType"], r["OtherID"])
            key = (r["SourceType"], r["SourceID"], r["TargetType"], r["TargetID"], r["Relation"])
            edge_rows.setdefault(key, r)
            if other in level or not _allowed(src, other[0], start):
                continue
            if only and other[0] != only:
                continue
            if (other[0] == "technique" and not techniques) or (other[0] == "indicator" and not indicators):
                continue
            groups.setdefault((src, other[0]), []).append(r)
        nxt = []
        for (src, t), cand in groups.items():
            seen, uniq = set(), []
            for r in sorted(cand, key=lambda r: (-(r["Confidence"] or 0), -r["OtherID"])):
                o = (r["OtherType"], r["OtherID"])
                if o not in seen and o not in level:
                    seen.add(o)
                    uniq.append(r)
            cap = 60 if only else CAPS[t]
            take = uniq[offset:offset + cap] if only else uniq[:cap]
            for r in take:
                o = (r["OtherType"], r["OtherID"])
                if len(level) >= limit:
                    hidden += 1
                    continue
                if o in level:
                    continue
                level[o] = lvl + 1
                main.add((r["SourceType"], r["SourceID"], r["TargetType"], r["TargetID"], r["Relation"]))
                if o[0] not in LEAF:
                    nxt.append(o)
            rest = len(uniq) - (offset if only else 0) - len(take)
            if rest > 0:
                clusters.append({"id": f"more:{src[0]}:{src[1]}:{t}", "parentType": src[0], "parentId": src[1], "childType": t,
                                 "count": rest, "offset": (offset if only else 0) + len(take)})
        frontier = nxt
    import json
    keys = json.dumps([{"t": t, "i": i} for t, i in level])
    labels = {(n["NodeType"], n["NodeID"]): n for n in db.query(
        """
        SELECT g.NodeType, g.NodeID, g.Label, g.SubLabel
        FROM dbo.vw_GraphNode AS g
        JOIN OPENJSON(?) WITH (t VARCHAR(15) '$.t', i BIGINT '$.i') AS k ON k.t = g.NodeType AND k.i = g.NodeID;
        """, (keys,))}
    nodes = [{**labels[k], "Lvl": v} for k, v in sorted(level.items(), key=lambda kv: (kv[1], kv[0][0])) if k in labels]
    # Dahil düğümler arasındaki tüm kenarlar (çapraz kenarlar da); sınırın son katmanının kenarları için ek sorgu
    if frontier:
        for r in _edges_touching(db, frontier):
            edge_rows.setdefault((r["SourceType"], r["SourceID"], r["TargetType"], r["TargetID"], r["Relation"]), r)
    edges = []
    for k, r in edge_rows.items():
        if (k[0], k[1]) in level and (k[2], k[3]) in level:
            edges.append({"SourceType": k[0], "SourceID": k[1], "TargetType": k[2], "TargetID": k[3], "Relation": k[4],
                          "Confidence": r["Confidence"], "EvidenceID": r["EvidenceID"], "Main": int(k in main)})
    return {"nodes": nodes, "edges": edges, "clusters": clusters, "hidden": hidden,
            "truncated": hidden > 0, "limit": limit, "depth": depth}


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
