"""Vaka (soruşturma) çalışma alanı. Vakaya eklenen varlıklar SQL Graph kenarıdır (InvestigationIncludes)."""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..db import Db, get_db
from ..security import current_user, require_analyst

router = APIRouter(prefix="/api/cases", tags=["cases"], dependencies=[Depends(current_user)])
NODE_TYPES = ("indicator", "malware", "actor", "campaign", "technique", "vulnerability")
STATUSES = ("open", "investigating", "closed")


@router.get("")
def list_cases(status: str = "", db: Db = Depends(get_db)):
    where, params = "1 = 1", ()
    if status in STATUSES:
        where, params = "c.Status = ?", (status,)
    return db.query(
        f"""
        SELECT c.InvestigationID, c.Title, c.Status, s.Code AS SeverityCode, c.CreatedAt, c.UpdatedAt, c.ClosedAt,
               u.FullName AS CreatedBy, a.FullName AS AssignedTo,
               (SELECT COUNT(*) FROM dbo.vw_InvestigationItem AS i WHERE i.InvestigationID = c.InvestigationID) AS Items,
               (SELECT COUNT(*) FROM dbo.InvestigationNote AS n WHERE n.InvestigationID = c.InvestigationID) AS Notes
        FROM dbo.Investigation AS c
        JOIN dbo.SeverityLevel AS s ON s.SeverityID = c.SeverityID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = c.CreatedBy
        LEFT JOIN dbo.AppUser AS a ON a.UserID = c.AssignedTo
        WHERE {where}
        ORDER BY CASE c.Status WHEN 'investigating' THEN 0 WHEN 'open' THEN 1 ELSE 2 END, c.UpdatedAt DESC;
        """, params)


@router.get("/assignees")
def assignees(db: Db = Depends(get_db)):
    """Vaka atanabilecek kullanıcılar: aktif analist ve yöneticiler."""
    return db.query(
        """
        SELECT u.UserID, u.FullName FROM dbo.AppUser AS u JOIN dbo.Role AS r ON r.RoleID = u.RoleID
        WHERE u.IsActive = 1 AND r.Code IN ('analyst', 'admin') ORDER BY u.FullName;
        """)


@router.get("/for-entity")
def cases_for_entity(type: str, id: int, db: Db = Depends(get_db)):
    """Bir varlığın içinde bulunduğu vakalar (IOC detayı, graf paneli)."""
    if type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz tür.")
    return db.query(
        """
        SELECT c.InvestigationID, c.Title, c.Status
        FROM dbo.vw_InvestigationItem AS i JOIN dbo.Investigation AS c ON c.InvestigationID = i.InvestigationID
        WHERE i.NodeType = ? AND i.NodeID = ? ORDER BY c.UpdatedAt DESC;
        """, (type, id))


class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=150)
    summary: str | None = Field(None, max_length=2000)
    severity: str = "medium"
    assignedTo: int | None = None


@router.post("", status_code=201)
def create_case(body: CaseIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    case_id = db.insert_id(
        """
        INSERT INTO dbo.Investigation (Title, Summary, SeverityID, CreatedBy, AssignedTo)
        OUTPUT inserted.InvestigationID
        SELECT ?, ?, s.SeverityID, ?, ? FROM dbo.SeverityLevel AS s WHERE s.Code = ?;
        """, (body.title.strip(), body.summary or None, user["UserID"], body.assignedTo or user["UserID"], body.severity))
    if not case_id:
        raise HTTPException(400, "Geçersiz önem düzeyi.")
    return {"InvestigationID": case_id}


@router.get("/{case_id}")
def get_case(case_id: int, db: Db = Depends(get_db)):
    case = db.one(
        """
        SELECT c.InvestigationID, c.Title, c.Summary, c.Status, s.Code AS SeverityCode, c.CreatedAt, c.UpdatedAt, c.ClosedAt,
               c.AssignedTo AS AssignedToID, u.FullName AS CreatedBy, a.FullName AS AssignedTo
        FROM dbo.Investigation AS c JOIN dbo.SeverityLevel AS s ON s.SeverityID = c.SeverityID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = c.CreatedBy LEFT JOIN dbo.AppUser AS a ON a.UserID = c.AssignedTo
        WHERE c.InvestigationID = ?;
        """, (case_id,))
    if not case:
        raise HTTPException(404, "Vaka bulunamadı.")
    items = db.query(
        """
        SELECT i.NodeType, i.NodeID, g.Label, g.SubLabel, i.AddedAt, i.Note, u.FullName AS AddedBy
        FROM dbo.vw_InvestigationItem AS i                         -- MATCH(v-(e)->t), düğüm türü başına
        JOIN dbo.vw_GraphNode AS g ON g.NodeType = i.NodeType AND g.NodeID = i.NodeID
        LEFT JOIN dbo.AppUser AS u ON u.UserID = i.AddedBy
        WHERE i.InvestigationID = ?
        ORDER BY i.AddedAt DESC;
        """, (case_id,))
    notes = db.query(
        """
        SELECT n.NoteID, n.CreatedAt, n.Body, u.FullName AS Author
        FROM dbo.InvestigationNote AS n LEFT JOIN dbo.AppUser AS u ON u.UserID = n.AuthorID
        WHERE n.InvestigationID = ? ORDER BY n.CreatedAt DESC;
        """, (case_id,))
    return {"case": case, "items": items, "notes": notes}


class CaseUpdate(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=150)
    summary: str | None = Field(None, max_length=2000)
    status: str | None = None
    severity: str | None = None
    assignedTo: int | None = None


@router.patch("/{case_id}")
def update_case(case_id: int, body: CaseUpdate, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if body.status and body.status not in STATUSES:
        raise HTTPException(400, "Geçersiz durum.")
    changed = db.execute(
        """
        UPDATE c SET Title = COALESCE(?, c.Title), Summary = COALESCE(?, c.Summary),
               SeverityID = COALESCE((SELECT SeverityID FROM dbo.SeverityLevel WHERE Code = ?), c.SeverityID),
               AssignedTo = COALESCE(?, c.AssignedTo),
               Status = COALESCE(?, c.Status),
               ClosedAt = CASE WHEN COALESCE(?, c.Status) = 'closed' THEN COALESCE(c.ClosedAt, SYSUTCDATETIME()) ELSE NULL END,
               UpdatedAt = SYSUTCDATETIME()
        FROM dbo.Investigation AS c WHERE c.InvestigationID = ?;
        """, (body.title, body.summary, body.severity, body.assignedTo, body.status, body.status, case_id))
    if not changed:
        raise HTTPException(404, "Vaka bulunamadı.")
    return {"ok": True}


class ItemIn(BaseModel):
    type: str
    id: int
    note: str | None = Field(None, max_length=400)


@router.post("/{case_id}/items", status_code=201)
def add_item(case_id: int, body: ItemIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if body.type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz tür.")
    db.execute("EXEC dbo.sp_InvestigationAddItem @InvestigationID = ?, @NodeType = ?, @NodeID = ?, @Note = ?, @UserID = ?;",
               (case_id, body.type, body.id, body.note or None, user["UserID"]))
    return {"ok": True}


class ItemsIn(BaseModel):
    type: str
    ids: list[int] = Field(min_length=1, max_length=200)
    note: str | None = Field(None, max_length=400)


@router.post("/{case_id}/items/batch", status_code=201)
def add_items(case_id: int, body: ItemsIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    """Listeden seçilen birden çok öğeyi tek transaction içinde vakaya ekler (IOC listesindeki toplu işlem)."""
    if body.type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz tür.")
    # Vakada zaten olanlar atlanır (yordam tekrarı hata sayar; toplu eklemede bu beklenen bir durum)
    present = {r["NodeID"] for r in db.query(
        "SELECT NodeID FROM dbo.vw_InvestigationItem WHERE InvestigationID = ? AND NodeType = ?;", (case_id, body.type))}
    todo = [i for i in dict.fromkeys(body.ids) if i not in present]
    with db.transaction():
        for node_id in todo:
            db.execute("EXEC dbo.sp_InvestigationAddItem @InvestigationID = ?, @NodeType = ?, @NodeID = ?, @Note = ?, @UserID = ?;",
                       (case_id, body.type, node_id, body.note or None, user["UserID"]))
    return {"ok": True, "added": len(todo), "skipped": len(set(body.ids)) - len(todo)}


@router.delete("/{case_id}/items")
def remove_item(case_id: int, type: str, id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if type not in NODE_TYPES:
        raise HTTPException(400, "Geçersiz tür.")
    db.execute("EXEC dbo.sp_InvestigationRemoveItem @InvestigationID = ?, @NodeType = ?, @NodeID = ?;", (case_id, type, id))
    return {"ok": True}


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


@router.post("/{case_id}/notes", status_code=201)
def add_note(case_id: int, body: NoteIn, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.Investigation WHERE InvestigationID = ?;", (case_id,)):
        raise HTTPException(404, "Vaka bulunamadı.")
    with db.transaction():
        db.execute("INSERT INTO dbo.InvestigationNote (InvestigationID, AuthorID, Body) VALUES (?, ?, ?);", (case_id, user["UserID"], body.body.strip()))
        db.execute("UPDATE dbo.Investigation SET UpdatedAt = SYSUTCDATETIME() WHERE InvestigationID = ?;", (case_id,))
    return {"ok": True}


@router.get("/{case_id}/graph")
def case_graph(case_id: int, db: Db = Depends(get_db)):
    """Vakanın grafı: vakadaki varlıklar, aralarındaki kenarlar ve en az İKİ vaka öğesine birden bağlı olan
    (vakada olmayan) ortak bağlantılar: 'bunlara da bakmalısın' önerisi."""
    items = db.query("SELECT NodeType, NodeID FROM dbo.vw_InvestigationItem WHERE InvestigationID = ?;", (case_id,))
    if not items:
        return {"nodes": [], "edges": [], "common": []}
    payload = json.dumps([{"t": i["NodeType"], "i": i["NodeID"]} for i in items])
    edges = db.query(
        """
        WITH it AS (SELECT t, i FROM OPENJSON(?) WITH (t VARCHAR(15) '$.t', i BIGINT '$.i'))
        SELECT e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence, e.EvidenceID
        FROM dbo.vw_GraphEdge AS e                                  -- MATCH tabanlı kenar görünümü
        WHERE EXISTS (SELECT 1 FROM it WHERE it.t = e.SourceType AND it.i = e.SourceID)
           OR EXISTS (SELECT 1 FROM it WHERE it.t = e.TargetType AND it.i = e.TargetID);
        """, (payload,))
    keys = {(i["NodeType"], i["NodeID"]) for i in items}
    counter: dict[tuple, set] = {}
    for e in edges:
        a, b = (e["SourceType"], e["SourceID"]), (e["TargetType"], e["TargetID"])
        for item, other in ((a, b), (b, a)):
            if item in keys and other not in keys:
                counter.setdefault(other, set()).add(item)
    # Eşit bağlantıda önce aktör/kampanya/zararlı (soruşturmada daha anlamlı), sonra IOC, zafiyet, teknik
    rank = {"actor": 0, "campaign": 1, "malware": 2, "indicator": 3, "vulnerability": 4, "technique": 5}
    common = sorted(((k, v) for k, v in counter.items() if len(v) >= 2), key=lambda kv: (-len(kv[1]), rank.get(kv[0][0], 9)))[:25]
    wanted = list(keys | {k for k, _ in common})
    labels = db.query(
        """
        SELECT g.NodeType, g.NodeID, g.Label, g.SubLabel
        FROM OPENJSON(?) WITH (t VARCHAR(15) '$.t', i BIGINT '$.i') AS w
        JOIN dbo.vw_GraphNode AS g ON g.NodeType = w.t AND g.NodeID = w.i;
        """, (json.dumps([{"t": t, "i": i} for t, i in wanted]),))
    common_keys = {k for k, _ in common}
    nodes = [{**n, "Lvl": 0 if (n["NodeType"], n["NodeID"]) in keys else 1} for n in labels]
    kept = keys | common_keys
    edges = [e for e in edges if (e["SourceType"], e["SourceID"]) in kept and (e["TargetType"], e["TargetID"]) in kept]
    common_out = [{"NodeType": k[0], "NodeID": k[1], "Connects": len(v),
                   "Label": next((n["Label"] for n in labels if (n["NodeType"], n["NodeID"]) == k), None)} for k, v in common]
    return {"nodes": nodes, "edges": edges, "common": common_out}


@router.delete("/{case_id}")
def delete_case(case_id: int, user: dict = Depends(require_analyst), db: Db = Depends(get_db)):
    if not db.execute("DELETE FROM dbo.Investigation WHERE InvestigationID = ?;", (case_id,)):
        raise HTTPException(404, "Vaka bulunamadı.")
    return {"ok": True}
