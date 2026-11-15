"""Dışa aktarma: MITRE ATT&CK Navigator katmanı ve STIX 2.1 paketi.

Navigator : https://mitre-attack.github.io/attack-navigator/ adresinde "Open Existing Layer > Upload from local" ile açılır.
STIX 2.1  : OASIS standardı; MISP, OpenCTI, TAXII sunucuları ve çoğu SIEM/TIP doğrudan içe alır.
Nesne kimlikleri belirlenimcidir (uuid5): aynı kayıt her dışa aktarımda aynı STIX kimliğini alır, karşı sistem
ikinci içe aktarımda kopya oluşturmak yerine günceller.
"""
import json
import uuid
from datetime import datetime, timezone
from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from .. import config
from ..db import Db, get_db
from ..security import current_user

router = APIRouter(prefix="/api/export", tags=["export"], dependencies=[Depends(current_user)])

NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/fat1hkaya/threat-intelligence-platform")
IDENTITY_ID = f"identity--{uuid.uuid5(NS, 'identity:threatlens')}"
# STIX 2.1 belirtiminde (7.2.1.4) tanımlı TLP işaretleme kimlikleri. TLP 2.0'daki CLEAR, 1.0'daki WHITE'a karşılık gelir.
TLP_MARKING = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
STIX_TYPE = {"indicator": "indicator", "malware": "malware", "actor": "intrusion-set", "campaign": "campaign",
             "technique": "attack-pattern", "vulnerability": "vulnerability"}
COV_COLOR = {2: "#34D399", 1: "#FBBF24", 0: "#F87171"}
COV_LABEL = {2: "tam", 1: "kısmi", 0: "yok"}


def _download(payload: dict, filename: str) -> JSONResponse:
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@lru_cache(maxsize=1)
def _attack_version() -> str:
    try:
        meta = json.loads((config.ROOT / "database" / "seed" / "attack_snapshot.json").read_text(encoding="utf-8"))["meta"]
        return str(meta.get("version", "")).split(".")[0] or "16"
    except (OSError, ValueError, KeyError):
        return "16"


# ================================================================ ATT&CK Navigator
def _layer(name: str, description: str, techniques: list[dict], legend: list[dict], gradient_max: int = 1) -> dict:
    return {
        "name": name, "description": description, "domain": "enterprise-attack",
        "versions": {"attack": _attack_version(), "navigator": "5.1.0", "layer": "4.5"},
        "sorting": 3, "hideDisabled": False,
        "layout": {"layout": "side", "showName": True, "showID": True, "aggregateFunction": "max"},
        "gradient": {"colors": ["#DDD6FE", "#7C5CFC"], "minValue": 0, "maxValue": max(gradient_max, 1)},
        "techniques": techniques, "legendItems": legend,
        "metadata": [{"name": "Kaynak", "value": "ThreatLens"},
                     {"name": "Oluşturulma", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}],
        "showTacticRowBackground": True, "tacticRowBackground": "#1F2D48", "selectSubtechniquesWithParent": False,
    }


def _has_coverage(db: Db) -> bool:
    return bool(db.scalar("SELECT COUNT(*) AS N FROM dbo.DetectionCoverage;"))


@router.get("/navigator/actor/{actor_id}")
def navigator_actor(actor_id: int, coverage: bool | None = None, db: Db = Depends(get_db)):
    """Aktörün teknikleri. Kurum kapsama beyanı varsa renk tespit düzeyini gösterir (kırmızı = kör nokta)."""
    actor = db.one("SELECT ActorID, Name, ExternalID FROM dbo.ThreatActor WHERE ActorID = ?;", (actor_id,))
    if not actor:
        raise HTTPException(404, "Aktör bulunamadı.")
    rows = (db.query_sets("EXEC dbo.sp_ActorCoverage @ActorID = ?;", (actor_id,)) + [[]])[0]
    use_cov = _has_coverage(db) if coverage is None else coverage
    techniques = []
    for r in rows:
        t = {"techniqueID": r["ExternalID"], "enabled": True, "showSubtechniques": "." in r["ExternalID"],
             "comment": f"{r['Name']} · bu tekniği kullanan aktör sayısı: {r['ActorCount']}"}
        if use_cov:
            lvl = int(r["Level"] or 0)
            t.update(color=COV_COLOR[lvl], score=lvl,
                     comment=t["comment"] + f" · tespit: {COV_LABEL[lvl]}" + (f" ({r['DataSource']})" if r.get("DataSource") else "")
                     + (" · üst teknikten devralındı" if r.get("Inherited") else ""))
        else:
            t["score"] = 1
        techniques.append(t)
    legend = ([{"label": "Tespit: tam", "color": COV_COLOR[2]}, {"label": "Tespit: kısmi", "color": COV_COLOR[1]},
               {"label": "Kör nokta", "color": COV_COLOR[0]}] if use_cov else [{"label": f"{actor['Name']} kullanıyor", "color": "#7C5CFC"}])
    desc = f"{actor['Name']} ({actor['ExternalID'] or 'ATT&CK dışı'}) tarafından kullanılan {len(rows)} teknik"
    desc += ", kurumun tespit kapsamıyla birlikte." if use_cov else "."
    layer = _layer(f"{actor['Name']}" + (" · tespit kapsamı" if use_cov else ""), desc, techniques, legend)
    slug = "".join(ch if ch.isalnum() else "_" for ch in actor["Name"]).strip("_").lower()
    return _download(layer, f"navigator_{slug}.json")


@router.get("/navigator/coverage")
def navigator_coverage(db: Db = Depends(get_db)):
    """Kurumun tespit kapsamı. Hiçbir düzeyi işaretlenmemiş ama en az bir aktörün kullandığı teknikler kırmızı;
    skor = o tekniği kullanan aktör sayısı (öncelik sırası)."""
    rows = db.query(
        """
        SELECT t.ExternalID, t.Name, ec.Level, ec.Inherited, ec.DataSource,
               (SELECT COUNT(*) FROM dbo.ActorTechnique AS x WHERE x.TechniqueID = t.TechniqueID) AS ActorCount
        FROM dbo.Technique AS t
        JOIN dbo.fn_EffectiveCoverage() AS ec ON ec.TechniqueID = t.TechniqueID
        WHERE ec.Level > 0 OR EXISTS (SELECT 1 FROM dbo.ActorTechnique AS x WHERE x.TechniqueID = t.TechniqueID);
        """)
    techniques = [{
        "techniqueID": r["ExternalID"], "enabled": True, "score": r["ActorCount"], "color": COV_COLOR[int(r["Level"])],
        "showSubtechniques": "." in r["ExternalID"],
        "comment": f"{r['Name']} · tespit: {COV_LABEL[int(r['Level'])]}" + (f" ({r['DataSource']})" if r["DataSource"] else "")
                   + f" · kullanan aktör: {r['ActorCount']}",
    } for r in rows]
    gaps = sum(1 for r in rows if not r["Level"])
    legend = [{"label": "Tespit: tam", "color": COV_COLOR[2]}, {"label": "Tespit: kısmi", "color": COV_COLOR[1]},
              {"label": "Kör nokta (aktörlerce kullanılıyor)", "color": COV_COLOR[0]}]
    layer = _layer("ThreatLens · tespit kapsamı", f"{len(rows) - gaps} teknik işaretli, aktörlerin kullandığı {gaps} teknikte kör nokta.",
                   techniques, legend, max((r["ActorCount"] for r in rows), default=1))
    return _download(layer, "navigator_tespit_kapsami.json")


# ================================================================ STIX 2.1
def _ts(v) -> str:
    """STIX zaman damgası: UTC, milisaniyeli, Z son ekli."""
    if v is None:
        v = datetime.now(timezone.utc)
    if isinstance(v, str):
        v = datetime.fromisoformat(v)
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{v.microsecond // 1000:03d}Z"


def _sid(kind: str, key) -> str:
    return f"{STIX_TYPE.get(kind, kind)}--{uuid.uuid5(NS, f'{kind}:{key}')}"


def _lit(value: str) -> str:
    """STIX desen dizgisi: ters eğik çizgi ve tek tırnak kaçışlanır."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


PATTERN = {
    "ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value", "url": "url:value",
    "email": "email-addr:value", "md5": "file:hashes.MD5", "sha1": "file:hashes.'SHA-1'", "sha256": "file:hashes.'SHA-256'",
}


def _identity() -> dict:
    return {"type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z", "name": "ThreatLens", "identity_class": "system",
            "description": "ThreatLens tehdit istihbaratı platformu (MSSQL Graph)"}


FIXED_CREATED = "2026-01-01T00:00:00.000Z"   # kendi zaman damgası olmayan kayıtlar (teknik, ilişki): created değişmez olmalı


def _common(created=None, modified=None) -> dict:
    c = _ts(created) if created else FIXED_CREATED
    m = _ts(modified) if modified else c
    return {"spec_version": "2.1", "created": c, "modified": max(c, m), "created_by_ref": IDENTITY_ID}


def _ext(source: str, external_id, url: str | None = None) -> list[dict]:
    if not external_id:
        return []
    ref = {"source_name": source, "external_id": external_id}
    if url:
        ref["url"] = url
    return [ref]


def _attack_url(ext_id: str, kind: str) -> str:
    base = {"technique": "techniques", "malware": "software", "actor": "groups", "campaign": "campaigns"}[kind]
    return f"https://attack.mitre.org/{base}/{ext_id.replace('.', '/')}/"


def _stix_objects(db: Db, keys: set[tuple[str, int]]) -> dict[tuple, dict]:
    """(tür, kimlik) kümesi -> STIX nesneleri. Her tür tek bir küme sorgusuyla (OPENJSON) okunur."""
    out: dict[tuple, dict] = {}
    ids = lambda t: json.dumps([i for k, i in keys if k == t])  # noqa: E731
    if any(k == "indicator" for k, _ in keys):
        for r in db.query(
                """SELECT v.IndicatorID, v.Value, v.TypeCode, v.Confidence, v.TLPCode, v.Description, v.FirstSeen, v.ExpiresAt,
                          v.CreatedAt, v.UpdatedAt, v.SeverityCode, v.SourceName, v.Status
                   FROM OPENJSON(?) WITH (id BIGINT '$') AS j JOIN dbo.vw_Indicator AS v ON v.IndicatorID = j.id;""", (ids("indicator"),)):
            valid_from = r["FirstSeen"] or r["CreatedAt"]
            o = {"type": "indicator", "id": _sid("indicator", r["IndicatorID"]), **_common(r["CreatedAt"], r["UpdatedAt"]),
                 "name": r["Value"], "pattern": f"[{PATTERN[r['TypeCode']]} = {_lit(r['Value'])}]", "pattern_type": "stix",
                 "valid_from": _ts(valid_from), "indicator_types": ["malicious-activity"],
                 "confidence": int(r["Confidence"]) if r["Confidence"] is not None else None,
                 "labels": [f"severity:{r['SeverityCode']}", f"source:{r['SourceName']}", f"status:{r['Status']}"],
                 "description": r["Description"]}
            if r["ExpiresAt"] and r["ExpiresAt"] > valid_from:
                o["valid_until"] = _ts(r["ExpiresAt"])
            if r["TLPCode"] in TLP_MARKING:
                o["object_marking_refs"] = [TLP_MARKING[r["TLPCode"]]]
            out[("indicator", r["IndicatorID"])] = o
    if any(k == "malware" for k, _ in keys):
        for r in db.query(
                """SELECT m.MalwareID, m.Name, m.ExternalID, m.Description, m.CreatedAt, m.UpdatedAt,
                          (SELECT STRING_AGG(a.Alias, '|') FROM dbo.MalwareAlias AS a WHERE a.MalwareID = m.MalwareID) AS Aliases
                   FROM OPENJSON(?) WITH (id INT '$') AS j JOIN dbo.Malware AS m ON m.MalwareID = j.id;""", (ids("malware"),)):
            o = {"type": "malware", "id": _sid("malware", r["MalwareID"]), **_common(r["CreatedAt"], r["UpdatedAt"]), "name": r["Name"], "is_family": True,
                 "description": r["Description"], "aliases": sorted(set(filter(None, (r["Aliases"] or "").split("|"))) - {r["Name"]}) or None,
                 "external_references": _ext("mitre-attack", r["ExternalID"], r["ExternalID"] and _attack_url(r["ExternalID"], "malware")) or None}
            out[("malware", r["MalwareID"])] = o
    if any(k == "actor" for k, _ in keys):
        for r in db.query(
                """SELECT a.ActorID, a.Name, a.ExternalID, a.Description, a.CreatedAt, a.UpdatedAt,
                          (SELECT STRING_AGG(x.Alias, '|') FROM dbo.ActorAlias AS x WHERE x.ActorID = a.ActorID) AS Aliases
                   FROM OPENJSON(?) WITH (id INT '$') AS j JOIN dbo.ThreatActor AS a ON a.ActorID = j.id;""", (ids("actor"),)):
            out[("actor", r["ActorID"])] = {
                "type": "intrusion-set", "id": _sid("actor", r["ActorID"]), **_common(r["CreatedAt"], r["UpdatedAt"]), "name": r["Name"], "description": r["Description"],
                "aliases": sorted(set(filter(None, (r["Aliases"] or "").split("|"))) - {r["Name"]}) or None,
                "external_references": _ext("mitre-attack", r["ExternalID"], r["ExternalID"] and _attack_url(r["ExternalID"], "actor")) or None}
    if any(k == "campaign" for k, _ in keys):
        for r in db.query(
                """SELECT c.CampaignID, c.Name, c.ExternalID, c.Description, c.StartDate, c.EndDate, c.CreatedAt, c.UpdatedAt
                   FROM OPENJSON(?) WITH (id INT '$') AS j JOIN dbo.Campaign AS c ON c.CampaignID = j.id;""", (ids("campaign"),)):
            o = {"type": "campaign", "id": _sid("campaign", r["CampaignID"]), **_common(r["CreatedAt"], r["UpdatedAt"]), "name": r["Name"], "description": r["Description"],
                 "external_references": _ext("mitre-attack", r["ExternalID"], r["ExternalID"] and _attack_url(r["ExternalID"], "campaign")) or None}
            if r["StartDate"]:
                o["first_seen"] = _ts(datetime.combine(r["StartDate"], datetime.min.time()))
            if r["EndDate"] and (not r["StartDate"] or r["EndDate"] >= r["StartDate"]):
                o["last_seen"] = _ts(datetime.combine(r["EndDate"], datetime.min.time()))
            out[("campaign", r["CampaignID"])] = o
    if any(k == "technique" for k, _ in keys):
        for r in db.query(
                """SELECT t.TechniqueID, t.ExternalID, t.Name, t.Description,
                          (SELECT STRING_AGG(ta.ShortName, '|') FROM dbo.TechniqueTactic AS tt JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID
                            WHERE tt.TechniqueID = t.TechniqueID) AS Phases
                   FROM OPENJSON(?) WITH (id INT '$') AS j JOIN dbo.Technique AS t ON t.TechniqueID = j.id;""", (ids("technique"),)):
            o = {"type": "attack-pattern", "id": _sid("technique", r["TechniqueID"]), **_common(), "name": r["Name"],
                 "description": r["Description"], "external_references": _ext("mitre-attack", r["ExternalID"], _attack_url(r["ExternalID"], "technique"))}
            phases = [p for p in (r["Phases"] or "").split("|") if p]
            if phases:
                o["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases]
            out[("technique", r["TechniqueID"])] = o
    if any(k == "vulnerability" for k, _ in keys):
        for r in db.query(
                """SELECT v.VulnerabilityID, v.CveID, v.Title, v.Description
                   FROM OPENJSON(?) WITH (id INT '$') AS j JOIN dbo.Vulnerability AS v ON v.VulnerabilityID = j.id;""", (ids("vulnerability"),)):
            out[("vulnerability", r["VulnerabilityID"])] = {
                "type": "vulnerability", "id": _sid("vulnerability", r["VulnerabilityID"]), **_common(), "name": r["CveID"],
                "description": r["Description"] or r["Title"], "external_references": _ext("cve", r["CveID"])}
    for o in out.values():                      # STIX'te boş/None özellik yazılmaz
        for k in [k for k, v in o.items() if v is None or v == []]:
            del o[k]
    return out


def _relationships(db: Db, objects: dict[tuple, dict]) -> list[dict]:
    """Seçili nesneler arasındaki graf kenarları -> STIX relationship (MATCH tabanlı vw_GraphEdge)."""
    payload = json.dumps([{"t": t, "i": i} for t, i in objects])
    edges = db.query(
        """
        WITH k AS (SELECT t, i FROM OPENJSON(?) WITH (t VARCHAR(15) '$.t', i BIGINT '$.i'))
        SELECT e.SourceType, e.SourceID, e.TargetType, e.TargetID, e.Relation, e.Confidence
        FROM dbo.vw_GraphEdge AS e
        JOIN k AS s ON s.t = e.SourceType AND s.i = e.SourceID
        JOIN k AS d ON d.t = e.TargetType AND d.i = e.TargetID;
        """, (payload,))
    rels = []
    for e in edges:
        src, dst = (e["SourceType"], e["SourceID"]), (e["TargetType"], e["TargetID"])
        rel = {"type": "relationship", "id": f"relationship--{uuid.uuid5(NS, f'rel:{src}:{e['Relation']}:{dst}')}", **_common(),
               "relationship_type": e["Relation"], "source_ref": objects[src]["id"], "target_ref": objects[dst]["id"]}
        if e["Confidence"] is not None:
            rel["confidence"] = int(e["Confidence"])
        rels.append(rel)
    return rels


def _bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [_identity(), *objects]}


@router.get("/stix/indicator/{indicator_id}")
def stix_indicator(indicator_id: int, db: Db = Depends(get_db)):
    """IOC + bağlı zararlı yazılımlar + bu zararlıları kullanan aktörler ve aralarındaki ilişkiler."""
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.Indicator WHERE IndicatorID = ?;", (indicator_id,)):
        raise HTTPException(404, "IOC bulunamadı.")
    keys = {("indicator", indicator_id)}
    for r in db.query(
            """SELECT mi.MalwareID, am.ActorID FROM dbo.MalwareIndicator AS mi
               LEFT JOIN dbo.ActorMalware AS am ON am.MalwareID = mi.MalwareID WHERE mi.IndicatorID = ?;""", (indicator_id,)):
        keys.add(("malware", r["MalwareID"]))
        if r["ActorID"]:
            keys.add(("actor", r["ActorID"]))
    objects = _stix_objects(db, keys)
    return _download(_bundle([*objects.values(), *_relationships(db, objects)]), f"stix_ioc_{indicator_id}.json")


@router.get("/stix/case/{case_id}")
def stix_case(case_id: int, db: Db = Depends(get_db)):
    """Vaka -> STIX 'grouping' (bağlam: suspicious-activity) + öğeleri + aralarındaki ilişkiler + notlar ('note')."""
    case = db.one("SELECT InvestigationID, Title, Summary, Status, CreatedAt, UpdatedAt FROM dbo.Investigation WHERE InvestigationID = ?;", (case_id,))
    if not case:
        raise HTTPException(404, "Vaka bulunamadı.")
    keys = {(r["NodeType"], r["NodeID"]) for r in db.query(
        "SELECT NodeType, NodeID FROM dbo.vw_InvestigationItem WHERE InvestigationID = ?;", (case_id,))}
    if not keys:
        raise HTTPException(400, "Vakada dışa aktarılacak öğe yok.")
    objects = _stix_objects(db, keys)
    rels = _relationships(db, objects)
    grouping = {"type": "grouping", "id": f"grouping--{uuid.uuid5(NS, f'case:{case_id}')}", **_common(case["CreatedAt"], case["UpdatedAt"]),
                "name": f"#{case_id} {case['Title']}", "context": "suspicious-activity",
                "object_refs": [o["id"] for o in objects.values()] + [r["id"] for r in rels]}
    if case["Summary"]:
        grouping["description"] = case["Summary"]
    notes = [{"type": "note", "id": f"note--{uuid.uuid5(NS, f'case-note:{n['NoteID']}')}", **_common(n["CreatedAt"]),
              "content": n["Body"], "authors": [n["Author"] or "ThreatLens"], "object_refs": [grouping["id"]]}
             for n in db.query(
                 """SELECT n.NoteID, n.CreatedAt, n.Body, u.FullName AS Author FROM dbo.InvestigationNote AS n
                    LEFT JOIN dbo.AppUser AS u ON u.UserID = n.AuthorID WHERE n.InvestigationID = ? ORDER BY n.CreatedAt;""", (case_id,))]
    return _download(_bundle([grouping, *objects.values(), *rels, *notes]), f"stix_vaka_{case_id}.json")


@router.get("/stix/actor/{actor_id}")
def stix_actor(actor_id: int, db: Db = Depends(get_db)):
    """Aktör (intrusion-set) + kullandığı araçlar, teknikler ve atfedilen kampanyalar."""
    if not db.scalar("SELECT COUNT(*) AS N FROM dbo.ThreatActor WHERE ActorID = ?;", (actor_id,)):
        raise HTTPException(404, "Aktör bulunamadı.")
    keys = {("actor", actor_id)}
    keys |= {("malware", r["MalwareID"]) for r in db.query("SELECT MalwareID FROM dbo.ActorMalware WHERE ActorID = ?;", (actor_id,))}
    keys |= {("technique", r["TechniqueID"]) for r in db.query("SELECT TechniqueID FROM dbo.ActorTechnique WHERE ActorID = ?;", (actor_id,))}
    keys |= {("campaign", r["CampaignID"]) for r in db.query("SELECT CampaignID FROM dbo.Campaign WHERE ActorID = ?;", (actor_id,))}
    objects = _stix_objects(db, keys)
    name = db.scalar("SELECT Name FROM dbo.ThreatActor WHERE ActorID = ?;", (actor_id,))
    slug = "".join(ch if ch.isalnum() else "_" for ch in name).strip("_").lower()
    return _download(_bundle([*objects.values(), *_relationships(db, objects)]), f"stix_{slug}.json")
