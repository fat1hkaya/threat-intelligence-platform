"""ATT&CK Navigator katmanı ve STIX 2.1 dışa aktarımı."""
from stix_check import validate

from app.api.exports import PATTERN, _lit
from conftest import needs_db


def test_stix_pattern_literal_escaping():
    assert _lit("a'b") == "'a\\'b'"
    assert _lit("c:\\x") == "'c:\\\\x'"
    assert PATTERN["sha256"] == "file:hashes.'SHA-256'"


@needs_db
def test_navigator_actor_layer(viewer, analyst):
    apt29 = next(a for a in viewer.get("/api/actors", params={"q": "APT29", "size": 5}).json()["items"] if a["Name"] == "APT29")
    r = viewer.get(f"/api/export/navigator/actor/{apt29['ActorID']}")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    layer = r.json()
    techs = analyst.get(f"/api/coverage/actor/{apt29['ActorID']}").json()["techniques"]
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert {t["techniqueID"] for t in layer["techniques"]} == {t["ExternalID"] for t in techs}
    cov = viewer.get(f"/api/export/navigator/actor/{apt29['ActorID']}", params={"coverage": "true"}).json()
    assert all(t["color"] in ("#34D399", "#FBBF24", "#F87171") for t in cov["techniques"]) and len(cov["legendItems"]) == 3
    assert viewer.get("/api/export/navigator/actor/999999999").status_code == 404


@needs_db
def test_navigator_coverage_layer(viewer):
    layer = viewer.get("/api/export/navigator/coverage").json()
    assert layer["techniques"] and all(t["score"] >= 0 for t in layer["techniques"])


@needs_db
def test_stix_indicator_bundle_is_valid_and_deterministic(viewer, linked_ioc):
    b1 = viewer.get(f"/api/export/stix/indicator/{linked_ioc['IndicatorID']}").json()
    assert validate(b1) == []
    ind = next(o for o in b1["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == f"[file:hashes.'SHA-256' = '{linked_ioc['Value']}']"
    mal = next(o for o in b1["objects"] if o["type"] == "malware" and o["name"] == linked_ioc["MalwareName"])
    assert any(o["type"] == "relationship" and o["source_ref"] == ind["id"] and o["target_ref"] == mal["id"]
               and o["relationship_type"] == "indicates" for o in b1["objects"])
    assert any(o["type"] == "intrusion-set" for o in b1["objects"])        # Cobalt Strike'ı kullanan aktörler
    b2 = viewer.get(f"/api/export/stix/indicator/{linked_ioc['IndicatorID']}").json()
    assert {o["id"] for o in b1["objects"]} == {o["id"] for o in b2["objects"]} and b1["id"] != b2["id"]


@needs_db
def test_stix_case_bundle_grouping(analyst, viewer, linked_ioc, unique):
    cid = analyst.post("/api/cases", json={"title": f"pytest stix {unique}", "summary": "özet"}).json()["InvestigationID"]
    try:
        assert viewer.get(f"/api/export/stix/case/{cid}").status_code == 400          # boş vaka
        analyst.post(f"/api/cases/{cid}/items", json={"type": "indicator", "id": linked_ioc["IndicatorID"]})
        analyst.post(f"/api/cases/{cid}/items", json={"type": "malware", "id": linked_ioc["MalwareID"]})
        analyst.post(f"/api/cases/{cid}/notes", json={"body": "STIX notu"})
        b = viewer.get(f"/api/export/stix/case/{cid}").json()
        assert validate(b) == []
        g = next(o for o in b["objects"] if o["type"] == "grouping")
        assert g["context"] == "suspicious-activity" and g["description"] == "özet"
        types = {o["id"].split("--")[0] for o in b["objects"] if o["id"] in g["object_refs"]}
        assert types == {"indicator", "malware", "relationship"}
        note = next(o for o in b["objects"] if o["type"] == "note")
        assert note["content"] == "STIX notu" and note["object_refs"] == [g["id"]]
    finally:
        analyst.delete(f"/api/cases/{cid}")


@needs_db
def test_stix_actor_bundle(viewer):
    apt29 = next(a for a in viewer.get("/api/actors", params={"q": "APT29", "size": 5}).json()["items"] if a["Name"] == "APT29")
    b = viewer.get(f"/api/export/stix/actor/{apt29['ActorID']}").json()
    assert validate(b) == []
    ap = [o for o in b["objects"] if o["type"] == "attack-pattern"]
    assert ap and all(o["external_references"][0]["source_name"] == "mitre-attack" for o in ap)
