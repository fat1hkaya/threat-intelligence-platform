"""STIX 2.1 paketleri için hafif yapısal doğrulayıcı (dış kütüphane gerektirmez).
Belirtimin zorunlu kurallarının test edilebilir alt kümesi: kimlik biçimi, ortak özellikler, zaman damgası,
tür başına zorunlu alanlar, desen sözdizimi ve başvuruların paket içinde çözülmesi."""
import re
import uuid

TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
ID = re.compile(r"^([a-z0-9-]+)--([0-9a-f-]{36})$")
REQUIRED = {
    "identity": ["name"],
    "indicator": ["pattern", "pattern_type", "valid_from"],
    "malware": ["name", "is_family"],
    "intrusion-set": ["name"],
    "campaign": ["name"],
    "attack-pattern": ["name"],
    "vulnerability": ["name"],
    "relationship": ["relationship_type", "source_ref", "target_ref"],
    "grouping": ["context", "object_refs"],
    "note": ["content", "object_refs"],
}
# [nesne-türü:özellik = 'değer'] ; özellik yolu hashes.'SHA-256' gibi tırnaklı bileşen içerebilir
PATTERN = re.compile(r"^\[[a-z0-9-]+:[a-z0-9_]+(\.('[A-Za-z0-9-]+'|[A-Za-z0-9_]+))* = '(?:[^'\\]|\\.)*'\]$")
TLP_IDS = {"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
           "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"}


def validate(bundle: dict) -> list[str]:
    errors: list[str] = []
    if bundle.get("type") != "bundle" or not ID.match(bundle.get("id", "")) or not bundle["id"].startswith("bundle--"):
        return ["paket türü/kimliği geçersiz"]
    objs = bundle.get("objects") or []
    ids = {o.get("id") for o in objs}
    if len(ids) != len(objs):
        errors.append("aynı kimlik birden çok kez kullanılmış")
    for o in objs:
        oid, typ = o.get("id", ""), o.get("type")
        m = ID.match(oid)
        if not m or m.group(1) != typ:
            errors.append(f"{oid}: kimlik türle uyuşmuyor")
            continue
        try:
            uuid.UUID(m.group(2))
        except ValueError:
            errors.append(f"{oid}: UUID geçersiz")
        if o.get("spec_version") != "2.1":
            errors.append(f"{oid}: spec_version 2.1 değil")
        for k in ("created", "modified"):
            if not TS.match(o.get(k, "")):
                errors.append(f"{oid}: {k} zaman damgası geçersiz")
        if o.get("modified", "") < o.get("created", ""):
            errors.append(f"{oid}: modified < created")
        for k in REQUIRED.get(typ, []):
            if o.get(k) in (None, "", []):
                errors.append(f"{oid}: zorunlu '{k}' eksik")
        for k, v in o.items():
            if v is None or v == [] or v == "":
                errors.append(f"{oid}: '{k}' boş bırakılmamalı (özellik hiç yazılmamalı)")
        if typ == "indicator":
            if not PATTERN.match(o.get("pattern", "")):
                errors.append(f"{oid}: desen sözdizimi geçersiz: {o.get('pattern')}")
            if "valid_until" in o and o["valid_until"] <= o["valid_from"]:
                errors.append(f"{oid}: valid_until <= valid_from")
        if "confidence" in o and not (0 <= o["confidence"] <= 100):
            errors.append(f"{oid}: confidence 0-100 dışında")
        refs = [o.get("created_by_ref"), o.get("source_ref"), o.get("target_ref"), *(o.get("object_refs") or [])]
        for r in filter(None, refs):
            if r not in ids:
                errors.append(f"{oid}: başvuru paket içinde yok: {r}")
        for r in o.get("object_marking_refs") or []:
            if r not in TLP_IDS and r not in ids:
                errors.append(f"{oid}: bilinmeyen işaretleme {r}")
    return errors
