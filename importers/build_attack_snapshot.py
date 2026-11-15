"""MITRE ATT&CK (Enterprise) STIX paketini, sp_ImportAttackBundle'ın beklediği
sade JSON biçimine indirger.

Kullanım:
    python -m importers.build_attack_snapshot                 # GitHub'dan indirir
    python -m importers.build_attack_snapshot enterprise.json # yerel dosyadan

Çıktı: database/seed/attack_snapshot.json
Her ilişkinin ATT&CK'teki açıklaması ve kaynak bağlantısı kanıt (Evidence) olarak taşınır.

Not: ATT&CK aktörün ülkesini, motivasyonunu ve zararlının türünü yapılı alan
olarak vermez. Bunlar açıklama metnindeki anahtar sözcüklerden çıkarılır;
emin olunamayan kayıtlar boş bırakılır ve arayüzden düzeltilebilir.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parent.parent / "database" / "seed" / "attack_snapshot.json"

COUNTRY_HINTS = [
    ("KP", r"north korea|dprk"), ("RU", r"russia"), ("CN", r"chin(?:a|ese)|\bprc\b"), ("IR", r"iran"),
    ("VN", r"vietnam"), ("PK", r"pakistan"), ("IN", r"\bindia"), ("KR", r"south korea"),
    ("TR", r"turk(ey|ish)"), ("LB", r"leban"), ("SY", r"syria"), ("BY", r"belarus"),
    ("UA", r"ukrain"), ("AE", r"united arab emirates"), ("NG", r"nigeria"), ("BR", r"brazil"),
]
ORIGIN = r"(?:{c})\w*\)?[\s-]{{0,2}}(?:based|state-sponsored|sponsored|linked|nexus|threat (?:group|actor)|cyber ?espionage|actor|group)|(?:attributed to|based in|operating (?:out of|from)|originat\w+ (?:in|from)|sponsored by|on behalf of|element within)[\w\s,'-]{{0,40}}?(?:{c})"

MALWARE_TYPES = [
    ("ransomware", r"ransomware"), ("wiper", r"\bwiper|wiping|destructive malware"),
    ("webshell", r"web ?shell"), ("rootkit", r"rootkit|bootkit"),
    ("banker", r"banking (?:trojan|malware)"), ("stealer", r"stealer|infostealer|credential[- ]stealing"),
    ("rat", r"remote access (?:trojan|tool)|\brat\b"), ("loader", r"\bloader|downloader|dropper"),
    ("botnet", r"botnet"), ("backdoor", r"backdoor"),
]


def clean(text: str, limit: int) -> str:
    if not text:
        return ""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r"[ \t]+", " ", text).strip()
    text = re.sub(r"\s+([.,;])", r"\1", text)
    first = text.split("\n\n")[0].strip()
    if len(first) > limit:
        cut = first[:limit]
        first = cut[: cut.rfind(". ") + 1] if ". " in cut[limit // 2:] else cut[: limit - 1].rstrip() + "…"
    return first


def ext_id(obj) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def alive(obj) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def guess_country(desc: str) -> str | None:
    # Yalnızca ilk cümle: sonraki cümleler genellikle hedef ülkeleri sayar
    head = re.split(r"(?<=[a-z\)])\. ", desc, maxsplit=1)[0][:400].lower()
    for code, pat in COUNTRY_HINTS:
        if re.search(ORIGIN.format(c=pat), head):
            return code
    return None


def guess_motivation(desc: str) -> int | None:
    d = desc.lower()
    if re.search(r"financially[- ]motivated|financial gain|cybercrim|ransomware|extortion|banking", d):
        return 2
    if re.search(r"espionage|state-sponsored|intelligence|nation-state|government-backed|military", d):
        return 1
    if re.search(r"hacktivis", d):
        return 3
    if re.search(r"destructive|sabotage|disrupt", d):
        return 4
    return None


def guess_type(obj, desc: str) -> str:
    if obj["type"] == "tool":
        return "tool"
    head = desc[:300].lower()
    for code, pat in MALWARE_TYPES:
        if re.search(pat, head):
            return code
    return "malware"


def unique_name(name: str, eid: str, seen: set) -> str:
    name = name[:100]
    if name.lower() in seen:
        name = f"{name[:88]} ({eid})"
    seen.add(name.lower())
    return name


def main() -> None:
    if len(sys.argv) > 1:
        raw = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        print("ATT&CK indiriliyor...")
        with urllib.request.urlopen(URL, timeout=120) as r:
            raw = r.read().decode("utf-8")
    objs = json.loads(raw)["objects"]
    by_id = {o["id"]: o for o in objs}

    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics = []
    for order, ref in enumerate(matrix["tactic_refs"], start=1):
        t = by_id[ref]
        tactics.append({"id": ext_id(t), "short": t["x_mitre_shortname"], "name": t["name"],
                        "desc": clean(t.get("description", ""), 900), "order": order})

    techniques, stix_to_ext = [], {}
    for o in objs:
        if o["type"] == "attack-pattern" and alive(o) and ext_id(o):
            eid = ext_id(o)
            stix_to_ext[o["id"]] = eid
            techniques.append({
                "id": eid, "name": o["name"][:150], "desc": clean(o.get("description", ""), 700),
                "parent": eid.split(".")[0] if "." in eid else None,
                "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            })
    known_tech = {t["id"] for t in techniques}
    for t in techniques:
        if t["parent"] and t["parent"] not in known_tech:
            t["parent"] = None

    actors, seen = [], set()
    for o in objs:
        if o["type"] == "intrusion-set" and alive(o) and ext_id(o):
            eid = ext_id(o)
            stix_to_ext[o["id"]] = eid
            desc = clean(o.get("description", ""), 1500)
            name = unique_name(o["name"], eid, seen)
            actors.append({"id": eid, "name": name, "desc": desc,
                           "aliases": sorted({a[:100] for a in o.get("aliases", []) if a != o["name"]}),
                           "country": guess_country(desc), "motivation": guess_motivation(desc)})

    software, seen = [], set()
    for o in objs:
        if o["type"] in ("malware", "tool") and alive(o) and ext_id(o):
            eid = ext_id(o)
            stix_to_ext[o["id"]] = eid
            desc = clean(o.get("description", ""), 900)
            name = unique_name(o["name"], eid, seen)
            software.append({"id": eid, "name": name, "desc": desc, "type": guess_type(o, desc),
                             "platforms": ", ".join(o.get("x_mitre_platforms", []))[:200] or None,
                             "aliases": sorted({a[:100] for a in o.get("x_mitre_aliases", []) if a != o["name"]})})

    def first_url(o):
        return next((r.get("url") for r in o.get("external_references", []) if r.get("url") and r.get("source_name") != "mitre-attack"), None)

    campaigns, seen, attributions = [], set(), {}
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "attributed-to" and alive(o):
            attributions[o["source_ref"]] = o
    for o in objs:
        if o["type"] == "campaign" and alive(o) and ext_id(o):
            eid = ext_id(o)
            stix_to_ext[o["id"]] = eid
            campaigns.append({"id": eid, "name": unique_name(o["name"], eid, seen)[:150],
                              "desc": clean(o.get("description", ""), 1500),
                              "first": (o.get("first_seen") or "")[:10] or None,
                              "last": (o.get("last_seen") or "")[:10] or None,
                              "actor": None, "_stix": o["id"]})
    rel = {k: [] for k in ("actor_software", "actor_technique", "software_technique", "campaign_software", "campaign_technique", "campaign_actor")}
    for c in campaigns:
        att = attributions.get(c.pop("_stix"))
        if att and att["target_ref"] in stix_to_ext:
            c["actor"] = stix_to_ext[att["target_ref"]]
            rel["campaign_actor"].append([c["id"], c["actor"], clean(att.get("description", ""), 900) or None, att["id"], first_url(att)])

    kind = {"intrusion-set": "actor", "malware": "software", "tool": "software", "campaign": "campaign", "attack-pattern": "technique"}
    seen_pairs = set()
    for o in objs:
        if o["type"] != "relationship" or o["relationship_type"] != "uses" or not alive(o):
            continue
        s_, t_ = o["source_ref"], o["target_ref"]
        key = f"{kind.get(s_.split('--')[0])}_{kind.get(t_.split('--')[0])}"
        if key in rel and s_ in stix_to_ext and t_ in stix_to_ext and (key, s_, t_) not in seen_pairs:
            seen_pairs.add((key, s_, t_))
            rel[key].append([stix_to_ext[s_], stix_to_ext[t_], clean(o.get("description", ""), 900) or None, o["id"], first_url(o)])

    collection = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    bundle = {
        "meta": {"source": "MITRE ATT&CK Enterprise", "version": collection.get("x_mitre_version"),
                 "license": "© The MITRE Corporation. ATT&CK kullanım koşulları: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"},
        "tactics": tactics, "techniques": techniques, "actors": actors, "software": software, "campaigns": campaigns,
        "rel": {k: sorted(v, key=lambda r: (r[0], r[1])) for k, v in rel.items()},
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(bundle, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"{OUT.name}: {OUT.stat().st_size / 1e6:.1f} MB | taktik {len(tactics)}, teknik {len(techniques)}, "
          f"aktör {len(actors)}, yazılım {len(software)}, kampanya {len(campaigns)}, "
          f"ilişki {sum(len(v) for v in rel.values())}")
    print("ülke atanan aktör:", sum(1 for a in actors if a["country"]), "| motivasyon atanan:", sum(1 for a in actors if a["motivation"]))


if __name__ == "__main__":
    main()
