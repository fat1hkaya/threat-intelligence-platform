"""abuse.ch kaynakları: ThreatFox, MalwareBazaar, URLhaus, Feodo Tracker.

Kullanım koşulları (Kasım 2026'da kontrol edildi):
- ThreatFox, MalwareBazaar ve URLhaus API'leri ücretsiz bir Auth-Key ister: https://auth.abuse.ch
  Anahtarı .env dosyasına ABUSECH_AUTH_KEY=... olarak yazın. Anahtar HTTP "Auth-Key" başlığıyla gönderilir.
- Kullanım "fair use" ilkesine tabidir; ticari kullanım ücretli abonelik gerektirebilir.
- Dökümleri 5 dakikadan sık çekmeyin. Bu modül her çalıştırmada tek istek yapar.
- MalwareBazaar'dan yalnızca özet (hash) ve aile bilgisi alınır; dosyanın kendisi ASLA indirilmez
  (get_file sorgusu kullanılmaz).
"""
import json
import os
import urllib.parse
import urllib.request

UA = "ThreatLens/1.0 (universite VTYS projesi)"


class FeedError(RuntimeError):
    pass


def _key() -> str:
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        raise FeedError("ABUSECH_AUTH_KEY tanımlı değil. Ücretsiz anahtar: https://auth.abuse.ch -> .env dosyasına ekleyin.")
    return key


def _post(url: str, data: bytes, content_type: str, auth: bool = True) -> dict:
    headers = {"User-Agent": UA, "Content-Type": content_type}
    if auth:
        headers["Auth-Key"] = _key()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=90) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{url} HTTP {exc.code}: {'Auth-Key geçersiz olabilir' if exc.code in (401, 403) else exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FeedError(f"{url} adresine ulaşılamadı: {exc.reason}") from exc


def _ts(value):
    """'2024-05-01 10:20:30 UTC' -> '2024-05-01T10:20:30'"""
    if not value:
        return None
    v = str(value).replace(" UTC", "").replace("Z", "").strip().replace(" ", "T")
    return v[:19] if len(v) >= 19 else (v[:10] + "T00:00:00" if len(v) >= 10 else None)


def threatfox(days: int = 1) -> tuple[str, list[dict]]:
    data = _post("https://threatfox-api.abuse.ch/api/v1/", json.dumps({"query": "get_iocs", "days": max(1, min(days, 7))}).encode(),
                 "application/json")
    if data.get("query_status") not in ("ok", "no_result"):
        raise FeedError(f"ThreatFox yanıtı: {data.get('query_status')}")
    kinds = {"domain": "domain", "url": "url", "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256", "ip:port": "ipv4"}
    items = []
    for r in data.get("data") or []:
        kind, value = kinds.get(r.get("ioc_type")), r.get("ioc")
        if not kind or not value:
            continue
        if kind == "ipv4":
            value = value.rsplit(":", 1)[0]
        malware = r.get("malware_printable")
        tags = r.get("tags") or []
        items.append({
            "type": kind, "value": value, "confidence": r.get("confidence_level"),
            "severity": "high" if r.get("threat_type") == "botnet_cc" else "medium", "tlp": "TLP:CLEAR",
            "malware": None if malware in (None, "", "Unknown malware") else malware,
            "role": "c2" if r.get("threat_type") == "botnet_cc" else "payload",
            "description": r.get("threat_type_desc"), "first_seen": _ts(r.get("first_seen")),
            "last_seen": _ts(r.get("last_seen")) or _ts(r.get("first_seen")),
            "evidence": f"ThreatFox IOC #{r.get('id')}: {r.get('threat_type_desc') or r.get('threat_type')}, "
                        f"raporlayan {r.get('reporter') or 'bilinmiyor'}" + (f", kaynak {r['reference']}" if r.get("reference") else ""),
            "tags": [t.lower() for t in (tags if isinstance(tags, list) else str(tags).split(",")) if t][:6],
        })
    return "abuse.ch ThreatFox", items


def malwarebazaar() -> tuple[str, list[dict]]:
    data = _post("https://mb-api.abuse.ch/api/v1/", urllib.parse.urlencode({"query": "get_recent", "selector": "100"}).encode(),
                 "application/x-www-form-urlencoded")
    if data.get("query_status") not in ("ok", "no_results"):
        raise FeedError(f"MalwareBazaar yanıtı: {data.get('query_status')}")
    items = []
    for r in data.get("data") or []:
        sig = r.get("signature")
        for kind, key in (("sha256", "sha256_hash"), ("md5", "md5_hash")):
            if r.get(key):
                items.append({
                    "type": kind, "value": r[key], "confidence": 90, "severity": "high", "tlp": "TLP:CLEAR",
                    "malware": sig, "role": "payload", "description": f"{r.get('file_type') or 'dosya'}: {r.get('file_name') or ''}"[:1000],
                    "first_seen": _ts(r.get("first_seen")), "last_seen": _ts(r.get("last_seen")) or _ts(r.get("first_seen")),
                    "evidence": f"MalwareBazaar örneği {r.get('sha256_hash', '')[:16]}..., imza: {sig or 'yok'}",
                    "tags": [t.lower() for t in (r.get("tags") or [])][:6],
                })
    return "abuse.ch MalwareBazaar", items


def urlhaus(limit: int = 1000) -> tuple[str, list[dict]]:
    req = urllib.request.Request(f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/",
                                 headers={"User-Agent": UA, "Auth-Key": _key()})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read())
    except urllib.error.URLError as exc:
        raise FeedError(f"URLhaus: {getattr(exc, 'reason', exc)}") from exc
    items = []
    for r in data.get("urls") or []:
        if not r.get("url") or len(r["url"]) > 400:
            continue
        items.append({
            "type": "url", "value": r["url"], "confidence": 85 if r.get("url_status") == "online" else 65,
            "severity": "medium", "tlp": "TLP:CLEAR", "role": "payload",
            "description": f"Tehdit: {r.get('threat')}", "first_seen": _ts(r.get("date_added")),
            "last_seen": _ts(r.get("last_online")) or _ts(r.get("date_added")),
            "tags": [t.lower() for t in (r.get("tags") or [])][:6],
        })
    return "abuse.ch URLhaus", items


def feodo() -> tuple[str, list[dict]]:
    """Feodo Tracker IP engelleme listesi (herkese açık döküm, anahtar gerekmez)."""
    req = urllib.request.Request("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            rows = json.loads(r.read())
    except urllib.error.URLError as exc:
        raise FeedError(f"Feodo Tracker: {getattr(exc, 'reason', exc)}") from exc
    return "abuse.ch Feodo Tracker", [{
        "type": "ipv4", "value": r["ip_address"], "confidence": 90 if r.get("status") == "online" else 75,
        "severity": "high", "tlp": "TLP:CLEAR", "malware": r.get("malware"), "role": "c2",
        "description": f"Botnet C2, port {r.get('port')}", "first_seen": _ts(r.get("first_seen")),
        "last_seen": _ts(r.get("last_online")) or _ts(r.get("first_seen")),
        "evidence": f"Feodo Tracker bu IP'yi {r.get('malware')} komuta sunucusu olarak listeliyor.", "tags": ["c2", "botnet"],
    } for r in rows if r.get("ip_address")]


FEEDS = {"threatfox": threatfox, "malwarebazaar": malwarebazaar, "urlhaus": urlhaus, "feodo": feodo}
