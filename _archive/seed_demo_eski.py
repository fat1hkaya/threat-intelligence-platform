"""Sunum için sentetik veri üretir. GERÇEK TEHDİT VERİSİ DEĞİLDİR.

- IP adresleri RFC 5737 belgeleme aralıklarındandır (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Alan adları RFC 2606 ayrılmış uzantılarını kullanır (.example, .test, .invalid).
- Özet (hash) değerleri rastgeledir.
Göstergeler gerçek zararlı aile adlarına bağlanır ki ilişki grafı ve atıf zinciri anlamlı görünsün;
hepsi "demo" etiketi taşır ve "Demo veri üreteci" kaynağına yazılır.

Zafiyet kayıtları (CVE numarası, başlık, CVSS) herkese açık gerçek bilgilerdir.
"""
import json
import random
from datetime import datetime, timedelta, timezone

from _common import connect, source_id

FAMILIES = ["Emotet", "TrickBot", "QakBot", "Cobalt Strike", "AsyncRAT", "Agent Tesla", "LockBit 3.0", "Conti", "Ryuk",
            "IcedID", "njRAT", "Remcos", "BlackCat", "Akira", "Black Basta", "Clop", "PlugX", "ShadowPad", "Sliver",
            "Brute Ratel C4", "SUNBURST", "WannaCry", "NotPetya", "DarkGate", "Pikabot", "Bumblebee", "Raccoon Stealer",
            "Lumma Stealer", "RedLine Stealer", "Mimikatz", "Royal", "Play", "Rhysida", "BlackByte", "Latrodectus"]
WORDS = ["update", "cdn", "secure", "portal", "mail", "login", "sync", "static", "files", "cloud", "auth", "api",
         "docs", "support", "invoice", "track", "media", "node", "relay", "gate"]
PATHS = ["gate.php", "load/update.bin", "wp-content/x.dll", "invoice.zip", "dl/setup.msi", "a/b/payload.exe", "panel/login"]
LOCATIONS = ["SIEM / güvenlik duvarı", "EDR / WS-0142", "EDR / SRV-DB-03", "E-posta ağ geçidi", "Web vekil sunucusu", "DNS kayıtları"]
SEVERITY_BY_TYPE = {"ransomware": ["high", "critical", "critical"], "wiper": ["critical"], "rat": ["medium", "high"],
                    "backdoor": ["high", "high", "critical"], "stealer": ["medium", "high"], "loader": ["medium", "high"],
                    "tool": ["low", "medium"], "banker": ["medium", "high"]}

# Herkese açık, gerçek zafiyet bilgileri (NVD / CISA KEV). Sondaki liste: bu zafiyeti istismar ettiği bilinen yazılımlar.
CVES = [
    ("CVE-2017-0144", "Windows SMBv1 uzaktan kod çalıştırma (EternalBlue)", "Microsoft", "Windows", 8.1, "2017-03-16", ["WannaCry", "NotPetya"]),
    ("CVE-2021-44228", "Apache Log4j2 JNDI uzaktan kod çalıştırma (Log4Shell)", "Apache", "Log4j2", 10.0, "2021-12-10", ["Conti"]),
    ("CVE-2023-34362", "MOVEit Transfer SQL enjeksiyonu", "Progress", "MOVEit Transfer", 9.8, "2023-06-02", ["Clop"]),
    ("CVE-2020-1472", "Netlogon yetki yükseltme (Zerologon)", "Microsoft", "Windows Server", 10.0, "2020-08-17", ["Ryuk", "Conti"]),
    ("CVE-2021-34527", "Windows Yazdırma Biriktiricisi uzaktan kod çalıştırma (PrintNightmare)", "Microsoft", "Windows", 8.8, "2021-07-02", ["Conti"]),
    ("CVE-2021-26855", "Exchange Server SSRF (ProxyLogon)", "Microsoft", "Exchange Server", 9.8, "2021-03-02", []),
    ("CVE-2022-30190", "MSDT uzaktan kod çalıştırma (Follina)", "Microsoft", "Windows", 7.8, "2022-06-01", ["QakBot"]),
    ("CVE-2019-0708", "Uzak Masaüstü Hizmetleri uzaktan kod çalıştırma (BlueKeep)", "Microsoft", "Windows", 9.8, "2019-05-16", []),
    ("CVE-2023-4966", "Citrix NetScaler ADC bilgi sızdırma (Citrix Bleed)", "Citrix", "NetScaler ADC", 9.4, "2023-10-10", ["LockBit 3.0"]),
    ("CVE-2022-26134", "Confluence OGNL enjeksiyonu", "Atlassian", "Confluence", 9.8, "2022-06-03", []),
    ("CVE-2023-27350", "PaperCut MF/NG kimlik doğrulama atlatma", "PaperCut", "MF/NG", 9.8, "2023-04-20", ["Clop", "LockBit 3.0"]),
    ("CVE-2020-0688", "Exchange Server doğrulama anahtarı uzaktan kod çalıştırma", "Microsoft", "Exchange Server", 8.8, "2020-02-11", []),
]
SECTOR_HINTS = [
    ("Finans ve bankacılık", ["financ", "bank"]), ("Kamu", ["government"]), ("Savunma", ["defense", "military"]),
    ("Enerji", ["energy", " oil", "petro"]), ("Sağlık", ["health", "medical", "pharma"]), ("Telekomünikasyon", ["telecom"]),
    ("Eğitim", ["universit", "academ", "education"]), ("Üretim", ["manufactur"]), ("Perakende", ["retail", "hospitality", "restaurant"]),
    ("Ulaştırma", ["transport", "shipping", "logistic", "maritime"]), ("Medya", ["media", "journalis"]),
    ("Teknoloji", ["technology", "software", "semiconductor"]), ("Havacılık", ["aerospace", "aviation"]),
    ("Hukuk ve danışmanlık", ["law firm", "legal", "consult"]),
]


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def main() -> None:
    rng = random.Random(42)
    conn = connect()
    cur = conn.cursor()
    src = source_id(conn, "Demo veri üreteci")

    if cur.execute("SELECT COUNT(*) FROM dbo.Indicator WHERE SourceID = ?;", src).fetchone()[0]:
        print("  Demo verisi zaten yüklü, atlandı.")
        return

    marks = ",".join("?" * len(FAMILIES))
    families = cur.execute(
        f"SELECT m.Name, mt.Code FROM dbo.Malware AS m JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID WHERE m.Name IN ({marks});",
        *FAMILIES).fetchall()

    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    pool = [f"{net}.{host}" for net in ("192.0.2", "198.51.100", "203.0.113") for host in range(1, 255)]
    rng.shuffle(pool)
    items, seen = [], set()

    def add(kind, value, name, code, role):
        if (kind, value) in seen:
            return
        seen.add((kind, value))
        # Yakın tarihe doğru yoğunlaşan dağılım: grafikte artış eğilimi görünsün
        first = now - timedelta(days=min(119, int(rng.expovariate(1 / 28))), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        last = min(now, first + timedelta(days=rng.randint(0, 20), hours=rng.randint(0, 12)))
        tags = ["demo", role] + ([code] if code not in ("malware", "tool") else [])
        items.append({"type": kind, "value": value, "confidence": rng.choice([55, 65, 70, 75, 80, 85, 90, 95, 100]),
                      "severity": rng.choice(SEVERITY_BY_TYPE.get(code, ["low", "medium", "high"])),
                      "tlp": rng.choice(["TLP:CLEAR", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]),
                      "description": None, "first_seen": iso(first), "last_seen": iso(last),
                      "expires_at": iso(last + timedelta(days=90)), "malware": name, "role": role, "tags": tags})

    for name, code in families:
        slug = "".join(c for c in name.lower() if c.isalnum())[:10]
        for _ in range(rng.randint(6, 16)):
            if pool:
                add("ipv4", pool.pop(), name, code, "c2")
        for n in range(rng.randint(5, 14)):
            domain = f"{rng.choice(WORDS)}-{slug}{n}.{rng.choice(['example', 'test', 'invalid'])}"
            add("domain", domain, name, code, rng.choice(["c2", "c2", "phishing", "exfil"]))
            if rng.random() < 0.5:
                add("url", f"http://{domain}/{rng.choice(PATHS)}", name, code, rng.choice(["payload", "dropper"]))
        for _ in range(rng.randint(8, 20)):
            add("sha256", "%064x" % rng.getrandbits(256), name, code, rng.choice(["payload", "payload", "dropper"]))
        for _ in range(rng.randint(0, 4)):
            add("md5", "%032x" % rng.getrandbits(128), name, code, "payload")

    run = cur.execute("EXEC dbo.sp_StartIngestRun @SourceID = ?;", src).fetchone()[0]
    for start in range(0, len(items), 500):
        cur.execute("EXEC dbo.sp_BulkImportIndicators @SourceID = ?, @Json = ?, @RunID = ?;",
                    src, json.dumps(items[start:start + 500], ensure_ascii=False), run).fetchone()
    cur.execute("EXEC dbo.sp_FinishIngestRun @RunID = ?, @Status = 'success';", run)

    # Kurum içi görülmeler: göstergelerin yaklaşık %9'u
    ids = [r[0] for r in cur.execute("SELECT IndicatorID FROM dbo.Indicator WHERE SourceID = ? ORDER BY IndicatorID;", src).fetchall()]
    analyst = cur.execute("SELECT UserID FROM dbo.AppUser WHERE Username = N'analist';").fetchone()
    sightings = 0
    for indicator_id in rng.sample(ids, k=max(1, len(ids) * 9 // 100)):
        for _ in range(rng.choice([1, 1, 1, 2, 3, 5])):
            when = now - timedelta(days=min(29, int(rng.expovariate(1 / 7))), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            cur.execute("EXEC dbo.sp_AddSighting @IndicatorID = ?, @Quantity = ?, @Location = ?, @Note = NULL, @SightedAt = ?, @UserID = ?;",
                        indicator_id, rng.choice([1, 1, 2, 3, 8, 21]), rng.choice(LOCATIONS), when, analyst[0] if analyst else None).fetchone()
            sightings += 1

    # Kampanya <-> gösterge: kampanyanın kullandığı zararlının göstergelerinden bir kısmı kampanyaya bağlanır
    cur.execute(
        """
        INSERT INTO dbo.CampaignIndicator (CampaignID, IndicatorID)
        SELECT x.CampaignID, x.IndicatorID
        FROM (
            SELECT cm.CampaignID, mi.IndicatorID,
                   ROW_NUMBER() OVER (PARTITION BY cm.CampaignID, cm.MalwareID ORDER BY mi.IndicatorID) AS rn
            FROM dbo.CampaignMalware AS cm
            JOIN dbo.MalwareIndicator AS mi ON mi.MalwareID = cm.MalwareID
            JOIN dbo.Indicator AS i ON i.IndicatorID = mi.IndicatorID AND i.SourceID = ?
        ) AS x
        WHERE x.rn <= 8
          AND NOT EXISTS (SELECT 1 FROM dbo.CampaignIndicator AS ci WHERE ci.CampaignID = x.CampaignID AND ci.IndicatorID = x.IndicatorID);
        """, src)

    # Zafiyetler ve zararlı bağlantıları
    for cve, title, vendor, product, cvss, published, exploited_by in CVES:
        if not cur.execute("SELECT 1 FROM dbo.Vulnerability WHERE CveID = ?;", cve).fetchone():
            cur.execute(
                "INSERT INTO dbo.Vulnerability (CveID, Title, Vendor, Product, CvssScore, PublishedDate, IsKnownExploited) VALUES (?, ?, ?, ?, ?, ?, 1);",
                cve, title, vendor, product, cvss, published)
        for malware in exploited_by:
            cur.execute(
                """
                INSERT INTO dbo.MalwareVulnerability (MalwareID, VulnerabilityID)
                SELECT m.MalwareID, v.VulnerabilityID
                FROM dbo.Malware AS m CROSS JOIN dbo.Vulnerability AS v
                WHERE m.Name = ? AND v.CveID = ?
                  AND NOT EXISTS (SELECT 1 FROM dbo.MalwareVulnerability AS x WHERE x.MalwareID = m.MalwareID AND x.VulnerabilityID = v.VulnerabilityID);
                """, malware, cve)

    # Hedef sektörler: ATT&CK açıklamasında geçen sektör sözcüklerinden (küme tabanlı INSERT ... SELECT)
    for sector, hints in SECTOR_HINTS:
        like = " OR ".join("a.Description LIKE ?" for _ in hints)
        cur.execute(
            f"""
            INSERT INTO dbo.ActorTargetSector (ActorID, SectorID)
            SELECT a.ActorID, s.SectorID
            FROM dbo.ThreatActor AS a CROSS JOIN dbo.Sector AS s
            WHERE s.Name = ? AND ({like})
              AND NOT EXISTS (SELECT 1 FROM dbo.ActorTargetSector AS x WHERE x.ActorID = a.ActorID AND x.SectorID = s.SectorID);
            """, sector, *[f"%{h}%" for h in hints])

    print(f"  Demo verisi: {len(families)} zararlı ailesi, {len(items)} gösterge, {sightings} görülme, {len(CVES)} zafiyet")
    conn.close()


if __name__ == "__main__":
    main()
