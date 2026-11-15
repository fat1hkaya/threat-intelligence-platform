"""DEMO DATA: sunum için sentetik göstergeler. GERÇEK TEHDİT VERİSİ DEĞİLDİR.

- IP adresleri RFC 5737 belgeleme aralıklarındandır (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Alan adları RFC 2606 ayrılmış uzantılarını kullanır (.example, .test, .invalid).
- Özet (hash) değerleri rastgele üretilir (sabit tohum: her kurulumda aynı veri).
- Göstergeler, ATT&CK'te bulunan gerçek zararlı aile adlarına YAPAY olarak bağlanır ki ilişki grafı
  ve atıf zinciri gösterilebilsin. Her gösterge "DEMO DATA" kaynağına yazılır, "demo" etiketi taşır ve
  her bağlantının kanıt metni "DEMO DATA: sentetik ilişki" ile başlar.
- Zafiyet (CVE) bilgileri ve CVE -> zararlı bağlantıları herkese açık raporlara dayanır; kanıt kaynağı
  "Analist girişi"dir.

Çalıştırma:  python -m importers demo
"""
import random
from datetime import datetime, timedelta, timezone

from app.services.importer import run_import

from ._db import source_id

DEMO_SOURCE = "DEMO DATA"
EVIDENCE_PREFIX = "DEMO DATA: sentetik ilişki"

# ATT&CK'te bulunmayan adlar sorguda eşleşmez ve atlanır.
FAMILIES = ["Emotet", "TrickBot", "QakBot", "Cobalt Strike", "AsyncRAT", "Agent Tesla", "LockBit 3.0", "Conti", "Ryuk",
            "IcedID", "njRAT", "Remcos", "BlackCat", "Akira", "Black Basta", "Clop", "PlugX", "ShadowPad", "Sliver",
            "Brute Ratel C4", "SUNBURST", "WannaCry", "NotPetya", "DarkGate", "Pikabot", "Bumblebee", "Raccoon Stealer",
            "Lumma Stealer", "RedLine Stealer", "Mimikatz", "Royal", "Latrodectus", "Industroyer", "Olympic Destroyer"]
WORDS = ["update", "cdn", "secure", "portal", "mail", "login", "sync", "static", "files", "cloud", "auth", "api",
         "docs", "support", "invoice", "track", "media", "node", "relay", "gate"]
PATHS = ["gate.php", "load/update.bin", "wp-content/x.dll", "invoice.zip", "dl/setup.msi", "a/b/payload.exe", "panel/login"]
LOCATIONS = ["SIEM / güvenlik duvarı", "EDR / WS-0142", "EDR / SRV-DB-03", "E-posta ağ geçidi", "Web vekil sunucusu", "DNS kayıtları"]
SEVERITY_BY_TYPE = {"ransomware": ["high", "critical", "critical"], "wiper": ["critical"], "rat": ["medium", "high"],
                    "backdoor": ["high", "high", "critical"], "stealer": ["medium", "high"], "loader": ["medium", "high"],
                    "tool": ["low", "medium"], "banker": ["medium", "high"]}

# Herkese açık zafiyet bilgileri (NVD / CISA KEV) ve bu zafiyeti istismar ettiği kamuya açık raporlarla bilinen yazılımlar.
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
# Hedef sektör: ATT&CK aktör açıklamasında geçen anahtar sözcüklerden SEZGİSEL çıkarım (raporda belirtilmeli).
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


def build_items(families: list[tuple[str, str]], now: datetime, rng: random.Random) -> list[dict]:
    pool = [f"{net}.{host}" for net in ("192.0.2", "198.51.100", "203.0.113") for host in range(1, 255)]
    rng.shuffle(pool)
    items, seen = [], set()

    def add(kind: str, value: str, name: str, code: str, role: str) -> None:
        if (kind, value) in seen:
            return
        seen.add((kind, value))
        # Yakın tarihe doğru yoğunlaşan dağılım (üstel): son günlerde daha çok kayıt
        first = now - timedelta(days=min(119, int(rng.expovariate(1 / 28))), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        last = min(now, first + timedelta(days=rng.randint(0, 20), hours=rng.randint(0, 12)))
        tags = ["demo", role] + ([code] if code not in ("malware", "tool") else [])
        items.append({
            "type": kind, "value": value, "confidence": rng.choice([55, 65, 70, 75, 80, 85, 90, 95, 100]),
            "severity": rng.choice(SEVERITY_BY_TYPE.get(code, ["low", "medium", "high"])),
            "tlp": rng.choice(["TLP:CLEAR", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER"]),
            "description": f"DEMO DATA - sentetik {kind} göstergesi (gerçek tehdit verisi değildir).",
            "first_seen": iso(first), "last_seen": iso(last), "expires_at": iso(last + timedelta(days=180)),
            "malware": name, "role": role, "tags": tags,
            "evidence": f"{EVIDENCE_PREFIX}: bu gösterge sunum için üretildi ve {name} ailesine yapay olarak bağlandı.",
        })

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
        for _ in range(rng.randint(0, 3)):
            add("sha1", "%040x" % rng.getrandbits(160), name, code, "payload")
    return items


def run(conn) -> dict:
    rng = random.Random(42)
    cur = conn.cursor()
    src = source_id(conn, DEMO_SOURCE)
    if cur.execute("SELECT COUNT(*) FROM dbo.Indicator WHERE SourceID = ?;", src).fetchone()[0]:
        print("  DEMO DATA zaten yüklü, atlandı.")
        return {"status": "skipped"}

    marks = ",".join("?" * len(FAMILIES))
    families = [(r[0], r[1]) for r in cur.execute(
        f"""SELECT m.Name, mt.Code FROM dbo.Malware AS m JOIN dbo.MalwareType AS mt ON mt.MalwareTypeID = m.MalwareTypeID
            WHERE m.Name IN ({marks}) ORDER BY m.Name;""", *FAMILIES).fetchall()]
    if not families:
        raise SystemExit("Zararlı aileleri bulunamadı. Önce MITRE ATT&CK yükleyin: python -m importers attack")

    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    items = build_items(families, now, rng)
    res = run_import(conn, src, items, job_type="demo", file_name="demo_data.py")
    print(f"  DEMO DATA içe aktarma işi #{res.job_id}: {res.status}, okunan {res.read}, eklenen {res.inserted}, "
          f"güncellenen {res.updated}, atlanan {res.skipped}, hatalı {res.failed}")

    analyst = cur.execute("SELECT UserID FROM dbo.AppUser WHERE Username = N'analist';").fetchone()
    analyst_id = analyst[0] if analyst else None

    # Kurum içi görülmeler (sighting): göstergelerin yaklaşık %9'u
    ids = [r[0] for r in cur.execute("SELECT IndicatorID FROM dbo.Indicator WHERE SourceID = ? ORDER BY IndicatorID;", src).fetchall()]
    sightings = 0
    cur.execute("EXEC sys.sp_set_session_context @key = N'skip_audit', @value = 1;")
    for indicator_id in rng.sample(ids, k=max(1, len(ids) * 9 // 100)):
        for _ in range(rng.choice([1, 1, 1, 2, 3, 5])):
            when = now - timedelta(days=min(29, int(rng.expovariate(1 / 7))), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            cur.execute("EXEC dbo.sp_AddSighting @IndicatorID = ?, @Quantity = ?, @Location = ?, @Note = N'DEMO DATA', @SightedAt = ?, @UserID = ?;",
                        indicator_id, rng.choice([1, 1, 2, 3, 8, 21]), rng.choice(LOCATIONS), when, analyst_id).fetchone()
            sightings += 1

    # Kampanya -> gösterge: kampanyanın (ATT&CK'e göre) kullandığı zararlının DEMO göstergelerinden bir kısmı.
    # Tek kanıt satırı tüm bu sentetik bağlantılar için ortak kullanılır.
    evidence_id = cur.execute(
        "INSERT INTO dbo.Evidence (SourceID, Summary) OUTPUT inserted.EvidenceID VALUES (?, ?);", src,
        f"{EVIDENCE_PREFIX}: kampanya-gösterge bağlantısı, kampanyanın ATT&CK'e göre kullandığı zararlının DEMO "
        "göstergelerinden seçilerek sunum için üretildi.").fetchone()[0]
    linked = cur.execute(
        """
        SET NOCOUNT ON;
        INSERT INTO dbo.CampaignIndicator (CampaignID, IndicatorID, Confidence, EvidenceID)
        SELECT x.CampaignID, x.IndicatorID, 50, ?
        FROM (
            SELECT cm.CampaignID, mi.IndicatorID,
                   ROW_NUMBER() OVER (PARTITION BY cm.CampaignID, cm.MalwareID ORDER BY mi.IndicatorID) AS rn
            FROM dbo.CampaignMalware AS cm
            JOIN dbo.MalwareIndicator AS mi ON mi.MalwareID = cm.MalwareID
            JOIN dbo.Indicator AS i ON i.IndicatorID = mi.IndicatorID AND i.SourceID = ?
        ) AS x
        WHERE x.rn <= 8
          AND NOT EXISTS (SELECT 1 FROM dbo.CampaignIndicator AS ci WHERE ci.CampaignID = x.CampaignID AND ci.IndicatorID = x.IndicatorID);
        SELECT @@ROWCOUNT;
        """, evidence_id, src).fetchone()[0]
    cur.execute("EXEC sys.sp_set_session_context @key = N'skip_audit', @value = NULL;")

    # Zafiyetler ve kamuya açık raporlara dayanan zararlı bağlantıları (kanıt: Analist girişi)
    analyst_src = source_id(conn, "Analist girişi")
    vuln_links = 0
    for cve, title, vendor, product, cvss, published, exploited_by in CVES:
        if not cur.execute("SELECT 1 FROM dbo.Vulnerability WHERE CveID = ?;", cve).fetchone():
            cur.execute("INSERT INTO dbo.Vulnerability (CveID, Title, Vendor, Product, CvssScore, PublishedDate, IsKnownExploited) "
                        "VALUES (?, ?, ?, ?, ?, ?, 1);", cve, title, vendor, product, cvss, published)
        for malware in exploited_by:
            row = cur.execute(
                """
                SET NOCOUNT ON;
                DECLARE @m INT = (SELECT MalwareID FROM dbo.Malware WHERE Name = ?);
                DECLARE @v INT = (SELECT VulnerabilityID FROM dbo.Vulnerability WHERE CveID = ?);
                IF @m IS NOT NULL AND NOT EXISTS (SELECT 1 FROM dbo.MalwareVulnerability WHERE MalwareID = @m AND VulnerabilityID = @v)
                BEGIN
                    DECLARE @e INT;
                    INSERT INTO dbo.Evidence (SourceID, Summary, Url) VALUES (?, ?, ?);
                    SET @e = SCOPE_IDENTITY();
                    INSERT INTO dbo.MalwareVulnerability (MalwareID, VulnerabilityID, Confidence, EvidenceID) VALUES (@m, @v, 70, @e);
                    SELECT 1;
                END
                ELSE SELECT 0;
                """, malware, cve, analyst_src,
                f"Analist girişi: kamuya açık güvenlik raporlarına göre {malware} operatörleri {cve} zafiyetini istismar etmiştir.",
                f"https://nvd.nist.gov/vuln/detail/{cve}").fetchone()
            vuln_links += row[0]

    # Hedef sektörler (sezgisel, ATT&CK açıklamasından)
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

    summary = {"status": res.status, "job_id": res.job_id, "families": len(families), "indicators": res.inserted,
               "sightings": sightings, "campaign_links": linked, "cves": len(CVES), "cve_links": vuln_links}
    print(f"  DEMO DATA: {len(families)} zararlı ailesi, {res.inserted} gösterge, {sightings} görülme, "
          f"{linked} kampanya-gösterge bağlantısı, {len(CVES)} zafiyet, {vuln_links} zafiyet-zararlı bağlantısı")
    return summary
