# Normalizasyon: çalışma taslağı (Ödev 3 / Ara Rapor 2)

> **TASLAK.** Bu dosya ekibin raporu yazarken kullanacağı teknik malzemedir: bağımlılıklar, örnek veriler ve doğrulama sorguları gerçek şemadan alınmıştır. Teslim edilecek metin ekip tarafından özgün olarak yazılmalıdır. Her örnek dersin istediği 4 adımı izler: (1) fonksiyonel bağımlılıklar, (2) ihlalin örnek veriyle gösterimi, (3) ayrıştırma, (4) kayıpsız birleştirmenin doğrulanması.
>
> Doğrulama sorgularını SSMS'te `USE ThreatLens;` sonrası çalıştırın. Hepsi gerçek veriyle sınandı.

---

## Örnek 1: Çok değerli nitelik → 1NF (aktör takma adları)

**1. Bağımlılıklar.** Bir aktörün birden çok takma adı vardır (APT29 = Cozy Bear = NOBELIUM = The Dukes …). `ActorID →→ Alias` (çok değerli bağımlılık).

**2. İhlal.** Takma adlar tek sütunda virgülle tutulsaydı:

| ActorID | Name | Aliases |
|---|---|---|
| 173 | APT29 | Cozy Bear, NOBELIUM, The Dukes, Midnight Blizzard |

Bu tasarımda sütun atomik değildir (1NF ihlali). "NOBELIUM takma adlı aktör hangisi?" sorusu `LIKE '%NOBELIUM%'` ile sorulur; bu yöntem indeks kullanamaz ve "NOBELIUM2" gibi değerlere de yanlış eşleşir. Bir takma adı silmek metni yeniden yazmayı gerektirir.

**3. Ayrıştırma.** `ThreatActor(ActorID, Name, …)` + `ActorAlias(ActorID, Alias)`. PK `(ActorID, Alias)`, FK `ActorID → ThreatActor`.

**4. Kayıpsızlık.** Ortak nitelik `ActorID`, `ThreatActor`'ın anahtarıdır; bu yüzden birleştirme kayıpsızdır. Doğrulama: birleştirmeden geri üretilen metin, ayrıştırılmış kümeyle birebir aynı olmalıdır.
```sql
WITH flat AS (   -- 1NF öncesi görünüm: virgülle birleştirilmiş tek sütun
    SELECT a.ActorID, STRING_AGG(al.Alias, N'|') AS Aliases
    FROM dbo.ThreatActor AS a JOIN dbo.ActorAlias AS al ON al.ActorID = a.ActorID GROUP BY a.ActorID)
SELECT ActorID, value AS Alias FROM flat CROSS APPLY STRING_SPLIT(Aliases, N'|')
EXCEPT
SELECT ActorID, Alias FROM dbo.ActorAlias;      -- boş sonuç = kayıp yok
```

---

## Örnek 2: Kısmi bağımlılık → 2NF (aktör–teknik ilişkisi)

**1. Bağımlılıklar.** Anahtar `(ActorID, TechniqueID)`. Ayrıca `TechniqueID → TechniqueExternalID, TechniqueName` ve `ActorID → ActorName`. Bu bağımlılıklar anahtarın yalnızca bir parçasına bağlıdır.

**2. İhlal.** Tek tabloda:

| ActorID | ActorName | TechniqueID | ExternalID | TechniqueName |
|---|---|---|---|---|
| 173 | APT29 | 118 | T1059.001 | PowerShell |
| 175 | APT28 | 118 | T1059.001 | PowerShell |

Bu durumda "PowerShell" adı, tekniği kullanan her aktör için bir kez tekrar eder. Gerçek veride bu tekniği 86 aktör kullanır. Ad değişirse bütün satırların güncellenmesi gerekir (güncelleme anomalisi). Hiçbir aktörün kullanmadığı bir teknik ise eklenemez (ekleme anomalisi).

**3. Ayrıştırma.** `ThreatActor(ActorID, Name…)`, `Technique(TechniqueID, ExternalID, Name…)`, `ActorTechnique(ActorID, TechniqueID, Confidence, EvidenceID)`.

**4. Kayıpsızlık.** `ActorTechnique ⋈ Technique` (ortak `TechniqueID`, Technique'in PK'sı) ve `⋈ ThreatActor` (ortak `ActorID`) kayıpsızdır.
```sql
SELECT COUNT(*) AS IliskiSatiri FROM dbo.ActorTechnique;                       -- 4815
SELECT COUNT(*) AS BirlesimSatiri FROM dbo.ActorTechnique AS x
JOIN dbo.ThreatActor AS a ON a.ActorID = x.ActorID
JOIN dbo.Technique AS t ON t.TechniqueID = x.TechniqueID;                     -- 4815: sahte satır yok, kayıp yok
```

---

## Örnek 3: Geçişli bağımlılık → 3NF (IOC ve kaynak güvenilirliği)

**1. Bağımlılıklar.** `IndicatorID → SourceID` ve `SourceID → SourceName, Reliability`. Buradan geçişli olarak `IndicatorID → Reliability`.

**2. İhlal.**

| IndicatorID | Value | SourceName | Reliability |
|---|---|---|---|
| 10 | 198.51.100.7 | abuse.ch ThreatFox | B |
| 11 | evil.example | abuse.ch ThreatFox | B |

Bu durumda kaynağın güvenilirliği her IOC satırında tekrar eder. Gerçek bir besleme on binlerce IOC getirir. Bir kaynağın güvenilirliği B'den C'ye düşerse binlerce satır güncellenmelidir; biri unutulursa tutarsızlık oluşur.

**3. Ayrıştırma.** `Indicator(IndicatorID, …, SourceID)` + `Source(SourceID, Name, Reliability, …)`. Aynı gerekçeyle `TypeID → TypeName` için `IndicatorType`, `SeverityID → Weight` için `SeverityLevel` tabloları ayrıldı.

**4. Kayıpsızlık.** Ortak nitelik `SourceID`, `Source`'un PK'sıdır.
```sql
SELECT (SELECT COUNT(*) FROM dbo.Indicator) AS IOC,
       (SELECT COUNT(*) FROM dbo.Indicator AS i JOIN dbo.Source AS s ON s.SourceID = i.SourceID) AS Birlesim;   -- eşit
```

---

## Örnek 4: Geçişli bağımlılık → 3NF (ilişki satırı, kanıt ve kaynak)

**1. Bağımlılıklar.** İlişki satırı `(MalwareID, IndicatorID) → EvidenceID`. Kanıt satırı `EvidenceID → SourceID, Summary, Url`. İlişki tablosunda ayrıca `SourceID` tutulsaydı `(MalwareID, IndicatorID) → EvidenceID → SourceID` geçişli bağımlılığı oluşurdu.

**2. İhlal.** (Kimlikler örnektir.)

| MalwareID | IndicatorID | EvidenceID | SourceID |
|---|---|---|---|
| 349 | 1442 | 20446 | 8 |

Bu satırdaki `SourceID` gereksizdir. Kanıtın kaynağı düzeltilirse ilişki satırındaki kopya eski değerde kalır ve kanıt başka kaynağı, ilişki başka kaynağı gösterir.

**3. Ayrıştırma.** İlişki tablolarında (`ActorMalware`, `MalwareIndicator`, `CampaignTechnique` …) yalnızca `EvidenceID` tutulur. Kaynak `Evidence.SourceID` üzerinden bulunur. (Bu karar `01_tables.sql` dosyasındaki `Evidence` açıklamasında belgelidir.)

**4. Kayıpsızlık.**
```sql
SELECT COUNT(*) FROM dbo.MalwareIndicator WHERE EvidenceID IS NOT NULL;            -- 1446
SELECT COUNT(*) FROM dbo.MalwareIndicator AS mi JOIN dbo.Evidence AS e ON e.EvidenceID = mi.EvidenceID
JOIN dbo.Source AS s ON s.SourceID = e.SourceID;                                    -- 1446
```

---

## Örnek 5: Çok değerli ilişki → M:N ara tablo (teknik–taktik)

**1. Bağımlılıklar.** Bir teknik birden çok taktiğe ait olabilir (örneğin T1078 Valid Accounts, ATT&CK v20'de dört taktiğe aittir: Initial Access, Persistence, Privilege Escalation, Stealth). `TechniqueID →→ TacticID`.

**2. İhlal.** `Technique` tablosunda tek bir `TacticID` sütunu olsaydı iki seçenek kalırdı. Ya taktiklerden yalnızca biri tutulur (bilgi kaybı), ya da teknik her taktik için ayrı satır olarak tekrarlanır. İkinci seçenekte `Name`, `Description` tekrar eder ve `ExternalID` benzersiz olamaz.
```sql
SELECT t.ExternalID, COUNT(*) AS TaktikSayisi FROM dbo.TechniqueTactic AS tt
JOIN dbo.Technique AS t ON t.TechniqueID = tt.TechniqueID
GROUP BY t.ExternalID HAVING COUNT(*) > 1 ORDER BY TaktikSayisi DESC;   -- birden çok taktiğe ait teknikler
```

**3. Ayrıştırma.** `Technique(TechniqueID, ExternalID UNIQUE, Name, …)`, `Tactic(TacticID, …)`, `TechniqueTactic(TechniqueID, TacticID)` (PK ikisi birden).

**4. Kayıpsızlık.**
```sql
SELECT COUNT(*) FROM dbo.TechniqueTactic;
SELECT COUNT(*) FROM dbo.TechniqueTactic AS tt JOIN dbo.Technique AS t ON t.TechniqueID = tt.TechniqueID
JOIN dbo.Tactic AS ta ON ta.TacticID = tt.TacticID;                    -- eşit
```

---

## Ek: bilinçli istisnalar (raporda gerekçelendirilmeli)

1. **`Indicator.NormalizedValue`** türetilmiş bir niteliktir (`Value → NormalizedValue`). Saklanmasının nedeni, tekrar kaydı engelleyen `UNIQUE (TypeID, NormalizedValue)` kısıtı ve indeksli aramadır. Normalleştirme kuralı uygulama katmanındadır; veritabanı biçimi `fn_IsValidIndicator` ile ayrıca denetler.
2. **Graf kenar tablolarındaki `Confidence` ve `EvidenceID`**, ilişkisel ara tabloların kopyasıdır (bilinçli denormalizasyon). Tutarlılığı tetikleyiciler (aynı transaction) ve `sp_CheckGraphConsistency` korur.
3. **Hesaplanan değerler saklanmaz:** risk skoru (`fn_RiskScore`), görülme sayısı ve ilişki sayıları görünümlerde hesaplanır.
