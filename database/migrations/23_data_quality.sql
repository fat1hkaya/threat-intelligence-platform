/* =====================================================================
   ThreatLens - 23: Veri doğruluğu (UI denetimi aşama 1)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   1) Yer tutucu aileler: "Unknown Loader", "Unknown Stealer" gibi kayıtlar gerçek aile değildir ama
      istatistiklerde "en çok IOC'ye bağlı aile" olarak birinci sıraya çıkıyordu.
      Malware.IsPlaceholder elle güncellenen bir bayrak yerine HESAPLANMIŞ (PERSISTED) sütundur:
      kural tek yerde (fn_IsPlaceholderMalware, 03_functions.sql) ve beslemeden gelen yeni aileler de
      kendiliğinden sınıflanır; sütun hiç tutarsız kalamaz. Gösterim adı: fn_MalwareLabel.
   2) Sınıflandırılmamış tür: beslemeden açılan ve ATT&CK'te karşılığı olmayan ailelerin türü bilinmiyor;
      "Zararlı yazılım (genel)" yerine açıkça "Sınıflandırılmamış". ATT&CK kayıtlarının türü değişmez.
   3) Risk bantları: "yüksek riskli" = risk skoru eşiği (RiskBand); "yüksek önemli" = önem düzeyi
      (SeverityLevel). İki kavram ayrı adlarla kullanılır; eşikler Ayarlar > Risk ekranında görünür.
   4) Kaynak birimleri: IOC üretmeyen kaynaklar kendi birimini gösterir (CISA KEV -> zafiyet,
      ATT&CK -> teknik, iptoasn -> IP aralığı, Malpedia -> aile).
   ===================================================================== */
USE ThreatLens;
GO

/* 2) Sınıflandırılmamış tür */
IF NOT EXISTS (SELECT 1 FROM dbo.MalwareType WHERE Code = 'unclassified')
    INSERT INTO dbo.MalwareType (MalwareTypeID, Code, Name) VALUES (13, 'unclassified', N'Sınıflandırılmamış');
GO

/* 1) Yer tutucu bayrağı (hesaplanmış, kalıcı) */
IF COL_LENGTH(N'dbo.Malware', N'IsPlaceholder') IS NULL
BEGIN
    ALTER TABLE dbo.Malware ADD IsPlaceholder AS dbo.fn_IsPlaceholderMalware(Name, ExternalID) PERSISTED;
    EXEC(N'CREATE INDEX IX_Malware_IsPlaceholder ON dbo.Malware (IsPlaceholder) INCLUDE (Name);');   -- yeni sütun aynı yığında derlenemez
END;
GO

/* Beslemeden açılmış, türü genel bırakılmış aileler -> Sınıflandırılmamış (ATT&CK kayıtlarına dokunulmaz) */
UPDATE m SET m.MalwareTypeID = (SELECT MalwareTypeID FROM dbo.MalwareType WHERE Code = 'unclassified'), m.UpdatedAt = SYSUTCDATETIME()
FROM dbo.Malware AS m
WHERE m.ExternalID IS NULL AND m.MalwareTypeID = (SELECT MalwareTypeID FROM dbo.MalwareType WHERE Code = 'malware');
GO

/* 3) Risk bantları */
IF OBJECT_ID(N'dbo.RiskBand') IS NULL
BEGIN
    CREATE TABLE dbo.RiskBand (
        Code      VARCHAR(10)  NOT NULL CONSTRAINT PK_RiskBand PRIMARY KEY,
        Name      NVARCHAR(30) NOT NULL,
        MinScore  TINYINT      NOT NULL CONSTRAINT UQ_RiskBand_MinScore UNIQUE,
        SortOrder TINYINT      NOT NULL,
        CONSTRAINT CK_RiskBand_MinScore CHECK (MinScore BETWEEN 0 AND 100)
    );
    INSERT INTO dbo.RiskBand (Code, Name, MinScore, SortOrder) VALUES
        ('critical', N'Kritik', 85, 1), ('high', N'Yüksek', 70, 2), ('medium', N'Orta', 40, 3), ('low', N'Düşük', 0, 4);
END;
GO

/* Bir skorun bandı (satır içi tablo fonksiyonu: sorgu planına gömülür) */
CREATE OR ALTER FUNCTION dbo.fn_RiskBandOf (@Score DECIMAL(5,1))
RETURNS TABLE
AS
RETURN
    SELECT TOP (1) b.Code, b.Name, b.SortOrder FROM dbo.RiskBand AS b WHERE b.MinScore <= @Score ORDER BY b.MinScore DESC;
GO

/* 4) Kaynak birimi: kaynağın ne ürettiği ve kaç tane */
CREATE OR ALTER VIEW dbo.vw_SourceUnit
AS
SELECT s.SourceID,
       CASE s.Name WHEN N'CISA KEV' THEN N'zafiyet' WHEN N'MITRE ATT&CK' THEN N'teknik'
                   WHEN N'iptoasn.com' THEN N'IP aralığı' WHEN N'Malpedia' THEN N'aile' ELSE N'IOC' END AS UnitLabel,
       CASE s.Name
           WHEN N'CISA KEV'     THEN (SELECT COUNT(*) FROM dbo.Vulnerability)
           WHEN N'MITRE ATT&CK' THEN (SELECT COUNT(*) FROM dbo.Technique)
           WHEN N'iptoasn.com'  THEN (SELECT COUNT(*) FROM dbo.IpRange)
           WHEN N'Malpedia'     THEN (SELECT TOP (1) j.RowsRead FROM dbo.ImportJob AS j
                                      WHERE j.SourceID = s.SourceID AND j.Status = 'success' ORDER BY j.JobID DESC)
           ELSE (SELECT COUNT(*) FROM dbo.Indicator AS i WHERE i.SourceID = s.SourceID)
       END AS UnitCount,
       CASE s.Name WHEN N'MITRE ATT&CK' THEN CONCAT((SELECT COUNT(*) FROM dbo.ThreatActor WHERE ExternalID LIKE 'G%'), N' aktör · ',
                                                    (SELECT COUNT(*) FROM dbo.Malware WHERE ExternalID LIKE 'S%'), N' yazılım') END AS UnitDetail
FROM dbo.Source AS s;
GO

GRANT EXECUTE ON dbo.fn_MalwareLabel TO tip_reader;
GRANT EXECUTE ON dbo.fn_IsPlaceholderMalware TO tip_reader;
GO
