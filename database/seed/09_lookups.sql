/* =====================================================================
   ThreatLens - 09: Sözlük verileri (DML - INSERT)
   Tekrar çalıştırılabilir: tablo boşsa doldurur.
   ===================================================================== */
USE ThreatLens;
GO

IF NOT EXISTS (SELECT 1 FROM dbo.Role)
INSERT INTO dbo.Role (RoleID, Code, Name) VALUES
    (1, 'viewer',  N'İzleyici'),
    (2, 'analyst', N'Analist'),
    (3, 'admin',   N'Yönetici');

IF NOT EXISTS (SELECT 1 FROM dbo.IndicatorType)
INSERT INTO dbo.IndicatorType (TypeID, Code, Name) VALUES
    (1, 'ipv4',   N'IPv4 adresi'),
    (2, 'ipv6',   N'IPv6 adresi'),
    (3, 'domain', N'Alan adı'),
    (4, 'url',    N'URL'),
    (5, 'md5',    N'MD5 özeti'),
    (6, 'sha1',   N'SHA-1 özeti'),
    (7, 'sha256', N'SHA-256 özeti'),
    (8, 'email',  N'E-posta adresi');

IF NOT EXISTS (SELECT 1 FROM dbo.SeverityLevel)
INSERT INTO dbo.SeverityLevel (SeverityID, Code, Name, Weight) VALUES
    (1, 'info',     N'Bilgi',  10),
    (2, 'low',      N'Düşük',  30),
    (3, 'medium',   N'Orta',   55),
    (4, 'high',     N'Yüksek', 80),
    (5, 'critical', N'Kritik', 100);

IF NOT EXISTS (SELECT 1 FROM dbo.TLPLevel)
INSERT INTO dbo.TLPLevel (TLPID, Code, Description) VALUES
    (1, 'TLP:CLEAR', N'Sınırsız paylaşılabilir.'),
    (2, 'TLP:GREEN', N'Topluluk içinde paylaşılabilir, herkese açık kanallarda yayımlanamaz.'),
    (3, 'TLP:AMBER', N'Yalnızca kurum içinde ve bilmesi gereken müşterilerle paylaşılabilir.'),
    (4, 'TLP:RED',   N'Yalnızca alıcının kendisi içindir, paylaşılamaz.');

IF NOT EXISTS (SELECT 1 FROM dbo.Motivation)
INSERT INTO dbo.Motivation (MotivationID, Name) VALUES
    (1, N'Casusluk'),
    (2, N'Finansal kazanç'),
    (3, N'Hacktivizm'),
    (4, N'Sabotaj'),
    (5, N'Bilinmiyor');

IF NOT EXISTS (SELECT 1 FROM dbo.MalwareType)
INSERT INTO dbo.MalwareType (MalwareTypeID, Code, Name) VALUES
    (1,  'malware',    N'Zararlı yazılım (genel)'),
    (2,  'tool',       N'Araç'),
    (3,  'ransomware', N'Fidye yazılımı'),
    (4,  'rat',        N'Uzaktan erişim truva atı'),
    (5,  'backdoor',   N'Arka kapı'),
    (6,  'loader',     N'Yükleyici'),
    (7,  'stealer',    N'Bilgi hırsızı'),
    (8,  'wiper',      N'Silici'),
    (9,  'botnet',     N'Botnet'),
    (10, 'rootkit',    N'Rootkit'),
    (11, 'webshell',   N'Web kabuğu'),
    (12, 'banker',     N'Bankacılık truva atı');

IF NOT EXISTS (SELECT 1 FROM dbo.Sector)
INSERT INTO dbo.Sector (Name) VALUES
    (N'Finans ve bankacılık'), (N'Kamu'), (N'Savunma'), (N'Enerji'), (N'Sağlık'),
    (N'Telekomünikasyon'), (N'Eğitim'), (N'Üretim'), (N'Perakende'), (N'Ulaştırma'),
    (N'Medya'), (N'Teknoloji'), (N'Havacılık'), (N'Hukuk ve danışmanlık');

IF NOT EXISTS (SELECT 1 FROM dbo.Country)
INSERT INTO dbo.Country (CountryCode, Name) VALUES
    ('TR', N'Türkiye'), ('US', N'Amerika Birleşik Devletleri'), ('RU', N'Rusya'), ('CN', N'Çin'),
    ('IR', N'İran'), ('KP', N'Kuzey Kore'), ('KR', N'Güney Kore'), ('IN', N'Hindistan'),
    ('PK', N'Pakistan'), ('VN', N'Vietnam'), ('UA', N'Ukrayna'), ('BY', N'Belarus'),
    ('IL', N'İsrail'), ('LB', N'Lübnan'), ('SY', N'Suriye'), ('SA', N'Suudi Arabistan'),
    ('AE', N'Birleşik Arap Emirlikleri'), ('GB', N'Birleşik Krallık'), ('DE', N'Almanya'),
    ('FR', N'Fransa'), ('NL', N'Hollanda'), ('IT', N'İtalya'), ('ES', N'İspanya'),
    ('PL', N'Polonya'), ('JP', N'Japonya'), ('TW', N'Tayvan'), ('SG', N'Singapur'),
    ('AU', N'Avustralya'), ('CA', N'Kanada'), ('BR', N'Brezilya'), ('MX', N'Meksika'),
    ('NG', N'Nijerya'), ('ZA', N'Güney Afrika'), ('EG', N'Mısır'), ('GE', N'Gürcistan'),
    ('AZ', N'Azerbaycan'), ('KZ', N'Kazakistan'), ('RO', N'Romanya'), ('BG', N'Bulgaristan'),
    ('GR', N'Yunanistan');

IF NOT EXISTS (SELECT 1 FROM dbo.Source)
INSERT INTO dbo.Source (Name, Url, Reliability, Description) VALUES
    (N'MITRE ATT&CK',         N'https://attack.mitre.org',            'A', N'Aktör, zararlı yazılım, kampanya ve teknik bilgi tabanı.'),
    (N'abuse.ch MalwareBazaar', N'https://bazaar.abuse.ch',           'B', N'Zararlı yazılım örneklerinin özet (hash) ve aile bilgileri. Dosyanın kendisi indirilmez.'),
    (N'abuse.ch ThreatFox',   N'https://threatfox.abuse.ch',          'B', N'Topluluk kaynaklı IOC paylaşımı (IP, alan adı, URL, özet).'),
    (N'abuse.ch URLhaus',     N'https://urlhaus.abuse.ch',            'B', N'Zararlı yazılım dağıtan URL''ler.'),
    (N'abuse.ch Feodo Tracker', N'https://feodotracker.abuse.ch',     'B', N'Botnet komuta-kontrol sunucusu IP adresleri.'),
    (N'CISA KEV',             N'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'A', N'Sahada istismar edildiği bilinen zafiyetler.'),
    (N'Analist girişi',       NULL,                                   'B', N'Platform kullanıcılarının elle girdiği veya dosyayla yüklediği kayıtlar.');
GO
