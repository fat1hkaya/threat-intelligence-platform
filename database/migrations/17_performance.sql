/* =====================================================================
   ThreatLens - 17: Performans özellikleri (indexed view, columnstore, Query Store)
   Tekrar çalıştırılabilir.
   ---------------------------------------------------------------------
   1) Indexed view (materialized view): IOC sayıları tip/önem/durum kırılımında ÖNCEDEN toplanmış olarak
      diskte tutulur; Indicator'daki her INSERT/UPDATE/DELETE görünümü otomatik günceller.
      Gösterge paneli sayaçları 10 bin satırı taramak yerine en çok 8 x 5 x 4 satır okur.
      Not: Standard (Developer) sürümünde iyileştirici indexed view'ı kendiliğinden eşlemez;
      sorgu WITH (NOEXPAND) ipucuyla görünüme yönlendirilir (Enterprise'da otomatik).
   2) Nonclustered columnstore index: AuditLog üzerindeki analitik sorgular (günlük olay sayısı,
      tablo/işlem dağılımı) sütun bazlı sıkıştırılmış okumayla yapılır.
   3) Query Store: sorgu planları ve çalışma istatistikleri kalıcı tutulur; Ayarlar ekranı en pahalı
      sorguları buradan gösterir (sp_TopQueries).
   ===================================================================== */
USE ThreatLens;
GO
SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
SET ANSI_PADDING ON;
SET ANSI_WARNINGS ON;
SET ARITHABORT ON;
SET CONCAT_NULL_YIELDS_NULL ON;
SET NUMERIC_ROUNDABORT OFF;
GO

/* 1) Indexed view */
IF OBJECT_ID(N'dbo.vw_IndicatorCounts') IS NULL
    EXEC(N'CREATE VIEW dbo.vw_IndicatorCounts
WITH SCHEMABINDING
AS
SELECT i.TypeID, i.SeverityID, i.Status, COUNT_BIG(*) AS Total
FROM dbo.Indicator AS i
GROUP BY i.TypeID, i.SeverityID, i.Status;');
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'dbo.vw_IndicatorCounts') AND name = N'UX_vw_IndicatorCounts')
    CREATE UNIQUE CLUSTERED INDEX UX_vw_IndicatorCounts ON dbo.vw_IndicatorCounts (TypeID, SeverityID, Status);
GO

/* 2) Columnstore: denetim analizleri */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'dbo.AuditLog') AND name = N'NCCI_AuditLog_Analytics')
    CREATE NONCLUSTERED COLUMNSTORE INDEX NCCI_AuditLog_Analytics ON dbo.AuditLog (TableName, Action, ChangedAt, ChangedBy, RecordID);
GO

/* 3) Query Store (2022+ yeni veritabanlarında varsayılan açıktır; eski sürümler için açıkça) */
IF NOT EXISTS (SELECT 1 FROM sys.database_query_store_options WHERE actual_state_desc = 'READ_WRITE')
    ALTER DATABASE CURRENT SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE, QUERY_CAPTURE_MODE = AUTO);
GO

/* Gösterge paneli sayaçları: indexed view'dan (NOEXPAND) */
CREATE OR ALTER PROCEDURE dbo.sp_IndicatorCountsFast
AS
BEGIN
    SET NOCOUNT ON;
    SELECT SUM(c.Total) AS TotalIOCs,
           SUM(CASE WHEN c.Status = 'active' THEN c.Total ELSE 0 END) AS ActiveIOCs,
           SUM(CASE WHEN c.Status = 'active' AND s.Code IN ('high', 'critical') THEN c.Total ELSE 0 END) AS HighRiskIOCs
    FROM dbo.vw_IndicatorCounts AS c WITH (NOEXPAND)
    JOIN dbo.SeverityLevel AS s ON s.SeverityID = c.SeverityID;

    SELECT s.Code, s.Name, ISNULL(SUM(c.Total), 0) AS Total
    FROM dbo.SeverityLevel AS s
    LEFT JOIN dbo.vw_IndicatorCounts AS c WITH (NOEXPAND) ON c.SeverityID = s.SeverityID AND c.Status = 'active'
    GROUP BY s.SeverityID, s.Code, s.Name
    ORDER BY s.SeverityID DESC;

    SELECT t.Code, t.Name, SUM(c.Total) AS Total
    FROM dbo.IndicatorType AS t
    JOIN dbo.vw_IndicatorCounts AS c WITH (NOEXPAND) ON c.TypeID = t.TypeID AND c.Status = 'active'
    GROUP BY t.TypeID, t.Code, t.Name
    ORDER BY Total DESC;
END;
GO

/* Query Store: ortalama süreye göre en pahalı sorgular (yönetici; VIEW DATABASE STATE) */
CREATE OR ALTER PROCEDURE dbo.sp_TopQueries @Top INT = 10
AS
BEGIN
    SET NOCOUNT ON;
    SELECT TOP (@Top)
           q.query_id AS QueryID,
           LEFT(REPLACE(REPLACE(qt.query_sql_text, CHAR(13), N' '), CHAR(10), N' '), 400) AS QueryText,
           SUM(rs.count_executions) AS Executions,
           CAST(SUM(rs.avg_duration * rs.count_executions) / NULLIF(SUM(rs.count_executions), 0) / 1000.0 AS DECIMAL(12,2)) AS AvgMs,
           CAST(MAX(rs.max_duration) / 1000.0 AS DECIMAL(12,2)) AS MaxMs,
           CAST(SUM(rs.avg_logical_io_reads * rs.count_executions) / NULLIF(SUM(rs.count_executions), 0) AS DECIMAL(14,1)) AS AvgReads,
           COUNT(DISTINCT p.plan_id) AS Plans,
           CAST(MAX(rs.last_execution_time) AS DATETIME2(0)) AS LastRun   -- datetimeoffset: sürücüler için düz tarih
    FROM sys.query_store_query AS q
    JOIN sys.query_store_query_text AS qt ON qt.query_text_id = q.query_text_id
    JOIN sys.query_store_plan AS p ON p.query_id = q.query_id
    JOIN sys.query_store_runtime_stats AS rs ON rs.plan_id = p.plan_id
    WHERE qt.query_sql_text NOT LIKE N'%query_store%'
    GROUP BY q.query_id, qt.query_sql_text
    ORDER BY AvgMs DESC;
END;
GO
GRANT EXECUTE ON dbo.sp_IndicatorCountsFast TO tip_reader;
GO
