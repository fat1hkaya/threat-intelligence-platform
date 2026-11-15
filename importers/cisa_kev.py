"""CISA Known Exploited Vulnerabilities kataloğu (herkese açık JSON) -> dbo.Vulnerability.
MERGE ile tekrar çalıştırılabilir; her çalıştırma bir ImportJob kaydı oluşturur."""
import json
import urllib.request

from ._db import source_id

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

MERGE_SQL = """
SET NOCOUNT ON;
DECLARE @changes TABLE (Act NVARCHAR(10));
MERGE dbo.Vulnerability AS t
USING (SELECT * FROM OPENJSON(?) WITH (
           cve VARCHAR(20) '$.cve', title NVARCHAR(300) '$.title', vendor NVARCHAR(100) '$.vendor',
           product NVARCHAR(150) '$.product', [desc] NVARCHAR(2000) '$.desc', added DATE '$.added')
       WHERE cve LIKE 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]%') AS s
ON t.CveID = s.cve
WHEN MATCHED AND t.IsKnownExploited = 0 THEN UPDATE SET IsKnownExploited = 1
WHEN NOT MATCHED THEN INSERT (CveID, Title, Vendor, Product, Description, PublishedDate, IsKnownExploited)
                      VALUES (s.cve, s.title, s.vendor, s.product, s.[desc], s.added, 1)
OUTPUT $action INTO @changes;
SELECT ISNULL(SUM(CASE WHEN Act = 'INSERT' THEN 1 ELSE 0 END), 0) AS Ins,
       ISNULL(SUM(CASE WHEN Act = 'UPDATE' THEN 1 ELSE 0 END), 0) AS Upd;
"""


def run(conn) -> dict:
    cur = conn.cursor()
    src = source_id(conn, "CISA KEV")
    job = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = 'feed';", src).fetchone()[0]
    try:
        req = urllib.request.Request(URL, headers={"User-Agent": "ThreatLens/1.0"})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read())
        rows = [{"cve": v["cveID"], "title": (v.get("vulnerabilityName") or v["cveID"])[:300], "vendor": (v.get("vendorProject") or "")[:100],
                 "product": (v.get("product") or "")[:150], "desc": (v.get("shortDescription") or "")[:2000], "added": v.get("dateAdded")}
                for v in data.get("vulnerabilities", [])]
        res = cur.execute(MERGE_SQL, json.dumps(rows, ensure_ascii=False)).fetchone()
        cur.execute("UPDATE dbo.ImportJob SET RowsRead = ?, RowsInserted = ?, RowsUpdated = ?, RowsSkipped = ? WHERE JobID = ?;",
                    len(rows), res.Ins, res.Upd, len(rows) - res.Ins - res.Upd, job)
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job).fetchone()
        return {"job_id": job, "status": "success", "read": len(rows), "inserted": res.Ins, "updated": res.Upd}
    except Exception as exc:
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job, str(exc)[:1000]).fetchone()
        return {"job_id": job, "status": "failed", "message": str(exc)}
