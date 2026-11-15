"""MITRE ATT&CK Enterprise anlık görüntüsünü (database/seed/attack_snapshot.json) yükler.
Güncel sürümü almak için önce: python -m importers.build_attack_snapshot"""
import time

from ._db import ROOT, source_id

SNAPSHOT = ROOT / "database" / "seed" / "attack_snapshot.json"


def run(conn) -> dict:
    cur = conn.cursor()
    src = source_id(conn, "MITRE ATT&CK")
    job = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = 'attack', @FileName = ?;", src, SNAPSHOT.name).fetchone()[0]
    started = time.perf_counter()
    try:
        row = cur.execute("EXEC dbo.sp_ImportAttackBundle @Json = ?;", SNAPSHOT.read_text(encoding="utf-8")).fetchone()
        total = row.Tactics + row.Techniques + row.Actors + row.Malware + row.Campaigns
        cur.execute("UPDATE dbo.ImportJob SET RowsRead = ?, RowsInserted = ? WHERE JobID = ?;", total + row.Evidence, total + row.Evidence, job)
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job).fetchone()
        return {"job_id": job, "status": "success", "tactics": row.Tactics, "techniques": row.Techniques, "actors": row.Actors,
                "malware": row.Malware, "campaigns": row.Campaigns, "evidence": row.Evidence, "seconds": round(time.perf_counter() - started, 1)}
    except Exception as exc:
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job, str(exc)[:1000]).fetchone()
        raise
