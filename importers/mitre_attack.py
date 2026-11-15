"""MITRE ATT&CK Enterprise anlık görüntüsünü (database/seed/attack_snapshot.json) yükler.
Güncel sürümü almak için önce: python -m importers.build_attack_snapshot"""
import time

from ._db import ROOT, source_id

SNAPSHOT = ROOT / "database" / "seed" / "attack_snapshot.json"

# Hedef sektör: ATT&CK aktör açıklamasında geçen anahtar sözcüklerden SEZGİSEL çıkarım (raporda belirtilmeli).
SECTOR_HINTS = [
    ("Finans ve bankacılık", ["financ", "bank"]), ("Kamu", ["government"]), ("Savunma", ["defense", "military"]),
    ("Enerji", ["energy", " oil", "petro"]), ("Sağlık", ["health", "medical", "pharma"]), ("Telekomünikasyon", ["telecom"]),
    ("Eğitim", ["universit", "academ", "education"]), ("Üretim", ["manufactur"]), ("Perakende", ["retail", "hospitality", "restaurant"]),
    ("Ulaştırma", ["transport", "shipping", "logistic", "maritime"]), ("Medya", ["media", "journalis"]),
    ("Teknoloji", ["technology", "software", "semiconductor"]), ("Havacılık", ["aerospace", "aviation"]),
    ("Hukuk ve danışmanlık", ["law firm", "legal", "consult"]),
]


def infer_sectors(cur) -> None:
    """Küme tabanlı INSERT ... SELECT: açıklamasında sektör sözcüğü geçen aktöre hedef sektör ekler."""
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


def run(conn) -> dict:
    cur = conn.cursor()
    src = source_id(conn, "MITRE ATT&CK")
    job = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = 'attack', @FileName = ?;", src, SNAPSHOT.name).fetchone()[0]
    started = time.perf_counter()
    try:
        row = cur.execute("EXEC dbo.sp_ImportAttackBundle @Json = ?;", SNAPSHOT.read_text(encoding="utf-8")).fetchone()
        total = row.Tactics + row.Techniques + row.Actors + row.Malware + row.Campaigns
        infer_sectors(cur)
        cur.execute("UPDATE dbo.ImportJob SET RowsRead = ?, RowsInserted = ? WHERE JobID = ?;", total + row.Evidence, total + row.Evidence, job)
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job).fetchone()
        return {"job_id": job, "status": "success", "tactics": row.Tactics, "techniques": row.Techniques, "actors": row.Actors,
                "malware": row.Malware, "campaigns": row.Campaigns, "evidence": row.Evidence, "seconds": round(time.perf_counter() - started, 1)}
    except Exception as exc:
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job, str(exc)[:1000]).fetchone()
        raise
