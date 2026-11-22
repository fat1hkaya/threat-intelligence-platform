"""İçe aktarma hattı: satırları normalleştirir, ImportJob açar, veritabanına yığınlar hâlinde gönderir.

Hem arayüzdeki dosya yükleme (POST /api/imports) hem de importers/ altındaki besleme
modülleri bu hattı kullanır. Veritabanı işi sp_StartImportJob, sp_BulkImportIndicators
ve sp_FinishImportJob yordamlarıyla yapılır; her yığın kendi transaction'ındadır.
"""
import csv
import io
import json
from dataclasses import dataclass, field

from .normalize import InvalidIndicator, guess_type, normalize

BATCH_SIZE = 1000
FIELDS = ("type", "value", "confidence", "severity", "tlp", "description", "first_seen", "last_seen",
          "expires_at", "malware", "malware_aliases", "role", "evidence", "tags")


@dataclass
class ImportResult:
    job_id: int
    status: str = "running"
    read: int = 0
    inserted: int = 0
    updated: int = 0
    skipped: int = 0
    failed: int = 0
    rolled_back: int = 0
    message: str | None = None
    errors: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("job_id", "status", "read", "inserted", "updated", "skipped",
                                              "failed", "rolled_back", "message", "errors")}


def prepare(item: dict, row_no: int) -> dict:
    """Ham satırı veritabanının beklediği biçime getirir. Normalleştirilemeyen satır 'error' alanı taşır;
    satır yine gönderilir ki hata kaydı ve (katı modda) ROLLBACK veritabanında gerçekleşsin."""
    raw = str(item.get("value") or "").strip()
    type_code = (item.get("type") or "").strip().lower() or guess_type(raw) or ""
    out = {k: item.get(k) for k in FIELDS if item.get(k) not in (None, "")}
    out.update(row=row_no, type=type_code, value=raw[:400])
    try:
        out["normalized"] = normalize(type_code, raw)
    except InvalidIndicator as exc:
        out["normalized"] = raw[:400].lower()
        out["error"] = str(exc)[:300]
    if isinstance(out.get("tags"), str):
        out["tags"] = [t.strip() for t in out["tags"].replace(";", ",").split(",") if t.strip()]
    for key in ("confidence",):
        if key in out:
            try:
                out[key] = int(out[key])
            except (TypeError, ValueError):
                out.pop(key)
    return out


def parse_file(name: str, content: bytes) -> list[dict]:
    """CSV (başlık satırlı) veya JSON (dizi ya da {"indicators": [...]}) dosyasını satır listesine çevirir."""
    text = content.decode("utf-8-sig", errors="replace")
    if name.lower().endswith(".json"):
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("indicators") or data.get("data") or []
        if not isinstance(data, list):
            raise ValueError("JSON dosyası bir dizi ya da 'indicators' alanı içermeli.")
        return [d if isinstance(d, dict) else {"value": str(d)} for d in data]
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
    if rows and "value" not in {(k or "").strip().lower() for k in rows[0]}:
        raise ValueError("CSV dosyasında 'value' sütunu bulunmalı (isteğe bağlı: type, confidence, severity, tlp, malware, tags).")
    return [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in rows]


def run_import(conn, source_id: int, items: list[dict], *, job_type: str = "feed", file_name: str | None = None,
               strict: bool = False, user_id: int | None = None) -> ImportResult:
    """Tek bir içe aktarma işini baştan sona yürütür. conn: autocommit açık pyodbc bağlantısı."""
    cur = conn.cursor()
    job_id = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = ?, @FileName = ?, @IsStrict = ?, @UserID = ?;",
                         source_id, job_type, file_name, int(strict), user_id).fetchone()[0]
    result = ImportResult(job_id=job_id)
    prepared = [prepare(item, n) for n, item in enumerate(items, start=1)]
    # Katı modda tüm dosya tek yığın olmalı: aksi hâlde önceki yığınlar zaten kalıcı olur
    size = (len(prepared) or 1) if strict else BATCH_SIZE
    try:
        for start in range(0, len(prepared), size):
            row = cur.execute("EXEC dbo.sp_BulkImportIndicators @SourceID = ?, @Json = ?, @JobID = ?, @Strict = ?;",
                              source_id, json.dumps(prepared[start:start + size], ensure_ascii=False, default=str),
                              job_id, int(strict)).fetchone()
            result.read += row.RowsRead
            result.inserted += row.RowsInserted
            result.updated += row.RowsUpdated
            result.skipped += row.RowsSkipped
            result.failed += row.RowsFailed
            result.rolled_back += row.RowsRolledBack
            result.message = row.Message or result.message
        final = cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job_id).fetchone()
        result.status = final.Status
    except Exception as exc:  # beklenmeyen hata: iş "failed" olarak kapanır, mesaj saklanır
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job_id, str(exc)[:1000]).fetchone()
        result.status, result.message = "failed", str(exc)
    result.errors = [{"row": r.RowNo, "value": r.RawValue, "reason": r.Reason} for r in cur.execute(
        "SELECT TOP (50) RowNo, RawValue, Reason FROM dbo.ImportJobError WHERE JobID = ? ORDER BY RowNo;", job_id).fetchall()]
    return result
