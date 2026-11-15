"""iptoasn.com IPv4 -> ASN / ülke veri seti.

Kullanım:  python -m importers ip2asn
- Kaynak: https://iptoasn.com/data/ip2asn-v4.tsv.gz  (Public Domain, PDDL v1.0; saatlik güncellenir)
- Biçim (sekmeyle ayrılmış): range_start  range_end  AS_number  country_code  AS_description
- Satırlar oturuma özel #ip2asn geçici tablosuna toplu yazılır (fast_executemany), ardından dbo.sp_LoadIpRanges
  tek işlemde aralıkları değiştirir ve tüm IP IOC'lerini yeniden zenginleştirir.
- İsteğe bağlı: TL_IP2ASN_FILE ortam değişkeni yerel bir .tsv/.tsv.gz dosyasını gösterirse indirme yapılmaz.
"""
import gzip
import io
import ipaddress
import os
import time
import urllib.request

from ._db import source_id

URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
UA = "ThreatLens/1.0 (universite VTYS projesi)"


class Ip2AsnError(RuntimeError):
    pass


def _open() -> tuple[io.TextIOBase, str]:
    local = os.getenv("TL_IP2ASN_FILE")
    if local:
        raw = open(local, "rb")
        name = os.path.basename(local)
    else:
        try:
            raw = io.BytesIO(urllib.request.urlopen(urllib.request.Request(URL, headers={"User-Agent": UA}), timeout=180).read())
        except Exception as exc:
            raise Ip2AsnError(f"iptoasn.com alınamadı: {exc}") from exc
        name = "ip2asn-v4.tsv.gz"
    head = raw.read(2)
    raw.seek(0)
    stream = gzip.GzipFile(fileobj=raw) if head == b"\x1f\x8b" else raw
    return io.TextIOWrapper(stream, encoding="utf-8", errors="replace"), name


def parse(lines) -> list[tuple]:
    rows = []
    for line in lines:
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) < 5:
            continue
        try:
            start, end, asn = int(ipaddress.IPv4Address(parts[0])), int(ipaddress.IPv4Address(parts[1])), int(parts[2])
        except ValueError:
            continue
        if asn <= 0 or end < start:          # 0 = "Not routed"
            continue
        cc = parts[3].strip().upper()
        rows.append((start, end, asn, cc if len(cc) == 2 and cc.isalpha() else None, parts[4].strip()[:200] or f"AS{asn}"))
    return rows


def run(conn) -> dict:
    cur = conn.cursor()
    src = source_id(conn, "iptoasn.com")
    started = time.perf_counter()
    name = os.path.basename(os.getenv("TL_IP2ASN_FILE") or "ip2asn-v4.tsv.gz")
    job = cur.execute("EXEC dbo.sp_StartImportJob @SourceID = ?, @JobType = 'feed', @FileName = ?;", src, name).fetchone()[0]
    try:
        text, _ = _open()
        with text:
            rows = parse(text)
        if len(rows) < 1000:
            raise Ip2AsnError(f"Beklenenden az aralık okundu ({len(rows)}); dosya bozuk olabilir.")
        cur.execute("""IF OBJECT_ID('tempdb..#ip2asn') IS NOT NULL DROP TABLE #ip2asn;
                       CREATE TABLE #ip2asn (StartIP BIGINT NOT NULL, EndIP BIGINT NOT NULL, ASN BIGINT NOT NULL,
                                             CountryCode CHAR(2) NULL, Name NVARCHAR(200) NOT NULL);""")
        cur.fast_executemany = True
        for i in range(0, len(rows), 50000):
            cur.executemany("INSERT INTO #ip2asn (StartIP, EndIP, ASN, CountryCode, Name) VALUES (?, ?, ?, ?, ?);", rows[i:i + 50000])
        cur.fast_executemany = False
        r = cur.execute("EXEC dbo.sp_LoadIpRanges @JobID = ?;", job).fetchone()
        cur.execute("DROP TABLE #ip2asn;")
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?;", job).fetchone()
        return {"job_id": job, "status": "success", "ranges": r.Ranges, "as_changed": r.AsChanged,
                "enriched_iocs": r.EnrichedIOCs, "seconds": round(time.perf_counter() - started, 1)}
    except Exception as exc:
        cur.execute("EXEC dbo.sp_FinishImportJob @JobID = ?, @Status = 'failed', @ErrorMessage = ?;", job, str(exc)[:1000]).fetchone()
        return {"job_id": job, "status": "failed", "message": str(exc)}
