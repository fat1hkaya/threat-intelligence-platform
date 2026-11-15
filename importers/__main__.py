"""Komut satırından içe aktarma.

    python -m importers attack                       # MITRE ATT&CK (yerel anlık görüntü)
    python -m importers threatfox malwarebazaar      # abuse.ch (ABUSECH_AUTH_KEY gerekir)
    python -m importers urlhaus feodo kev
    python -m importers ip2asn                       # IP -> ASN/ülke aralıkları (iptoasn.com, PDDL)
    python -m importers all                          # hepsi; biri başarısız olsa da diğerleri denenir
"""
import sys

from . import abusech, cisa_kev, ip2asn, malpedia, mitre_attack
from ._db import connect, source_id
from app.services.importer import run_import


def main(args: list[str]) -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    wanted = args or ["all"]
    if "all" in wanted:
        wanted = ["attack", *abusech.FEEDS, "kev", "malpedia"]
    conn = connect()
    for name in wanted:
        try:
            if name == "attack":
                print("MITRE ATT&CK:", mitre_attack.run(conn))
            elif name == "malpedia":
                print("Malpedia:", malpedia.run(conn))
            elif name == "ip2asn":
                print("iptoasn.com:", ip2asn.run(conn))
                continue
            elif name == "kev":
                print("CISA KEV:", cisa_kev.run(conn))
            elif name in abusech.FEEDS:
                source, items = abusech.FEEDS[name]()
                res = run_import(conn, source_id(conn, source), items, job_type="feed")
                print(f"{source}: {res.status}, okunan {res.read}, eklenen {res.inserted}, güncellenen {res.updated}, "
                      f"atlanan {res.skipped}, hatalı {res.failed}")
            else:
                print(f"Bilinmeyen kaynak: {name}. Seçenekler: attack, {', '.join(abusech.FEEDS)}, kev, malpedia, ip2asn, all")
                continue
            if name != "kev":
                conn.cursor().execute("EXEC dbo.sp_RefreshActorSimilarity;")
        except abusech.FeedError as exc:
            print(f"{name}: atlandı - {exc}")
        except Exception as exc:  # bir kaynak hata verse de diğerleri denenir
            print(f"{name}: başarısız - {exc}")
    conn.close()


if __name__ == "__main__":
    main(sys.argv[1:])
