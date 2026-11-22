"""Besleme senkronu, konsol penceresi açmadan (Windows Görev Zamanlayıcı pythonw.exe ile çalıştırır).

    .venv\\Scripts\\pythonw.exe scripts\\sync_feeds.py      # görev böyle çalıştırır (pencere yok)
    .venv\\Scripts\\python.exe  scripts\\sync_feeds.py      # elle; çıktı yine logs\\sync_feeds.log dosyasına

pythonw.exe'de stdout/stderr yoktur: tüm çıktı UTF-8 olarak logs/sync_feeds.log dosyasına yönlendirilir.
Aynı anda iki senkron çalışmasın diye kilit dosyası kullanılır (önceki çalışma sürüyorsa yeni çalışma atlanır).
"""
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEEDS = ["threatfox", "malwarebazaar", "urlhaus", "feodo", "kev", "malpedia"]
STALE_LOCK_SECONDS = 2 * 3600


def main() -> int:
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    lock = logs / "sync_feeds.lock"
    with open(logs / "sync_feeds.log", "a", encoding="utf-8", buffering=1) as out:
        sys.stdout = sys.stderr = out
        print(f"==== {datetime.now():%d.%m.%Y %H:%M:%S} ====")
        if lock.exists() and time.time() - lock.stat().st_mtime < STALE_LOCK_SECONDS:
            print("Önceki senkron hâlâ çalışıyor (kilit dosyası var); bu çalışma atlandı.")
            return 0
        lock.write_text(str(os.getpid()), encoding="utf-8")
        started = time.perf_counter()
        try:
            from importers.__main__ import main as run_importers
            run_importers(FEEDS)
            print(f"Bitti: {time.perf_counter() - started:.0f} sn")
            return 0
        except Exception:  # noqa: BLE001 - zamanlanmış görev her hatayı günlüğe yazıp çıkış koduyla bildirir
            traceback.print_exc()
            return 1
        finally:
            lock.unlink(missing_ok=True)
            sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__


if __name__ == "__main__":
    sys.exit(main())
