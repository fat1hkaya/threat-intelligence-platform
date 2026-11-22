"""Koruma testi: test oturumu canlı veritabanına (ThreatLens) hiçbir satır yazmamalı ve silmemeli.
Dosya adı 'zz' ile başlar: pytest dosyaları alfabetik çalıştırdığı için en son çalışır.
Oturum başındaki satır sayıları conftest.LIVE_BEFORE'da; burada yeniden sayılıp karşılaştırılır.
Not: test sürerken zamanlanmış besleme senkronu ya da uygulamayı kullanan biri canlı veritabanına yazarsa bu test
yanlış alarm verebilir; o durumda yeniden çalıştırın."""
import pytest

import conftest


def test_live_database_untouched():
    if conftest.LIVE_BEFORE is None:
        pytest.skip(f"Canlı veritabanı ({conftest.LIVE_DB}) bu sunucuda yok")
    after = conftest.live_row_counts()
    assert after is not None
    changed = {t: (conftest.LIVE_BEFORE.get(t), n) for t, n in after.items() if conftest.LIVE_BEFORE.get(t) != n}
    assert not changed, f"Testler canlı veritabanını değiştirdi (tablo: önce, sonra): {changed}"


def test_tests_ran_on_test_database(conn):
    assert conn.cursor().execute("SELECT DB_NAME();").fetchone()[0] == conftest.TEST_DB
