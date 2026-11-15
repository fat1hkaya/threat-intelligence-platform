"""Log ayıklama birim testleri (veritabanı gerekmez)."""
from app.services.hunt import extract

LOG = """\
2026-11-15T10:00:01 ALLOW src=10.0.0.5 dst=198.51.100.23:443 host=cdn.kotu-ornek.example
2026-11-15T10:00:02 GET hxxp://Kotu-Ornek[.]example/load/x.bin?id=7 ua="Mozilla"
2026-11-15T10:00:03 file=update.exe sha256=AEEB5608B2ED003DD641AEE399D8176413CDAA4CB415B7CF24FEFBBE5F7A6026
2026-11-15T10:00:04 DNS query mail.ornek.test -> 203.0.113[.]9
2026-11-15T10:00:05 smtp from=phish@kotu-ornek.example md5=d41d8cd98f00b204e9800998ecf8427e
2026-11-15T10:00:06 GET hxxp://Kotu-Ornek[.]example/load/x.bin?id=7
"""


def _index(ex):
    return {(c.type, c.value): c for c in ex.candidates.values()}


def test_extracts_all_types_and_refangs():
    c = _index(extract(LOG))
    assert ("ipv4", "198.51.100.23") in c and ("ipv4", "203.0.113.9") in c
    assert ("url", "http://kotu-ornek.example/load/x.bin?id=7") in c
    assert ("sha256", "aeeb5608b2ed003dd641aee399d8176413cdaa4cb415b7cf24fefbbe5f7a6026") in c
    assert ("md5", "d41d8cd98f00b204e9800998ecf8427e") in c
    assert ("email", "phish@kotu-ornek.example") in c
    assert ("domain", "mail.ornek.test") in c


def test_url_host_and_parent_domains():
    c = _index(extract(LOG))
    assert c[("domain", "cdn.kotu-ornek.example")].kind == "exact"
    assert c[("domain", "kotu-ornek.example")].kind in ("host", "parent")
    assert c[("domain", "ornek.test")].kind == "parent"


def test_hits_and_first_line():
    c = _index(extract(LOG))
    url = c[("url", "http://kotu-ornek.example/load/x.bin?id=7")]
    assert url.hits == 2 and url.first_line == 2 and "hxxp" in url.sample


def test_file_names_are_not_domains():
    c = _index(extract(LOG))
    assert ("domain", "update.exe") not in c and ("domain", "x.bin") not in c


def test_ip_inside_url_not_double_counted_as_exact():
    c = _index(extract("GET http://192.0.2.44/a.php\n"))
    assert c[("ipv4", "192.0.2.44")].kind == "host"


def test_defanged_https_keeps_scheme():
    c = _index(extract("visit hxxps://Secure-Login[.]example/a and fxp://files[.]example/b\n"))
    assert ("url", "https://secure-login.example/a") in c and ("url", "ftp://files.example/b") in c
