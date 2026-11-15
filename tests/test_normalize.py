"""Normalleştirme kuralları (veritabanı gerektirmez):  pytest tests/test_normalize.py -v"""
import pytest

from app.services.importer import parse_file, prepare
from app.services.normalize import InvalidIndicator, defang, guess_type, normalize, refang


@pytest.mark.parametrize("type_code, raw, expected", [
    ("ipv4", "010.000.002.001", "10.0.2.1"),
    ("ipv4", "198.51.100[.]7", "198.51.100.7"),
    ("ipv6", "2001:DB8:0:0::1", "2001:db8::1"),
    ("domain", "WWW.Evil[.]Example.", "www.evil.example"),
    ("domain", "bücher.example", "xn--bcher-kva.example"),
    ("url", "hxxps://Evil[.]Example:443/A?b=1", "https://evil.example/A?b=1"),
    ("url", "evil.example/gate.php", "http://evil.example/gate.php"),
    ("url", "http://198.51.100.7:8080/x", "http://198.51.100.7:8080/x"),
    ("md5", " 44D88612FEA8A8F36DE82E1278ABB02F ", "44d88612fea8a8f36de82e1278abb02f"),
    ("sha256", "A" * 64, "a" * 64),
    ("email", "Ali@Example.COM", "ali@example.com"),
])
def test_normalize(type_code, raw, expected):
    assert normalize(type_code, raw) == expected


@pytest.mark.parametrize("type_code, raw", [
    ("ipv4", "192.0.2.999"), ("ipv4", "1.2.3"), ("ipv6", "2001:::1"), ("domain", "localhost"),
    ("domain", "-bad.example"), ("sha256", "abc123"), ("md5", "z" * 32), ("email", "no-at-sign"),
    ("url", "http://"), ("unknown", "x"), ("ipv4", "   "),
])
def test_invalid(type_code, raw):
    with pytest.raises(InvalidIndicator):
        normalize(type_code, raw)


@pytest.mark.parametrize("raw, expected", [
    ("192.0.2.1", "ipv4"), ("2001:db8::1", "ipv6"), ("evil.example", "domain"), ("hxxp://evil[.]example/x", "url"),
    ("a" * 32, "md5"), ("a" * 40, "sha1"), ("a" * 64, "sha256"), ("x@evil.example", "email"), ("merhaba", None),
])
def test_guess_type(raw, expected):
    assert guess_type(raw) == expected


def test_defang_roundtrip():
    assert defang("http://evil.example/a") == "hxxp://evil[.]example/a"
    assert refang(defang("http://evil.example/a")) == "http://evil.example/a"


def test_prepare_marks_errors_but_keeps_row():
    good = prepare({"value": "hxxp://evil[.]example/x", "tags": "a, b"}, 1)
    bad = prepare({"type": "sha256", "value": "abc123"}, 2)
    assert good["type"] == "url" and good["normalized"] == "http://evil.example/x" and good["tags"] == ["a", "b"]
    assert bad["row"] == 2 and "error" in bad


def test_parse_csv_and_json():
    rows = parse_file("x.csv", "type;value;confidence\nipv4;192.0.2.1;80\n".encode())
    assert rows == [{"type": "ipv4", "value": "192.0.2.1", "confidence": "80"}]
    assert parse_file("x.json", b'{"indicators":[{"value":"evil.example"}]}') == [{"value": "evil.example"}]
    with pytest.raises(ValueError):
        parse_file("x.csv", b"foo,bar\n1,2\n")
