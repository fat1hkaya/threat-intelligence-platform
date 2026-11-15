"""Gösterge (IOC) normalleştirme ve doğrulama kuralları.

Veritabanı aynı göstergeyi iki kez kaydetmemek için (TypeID, NormalizedValue)
benzersizlik kısıtı kullanır. Bu modül, farklı yazılmış aynı değeri tek bir
kanonik biçime indirger:

    tip      örnek girdi                         kanonik biçim
    ipv4     010.000.002.001 / 10.0.2[.]1        10.0.2.1
    ipv6     2001:DB8:0:0::1                     2001:db8::1
    domain   WWW.Evil[.]Example.               www.evil.example
    url      hxxps://Evil[.]Example:443/A?b=1    https://evil.example/A?b=1
    md5/sha1/sha256  büyük harf, boşluklu        küçük harf onaltılık
    email    Ali@Example.COM                     ali@example.com

Kurallar uygulama katmanındadır; veritabanı fn_IsValidIndicator ile biçimi
ikinci kez denetler (savunma derinliği).
"""
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email")
HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class InvalidIndicator(ValueError):
    """Değer, belirtilen tipe uymuyor. Mesaj kullanıcıya gösterilir."""


def refang(value: str) -> str:
    """Güvenli yazımı (defang) çözer: 1.2.3[.]4, evil(.)com, hxxp://, [:]//"""
    v = value.strip().strip('"\'<>')
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", v, flags=re.I)
    v = re.sub(r"\[:\]", ":", v)
    v = re.sub(r"\[/\]", "/", v)
    v = re.sub(r"^h[x*]{2}p(s?)://", r"http\1://", v, flags=re.I)
    v = re.sub(r"^fxp://", "ftp://", v, flags=re.I)
    return v


def guess_type(value: str) -> str | None:
    """Değerin biçiminden tipini tahmin eder. Belirsizse None."""
    v = refang(value)
    low = v.lower()
    if re.fullmatch(r"[0-9a-f]{64}", low):
        return "sha256"
    if re.fullmatch(r"[0-9a-f]{40}", low):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{32}", low):
        return "md5"
    if re.match(r"^(https?|ftp)://", low):
        return "url"
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if "@" in v and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        return "email"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\.?", v):
        return "domain"
    return None


def _domain(v: str) -> str:
    host = v.strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")            # ünlü/IDN alan adları: xn-- biçimi
    except UnicodeError as exc:
        raise InvalidIndicator("Alan adı IDNA biçimine çevrilemedi.") from exc
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or not all(_LABEL.match(l) for l in labels) or labels[-1].isdigit():
        raise InvalidIndicator("Geçerli bir alan adı değil.")
    return host


def normalize(type_code: str, value: str) -> str:
    """Değeri kanonik biçime çevirir; uymuyorsa InvalidIndicator fırlatır."""
    if type_code not in TYPES:
        raise InvalidIndicator(f"Bilinmeyen gösterge tipi: {type_code}")
    if value is None or not str(value).strip():
        raise InvalidIndicator("Değer boş.")
    v = refang(str(value))

    if type_code == "ipv4":
        parts = v.split(".")
        if len(parts) != 4 or not all(p.isdigit() and len(p) <= 3 for p in parts):
            raise InvalidIndicator("IPv4 adresi dört noktalı sayıdan oluşmalı (ör. 198.51.100.7).")
        nums = [int(p) for p in parts]                         # baştaki sıfırlar atılır: 010 -> 10
        if any(n > 255 for n in nums):
            raise InvalidIndicator("IPv4 adresinin her bölümü 0-255 arasında olmalı.")
        return ".".join(map(str, nums))

    if type_code == "ipv6":
        try:
            ip = ipaddress.IPv6Address(v.strip("[]"))
        except ValueError as exc:
            raise InvalidIndicator("Geçerli bir IPv6 adresi değil.") from exc
        return ip.compressed

    if type_code == "domain":
        return _domain(v)

    if type_code == "url":
        if not re.match(r"^(https?|ftp)://", v, flags=re.I):
            v = "http://" + v
        try:
            parts = urlsplit(v)
            host = parts.hostname or ""
            port = parts.port
        except ValueError as exc:
            raise InvalidIndicator("URL çözümlenemedi.") from exc
        if not host:
            raise InvalidIndicator("URL'de alan adı veya IP bulunamadı.")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = _domain(host)
        scheme = parts.scheme.lower()
        default = {"http": 80, "https": 443, "ftp": 21}[scheme]
        netloc = host if port in (None, default) else f"{host}:{port}"
        if ":" in host and not host.startswith("["):
            netloc = f"[{host}]" + ("" if port in (None, default) else f":{port}")
        url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))   # yol ve sorgu büyük/küçük harf korunur
        if len(url) > 400:
            raise InvalidIndicator("URL 400 karakterden uzun.")
        return url

    if type_code in HASH_LEN:
        h = re.sub(r"\s+", "", v).lower()
        if len(h) != HASH_LEN[type_code] or not _HEX.match(h):
            raise InvalidIndicator(f"{type_code.upper()} özeti {HASH_LEN[type_code]} karakter onaltılık (0-9, a-f) olmalı.")
        return h

    # email
    m = re.fullmatch(r"([^@\s]+)@([^@\s]+)", v)
    if not m:
        raise InvalidIndicator("Geçerli bir e-posta adresi değil.")
    return f"{m.group(1).lower()}@{_domain(m.group(2))}"


def defang(value: str) -> str:
    """Rapor ve kopyalama için güvenli yazım."""
    return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]")
