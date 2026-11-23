"""Log'dan geriye dönük av: serbest metinden (güvenlik duvarı, proxy, DNS, EDR logları) IOC adaylarını ayıklar.

Her aday kanonik biçime getirilir (normalize.py) ki veritabanındaki UNIQUE (TypeID, NormalizedValue)
indeksiyle birebir eşleşebilsin. Ayrıca:
- URL'nin ana bilgisayarı (domain veya IP) ayrı aday olur ("host" eşleşmesi),
- alt domainlerin üst domainleri aday olur: cdn.kotu.example -> kotu.example ("parent" eşleşmesi).
Eşleştirme veritabanında tek bir set tabanlı sorguyla yapılır (dbo.sp_RetroHunt).
"""
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .normalize import InvalidIndicator, normalize, refang

MAX_CANDIDATES = 20000
DOT = r"(?:\.|\[\.\]|\(\.\))"
RX = {
    "url": re.compile(r"\b(?:https?|hxxps?|ftp)(?:://|\[:\]//|\[://\])[^\s\"'<>()\[\]{}|\\^`]+", re.I),
    "email": re.compile(rf"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:{DOT}[A-Za-z0-9-]+)*{DOT}[A-Za-z]{{2,24}}\b"),
    "ipv4": re.compile(rf"(?<![\d.])(?:\d{{1,3}}{DOT}){{3}}\d{{1,3}}(?![\d.])"),
    "sha256": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])"),
    "sha1": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])"),
    "md5": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])"),
    "domain": re.compile(rf"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?{DOT})+[A-Za-z][A-Za-z0-9-]{{1,23}}(?![\w-])"),
}
# Dosya adı gibi görünen "domain" adaylarını ele (update.exe, index.php ...)
FILE_EXT = {"exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "php", "asp", "aspx", "jsp", "html", "htm",
            "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "txt", "log", "csv", "json", "xml", "yml", "yaml", "zip", "rar", "7z",
            "gz", "tar", "iso", "img", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "lnk", "tmp", "dat", "bin", "py",
            "sh", "conf", "ini", "cfg", "bak", "old", "jar", "class", "apk", "local", "lan", "internal", "localdomain", "arpa"}


@dataclass
class Candidate:
    type: str
    value: str
    kind: str                 # exact | host | parent
    source: str               # logda geçen biçim
    hits: int = 0
    first_line: int = 0
    sample: str = ""


@dataclass
class Extraction:
    lines: int = 0
    candidates: dict = field(default_factory=dict)      # (type, value) -> Candidate
    truncated: bool = False
    nonempty: int = 0                                    # boş olmayan satır sayısı
    hit_lines: set = field(default_factory=set)          # en az bir aday çıkan satırlar

    @property
    def unrecognized_lines(self) -> int:
        """İçinden hiçbir IP, domain, URL, e-posta ya da hash çıkmayan (boş olmayan) satır sayısı."""
        return self.nonempty - len(self.hit_lines)

    def add(self, type_: str, value: str, kind: str, source: str, line_no: int, line: str) -> None:
        key = (type_, value)
        self.hit_lines.add(line_no)
        c = self.candidates.get(key)
        if c is None:
            if len(self.candidates) >= MAX_CANDIDATES:
                self.truncated = True
                return
            c = self.candidates[key] = Candidate(type_, value, kind, source[:400], 0, line_no, line.strip()[:300])
        elif kind == "exact" and c.kind != "exact":       # aynı değer birebir de geçiyorsa en güçlü eşleşme türü kalır
            c.kind, c.source = "exact", source[:400]
        c.hits += 1

    def as_json(self) -> list[dict]:
        return [{"type": c.type, "value": c.value, "kind": c.kind, "source": c.source, "hits": c.hits,
                 "line": c.first_line, "sample": c.sample} for c in self.candidates.values()]


def _parents(domain: str) -> list[str]:
    """a.b.kotu.example -> [b.kotu.example, kotu.example] (tek etiketli TLD'ye kadar inilmez)."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def _add_domain(ex: Extraction, raw: str, kind: str, n: int, line: str) -> None:
    try:
        d = normalize("domain", raw)
    except InvalidIndicator:
        return
    if d.rsplit(".", 1)[-1] in FILE_EXT:
        return
    ex.add("domain", d, kind, raw, n, line)
    for p in _parents(d):
        ex.add("domain", p, "parent", raw, n, line)


_DEFANG = [(re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."), (re.compile(r"\[:\]"), ":"),
           (re.compile(r"\[/\]"), "/"), (re.compile(r"\bh[x*]{2}p(s?)(?=:|\[:)", re.I), r"http\1"), (re.compile(r"\bfxp(?=:)", re.I), "ftp")]


def _refang_line(line: str) -> str:
    """Satır içindeki tüm güvenli yazımları çözer (normalize.refang yalnızca tek bir değer içindir)."""
    for rx, rep in _DEFANG:
        line = rx.sub(rep, line)
    return line


def extract(text: str) -> Extraction:
    ex = Extraction()
    for n, original in enumerate(text.splitlines(), start=1):
        ex.lines = n
        if not original.strip():
            continue
        ex.nonempty += 1
        line = _refang_line(original)
        spans: list[tuple[int, int]] = []          # URL/e-posta içindeki parçaları ayrıca domain diye saymamak için
        for m in RX["url"].finditer(line):
            raw = m.group(0).rstrip(".,;:'\")]")
            spans.append(m.span())
            try:
                u = normalize("url", raw)
            except InvalidIndicator:
                continue
            ex.add("url", u, "exact", raw, n, original)
            host = urlsplit(u).hostname or ""
            try:
                ip = ipaddress.ip_address(host)
                ex.add("ipv4" if ip.version == 4 else "ipv6", str(ip), "host", raw, n, line)
            except ValueError:
                _add_domain(ex, host, "host", n, line)
        for m in RX["email"].finditer(line):
            spans.append(m.span())
            try:
                ex.add("email", normalize("email", m.group(0)), "exact", m.group(0), n, line)
            except InvalidIndicator:
                pass
        inside = lambda s, e: any(a <= s and e <= b for a, b in spans)      # noqa: E731
        for t in ("sha256", "sha1", "md5"):
            for m in RX[t].finditer(line):
                ex.add(t, m.group(0).lower(), "exact", m.group(0), n, line)
        for m in RX["ipv4"].finditer(line):
            if inside(*m.span()):
                continue
            try:
                ex.add("ipv4", normalize("ipv4", m.group(0)), "exact", m.group(0), n, line)
            except InvalidIndicator:
                pass
        for m in RX["domain"].finditer(line):
            if inside(*m.span()) or re.fullmatch(r"[\d.\[\]()]+", m.group(0)):
                continue
            _add_domain(ex, refang(m.group(0)), "exact", n, line)
    return ex
