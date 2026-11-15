"""Canlı sistemden belge üretir (elle güncel tutmak gerekmesin diye):
    docs/veritabani_nesneleri.md  - sys katalog görünümlerinden tablolar, sütunlar, kısıtlar, graf tabloları, nesneler
    docs/api.md                   - FastAPI OpenAPI şemasından uç nokta listesi
Çalıştırma: python scripts/gen_docs.py
"""
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from importers._db import connect  # noqa: E402

DOCS = ROOT / "docs"


def db_objects() -> str:
    cur = connect().cursor()
    out = ["# Veritabanı nesneleri (otomatik üretildi)", "",
           "> `python scripts/gen_docs.py` ile SQL Server sistem kataloğundan (sys.tables, sys.columns, sys.objects...) üretilmiştir.", ""]
    rows = cur.execute("""
        SELECT t.name, t.is_node, t.is_edge,
               (SELECT SUM(p.rows) FROM sys.partitions AS p WHERE p.object_id = t.object_id AND p.index_id IN (0, 1)) AS RowCnt
        FROM sys.tables AS t WHERE t.is_ms_shipped = 0 ORDER BY t.is_node, t.is_edge, t.name;""").fetchall()
    rel = [r for r in rows if not r.is_node and not r.is_edge]
    out += [f"## İlişkisel tablolar ({len(rel)})", "", "| Tablo | Satır | Sütunlar (PK **kalın**, FK → hedef) |", "|---|---:|---|"]
    pk = defaultdict(set)
    for r in cur.execute("""SELECT OBJECT_NAME(ic.object_id), c.name FROM sys.indexes i JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
                            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id WHERE i.is_primary_key = 1""").fetchall():
        pk[r[0]].add(r[1])
    fk = {}
    for r in cur.execute("""SELECT OBJECT_NAME(fc.parent_object_id), pc.name, OBJECT_NAME(fc.referenced_object_id)
                            FROM sys.foreign_key_columns fc JOIN sys.columns pc ON pc.object_id = fc.parent_object_id AND pc.column_id = fc.parent_column_id""").fetchall():
        fk[(r[0], r[1])] = r[2]
    cols = defaultdict(list)
    for r in cur.execute("""SELECT OBJECT_NAME(c.object_id), c.name, TYPE_NAME(c.user_type_id), c.max_length, c.is_nullable, c.is_identity, c.is_computed
                            FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id WHERE t.is_ms_shipped = 0 ORDER BY c.object_id, c.column_id""").fetchall():
        cols[r[0]].append(r)
    for t in rel:
        parts = []
        for c in cols[t.name]:
            name = f"**{c[1]}**" if c[1] in pk[t.name] else c[1]
            parts.append(name + (f" → {fk[(t.name, c[1])]}" if (t.name, c[1]) in fk else ""))
        out.append(f"| `{t.name}` | {t.RowCnt:,} | {', '.join(parts)} |")
    for title, flag in (("Graf düğüm tabloları (AS NODE)", "is_node"), ("Graf kenar tabloları (AS EDGE)", "is_edge")):
        sub = [r for r in rows if getattr(r, flag)]
        out += ["", f"## {title} ({len(sub)})", "", "| Tablo | Satır | Kullanıcı sütunları |", "|---|---:|---|"]
        for t in sub:
            user_cols = [c[1] for c in cols[t.name] if not c[1].startswith(("$", "graph_id", "from_", "to_")) and not c[6]]
            out.append(f"| `{t.name}` | {t.RowCnt:,} | {', '.join(user_cols)} |")
    out += ["", "## Kenar kısıtları (CONNECTION)", "", "| Kenar | Bağlantı | Silme |", "|---|---|---|"]
    for r in cur.execute("""SELECT OBJECT_NAME(ec.parent_object_id), OBJECT_NAME(ecc.from_object_id), OBJECT_NAME(ecc.to_object_id), ec.delete_referential_action_desc
                            FROM sys.edge_constraints ec JOIN sys.edge_constraint_clauses ecc ON ecc.object_id = ec.object_id ORDER BY 1""").fetchall():
        out.append(f"| `{r[0]}` | {r[1]} → {r[2]} | {r[3]} |")
    kinds = {"V": "Görünümler", "P": "Saklı yordamlar", "FN": "Skaler fonksiyonlar", "IF": "Satır içi tablo değerli fonksiyonlar", "TR": "Tetikleyiciler"}
    for code, title in kinds.items():
        names = [r[0] for r in cur.execute("SELECT name FROM sys.objects WHERE is_ms_shipped = 0 AND type = ? ORDER BY name;", code).fetchall()]
        out += ["", f"## {title} ({len(names)})", "", ", ".join(f"`{n}`" for n in names)]
    counts = cur.execute("""SELECT
        (SELECT COUNT(*) FROM sys.check_constraints) , (SELECT COUNT(*) FROM sys.foreign_keys),
        (SELECT COUNT(*) FROM sys.key_constraints WHERE type = 'UQ'), (SELECT COUNT(*) FROM sys.default_constraints),
        (SELECT COUNT(*) FROM sys.indexes i JOIN sys.tables t ON t.object_id = i.object_id WHERE i.type > 0 AND t.is_ms_shipped = 0)""").fetchone()
    out += ["", "## Kısıt ve indeks sayıları", "", f"CHECK: {counts[0]} · FOREIGN KEY: {counts[1]} · UNIQUE: {counts[2]} · DEFAULT: {counts[3]} · İndeks (PK dahil): {counts[4]}", ""]
    out += ["## Veritabanı rolleri", "", "| Rol | GRANT | DENY |", "|---|---:|---:|"]
    for r in cur.execute("""SELECT p.name, SUM(CASE WHEN dp.state = 'G' THEN 1 ELSE 0 END), SUM(CASE WHEN dp.state = 'D' THEN 1 ELSE 0 END)
                            FROM sys.database_principals p LEFT JOIN sys.database_permissions dp ON dp.grantee_principal_id = p.principal_id
                            WHERE p.type = 'R' AND p.name LIKE 'tip[_]%' GROUP BY p.name ORDER BY p.name""").fetchall():
        out.append(f"| `{r[0]}` | {r[1]} | {r[2]} |")
    return "\n".join(out) + "\n"


def api_doc() -> str:
    from app.main import app
    spec = app.openapi()
    out = ["# API uç noktaları (otomatik üretildi)", "",
           "> `python scripts/gen_docs.py` ile FastAPI OpenAPI şemasından üretilmiştir. Etkileşimli belge: http://127.0.0.1:8000/api/docs", "",
           "Kimlik doğrulama: `POST /api/auth/login` oturum çerezi (`tl_session`, HttpOnly) verir. Roller: **İzleyici** okur; **Analist** IOC, ilişki ve içe aktarma yazar; **Yönetici** ek olarak kullanıcıları ve ATT&CK yüklemesini yönetir.",
           "Hatalar her zaman `{\"detail\": \"...\"}` biçimindedir: 400 iş kuralı (T-SQL THROW 50001-50099), 401 oturum yok, 403 yetki yok, 404 bulunamadı, 409 benzersizlik/yabancı anahtar, 422 alan doğrulama, 503 veritabanına ulaşılamıyor.", ""]
    by_tag = defaultdict(list)
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            by_tag[(op.get("tags") or ["diğer"])[0]].append((path, method.upper(), op))
    for tag, items in by_tag.items():
        out += [f"## {tag}", "", "| Yöntem | Yol | Açıklama | Parametreler |", "|---|---|---|---|"]
        for path, method, op in items:
            params = ", ".join(f"`{p['name']}`" for p in op.get("parameters", []))
            if "requestBody" in op:
                params += (" + " if params else "") + "gövde (JSON / form)"
            desc = (op.get("description") or op.get("summary") or "").split("\n")[0]
            out.append(f"| {method} | `{path}` | {desc} | {params} |")
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    DOCS.mkdir(exist_ok=True)
    (DOCS / "veritabani_nesneleri.md").write_text(db_objects(), encoding="utf-8")
    (DOCS / "api.md").write_text(api_doc(), encoding="utf-8")
    print("docs/veritabani_nesneleri.md ve docs/api.md üretildi.")
