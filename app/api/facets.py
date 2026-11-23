"""Filtre paneli sayıları (facet).

Bir boyutun sayısı listedeki diğer etkin filtreleri uygular ama kendi boyutunu uygulamaz; böylece panelde seçili değerin
yanındaki seçeneklerin de kaç kayıt getireceği görünür.

Basit boyutlar tek taramada sayılır: boyut dışı koşullar (arama metni, tarih...) WHERE'e, boyut koşulları ise satır başına
0/1 bayrağa dönüşür; GROUPING SETS her boyutu ayrı gruplar ve her boyutun sayımı yalnızca diğer boyutların bayraklarına
bakar. Çoka-çok boyutlar (ek JOIN'li, ör. aktörün hedef sektörü) kendi sorgusuyla ve COUNT(DISTINCT anahtar) ile sayılır.
Koşullar çağıran uçta sabit parçalardan kurulur; kullanıcı girdisi yalnızca parametre (?) olarak gelir. Gruplama ifadeleri
koddaki sabit sözlüklerdendir, istekten gelmez.
"""
from ..db import Db

Cond = tuple[str, str, list]


def facet_counts(db: Db, from_sql: str, conds: list[Cond], dims: dict[str, str | tuple[str, str]],
                 key: str | None = None) -> dict[str, dict[str, int]]:
    """conds: [(boyut, koşul, parametreler)]; dims: ad -> gruplama ifadesi ya da (ek JOIN, gruplama ifadesi).
    Dönüş: {boyut: {değer: sayı}}; diğer filtreler yüzünden 0 kalan değerler de döner (panelde soluk gösterilir)."""
    simple = {n: e for n, e in dims.items() if isinstance(e, str)}
    out = _single_scan(db, from_sql, conds, simple) if simple else {}
    for name, (join, expr) in ((n, e) for n, e in dims.items() if not isinstance(e, str)):
        use = [c for c in conds if c[0] != name]
        where = "\n          AND ".join(["1 = 1"] + [c[1] for c in use])
        rows = db.query(f"SELECT {expr} AS V, COUNT(DISTINCT {key}) AS N FROM {from_sql} {join}\n        WHERE {where}\n        GROUP BY {expr};",
                        tuple(x for c in use for x in c[2]))
        out[name] = {str(r["V"]): r["N"] for r in rows if r["V"] is not None}
    return out


def _single_scan(db: Db, from_sql: str, conds: list[Cond], dims: dict[str, str]) -> dict[str, dict[str, int]]:
    names = list(dims)
    base = [c for c in conds if c[0] not in dims]               # boyut dışı koşullar: herkese uygulanır
    flags, fparams = [], []                                       # boyut koşulları: satır başına 0/1
    active = [n for n in names if any(c[0] == n for c in conds)]
    for n in active:
        own = [c for c in conds if c[0] == n]
        flags.append(f"CASE WHEN {' AND '.join(c[1] for c in own)} THEN 1 ELSE 0 END AS F{names.index(n)}")
        fparams += [x for c in own for x in c[2]]
    cols = ", ".join(f"{dims[n]} AS D{i}" for i, n in enumerate(names))
    where = "\n          AND ".join(["1 = 1"] + [c[1] for c in base])

    def count(i: int) -> str:                                     # boyut i: diğer etkin boyutların bayrakları 1 olmalı
        others = [f"x.F{names.index(n)} = 1" for n in active if names.index(n) != i]
        return f"SUM(CASE WHEN {' AND '.join(others)} THEN 1 ELSE 0 END)" if others else "COUNT(*)"

    sql = f"""SELECT {', '.join(f'x.D{i}, GROUPING(x.D{i}) AS G{i}, {count(i)} AS N{i}' for i in range(len(names)))}
        FROM (SELECT {cols}{', ' if flags else ''}{', '.join(flags)} FROM {from_sql}
              WHERE {where}) AS x
        GROUP BY GROUPING SETS ({', '.join(f'(x.D{i})' for i in range(len(names)))});"""
    out: dict[str, dict[str, int]] = {n: {} for n in names}
    for r in db.query(sql, tuple(fparams) + tuple(x for c in base for x in c[2])):
        for i, n in enumerate(names):
            if r[f"G{i}"] == 0 and r[f"D{i}"] is not None:
                out[n][str(r[f"D{i}"])] = r[f"N{i}"] or 0
    return out
