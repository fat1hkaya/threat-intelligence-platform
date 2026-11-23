"""Erişilebilirlik denetimi: Playwright + axe-core (WCAG 2.1 A/AA ve en iyi uygulamalar).

    python scripts/a11y_audit.py after                    # docs/ui-audit/after/a11y.json
    python scripts/a11y_audit.py after --pages overview,iocs,graph-hash

axe-core yalnızca bu betikte kullanılır (CSP yalnızca denetim tarayıcısında atlanır; uygulamanın CSP politikası değişmez) (scripts/vendor/axe.min.js, sürüm 4.10.2, MPL-2.0); uygulama yüklemez.
Puan, Lighthouse'un erişilebilirlik puanına benzer biçimde hesaplanır: uygulanabilir her kuralın ağırlıklı ortalaması
(geçen kural / tüm uygulanabilir kurallar). Ağırlık kuralın etkisine göre: kritik 10, ciddi 7, orta 3, küçük 1.
Giriş ui_screenshots.py ile aynıdır (canlı veritabanı koruması LoginAttempt/UserSession için +1 sayar: pytest ile
aynı anda çalıştırmayın).
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from scripts.ui_screenshots import discover, page_list, password  # noqa: E402

AXE = ROOT / "scripts" / "vendor" / "axe.min.js"
WEIGHT = {"critical": 10, "serious": 7, "moderate": 3, "minor": 1}
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"]
DEFAULT_PAGES = ["login", "overview", "iocs", "graph-hash"]


def score(res: dict) -> tuple[int, list[dict]]:
    """Ağırlıklı puan (0-100) ve ihlal özeti."""
    rules = {}
    for r in res["passes"]:
        rules[r["id"]] = (WEIGHT.get(r.get("impact") or "moderate", 3), True)
    for r in res["violations"]:
        rules[r["id"]] = (WEIGHT.get(r.get("impact") or "moderate", 3), False)
    total = sum(w for w, _ in rules.values()) or 1
    passed = sum(w for w, ok in rules.values() if ok)
    viol = [{"id": v["id"], "impact": v["impact"], "help": v["help"], "nodes": len(v["nodes"]),
             "targets": [", ".join(n["target"]) if isinstance(n["target"], list) else str(n["target"]) for n in v["nodes"][:5]]}
            for v in res["violations"]]
    return round(100 * passed / total), viol


def run(phase: str, pages: list[str], base: str, schemes: list[str]) -> dict:
    axe_src = AXE.read_text(encoding="utf-8")
    out: dict = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for scheme in schemes:
            ctx = browser.new_context(viewport={"width": 1440, "height": 790}, locale="tr-TR", color_scheme=scheme, timezone_id="Europe/Istanbul", bypass_csp=True)
            # tema seçimi tarayıcıda saklanır; denetim istenen şemayı zorlar
            ctx.add_init_script(f"try {{ localStorage.setItem('tl-theme', '{scheme}'); }} catch (e) {{}}")
            page = ctx.new_page()
            ids, todo = {}, []
            if "login" in pages:
                todo.append(("login", "/login"))
            page.goto(base + "/login")
            page.fill("#u", "fatih")
            page.fill("#p", password())
            page.click("#submit")
            page.wait_for_url(lambda u: "/login" not in u, timeout=20000)
            ids = discover(base, ctx.request)
            todo += [(n, p) for n, p, action in page_list(ids) if n in pages and not action]
            res_scheme = {}
            for name, path in todo:
                if name == "login":
                    lc = browser.new_context(viewport={"width": 1440, "height": 790}, locale="tr-TR", color_scheme=scheme, bypass_csp=True)
                    lc.add_init_script(f"try {{ localStorage.setItem('tl-theme', '{scheme}'); }} catch (e) {{}}")
                    p = lc.new_page()
                else:
                    lc, p = None, page
                p.goto(base + path)
                try:
                    p.wait_for_load_state("networkidle", timeout=15000)
                except Exception:  # noqa: BLE001
                    pass
                p.wait_for_timeout(2500 if name.startswith("graph") else 800)
                p.add_script_tag(content=axe_src)
                res = p.evaluate("(tags) => axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations', 'passes'] })", TAGS)
                sc, viol = score(res)
                res_scheme[name] = {"score": sc, "critical": sum(1 for v in viol if v["impact"] == "critical"),
                                    "serious": sum(1 for v in viol if v["impact"] == "serious"), "violations": viol}
                print(f"{scheme:5} {name:22} puan={sc:3}  kritik={res_scheme[name]['critical']}  ciddi={res_scheme[name]['serious']}  "
                      f"ihlal={[v['id'] for v in viol]}")
                if lc:
                    lc.close()
            out[scheme] = res_scheme
            ctx.close()
        browser.close()
    folder = ROOT / "docs" / "ui-audit" / phase
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "a11y.json").write_text(json.dumps({"tool": "axe-core 4.10.2", "tags": TAGS, "viewport": "1440x790", "results": out},
                                                 ensure_ascii=False, indent=2), encoding="utf-8")
    return out


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("phase")
    ap.add_argument("--pages", help="virgülle sayfa adları (varsayılan: login, overview, iocs, graph-hash)")
    ap.add_argument("--all", action="store_true", help="ekran denetimindeki tüm sayfalar")
    ap.add_argument("--schemes", default="dark,light")
    ap.add_argument("--base", default=os.getenv("TL_BASE_URL", "http://127.0.0.1:8000"))
    a = ap.parse_args()
    if a.all:
        pg = ["login"] + [n for n, _, act in page_list({k: 1 for k in ("ioc", "hash", "actor", "campaign", "malware", "case")}) if not act]
    else:
        pg = a.pages.split(",") if a.pages else DEFAULT_PAGES
    run(a.phase, pg, a.base, a.schemes.split(","))
