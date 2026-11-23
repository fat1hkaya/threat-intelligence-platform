"""Konsol önizlemesi ile uygulamanın karşılaştırması (Playwright).

    python scripts/konsol_compare.py konsol-after

docs/design/konsol/onizleme.html içindeki A (Konsol) çerçevesini koyu ve açık temada, masaüstü (1440) ve mobil (390)
görünümünde çeker: <klasör>/onizleme-A-<tema>-<genişlik>.png. Uygulamada IOC araştırmayı (önizleme paneli açık) aynı
temalarda çeker: <klasör>/iocs-uygulama-<tema>.png. İkisini yan yana koyan tek görüntü: <klasör>/karsilastirma.png
(üst satır koyu, alt satır açık). Uygulama çalışıyor olmalı; veritabanına yazmaz.
"""
import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from scripts.ui_screenshots import password  # noqa: E402

THEMES = (("dark", "Koyu"), ("light", "Açık"))


def main(phase: str, base: str) -> None:
    out = ROOT / "docs" / "ui-audit" / phase
    out.mkdir(parents=True, exist_ok=True)
    preview = (ROOT / "docs" / "design" / "konsol" / "onizleme.html").as_uri()
    b64 = lambda p: base64.b64encode(p.read_bytes()).decode()  # noqa: E731
    with sync_playwright() as pw:
        browser = browser_ = pw.chromium.launch()
        for theme, label in THEMES:
            for width, button in ((1440, "Masaüstü 1440"), (390, "Mobil 390")):
                pg = browser.new_page(viewport={"width": 1700, "height": 1000})
                pg.goto(preview); pg.wait_for_timeout(1200)
                sec = pg.locator("#secenek-a")
                sec.locator(f'button:has-text("{label}")').first.click()
                sec.locator(f'button:has-text("{button}")').first.click(); pg.wait_for_timeout(400)
                sec.locator(".A").first.screenshot(path=str(out / f"onizleme-A-{theme}-{width}.png"))
                pg.close()
            ctx = browser.new_context(viewport={"width": 1440, "height": 790}, color_scheme=theme, locale="tr-TR", timezone_id="Europe/Istanbul")
            ctx.add_init_script(f"try {{ localStorage.setItem('tl-theme', '{theme}'); }} catch (e) {{}}")
            app = ctx.new_page()
            app.goto(base + "/login"); app.fill("#u", "fatih"); app.fill("#p", password()); app.click("#submit")
            app.wait_for_url(lambda u: "/login" not in u, timeout=20000)
            app.goto(base + "/iocs"); app.wait_for_load_state("networkidle"); app.locator("tr[data-id]").nth(2).click(); app.wait_for_timeout(1500)
            app.screenshot(path=str(out / f"iocs-uygulama-{theme}.png"), animations="disabled")
            ctx.close()
        rows = "".join(f"""<div class="row">
            <figure><figcaption>Önizleme A · Konsol ({label})</figcaption><img src="data:image/png;base64,{b64(out / f'onizleme-A-{theme}-1440.png')}"></figure>
            <figure><figcaption>Uygulama · IOC araştırma ({label})</figcaption><img src="data:image/png;base64,{b64(out / f'iocs-uygulama-{theme}.png')}"></figure></div>"""
                       for theme, label in THEMES)
        cmp = browser_.new_page(viewport={"width": 2940, "height": 1000})
        cmp.set_content(f"""<style>body{{margin:0;background:#8a8d93;font:16px system-ui;padding:20px;display:grid;gap:20px}}
            .row{{display:flex;gap:20px}} figure{{margin:0}} figcaption{{color:#fff;padding:0 0 8px}} img{{width:1440px;display:block}}</style>{rows}""")
        cmp.wait_for_timeout(400)
        cmp.screenshot(path=str(out / "karsilastirma.png"), full_page=True)
        browser.close()
    print("ok:", out)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    main(sys.argv[1] if len(sys.argv) > 1 else "konsol-after", os.getenv("TL_BASE_URL", "http://127.0.0.1:8000"))
