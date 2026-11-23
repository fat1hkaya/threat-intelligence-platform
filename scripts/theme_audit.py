"""Tema denetimi (Playwright): her sayfada ve iki temada yüzey, kart ve metin kontrastı.

    python scripts/theme_audit.py konsol-asama6                       # docs/ui-audit/konsol-asama6/theme.json
    python scripts/theme_audit.py konsol-asama6 --pages iocs,overview --themes light

Raporlananlar (sayfa başına):
  wrongSurface  koyu temada göreli parlaklığı > 0,7 olan, açık temada < 0,03 olan ve en az 24×24 px görünür alanı kaplayan
                yüzeyler. İstisnalar: .force-dark ve içindekiler (graf tuvali, kod blokları), bilinçli ters birincil düğme.
  sameSurface   kendi zemini arkasındaki zeminle aynı tonda olan kartlar ("beyaz kart beyaz zemine konmaz")
  lowContrast   12–14 px metinlerde hesaplanan zemine göre 4,5:1'in altındaki kontrast (devre dışı kontroller hariç)
  nativeSelect  araç çubuklarında kalan yerel <select>
Ayrıca açık filtre paneli (iocs-facet) ve geliştirici modunda SQL çekmecesi ile veritabanı sekmesi denetlenir.
Zemin, öğenin ve üst öğelerinin arka plan renkleri saydamlıkla üst üste bindirilerek hesaplanır (gradyan/görsel yok sayılır).
Giriş ui_screenshots.py ile aynıdır (canlı veritabanı koruması LoginAttempt/UserSession için +1 sayar: pytest ile aynı anda
çalıştırmayın). Veritabanına yazmaz.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from scripts.ui_screenshots import discover, do_action, page_list, password  # noqa: E402

THEME_JS = r"""
(theme) => {
  const parse = (c) => {
    if (!c || c === 'transparent') return [0, 0, 0, 0];
    let m = c.match(/^rgba?\(([^)]+)\)/);
    if (m) { const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(parseFloat); return [p[0], p[1], p[2], p[3] ?? 1]; }
    m = c.match(/^color\(srgb\s+([^)]+)\)/);
    if (m) { const p = m[1].split(/[\s\/]+/).filter(Boolean).map(parseFloat); return [p[0] * 255, p[1] * 255, p[2] * 255, p[3] ?? 1]; }
    return null;
  };
  const lin = (x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; };
  const lum = (c) => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  const over = (top, under) => { const a = top[3]; return [top[0] * a + under[0] * (1 - a), top[1] * a + under[1] * (1 - a), top[2] * a + under[2] * (1 - a), 1]; };
  const page = parse(getComputedStyle(document.body).backgroundColor) || [255, 255, 255, 1];
  const effBg = (el) => {
    const stack = [];
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c[3] > 0) { stack.push(c); if (c[3] >= 0.999) break; }
      if (e.tagName === 'DIALOG') break;
    }
    let base = stack.length && stack[stack.length - 1][3] >= 0.999 ? stack.pop() : page;
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };
  const label = (el) => {
    let s = el.tagName.toLowerCase(); if (el.id) s += '#' + el.id;
    const cls = [...el.classList].slice(0, 3).join('.'); if (cls) s += '.' + cls;
    const t = (el.innerText || el.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ').slice(0, 40);
    return t ? `${s} "${t}"` : s;
  };
  const visible = (el) => { const r = el.getBoundingClientRect(); if (r.width < 1 || r.height < 1) return null;
    const cs = getComputedStyle(el); if (cs.visibility === 'hidden' || cs.display === 'none' || +cs.opacity === 0) return null; return r; };
  const vw = innerWidth, vh = innerHeight;
  const out = { wrongSurface: [], sameSurface: [], lowContrast: [], nativeSelect: [] };
  const all = [...document.querySelectorAll('body *')].filter((el) => !el.closest('.force-dark, [hidden], .sr-only, svg, canvas'));
  for (const el of all) {
    const r = visible(el); if (!r) continue;
    const cs = getComputedStyle(el);
    // 1) yanlış tonda büyük yüzey
    const own = parse(cs.backgroundColor);
    if (own && own[3] > 0.5 && !el.matches('.btn.primary, .btn.primary *, .avatar, mark, .skip-link')) {
      const w = Math.min(r.right, vw) - Math.max(r.left, 0), h = Math.min(r.bottom, document.documentElement.scrollHeight) - Math.max(r.top, -1e9);
      if (w >= 24 && h >= 24) {
        const L = lum(effBg(el));
        if ((theme === 'dark' && L > 0.7) || (theme === 'light' && L < 0.03)) out.wrongSurface.push(`${label(el)} L=${L.toFixed(2)}`);
      }
    }
    // 2) zeminle aynı tonda kart
    if (el.matches('.card, .facet-pop, .menu-pop, .help-pop, .panel, dialog') && own && own[3] > 0.5 && el.parentElement) {
      const me = effBg(el), behind = effBg(el.parentElement);
      // aynı ton: iki yüzeyin kontrastı 1,02:1'in altında (üç yüzey adımı koyu temada ~1,06, açık temada ~1,04)
      const same = ratio(me, behind) < 1.02;
      if (same && cs.borderTopStyle === 'none' && cs.boxShadow === 'none') out.sameSurface.push(label(el));
      else if (same && el.matches('.card') && !el.matches('.bare')) out.sameSurface.push(label(el) + ' (çerçeveli)');
    }
    // 3) 12–14 px metin kontrastı
    const fs = parseFloat(cs.fontSize);
    if (fs >= 11.5 && fs <= 14.5 && [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())
        && !el.closest('[disabled], [aria-disabled="true"], .is-disabled, [aria-hidden="true"]') && !el.matches('option, optgroup')) {
      const fg0 = parse(cs.color); if (!fg0) continue;
      const bg = effBg(el), fg = fg0[3] < 1 ? over(fg0, bg) : fg0;
      const op = [...function* () { for (let e = el; e && e !== document.body; e = e.parentElement) yield +getComputedStyle(e).opacity; }()].reduce((a, b) => a * b, 1);
      const k = ratio(op < 1 ? over([...fg.slice(0, 3), op], bg) : fg, bg);
      if (k < 4.5) out.lowContrast.push(`${label(el)} ${k.toFixed(2)}:1 (${fs}px)`);
    }
  }
  out.nativeSelect = [...document.querySelectorAll('.toolbar select, .tb-row select, .page-actions select, .table-bar select, .head-actions select')].map(label);
  for (const k of Object.keys(out)) { out[k + 'Count'] = out[k].length; out[k] = [...new Set(out[k])].slice(0, 20); }
  return out;
}
"""


def run(phase: str, pages: list[str] | None, themes: list[str], base: str) -> dict:
    result: dict = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for theme in themes:
            ctx = browser.new_context(viewport={"width": 1440, "height": 790}, locale="tr-TR", color_scheme=theme, timezone_id="Europe/Istanbul")
            ctx.add_init_script(f"try {{ localStorage.setItem('tl-theme', '{theme}'); }} catch (e) {{}}")
            page = ctx.new_page()
            rep: dict = {}

            def check(name: str, path: str, action: str | None = None) -> None:
                page.goto(base + path)
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(2.5 if name.startswith("graph") else 0.8)
                if action:
                    try:
                        do_action(page, action)
                    except Exception as exc:  # noqa: BLE001
                        print(f"  {name}: açılamadı ({str(exc)[:80]})")
                rep[name] = page.evaluate(THEME_JS, theme)
                if action:
                    page.keyboard.press("Escape")

            if not pages or "login" in pages:
                check("login", "/login")
            page.goto(base + "/login"); page.fill("#u", "fatih"); page.fill("#p", password()); page.click("#submit")
            page.wait_for_url(lambda u: "/login" not in u, timeout=20000)
            ids = discover(base, ctx.request)
            for name, path, action in page_list(ids):
                if path and (not pages or name in pages):
                    check(name, path, action)
            # geliştirici modu: SQL çekmecesi ve veritabanı sekmesi (kod blokları .force-dark kalır)
            if not pages or "dev-sql" in pages:
                page.evaluate("() => { localStorage.setItem('tl-dev', '1'); }")
                page.goto(base + "/iocs"); page.wait_for_load_state("networkidle"); time.sleep(0.6)
                page.click("#sqlBtn"); time.sleep(1.0)
                rep["dev-sql-drawer"] = page.evaluate(THEME_JS, theme)
                page.goto(base + "/settings?tab=db"); page.wait_for_load_state("networkidle"); time.sleep(1.0)
                rep["dev-settings-db"] = page.evaluate(THEME_JS, theme)
                page.evaluate("() => { localStorage.removeItem('tl-dev'); }")
            result[theme] = rep
            n = lambda k: sum(v[k + "Count"] for v in rep.values())  # noqa: E731
            print(f"{theme:5} sayfa={len(rep)}  yanlış-yüzey={n('wrongSurface')}  aynı-zemin-kart={n('sameSurface')}  "
                  f"düşük-kontrast={n('lowContrast')}  yerel-select={n('nativeSelect')}")
            ctx.close()
        browser.close()
    folder = ROOT / "docs" / "ui-audit" / phase
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "theme.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("phase")
    ap.add_argument("--pages", help="virgülle sayfa adları")
    ap.add_argument("--themes", default="dark,light")
    ap.add_argument("--base", default=os.getenv("TL_BASE_URL", "http://127.0.0.1:8000"))
    a = ap.parse_args()
    run(a.phase, a.pages.split(",") if a.pages else None, a.themes.split(","), a.base)
