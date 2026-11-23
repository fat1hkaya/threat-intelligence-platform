"""Arayüz ekran görüntüleri ve otomatik düzen denetimi (Playwright).

    python scripts/ui_screenshots.py before          # docs/ui-audit/before/<görünüm>/<sayfa>.png + report.json
    python scripts/ui_screenshots.py after
    python scripts/ui_screenshots.py after --only primary --pages overview,iocs

Uygulama çalışıyor olmalı (python run.py). Giriş: fatih kullanıcısı; parola TL_SCREENSHOT_PASSWORD ortam
değişkeninden, yoksa kurulumun yerel parolasından. Betik veritabanına YAZMAZ: yalnızca sayfaları açar,
pencereleri açıp kapatır (form gönderilmez).

Her sayfada denetlenenler (report.json):
  overflow         belge yatay taşıyor mu (scrollWidth > innerWidth)
  sidebarScroll    kenar çubuğu kendi içinde kayıyor mu
  nestedScroll     kendi kaydırma çubuğu olan ve içeriği taşan iç öğeler (izinli olanlar hariç)
  allowedScroll    şartnamenin izin verdiği iç kaydırmalar: sağ panel, pencere gövdesi, gölgeli yatay tablo/matris
  truncatedNoTitle metni kesik (scrollWidth > clientWidth) olup ipucu (title) olmayan öğeler (.sr-only hariç)
  overlaps         aynı üst öğedeki metin kutularının kesişmesi
  consoleErrors    konsol hataları ve yakalanmamış istisnalar
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

VIEWPORTS = {
    "primary": (1440, 790),
    "wide": (1920, 1000),
    "laptop": (1280, 720),
    "tablet": (1024, 768),
    "mobile": (390, 844),
}

AUDIT_JS = r"""
() => {
  const vw = innerWidth, out = {};
  const label = (el) => {
    const id = el.id ? '#' + el.id : '';
    const cls = typeof el.className === 'string' && el.className.trim() ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '';
    const text = (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 40);
    return `${el.tagName.toLowerCase()}${id}${cls}${text ? ` "${text}"` : ''}`;
  };
  const visible = (el) => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  out.overflow = document.documentElement.scrollWidth > vw;
  out.overflowPx = Math.max(0, document.documentElement.scrollWidth - vw);
  const sb = document.getElementById('sidebar');
  out.sidebarScroll = !!(sb && visible(sb) && sb.getBoundingClientRect().left >= -1 && sb.scrollHeight > sb.clientHeight + 1);
  const nested = [], allowed = [], trunc = [], overlaps = [];
  const okScroll = (el) => el.matches('.panel, dialog') || (el.matches('.table-scroll, .matrix') && el.scrollHeight <= el.clientHeight + 1 && el.closest('.scroll-host'));
  for (const el of document.querySelectorAll('body *')) {
    if (!visible(el) || el.closest('#sqlDrawer, .vis-network, dialog:not([open])')) continue;
    const cs = getComputedStyle(el);
    if (el !== sb && /(auto|scroll)/.test(cs.overflowY + cs.overflowX)
        && (el.scrollHeight > el.clientHeight + 1 || el.scrollWidth > el.clientWidth + 1)) (okScroll(el) ? allowed : nested).push(label(el));
    const hasText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (hasText && el.scrollWidth > el.clientWidth + 1 && /(hidden|clip)/.test(cs.overflowX) && !el.closest('[title]')
        && !el.getAttribute('aria-label') && !el.closest('.sr-only')) trunc.push(label(el));
  }
  // Üst üste binen metin: aynı üst öğedeki metinli kardeşlerin kutuları kesişiyor mu
  const parents = new Set([...document.querySelectorAll('body *')].filter((el) => visible(el) && [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())).map((el) => el.parentElement));
  for (const p of parents) {
    if (!p || p.closest('.vis-network, svg')) continue;
    const kids = [...p.children].filter((k) => visible(k) && (k.textContent || '').trim() && getComputedStyle(k).position !== 'absolute' && getComputedStyle(k).position !== 'fixed');
    for (let i = 0; i < kids.length; i += 1) for (let j = i + 1; j < kids.length; j += 1) {
      const a = kids[i].getBoundingClientRect(), b = kids[j].getBoundingClientRect();
      const w = Math.min(a.right, b.right) - Math.max(a.left, b.left), h = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (w > 2 && h > 2) overlaps.push(`${label(kids[i])}  ×  ${label(kids[j])}`);
    }
  }
  out.nestedScroll = [...new Set(nested)].slice(0, 25);
  out.allowedScroll = [...new Set(allowed)].slice(0, 25);
  out.truncatedNoTitle = [...new Set(trunc)].slice(0, 25);
  out.truncatedCount = trunc.length;
  out.overlaps = [...new Set(overlaps)].slice(0, 25);
  out.overlapCount = overlaps.length;
  return out;
}
"""


def password() -> str:
    if os.getenv("TL_SCREENSHOT_PASSWORD"):
        return os.environ["TL_SCREENSHOT_PASSWORD"]
    from scripts.setup_db import DEMO_PASSWORD  # yerel kurulumun parolası
    return DEMO_PASSWORD


def discover(base: str, request) -> dict:
    """Örnek kayıtları API'den bulur (detay sayfaları ve paneller için). Kayıt oluşturmaz."""
    def get(path):
        r = request.get(base + path)
        return r.json() if r.ok else None
    ex = get("/api/iocs/examples") or []
    sha = next((e for e in ex if e.get("TypeCode") in ("sha256", "md5", "sha1")), ex[0] if ex else None)
    iocs = (get("/api/iocs?size=5") or {}).get("items") or []
    actors = (get("/api/actors?size=5&sort=techniques") or {}).get("items") or []
    camps = (get("/api/campaigns?size=5") or {}).get("items") or []
    mal = (get("/api/malware?size=5") or {}).get("items") or []
    cases = get("/api/cases") or []
    return {
        "ioc": iocs[0]["IndicatorID"] if iocs else None,
        "hash": sha["IndicatorID"] if sha else None,
        "actor": actors[0]["ActorID"] if actors else None,
        "campaign": camps[0]["CampaignID"] if camps else None,
        "malware": mal[0]["MalwareID"] if mal else None,
        "case": cases[0]["InvestigationID"] if cases else None,
    }


def page_list(ids: dict) -> list[tuple[str, str, str | None]]:
    """(ad, yol, eylem) - eylem: açılacak pencere düğmesinin kimliği."""
    pages = [
        ("overview", "/", None),
        ("iocs", "/iocs", None),
        ("ioc-detail", f"/iocs/{ids['hash'] or ids['ioc']}" if (ids["hash"] or ids["ioc"]) else None, None),   # atıf zinciri olan örnek
        ("ioc-new-dialog", "/iocs", "#newBtn"),
        ("ioc-lookup-dialog", "/iocs", "#lookupBtn"),
        ("hunt", "/hunt", None),
        ("cases", "/cases", None),
        ("case-detail", f"/cases?id={ids['case']}" if ids["case"] else None, None),
        ("graph-empty", "/graph", None),
        ("graph-hash", f"/graph?type=indicator&id={ids['hash']}" if ids["hash"] else None, None),
        ("infrastructure", "/infrastructure", None),
        ("actors", "/actors", None),
        ("actors-panel", f"/actors?id={ids['actor']}" if ids["actor"] else None, None),
        ("campaigns", "/campaigns", None),
        ("campaigns-panel", f"/campaigns?id={ids['campaign']}" if ids["campaign"] else None, None),
        ("malware", "/malware", None),
        ("malware-panel", f"/malware?id={ids['malware']}" if ids["malware"] else None, None),
        ("attack-list", "/attack", None),
        ("attack-matrix", "/attack?view=matrix", None),
        ("attack-coverage", "/attack?view=coverage", None),
        ("sources", "/sources", None),
        ("audit", "/audit", None),
        ("audit-logins", "/audit?tab=logins", None),
        ("audit-runs", "/audit?tab=runs", None),
        ("settings", "/settings", None),
        ("settings-risk", "/settings?tab=risk", None),
        ("settings-integrations", "/settings?tab=integrations", None),
        ("settings-maintenance", "/settings?tab=maintenance", None),
    ]
    return [p for p in pages if p[1]]


def shoot(page, name: str, folder: Path, report: dict, errors: list) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    try:
        page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:  # noqa: BLE001 - uzun süren istek varsa yine de çek
        pass
    time.sleep(3.0 if name.startswith("graph") else 0.9)
    audit = page.evaluate(AUDIT_JS)
    audit["consoleErrors"] = list(errors)
    report[name] = audit
    # animations="disabled": tam sayfa çekimi görünüm alanını büyütürken giriş animasyonları (ör. detay paneli) yeniden başlar; bitmiş hâli çekilir
    page.screenshot(path=str(folder / f"{name}.png"), full_page=True, animations="disabled")


def run(phase: str, only: list[str] | None, only_pages: list[str] | None, base: str) -> dict:
    out_root = ROOT / "docs" / "ui-audit" / phase
    result: dict = {}
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for vp, (w, h) in VIEWPORTS.items():
            if only and vp not in only:
                continue
            ctx = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=1, locale="tr-TR",
                                      color_scheme="dark", timezone_id="Europe/Istanbul")
            page = ctx.new_page()
            errors: list[str] = []
            page.on("console", lambda m, e=errors: e.append(m.text[:200]) if m.type == "error" else None)
            page.on("pageerror", lambda exc, e=errors: e.append(f"pageerror: {exc}"[:200]))
            report: dict = {}
            folder = out_root / vp
            # giriş sayfası (oturumsuz)
            if not only_pages or "login" in only_pages:
                page.goto(base + "/login")
                shoot(page, "login", folder, report, errors)
            page.goto(base + "/login")
            page.fill("#u", "fatih")
            page.fill("#p", password())
            page.click("#submit")
            page.wait_for_url(lambda u: "/login" not in u, timeout=20000)
            ids = discover(base, ctx.request)
            for name, path, action in page_list(ids):
                if only_pages and name not in only_pages:
                    continue
                errors.clear()
                page.goto(base + path)
                if action:
                    try:
                        page.wait_for_load_state("networkidle", timeout=15000)
                        # telefonda sayfanın birincil eylemi üst çubuktaki ikondur (#topPrimary aynı düğmeyi tetikler)
                        target = action if page.locator(action).is_visible() else "#topPrimary"
                        page.click(target)
                        page.wait_for_selector("dialog[open]", timeout=5000)
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"pencere açılamadı: {exc}"[:200])
                shoot(page, name, folder, report, errors)
                if action:
                    page.keyboard.press("Escape")
            result[vp] = report
            ctx.close()
            print(f"{vp}: {len(report)} sayfa")
        browser.close()
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def summarize(result: dict) -> str:
    lines = []
    for vp, pages in result.items():
        ov = [p for p, a in pages.items() if a["overflow"]]
        sb = [p for p, a in pages.items() if a["sidebarScroll"]]
        lines.append(f"{vp:8} taşma={len(ov)} {ov[:4]}  kenar-kaydırma={len(sb)}  "
                     f"iç-kaydırma={sum(len(a['nestedScroll']) for a in pages.values())} (+izinli {sum(len(a.get('allowedScroll', [])) for a in pages.values())})  "
                     f"kesik-ipucusuz={sum(a['truncatedCount'] for a in pages.values())}  "
                     f"çakışma={sum(a['overlapCount'] for a in pages.values())}  "
                     f"konsol-hatası={sum(len(a['consoleErrors']) for a in pages.values())}")
    return "\n".join(lines)


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("phase", help="klasör adı: before, asama1 ... after")
    ap.add_argument("--only", help="virgülle görünüm alanları: primary,wide,laptop,tablet,mobile")
    ap.add_argument("--pages", help="virgülle sayfa adları")
    ap.add_argument("--base", default=os.getenv("TL_BASE_URL", "http://127.0.0.1:8000"))
    a = ap.parse_args()
    res = run(a.phase, a.only.split(",") if a.only else None, a.pages.split(",") if a.pages else None, a.base)
    print(summarize(res))
