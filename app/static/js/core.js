/* ThreatLens - ortak arayüz yardımcıları (kütüphanesiz, saf JavaScript). */
(() => {
  const TL = window.TL || (window.TL = {});
  TL.traces = [];                     // bu sayfanın API isteklerinin SQL izi kimlikleri

  // ---------- biçimlendirme ----------
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const TZ = 'Europe/Istanbul';
  const toDate = (v) => { if (!v) return null; const s = String(v); return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(s) || s.length <= 10 ? s : s + 'Z'); };
  const fmtDT = (v) => { const d = toDate(v); return d ? d.toLocaleString('tr-TR', { timeZone: TZ, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'; };
  const fmtD = (v) => { if (!v) return '—'; const s = String(v); const d = s.length <= 10 ? new Date(s + 'T00:00:00') : toDate(s);
    return d.toLocaleDateString('tr-TR', s.length <= 10 ? {} : { timeZone: TZ }); };
  const fmtN = (n) => (n ?? 0).toLocaleString('tr-TR');
  const ago = (v) => { const d = toDate(v); if (!d) return '—'; const s = (Date.now() - d) / 1000;
    if (s < 60) return 'az önce'; if (s < 3600) return `${Math.floor(s / 60)} dk önce`; if (s < 86400) return `${Math.floor(s / 3600)} sa önce`;
    return `${Math.floor(s / 86400)} gün önce`; };
  const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : 0);
  const fmtSize = (b) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toLocaleString('tr-TR', { maximumFractionDigits: 1 })} KB` : `${(b / 1048576).toLocaleString('tr-TR', { maximumFractionDigits: 1 })} MB`;

  /** Uzun hash/URL: baştan 10 + "…" + sondan 8 karakter. Tam değer çağıranın title'ında durur. */
  const midTruncate = (v, head = 10, tail = 8) => { const s = String(v ?? ''); return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`; };
  /** Liste hücresi: en çok n öğe + "+N"; tam liste ipucunda. Öğeler kelime ortasından kesilmez. */
  const clipList = (items, n = 3, sep = ', ') => {
    const a = (Array.isArray(items) ? items : String(items || '').split(/\s*,\s*/)).filter(Boolean);
    if (!a.length) return '<span class="faint">—</span>';
    const more = a.length - n;
    return `<span class="clip-list" title="${esc(a.join(sep))}">${a.slice(0, n).map(esc).join(sep)}${more > 0 ? ` <span class="more-n">+${more}</span>` : ''}</span>`;
  };
  /** Sayı hücresi: 0 ya da boş değer soluk tire (bilgi taşımaz); strong=true kalın yazar. */
  const num = (n, { strong = false } = {}) => !n ? '<span class="zero" title="0">—</span>' : strong ? `<b>${fmtN(n)}</b>` : fmtN(n);

  // ---------- sözlükler ----------
  const SEV = { critical: 'Kritik', high: 'Yüksek', medium: 'Orta', low: 'Düşük', info: 'Bilgi' };
  const NODE = {
    indicator: { label: 'IOC', icon: 'fingerprint', color: '#22D3EE' }, malware: { label: 'Zararlı yazılım', icon: 'bug', color: '#A78BFA' },
    campaign: { label: 'Kampanya', icon: 'target', color: '#FBBF24' }, actor: { label: 'Tehdit aktörü', icon: 'user-round-x', color: '#F87171' },
    technique: { label: 'ATT&CK tekniği', icon: 'grid-3x3', color: '#34D399' }, vulnerability: { label: 'Zafiyet', icon: 'shield-alert', color: '#F472B6' },
  };
  const TYPE_LABEL = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'E-posta' };
  const JOB = { success: ['Başarılı', 'b-ok', 'check'], partial: ['Kısmi', 'b-warn', 'triangle-alert'], failed: ['Hatalı', 'b-bad', 'x'], running: ['Çalışıyor', 'b-cyan', 'loader'] };
  const STATUS = { active: ['Aktif', 'b-ok'], expired: ['Süresi doldu', 'b-muted'], revoked: ['İptal edildi', 'b-muted'], false_positive: ['Yanlış pozitif', 'b-warn'] };

  const sev = (code) => code ? `<span class="badge sev-${esc(code)}"><span class="dot"></span>${esc(SEV[code] || code)}</span>` : '<span class="faint">—</span>';
  const typeBadge = (code) => `<span class="badge b-purple">${esc(TYPE_LABEL[code] || code)}</span>`;
  const status = (s) => { const [l, c] = STATUS[s] || [s, 'b-muted']; return `<span class="badge ${c}">${esc(l)}</span>`; };
  const job = (s) => { const [l, c, i] = JOB[s] || [s, 'b-muted', 'circle']; return `<span class="badge ${c}"><i data-lucide="${i}" style="width:13px;height:13px"></i>${esc(l)}</span>`; };
  const conf = (n) => n == null ? '<span class="faint">—</span>' :
    `<span class="conf"><b>${n}</b><span class="meter" aria-hidden="true"><i style="width:${n}%;background:${n >= 80 ? 'var(--low)' : n >= 50 ? 'var(--medium)' : 'var(--high)'}"></i></span></span>`;
  /** Kaynağın kısa adı ("abuse.ch MalwareBazaar" → "MalwareBazaar"); tam ad ipucunda */
  const sourceShort = (name) => String(name || '').replace(/^abuse\.ch\s+/i, '').replace(/\.com$/i, '');
  const sourceBadge = (name) => { if (!name) return '<span class="faint">—</span>'; const s = sourceShort(name);
    return s === name ? `<span class="src-name">${esc(name)}</span>` : `<span class="src-name" title="${esc(name)}">${esc(s)}</span>`; };
  const copyBtn = (v) => `<button type="button" class="btn sm icon ghost copy" data-copy="${esc(v)}" aria-label="Değeri kopyala" title="Kopyala"><i data-lucide="copy"></i></button>`;
  /** IOC değeri hücresi: kısaltılmış değer + sağda sabit konumlu kopyalama düğmesi */
  const iocCell = (v, { href, trunc = true } = {}) => {
    const shown = trunc ? midTruncate(v, 18, 10) : v;
    const inner = href ? `<a class="mono value" href="${href}" title="${esc(v)}">${esc(shown)}</a>` : `<span class="mono value" title="${esc(v)}">${esc(shown)}</span>`;
    return `<span class="cell-ioc">${inner}${copyBtn(v)}</span>`;
  };
  const nodeIcon = (t) => { const n = NODE[t] || NODE.indicator; return `<span class="ic" style="background:${n.color}22;color:${n.color}"><i data-lucide="${n.icon}"></i></span>`; };
  /** ATT&CK teknik çipi: kod görünür, ad ipucunda ve ekran okuyucuda */
  const techChip = (id, code, name, href) => `<a class="chip" href="${href || `/attack?id=${id}`}" title="${esc(code)} ${esc(name || '')}" aria-label="${esc(code)} ${esc(name || '')}"><span class="mono">${esc(code)}</span></a>`;

  const entityUrl = (type, id) => ({
    indicator: `/iocs/${id}`, actor: `/actors?id=${id}`, malware: `/malware?id=${id}`, campaign: `/campaigns?id=${id}`,
    technique: `/attack?id=${id}`, vulnerability: `/graph?type=vulnerability&id=${id}`,
  }[type] || '#');
  const graphUrl = (type, id) => `/graph?type=${type}&id=${id}`;

  // ---------- IOC tipi tahmini (sunucudaki normalize.guess_type ile aynı kurallar; yalnızca canlı sayaç için) ----------
  const refang = (v) => String(v).trim().replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp').replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
    .replace(/\[:\]/g, ':').replace(/\[@\]|\[at\]/gi, '@');
  const guessType = (raw) => {
    const v = refang(raw), low = v.toLowerCase();
    if (/^[0-9a-f]{64}$/.test(low)) return 'sha256';
    if (/^[0-9a-f]{40}$/.test(low)) return 'sha1';
    if (/^[0-9a-f]{32}$/.test(low)) return 'md5';
    if (/^(https?|ftp):\/\//.test(low)) return 'url';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) && v.split('.').every((p) => +p <= 255)) return 'ipv4';
    if (v.includes(':') && /^[0-9a-f:.]+$/i.test(v.replace(/^\[|\]$/g, '')) && (v.match(/:/g) || []).length >= 2) return 'ipv6';
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return 'email';
    if (/^[a-z0-9.-]+\.[a-z]{2,}\.?$/i.test(v)) return 'domain';
    return null;
  };
  const TYPE_GROUP = { ipv4: 'IP', ipv6: 'IP', domain: 'domain', url: 'URL', md5: 'hash', sha1: 'hash', sha256: 'hash', email: 'e-posta' };
  /** "12 değer: 5 IP, 4 domain, 3 hash · 1 tanınmadı" */
  const countTypes = (values) => {
    const c = {}; let unknown = 0;
    values.forEach((v) => { const t = guessType(v); if (t) c[TYPE_GROUP[t]] = (c[TYPE_GROUP[t]] || 0) + 1; else unknown += 1; });
    const parts = Object.entries(c).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${fmtN(n)} ${k}`);
    return values.length ? `${fmtN(values.length)} değer${parts.length ? `: ${parts.join(', ')}` : ''}${unknown ? ` · ${fmtN(unknown)} tanınmadı` : ''}` : 'Henüz değer yok';
  };

  // ---------- API ----------
  async function api(path, opts = {}) {
    const init = { method: opts.method || 'GET', headers: {}, credentials: 'same-origin' };
    if (opts.body instanceof FormData) init.body = opts.body;
    else if (opts.body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
    let url = path;
    if (opts.params) {
      const q = new URLSearchParams();
      Object.entries(opts.params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
      const s = q.toString(); if (s) url += (url.includes('?') ? '&' : '?') + s;
    }
    let res;
    try { res = await fetch(url, init); } catch { throw new Error('Sunucuya ulaşılamadı. Uygulamanın çalıştığını kontrol edin.'); }
    const trace = res.headers.get('X-Trace-Id');
    if (trace) { TL.traces.push({ id: trace, path: url.split('?')[0] }); if (TL.traces.length > 40) TL.traces.shift(); }
    if (res.status === 401) { location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); throw new Error('Oturum gerekli'); }
    const data = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) { const e = new Error((data && data.detail) || `İstek başarısız (${res.status})`); e.status = res.status; throw e; }
    return data;
  }

  let metaCache;
  const meta = async () => (metaCache ||= await api('/api/meta'));   // sözlük tabloları (bir kez alınır)

  // ---------- yerel tercihler (yalnızca bu tarayıcı) ----------
  const pref = {
    get: (k, d = null) => { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set: (k, v) => { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, JSON.stringify(v)); } catch { /* depolama kapalı */ } },
  };

  // ---------- küçük bileşenler ----------
  function toast(msg, kind = 'ok') {
    const box = document.getElementById('toasts'); if (!box) return;
    const t = document.createElement('div'); t.className = `toast ${kind}`;
    t.innerHTML = `<i data-lucide="${kind === 'ok' ? 'circle-check' : 'circle-alert'}"></i><div>${esc(msg)}</div>`;
    box.appendChild(t); icons(); setTimeout(() => t.remove(), kind === 'ok' ? 3500 : 7000);
  }
  // İçerik yerini tutan iskelet; ekran okuyucuya metin olarak duyurulur
  const loading = (t = 'Yükleniyor') => `<div class="skeleton" role="status"><span class="sr-only">${esc(t)}…</span><i></i><i></i><i></i><i></i><i></i></div>`;
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  /** Boş durum: ikon + tek cümle + isteğe bağlı eylem düğmesi (action: {label, icon, attr}) */
  const empty = (t, icon = 'search-x', action = null) => `<div class="empty"><i data-lucide="${icon}"></i><p>${esc(t)}</p>${action
    ? `<button type="button" class="btn sm" ${action.attr || 'data-empty-action'}>${action.icon ? `<i data-lucide="${action.icon}"></i>` : ''}${esc(action.label)}</button>` : ''}</div>`;
  /** Hata durumu: ne oldu + "Tekrar dene". retry verilirse düğme ona bağlanır. */
  function failed(el, err, retry) {
    const msg = err && err.message ? err.message : String(err || 'Beklenmeyen bir hata oluştu.');
    const hint = err && err.status >= 500 ? 'Sunucu tarafında bir sorun var; birkaç saniye sonra yeniden deneyin.'
      : err && err.status === 403 ? 'Bu işlem için yetkiniz yok.' : 'Bağlantıyı kontrol edip yeniden deneyin.';
    el.innerHTML = `<div class="empty error-state" role="alert"><i data-lucide="circle-alert"></i><p><b>${esc(msg)}</b></p><p class="faint">${esc(hint)}</p>
      ${retry ? '<button type="button" class="btn sm" data-retry><i data-lucide="refresh-cw"></i>Tekrar dene</button>' : ''}</div>`;
    if (retry) el.querySelector('[data-retry]').addEventListener('click', retry);
    icons();
  }
  const debounce = (fn, ms = 300) => { let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); }; };
  const can = (role) => { const r = TL.user && TL.user.Role; return role === 'admin' ? r === 'admin' : role === 'analyst' ? r === 'admin' || r === 'analyst' : true; };
  const qs = {
    get: (k) => new URLSearchParams(location.search).get(k),
    set: (obj) => { const u = new URL(location.href); Object.entries(obj).forEach(([k, v]) => (v === null || v === undefined || v === '') ? u.searchParams.delete(k) : u.searchParams.set(k, v)); history.replaceState(history.state, '', u); },
  };
  /** Uzun metin: 4 satırlık kırpma + "Devamını göster / Daha az" (iç kaydırma alanı yerine) */
  const clampText = (text, cls = 'desc') => text ? `<div class="clamp-box"><p class="${cls} clamp">${esc(text)}</p><button type="button" class="link-btn clamp-toggle" aria-expanded="false" hidden>Devamını göster</button></div>` : '';
  /** Panel eylemleri: tek satır; birincil + ikincil düğmeler + "Diğer" menüsü (more: HTML dizisi) */
  const actions = (main, more = []) => `<div class="panel-actions">${main.filter(Boolean).join('')}${more.filter(Boolean).length
    ? `<details class="more-menu"><summary class="btn sm" aria-label="Diğer eylemler" title="Diğer eylemler"><i data-lucide="ellipsis"></i>Diğer</summary><div class="menu-pop" role="menu">${more.filter(Boolean).join('')}</div></details>` : ''}</div>`;

  // ---------- render sonrası iyileştirmeler (her icons() çağrısında) ----------
  const TRUNC = '.data .cell, .data .value, .name-id > b, .list li span, .list li small, .chain b, .bar-row span, .clip-list, .omni-results .t, .kv dd, .chip, .badge, .tactic b, .legend span, .node-ref > a, .trunc, .att-label, .log-line, .rg-main small, .rh-msg, .test-out, .user-cell b';
  function enhance(root = document) {
    // kesik metne ipucu: yalnızca gerçekten kesikse ve atalarında ipucu yoksa
    root.querySelectorAll(TRUNC).forEach((el) => {
      if (el.title || el.closest('[title]') || el.dataset.tipped) return;
      if (el.scrollWidth > el.clientWidth + 1) { el.title = el.textContent.trim().replace(/\s+/g, ' '); el.dataset.tipped = '1'; }
    });
    // kırpılmış açıklama: taşıyorsa "Devamını göster"
    root.querySelectorAll('.clamp-box').forEach((box) => {
      const p = box.querySelector('.clamp'), b = box.querySelector('.clamp-toggle');
      if (!p || !b || box.dataset.ready) return;
      if (p.scrollHeight > p.clientHeight + 2) { b.hidden = false; box.dataset.ready = '1'; }
    });
    // yatay kaydırmalı alanlar: sağda devamı olduğunu gösteren gölge, klavyeyle kaydırılabilir bölge
    root.querySelectorAll('.table-scroll, .matrix').forEach((sc) => {
      if (sc.dataset.shadow) { sc._shade?.(); return; }
      sc.dataset.shadow = '1';
      let host = sc.parentElement;
      if (!host.classList.contains('scroll-host')) { host = document.createElement('div'); host.className = 'scroll-host'; sc.before(host); host.appendChild(sc); }
      const shade = () => {
        const over = sc.scrollWidth > sc.clientWidth + 1;
        host.classList.toggle('more-right', over && sc.scrollLeft + sc.clientWidth < sc.scrollWidth - 2);
        host.classList.toggle('more-left', over && sc.scrollLeft > 2);
        host.classList.toggle('scroll-x', over);
        if (over) { sc.tabIndex = 0; if (!sc.getAttribute('role')) { sc.setAttribute('role', 'region'); sc.setAttribute('aria-label', sc.querySelector('caption')?.textContent || 'Kaydırılabilir tablo'); } }
        else if (sc.getAttribute('role') === 'region') { sc.removeAttribute('tabindex'); sc.removeAttribute('role'); sc.removeAttribute('aria-label'); }
      };
      sc._shade = shade; sc.addEventListener('scroll', shade, { passive: true }); shade();
    });
  }
  const icons = () => { window.lucide && window.lucide.createIcons(); requestAnimationFrame(() => enhance()); };
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.clamp-toggle'); if (!b) return;
    const p = b.parentElement.querySelector('.clamp'); const open = p.classList.toggle('open');
    b.textContent = open ? 'Daha az' : 'Devamını göster'; b.setAttribute('aria-expanded', String(open));
  });
  window.addEventListener('resize', debounce(() => document.querySelectorAll('.table-scroll, .matrix').forEach((s) => s._shade?.()), 150));

  // ---------- tablo ----------
  const colId = (c, i) => c.id || c.sort || c.key || `c${i}`;
  /** Tablo: columns = [{key, label, render(row), num, sort, primary, cls, priority 1|2|3, id, hideIfAllZero(row)}]
      opts: rowId, selected, sort, dir, caption, cards, key (sütun tercihlerinin anahtarı), select {label(row)} */
  function table(columns, rows, { rowId, selected, sort, dir, caption, cards = true, key, select, selectedIds } = {}) {
    if (!rows.length) return '';
    const prefs = key ? pref.get(`tl-cols:${key}`, {}) : {};
    const cols = columns.map((c, i) => ({ ...c, _id: colId(c, i), _prio: c.primary ? 1 : (c.priority || 1) }))
      .filter((c) => c.primary || prefs[c._id] !== 0)
      .filter((c) => !c.hideIfAllZero || prefs[c._id] === 1 || rows.some((r) => c.hideIfAllZero(r)));
    const attrs = (c) => `data-col="${esc(c._id)}" data-priority="${c._prio}"${prefs[c._id] === 1 ? ' data-force' : ''}`;
    const th = (select ? `<th scope="col" class="sel"><input type="checkbox" data-select-all aria-label="Bu sayfadaki tüm satırları seç"></th>` : '') + cols.map((c) => {
      const ariaSort = c.sort && sort === c.sort ? (dir === 'asc' ? 'ascending' : 'descending') : null;
      const inner = c.sort ? `<button type="button" data-sort="${c.sort}" aria-label="${esc(c.label)}: sırala">${esc(c.label)}</button>` : (c.label ? esc(c.label) : '<span class="sr-only">İşlemler</span>');
      return `<th scope="col" class="${c.num ? 'num ' : ''}${c.primary ? 'primary ' : ''}${c.sort ? 'sortable' : ''}" ${attrs(c)} ${ariaSort ? `aria-sort="${ariaSort}"` : ''}>${inner}</th>`;
    }).join('');
    const sel = selectedIds || new Set();
    const tr = rows.map((r) => {
      const id = rowId ? rowId(r) : null;
      const box = select ? `<td class="sel" data-label=""><input type="checkbox" data-select="${esc(id)}" ${sel.has(String(id)) ? 'checked' : ''} aria-label="Seç: ${esc(select.label ? select.label(r) : id)}"></td>` : '';
      const tds = cols.map((c) => `<td data-label="${esc(c.label)}" ${attrs(c)} class="${c.num ? 'num ' : ''}${c.primary ? 'primary ' : ''}${c.cls || ''}"><div class="cell">${c.render ? c.render(r) : esc(r[c.key] ?? '—')}</div></td>`).join('');
      return `<tr ${id != null ? `data-id="${esc(id)}" class="clickable" tabindex="0"` : ''} ${id != null && String(id) === String(selected) ? 'aria-selected="true"' : ''}>${box}${tds}</tr>`;
    }).join('');
    return `<div class="table-wrap"><div class="table-scroll"><table class="data${cards ? ' cards' : ''}${select ? ' selectable' : ''}">${caption ? `<caption class="sr-only">${esc(caption)}</caption>` : ''}<thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></div></div>`;
  }

  /** Tablo olaylarını bağlar: satır tıklama/Enter, sıralama başlıkları, kopyalama */
  function bindTable(el, { onRow, onSort } = {}) {
    el.addEventListener('click', (e) => {
      const s = e.target.closest('[data-sort]'); if (s && onSort) { onSort(s.dataset.sort); return; }
      if (e.target.closest('a, button, input, label, summary')) return;
      const tr = e.target.closest('tr[data-id]'); if (tr && onRow) onRow(tr.dataset.id, tr);
    });
    el.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' || e.target.closest('a, button, input')) return;
      const tr = e.target.closest('tr[data-id]'); if (tr && onRow) onRow(tr.dataset.id, tr);
    });
  }
  const markRow = (el, id) => el.querySelectorAll('tr[data-id]').forEach((tr) => tr.setAttribute('aria-selected', String(tr.dataset.id === String(id))));

  /** Sayfa boyutu tercihi (25/50/100), sayfa başına saklanır */
  const pageSize = (key, def = 25) => { const v = +pref.get(`tl-size:${key}`, def); return [25, 50, 100].includes(v) ? v : def; };

  /** Tablo başlık çubuğu: toplam sonuç, "Sütunlar" menüsü, sayfa boyutu; seçim varken toplu işlem çubuğu.
      o: {total, unit, size, onSize, key, columns, onCols, selection: {count, actions:[{label, icon, run}], clear}} */
  function tableBar(el, o) {
    if (!el) return;
    const s = o.selection;
    if (s && s.count) {
      el.className = 'table-bar bulk';
      el.innerHTML = `<span class="tb-total" role="status"><b>${fmtN(s.count)}</b> seçili</span>
        <div class="tb-actions">${s.actions.map((a, i) => `<button type="button" class="btn sm" data-bulk="${i}"><i data-lucide="${a.icon}"></i>${esc(a.label)}</button>`).join('')}
        <button type="button" class="btn sm ghost" data-bulk-clear><i data-lucide="x"></i>Seçimi temizle</button></div>`;
      el.onclick = (e) => { const b = e.target.closest('[data-bulk]'); if (b) s.actions[+b.dataset.bulk].run(); if (e.target.closest('[data-bulk-clear]')) s.clear(); };
      icons(); return;
    }
    el.className = 'table-bar';
    const colsMenu = o.columns && o.key ? `<details class="more-menu cols-menu"><summary class="btn sm ghost"><i data-lucide="columns-3"></i>Sütunlar</summary><div class="menu-pop" role="group" aria-label="Görünen sütunlar"></div></details>` : '';
    el.innerHTML = `<span class="tb-total" role="status"><b>${fmtN(o.total)}</b> ${esc(o.unit || 'sonuç')}</span>
      <div class="tb-actions">${colsMenu}${o.onSize ? `<label class="tb-size"><span>Sayfa başına</span><select class="input" aria-label="Sayfa başına satır">${[25, 50, 100].map((n) => `<option ${n === o.size ? 'selected' : ''}>${n}</option>`).join('')}</select></label>` : ''}</div>`;
    el.onclick = null;
    el.querySelector('.tb-size select')?.addEventListener('change', (e) => o.onSize(+e.target.value));
    const cm = el.querySelector('.cols-menu');
    cm?.addEventListener('toggle', () => {
      if (!cm.open) return;
      const host = el.parentElement, prefs = pref.get(`tl-cols:${o.key}`, {});
      cm.querySelector('.menu-pop').innerHTML = o.columns.map((c, i) => ({ ...c, _id: colId(c, i) })).filter((c) => c.label).map((c) => {
        const th = host.querySelector(`th[data-col="${CSS.escape(c._id)}"]`);
        const vis = !!th && getComputedStyle(th).display !== 'none';
        return `<label class="check"><input type="checkbox" data-col-toggle="${esc(c._id)}" ${vis ? 'checked' : ''} ${c.primary ? 'disabled' : ''}>${esc(c.label)}${c.hideIfAllZero && !th && prefs[c._id] !== 0 ? ' <small class="faint">(tümü boş)</small>' : ''}</label>`;
      }).join('') + '<button type="button" class="btn sm ghost" data-col-reset>Varsayılana dön</button>';
    });
    cm?.addEventListener('change', (e) => {
      const t = e.target.closest('[data-col-toggle]'); if (!t) return;
      const prefs = pref.get(`tl-cols:${o.key}`, {}); prefs[t.dataset.colToggle] = t.checked ? 1 : 0;
      pref.set(`tl-cols:${o.key}`, prefs); o.onCols && o.onCols();
    });
    cm?.addEventListener('click', (e) => { if (e.target.closest('[data-col-reset]')) { pref.set(`tl-cols:${o.key}`, null); cm.open = false; o.onCols && o.onCols(); } });
    icons();
  }

  /** Satır seçimi: sayfalar arasında korunur. onChange(seçili kimlik kümesi) */
  function selection(el, onChange) {
    const ids = new Set();
    el.addEventListener('change', (e) => {
      const all = e.target.closest('[data-select-all]');
      if (all) el.querySelectorAll('[data-select]').forEach((b) => { b.checked = all.checked; all.checked ? ids.add(b.dataset.select) : ids.delete(b.dataset.select); });
      const one = e.target.closest('[data-select]');
      if (one) one.checked ? ids.add(one.dataset.select) : ids.delete(one.dataset.select);
      if (all || one) { sync(); onChange(ids); }
    });
    const sync = () => {
      const boxes = [...el.querySelectorAll('[data-select]')], all = el.querySelector('[data-select-all]');
      boxes.forEach((b) => { b.checked = ids.has(b.dataset.select); b.closest('tr')?.classList.toggle('is-checked', b.checked); });
      if (all) { const n = boxes.filter((b) => b.checked).length; all.checked = !!n && n === boxes.length; all.indeterminate = n > 0 && n < boxes.length; }
    };
    return { ids, sync, clear: () => { ids.clear(); sync(); onChange(ids); } };
  }

  function pager(el, { page, size, total }, onPage, unit = 'kayıt') {
    const pages = Math.max(1, Math.ceil(total / size));
    const from = total ? (page - 1) * size + 1 : 0, to = Math.min(total, page * size);
    if (!total) { el.innerHTML = ''; el.hidden = true; return; }
    el.hidden = false;
    const nums = new Set([1, pages, page - 1, page, page + 1, page - 2, page + 2].filter((n) => n >= 1 && n <= pages));
    let prev = 0, btns = '';
    [...nums].sort((a, b) => a - b).forEach((n) => { if (n - prev > 1) btns += '<span class="faint" aria-hidden="true" style="padding:6px 4px">…</span>';
      btns += `<button type="button" data-page="${n}" ${n === page ? 'aria-current="page"' : ''} aria-label="Sayfa ${n}">${fmtN(n)}</button>`; prev = n; });
    el.innerHTML = `<span>${fmtN(from)}–${fmtN(to)} / ${fmtN(total)} ${esc(unit)}</span>
      <nav aria-label="Sayfalama"><button type="button" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''} aria-label="Önceki sayfa">‹</button>${btns}
      <button type="button" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''} aria-label="Sonraki sayfa">›</button></nav>`;
    el.onclick = (e) => { const b = e.target.closest('button[data-page]'); if (b && !b.disabled) onPage(+b.dataset.page); };
  }

  // ---------- filtre araç çubuğu ----------
  /** form#filters: kendiliğinden uygulanır (metin 300 ms gecikmeli), etkin filtreler çıkarılabilir etiket olarak
      görünür, "Temizle" yalnızca etkin filtre varken görünür, durum adres çubuğundan geri yüklenir.
      Varsayılan değer: öğenin data-default özniteliği (yoksa boş / işaretsiz). data-chip="off" etiket üretmez. */
  function filterBar(form, { onChange } = {}) {
    if (!form) return null;
    const named = () => [...form.elements].filter((el) => el.name && !['submit', 'button', 'reset'].includes(el.type));
    const defOf = (el) => el.type === 'checkbox' ? el.hasAttribute('data-default') : (el.dataset.default ?? '');
    const valOf = (el) => el.type === 'checkbox' ? el.checked : el.value;
    const isActive = (el) => valOf(el) !== defOf(el) && !(el.type !== 'checkbox' && el.value === '' && defOf(el) === '');
    const chipsEl = form.querySelector('.tb-chips'), clearBtn = form.querySelector('.tb-clear'), toggle = form.querySelector('.filter-toggle');
    const moreCount = form.querySelector('.more-filters .count');
    const labelOf = (el) => el.dataset.label || el.closest('[data-label]')?.dataset.label
      || el.closest('label')?.querySelector(':scope > span')?.textContent.trim()
      || (el.labels && el.labels[0] ? el.labels[0].textContent.trim() : el.name);
    const textOf = (el) => el.tagName === 'SELECT' ? el.selectedOptions[0]?.textContent.trim() : el.type === 'checkbox' ? '' : (el.dataset.text || el.value);

    const restore = () => named().forEach((el) => {
      const v = qs.get(el.name);
      if (el.type === 'checkbox') { if (v !== null) el.checked = v === (el.value || 'true'); }
      else if (v !== null) el.value = v;
      el.closest('.range2')?._sync?.();
    });
    /** API ve adres çubuğu için değerler: varsayılandakiler '' (qs.set bunları adresten siler) */
    const values = () => {
      const o = {};
      named().forEach((el) => {
        if (el.type === 'checkbox') o[el.name] = el.checked === defOf(el) ? '' : (el.checked ? (el.value === 'on' ? 'true' : el.value) : 'false');
        else o[el.name] = isActive(el) ? el.value.trim() : '';
      });
      return o;
    };
    const chips = () => {
      const out = [], seen = new Set();
      named().filter((el) => el.dataset.chip !== 'off' && (el.type !== 'hidden' || el.dataset.label) && isActive(el)).forEach((el) => {
        const r2 = el.closest('.range2');
        if (r2) { if (seen.has(r2)) return; seen.add(r2); out.push({ els: [...r2.querySelectorAll('input')], text: `${r2.dataset.label}: ${r2._text()}` }); return; }
        const t = textOf(el), l = labelOf(el);
        out.push({ els: [el], text: el.type === 'checkbox' ? (el.checked ? l : `${l}: kapalı`) : `${l}: ${t}` });
      });
      return out;
    };
    const activeCount = () => named().filter((el) => isActive(el) && el.dataset.chip !== 'off').length;
    let current = [];
    const render = () => {
      current = chips();
      if (chipsEl) {
        chipsEl.innerHTML = current.map((c, i) => `<span class="chip fchip">${esc(c.text)}<button type="button" data-unchip="${i}" aria-label="Filtreyi kaldır: ${esc(c.text)}" title="Kaldır"><i data-lucide="x"></i></button></span>`).join('');
        chipsEl.hidden = !current.length;
      }
      const n = current.length + named().filter((el) => el.type === 'hidden' && !el.dataset.label && isActive(el)).length;
      if (clearBtn) clearBtn.hidden = !n;
      if (toggle) toggle.innerHTML = `<i data-lucide="sliders-horizontal"></i>Filtreler${current.length ? ` <span class="count">${current.length}</span>` : ''}`;
      if (moreCount) { const m = [...form.querySelectorAll('.more-filters [name]')].filter((el) => isActive(el)); const k = new Set(m.map((el) => el.closest('.range2') || el)).size;
        moreCount.textContent = k || ''; moreCount.hidden = !k; }
      icons();
    };
    const apply = () => { render(); onChange && onChange(values()); };
    const later = debounce(apply, 300);
    form.addEventListener('input', (e) => {
      const el = e.target; if (!el.name) return;
      if (el.type === 'range') { el.closest('.range2')?._sync?.(); return; }      // bırakınca (change) uygulanır
      if (['text', 'search', 'number'].includes(el.type) || el.tagName === 'TEXTAREA') later();
    });
    form.addEventListener('change', (e) => { const el = e.target; if (!el.name) return; if (['text', 'search', 'number'].includes(el.type)) return; apply(); });
    form.addEventListener('submit', (e) => { e.preventDefault(); apply(); closeSheet(); });
    form.addEventListener('reset', (e) => {
      e.preventDefault();
      named().forEach((el) => { if (el.type === 'checkbox') el.checked = defOf(el); else el.value = defOf(el); el.closest('.range2')?._sync?.(); });
      apply();
    });
    chipsEl?.addEventListener('click', (e) => {
      const b = e.target.closest('[data-unchip]'); if (!b) return;
      current[+b.dataset.unchip].els.forEach((el) => { if (el.type === 'checkbox') el.checked = defOf(el); else el.value = defOf(el); el.closest('.range2')?._sync?.(); });
      apply(); form.querySelector('.tb-search input, input[type=search]')?.focus();
    });
    // Telefonda filtreler alttan açılan panelde
    const sheet = form.querySelector('.tb-filters');
    let scrim;
    const closeSheet = () => { if (!form.classList.contains('sheet-open')) return; form.classList.remove('sheet-open'); form.querySelectorAll('.more-filters').forEach((d) => { d.open = false; }); toggle?.setAttribute('aria-expanded', 'false'); scrim?.remove(); scrim = null; document.documentElement.classList.remove('nav-open'); toggle?.focus(); };
    const openSheet = () => {
      form.classList.add('sheet-open'); toggle.setAttribute('aria-expanded', 'true');
      scrim = document.createElement('div'); scrim.className = 'scrim sheet-scrim'; scrim.addEventListener('click', closeSheet); document.body.appendChild(scrim);
      document.documentElement.classList.add('nav-open');
      form.querySelectorAll('.more-filters').forEach((d) => { d.open = true; });
      sheet.querySelector('select, input:not([type=hidden])')?.focus();
    };
    toggle?.addEventListener('click', () => (form.classList.contains('sheet-open') ? closeSheet() : openSheet()));
    form.querySelector('.sheet-close')?.addEventListener('click', closeSheet);
    form.querySelector('.sheet-done')?.addEventListener('click', closeSheet);
    form.addEventListener('keydown', (e) => { if (e.key === 'Escape' && form.classList.contains('sheet-open')) { e.stopPropagation(); closeSheet(); } });
    form.querySelectorAll('.range2').forEach(range2);
    // 768-1279 px: araç çubuğu tek satırda kalsın diye ilk iki açılır filtreden sonrakiler "Diğer filtreler"e taşınır.
    // Öğeler taşınır (kopyalanmaz): form içinde kalır, değerleri ve dinleyicileri korunur; geniş ekranda yerine döner.
    const pop = form.querySelector('.more-filters .more-pop');
    if (pop) {
      const extra = [...form.querySelectorAll('.tb-filters > .tb-field:not(.tb-sort)')].slice(2);
      const slots = extra.map((el) => { const c = document.createComment('tb-slot'); el.before(c); return c; });
      const mq = window.matchMedia('(min-width: 768px) and (max-width: 1279px)');
      const place = () => {
        if (mq.matches) extra.slice().reverse().forEach((el) => { el.classList.add('in-more'); pop.prepend(el); });
        else extra.forEach((el, i) => { el.classList.remove('in-more'); slots[i].after(el); });
        render();
      };
      mq.addEventListener('change', place);
      if (mq.matches) place();
    }
    restore(); render();
    return { values, activeCount, render, restore, reset: () => form.reset() };
  }

  /** Çift uçlu kaydırıcı: .range2[data-label] içinde iki input[type=range] (alt ve üst sınır) */
  function range2(box) {
    const [lo, hi] = box.querySelectorAll('input[type=range]'), out = box.querySelector('output');
    const min = +lo.min || 0, max = +hi.max || 100;
    box._text = () => `${lo.value}–${hi.value}`;
    box._sync = () => {
      if (+lo.value > +hi.value) { if (document.activeElement === lo) lo.value = hi.value; else hi.value = lo.value; }
      box.style.setProperty('--lo', `${((lo.value - min) / (max - min)) * 100}%`);
      box.style.setProperty('--hi', `${((hi.value - min) / (max - min)) * 100}%`);
      if (out) out.textContent = box._text();
      lo.setAttribute('aria-valuetext', `en az ${lo.value}`); hi.setAttribute('aria-valuetext', `en çok ${hi.value}`);
    };
    box._sync();
  }

  // ---------- sağ detay paneli (split düzeni) ----------
  const OVERLAY = window.matchMedia('(max-width: 1279px)');
  function panel(splitEl, html) {
    const p = splitEl.querySelector('.panel');
    if (html === null) {
      splitEl.classList.add('no-panel'); p.hidden = true; document.documentElement.classList.remove('panel-full');
      if (p._opener && document.contains(p._opener)) p._opener.focus?.();
      return p;
    }
    const full = FULL.matches;
    if (p.hidden) {
      p._opener = document.activeElement;
      // <1024: panel ayrı bir sayfa gibi davranır; tarayıcının geri tuşu paneli kapatır
      if (full && !(history.state && history.state.tlPanel)) history.pushState({ ...(history.state || {}), tlPanel: 1 }, '');
    }
    splitEl.classList.remove('no-panel'); p.hidden = false; p.innerHTML = html; icons();
    p.querySelector('[data-close]')?.addEventListener('click', () => closePanel(splitEl));
    document.documentElement.classList.toggle('panel-full', full);
    if (full) p.scrollTop = 0;
    if (OVERLAY.matches && !p.contains(document.activeElement)) p.focus?.({ preventScroll: true });
    return p;
  }
  const FULL = window.matchMedia('(max-width: 1023px)');
  const doClose = (splitEl) => { panel(splitEl, null); TL.onPanelClose && TL.onPanelClose(); };
  const closePanel = (splitEl) => { if (history.state && history.state.tlPanel) history.back(); else doClose(splitEl); };
  window.addEventListener('popstate', (e) => {
    if (e.state && e.state.tlPanel) return;
    const sp = document.querySelector('.split:not(.no-panel)');
    if (sp && sp.querySelector('.panel:not([hidden])')) doClose(sp);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || document.querySelector('dialog[open]') || e.defaultPrevented) return;
    const sp = document.querySelector('.split:not(.no-panel)');
    if (sp && sp.querySelector('.panel:not([hidden])')) { closePanel(sp); e.preventDefault(); }
  });
  const panelHead = (title) => `<div class="panel-head"><h2>${esc(title)}</h2><button type="button" class="btn icon ghost" data-close aria-label="Paneli kapat" title="Kapat (Esc)"><i data-lucide="x"></i></button></div>`;
  const list = (items, render, emptyText = 'Kayıt yok.') => items && items.length ? `<ul class="list">${items.map(render).join('')}</ul>` : `<p class="faint" style="font-size:13px">${esc(emptyText)}</p>`;

  // ---------- diyalog ----------
  /** Açılınca odak ilk giriş alanına gider; Esc kapatır; kapanınca odak açan öğeye döner; Ctrl+Enter formu gönderir. */
  function dialog(html, { wide = false } = {}) {
    const opener = document.activeElement;
    const d = document.createElement('dialog'); if (wide) d.className = 'wide';
    d.innerHTML = html; document.body.appendChild(d);
    d.addEventListener('close', () => { d.remove(); if (opener && document.contains(opener)) opener.focus?.(); });
    d.querySelectorAll('[data-dismiss]').forEach((b) => b.addEventListener('click', () => d.close()));
    d.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { const f = d.querySelector('form'); if (f) { e.preventDefault(); f.requestSubmit(); } }
    });
    icons(); d.showModal();
    const first = d.querySelector('input:not([type=hidden]):not([disabled]), textarea, select');
    (first || d.querySelector('.dlg-foot .btn.primary') || d.querySelector('button'))?.focus();
    return d;
  }
  const formData = (form) => Object.fromEntries([...new FormData(form).entries()].map(([k, v]) => [k, typeof v === 'string' ? v.trim() : v]));

  /** Dosya seçimi: tarayıcının "Dosya Seç" düğmesi yerine sürükle-bırak alanı. input formda kalır (FormData çalışır). */
  function dropzone(input, { hint = '' } = {}) {
    if (!input || input.dataset.dz) return;
    input.dataset.dz = '1';
    const zone = document.createElement('div'); zone.className = 'dropzone';
    const label = input.labels && input.labels[0];
    input.before(zone); zone.appendChild(input); input.classList.add('dz-input');
    zone.insertAdjacentHTML('beforeend', `<div class="dz-empty"><i data-lucide="upload-cloud"></i><span><b>Dosyayı bırakın</b> ya da <span class="link">seçin</span></span>${hint ? `<small class="faint">${esc(hint)}</small>` : ''}</div>
      <div class="dz-file" hidden><i data-lucide="file-text"></i><span class="dz-name"></span><small class="faint dz-size"></small><button type="button" class="btn sm icon ghost dz-remove" aria-label="Seçilen dosyayı kaldır" title="Kaldır"><i data-lucide="x"></i></button></div>`);
    if (label) label.classList.add('dz-label');
    const show = () => {
      const f = input.files && input.files[0];
      zone.querySelector('.dz-empty').hidden = !!f; zone.querySelector('.dz-file').hidden = !f; zone.classList.toggle('has-file', !!f);
      if (f) { zone.querySelector('.dz-name').textContent = f.name; zone.querySelector('.dz-size').textContent = fmtSize(f.size); }
    };
    input.addEventListener('change', show);
    zone.querySelector('.dz-remove').addEventListener('click', (e) => { e.preventDefault(); input.value = ''; input.dispatchEvent(new Event('change', { bubbles: true })); input.focus(); });
    ['dragenter', 'dragover'].forEach((t) => zone.addEventListener(t, (e) => { e.preventDefault(); zone.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((t) => zone.addEventListener(t, () => zone.classList.remove('over')));
    zone.addEventListener('drop', (e) => {
      e.preventDefault(); if (!e.dataTransfer.files.length) return;
      const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]); input.files = dt.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    input.form?.addEventListener('reset', () => setTimeout(show));
    show(); icons();
  }

  /** Metin alanına dosya bırakma: dosyanın metni alana yazılır (toplu kontrol, log avı) */
  function dropText(area, onText, maxBytes = 5 * 1048576) {
    ['dragenter', 'dragover'].forEach((t) => area.addEventListener(t, (e) => { if ([...(e.dataTransfer?.types || [])].includes('Files')) { e.preventDefault(); area.classList.add('over'); } }));
    ['dragleave', 'drop'].forEach((t) => area.addEventListener(t, () => area.classList.remove('over')));
    area.addEventListener('drop', async (e) => {
      const f = e.dataTransfer.files[0]; if (!f) return; e.preventDefault();
      if (f.size > maxBytes) { toast(`Dosya çok büyük (${fmtSize(f.size)}); en çok ${fmtSize(maxBytes)}.`, 'err'); return; }
      area.value = await f.text(); area.dispatchEvent(new Event('input', { bubbles: true })); onText && onText(f);
    });
  }

  // ---------- SQL çekmecesi ----------
  const KW = /\b(SELECT|FROM|WHERE|JOIN|LEFT|INNER|OUTER|APPLY|CROSS|ON|AND|OR|NOT|IN|EXISTS|GROUP BY|ORDER BY|HAVING|TOP|DISTINCT|AS|WITH|UNION ALL|UNION|INSERT INTO|INSERT|UPDATE|DELETE|SET|VALUES|OUTPUT|EXEC|DECLARE|CASE|WHEN|THEN|ELSE|END|OFFSET|FETCH NEXT|ROWS ONLY|ROWS|MATCH|SHORTEST_PATH|COUNT|SUM|ISNULL|COALESCE|CAST|BEGIN TRANSACTION|COMMIT TRANSACTION|ROLLBACK TRANSACTION|OPENJSON|STRING_AGG|OPTION|DESC|ASC|BETWEEN|LIKE|IS|NULL)\b/g;
  const hl = (sql) => esc(sql).split('\n').map((line) => {
    const i = line.indexOf('--'); const code = i >= 0 ? line.slice(0, i) : line, cmt = i >= 0 ? line.slice(i) : '';
    return code.replace(/(N?&#39;[^&]*?&#39;)/g, '<span class="sql-str">$1</span>').replace(KW, '<span class="sql-kw">$1</span>') + (cmt ? `<span class="sql-cmt">${cmt}</span>` : '');
  }).join('\n');
  async function openSql() {
    const dr = document.getElementById('sqlDrawer'), body = document.getElementById('sqlBody');
    dr.classList.add('open'); dr.setAttribute('aria-hidden', 'false'); body.innerHTML = loading('Sorgular alınıyor');
    const ids = [...new Map(TL.traces.map((t) => [t.id, t])).values()].slice(-12).reverse();
    const parts = [];
    for (const t of ids) {
      try {
        const tr = await api(`/api/trace/${t.id}`);
        tr.statements.forEach((s) => parts.push(`<div class="sql-item"><div class="meta"><span>${esc(tr.method)} ${esc(tr.path)}</span><span>${s.ms} ms · ${s.rows ?? '—'} satır</span></div>
          <pre>${hl(s.sql)}</pre>${s.params && s.params.length ? `<div class="meta"><span>Parametreler (?): ${esc(JSON.stringify(s.params))}</span></div>` : ''}</div>`));
      } catch { /* iz bellekten düşmüş olabilir */ }
    }
    TL.traces = TL.traces.filter((t) => !t.path.startsWith('/api/trace'));
    body.innerHTML = parts.length ? parts.join('') : empty('Bu sayfada henüz SQL çalıştırılmadı.', 'database');
    icons(); document.getElementById('sqlClose').focus();
  }
  function closeSql() { const dr = document.getElementById('sqlDrawer'); if (!dr) return; dr.classList.remove('open'); dr.setAttribute('aria-hidden', 'true'); }

  // ---------- global arama ----------
  function initOmni() {
    const input = document.getElementById('omniInput'), box = document.getElementById('omniResults');
    if (!input) return;
    const mq = window.matchMedia('(min-width: 720px)');
    const setPh = () => { input.placeholder = mq.matches ? input.dataset.longPlaceholder : 'IOC, aktör, teknik ara'; };
    setPh(); mq.addEventListener('change', setPh);
    let items = [], idx = -1;
    const close = () => { box.hidden = true; input.setAttribute('aria-expanded', 'false'); idx = -1; };
    const render = () => {
      box.innerHTML = items.length ? items.map((r, i) => `<a role="option" id="omni-${i}" href="${entityUrl(r.EntityType, r.EntityID)}" ${i === idx ? 'aria-selected="true"' : ''}>
          <i data-lucide="${(NODE[r.EntityType] || NODE.indicator).icon}" style="color:${(NODE[r.EntityType] || NODE.indicator).color}"></i>
          <span class="t">${esc(r.Title)}<br><small>${esc(r.Subtitle || '')}</small></span><small>${esc((NODE[r.EntityType] || {}).label || r.EntityType)}</small></a>`).join('')
        : `<div class="empty" style="padding:16px">Sonuç bulunamadı.</div>`;
      box.hidden = false; input.setAttribute('aria-expanded', 'true'); icons();
      if (idx >= 0) input.setAttribute('aria-activedescendant', `omni-${idx}`); else input.removeAttribute('aria-activedescendant');
    };
    const search = debounce(async () => {
      const q = input.value.trim(); if (q.length < 2) { close(); return; }
      try { items = await api('/api/search', { params: { q } }); idx = -1; render(); } catch (e) { toast(e.message, 'err'); }
    }, 250);
    input.addEventListener('input', search);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' && items.length) { idx = Math.min(items.length - 1, idx + 1); render(); e.preventDefault(); }
      else if (e.key === 'ArrowUp' && items.length) { idx = Math.max(0, idx - 1); render(); e.preventDefault(); }
      else if (e.key === 'Escape') close();
      else if (e.key === 'Enter') {
        e.preventDefault();
        if (idx >= 0 && items[idx]) location.href = entityUrl(items[idx].EntityType, items[idx].EntityID);
        else if (input.value.trim()) location.href = '/search?q=' + encodeURIComponent(input.value.trim());
      }
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.omni')) close(); });
    document.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); input.focus(); input.select(); } });
  }

  // ---------- iskelet ----------
  function initShell() {
    const html = document.documentElement;
    const sb = document.getElementById('sidebar'), scrim = document.getElementById('scrim'), mb = document.getElementById('menuBtn');
    const isOpen = () => sb.classList.contains('open');
    // Dar ekranda kapalı çekmece "inert": içindeki bağlantılar Tab ile odaklanmaz, ekran okuyucu okumaz
    const syncInert = () => { sb.inert = NARROW.matches && !isOpen(); };
    const setNav = (open, { restoreFocus = true } = {}) => {
      if (open && !NARROW.matches) return;                  // geniş ekranda kenar çubuğu zaten görünür
      if (!open && !isOpen()) return;
      sb.classList.toggle('open', open); scrim.hidden = !open;
      html.classList.toggle('nav-open', open);   // arka sayfa kaymaz
      if (mb) {
        mb.setAttribute('aria-expanded', String(open));
        mb.setAttribute('aria-label', open ? 'Menüyü kapat' : 'Menüyü aç');
        mb.innerHTML = `<i data-lucide="${open ? 'x' : 'menu'}"></i>`; icons();
      }
      syncInert();
      if (open) (sb.querySelector('.nav a[aria-current="page"]') || sb.querySelector('.nav a'))?.focus();
      else if (restoreFocus && mb && sb.contains(document.activeElement)) mb.focus();
    };
    syncInert();
    NARROW.addEventListener('change', () => { setNav(false, { restoreFocus: false }); syncInert(); });
    mb?.addEventListener('click', () => setNav(!isOpen()));
    document.getElementById('navClose')?.addEventListener('click', () => setNav(false));
    scrim?.addEventListener('click', () => setNav(false));
    sb.addEventListener('click', (e) => { if (e.target.closest('.nav a') && isOpen()) setNav(false, { restoreFocus: false }); });
    // Odak tuzağı: çekmece açıkken Tab çekmecenin içinde döner
    sb.addEventListener('keydown', (e) => {
      if (e.key !== 'Tab' || !isOpen()) return;
      const f = [...sb.querySelectorAll('a[href], button:not([disabled])')].filter((el) => el.offsetParent !== null);
      if (!f.length) return;
      if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
    });
    // Masaüstü: kenar çubuğu ikon şeridine daraltılabilir. Seçim saklanır; seçim yoksa 1024-1279 px'de şerit varsayılan.
    const nc = document.getElementById('navCollapse');
    const showCollapse = () => {
      const on = html.classList.contains('nav-collapsed');
      if (!nc) return;
      nc.setAttribute('aria-pressed', String(on)); nc.setAttribute('aria-label', on ? 'Menüyü genişlet' : 'Menüyü daralt'); nc.title = nc.getAttribute('aria-label');
      nc.innerHTML = `<i data-lucide="${on ? 'panel-left-open' : 'panel-left-close'}"></i>`; icons();
    };
    showCollapse();
    nc?.addEventListener('click', () => {
      const on = html.classList.toggle('nav-collapsed');
      try { localStorage.setItem('tl-nav-collapsed', on ? '1' : '0'); } catch { /* yok say */ }
      showCollapse();
      window.dispatchEvent(new Event('resize'));          // graf ve grafikler yeni genişliğe uysun
    });

    // ---- kullanıcı menüsü ----
    const ub = document.getElementById('userBtn'), um = document.getElementById('userMenu');
    const items = () => [...um.querySelectorAll('[role^="menuitem"], .seg button')].filter((el) => el.offsetParent !== null);
    const setMenu = (open, focusFirst = false) => {
      if (!um) return;
      um.hidden = !open; ub.setAttribute('aria-expanded', String(open));
      if (open && focusFirst) items()[0]?.focus();
    };
    ub?.addEventListener('click', (e) => { e.stopPropagation(); setMenu(um.hidden, e.detail === 0); });
    ub?.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown') { e.preventDefault(); setMenu(true, true); } });
    um?.addEventListener('keydown', (e) => {
      const list = items(), i = list.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') { e.preventDefault(); list[(i + 1) % list.length]?.focus(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); list[(i - 1 + list.length) % list.length]?.focus(); }
      else if (e.key === 'Escape') { e.stopPropagation(); setMenu(false); ub.focus(); }
      else if (e.key === 'Tab') setMenu(false);
    });
    document.addEventListener('click', (e) => { if (um && !um.hidden && !e.target.closest('#userMenu')) setMenu(false); });
    document.getElementById('pwBtn')?.addEventListener('click', () => {
      setMenu(false);
      const d = dialog(`<form><div class="dlg-head"><h2>Parolamı değiştir</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <div class="field"><label for="pw-c">Mevcut parola</label><input class="input" id="pw-c" name="current" type="password" autocomplete="current-password" required></div>
        <div class="field"><label for="pw-n">Yeni parola (en az 10 karakter, harf ve rakam/sembol)</label><input class="input" id="pw-n" name="new" type="password" autocomplete="new-password" minlength="10" required></div>
        <div class="field"><label for="pw-r">Yeni parola (tekrar)</label><input class="input" id="pw-r" name="repeat" type="password" autocomplete="new-password" minlength="10" required></div>
        <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Parolayı değiştir</button></div></form>`);
      d.querySelector('form').onsubmit = async (e) => {
        e.preventDefault(); const f = formData(e.target), err = e.target.querySelector('.err');
        if (f.new !== f.repeat) { err.textContent = 'Yeni parolalar eşleşmiyor.'; return; }
        try { const r = await api('/api/auth/password', { method: 'POST', body: { current: f.current, new: f.new } });
          d.close(); toast(`Parola değiştirildi.${r.endedSessions ? ` Diğer ${r.endedSessions} oturum kapatıldı.` : ''}`); }
        catch (x) { err.textContent = x.message; }
      };
    });
    // Tema: Sistem / Koyu / Açık; tercih tarayıcıda saklanır (yalnızca bu cihaz için)
    const seg = document.getElementById('themeSeg');
    const curTheme = () => { try { return localStorage.getItem('tl-theme') || 'system'; } catch { return 'system'; } };
    const showTheme = () => seg?.querySelectorAll('[data-theme-set]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.themeSet === curTheme())));
    showTheme();
    seg?.addEventListener('click', (e) => {
      e.stopPropagation();
      const b = e.target.closest('[data-theme-set]'); if (!b) return;
      const next = b.dataset.themeSet;
      try { next === 'system' ? localStorage.removeItem('tl-theme') : localStorage.setItem('tl-theme', next); } catch { /* yok say */ }
      if (next === 'system') html.removeAttribute('data-theme'); else html.dataset.theme = next;
      showTheme();
      if (window.Chart && Object.keys(Chart.instances || {}).length) location.reload();   // grafikler renkleri oluşturulurken alır
    });
    // Açma/kapama anahtarları: rahat tablo görünümü ve geliştirici modu
    const switchBtn = (id, cls, key, after) => {
      const b = document.getElementById(id); if (!b) return;
      const show = () => b.setAttribute('aria-checked', String(html.classList.contains(cls)));
      show();
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        const on = html.classList.toggle(cls);
        try { on ? localStorage.setItem(key, '1') : localStorage.removeItem(key); } catch { /* yok say */ }
        show(); after && after(on);
      });
    };
    // Geliştirici modu: SQL çekmecesi ve teknik açıklamalar (görünüm, yordam, tetikleyici adları). Sunumda açılır.
    switchBtn('devBtn', 'dev', 'tl-dev', (on) => { if (!on) closeSql(); requestAnimationFrame(() => enhance()); });
    switchBtn('denseBtn', 'comfortable', 'tl-comfortable', () => document.querySelectorAll('.table-scroll').forEach((s) => s._shade?.()));
    document.getElementById('logoutBtn')?.addEventListener('click', async () => { await api('/api/auth/logout', { method: 'POST' }).catch(() => {}); location.href = '/login'; });
    document.getElementById('sqlBtn')?.addEventListener('click', openSql);
    document.getElementById('sqlClose')?.addEventListener('click', closeSql);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeSql(); setNav(false); } });
    document.addEventListener('click', async (e) => {
      const b = e.target.closest('[data-copy]'); if (!b) return;
      e.stopPropagation();
      try { await navigator.clipboard.writeText(b.dataset.copy); toast('Panoya kopyalandı.'); }
      catch { const t = document.createElement('textarea'); t.value = b.dataset.copy; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); toast('Panoya kopyalandı.'); }
    }, true);
    initOmni(); icons();
    // Sayfalar içeriği kendi çizer; ipucu, gölge ve kırpma iyileştirmeleri her değişiklikten sonra (gecikmeli) uygulanır
    const main = document.getElementById('content');
    if (main) { const later = debounce(() => enhance(main), 120); new MutationObserver(later).observe(main, { childList: true, subtree: true }); }
  }

  // ---------- dar ekran yardımcıları ----------
  const NARROW = window.matchMedia('(max-width: 1023px)');
  const PHONE = window.matchMedia('(max-width: 560px)');

  /** Eylem çubuğu: telefonda birincil düğme ve ilk `keep` eylem görünür kalır, gerisi "Diğer" menüsüne taşınır.
      Öğeler kopyalanmaz, taşınır: bağlı olay dinleyicileri korunur; geniş ekrana dönünce yerlerine geri konur. */
  function overflowActions(container, keep = 2) {
    if (!container || container.dataset.overflow) return;
    container.dataset.overflow = '1';
    const items = [...container.children];
    const more = document.createElement('details'); more.className = 'more-menu';
    more.innerHTML = '<summary class="btn" aria-label="Diğer eylemler"><i data-lucide="ellipsis"></i>Diğer</summary><div class="menu-pop" role="menu"></div>';
    const pop = more.querySelector('.menu-pop');
    const slots = items.map((el) => { const c = document.createComment('slot'); el.before(c); return c; });
    const apply = () => {
      if (PHONE.matches) {
        let shown = 0;
        items.forEach((el) => {
          const stay = el.classList.contains('primary') || (shown < keep && !el.classList.contains('danger'));
          if (stay) { if (!el.classList.contains('primary')) shown += 1; return; }
          if (!el.textContent.trim() && el.getAttribute('aria-label') && !el.querySelector('.menu-label')) {
            el.insertAdjacentHTML('beforeend', `<span class="menu-label">${esc(el.getAttribute('aria-label'))}</span>`);
          }
          pop.appendChild(el);
        });
        if (pop.children.length) container.appendChild(more);
      } else {
        items.forEach((el, i) => slots[i].after(el));
        more.remove(); more.open = false;
      }
      icons();
    };
    apply(); PHONE.addEventListener('change', apply);
  }
  // Bakım işleri: iş türüne göre gruplu; her grupta son çalışma ve sonucu, geçmiş açılır (aynı satırlar listeyi doldurmasın)
  const TASK_LABEL = { 'expire-indicators': ["Süresi dolan IOC'leri kapat", 'Her gece 02:00'], 'graph-maintenance': ['Graf bakımı', 'Her pazar 03:00'] };
  const RUN_STATUS = { success: ['Başarılı', 'b-ok'], failed: ['Hatalı', 'b-bad'], running: ['Çalışıyor', 'b-cyan'] };
  function maintenanceRuns(runs) {
    if (!runs.length) return '<p class="faint" style="font-size:13px">Bakım işleri henüz çalışmadı.</p>';
    const groups = new Map(); runs.forEach((r) => { if (!groups.has(r.Task)) groups.set(r.Task, []); groups.get(r.Task).push(r); });
    const badge = (r) => { const [l, c] = RUN_STATUS[r.Status] || [r.Status, 'b-muted']; return `<span class="badge ${c}">${esc(l)}</span>`; };
    return `<div class="run-groups">${[...groups.entries()].map(([task, rs]) => { const [name, when] = TASK_LABEL[task] || [task, ''], last = rs[0];
      const fails = rs.filter((r) => r.Status === 'failed').length;
      return `<details class="run-group"><summary><span class="rg-main"><b>${esc(name)}</b><small class="muted">${esc(when)}${when ? ' · ' : ''}son çalışma ${ago(last.StartedAt)} · ${esc(last.Message || (last.RowsAffected != null ? `${fmtN(last.RowsAffected)} satır` : ''))}</small></span>
          <span class="rg-side">${fails ? `<span class="badge b-bad" title="Listelenen çalışmalarda hata">${fmtN(fails)} hata</span>` : ''}${badge(last)}</span></summary>
        <ol class="run-hist">${rs.map((r) => `<li><span class="nowrap" title="${fmtDT(r.StartedAt)}">${fmtDT(r.StartedAt)}</span><span class="rh-msg">${esc(r.Message || '—')}</span>${badge(r)}</li>`).join('')}</ol></details>`; }).join('')}</div>`;
  }

  // Tablo satırındaki menü: kaydırma alanı tarafından kesilmesin diye sabit konumlanır, sayfa kayınca kapanır
  document.addEventListener('toggle', (e) => {
    const d = e.target; if (!(d instanceof HTMLDetailsElement) || !d.classList.contains('row-menu') || !d.open) return;
    const r = d.querySelector('summary').getBoundingClientRect(), pop = d.querySelector('.menu-pop');
    const below = innerHeight - r.bottom > 200;
    pop.style.right = `${Math.max(8, innerWidth - r.right)}px`;
    pop.style.top = below ? `${r.bottom + 6}px` : ''; pop.style.bottom = below ? '' : `${innerHeight - r.top + 6}px`;
  }, true);
  window.addEventListener('scroll', () => document.querySelectorAll('details.row-menu[open]').forEach((d) => { d.open = false; }), { passive: true });
  document.addEventListener('click', (e) => {
    document.querySelectorAll('details.more-menu[open], details.more-filters[open]').forEach((d) => {
      if (d.closest('.sheet-open')) return;                        // alttan açılan filtre panelinde açık kalır
      if (!d.contains(e.target) || (e.target.closest('.menu-pop > a, .menu-pop > button') && !d.classList.contains('cols-menu'))) d.open = false;
    });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const d = document.querySelector('details.more-menu[open], .toolbar:not(.sheet-open) details.more-filters[open]'); if (!d) return;
    d.open = false; d.querySelector('summary')?.focus(); e.preventDefault(); e.stopPropagation();
  }, true);

  // ---------- Chart.js ortak ayarları ----------
  function chartDefaults() {
    if (!window.Chart) return;
    Chart.defaults.color = cssVar('--text-2'); Chart.defaults.borderColor = cssVar('--line');
    Chart.defaults.font.family = 'Inter, system-ui, sans-serif'; Chart.defaults.font.size = 12;
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.plugins.tooltip.backgroundColor = cssVar('--elev-2'); Chart.defaults.plugins.tooltip.borderColor = cssVar('--line-strong'); Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = cssVar('--text'); Chart.defaults.plugins.tooltip.bodyColor = cssVar('--text');
    Chart.defaults.animation.duration = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 500;
  }

  Object.assign(TL, { esc, fmtDT, fmtD, fmtN, fmtSize, ago, pct, midTruncate, clipList, num, SEV, NODE, TYPE_LABEL, sev, typeBadge, status, job, conf,
    sourceBadge, sourceShort, maintenanceRuns, copyBtn, iocCell, nodeIcon, techChip, entityUrl, graphUrl, refang, guessType, countTypes, api, icons, enhance, toast, loading, empty,
    failed, debounce, can, qs, pref, clampText, actions, table, bindTable, markRow, pageSize, tableBar, selection, pager, filterBar, panel, closePanel,
    panelHead, list, dialog, dropzone, dropText, formData, chartDefaults, meta, overflowActions, NARROW, PHONE, cssVar });
  document.addEventListener('DOMContentLoaded', () => { initShell(); chartDefaults(); });
})();
