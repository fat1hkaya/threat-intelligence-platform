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
    `<span class="conf"><span class="meter" aria-hidden="true"><i style="width:${n}%;background:${n >= 80 ? 'var(--low)' : n >= 50 ? 'var(--medium)' : 'var(--high)'}"></i></span>${n}</span>`;
  const sourceBadge = (name) => esc(name || '—');
  const copyBtn = (v) => `<button class="btn sm icon ghost" data-copy="${esc(v)}" aria-label="Değeri kopyala" title="Kopyala"><i data-lucide="copy"></i></button>`;
  const nodeIcon = (t) => { const n = NODE[t] || NODE.indicator; return `<span class="ic" style="background:${n.color}22;color:${n.color}"><i data-lucide="${n.icon}"></i></span>`; };

  const entityUrl = (type, id) => ({
    indicator: `/iocs/${id}`, actor: `/actors?id=${id}`, malware: `/malware?id=${id}`, campaign: `/campaigns?id=${id}`,
    technique: `/attack?id=${id}`, vulnerability: `/graph?type=vulnerability&id=${id}`,
  }[type] || '#');
  const graphUrl = (type, id) => `/graph?type=${type}&id=${id}`;

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

  // ---------- küçük bileşenler ----------
  const icons = () => window.lucide && window.lucide.createIcons();
  function toast(msg, kind = 'ok') {
    const box = document.getElementById('toasts'); if (!box) return;
    const t = document.createElement('div'); t.className = `toast ${kind}`;
    t.innerHTML = `<i data-lucide="${kind === 'ok' ? 'circle-check' : 'circle-alert'}"></i><div>${esc(msg)}</div>`;
    box.appendChild(t); icons(); setTimeout(() => t.remove(), kind === 'ok' ? 3500 : 7000);
  }
  const loading = (t = 'Yükleniyor') => `<div class="loading"><span class="spinner"></span>${esc(t)}…</div>`;
  const empty = (t, icon = 'search-x') => `<div class="empty"><i data-lucide="${icon}"></i><p>${esc(t)}</p></div>`;
  const debounce = (fn, ms = 300) => { let h; return (...a) => { clearTimeout(h); h = setTimeout(() => fn(...a), ms); }; };
  const can = (role) => { const r = TL.user && TL.user.Role; return role === 'admin' ? r === 'admin' : role === 'analyst' ? r === 'admin' || r === 'analyst' : true; };
  const qs = {
    get: (k) => new URLSearchParams(location.search).get(k),
    set: (obj) => { const u = new URL(location.href); Object.entries(obj).forEach(([k, v]) => (v === null || v === undefined || v === '') ? u.searchParams.delete(k) : u.searchParams.set(k, v)); history.replaceState(null, '', u); },
  };

  /** Tablo: columns = [{key, label, render(row), num, sort, primary, cls}] */
  function table(columns, rows, { rowId, selected, sort, dir, caption, cards = true } = {}) {
    if (!rows.length) return '';
    const th = columns.map((c) => {
      const ariaSort = c.sort && sort === c.sort ? (dir === 'asc' ? 'ascending' : 'descending') : null;
      const inner = c.sort ? `<button type="button" data-sort="${c.sort}">${esc(c.label)}</button>` : esc(c.label);
      return `<th scope="col" class="${c.num ? 'num' : ''}" ${ariaSort ? `aria-sort="${ariaSort}"` : ''}>${inner}</th>`;
    }).join('');
    const tr = rows.map((r) => {
      const id = rowId ? rowId(r) : null;
      const tds = columns.map((c) => `<td data-label="${esc(c.label)}" class="${c.num ? 'num ' : ''}${c.primary ? 'primary ' : ''}${c.cls || ''}">${c.render ? c.render(r) : esc(r[c.key] ?? '—')}</td>`).join('');
      return `<tr ${id != null ? `data-id="${esc(id)}" class="clickable" tabindex="0"` : ''} ${id != null && String(id) === String(selected) ? 'aria-selected="true"' : ''}>${tds}</tr>`;
    }).join('');
    return `<div class="table-wrap"><table class="data${cards ? ' cards' : ''}">${caption ? `<caption class="sr-only">${esc(caption)}</caption>` : ''}<thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></div>`;
  }

  /** Tablo olaylarını bağlar: satır tıklama/Enter, sıralama başlıkları, kopyalama */
  function bindTable(el, { onRow, onSort } = {}) {
    el.addEventListener('click', (e) => {
      const s = e.target.closest('[data-sort]'); if (s && onSort) { onSort(s.dataset.sort); return; }
      if (e.target.closest('a, button, input')) return;
      const tr = e.target.closest('tr[data-id]'); if (tr && onRow) onRow(tr.dataset.id, tr);
    });
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter') { const tr = e.target.closest('tr[data-id]'); if (tr && onRow) onRow(tr.dataset.id, tr); } });
  }
  const markRow = (el, id) => el.querySelectorAll('tr[data-id]').forEach((tr) => tr.setAttribute('aria-selected', String(tr.dataset.id === String(id))));

  function pager(el, { page, size, total }, onPage, unit = 'kayıt') {
    const pages = Math.max(1, Math.ceil(total / size));
    const from = total ? (page - 1) * size + 1 : 0, to = Math.min(total, page * size);
    const nums = new Set([1, pages, page - 1, page, page + 1, page - 2, page + 2].filter((n) => n >= 1 && n <= pages));
    let prev = 0, btns = '';
    [...nums].sort((a, b) => a - b).forEach((n) => { if (n - prev > 1) btns += '<span class="faint" aria-hidden="true" style="padding:6px 4px">…</span>';
      btns += `<button data-page="${n}" ${n === page ? 'aria-current="page"' : ''} aria-label="Sayfa ${n}">${fmtN(n)}</button>`; prev = n; });
    el.innerHTML = `<span>Toplam <b>${fmtN(total)}</b> ${unit} · ${fmtN(from)}–${fmtN(to)} gösteriliyor</span>
      <nav aria-label="Sayfalama"><button data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''} aria-label="Önceki sayfa">‹</button>${btns}
      <button data-page="${page + 1}" ${page >= pages ? 'disabled' : ''} aria-label="Sonraki sayfa">›</button></nav>`;
    el.onclick = (e) => { const b = e.target.closest('button[data-page]'); if (b && !b.disabled) onPage(+b.dataset.page); };
  }

  // ---------- sağ detay paneli (split düzeni) ----------
  function panel(splitEl, html) {
    const p = splitEl.querySelector('.panel');
    if (html === null) { splitEl.classList.add('no-panel'); p.hidden = true; return p; }
    splitEl.classList.remove('no-panel'); p.hidden = false; p.innerHTML = html; icons();
    p.querySelector('[data-close]')?.addEventListener('click', () => { panel(splitEl, null); TL.onPanelClose && TL.onPanelClose(); });
    if (window.matchMedia('(max-width: 1180px)').matches) p.focus?.();
    return p;
  }
  const panelHead = (title) => `<div class="panel-head"><h2>${esc(title)}</h2><button class="btn icon ghost" data-close aria-label="Paneli kapat"><i data-lucide="x"></i></button></div>`;
  const list = (items, render, emptyText = 'Kayıt yok.') => items && items.length ? `<ul class="list">${items.map(render).join('')}</ul>` : `<p class="faint" style="font-size:13px">${esc(emptyText)}</p>`;

  // ---------- diyalog ----------
  function dialog(html, { wide = false } = {}) {
    const d = document.createElement('dialog'); if (wide) d.className = 'wide';
    d.innerHTML = html; document.body.appendChild(d);
    d.addEventListener('close', () => d.remove());
    d.querySelectorAll('[data-dismiss]').forEach((b) => b.addEventListener('click', () => d.close()));
    icons(); d.showModal(); return d;
  }
  const formData = (form) => Object.fromEntries([...new FormData(form).entries()].map(([k, v]) => [k, typeof v === 'string' ? v.trim() : v]));

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
  function closeSql() { const dr = document.getElementById('sqlDrawer'); dr.classList.remove('open'); dr.setAttribute('aria-hidden', 'true'); }

  // ---------- global arama ----------
  function initOmni() {
    const input = document.getElementById('omniInput'), box = document.getElementById('omniResults');
    if (!input) return;
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
    const sb = document.getElementById('sidebar'), scrim = document.getElementById('scrim'), mb = document.getElementById('menuBtn');
    const setNav = (open) => { sb.classList.toggle('open', open); scrim.hidden = !open; mb.setAttribute('aria-expanded', String(open)); };
    mb?.addEventListener('click', () => setNav(!sb.classList.contains('open')));
    scrim?.addEventListener('click', () => setNav(false));
    const ub = document.getElementById('userBtn'), um = document.getElementById('userMenu');
    ub?.addEventListener('click', (e) => { e.stopPropagation(); um.hidden = !um.hidden; ub.setAttribute('aria-expanded', String(!um.hidden)); });
    document.addEventListener('click', (e) => { if (um && !e.target.closest('#userMenu')) { um.hidden = true; ub?.setAttribute('aria-expanded', 'false'); } });
    document.getElementById('pwBtn')?.addEventListener('click', () => {
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
  }

  // ---------- Chart.js ortak ayarları ----------
  function chartDefaults() {
    if (!window.Chart) return;
    Chart.defaults.color = '#94A3B8'; Chart.defaults.borderColor = 'rgba(148,163,184,.12)';
    Chart.defaults.font.family = 'Inter, system-ui, sans-serif'; Chart.defaults.font.size = 12;
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.plugins.tooltip.backgroundColor = '#1F2D48'; Chart.defaults.plugins.tooltip.borderColor = '#2E3F61'; Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.animation.duration = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 500;
  }

  Object.assign(TL, { esc, fmtDT, fmtD, fmtN, ago, pct, SEV, NODE, TYPE_LABEL, sev, typeBadge, status, job, conf, sourceBadge, copyBtn, nodeIcon,
    entityUrl, graphUrl, api, icons, toast, loading, empty, debounce, can, qs, table, bindTable, markRow, pager, panel, panelHead, list, dialog,
    formData, chartDefaults, meta });
  document.addEventListener('DOMContentLoaded', () => { initShell(); chartDefaults(); });
})();
