/* IOC araştırma listesi: /api/iocs */
(() => {
  const { api, esc, fmtDT, fmtN, ago, sev, typeBadge, conf, sourceBadge, copyBtn, status, table, bindTable, markRow, pager, panel, panelHead, toast, empty, loading, icons, qs, can, dialog } = TL;
  const KEY = 'iocs';
  const st = { page: +(qs.get('page') || 1), size: TL.pageSize(KEY), sort: qs.get('sort') || 'lastSeen', dir: qs.get('dir') || 'desc', selected: qs.get('id'), last: null };
  const split = document.getElementById('split'), tbl = document.getElementById('tbl'), form = document.getElementById('filters'), bar = document.getElementById('tblBar');
  let fb = null, sel = null;

  const fam = (r) => {
    if (!r.MalwareName) return TL.unknown('Zararlı ailesiyle ilişkilendirilmemiş');
    if (/^Ailesi belirlenmemiş/.test(r.MalwareName)) return '<span class="faint">Ailesi belirlenmemiş</span>';
    const t = r.ActorName ? `${r.MalwareName} → ${r.ActorName}` : r.MalwareName;
    return `<span class="fam" title="${esc(t)}"><b>${esc(r.MalwareName)}</b>${r.ActorName ? `<span class="to" aria-hidden="true">→</span><span class="act">${esc(r.ActorName)}</span>` : ''}</span>`;
  };
  const cols = [
    { id: 'value', label: 'Gösterge', sort: 'value', primary: true, render: (r) => TL.iocCell(r.Value) },
    { id: 'type', label: 'Tip', sort: 'type', render: (r) => typeBadge(r.TypeCode) },
    { id: 'severity', label: 'Önem', sort: 'severity', render: (r) => sev(r.SeverityCode) },
    { id: 'risk', label: 'Risk', sort: 'risk', hint: 'Risk skoru (0–100); çubuk risk bandının renginde. Bileşenleri satıra tıklayınca açılan panelde.', render: (r) => TL.risk(r.RiskScore) },
    { id: 'confidence', label: 'Güven', sort: 'confidence', hidden: true, render: (r) => conf(r.Confidence) },
    { id: 'malware', label: 'Aile → aktör', priority: 2, hint: 'Zararlı ailesi ve onu kullanan tehdit aktörü; — : bir aileyle ilişkilendirilmemiş', render: fam },
    { id: 'source', label: 'Kaynak', sort: 'source', priority: 3, render: (r) => sourceBadge(r.SourceName) },
    { id: 'firstSeen', label: 'İlk görülme', sort: 'firstSeen', hidden: true, render: (r) => `<span class="muted nowrap" title="${fmtDT(r.FirstSeen)}">${ago(r.FirstSeen)}</span>` },
    { id: 'lastSeen', label: 'Son görülme', sort: 'lastSeen', render: (r) => `<span class="nowrap" title="${fmtDT(r.LastSeen)}">${ago(r.LastSeen)}</span>` },
    { id: 'actions', label: 'İşlemler', cls: 'actions', priority: 2, render: (r) => `<a class="btn sm icon ghost" href="/iocs/${r.IndicatorID}" aria-label="Detay sayfası: ${esc(r.Value)}" title="Detay sayfası"><i data-lucide="external-link"></i></a>
        <a class="btn sm icon ghost" href="${TL.graphUrl('indicator', r.IndicatorID)}" aria-label="İlişki grafında aç: ${esc(r.Value)}" title="İlişki grafında aç"><i data-lucide="share-2"></i></a>` },
  ];

  const filters = () => (fb ? fb.values() : {});
  const params = () => ({ ...filters(), page: st.page, size: st.size, sort: st.sort, dir: st.dir });

  // ---------- toplu işlemler ----------
  const ids = () => [...sel.ids].map(Number);
  const BULK = [
    can('analyst') && { label: 'Vakaya ekle', icon: 'briefcase', run: () => TL.addToCase('indicator', ids(), `${ids().length} IOC`, () => sel.clear()) },
    can('analyst') && { label: 'Durum değiştir', icon: 'circle-dot', run: bulkStatus },
    { label: 'Dışa aktar', icon: 'download', run: bulkExport },
  ].filter(Boolean);
  function bulkStatus() {
    const n = ids().length;
    const d = dialog(`<form><div class="dlg-head"><h2>Durum değiştir</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="muted">Seçili <b>${fmtN(n)} IOC</b> için yeni durum. Her değişiklik denetim kaydına ayrı satır olarak yazılır.</p>
      <div class="field"><label for="bs-status">Yeni durum</label><select class="input" id="bs-status" name="status">
        <option value="active">Aktif</option><option value="expired">Süresi doldu</option><option value="revoked">İptal edildi</option><option value="false_positive">Yanlış pozitif</option></select></div>
      <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Durumu değiştir</button></div></form>`);
    d.querySelector('form').onsubmit = async (e) => {
      e.preventDefault();
      try { const r = await api('/api/iocs/bulk-status', { method: 'POST', body: { ids: ids(), status: e.target.status.value } });
        d.close(); toast(`${fmtN(r.updated)} IOC güncellendi.${r.updated < n ? ` ${fmtN(n - r.updated)} kayıt zaten bu durumdaydı.` : ''}`); sel.clear(); load(); }
      catch (x) { e.target.querySelector('.err').textContent = x.message; }
    };
  }
  function bulkExport() {
    const d = dialog(`<div class="dlg"><div class="dlg-head"><h2>Seçili IOC'leri dışa aktar</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="muted">${fmtN(ids().length)} IOC için biçim seçin.</p>
      <div class="dlg-foot"><button type="button" class="btn" data-fmt="txt"><i data-lucide="shield-ban"></i>Engelleme listesi (.txt)</button><button type="button" class="btn primary" data-fmt="csv"><i data-lucide="file-spreadsheet"></i>CSV (tüm sütunlar)</button></div></div>`);
    d.addEventListener('click', (e) => { const b = e.target.closest('[data-fmt]'); if (!b) return; location.href = `/api/iocs/export?format=${b.dataset.fmt}&ids=${ids().join(',')}`; d.close(); });
  }
  const renderBar = () => TL.tableBar(bar, {
    total: st.last ? st.last.total : 0, unit: 'sonuç', headUnit: 'gösterge', size: st.size, key: KEY, columns: cols, onCols: render,
    onSize: (n) => { st.size = n; st.page = 1; TL.pref.set(`tl-size:${KEY}`, n); load(); },
    selection: { count: sel.ids.size, actions: BULK, clear: () => sel.clear() },
  });

  function render() {
    const d = st.last; if (!d) return;
    tbl.innerHTML = d.items.length ? table(cols, d.items, { rowId: (r) => r.IndicatorID, selected: st.selected, sort: st.sort, dir: st.dir, caption: 'IOC listesi', key: KEY,
      select: { label: (r) => r.Value }, selectedIds: sel.ids })
      : empty(fb.activeCount() ? 'Bu filtrelere uyan IOC yok. Filtreleri gevşetin veya başka bir değer arayın.' : 'Henüz IOC yok. Veri kaynaklarından besleme senkronize edin veya yeni IOC ekleyin.', 'search-x',
        fb.activeCount() ? { label: 'Filtreleri temizle', icon: 'filter-x' } : null);
    tbl.querySelector('[data-empty-action]')?.addEventListener('click', () => fb.reset());
    sel.sync(); renderBar();
    pager(document.getElementById('pager'), d, (n) => { st.page = n; load(); split.scrollIntoView({ block: 'start', behavior: 'smooth' }); }, 'IOC');
    icons();
  }

  async function load() {
    if (!st.last) tbl.innerHTML = loading(); else tbl.setAttribute('aria-busy', 'true');
    const p = params(); qs.set({ ...p, size: null, page: p.page > 1 ? p.page : null, sort: p.sort === 'lastSeen' ? null : p.sort, dir: p.dir === 'desc' ? null : p.dir, id: st.selected });
    try { st.last = await api('/api/iocs', { params: p }); render(); }
    catch (e) { st.last = null; bar.innerHTML = ''; TL.failed(tbl, e, load); }
    finally { tbl.removeAttribute('aria-busy'); }
  }

  const num = (n, d = 1) => Number(n).toLocaleString('tr-TR', { maximumFractionDigits: d });
  const chainList = (i, attribution) => {
    const seen = new Set(), rows = attribution.filter((a) => { const k = `${a.ViaType}${a.ViaID}${a.ActorID}`; if (seen.has(k)) return false; seen.add(k); return true; });
    const step = (color, title, sub, href) => `<li><span class="dot" style="background:var(${color})" aria-hidden="true"></span><span>${href ? `<a href="${href}"><b>${esc(title)}</b></a>` : `<b>${esc(title)}</b>`}<small>${sub}</small></span></li>`;
    const first = step('--n-ioc', 'Bu gösterge', `${esc(TL.TYPE_LABEL[i.TypeCode] || i.TypeCode)} · ${esc(TL.sourceShort(i.SourceName))}`);
    if (!rows.length) return `<ol class="pk-chain" aria-label="Atıf zinciri">${first}<li><span class="dot" style="background:var(--line-strong)" aria-hidden="true"></span><span><b class="faint">Ailesi belirlenmemiş</b><small>Bir zararlı yazılım ya da kampanyayla ilişkilendirilmemiş</small></span></li></ol>`;
    const via = new Map(); rows.forEach((a) => { const k = `${a.ViaType}:${a.ViaID}`; if (!via.has(k)) via.set(k, { ...a, actors: [] }); if (a.ActorID) via.get(k).actors.push(a); });
    return [...via.values()].slice(0, 3).map((v) => `<ol class="pk-chain" aria-label="Atıf zinciri: ${esc(v.ViaName)}">${first}
      ${step(v.ViaType === 'malware' ? '--n-malware' : '--n-campaign', v.ViaName, `${v.ViaType === 'malware' ? 'Zararlı yazılım' : 'Kampanya'} · kanıt: ${esc(v.EvidenceSource || 'kaynak belirtilmemiş')}`, TL.entityUrl(v.ViaType, v.ViaID))}
      ${v.actors.length ? step('--n-actor', v.actors.map((x) => x.ActorName).join(', '), `Tehdit aktörü · ${esc(v.actors[0].ActorEvidenceSource || 'MITRE ATT&CK')}`, TL.entityUrl('actor', v.actors[0].ActorID))
        : `<li><span class="dot" style="background:var(--line-strong)" aria-hidden="true"></span><span><b class="faint">Aktör bilinmiyor</b><small>Bu aileyi kullanan aktör kaydı yok</small></span></li>`}</ol>`).join('');
  };
  const riskBox = (i, r) => {
    if (!r) return '';
    const [, band] = TL.riskBand(r.Score), sevW = r.SeverityWeight, k = r.ReliabilityFactor * r.FreshnessFactor * r.StatusFactor, w = (x) => Math.max(0, (x * k)).toFixed(2);
    return `<section aria-labelledby="pkRisk"><h3 id="pkRisk">Risk puanı</h3>
      <div class="pk-score"><b>${r.Score}</b><span>/ 100 · ${esc(band)} bant</span></div>
      <div class="pk-stack" role="img" aria-label="Bileşenler: güven ${num(r.ConfidencePart)}, önem ${num(r.SeverityPart)}, kurumda görülme ${num(r.SightingPart)}">
        <i style="width:${w(r.ConfidencePart)}%;background:var(--accent)"></i><i style="width:${w(r.SeverityPart)}%;background:color-mix(in srgb, var(--accent) 50%, transparent)"></i><i style="width:${w(r.SightingPart)}%;background:var(--text-3)"></i></div>
      <div class="pk-legend">
        <i style="background:var(--accent)"></i><span>Güven ${i.Confidence} × 0,45</span><b>${num(r.ConfidencePart)}</b>
        <i style="background:color-mix(in srgb, var(--accent) 50%, transparent)"></i><span>Önem ${esc(TL.SEV[i.SeverityCode] || i.SeverityCode)} ${sevW} × 0,35</span><b>${num(r.SeverityPart)}</b>
        <i style="background:var(--text-3)"></i><span>Kurumda görülme ${fmtN(i.SightingCount || 0)} × 2 (en çok 20)</span><b>${num(r.SightingPart)}</b>
        <span class="eq">× kaynak ${esc(i.Reliability)} ${num(r.ReliabilityFactor, 2)} · tazelik ${num(r.FreshnessFactor, 2)}${r.StatusFactor < 1 ? ` · durum ${num(r.StatusFactor, 2)}` : ''} = <b>${r.Score}</b><span class="tech"> · fn_RiskBreakdown</span></span>
      </div></section>`;
  };

  async function show(id, _tr, opts = {}) {
    st.selected = id; qs.set({ id }); markRow(tbl, id);
    if (!opts.keepFocus) panel(split, panelHead('IOC detayı') + loading());
    try {
      const [d, rel] = await Promise.all([api(`/api/iocs/${id}`), api(`/api/iocs/${id}/relationships`)]);
      if (String(st.selected) !== String(id)) return;              // bu arada başka satır seçildi
      const i = d.indicator, tech = rel.malwareTechniques, techSeen = new Map();
      tech.forEach((t) => { if (!techSeen.has(t.ExternalID)) techSeen.set(t.ExternalID, t); });
      const techs = [...techSeen.values()];
      panel(split, `<div class="panel-head"><span class="pk-kind"><i data-lucide="hash" aria-hidden="true"></i>IOC · ${esc(TL.TYPE_LABEL[i.TypeCode] || i.TypeCode)}</span>
          <button type="button" class="btn icon ghost" data-close aria-label="Paneli kapat" title="Kapat (Esc)"><i data-lucide="x"></i></button></div>
        <section aria-label="Gösterge"><h2 class="pk-val">${esc(i.Value)}</h2>
          <div class="pk-tags">${sev(i.SeverityCode)}<span class="badge" title="Kaynak ve güvenilirlik derecesi">${esc(TL.sourceShort(i.SourceName))} · ${esc(i.Reliability)}</span><span class="badge">Güven ${i.Confidence}</span>${i.Status !== 'active' ? status(i.Status) : ''}</div></section>
        ${riskBox(i, d.risk)}
        <section aria-labelledby="pkChain"><h3 id="pkChain">Atıf zinciri</h3>${chainList(i, rel.attribution)}</section>
        <section class="pk-more" aria-labelledby="pkKv"><h3 id="pkKv">Ayrıntılar</h3><dl class="kv">
          <dt>Son görülme</dt><dd title="${fmtDT(i.LastSeen)}">${ago(i.LastSeen)}</dd><dt>İlk görülme</dt><dd>${fmtDT(i.FirstSeen)}</dd>
          ${i.ExpiresAt ? `<dt>Geçerlilik sonu</dt><dd>${fmtDT(i.ExpiresAt)}</dd>` : ''}
          <dt>Kurumda görülme</dt><dd>${i.SightingCount ? `${fmtN(i.SightingCount)} kez` : '<span class="faint">Görülmedi</span>'}</dd>
          <dt>İlişkili kayıt</dt><dd>${fmtN(rel.attribution.length)} atıf · ${fmtN(d.related.length)} benzer gösterge</dd>
          <dt>Durum</dt><dd>${status(i.Status)}</dd><dt>TLP</dt><dd>${esc(i.TLPCode)}</dd>
          ${i.Tags.length ? `<dt>Etiketler</dt><dd><div class="chips">${i.Tags.map((t) => `<a class="chip" href="/iocs?tag=${encodeURIComponent(t)}">${esc(t)}</a>`).join('')}</div></dd>` : ''}
        </dl></section>
        <section class="pk-more" aria-labelledby="pkTech"><h3 id="pkTech">Teknikler${techs.length ? ` (${techs.length})` : ''}</h3>
          ${techs.length ? `<div class="pk-tech">${techs.slice(0, 5).map((t) => `<a class="chip" href="/attack?id=${t.TechniqueID || ''}" title="${esc(t.ExternalID)} ${esc(t.Technique)} (${esc(t.Malware)} üzerinden)"><span class="mono">${esc(t.ExternalID)}</span>${esc(TL.midTruncate(t.Technique, 16, 0))}</a>`).join('')}${techs.length > 5 ? `<a class="chip" href="/iocs/${i.IndicatorID}">+${techs.length - 5}</a>` : ''}</div>`
            : '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>'}</section>
        <div class="panel-foot"><a class="btn" href="${TL.graphUrl('indicator', i.IndicatorID)}"><i data-lucide="share-2"></i>Grafta aç</a>
          ${can('analyst') ? `<button type="button" class="btn" data-add-case><i data-lucide="briefcase"></i>Vakaya ekle</button>` : ''}
          <a class="btn icon" href="/iocs/${i.IndicatorID}" aria-label="Kayda git: tam sayfa" title="Kayda git"><i data-lucide="arrow-up-right"></i></a></div>`);
      split.querySelector('[data-add-case]')?.addEventListener('click', () => TL.addToCase('indicator', [i.IndicatorID], i.Value));
    } catch (e) { const p = panel(split, panelHead('IOC detayı') + '<div class="panel-err"></div>'); TL.failed(p.querySelector('.panel-err'), e, () => show(id)); }
  }

  TL.onPanelClose = () => { st.selected = null; qs.set({ id: null }); markRow(tbl, -1); };
  // Dışa aktarma: ekrandaki filtrelerle (sayfa/sıralama hariç)
  document.getElementById('exportMenu')?.addEventListener('click', (e) => {
    const a = e.target.closest('[data-export]'); if (!a) return;
    e.preventDefault();
    const q = new URLSearchParams({ format: a.dataset.export });
    Object.entries(filters()).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
    location.href = `/api/iocs/export?${q}`;
  });
  bindTable(tbl, { onRow: show, href: (id) => `/iocs/${id}`, onSort: (s) => { st.dir = st.sort === s && st.dir === 'desc' ? 'asc' : 'desc'; st.sort = s; st.page = 1; TL.onSortSync?.(); load(); } });

  // ---------- toplu kontrol ----------
  document.getElementById('lookupBtn').addEventListener('click', () => {
    const d = dialog(`<form><div class="dlg-head"><h2>Toplu IOC kontrolü</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="field"><label for="lk">Her satıra bir değer yapıştırın ya da metin dosyasını buraya bırakın (en çok 2000 değer)</label>
        <textarea class="input mono drop-text" id="lk" rows="8" spellcheck="false" placeholder="185.220.101.4&#10;hxxp://evil[.]example/a&#10;44d88612fea8a8f36de82e1278abb02f"></textarea>
        <small class="faint" id="lkCount" aria-live="polite">Henüz değer yok</small></div>
      <div id="lkOut"></div><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Kapat</button><button class="btn primary" type="submit"><i data-lucide="list-checks"></i>Kontrol et</button></div></form>`, { wide: true });
    const ta = d.querySelector('#lk'), cnt = d.querySelector('#lkCount');
    const values = () => [...new Set(ta.value.split(/\r?\n|\t/).map((v) => v.trim()).filter(Boolean))];
    const count = TL.debounce(() => { const v = values(); cnt.textContent = TL.countTypes(v) + (v.length > 2000 ? ' · ilk 2000 değer kontrol edilir' : ''); }, 150);
    ta.addEventListener('input', count);
    TL.dropText(ta, (f) => toast(`${f.name} yüklendi.`));
    d.querySelector('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const v = values().slice(0, 2000); if (!v.length) { ta.focus(); return; }
      const out = d.querySelector('#lkOut'); out.innerHTML = loading('Kontrol ediliyor');
      try {
        const r = await api('/api/iocs/lookup', { method: 'POST', body: { values: v } });
        const rows = [...r.matches].sort((a, b) => b.RiskScore - a.RiskScore);
        out.innerHTML = `<p class="notice"><i data-lucide="info"></i><span>${fmtN(r.asked)} değerden <b>${fmtN(rows.length)}</b> tanesi kayıtlı, ${fmtN(r.unknown.length)} tanesi bilinmiyor. Sonuçlar risk skoruna göre sıralı.</span></p>
          ${rows.length ? table([{ label: 'Değer', primary: true, render: (m) => TL.iocCell(m.Value, { href: `/iocs/${m.IndicatorID}` }) }, { label: 'Tip', render: (m) => typeBadge(m.TypeCode) },
            { label: 'Önem', render: (m) => sev(m.SeverityCode) }, { label: 'Risk', num: true, render: (m) => `<b>${m.RiskScore}</b>` }, { label: 'Durum', priority: 2, render: (m) => status(m.Status) },
            { label: 'Kaynak', priority: 3, render: (m) => sourceBadge(m.SourceName) }], rows, { caption: 'Kayıtlı değerler' }) : ''}
          ${r.unknown.length ? `<details class="unknown-list"><summary>Bilinmeyen ${fmtN(r.unknown.length)} değer</summary><p class="mono">${r.unknown.map(esc).join('<br>')}</p></details>` : ''}`;
        icons();
      } catch (err) { TL.failed(out, err, () => d.querySelector('form').requestSubmit()); }
    });
  });

  document.addEventListener('DOMContentLoaded', async () => {
    const newBtn = document.getElementById('newBtn');
    if (can('analyst')) { newBtn.hidden = false; newBtn.addEventListener('click', () => TL.iocForm(null, (r) => { location.href = `/iocs/${r.IndicatorID}`; })); }
    sel = TL.selection(tbl, renderBar);
    try {
      const m = await TL.meta();
      TL.facetOptions(document.getElementById('type'), m.types.map((t) => ({ value: t.Code, label: TL.TYPE_LABEL[t.Code] || t.Name })));
      TL.facetOptions(document.getElementById('source'), m.iocSources.map((s) => ({ value: s.SourceID, label: TL.sourceShort(s.Name), hint: s.Name })));
    } catch (e) { toast(e.message, 'err'); }
    fb = TL.filterBar(form, {
      onChange: () => { st.page = 1; sel.clear(); load(); },
      counts: '/api/iocs/facets',
      dates: [{ from: 'dateFrom', to: 'dateTo', hours: 'hours', label: 'Son görülme' }],
      // Kayıtlı görünümler (B · Dosya): sayılar sunucudan; genel bakıştaki "Dikkat gerektirenler" bunlara bağlanır
      views: { endpoint: '/api/iocs/views', items: [
        { key: 'all', label: 'Tümü', params: {} },
        { key: 'high24h', label: 'Son 24 saat · yüksek önem', params: { severity: 'high,critical', status: 'active', hours: '24' }, hint: 'Son 24 saatte görülen, önemi yüksek ya da kritik aktif IOC\'ler' },
        { key: 'sighted', label: 'Kurumda görülen', params: { sighted: 'true' }, hint: 'Kurum içinde en az bir görülme kaydı olan IOC\'ler' },
        { key: 'expiring', label: 'Süresi dolacak (7 gün)', params: { expiring: '7' }, hint: 'Geçerlilik süresi önümüzdeki 7 gün içinde dolacak aktif IOC\'ler' }] },
    });
    // Sırala menüsü: sütun başlıklarıyla aynı durum (st.sort, st.dir)
    const sortIn = document.getElementById('iocSort');
    const syncSort = () => { sortIn.value = `${st.sort}:${st.dir}`; sortIn._facet?.render(); };
    TL.facet(sortIn); syncSort();
    sortIn.addEventListener('change', () => { const [s2, d2] = sortIn.value.split(':'); st.sort = s2; st.dir = d2 || 'desc'; st.page = 1; load(); });
    TL.onSortSync = syncSort;
    const mw = document.getElementById('malware');
    if (mw.value) api(`/api/malware/${mw.value}`).then((r) => { mw.dataset.text = r.malware.IsPlaceholder ? 'Ailesi belirlenmemiş' : r.malware.Name; fb.render(); }).catch(() => {});
    await load();
    if (st.selected) show(st.selected);
  });
})();
