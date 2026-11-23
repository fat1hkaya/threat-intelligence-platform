/* IOC araştırma listesi: /api/iocs */
(() => {
  const { api, esc, fmtDT, fmtN, ago, sev, typeBadge, conf, sourceBadge, copyBtn, status, table, bindTable, markRow, pager, panel, panelHead, toast, empty, loading, icons, qs, can, dialog } = TL;
  const KEY = 'iocs';
  const st = { page: +(qs.get('page') || 1), size: TL.pageSize(KEY), sort: qs.get('sort') || 'lastSeen', dir: qs.get('dir') || 'desc', selected: qs.get('id'), last: null };
  const split = document.getElementById('split'), tbl = document.getElementById('tbl'), form = document.getElementById('filters'), bar = document.getElementById('tblBar');
  let fb = null, sel = null;

  const cols = [
    { id: 'value', label: 'Gösterge', sort: 'value', primary: true, render: (r) => TL.iocCell(r.Value) },
    { id: 'type', label: 'Tip', sort: 'type', render: (r) => typeBadge(r.TypeCode) },
    { id: 'severity', label: 'Önem', sort: 'severity', render: (r) => sev(r.SeverityCode) },
    { id: 'confidence', label: 'Güven', sort: 'confidence', render: (r) => conf(r.Confidence) },
    { id: 'malware', label: 'Zararlı ailesi', priority: 2, render: (r) => r.MalwareName ? `<span class="trunc">${esc(r.MalwareName)}</span>` : '<span class="faint">—</span>' },
    { id: 'source', label: 'Kaynak', sort: 'source', priority: 2, render: (r) => sourceBadge(r.SourceName) },
    { id: 'firstSeen', label: 'İlk görülme', sort: 'firstSeen', priority: 3, render: (r) => `<span class="muted nowrap" title="${fmtDT(r.FirstSeen)}">${ago(r.FirstSeen)}</span>` },
    { id: 'lastSeen', label: 'Son görülme', sort: 'lastSeen', render: (r) => `<span class="nowrap" title="${fmtDT(r.LastSeen)}">${ago(r.LastSeen)}</span>` },
    { id: 'actions', label: 'İşlemler', cls: 'actions', render: (r) => `<a class="btn sm icon ghost" href="/iocs/${r.IndicatorID}" aria-label="Detay sayfası: ${esc(r.Value)}" title="Detay sayfası"><i data-lucide="external-link"></i></a>
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
    total: st.last ? st.last.total : 0, unit: 'sonuç', size: st.size, key: KEY, columns: cols, onCols: render,
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

  async function show(id) {
    st.selected = id; qs.set({ id }); markRow(tbl, id);
    panel(split, panelHead('IOC detayı') + loading());
    try {
      const [d, rel] = await Promise.all([api(`/api/iocs/${id}`), api(`/api/iocs/${id}/relationships`)]);
      const i = d.indicator;
      panel(split, `${panelHead('IOC detayı')}
        <section><div class="entity-title">${TL.nodeIcon('indicator')}<div style="min-width:0"><h2 class="mono ioc-title">${esc(i.Value)}</h2>
          <div class="chips" style="margin-top:6px">${typeBadge(i.TypeCode)}${sev(i.SeverityCode)}${status(i.Status)}</div></div></div>
          ${TL.actions([`<a class="btn sm primary" href="${TL.graphUrl('indicator', i.IndicatorID)}"><i data-lucide="share-2"></i>İlişki grafı</a>`,
            copyBtn(i.Value).replace('btn sm icon ghost copy', 'btn sm copy').replace('</i>', '</i>Kopyala')],
            [TL.caseBtn('indicator', i.IndicatorID, i.Value, 'btn')])}</section>
        <section><dl class="kv">
          <dt>Güven skoru</dt><dd>${conf(i.Confidence)}</dd><dt>Risk skoru</dt><dd>${i.RiskScore} / 100</dd>
          <dt>Kaynak</dt><dd>${sourceBadge(i.SourceName)} <span class="faint">(güvenilirlik ${esc(i.Reliability)})</span></dd>
          <dt>İlk görülme</dt><dd>${fmtDT(i.FirstSeen)}</dd><dt>Son görülme</dt><dd>${fmtDT(i.LastSeen)}</dd>
          <dt>Görülme</dt><dd>${i.SightingCount ? `${fmtN(i.SightingCount)} kez (kurum içi)` : '<span class="faint">Kurum içinde görülmedi</span>'}</dd><dt>TLP</dt><dd>${esc(i.TLPCode)}</dd>
          ${i.Tags.length ? `<dt>Etiketler</dt><dd><div class="chips">${i.Tags.map((t) => `<a class="chip" href="/iocs?tag=${encodeURIComponent(t)}">${esc(t)}</a>`).join('')}</div></dd>` : ''}
        </dl></section>
        <section><h3><i data-lucide="git-branch"></i>Atıf zinciri</h3>${TL.chains(i, rel.attribution)}</section>
        <section><h3><i data-lucide="grid-3x3"></i>İlişkili ATT&amp;CK teknikleri</h3>
          ${rel.malwareTechniques.length ? `<div class="chips">${rel.malwareTechniques.slice(0, 14).map((t) => `<span class="chip" title="${esc(t.ExternalID)} ${esc(t.Technique)} (${esc(t.Malware)})" aria-label="${esc(t.ExternalID)} ${esc(t.Technique)}"><span class="mono">${esc(t.ExternalID)}</span></span>`).join('')}</div>
            <p class="faint" style="font-size:12px">${rel.malwareTechniques.length} teknik<span class="tech"> · IOC → zararlı → teknik MATCH deseni</span></p>` : '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>'}</section>
        <div class="panel-foot"><a class="btn" href="/iocs/${i.IndicatorID}"><i data-lucide="maximize-2"></i>Tam sayfada aç</a></div>`);
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
  bindTable(tbl, { onRow: show, onSort: (s) => { st.dir = st.sort === s && st.dir === 'desc' ? 'asc' : 'desc'; st.sort = s; st.page = 1; load(); } });

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
      document.getElementById('type').insertAdjacentHTML('beforeend', m.types.map((t) => `<option value="${t.Code}">${esc(t.Name)}</option>`).join(''));
      document.getElementById('source').insertAdjacentHTML('beforeend', m.sources.map((s) => `<option value="${s.SourceID}">${esc(s.Name)}</option>`).join(''));
    } catch (e) { toast(e.message, 'err'); }
    fb = TL.filterBar(form, { onChange: () => { st.page = 1; sel.clear(); load(); } });
    const mw = document.getElementById('malware');
    if (mw.value) api(`/api/malware/${mw.value}`).then((r) => { mw.dataset.text = r.malware.IsPlaceholder ? 'Ailesi belirlenmemiş' : r.malware.Name; fb.render(); }).catch(() => {});
    await load();
    if (st.selected) show(st.selected);
  });
})();
