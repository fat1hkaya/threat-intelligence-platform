/* IOC araştırma listesi: /api/iocs */
(() => {
  const { api, esc, fmtDT, ago, sev, typeBadge, conf, sourceBadge, copyBtn, status, table, bindTable, markRow, pager, panel, panelHead, toast, empty, loading, icons, qs, can, dialog, kvRow } = TL;
  const FIELDS = ['q', 'type', 'severity', 'source', 'status', 'minConfidence', 'maxConfidence', 'dateFrom', 'dateTo'];
  const st = { page: +(qs.get('page') || 1), size: 25, sort: qs.get('sort') || 'lastSeen', dir: qs.get('dir') || 'desc', malware: qs.get('malware'), tag: qs.get('tag'), selected: qs.get('id') };
  const split = document.getElementById('split'), tbl = document.getElementById('tbl'), form = document.getElementById('filters');

  const cols = [
    { label: 'Gösterge', sort: 'value', primary: true, render: (r) => `<span class="cell-ioc"><span class="mono value" title="${esc(r.Value)}">${esc(r.Value)}</span>${copyBtn(r.Value)}</span>` },
    { label: 'Tip', sort: 'type', render: (r) => typeBadge(r.TypeCode) },
    { label: 'Önem', sort: 'severity', render: (r) => sev(r.SeverityCode) },
    { label: 'Güven', sort: 'confidence', render: (r) => conf(r.Confidence) },
    { label: 'Zararlı ailesi', render: (r) => r.MalwareName ? esc(r.MalwareName) : '<span class="faint">—</span>' },
    { label: 'Kaynak', sort: 'source', render: (r) => sourceBadge(r.SourceName) },
    { label: 'İlk görülme', sort: 'firstSeen', render: (r) => `<span class="muted">${fmtDT(r.FirstSeen)}</span>` },
    { label: 'Son görülme', sort: 'lastSeen', render: (r) => `<span title="${fmtDT(r.LastSeen)}">${ago(r.LastSeen)}</span>` },
    { label: 'İşlemler', render: (r) => `<a class="btn sm icon ghost" href="/iocs/${r.IndicatorID}" aria-label="Detay sayfası" title="Detay sayfası"><i data-lucide="external-link"></i></a>
        <a class="btn sm icon ghost" href="${TL.graphUrl('indicator', r.IndicatorID)}" aria-label="İlişki grafında aç" title="İlişki grafında aç"><i data-lucide="share-2"></i></a>` },
  ];

  const params = () => { const f = TL.formData(form); const p = { page: st.page, size: st.size, sort: st.sort, dir: st.dir, malware: st.malware, tag: st.tag };
    FIELDS.forEach((k) => { if (f[k]) p[k] = f[k]; }); return p; };

  async function load() {
    tbl.innerHTML = loading();
    const p = params(); qs.set({ ...p, size: null, id: st.selected });
    try {
      const d = await api('/api/iocs', { params: p });
      tbl.innerHTML = d.items.length ? table(cols, d.items, { rowId: (r) => r.IndicatorID, selected: st.selected, sort: st.sort, dir: st.dir, caption: 'IOC listesi' })
        : empty('Bu filtrelere uyan IOC yok. Filtreleri gevşetin veya başka bir değer arayın.');
      pager(document.getElementById('pager'), d, (n) => { st.page = n; load(); }, 'IOC');
      icons();
    } catch (e) { tbl.innerHTML = empty(e.message, 'circle-alert'); }
  }

  async function show(id) {
    st.selected = id; qs.set({ id }); markRow(tbl, id);
    panel(split, panelHead('IOC detayı') + loading());
    try {
      const [d, rel] = await Promise.all([api(`/api/iocs/${id}`), api(`/api/iocs/${id}/relationships`)]);
      const i = d.indicator;
      panel(split, `${panelHead('IOC detayı')}
        <section><div class="entity-title">${TL.nodeIcon('indicator')}<div style="min-width:0"><h2 class="mono" style="font-size:14px">${esc(i.Value)}</h2>
          <div class="chips" style="margin-top:6px">${typeBadge(i.TypeCode)}${sev(i.SeverityCode)}${status(i.Status)}</div></div></div>
          <div class="chips">${copyBtn(i.Value).replace('btn sm icon ghost', 'btn sm').replace('</i>', '</i>Kopyala')}
            <a class="btn sm" href="/iocs/${i.IndicatorID}"><i data-lucide="file-text"></i>Detay sayfası</a>
            <a class="btn sm" href="${TL.graphUrl('indicator', i.IndicatorID)}"><i data-lucide="share-2"></i>Grafta aç</a></div></section>
        <section><dl class="kv">
          <dt>Güven skoru</dt><dd>${conf(i.Confidence)}</dd><dt>Risk skoru</dt><dd>${i.RiskScore} / 100</dd>
          <dt>Kaynak</dt><dd>${sourceBadge(i.SourceName)} <span class="faint">(güvenilirlik ${esc(i.Reliability)})</span></dd>
          <dt>İlk görülme</dt><dd>${fmtDT(i.FirstSeen)}</dd><dt>Son görülme</dt><dd>${fmtDT(i.LastSeen)}</dd>
          <dt>Görülme</dt><dd>${i.SightingCount} kez (kurum içi)</dd><dt>TLP</dt><dd>${esc(i.TLPCode)}</dd>
          ${i.Tags.length ? `<dt>Etiketler</dt><dd><div class="chips">${i.Tags.map((t) => `<a class="chip" href="/iocs?tag=${encodeURIComponent(t)}">${esc(t)}</a>`).join('')}</div></dd>` : ''}
        </dl></section>
        <section><h3><i data-lucide="git-branch"></i>Atıf zinciri</h3>${TL.chains(i, rel.attribution)}</section>
        <section><h3><i data-lucide="grid-3x3"></i>İlişkili ATT&amp;CK teknikleri</h3>
          ${rel.malwareTechniques.length ? `<div class="chips">${rel.malwareTechniques.slice(0, 14).map((t) => `<span class="chip" title="${esc(t.Technique)} (${esc(t.Malware)})"><span class="mono">${esc(t.ExternalID)}</span></span>`).join('')}</div>
            <p class="faint" style="font-size:12px">${rel.malwareTechniques.length} teknik <span class="tech">· IOC → zararlı → teknik MATCH deseni</span></p>` : '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>'}</section>`);
    } catch (e) { panel(split, panelHead('IOC detayı') + empty(e.message, 'circle-alert')); }
  }

  TL.onPanelClose = () => { st.selected = null; qs.set({ id: null }); markRow(tbl, -1); };
  // Dışa aktarma: ekrandaki filtrelerle (sayfa/sıralama hariç)
  document.getElementById('exportMenu')?.addEventListener('click', (e) => {
    const a = e.target.closest('[data-export]'); if (!a) return;
    e.preventDefault();
    const { page, size, sort, dir, ...f } = params();
    const q = new URLSearchParams({ format: a.dataset.export });
    Object.entries(f).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') q.set(k, v); });
    location.href = `/api/iocs/export?${q}`;
  });
  bindTable(tbl, { onRow: show, onSort: (s) => { st.dir = st.sort === s && st.dir === 'desc' ? 'asc' : 'desc'; st.sort = s; st.page = 1; load(); } });
  form.addEventListener('submit', (e) => { e.preventDefault(); st.page = 1; load(); });
  form.addEventListener('reset', () => setTimeout(() => { st.page = 1; st.malware = null; st.tag = null; load(); }));
  form.querySelectorAll('select').forEach((s) => s.addEventListener('change', () => { st.page = 1; load(); }));

  document.getElementById('lookupBtn').addEventListener('click', () => {
    const d = dialog(`<form><div class="dlg-head"><h2>Toplu IOC kontrolü</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="field"><label for="lk">Her satıra bir değer yapıştırın (en çok 2000)</label><textarea class="input mono" id="lk" rows="8" placeholder="185.220.101.4&#10;hxxp://evil[.]example/a&#10;..."></textarea></div>
      <div id="lkOut"></div><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Kapat</button><button class="btn primary" type="submit">Kontrol et</button></div></form>`, { wide: true });
    d.querySelector('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const values = d.querySelector('#lk').value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
      if (!values.length) return;
      try {
        const r = await api('/api/iocs/lookup', { method: 'POST', body: { values } });
        d.querySelector('#lkOut').innerHTML = `<p class="notice"><i data-lucide="info"></i>${r.asked} değerden ${r.matches.length} tanesi kayıtlı, ${r.unknown.length} tanesi bilinmiyor.</p>
          ${r.matches.length ? table([{ label: 'Değer', primary: true, render: (m) => `<a class="mono" href="/iocs/${m.IndicatorID}">${esc(m.Value)}</a>` }, { label: 'Tip', render: (m) => typeBadge(m.TypeCode) },
            { label: 'Önem', render: (m) => sev(m.SeverityCode) }, { label: 'Risk', num: true, render: (m) => m.RiskScore }, { label: 'Kaynak', render: (m) => sourceBadge(m.SourceName) }], r.matches) : ''}
          ${r.unknown.length ? `<p class="faint" style="font-size: 13px">Bilinmeyenler: <span class="mono">${r.unknown.map(esc).join(', ')}</span></p>` : ''}`;
        icons();
      } catch (err) { toast(err.message, 'err'); }
    });
  });

  document.addEventListener('DOMContentLoaded', async () => {
    const newBtn = document.getElementById('newBtn');
    if (can('analyst')) { newBtn.hidden = false; newBtn.addEventListener('click', () => TL.iocForm(null, (r) => { location.href = `/iocs/${r.IndicatorID}`; })); }
    const m = await TL.meta();
    document.getElementById('type').insertAdjacentHTML('beforeend', m.types.map((t) => `<option value="${t.Code}">${esc(t.Name)}</option>`).join(''));
    document.getElementById('source').insertAdjacentHTML('beforeend', m.sources.map((s) => `<option value="${s.SourceID}">${esc(s.Name)}</option>`).join(''));
    FIELDS.forEach((k) => { const v = qs.get(k); if (v && form.elements[k]) form.elements[k].value = v; });
    await load();
    if (st.selected) show(st.selected);
  });
})();
