/* Veri kaynakları: /api/sources, /api/imports */
(() => {
  const { api, esc, fmtN, fmtDT, ago, job, table, bindTable, pager, empty, loading, icons, toast, can, dialog, qs, sourceBadge } = TL;
  const REL = { A: 'A · tamamen güvenilir', B: 'B · genelde güvenilir', C: 'C · oldukça güvenilir', D: 'D · genelde güvenilmez', E: 'E · güvenilmez', F: 'F · değerlendirilemez' };
  const TYPE = { feed: 'Besleme', file: 'Dosya', attack: 'ATT&CK' };
  const st = { page: 1, running: new Set() };
  const cnt = (n, cls = '') => n ? `<span class="${cls}">${fmtN(n)}</span>` : '<span class="zero" title="0">—</span>';

  async function loadSources() {
    const d = await api('/api/sources'); const t = d.totals;
    document.getElementById('kpis').innerHTML = [
      ['database', '', 'Kaynak', fmtN(t.Sources), t.ActiveSources === t.Sources ? 'Hepsi etkin' : `${fmtN(t.ActiveSources)} etkin · ${fmtN(t.Sources - t.ActiveSources)} devre dışı`],
      ['calendar-clock', 'c', 'Son içe aktarma', t.LastJobAt ? ago(t.LastJobAt) : '—', t.LastJobAt ? fmtDT(t.LastJobAt) : 'Henüz iş yok'],
      ['circle-check', '', 'Başarılı işler (7 gün)', fmtN(t.Success7d), `${fmtN(t.Jobs7d)} işten`],
      ['triangle-alert', 'r', 'Sorunlu işler (7 gün)', fmtN(t.Problem7d), 'Kısmi veya hatalı'],
    ].map(([i, c, l, v, s]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="val">${v}</div><div class="lbl">${l}</div><div class="sub">${s}</div></div></article>`).join('');
    document.getElementById('keyNotice').hidden = d.abusechKey;
    const writer = can('analyst'), admin = can('admin');
    st.sources = d.sources;
    document.getElementById('srcTbl').innerHTML = table([
      { label: 'Kaynak', primary: true, render: (s) => `<span class="src-cell"><b${s.Url ? ` title="${esc(s.Url)}"` : ''}>${esc(s.Name)}</b>${s.Url ? `<a class="btn sm icon ghost" href="${esc(s.Url)}" target="_blank" rel="noopener noreferrer" aria-label="${esc(s.Name)} sitesini aç" title="${esc(s.Url)}"><i data-lucide="external-link"></i></a>` : ''}${s.IsActive ? '' : '<span class="badge b-muted">Kapalı</span>'}</span>` },
      { label: 'Güvenilirlik', priority: 2, render: (s) => `<span class="badge b-muted" title="${esc(REL[s.Reliability])}">${esc(s.Reliability)}</span>` },
      { label: 'Kayıt', num: true, render: (s) => `<span class="nowrap" ${s.UnitDetail ? `title="${esc(s.UnitDetail)}"` : ''}>${fmtN(s.UnitCount || 0)} <span class="faint">${esc(s.UnitLabel || 'IOC')}</span></span>` },
      { label: 'Son iş', render: (s) => st.running.has(s.Feed) ? '<span class="nowrap"><span class="spinner" aria-hidden="true"></span> Senkronize ediliyor…</span>'
        : s.LastRunAt ? `<span class="nowrap">${job(s.LastRunStatus)} <span class="muted" style="font-size:12px" title="${fmtDT(s.LastRunAt)}">${ago(s.LastRunAt)}</span></span>` : '<span class="faint">Henüz yok</span>' },
      // Son işin sonucu ayrı sütunlarda; birim kaynağın kendi birimi (IOC, zafiyet, teknik, IP aralığı)
      { label: 'Yeni', num: true, render: (s) => s.LastRunAt ? cnt(s.LastRowsInserted) : '<span class="faint">—</span>' },
      { label: 'Güncellenen', num: true, priority: 2, render: (s) => s.LastRunAt ? cnt(s.LastRowsUpdated) : '<span class="faint">—</span>' },
      { label: 'Hatalı', num: true, render: (s) => s.LastRunAt ? cnt(s.LastRowsFailed, 'delta-down') : '<span class="faint">—</span>' },
      { label: 'İşlemler', cls: 'actions', render: (s) => {
        const allowed = s.Feed === 'attack' ? admin : writer;
        const why = !s.Feed ? 'Bu kaynak elle ya da dosyayla beslenir' : !s.IsActive ? 'Kaynak devre dışı' : !s.Ready ? 'ABUSECH_AUTH_KEY gerekli' : !allowed ? 'Yetkiniz yok' : 'Şimdi senkronize et';
        const can_ = s.Feed && s.Ready && allowed && !st.running.has(s.Feed);
        const menu = [s.LastJobID ? `<button type="button" class="btn" role="menuitem" data-job="${s.LastJobID}"><i data-lucide="file-text"></i>Son işin günlüğü</button>` : '',
          `<button type="button" class="btn" role="menuitem" data-jobs-of="${s.SourceID}"><i data-lucide="list"></i>Bu kaynağın işleri</button>`,
          admin ? `<button type="button" class="btn" role="menuitem" data-toggle="${s.SourceID}" data-on="${s.IsActive ? 0 : 1}"><i data-lucide="${s.IsActive ? 'power-off' : 'power'}"></i>${s.IsActive ? 'Kaynağı devre dışı bırak' : 'Kaynağı etkinleştir'}</button>` : ''].join('');
        return `<button type="button" class="btn sm icon ghost" data-feed="${s.Feed || ''}" ${can_ ? '' : 'disabled'} aria-label="${esc(why)}: ${esc(s.Name)}" title="${esc(why)}"><i data-lucide="refresh-cw"></i></button>
          <details class="more-menu row-menu"><summary class="btn sm icon ghost" aria-label="${esc(s.Name)}: diğer eylemler" title="Diğer eylemler"><i data-lucide="ellipsis"></i></summary><div class="menu-pop" role="menu">${menu}</div></details>`; } },
    ], d.sources, { caption: 'Kaynaklar' });
    TL.facetOptions(document.getElementById('jSrc'), d.sources.filter((s) => s.LastJobID).map((s) => ({ value: s.SourceID, label: TL.sourceShort(s.Name), hint: s.Name })));
    icons();
  }

  async function loadJobs() {
    const box = document.getElementById('jobTbl'); box.innerHTML = loading();
    const d = await api('/api/imports', { params: { page: st.page, source: document.getElementById('jSrc').value, status: document.getElementById('jStatus').value, changed: document.getElementById('jChanged').checked } });
    box.innerHTML = d.items.length ? table([
      { label: 'İş', primary: true, render: (j) => `<b class="mono">#${j.JobID}</b>` },
      { label: 'Kaynak', render: (j) => `<span class="nowrap" title="${esc(j.SourceName)}${j.FileName ? ` · ${esc(j.FileName)}` : ''}">${esc(TL.sourceShort(j.SourceName))}</span>` },
      { label: 'Tür', priority: 2, render: (j) => `<span class="badge b-muted" ${j.IsStrict ? 'title="Katı mod"' : ''}>${esc(TYPE[j.JobType] || j.JobType)}</span>` },
      { label: 'Durum', render: (j) => job(j.Status) },
      { label: 'Başlangıç', render: (j) => `<span class="nowrap" title="${fmtDT(j.StartedAt)}${j.StartedBy ? ` · ${esc(j.StartedBy)}` : ''}">${ago(j.StartedAt)}</span>` },
      { label: 'Süre', num: true, priority: 2, render: (j) => j.DurationSec != null ? `<span class="nowrap">${fmtN(j.DurationSec)} sn</span>` : '—' },
      { label: 'Okunan', num: true, priority: 2, render: (j) => cnt(j.RowsRead) },
      { label: 'Yeni', num: true, render: (j) => cnt(j.RowsInserted) },
      { label: 'Güncellenen', num: true, priority: 2, render: (j) => cnt(j.RowsUpdated) },
      { label: 'Atlanan', num: true, priority: 2, render: (j) => cnt(j.RowsSkipped) },
      { label: 'Hatalı', num: true, render: (j) => j.RowsFailed ? `<b class="delta-down">${fmtN(j.RowsFailed)}</b>` : cnt(0) },
    ], d.items, { caption: 'İçe aktarma işleri', rowId: (j) => j.JobID })
      : empty(document.getElementById('jChanged').checked ? 'Değişiklik getiren ya da hatalı iş yok. Tüm işleri görmek için filtreyi kapatın.' : 'Bu filtrelere uyan iş yok.', 'inbox');
    pager(document.getElementById('jobPager'), d, (n) => { st.page = n; loadJobs(); }, 'iş');
    icons();
  }

  const resultHtml = (r) => `<div class="notice ${r.status === 'success' ? '' : 'warn'}"><i data-lucide="${r.status === 'success' ? 'circle-check' : 'triangle-alert'}"></i><div>
      <b>İş #${r.job_id ?? r.JobID}: ${job(r.status ?? r.Status)}</b><br>Okunan ${fmtN(r.read ?? r.RowsRead)}, eklenen ${fmtN(r.inserted ?? r.RowsInserted)}, güncellenen ${fmtN(r.updated ?? r.RowsUpdated)}, atlanan ${fmtN(r.skipped ?? r.RowsSkipped)}, hatalı ${fmtN(r.failed ?? r.RowsFailed)}
      ${r.rolled_back ? `<br><b>ROLLBACK:</b> ${fmtN(r.rolled_back)} satırlık değişiklik geri alındı.` : ''}${(r.message ?? r.ErrorMessage) ? `<br><span class="muted">${esc(r.message ?? r.ErrorMessage)}</span>` : ''}</div></div>`;
  const errorsHtml = (errs) => errs.length ? table([{ label: 'Satır', num: true, render: (e) => e.RowNo ?? e.row }, { label: 'Değer', render: (e) => `<span class="mono">${esc(e.RawValue ?? e.value ?? '—')}</span>` },
    { label: 'Neden', primary: true, render: (e) => esc(e.Reason ?? e.reason) }], errs, { caption: 'Hatalı satırlar' }) : '';

  function uploadDialog(sources) {
    const opts = sources.filter((x) => x.IsActive).map((x) => `<option value="${x.SourceID}" ${x.Name === 'Analist girişi' ? 'selected' : ''}>${esc(x.Name)}</option>`).join('');
    const d = dialog(`<form id="upForm"><div class="dlg-head"><h2>Dosyadan IOC içe aktar</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="muted" style="font-size:13px">CSV (başlık satırında en az <code>value</code>) ya da JSON. Satırlar normalleştirilir, doğrulanır ve tek seferde yazılır.<span class="tech"> · sp_BulkImportIndicators, tek transaction</span></p>
      <div class="field"><label for="file">Dosya</label><input id="file" name="file" type="file" accept=".csv,.json,.txt" required></div>
      <div class="field"><label for="upSrc">Kaynak</label><select class="input" id="upSrc" name="sourceId">${opts}</select></div>
      <label class="check"><input type="checkbox" name="strict" value="true"><span>Katı mod: tek hatalı satır varsa hiçbir satırı kaydetme<span class="tech"> (ROLLBACK)</span></span></label>
      <p class="faint" style="font-size: 13px">Örnek dosyalar: <a href="/static/samples/ornek_gecerli.csv" download>geçerli CSV</a>, <a href="/static/samples/ornek_hatali.csv" download>hatalı CSV</a>, <a href="/static/samples/ornek.json" download>JSON</a></p>
      <div id="upOut"></div>
      <div class="dlg-foot"><button type="button" class="btn" data-dismiss>Kapat</button><button class="btn primary" type="submit"><i data-lucide="upload"></i>İçe aktar</button></div></form>`, { wide: true });
    TL.dropzone(d.querySelector('#file'), { hint: '.csv, .json · en çok 5 MB' });
    d.querySelector('#upForm').addEventListener('submit', async (e) => {
      e.preventDefault(); const f = e.target, out = d.querySelector('#upOut');
      const fd = new FormData(); fd.append('file', f.file.files[0]); fd.append('sourceId', f.sourceId.value); fd.append('strict', f.strict.checked ? 'true' : 'false');
      out.innerHTML = loading('İçe aktarılıyor');
      try { const r = await api('/api/imports', { method: 'POST', body: fd }); out.innerHTML = resultHtml(r) + errorsHtml(r.errors); toast(`İçe aktarma işi #${r.job_id} tamamlandı.`); }
      catch (er) { out.innerHTML = `<p class="err">${esc(er.message)}</p>`; }
      icons(); loadSources(); st.page = 1; loadJobs();
    });
  }

  async function jobDetail(id) {
    const d = await api(`/api/imports/${id}`);
    dialog(`<div class="dlg"><div class="dlg-head"><h2>İçe aktarma işi #${id}</h2><button class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <dl class="kv"><dt>Kaynak</dt><dd>${esc(d.job.SourceName)}</dd><dt>Tür</dt><dd>${esc(TYPE[d.job.JobType])}${d.job.IsStrict ? ' (katı mod)' : ''}</dd>
      <dt>Dosya</dt><dd>${esc(d.job.FileName || '—')}</dd><dt>Başlatan</dt><dd>${esc(d.job.StartedByName || 'Sistem')}</dd>
      <dt>Başlangıç</dt><dd>${fmtDT(d.job.StartedAt)}</dd><dt>Bitiş</dt><dd>${fmtDT(d.job.FinishedAt)}</dd></dl>
      ${resultHtml(d.job)}<h3>Hatalı satırlar (ImportJobError)</h3>${errorsHtml(d.errors) || '<p class="faint">Hatalı satır yok.</p>'}</div>`, { wide: true });
  }

  // Senkronizasyon: satırda dönen gösterge; iş bitince satır kendiliğinden güncellenir
  async function sync(feed) {
    st.running.add(feed); await loadSources();
    try {
      await api('/api/imports/feed', { method: 'POST', body: { feed } });
      toast('Senkronizasyon arka planda başladı.');
      for (let i = 0; i < 200; i += 1) {                     // 3 sn aralıkla, en çok 10 dk
        await new Promise((r) => setTimeout(r, 3000));
        const s = await api('/api/imports/feed/status');
        if (!s.running.includes(feed)) break;
        if (i % 5 === 4) loadJobs();
      }
      toast('Senkronizasyon tamamlandı.');
    } catch (er) { toast(er.message, 'err'); }
    st.running.delete(feed); await loadSources(); st.page = 1; loadJobs();
  }

  document.addEventListener('DOMContentLoaded', async () => {
    const srcParam = qs.get('source');
    ['jSrc', 'jStatus'].forEach((id) => TL.facet(document.getElementById(id)));
    await loadSources(); if (srcParam) { document.getElementById('jSrc').value = srcParam; document.getElementById('jSrc')._facet.render(); document.getElementById('jChanged').checked = false; }
    loadJobs();
    if (can('analyst')) { const ub = document.getElementById('uploadBtn'); ub.hidden = false; ub.onclick = () => uploadDialog(st.sources || []); }
    document.getElementById('jSrc').onchange = document.getElementById('jStatus').onchange = document.getElementById('jChanged').onchange = () => { st.page = 1; loadJobs(); };
    bindTable(document.getElementById('jobTbl'), { onRow: (id) => jobDetail(id).catch((er) => toast(er.message, 'err')) });
    document.getElementById('srcTbl').addEventListener('click', async (e) => {
      const j = e.target.closest('[data-job]'); if (j) { jobDetail(j.dataset.job).catch((er) => toast(er.message, 'err')); return; }
      const of = e.target.closest('[data-jobs-of]');
      if (of) { document.getElementById('jSrc').value = of.dataset.jobsOf; document.getElementById('jSrc')._facet.render(); document.getElementById('jChanged').checked = false; st.page = 1; loadJobs(); document.getElementById('jobTbl').scrollIntoView({ block: 'start' }); return; }
      const tg = e.target.closest('[data-toggle]');
      if (tg) {
        const on = tg.dataset.on === '1', src = st.sources.find((x) => String(x.SourceID) === tg.dataset.toggle);
        const dl = dialog(`<div class="dlg"><div class="dlg-head"><h2>${on ? 'Kaynağı etkinleştir' : 'Kaynağı devre dışı bırak'}</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
          <p>${esc(src?.Name || '')} ${on ? 'yeniden senkronize edilebilir hâle gelir.' : 'artık senkronize edilmez. Kaynaktan gelmiş kayıtlar silinmez; istediğiniz zaman yeniden etkinleştirebilirsiniz.'}</p>
          <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn primary" id="yes">${on ? 'Etkinleştir' : 'Devre dışı bırak'}</button></div></div>`);
        dl.querySelector('#yes').onclick = async () => {
          try { await api(`/api/sources/${tg.dataset.toggle}`, { method: 'PATCH', body: { isActive: on } }); dl.close(); toast(on ? 'Kaynak etkinleştirildi.' : 'Kaynak devre dışı bırakıldı.'); loadSources(); }
          catch (er) { toast(er.message, 'err'); }
        };
        return;
      }
      const b = e.target.closest('[data-feed]'); if (b && b.dataset.feed && !b.disabled) sync(b.dataset.feed);
    });
  });
})();
