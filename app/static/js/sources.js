/* Veri kaynakları: /api/sources, /api/imports */
(() => {
  const { api, esc, fmtN, fmtDT, ago, job, table, pager, empty, loading, icons, toast, can, dialog, qs } = TL;
  const REL = { A: 'A · tamamen güvenilir', B: 'B · genelde güvenilir', C: 'C · oldukça güvenilir', D: 'D · genelde güvenilmez', E: 'E · güvenilmez', F: 'F · değerlendirilemez' };
  const TYPE = { feed: 'Besleme', file: 'Dosya', attack: 'ATT&CK' };
  const st = { page: 1 };

  async function loadSources() {
    const d = await api('/api/sources'); const t = d.totals;
    document.getElementById('kpis').innerHTML = [
      ['database', '', 'Toplam kaynak', fmtN(t.Sources), `${fmtN(t.ActiveSources)} aktif`],
      ['calendar-clock', 'c', 'Son içe aktarma', t.LastJobAt ? ago(t.LastJobAt) : '—', t.LastJobAt ? fmtDT(t.LastJobAt) : 'Henüz iş yok'],
      ['circle-check', '', 'Başarılı işler (7 gün)', fmtN(t.Success7d), `${fmtN(t.Jobs7d)} işten`],
      ['triangle-alert', 'r', 'Sorunlu işler (7 gün)', fmtN(t.Problem7d), 'Kısmi veya hatalı'],
    ].map(([i, c, l, v, s]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="lbl">${l}</div><div class="val">${v}</div><div class="sub">${s}</div></div></article>`).join('');
    document.getElementById('keyNotice').hidden = d.abusechKey;
    const writer = can('analyst'), admin = can('admin');
    document.getElementById('srcTbl').innerHTML = table([
      { label: 'Kaynak', primary: true, render: (s) => `<b>${esc(s.Name)}</b>${s.Url ? `<br><a href="${esc(s.Url)}" target="_blank" rel="noopener noreferrer" style="font-size:12px">${esc(s.Url.replace(/^https?:\/\//, ''))}</a>` : ''}` },
      { label: 'Güvenilirlik', render: (s) => `<span class="badge b-muted" title="${esc(REL[s.Reliability])}">${esc(s.Reliability)}</span>` },
      { label: 'Kayıt', num: true, render: (s) => `<span style="white-space:nowrap" ${s.UnitDetail ? `title="${esc(s.UnitDetail)}"` : ''}>${fmtN(s.UnitCount || 0)} <span class="faint">${esc(s.UnitLabel || 'IOC')}</span></span>` },
      { label: 'Kanıt', num: true, render: (s) => fmtN(s.EvidenceCount) },
      { label: 'Son iş', render: (s) => s.LastRunAt ? `<span style="display:inline-flex;gap:6px;align-items:center;white-space:nowrap">${job(s.LastRunStatus)} <span class="muted" style="font-size:12px" title="${fmtDT(s.LastRunAt)}">${TL.ago(s.LastRunAt)}</span></span>` : '<span class="faint">Henüz yok</span>' },
      { label: 'Son işte', render: (s) => s.LastRunAt ? `<span style="font-size: 13px">+${fmtN(s.LastRowsInserted)} / ~${fmtN(s.LastRowsUpdated)} / <span class="${s.LastRowsFailed ? 'delta-down' : ''}">✕${fmtN(s.LastRowsFailed)}</span></span>` : '—' },
      { label: 'İşlemler', render: (s) => {
        if (!s.Feed) return '<span class="faint" style="font-size:12px">Elle / dosya</span>';
        const allowed = s.Feed === 'attack' ? admin : writer;
        const why = !s.Ready ? 'ABUSECH_AUTH_KEY gerekli' : !allowed ? 'Yetkiniz yok' : 'Kaynaktan şimdi çek';
        return `<button class="btn sm" data-feed="${s.Feed}" ${s.Ready && allowed ? '' : 'disabled'} title="${why}"><i data-lucide="refresh-cw"></i>Senkronize et</button>`; } },
    ], d.sources, { caption: 'Kaynaklar' });
    const opts = d.sources.map((s) => `<option value="${s.SourceID}">${esc(s.Name)}</option>`).join('');
    const js = document.getElementById('jSrc'); if (js.options.length === 1) js.insertAdjacentHTML('beforeend', opts);
    const up = document.getElementById('upSrc'); if (!up.options.length) { up.innerHTML = opts; up.value = d.sources.find((s) => s.Name === 'Analist girişi')?.SourceID || ''; }
    icons();
  }

  async function loadJobs() {
    const box = document.getElementById('jobTbl'); box.innerHTML = loading();
    const d = await api('/api/imports', { params: { page: st.page, source: document.getElementById('jSrc').value, status: document.getElementById('jStatus').value } });
    box.innerHTML = d.items.length ? table([
      { label: 'İş', primary: true, render: (j) => `<b class="mono">#${j.JobID}</b>` },
      { label: 'Kaynak', render: (j) => `${esc(j.SourceName)}<br><small class="muted">${esc(TYPE[j.JobType] || j.JobType)}${j.FileName ? ' · ' + esc(j.FileName) : ''}${j.IsStrict ? ' · katı' : ''}</small>` },
      { label: 'Durum', render: (j) => job(j.Status) },
      { label: 'Başlangıç', render: (j) => `<span title="${esc(j.StartedBy || '')}">${fmtDT(j.StartedAt)}</span>` },
      { label: 'Süre', num: true, render: (j) => j.DurationSec != null ? `${j.DurationSec} sn` : '—' },
      { label: 'Okunan', num: true, render: (j) => fmtN(j.RowsRead) },
      { label: 'Eklenen', num: true, render: (j) => fmtN(j.RowsInserted) },
      { label: 'Güncellenen', num: true, render: (j) => fmtN(j.RowsUpdated) },
      { label: 'Atlanan', num: true, render: (j) => fmtN(j.RowsSkipped) },
      { label: 'Hatalı', num: true, render: (j) => j.RowsFailed ? `<b class="delta-down">${fmtN(j.RowsFailed)}</b>` : '0' },
      { label: '', render: (j) => `<button class="btn sm" data-job="${j.JobID}"><i data-lucide="file-text"></i>Ayrıntı</button>` },
    ], d.items, { caption: 'İçe aktarma işleri' }) : empty('Bu filtrelere uyan iş yok.');
    pager(document.getElementById('jobPager'), d, (n) => { st.page = n; loadJobs(); }, 'iş');
    icons();
  }

  const resultHtml = (r) => `<div class="notice ${r.status === 'success' ? '' : 'warn'}"><i data-lucide="${r.status === 'success' ? 'circle-check' : 'triangle-alert'}"></i><div>
      <b>İş #${r.job_id ?? r.JobID}: ${job(r.status ?? r.Status)}</b><br>Okunan ${fmtN(r.read ?? r.RowsRead)}, eklenen ${fmtN(r.inserted ?? r.RowsInserted)}, güncellenen ${fmtN(r.updated ?? r.RowsUpdated)}, atlanan ${fmtN(r.skipped ?? r.RowsSkipped)}, hatalı ${fmtN(r.failed ?? r.RowsFailed)}
      ${r.rolled_back ? `<br><b>ROLLBACK:</b> ${fmtN(r.rolled_back)} satırlık değişiklik geri alındı.` : ''}${(r.message ?? r.ErrorMessage) ? `<br><span class="muted">${esc(r.message ?? r.ErrorMessage)}</span>` : ''}</div></div>`;
  const errorsHtml = (errs) => errs.length ? table([{ label: 'Satır', num: true, render: (e) => e.RowNo ?? e.row }, { label: 'Değer', render: (e) => `<span class="mono">${esc(e.RawValue ?? e.value ?? '—')}</span>` },
    { label: 'Neden', primary: true, render: (e) => esc(e.Reason ?? e.reason) }], errs, { caption: 'Hatalı satırlar' }) : '';

  async function jobDetail(id) {
    const d = await api(`/api/imports/${id}`);
    dialog(`<div class="dlg"><div class="dlg-head"><h2>İçe aktarma işi #${id}</h2><button class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <dl class="kv"><dt>Kaynak</dt><dd>${esc(d.job.SourceName)}</dd><dt>Tür</dt><dd>${esc(TYPE[d.job.JobType])}${d.job.IsStrict ? ' (katı mod)' : ''}</dd>
      <dt>Dosya</dt><dd>${esc(d.job.FileName || '—')}</dd><dt>Başlatan</dt><dd>${esc(d.job.StartedByName || 'Sistem')}</dd>
      <dt>Başlangıç</dt><dd>${fmtDT(d.job.StartedAt)}</dd><dt>Bitiş</dt><dd>${fmtDT(d.job.FinishedAt)}</dd></dl>
      ${resultHtml(d.job)}<h3>Hatalı satırlar (ImportJobError)</h3>${errorsHtml(d.errors) || '<p class="faint">Hatalı satır yok.</p>'}</div>`, { wide: true });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    if (!can('analyst')) document.getElementById('uploadCard').innerHTML = '<h2>Dosyadan IOC içe aktar</h2><p class="muted" style="margin-top:8px">İçe aktarma için analist veya yönetici yetkisi gerekir.</p>';
    const srcParam = qs.get('source');
    await loadSources(); if (srcParam) document.getElementById('jSrc').value = srcParam;
    loadJobs();
    document.getElementById('jSrc').onchange = document.getElementById('jStatus').onchange = () => { st.page = 1; loadJobs(); };
    document.getElementById('jobTbl').addEventListener('click', (e) => { const b = e.target.closest('[data-job]'); if (b) jobDetail(b.dataset.job).catch((er) => toast(er.message, 'err')); });
    document.getElementById('srcTbl').addEventListener('click', async (e) => {
      const b = e.target.closest('[data-feed]'); if (!b) return;
      b.disabled = true; b.innerHTML = '<span class="spinner"></span>Çalışıyor';
      const feed = b.dataset.feed;
      try {
        await api('/api/imports/feed', { method: 'POST', body: { feed } });
        toast('Senkronizasyon arka planda başladı. Bitince liste kendiliğinden yenilenir.');
        // Arka plan işini yokla (3 sn aralıkla, en çok 10 dk)
        for (let i = 0; i < 200; i += 1) {
          await new Promise((r) => setTimeout(r, 3000));
          const s = await api('/api/imports/feed/status');
          if (!s.running.includes(feed)) break;
          if (i % 5 === 4) { loadJobs(); }
        }
        toast('Senkronizasyon tamamlandı. Sonuç içe aktarma işleri listesinde.');
      } catch (er) { toast(er.message, 'err'); }
      await loadSources(); st.page = 1; loadJobs();
    });
    document.getElementById('upForm')?.addEventListener('submit', async (e) => {
      e.preventDefault(); const f = e.target, out = document.getElementById('upOut');
      const fd = new FormData(); fd.append('file', f.file.files[0]); fd.append('sourceId', f.sourceId.value); fd.append('strict', f.strict.checked ? 'true' : 'false');
      out.innerHTML = loading('İçe aktarılıyor');
      try { const r = await api('/api/imports', { method: 'POST', body: fd }); out.innerHTML = resultHtml(r) + errorsHtml(r.errors); toast(`İçe aktarma işi #${r.job_id} tamamlandı.`); }
      catch (er) { out.innerHTML = `<p class="err">${esc(er.message)}</p>`; }
      icons(); loadSources(); st.page = 1; loadJobs();
    });
  });
})();
