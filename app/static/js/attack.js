/* MITRE ATT&CK: /api/tactics, /api/techniques, /api/attack/matrix */
(() => {
  const { api, esc, fmtN, fmtD, list, qs, panel, panelHead, loading, empty, icons, toast } = TL;
  const split = document.getElementById('split');
  let view = qs.get('view') || 'list', brush = null;   // brush: matriste tıklayarak işaretleme düzeyi (null = kapalı)
  // Isı lejantı: tekniği kullanan aktör sayısı kovaları
  const HEAT = [[0, '0'], [1, '1–5'], [6, '6–20'], [21, '21–50'], [51, '50+']];
  const heatOf = (n) => (n <= 0 ? 0 : n <= 5 ? 1 : n <= 20 ? 2 : n <= 50 ? 3 : 4);
  const BLIND_PER_PAGE = 10;

  const LEVEL = ['Tespit edilemiyor', 'Kısmi tespit', 'Tam tespit'];
  const covBadge = (l) => `<span class="cov-pill cov-${l}"><i data-lucide="${['shield-x', 'shield-half', 'shield-check'][l]}" style="width:15px;height:15px"></i>${LEVEL[l]}</span>`;
  function coverageEditor(c) {
    const lvl = c.Level ?? null;
    return `<section><h3><i data-lucide="shield-half"></i>Tespit kapsamamız</h3>
      <p style="font-size:13px">${covBadge(c.EffectiveLevel)}${c.Inherited ? ' <span class="faint">(üst teknikten devralındı)</span>' : ''}${c.UpdatedBy ? ` <span class="faint">· ${esc(c.UpdatedBy)}</span>` : ''}</p>
      ${TL.can('analyst') ? `<form id="covForm" class="grid" style="gap:8px">
        <div class="seg" role="group" aria-label="Kapsama düzeyi">${[0, 1, 2].map((l) => `<button type="button" data-level="${l}" aria-pressed="${String(lvl === l)}">${LEVEL[l]}</button>`).join('')}</div>
        <input class="input" name="dataSource" maxlength="100" placeholder="Veri kaynağı (ör. Sysmon EID 1 + EDR)" value="${esc(c.DataSource || '')}" aria-label="Veri kaynağı">
        <input class="input" name="note" maxlength="400" placeholder="Not" value="${esc(c.Note || '')}" aria-label="Not">
        <div style="display:flex;gap:8px"><button class="btn primary sm">Kaydet</button>${c.Level != null ? '<button type="button" class="btn sm" id="covClear">İşareti kaldır</button>' : ''}</div></form>` : ''}</section>`;
  }
  function bindCoverageEditor(id) {
    const f = document.getElementById('covForm'); if (!f) return;
    let level = null;
    f.querySelectorAll('[data-level]').forEach((b) => {
      if (b.getAttribute('aria-pressed') === 'true') level = +b.dataset.level;
      b.onclick = () => { level = +b.dataset.level; f.querySelectorAll('[data-level]').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); };
    });
    f.onsubmit = async (e) => {
      e.preventDefault();
      if (level === null) { toast('Bir kapsama düzeyi seçin.', 'err'); return; }
      try {
        await api(`/api/coverage/technique/${id}`, { method: 'PUT', body: { level, dataSource: f.dataSource.value || null, note: f.note.value || null } });
        toast('Kapsama kaydedildi.'); showTech(id); if (view === 'matrix') matrix(); if (view === 'coverage') coverage();
      } catch (x) { toast(x.message, 'err'); }
    };
    const clr = document.getElementById('covClear');
    if (clr) clr.onclick = async () => { await api(`/api/coverage/technique/${id}`, { method: 'DELETE' }); toast('İşaret kaldırıldı.'); showTech(id); if (view === 'matrix') matrix(); };
  }

  async function coverage() {
    let d; try { d = await api('/api/coverage'); } catch (e) { toast(e.message, 'err'); return; }
    const t = d.totals || {}; const pct = (x) => `%${Number(x ?? 0).toLocaleString('tr-TR')}`;
    // Kapsam hiç girilmediyse grafik ve tablolar yerine başlangıç ekranı (her değer %0 olurdu)
    const startBox = document.getElementById('covStart'), body = document.getElementById('covBody');
    const none = !t.Marked;
    startBox.hidden = !none; body.hidden = none;
    if (none) { icons(); return; }
    document.getElementById('covKpis').innerHTML = [
      ['shield-check', '', 'İşaretlenen teknik', fmtN(t.Marked), 'kurumun beyanı'],
      ['grid-3x3', 'c', 'Üst tekniklerde tam tespit', fmtN(t.FullTop), `${fmtN(t.PartialTop || 0)} kısmi · toplam ${fmtN(t.TopTechniques || 0)}`],
      ['crosshair', 'a', 'Aktör tekniklerinde kapsama', pct(t.UsedCoveragePct), 'tam = 1, kısmi = 0,5 puan'],
      ['users', 'r', 'Tamamen kapsanan aktör', fmtN(d.fullyCovered.length), 'ilişkisel bölme sonucu'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="val">${v}</div><div class="lbl">${l}</div><div class="sub">${sub}</div></div></article>`).join('');
    document.getElementById('covGaps').innerHTML = d.gaps.length ? TL.table([
      { label: 'Teknik', primary: true, render: (g) => `<a href="/attack?id=${g.TechniqueID}"><span class="mono">${esc(g.ExternalID)}</span> ${esc(g.Name)}</a>` },
      { label: 'Kullanan aktör', num: true, render: (g) => fmtN(g.ActorCount) },
    ], d.gaps, { caption: 'Öncelikli kör noktalar' }) : empty('Kör nokta kalmadı: aktörlerin kullandığı her teknik en az kısmi tespit ediliyor.', 'shield-check');
    document.getElementById('covTactics').innerHTML = d.tactics.map((x) => `<div class="bar-row"><span>${esc(x.Name)}</span>
      <span class="track" aria-hidden="true"><i style="width:${Number(x.CoveragePct || 0)}%"></i></span><b>${pct(x.CoveragePct)}</b></div>`).join('');
    document.getElementById('covWeak').innerHTML = d.actors.map((a) => `<li><a href="#" data-cov-actor="${a.ActorID}"><span>${esc(a.Name)}</span><small>${pct(a.CoveragePct)} · ${a.Techniques} teknik</small></a></li>`).join('');
    document.getElementById('covFull').innerHTML = d.fullyCovered.length
      ? `<div class="chips">${d.fullyCovered.map((a) => `<a class="chip" href="/actors?id=${a.ActorID}">${esc(a.Name)} <span class="faint">${a.Techniques}</span></a>`).join('')}</div>`
      : '<p class="faint" style="font-size:13px">Henüz yok. Teknikleri işaretledikçe, kullandığı tüm teknikleri kapsanan aktörler burada listelenir.</p>';
    icons();
  }

  async function actorCoverage(id) {
    const out = document.getElementById('covActorOut'); if (!id) return; out.innerHTML = loading('Kapsama hesaplanıyor');
    const d = await api(`/api/coverage/actor/${id}`); const s = d.summary;
    const blind = d.techniques.filter((t) => t.Level === 0);
    out.innerHTML = `<p style="font-size:28px;font-weight:700">%${Number(s.CoveragePct ?? 0).toLocaleString('tr-TR')}</p>
      <p class="muted" style="font-size:13px">${fmtN(s.Techniques)} teknik: ${fmtN(s.FullCount)} tam, ${fmtN(s.PartialCount)} kısmi, <b class="cov-0">${fmtN(s.NoneCount)} kör nokta</b></p>
      <p style="margin-top:8px"><a class="btn sm" href="/api/export/navigator/actor/${id}?coverage=true" download title="Aktörün teknikleri kapsama renkleriyle (yeşil tam, sarı kısmi, kırmızı kör nokta)"><i data-lucide="download"></i>Navigator katmanı</a></p>
      <h3 style="margin-top:12px">Kör noktalar (en çok aktörün kullandığı önce)</h3>
      ${blind.length ? '<ul class="list" id="blindList"></ul><div class="pager" id="blindPager"></div>' : '<p class="cov-2" style="font-size:13px">Kör nokta yok.</p>'}`;
    if (!blind.length) { icons(); return; }
    const page = (p) => {
      document.getElementById('blindList').innerHTML = blind.slice((p - 1) * BLIND_PER_PAGE, p * BLIND_PER_PAGE).map((t) => `<li><a href="/attack?id=${t.TechniqueID}"><span><span class="mono">${esc(t.ExternalID)}</span> ${esc(t.Name)}</span><small>${t.ActorCount} aktör</small></a></li>`).join('');
      TL.pager(document.getElementById('blindPager'), { page: p, size: BLIND_PER_PAGE, total: blind.length }, page, 'kör nokta');
      icons();
    };
    page(1);
  }

  async function detail(id) {
    const [d, cov] = await Promise.all([api(`/api/techniques/${id}`), api(`/api/coverage/technique/${id}`)]); const t = d.technique;
    setTimeout(() => bindCoverageEditor(id));
    return `<section><div class="entity-title">${TL.nodeIcon('technique')}<div><span class="mono muted">${esc(t.ExternalID)}</span><h2>${esc(t.Name)}</h2></div></div>
        <div class="chips">${d.tactics.map((x) => `<span class="badge b-cyan">${esc(x.Name)} <span class="mono">${esc(x.ExternalID)}</span></span>`).join('')}</div>
        ${t.ParentTechniqueID ? `<p style="font-size:13px">Üst teknik: <a href="/attack?id=${t.ParentTechniqueID}">${esc(t.ParentExternalID)} ${esc(t.ParentName)}</a></p>` : ''}
        ${t.Description ? `<p class="desc">${esc(t.Description)}</p>` : ''}
        <dl class="kv"><dt>İlişkili IOC</dt><dd><b>${fmtN(d.indicatorCount)}</b> <span class="faint">(bu tekniği kullanan zararlılara bağlı)</span></dd></dl>
        <div class="chips"><a class="btn sm" href="${TL.graphUrl('technique', t.TechniqueID)}"><i data-lucide="share-2"></i>İlişki grafı</a>
          <a class="btn sm" href="https://attack.mitre.org/techniques/${esc(t.ExternalID.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"><i data-lucide="external-link"></i>attack.mitre.org</a></div></section>
      ${coverageEditor(cov)}
      ${d.subTechniques.length ? `<section><h3>Alt teknikler (${d.subTechniques.length})</h3>${list(d.subTechniques, (s) => `<li><a href="/attack?id=${s.TechniqueID}"><span><span class="mono">${esc(s.ExternalID)}</span> ${esc(s.Name)}</span></a></li>`)}</section>` : ''}
      <section><h3><i data-lucide="user-round-x"></i>İlişkili aktörler (${d.actors.length})</h3>${d.actors.length ? `<div class="chips">${d.actors.slice(0, 30).map((a) => `<a class="chip" href="/actors?id=${a.ActorID}">${esc(a.Name)}</a>`).join('')}${d.actors.length > 30 ? `<span class="chip faint">+${d.actors.length - 30}</span>` : ''}</div>` : '<p class="faint" style="font-size:13px">Yok.</p>'}</section>
      <section><h3><i data-lucide="target"></i>İlişkili kampanyalar (${d.campaigns.length})</h3>${list(d.campaigns.slice(0, 8), (c) => `<li><a href="/campaigns?id=${c.CampaignID}"><span>${esc(c.Name)}</span><small>${c.StartDate ? fmtD(c.StartDate) : ''}</small></a></li>`, 'Yok.')}</section>
      <section><h3><i data-lucide="bug"></i>İlişkili zararlılar (${d.malware.length})</h3>${d.malware.length ? `<div class="chips">${d.malware.slice(0, 30).map((m) => `<a class="chip" href="/malware?id=${m.MalwareID}">${esc(m.Name)}</a>`).join('')}${d.malware.length > 30 ? `<span class="chip faint">+${d.malware.length - 30}</span>` : ''}</div>` : '<p class="faint" style="font-size:13px">Yok.</p>'}</section>`;
  }

  const page = TL.listPage({
    endpoint: '/api/techniques', title: 'Teknik detayı', unit: 'teknik', rowId: (r) => r.TechniqueID, size: 20, filters: { counts: '/api/techniques/facets' },
    extra: () => ({ malware: qs.get('malware') }),
    columns: [
      { id: 'code', label: 'Teknik', render: (r) => `<span class="badge b-purple mono">${esc(r.ExternalID)}</span>` },
      { id: 'name', label: 'Ad', primary: true, render: (r) => `<span class="name-id"><b>${esc(r.Name)}</b>${r.SubCount ? ` <span class="faint">+${r.SubCount} alt teknik</span>` : ''}</span>` },
      { id: 'tactic', label: 'Taktik', priority: 2, render: (r) => `<span class="muted">${TL.clipList(r.Tactics, 2)}</span>` },
      { id: 'actors', label: 'Aktör', num: true, render: (r) => TL.num(r.ActorCount) },
      { id: 'campaigns', label: 'Kampanya', num: true, priority: 3, render: (r) => TL.num(r.CampaignCount) },
      { id: 'malware', label: 'Zararlı', num: true, priority: 2, render: (r) => TL.num(r.MalwareCount) },
    ],
    detail,
  });

  async function tactics() {
    const rows = await api('/api/tactics'); const sel = document.getElementById('tactic').value;
    document.getElementById('tactics').innerHTML = rows.map((t) => `<button type="button" class="tactic" data-id="${t.TacticID}" aria-pressed="${String(t.TacticID) === sel}">
      <b>${esc(t.Name)}</b><span class="cnt" title="${t.TechniqueCount} teknikten ${t.UsedByActors} tanesini en az bir aktör kullanıyor">${t.TechniqueCount} teknik · aktörlerin kullandığı ${t.UsedByActors}</span></button>`).join('');
  }

  async function matrix() {
    const f = TL.formData(document.getElementById('filters'));
    const p = { actor: f.actor, campaign: f.campaign, malware: qs.get('malware') };
    const box = document.getElementById('matrix'); box.innerHTML = loading('Matris hazırlanıyor');
    try {
      const [cols, covRows] = await Promise.all([api('/api/attack/matrix', { params: p }), api('/api/coverage/levels')]);
      const cov = Object.fromEntries(covRows.map((c) => [c.TechniqueID, c.Level]));
      const max = Math.max(1, ...cols.flatMap((c) => c.techniques.map((t) => t.ActorCount)));
      const hl = p.actor || p.campaign || p.malware;
      void max;
      document.getElementById('matrixNote').innerHTML = `<span class="legend-box" aria-label="Renk: tekniği kullanan aktör sayısı">${HEAT.map(([, l], k) => `<span><i class="heat-${k}"></i>${l}</span>`).join('')}<span class="faint">aktör</span></span>
        <span class="legend-box"><span><i class="cov-line-2"></i>tam tespit</span><span><i class="cov-line-1"></i>kısmi</span>${hl ? '<span><i class="hl-mark"></i>seçili aktör/kampanya</span>' : ''}</span>`;
      document.getElementById('matrixHead').innerHTML = cols.map((c) => `<div class="mh-col"><b title="${esc(c.Name)}">${esc(c.Name)}</b><small>${c.techniques.length} teknik</small></div>`).join('');
      box.innerHTML = cols.map((c) => `<div class="col" role="group" aria-label="${esc(c.Name)}"><h2 class="sr-only">${esc(c.Name)} (${c.techniques.length} teknik)</h2>
        ${c.techniques.map((t) => `<button type="button" class="cell heat-${heatOf(t.ActorCount)} ${t.Highlighted ? 'hl' : ''}" data-id="${t.TechniqueID}" ${cov[t.TechniqueID] ? `data-cov="${cov[t.TechniqueID]}"` : ''}
          title="${esc(t.ExternalID)} ${esc(t.Name)}: ${t.ActorCount} aktör, ${t.MalwareCount} zararlı"><small>${esc(t.ExternalID)}</small><br>${esc(t.Name)}</button>`).join('')}</div>`).join('');
      syncHead();
    } catch (e) { box.innerHTML = empty(e.message); }
  }

  // Yapışkan sütun başlığı şeridi matrisle birlikte yatay kayar
  function syncHead() {
    const m = document.getElementById('matrix'), h = document.getElementById('matrixHead');
    if (!m || !h) return;
    h.style.gridTemplateColumns = getComputedStyle(m).gridTemplateColumns;
    h.scrollLeft = m.scrollLeft;
    const cols = m.querySelectorAll('.col'), vis = [...cols].filter((c) => c.offsetLeft - m.scrollLeft < m.clientWidth - 40 && c.offsetLeft + c.offsetWidth - m.scrollLeft > 40).length;
    document.getElementById('matrixScroll').textContent = m.scrollWidth > m.clientWidth + 1 ? `${cols.length} taktikten ${vis} tanesi görünüyor · yana kaydırın` : '';
  }
  // Matriste tıklayarak işaretleme: seçilen düzey tıklanan tekniğe yazılır
  function setBrush(v) {
    brush = v;
    document.querySelectorAll('#brush [data-brush]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.brush === String(v))));
    document.getElementById('matrixView').classList.toggle('marking', v !== null);
    document.getElementById('brushHint').textContent = v === null ? '' : 'İşaretleme açık: bir tekniğe tıklayınca seçili düzey kaydedilir.';
  }
  async function paint(cell) {
    const id = cell.dataset.id;
    try {
      if (brush === 'clear') { await api(`/api/coverage/technique/${id}`, { method: 'DELETE' }); delete cell.dataset.cov; }
      else { await api(`/api/coverage/technique/${id}`, { method: 'PUT', body: { level: +brush } }); if (+brush) cell.dataset.cov = brush; else delete cell.dataset.cov; }
      cell.classList.add('painted'); setTimeout(() => cell.classList.remove('painted'), 600);
    } catch (e) { toast(e.message, 'err'); }
  }

  function setView(v) {
    view = v; qs.set({ view: v === 'list' ? null : v });
    document.querySelectorAll('#view button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === v)));
    document.getElementById('listView').hidden = v !== 'list'; document.getElementById('matrixView').hidden = v !== 'matrix';
    const cov = v === 'coverage';
    document.getElementById('coverageView').hidden = !cov;
    document.getElementById('filters').hidden = cov;
    document.querySelector('[aria-label="Taktikler"]').hidden = cov;
    document.getElementById('split').hidden = cov;
    if (v === 'matrix') matrix();
    if (cov) coverage();
  }
  async function showTech(id) { qs.set({ id }); panel(split, panelHead('Teknik detayı') + loading()); try { panel(split, panelHead('Teknik detayı') + await detail(id)); } catch (e) { toast(e.message, 'err'); } }

  document.addEventListener('DOMContentLoaded', async () => {
    const [actors, camps] = await Promise.all([api('/api/actors', { params: { size: 200, sort: 'name' } }), api('/api/campaigns', { params: { size: 100 } })]);
    TL.facetOptions(document.getElementById('actor'), actors.items.map((a) => ({ value: a.ActorID, label: a.Name })));
    TL.facetOptions(document.getElementById('campaign'), camps.items.sort((a, b) => a.Name.localeCompare(b.Name, 'tr')).map((c) => ({ value: c.CampaignID, label: c.Name })));
    const form = document.getElementById('filters');
    ['tactic', 'actor', 'campaign'].forEach((k) => { const v = qs.get(k); if (v) form.elements[k].value = v; });
    if (qs.get('subtechniques')) form.elements.subtechniques.checked = true;
    tactics();
    document.getElementById('tactics').addEventListener('click', (e) => {
      const b = e.target.closest('.tactic'); if (!b) return;
      const el = document.getElementById('tactic'); el.value = el.value === b.dataset.id ? '' : b.dataset.id;
      document.querySelectorAll('.tactic').forEach((x) => x.setAttribute('aria-pressed', String(x.dataset.id === el.value)));
      form.requestSubmit();
    });
    form.addEventListener('reset', () => setTimeout(() => { document.querySelectorAll('.tactic').forEach((x) => x.setAttribute('aria-pressed', 'false')); qs.set({ malware: null }); if (view === 'matrix') matrix(); }));
    form.addEventListener('change', () => { if (view === 'matrix') matrix(); });
    document.getElementById('view').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) setView(b.dataset.v); });
    document.getElementById('covActor').insertAdjacentHTML('beforeend', actors.items.map((a) => `<option value="${a.ActorID}">${esc(a.Name)}</option>`).join(''));
    document.getElementById('covActor').addEventListener('change', (e) => actorCoverage(e.target.value));
    document.getElementById('covWeak').addEventListener('click', (e) => {
      const a = e.target.closest('[data-cov-actor]'); if (!a) return; e.preventDefault();
      document.getElementById('covActor').value = a.dataset.covActor; actorCoverage(a.dataset.covActor);
    });
    document.getElementById('matrix').addEventListener('click', (e) => { const c = e.target.closest('.cell'); if (!c) return; brush !== null ? paint(c) : showTech(c.dataset.id); });
    document.getElementById('matrix').addEventListener('scroll', syncHead, { passive: true });
    window.addEventListener('resize', TL.debounce(syncHead, 150));
    document.getElementById('brush')?.addEventListener('click', (e) => { const b = e.target.closest('[data-brush]'); if (!b) return; setBrush(brush === b.dataset.brush ? null : b.dataset.brush); });
    if (!TL.can('analyst')) {   // izleyici kapsama işaretleyemez
      ['covMark', 'covImport'].forEach((k) => { const el = document.getElementById(k); if (el) { el.disabled = true; el.title = 'Kapsama işaretlemek için analist yetkisi gerekir'; } });
      document.querySelector('.brush-wrap').hidden = true;
    }
    // Kapsam başlangıç ekranı: işaretlemeye başla / Navigator katmanı içe aktar
    document.getElementById('covMark')?.addEventListener('click', () => { setView('matrix'); setBrush('2'); document.getElementById('matrixView').scrollIntoView({ block: 'start' }); });
    const navFile = document.getElementById('navFile');
    document.getElementById('covImport')?.addEventListener('click', () => navFile.click());
    navFile?.addEventListener('change', async () => {
      const f = navFile.files[0]; navFile.value = ''; if (!f) return;
      let layer; try { layer = JSON.parse(await f.text()); } catch { toast('Dosya geçerli bir JSON değil.', 'err'); return; }
      try {
        const pre = await api('/api/coverage/import-navigator', { method: 'POST', params: { dryRun: true }, body: layer });
        if (!pre.matched) { toast('Katmanda tam ya da kısmi tespit olarak yorumlanabilecek teknik bulunamadı.', 'err'); return; }
        const d = TL.dialog(`<div class="dlg"><div class="dlg-head"><h2>Navigator katmanını içe aktar</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
          <p><b>${fmtN(pre.matched)}</b> teknik tam ya da kısmi tespit olarak işaretlenecek${pre.skipped ? `; ${fmtN(pre.skipped)} teknik atlanacak (kapalı, kırmızı ya da düşük skorlu)` : ''}.</p>
          <p class="muted" style="font-size:13px;margin-top:6px">Yeşil = tam, sarı = kısmi; başka araçların katmanlarında skor ≥ 67 tam, ≥ 34 kısmi sayılır. Var olan işaretlerin düzeyi güncellenir.</p>
          <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn primary" id="navYes">İçe aktar</button></div></div>`);
        d.querySelector('#navYes').onclick = async () => {
          try { const r = await api('/api/coverage/import-navigator', { method: 'POST', body: layer }); d.close(); toast(`${fmtN(r.applied)} teknik işaretlendi.`); coverage(); }
          catch (x) { toast(x.message, 'err'); }
        };
      } catch (x) { toast(x.message, 'err'); }
    });
    await page.start();
    const linked = qs.get('actor') || qs.get('campaign') || qs.get('malware');
    if (view !== 'list') setView(view); else if (linked) setView('matrix');
  });
})();
