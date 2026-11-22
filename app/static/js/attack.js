/* MITRE ATT&CK: /api/tactics, /api/techniques, /api/attack/matrix */
(() => {
  const { api, esc, fmtN, fmtD, list, qs, panel, panelHead, loading, empty, icons, toast } = TL;
  const split = document.getElementById('split');
  let view = qs.get('view') || 'list';

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
    document.getElementById('covKpis').innerHTML = [
      ['shield-check', '', 'İşaretlenen teknik', fmtN(t.Marked), 'kurumun beyanı'],
      ['grid-3x3', 'c', 'Üst tekniklerde tam tespit', fmtN(t.FullTop), `${fmtN(t.PartialTop || 0)} kısmi · toplam ${fmtN(t.TopTechniques || 0)}`],
      ['crosshair', 'a', 'Aktör tekniklerinde kapsama', pct(t.UsedCoveragePct), 'tam = 1, kısmi = 0,5 puan'],
      ['users', 'r', 'Tamamen kapsanan aktör', fmtN(d.fullyCovered.length), 'ilişkisel bölme sonucu'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="lbl">${l}</div><div class="val">${v}</div><div class="sub">${sub}</div></div></article>`).join('');
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
      ${blind.length ? `<ul class="list" style="max-height:300px;overflow:auto">${blind.slice(0, 40).map((t) => `<li><a href="/attack?id=${t.TechniqueID}"><span><span class="mono">${esc(t.ExternalID)}</span> ${esc(t.Name)}</span><small>${t.ActorCount} aktör</small></a></li>`).join('')}</ul>` : '<p class="cov-2" style="font-size:13px">Kör nokta yok.</p>'}`;
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
    endpoint: '/api/techniques', title: 'Teknik detayı', unit: 'teknik', rowId: (r) => r.TechniqueID, size: 20,
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
      <small>${esc(t.ExternalID)}</small><b>${esc(t.Name)}</b><span class="cnt">${t.TechniqueCount} teknik · ${t.UsedByActors} kullanımda</span></button>`).join('');
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
      document.getElementById('matrixNote').textContent = hl ? 'Çerçeveli hücreler seçili aktör/kampanya/zararlının kullandığı tekniklerdir. Renk yoğunluğu: tekniği kullanan aktör sayısı.'
        : 'Renk yoğunluğu tekniği kullanan aktör sayısını gösterir. Bir aktör veya kampanya seçerek tekniklerini işaretleyin.';
      document.getElementById('matrixNote').textContent += ' Hücre alt çizgisi: tespit kapsaması (yeşil tam, sarı kısmi).';
      box.innerHTML = cols.map((c) => `<div class="col"><h3>${esc(c.Name)}<small>${c.techniques.length} teknik</small></h3>
        ${c.techniques.map((t) => `<button type="button" class="cell ${t.Highlighted ? 'hl' : ''}" data-id="${t.TechniqueID}" ${cov[t.TechniqueID] ? `data-cov="${cov[t.TechniqueID]}"` : ''} style="--heat:${(t.ActorCount / max).toFixed(2)}"
          title="${esc(t.ExternalID)} ${esc(t.Name)}: ${t.ActorCount} aktör, ${t.MalwareCount} zararlı"><small>${esc(t.ExternalID)}</small><br>${esc(t.Name)}</button>`).join('')}</div>`).join('');
    } catch (e) { box.innerHTML = empty(e.message); }
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
    document.getElementById('actor').insertAdjacentHTML('beforeend', actors.items.map((a) => `<option value="${a.ActorID}">${esc(a.Name)}</option>`).join(''));
    document.getElementById('campaign').insertAdjacentHTML('beforeend', camps.items.sort((a, b) => a.Name.localeCompare(b.Name, 'tr')).map((c) => `<option value="${c.CampaignID}">${esc(c.Name)}</option>`).join(''));
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
    document.getElementById('matrix').addEventListener('click', (e) => { const c = e.target.closest('.cell'); if (c) showTech(c.dataset.id); });
    await page.start();
    const linked = qs.get('actor') || qs.get('campaign') || qs.get('malware');
    if (view !== 'list') setView(view); else if (linked) setView('matrix');
  });
})();
