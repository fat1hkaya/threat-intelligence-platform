/* MITRE ATT&CK: /api/tactics, /api/techniques, /api/attack/matrix */
(() => {
  const { api, esc, fmtN, fmtD, list, qs, panel, panelHead, loading, empty, icons, toast } = TL;
  const split = document.getElementById('split');
  let view = qs.get('view') || 'list';

  async function detail(id) {
    const d = await api(`/api/techniques/${id}`); const t = d.technique;
    return `<section><div class="entity-title">${TL.nodeIcon('technique')}<div><span class="mono muted">${esc(t.ExternalID)}</span><h2>${esc(t.Name)}</h2></div></div>
        <div class="chips">${d.tactics.map((x) => `<span class="badge b-cyan">${esc(x.Name)} <span class="mono">${esc(x.ExternalID)}</span></span>`).join('')}</div>
        ${t.ParentTechniqueID ? `<p style="font-size:13px">Üst teknik: <a href="/attack?id=${t.ParentTechniqueID}">${esc(t.ParentExternalID)} ${esc(t.ParentName)}</a></p>` : ''}
        ${t.Description ? `<p class="desc">${esc(t.Description)}</p>` : ''}
        <dl class="kv"><dt>İlişkili IOC</dt><dd><b>${fmtN(d.indicatorCount)}</b> <span class="faint">(bu tekniği kullanan zararlılara bağlı)</span></dd></dl>
        <div class="chips"><a class="btn sm" href="${TL.graphUrl('technique', t.TechniqueID)}"><i data-lucide="share-2"></i>İlişki grafı</a>
          <a class="btn sm" href="https://attack.mitre.org/techniques/${esc(t.ExternalID.replace('.', '/'))}/" target="_blank" rel="noopener noreferrer"><i data-lucide="external-link"></i>attack.mitre.org</a></div></section>
      ${d.subTechniques.length ? `<section><h3>Alt teknikler (${d.subTechniques.length})</h3>${list(d.subTechniques, (s) => `<li><a href="/attack?id=${s.TechniqueID}"><span><span class="mono">${esc(s.ExternalID)}</span> ${esc(s.Name)}</span></a></li>`)}</section>` : ''}
      <section><h3><i data-lucide="user-round-x"></i>İlişkili aktörler (${d.actors.length})</h3>${d.actors.length ? `<div class="chips">${d.actors.slice(0, 30).map((a) => `<a class="chip" href="/actors?id=${a.ActorID}">${esc(a.Name)}</a>`).join('')}${d.actors.length > 30 ? `<span class="chip faint">+${d.actors.length - 30}</span>` : ''}</div>` : '<p class="faint" style="font-size:13px">Yok.</p>'}</section>
      <section><h3><i data-lucide="target"></i>İlişkili kampanyalar (${d.campaigns.length})</h3>${list(d.campaigns.slice(0, 8), (c) => `<li><a href="/campaigns?id=${c.CampaignID}"><span>${esc(c.Name)}</span><small>${c.StartDate ? fmtD(c.StartDate) : ''}</small></a></li>`, 'Yok.')}</section>
      <section><h3><i data-lucide="bug"></i>İlişkili zararlılar (${d.malware.length})</h3>${d.malware.length ? `<div class="chips">${d.malware.slice(0, 30).map((m) => `<a class="chip" href="/malware?id=${m.MalwareID}">${esc(m.Name)}</a>`).join('')}${d.malware.length > 30 ? `<span class="chip faint">+${d.malware.length - 30}</span>` : ''}</div>` : '<p class="faint" style="font-size:13px">Yok.</p>'}</section>`;
  }

  const page = TL.listPage({
    endpoint: '/api/techniques', title: 'Teknik detayı', unit: 'teknik', rowId: (r) => r.TechniqueID, size: 20,
    extra: () => ({ malware: qs.get('malware') }),
    columns: [
      { label: 'Teknik', render: (r) => `<span class="badge b-purple mono">${esc(r.ExternalID)}</span>` },
      { label: 'Ad', primary: true, render: (r) => `<b>${esc(r.Name)}</b>${r.SubCount ? ` <span class="faint" style="font-size:12px">+${r.SubCount} alt teknik</span>` : ''}` },
      { label: 'Taktik', render: (r) => `<span class="muted" style="font-size:12.5px">${esc(r.Tactics || '—')}</span>` },
      { label: 'Aktör', num: true, render: (r) => fmtN(r.ActorCount) },
      { label: 'Kampanya', num: true, render: (r) => fmtN(r.CampaignCount) },
      { label: 'Zararlı', num: true, render: (r) => fmtN(r.MalwareCount) },
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
    const box = document.getElementById('matrix'); box.innerHTML = loading('sp_AttackMatrix');
    try {
      const cols = await api('/api/attack/matrix', { params: p });
      const max = Math.max(1, ...cols.flatMap((c) => c.techniques.map((t) => t.ActorCount)));
      const hl = p.actor || p.campaign || p.malware;
      document.getElementById('matrixNote').textContent = hl ? 'Çerçeveli hücreler seçili aktör/kampanya/zararlının kullandığı tekniklerdir. Renk yoğunluğu: tekniği kullanan aktör sayısı.'
        : 'Renk yoğunluğu tekniği kullanan aktör sayısını gösterir. Bir aktör veya kampanya seçerek tekniklerini işaretleyin.';
      box.innerHTML = cols.map((c) => `<div class="col"><h3>${esc(c.Name)}<small>${c.techniques.length} teknik</small></h3>
        ${c.techniques.map((t) => `<button type="button" class="cell ${t.Highlighted ? 'hl' : ''}" data-id="${t.TechniqueID}" style="--heat:${(t.ActorCount / max).toFixed(2)}"
          title="${esc(t.ExternalID)} ${esc(t.Name)}: ${t.ActorCount} aktör, ${t.MalwareCount} zararlı"><small>${esc(t.ExternalID)}</small><br>${esc(t.Name)}</button>`).join('')}</div>`).join('');
    } catch (e) { box.innerHTML = empty(e.message); }
  }

  function setView(v) {
    view = v; qs.set({ view: v === 'list' ? null : v });
    document.querySelectorAll('#view button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === v)));
    document.getElementById('listView').hidden = v !== 'list'; document.getElementById('matrixView').hidden = v !== 'matrix';
    if (v === 'matrix') matrix();
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
    document.getElementById('matrix').addEventListener('click', (e) => { const c = e.target.closest('.cell'); if (c) showTech(c.dataset.id); });
    await page.start();
    if (view === 'matrix' || qs.get('actor') || qs.get('campaign') || qs.get('malware')) setView(view === 'list' && (qs.get('actor') || qs.get('campaign') || qs.get('malware')) ? 'matrix' : view);
  });
})();
