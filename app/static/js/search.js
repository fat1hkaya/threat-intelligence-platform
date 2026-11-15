/* Birleşik arama sayfası: /api/search/full */
(() => {
  const { api, esc, NODE, entityUrl, empty, loading, icons, qs, toast } = TL;
  const REL = { 'actor-technique': 'aktör → teknik', 'actor-malware': 'aktör → zararlı', 'malware-technique': 'zararlı → teknik', 'campaign-technique': 'kampanya → teknik' };
  const typeLabel = (t) => (NODE[t] || {}).label || t;
  const icon = (t) => `<i data-lucide="${(NODE[t] || NODE.indicator).icon}" style="color:${(NODE[t] || NODE.indicator).color}"></i>`;

  async function run(q) {
    const out = document.getElementById('sOut');
    out.innerHTML = loading('Aranıyor'); qs.set({ q });
    let d; try { d = await api('/api/search/full', { params: { q } }); } catch (e) { out.innerHTML = empty(e.message, 'circle-alert'); icons(); return; }
    const names = d.names.length ? `<ul class="list">${d.names.map((r) => `<li><a href="${entityUrl(r.EntityType, r.EntityID)}"><span style="display:flex;gap:10px;align-items:center">${icon(r.EntityType)}<span><b class="${r.EntityType === 'indicator' ? 'mono' : ''}">${esc(r.Title)}</b><br><small>${esc(r.Subtitle || '')}</small></span></span><small>${esc(typeLabel(r.EntityType))}</small></a></li>`).join('')}</ul>`
      : '<p class="faint" style="font-size:13px">Ad veya kimlikle eşleşen kayıt yok.</p>';
    const engine = d.engine === 'fulltext' ? 'SQL Server Full-Text (FREETEXTTABLE, alaka puanına göre)' : d.engine === 'like' ? 'LIKE (Full-Text kurulu değil)' : '';
    const ents = d.entities.length ? `<ul class="list">${d.entities.map((r) => `<li><a href="${entityUrl(r.EntityType, r.EntityID)}"><span style="display:flex;gap:10px;align-items:flex-start">${icon(r.EntityType)}<span><b>${esc(r.Title)}</b> <span class="faint mono" style="font-size:11.5px">${esc(r.Sub || '')}</span><br><small>${esc(r.Snippet || '')}</small></span></span><small>${esc(typeLabel(r.EntityType))}${r.Rnk ? ` · ${r.Rnk}` : ''}</small></a></li>`).join('')}</ul>`
      : '<p class="faint" style="font-size:13px">Açıklamalarda eşleşme yok.</p>';
    const evs = d.evidence.length ? `<ul class="list">${d.evidence.map((e) => `<li><div style="display:block"><p style="font-size:13px">${esc(e.Summary)}</p>
        <small>${e.RelType ? `${esc(REL[e.RelType] || e.RelType)}: <a href="${entityUrl(e.RelType.split('-')[0], e.AID)}">${esc(e.AName)}</a> → <a href="${entityUrl(e.BType, e.BID)}">${esc(e.BName)}</a> · ` : ''}${esc(e.SourceName)} · alaka ${e.Rnk}</small></div></li>`).join('')}</ul>` : '';
    out.innerHTML = `<div class="grid g-2">
      <article class="card"><h2>Ad, kimlik ve IOC eşleşmeleri</h2><p class="faint" style="font-size:12px;margin-bottom:8px">sp_GlobalSearch</p>${names}</article>
      <article class="card"><h2>Açıklamalarda geçenler</h2><p class="faint" style="font-size:12px;margin-bottom:8px">${esc(engine) || 'IOC değeri arandığı için metin araması yapılmadı'}</p>${ents}</article>
    </div>${evs ? `<article class="card" style="margin-top:18px"><h2>İlişki kanıtlarında geçenler</h2><p class="faint" style="font-size:12px;margin-bottom:8px">Evidence.Summary tam metin dizini: hangi ilişkiyi desteklediğiyle birlikte</p>${evs}</article>` : ''}`;
    icons();
  }

  document.addEventListener('DOMContentLoaded', () => {
    const f = document.getElementById('sForm'), input = document.getElementById('sq');
    f.addEventListener('submit', (e) => { e.preventDefault(); if (input.value.trim().length >= 2) run(input.value.trim()); });
    const q = qs.get('q'); if (q) { input.value = q; run(q); }
    if (!q) input.focus();
    window.addEventListener('error', (e) => toast(e.message, 'err'));
  });
})();
