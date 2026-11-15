/* Tehdit aktörleri: /api/actors */
(() => {
  const { api, esc, fmtN, fmtD, list, typeBadge, sev, graphUrl } = TL;
  const flagless = (code, name) => code ? `<span class="badge b-muted" title="${esc(name || code)}">${esc(code)}</span> ${esc(name || '')}` : '<span class="faint">—</span>';

  const page = TL.listPage({
    endpoint: '/api/actors', title: 'Aktör detayı', unit: 'aktör', rowId: (r) => r.ActorID,
    columns: [
      { label: 'Aktör', primary: true, render: (r) => `<b>${esc(r.Name)}</b> <span class="faint mono" style="font-size:11.5px">${esc(r.ExternalID || '')}</span>` },
      { label: 'Takma adlar', render: (r) => `<span class="muted" style="font-size:12.5px">${esc((r.Aliases || '').slice(0, 60) || '—')}</span>` },
      { label: 'Köken', render: (r) => r.CountryCode ? `<span class="badge b-muted">${esc(r.CountryCode)}</span>` : '<span class="faint">—</span>' },
      { label: 'Motivasyon', render: (r) => esc(r.Motivation || '—') },
      { label: 'Kampanya', num: true, render: (r) => fmtN(r.CampaignCount) },
      { label: 'Araç', num: true, render: (r) => fmtN(r.MalwareCount) },
      { label: 'Teknik', num: true, render: (r) => fmtN(r.TechniqueCount) },
      { label: 'IOC', num: true, render: (r) => r.IndicatorCount ? `<b>${fmtN(r.IndicatorCount)}</b>` : '<span class="faint">0</span>' },
      { label: '', render: (r) => `<a class="btn sm icon ghost" href="${graphUrl('actor', r.ActorID)}" aria-label="${esc(r.Name)} ilişki grafı" title="İlişki grafı"><i data-lucide="share-2"></i></a>` },
    ],
    async detail(id) {
      const d = await api(`/api/actors/${id}`); const a = d.actor;
      return `<section><div class="entity-title">${TL.nodeIcon('actor')}<div><h2>${esc(a.Name)}</h2><span class="muted mono" style="font-size:12px">${esc(a.ExternalID || 'Analist kaydı')}</span></div></div>
          ${d.aliases.length ? `<div class="chips">${d.aliases.slice(0, 12).map((x) => `<span class="chip">${esc(x)}</span>`).join('')}</div>` : ''}
          <dl class="kv"><dt>Köken</dt><dd>${flagless(a.CountryCode, a.CountryName)}</dd><dt>Motivasyon</dt><dd>${esc(a.Motivation || 'Bilinmiyor')}</dd>
            <dt>Hedef sektör</dt><dd>${d.sectors.length ? d.sectors.map((s) => esc(s.Name)).join(', ') : '—'}</dd></dl>
          ${a.Description ? `<p class="desc">${esc(a.Description)}</p>` : ''}
          <p class="faint" style="font-size:11.5px">Köken ülke, motivasyon ve sektör ATT&amp;CK açıklamasından anahtar sözcükle çıkarılmıştır (sezgisel).</p>
          <div class="chips"><a class="btn sm" href="${graphUrl('actor', a.ActorID)}"><i data-lucide="share-2"></i>İlişki grafı</a>${TL.caseBtn('actor', a.ActorID, a.Name)}
            <a class="btn sm" href="/attack?actor=${a.ActorID}"><i data-lucide="grid-3x3"></i>ATT&amp;CK matrisinde göster</a>
            <a class="btn sm" href="/api/export/navigator/actor/${a.ActorID}" download title="MITRE ATT&amp;CK Navigator'da açılabilen katman dosyası (JSON)"><i data-lucide="download"></i>Navigator katmanı</a>
            <a class="btn sm" href="/api/export/stix/actor/${a.ActorID}" download title="STIX 2.1 paketi: aktör, araçları ve teknikleri"><i data-lucide="download"></i>STIX 2.1</a></div></section>
        <section><h3><i data-lucide="target"></i>Kampanyalar (${d.campaigns.length})</h3>${list(d.campaigns.slice(0, 8), (c) => `<li><a href="/campaigns?id=${c.CampaignID}"><span>${esc(c.Name)}</span><small>${c.StartDate ? fmtD(c.StartDate) : ''}</small></a></li>`, 'Atfedilen kampanya yok.')}</section>
        <section><h3><i data-lucide="bug"></i>Kullandığı zararlı/araçlar (${d.malware.length})</h3>${list(d.malware.slice(0, 10), (m) => `<li><a href="/malware?id=${m.MalwareID}"><span>${esc(m.Name)}</span><small>${esc(m.TypeName)}${m.IndicatorCount ? ` · ${m.IndicatorCount} IOC` : ''}</small></a></li>`)}</section>
        <section><h3><i data-lucide="grid-3x3"></i>ATT&amp;CK teknikleri (${new Set(d.techniques.map((t) => t.ExternalID)).size})</h3><p class="faint" style="font-size:12px">fn_ActorTechniques tablo değerli fonksiyonu</p>${TL.techByTactic(d.techniques)}</section>
        <section><h3><i data-lucide="fingerprint"></i>Atfedilen IOC'ler</h3>${list(d.indicators, (i) => `<li><a href="/iocs/${i.IndicatorID}"><span class="mono value" style="max-width:210px">${esc(i.Value)}</span><small>${esc(i.ViaName)}</small></a></li>`, 'Bu aktöre atfedilen IOC yok.')}</section>
        <section><h3><i data-lucide="users"></i>Benzer aktörler</h3><p class="faint" style="font-size:12px">Ortak teknik oranı (Jaccard benzerliği)</p>${list(d.similar, (s) => `<li><a href="/actors?id=${s.ActorID}"><span>${esc(s.Name)}</span><small>%${s.Similarity} · ${s.Shared} ortak teknik</small></a></li>`, 'Benzer aktör yok.')}</section>`;
    },
  });

  document.addEventListener('DOMContentLoaded', async () => {
    const m = await TL.meta();
    const fill = (id, rows, v, l) => document.getElementById(id).insertAdjacentHTML('beforeend', rows.map((r) => `<option value="${esc(r[v])}">${esc(r[l])}</option>`).join(''));
    fill('country', m.countries, 'CountryCode', 'Name'); fill('motivation', m.motivations, 'Name', 'Name'); fill('sector', m.sectors, 'SectorID', 'Name');
    page.start();
  });
})();
