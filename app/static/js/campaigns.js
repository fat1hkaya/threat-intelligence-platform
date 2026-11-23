/* Kampanyalar: /api/campaigns */
(() => {
  const { api, esc, fmtN, fmtD, list, typeBadge, sev, graphUrl, qs, num } = TL;
  // "Süren": bitiş tarihi yok ya da son 90 gün içinde. Yalnızca bu vurgulanır; tamamlananlar soluk metin.
  const isOngoing = (r) => !r.EndDate || new Date(r.EndDate) >= new Date(Date.now() - 90 * 864e5);
  const ongoing = (r) => isOngoing(r) ? `<span class="badge b-ok" title="${r.EndDate ? 'Son 90 gün içinde görüldü' : 'Bitiş tarihi yok'}">Süren</span>` : '<span class="faint">Tamamlandı</span>';

  const page = TL.listPage({
    endpoint: '/api/campaigns', title: 'Kampanya detayı', unit: 'kampanya', rowId: (r) => r.CampaignID,
    extra: () => ({ actor: qs.get('actor') }),
    columns: [
      { id: 'name', label: 'Kampanya', primary: true, render: (r) => `<span class="name-id"><b>${esc(r.Name)}</b>${r.ExternalID ? ` <span class="faint mono">${esc(r.ExternalID)}</span>` : ''}</span>` },
      // hep aynı değeri taşıyan sütun bilgi vermez: tüm satırlar tamamlandıysa varsayılan olarak gizli
      { id: 'status', label: 'Durum', priority: 2, hideIfAllZero: isOngoing, render: ongoing },
      { id: 'start', label: 'Başlangıç', priority: 2, render: (r) => r.StartDate ? fmtD(r.StartDate) : '—' },
      { id: 'end', label: 'Bitiş', priority: 3, render: (r) => r.EndDate ? fmtD(r.EndDate) : '—' },
      { id: 'actor', label: 'Aktör', hint: '— : kaynakta bir aktöre atfedilmemiş', render: (r) => r.ActorName ? `<a href="/actors?id=${r.ActorID}">${esc(r.ActorName)}</a>` : TL.unknown('Atfedilmemiş') },
      { id: 'malware', label: 'Zararlı', num: true, priority: 3, render: (r) => num(r.MalwareCount) },
      { id: 'techniques', label: 'Teknik', num: true, render: (r) => num(r.TechniqueCount) },
      { id: 'iocs', label: 'IOC', num: true, hideIfAllZero: (r) => r.IndicatorCount, render: (r) => num(r.IndicatorCount, { strong: true }) },
      { id: 'graph', label: 'İlişki grafı', cls: 'actions', render: (r) => `<a class="btn sm icon ghost" href="${graphUrl('campaign', r.CampaignID)}" aria-label="${esc(r.Name)} ilişki grafı" title="İlişki grafı"><i data-lucide="share-2"></i></a>` },
    ],
    async detail(id) {
      const d = await api(`/api/campaigns/${id}`); const c = d.campaign;
      const steps = [['İlk tespit', c.StartDate, true], ['Son görülme / bitiş', c.EndDate, !!c.EndDate]];
      return `<section><div class="entity-title">${TL.nodeIcon('campaign')}<div><h2>${esc(c.Name)}</h2><span class="muted sub">${c.ExternalID ? `<span class="mono">${esc(c.ExternalID)}</span>` : 'Analist kaydı'}</span></div></div>
          <div class="chips">${ongoing(c)}</div>
          ${TL.clampText(c.Description)}
          ${TL.actions([`<a class="btn sm primary" href="${graphUrl('campaign', c.CampaignID)}"><i data-lucide="share-2"></i>İlişki grafı</a>`, TL.caseBtn('campaign', c.CampaignID, c.Name),
            `<a class="btn sm" href="/attack?campaign=${c.CampaignID}"><i data-lucide="grid-3x3"></i>ATT&amp;CK matrisi</a>`])}</section>
        <section><h3><i data-lucide="user-round-x"></i>İlişkili tehdit aktörü</h3>
          ${c.ActorID ? `<ul class="list"><li><a href="/actors?id=${c.ActorID}"><b>${esc(c.ActorName)}</b><small>atfedildi</small></a></li></ul>
            ${d.attribution ? `<p class="faint" style="font-size:12px">Atıf kanıtı (${esc(d.attribution.EvidenceSource)}): ${esc((d.attribution.Evidence || '').slice(0, 220))}</p>` : '<p class="faint" style="font-size:12px">Atıf için kanıt kaydı yok.</p>'}`
            : '<p class="faint" style="font-size:13px">Bu kampanya kaynakta bir aktöre atfedilmemiş.</p>'}</section>
        <section><h3><i data-lucide="calendar-range"></i>Zaman çizelgesi</h3>
          <ol class="timeline">${steps.map(([l, v, done]) => `<li><span class="dot ${done ? 'done' : ''}"></span><div><b>${l}</b><br><small class="muted">${v ? fmtD(v) : 'Bitiş tarihi yok: devam ediyor sayılır'}</small></div></li>`).join('')}</ol></section>
        <section><h3><i data-lucide="bug"></i>Kullanılan zararlılar (${d.malware.length})</h3>
          ${d.malware.length ? `<div class="chips">${d.malware.map((m) => `<a class="chip" href="/malware?id=${m.MalwareID}">${esc(m.Name)}</a>`).join('')}</div>` : '<p class="faint" style="font-size:13px">Kayıt yok.</p>'}</section>
        <section><h3><i data-lucide="grid-3x3"></i>Öne çıkan teknikler</h3>${TL.techByTactic(d.techniques, 40)}</section>
        <section><h3><i data-lucide="fingerprint"></i>Gözlenen IOC'ler (${d.indicators.length}${d.indicators.length >= 40 ? '+' : ''})</h3>
          ${list(d.indicators.slice(0, 12), (i) => `<li><a href="/iocs/${i.IndicatorID}" title="${esc(i.Value)}"><span class="mono value">${esc(TL.midTruncate(i.Value, 18, 10))}</span>${typeBadge(i.TypeCode)}</a></li>`, 'Bu kampanyaya bağlı IOC yok.')}</section>`;
    },
  });
  document.addEventListener('DOMContentLoaded', page.start);
})();
