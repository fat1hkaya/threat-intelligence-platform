/* Kampanyalar: /api/campaigns */
(() => {
  const { api, esc, fmtN, fmtD, list, typeBadge, sev, graphUrl, qs } = TL;
  const ongoing = (r) => r.EndDate ? '<span class="badge b-muted">Tamamlandı</span>' : '<span class="badge b-ok">Devam ediyor</span>';

  const page = TL.listPage({
    endpoint: '/api/campaigns', title: 'Kampanya detayı', unit: 'kampanya', rowId: (r) => r.CampaignID,
    extra: () => ({ actor: qs.get('actor') }),
    columns: [
      { label: 'Kampanya', primary: true, render: (r) => `<b>${esc(r.Name)}</b> <span class="faint mono" style="font-size:11.5px">${esc(r.ExternalID || '')}</span>` },
      { label: 'Durum', render: ongoing },
      { label: 'Başlangıç', render: (r) => r.StartDate ? fmtD(r.StartDate) : '—' },
      { label: 'Bitiş', render: (r) => r.EndDate ? fmtD(r.EndDate) : '—' },
      { label: 'Aktör', render: (r) => r.ActorName ? `<a href="/actors?id=${r.ActorID}">${esc(r.ActorName)}</a>` : '<span class="faint">Atfedilmemiş</span>' },
      { label: 'Zararlı', num: true, render: (r) => fmtN(r.MalwareCount) },
      { label: 'Teknik', num: true, render: (r) => fmtN(r.TechniqueCount) },
      { label: 'IOC', num: true, render: (r) => r.IndicatorCount ? `<b>${fmtN(r.IndicatorCount)}</b>` : '<span class="faint">0</span>' },
      { label: '', render: (r) => `<a class="btn sm icon ghost" href="${graphUrl('campaign', r.CampaignID)}" aria-label="İlişki grafı" title="İlişki grafı"><i data-lucide="share-2"></i></a>` },
    ],
    async detail(id) {
      const d = await api(`/api/campaigns/${id}`); const c = d.campaign;
      const steps = [['İlk tespit', c.StartDate, true], ['Son görülme / bitiş', c.EndDate, !!c.EndDate]];
      return `<section><div class="entity-title">${TL.nodeIcon('campaign')}<div><h2>${esc(c.Name)}</h2><span class="muted mono" style="font-size:12px">${esc(c.ExternalID || 'Analist kaydı')}</span></div></div>
          <div class="chips">${ongoing(c)}</div>
          ${c.Description ? `<p class="desc">${esc(c.Description)}</p>` : ''}
          <div class="chips"><a class="btn sm" href="${graphUrl('campaign', c.CampaignID)}"><i data-lucide="share-2"></i>İlişki grafı</a>${TL.caseBtn('campaign', c.CampaignID, c.Name)}
            <a class="btn sm" href="/attack?campaign=${c.CampaignID}"><i data-lucide="grid-3x3"></i>Teknikleri ATT&amp;CK'te göster</a></div></section>
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
          ${list(d.indicators.slice(0, 12), (i) => `<li><a href="/iocs/${i.IndicatorID}"><span class="mono value" style="max-width:220px">${esc(i.Value)}</span>${typeBadge(i.TypeCode)}</a></li>`, 'Bu kampanyaya bağlı IOC yok.')}</section>`;
    },
  });
  document.addEventListener('DOMContentLoaded', page.start);
})();
