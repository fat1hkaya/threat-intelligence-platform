/* Genel bakış: /api/dashboard/summary */
(() => {
  const { api, esc, fmtN, fmtDT, ago, sev, typeBadge, job, sourceBadge, TYPE_LABEL, SEV, icons, empty, toast, pct } = TL;
  const SEV_COLORS = { critical: '#F87171', high: '#FB923C', medium: '#FBBF24', low: '#34D399', info: '#60A5FA' };
  let sevChart, trendChart;

  const delta = (now, prev) => {
    if (!prev) return now ? 'Karşılaştırma yok: önceki dönemde kayıt bulunmuyor' : 'Bu dönemde yeni kayıt yok';
    const d = Math.round(((now - prev) / prev) * 1000) / 10;
    return `<span class="${d >= 0 ? 'delta-up' : 'delta-down'}">${d >= 0 ? '▲' : '▼'} %${Math.abs(d).toLocaleString('tr-TR')}</span> önceki döneme göre`;
  };
  const bars = (el, rows, label, value, href) => {
    const max = Math.max(1, ...rows.map(value));
    el.innerHTML = rows.length ? rows.map((r) => `<div class="bar-row"><span title="${esc(label(r))}">${href ? `<a href="${href(r)}">${esc(label(r))}</a>` : esc(label(r))}</span>
      <span class="track" aria-hidden="true"><i style="width:${(value(r) / max) * 100}%"></i></span><b>${fmtN(value(r))}</b></div>`).join('')
      : empty('Henüz veri yok.');
  };


  // Dikkat gerektirenler: sayı sıfırdan büyükse ve önemliyse vurgulanır; her öğe ilgili ekrana götürür
  async function attention() {
    const box = document.getElementById('attention');
    let a;
    try { a = await api('/api/dashboard/attention'); } catch (e) { box.innerHTML = empty(e.message, 'circle-alert'); icons(); return; }
    const since = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
    const items = [
      { icon: 'siren', tone: a.HighRisk24h ? 'bad' : 'ok', n: a.HighRisk24h, label: 'yüksek riskli IOC son 24 saatte görüldü',
        href: `/iocs?severity=high,critical&status=active&dateFrom=${since}` },
      { icon: 'eye', tone: a.Sighted7d ? 'warn' : 'ok', n: a.Sighted7d, label: 'IOC son 7 günde kurum içinde görüldü', href: '/hunt' },
      { icon: 'briefcase', tone: a.OpenCases ? 'info' : 'ok', n: a.OpenCases, label: a.InvestigatingCases ? `açık vaka, ${fmtN(a.InvestigatingCases)} tanesi inceleniyor` : 'açık vaka', href: '/cases' },
      { icon: 'triangle-alert', tone: a.FailedJobs7d ? 'bad' : 'ok', n: a.FailedJobs7d, label: 'başarısız içe aktarma veya bakım işi (7 gün)', href: '/sources' },
      a.CoverageMarked
        ? { icon: 'shield-half', tone: a.BlindSpots ? 'warn' : 'ok', n: a.BlindSpots, label: 'kör nokta: 10+ aktörün kullandığı, tespit edilemeyen teknik', href: '/attack?view=coverage' }
        : { icon: 'shield-half', tone: 'muted', n: null, label: 'Tespit kapsamı henüz girilmedi. Hangi teknikleri görebildiğinizi işaretleyin.', href: '/attack?view=coverage' },
    ];
    box.innerHTML = items.map((i) => `<a class="att-item tone-${i.tone}" href="${i.href}">
        <span class="att-ic"><i data-lucide="${i.icon}"></i></span>
        <span class="att-body">${i.n == null ? '' : `<b class="att-n">${fmtN(i.n)}</b>`}<span class="att-label">${esc(i.label)}</span></span>
        <i data-lucide="chevron-right" class="att-go" aria-hidden="true"></i></a>`).join('');
    document.getElementById('attSync').textContent = a.LastSyncAt ? `Son besleme senkronu ${ago(a.LastSyncAt)}` : 'Henüz besleme senkronu yok';
    icons();
  }

  async function load() {
    const days = +document.getElementById('days').value;
    let d;
    try { d = await api('/api/dashboard/summary', { params: { days } }); } catch (e) { toast(e.message, 'err'); return; }
    const k = d.kpi;
    document.getElementById('kpis').innerHTML = [
      ['database', '', "Toplam IOC", k.TotalIOCs, `${fmtN(k.ActiveIOCs)} aktif · ${fmtN(k.NewIOCs)} yeni${k.PrevNewIOCs ? ` · ${delta(k.NewIOCs, k.PrevNewIOCs)}` : ''}`],
      ['users', 'r', 'Tehdit aktörü', k.Actors, `${fmtN(k.ActorsWithIOCs)} tanesi IOC'lerimizle ilişkili`],
      ['bug', 'c', 'Zararlı yazılım ailesi', k.MalwareFamilies, `${fmtN(k.FamiliesWithIOCs)} ailenin IOC'si var`],
      ['triangle-alert', 'a', 'Yüksek riskli IOC', k.HighRiskIOCs, `aktif · son ${days} günde ${fmtN(k.NewHighRiskIOCs)} yeni`],
    ].map(([icon, c, lbl, val, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${icon}"></i></span>
      <div><div class="lbl">${lbl}</div><div class="val">${fmtN(val)}</div><div class="sub">${sub}</div></div></article>`).join('');
    if (!k.PrevNewIOCs) document.querySelector('#kpis .kpi .sub')?.setAttribute('title', 'Önceki dönemde kayıt olmadığı için karşılaştırma yapılmadı');

    // Önem halkası
    const sevRows = d.bySeverity.filter((r) => r.Total > 0);
    const total = sevRows.reduce((a, r) => a + r.Total, 0);
    document.getElementById('sevLegend').innerHTML = sevRows.map((r) => `<li><a href="/iocs?severity=${r.Code}&status=active"><i class="sev-dot sev-${r.Code}"></i><span>${esc(SEV[r.Code])}</span><b>${fmtN(r.Total)} <span class="faint">%${pct(r.Total, total).toLocaleString('tr-TR')}</span></b></a></li>`).join('');
    document.getElementById('sevSummary').textContent = 'Önem dağılımı: ' + sevRows.map((r) => `${SEV[r.Code]} ${r.Total}`).join(', ');
    document.getElementById('sevTotal').textContent = `${fmtN(total)} aktif IOC`;
    document.getElementById('sevStack').innerHTML = sevRows.map((r) => `<i class="sev-seg sev-${r.Code}" style="flex-grow:${r.Total}" title="${esc(SEV[r.Code])}: ${fmtN(r.Total)}"></i>`).join('');

    bars(document.getElementById('typeBars'), d.byType, (r) => TYPE_LABEL[r.Code] || r.Name, (r) => r.Total, (r) => `/iocs?type=${r.Code}`);

    // Eğilim
    document.getElementById('trendTitle').textContent = `Son ${days} günde eklenen IOC'ler`;
    const sum = d.trend.reduce((a, r) => a + r.Added, 0);
    document.getElementById('trendNote').textContent = `${fmtN(sum)} kayıt, ilk görülme tarihine göre`;
    document.getElementById('trendSummary').textContent = `Son ${days} günde toplam ${sum} IOC eklendi. En yoğun gün: ` +
      (() => { const m = d.trend.reduce((a, r) => (r.Added > a.Added ? r : a), d.trend[0] || { Added: 0 }); return m ? `${m.Day} (${m.Added})` : '-'; })();
    trendChart?.destroy();
    trendChart = new Chart(document.getElementById('trendChart'), {
      type: 'bar',
      data: { labels: d.trend.map((r) => new Date(r.Day + 'T00:00:00').toLocaleDateString('tr-TR', { day: '2-digit', month: 'short' })),
        datasets: [{ data: d.trend.map((r) => r.Added), backgroundColor: (c) => { const g = c.chart.ctx.createLinearGradient(0, 0, 0, 240); g.addColorStop(0, '#7C5CFC'); g.addColorStop(1, '#22D3EE'); return g; }, borderRadius: 3, maxBarThickness: 14 }] },
      options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { beginAtZero: true, ticks: { precision: 0 } } } },
    });

    document.getElementById('latest').innerHTML = d.latest.length ? TL.table([
      { label: 'IOC', primary: true, render: (r) => `<span class="cell-ioc"><a class="mono value" style="max-width:240px" href="/iocs/${r.IndicatorID}" title="${esc(r.Value)}">${esc(r.Value)}</a></span>` },
      { label: 'Tip', render: (r) => typeBadge(r.TypeCode) },
      { label: 'Önem', render: (r) => sev(r.SeverityCode) },
      { label: 'İlişkili varlık', render: (r) => r.MalwareName || r.CampaignName ? esc([r.MalwareName, r.CampaignName].filter(Boolean).join(' · ')) : '<span class="faint">—</span>' },
      { label: 'Kaynak', render: (r) => sourceBadge(r.SourceName) },
      { label: 'Son görülme', render: (r) => `<span title="${fmtDT(r.LastSeen)}">${ago(r.LastSeen)}</span>` },
    ], d.latest, { caption: 'Son istihbarat' }) : empty('Henüz IOC yok. Veri kaynaklarından içe aktarma yapın.', 'inbox');

    document.getElementById('sources').innerHTML = d.sources.map((s) => `<li><a href="/sources?source=${s.SourceID}">
      <span><b>${esc(s.Name)}</b><br><small>${s.LastRunAt ? `Son iş: ${fmtDT(s.LastRunAt)}` : 'Henüz içe aktarma yapılmadı'} · ${fmtN(s.IndicatorCount)} IOC</small></span>
      ${s.LastRunStatus ? job(s.LastRunStatus) : '<span class="badge b-muted">Bekliyor</span>'}</a></li>`).join('');

    bars(document.getElementById('topTech'), d.topTechniques, (r) => `${r.ExternalID} ${r.Name}`, (r) => r.ActorCount, (r) => `/attack?id=${r.TechniqueID}`);
    bars(document.getElementById('topMal'), d.topMalware, (r) => r.Name, (r) => r.IndicatorCount, (r) => `/malware?id=${r.MalwareID}`);
    icons();
  }
  document.addEventListener('DOMContentLoaded', () => { document.getElementById('days').addEventListener('change', load); attention(); load(); });
})();
