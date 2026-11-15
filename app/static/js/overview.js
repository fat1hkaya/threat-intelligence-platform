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

  async function load() {
    const days = +document.getElementById('days').value;
    let d;
    try { d = await api('/api/dashboard/summary', { params: { days } }); } catch (e) { toast(e.message, 'err'); return; }
    const k = d.kpi;
    document.getElementById('kpis').innerHTML = [
      ['database', '', "Toplam IOC", k.TotalIOCs, `${fmtN(k.ActiveIOCs)} aktif · son ${days} günde ${fmtN(k.NewIOCs)} yeni<br>${delta(k.NewIOCs, k.PrevNewIOCs)}`],
      ['users', 'r', 'Tehdit aktörü', k.Actors, `${fmtN(k.ActorsWithIOCs)} tanesi elimizdeki IOC'lerle ilişkili`],
      ['bug', 'c', 'Zararlı yazılım ailesi', k.MalwareFamilies, `${fmtN(k.FamiliesWithIOCs)} ailenin IOC'si var`],
      ['triangle-alert', 'a', 'Yüksek riskli IOC', k.HighRiskIOCs, `Yüksek + kritik, aktif · son ${days} günde ${fmtN(k.NewHighRiskIOCs)} yeni`],
    ].map(([icon, c, lbl, val, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${icon}"></i></span>
      <div><div class="lbl">${lbl}</div><div class="val">${fmtN(val)}</div><div class="sub">${sub}</div></div></article>`).join('');

    // Önem halkası
    const sevRows = d.bySeverity.filter((r) => r.Total > 0);
    const total = sevRows.reduce((a, r) => a + r.Total, 0);
    document.getElementById('sevLegend').innerHTML = sevRows.map((r) => `<li><i style="background:${SEV_COLORS[r.Code]}"></i><span>${esc(SEV[r.Code])}</span><b>${fmtN(r.Total)} <span class="faint">(%${pct(r.Total, total).toLocaleString('tr-TR')})</span></b></li>`).join('');
    document.getElementById('sevSummary').textContent = 'Önem dağılımı: ' + sevRows.map((r) => `${SEV[r.Code]} ${r.Total}`).join(', ');
    sevChart?.destroy();
    sevChart = new Chart(document.getElementById('sevChart'), {
      type: 'doughnut',
      data: { labels: sevRows.map((r) => SEV[r.Code]), datasets: [{ data: sevRows.map((r) => r.Total), backgroundColor: sevRows.map((r) => SEV_COLORS[r.Code]), borderColor: '#111A2E', borderWidth: 3 }] },
      options: { cutout: '68%', maintainAspectRatio: false },
      plugins: [{ id: 'center', afterDraw(c) { const { ctx, chartArea: a } = c; ctx.save(); ctx.textAlign = 'center'; ctx.fillStyle = '#F1F5F9';
        ctx.font = '700 22px Inter'; ctx.fillText(fmtN(total), (a.left + a.right) / 2, (a.top + a.bottom) / 2 + 4);
        ctx.font = '12px Inter'; ctx.fillStyle = '#94A3B8'; ctx.fillText('aktif IOC', (a.left + a.right) / 2, (a.top + a.bottom) / 2 + 22); ctx.restore(); } }],
    });

    bars(document.getElementById('typeBars'), d.byType, (r) => TYPE_LABEL[r.Code] || r.Name, (r) => r.Total, (r) => `/iocs?type=${r.Code}`);

    // Eğilim
    document.getElementById('trendTitle').textContent = `Son ${days} günde eklenen IOC'ler`;
    const sum = d.trend.reduce((a, r) => a + r.Added, 0);
    document.getElementById('trendNote').textContent = `${fmtN(sum)} kayıt (FirstSeen'e göre)`;
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
  document.addEventListener('DOMContentLoaded', () => { document.getElementById('days').addEventListener('change', load); load(); });
})();
