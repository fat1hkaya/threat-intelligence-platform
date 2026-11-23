/* Genel bakış: /api/dashboard/summary */
(() => {
  const { api, esc, fmtN, fmtDT, ago, sev, typeBadge, job, sourceBadge, iocCell, TYPE_LABEL, SEV, icons, empty, toast, pct } = TL;
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
    // Her kart aynı biçimde: ikon, sayı, tek satır etiket, ok. 0 olanlar soluk; >0 olanların sol kenarı önem renginde.
    const items = [
      { icon: 'siren', tone: 'bad', n: a.HighSeverity24h, label: 'son 24 saatte yüksek önem', title: 'Son 24 saatte görülen, önemi yüksek ya da kritik olan aktif IOC sayısı',
        href: `/iocs?severity=high,critical&status=active&dateFrom=${since}` },
      { icon: 'eye', tone: 'warn', n: a.Sighted7d, label: 'kurumda görüldü · 7 gün', title: 'Son 7 günde kurum içinde görülen (görülme kaydı olan) IOC', href: '/hunt' },
      { icon: 'briefcase', tone: 'info', n: a.OpenCases, label: a.InvestigatingCases ? `açık vaka · ${fmtN(a.InvestigatingCases)} inceleme` : 'açık vaka', title: 'Kapatılmamış vakalar', href: '/cases' },
      { icon: 'triangle-alert', tone: 'bad', n: a.FailedJobs7d, label: 'başarısız iş · 7 gün', title: 'Son 7 günde başarısız olan içe aktarma veya bakım işi', href: '/sources' },
      a.CoverageMarked
        ? { icon: 'shield-half', tone: 'warn', n: a.BlindSpots, label: 'kör nokta tekniği', title: '10 ya da daha fazla aktörün kullandığı, tespit edilemeyen teknik', href: '/attack?view=coverage' }
        : { icon: 'shield-half', tone: 'action', n: '%0', label: 'tespit kapsamı', cta: 'Başla', title: 'Tespit kapsamı henüz girilmedi: hangi teknikleri görebildiğinizi işaretleyin', href: '/attack?view=coverage' },
    ];
    box.innerHTML = items.map((i) => {
      const zero = typeof i.n === 'number' && !i.n;
      return `<a class="att-item ${zero ? 'is-zero' : `tone-${i.tone}`}" href="${i.href}" title="${esc(i.title)}">
        <span class="att-ic"><i data-lucide="${i.icon}"></i></span>
        <span class="att-body"><b class="att-n">${typeof i.n === 'number' ? fmtN(i.n) : esc(i.n)}</b><span class="att-label">${esc(i.label)}${i.cta ? ` · <span class="att-cta">${esc(i.cta)}</span>` : ''}</span></span>
        <i data-lucide="chevron-right" class="att-go" aria-hidden="true"></i></a>`;
    }).join('');
    document.getElementById('attSync').textContent = a.LastSyncAt ? `Son besleme senkronu ${ago(a.LastSyncAt)}` : 'Henüz besleme senkronu yok';
    icons();
  }

  async function load() {
    const days = +document.getElementById('days').value;
    let d;
    try { d = await api('/api/dashboard/summary', { params: { days } }); } catch (e) { toast(e.message, 'err'); return; }
    const k = d.kpi;
    document.getElementById('kpis').innerHTML = [
      ['database', '', "Toplam IOC", k.TotalIOCs, (k.ActiveIOCs === k.NewIOCs ? `${fmtN(k.ActiveIOCs)} aktif, tümü son ${days} günde eklendi`
        : `${fmtN(k.ActiveIOCs)} aktif · ${fmtN(k.NewIOCs)} yeni`) + (k.PrevNewIOCs ? ` · ${delta(k.NewIOCs, k.PrevNewIOCs)}` : '')],
      ['users', 'r', 'Tehdit aktörü', k.Actors, `${fmtN(k.ActorsWithIOCs)} tanesi IOC'lerimizle ilişkili`],
      ['bug', 'c', 'Zararlı yazılım ailesi', k.MalwareFamilies, `${fmtN(k.FamiliesWithIOCs)} ailenin IOC'si var`],
      ['triangle-alert', 'a', 'Yüksek veya kritik önemli', k.HighSeverityIOCs, `tümü · risk skoru ${k.HighRiskMin} ve üstü: ${fmtN(k.HighRiskIOCs)}`,
        'Önemi yüksek ya da kritik olan tüm aktif IOC sayısı (zaman sınırı yok)'],
    ].map(([icon, c, lbl, val, sub, tip]) => `<article class="card kpi"${tip ? ` title="${esc(tip)}"` : ''}><span class="ic ${c}"><i data-lucide="${icon}"></i></span>
      <div><div class="val">${fmtN(val)}</div><div class="lbl">${lbl}</div><div class="sub">${sub}</div></div></article>`).join('');

    // Önem halkası
    // Risk skoru bantları (Ayarlar > Risk eşikleri). Sıfır olan bantlar da listelenir.
    const RISK_CLS = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
    const sevRows = d.byRisk.map((r) => ({ ...r, Code: RISK_CLS[r.Code] || 'info' }));
    const total = sevRows.reduce((a, r) => a + r.Total, 0);
    const label = (r) => `${r.Name} (${r.MinScore}+)`;
    document.getElementById('sevLegend').innerHTML = sevRows.map((r) => `<li><a href="/iocs?minRisk=${r.MinScore}&maxRisk=${(d.byRisk[d.byRisk.findIndex((b) => b.Code === r.Code) - 1] || { MinScore: 101 }).MinScore - 1}&status=active" class="${r.Total ? '' : 'is-zero'}"><i class="sev-dot sev-${r.Code}"></i><span>${esc(label(r))}</span><b>${fmtN(r.Total)} <span class="faint">%${pct(r.Total, total).toLocaleString('tr-TR')}</span></b></a></li>`).join('');
    document.getElementById('sevSummary').textContent = 'Risk skoru dağılımı: ' + sevRows.map((r) => `${r.Name} ${r.Total}`).join(', ');
    const top = sevRows.filter((r) => r.Code === 'critical' || r.Code === 'high').reduce((a, r) => a + r.Total, 0);
    document.getElementById('riskNote').textContent = top ? '' : 'Yüksek ve kritik banda çıkmak için IOC\'nin kurum içinde görülmüş olması gerekir (görülme sayısı skora eklenir).';
    document.getElementById('sevTotal').textContent = "Aktif IOC'ler, Ayarlar'daki bant eşiklerine göre";
    document.getElementById('sevStack').innerHTML = sevRows.filter((r) => r.Total).map((r) => `<i class="sev-seg sev-${r.Code}" style="flex-grow:${r.Total}" title="${esc(label(r))}: ${fmtN(r.Total)}"></i>`).join('');

    bars(document.getElementById('typeBars'), d.byType, (r) => TYPE_LABEL[r.Code] || r.Name, (r) => r.Total, (r) => `/iocs?type=${r.Code}`);

    // Eğilim
    document.getElementById('trendTitle').textContent = `Son ${days} günde eklenen IOC'ler`;
    const sum = d.trend.reduce((a, r) => a + r.Added, 0);
    document.getElementById('trendNote').textContent = 'İlk görülme tarihine göre';
    document.getElementById('trendSummary').textContent = `Son ${days} günde toplam ${sum} IOC eklendi. En yoğun gün: ` +
      (() => { const m = d.trend.reduce((a, r) => (r.Added > a.Added ? r : a), d.trend[0] || { Added: 0 }); return m ? `${m.Day} (${m.Added})` : '-'; })();
    trendChart?.destroy();
    const dayLbl = (day) => new Date(day + 'T00:00:00').toLocaleDateString('tr-TR', { day: 'numeric', month: 'short' });
    // İlk içe aktarmadan önceki günler boşsa o gün işaretlenir: boşluk "IOC yoktu" değil, "henüz veri çekilmiyordu" demektir
    const firstIdx = k.FirstImportDay ? d.trend.findIndex((r) => r.Day >= k.FirstImportDay) : -1;
    const markIdx = firstIdx > 0 && d.trend.slice(0, firstIdx).every((r) => !r.Added) ? firstIdx : -1;
    const marker = {
      id: 'firstImport',
      afterDatasetsDraw(chart) {
        if (markIdx < 0) return;
        const { ctx, chartArea: ca, scales: { x } } = chart;
        const px = x.getPixelForValue(markIdx) - (x.getPixelForValue(1) - x.getPixelForValue(0)) / 2;
        const css = getComputedStyle(document.documentElement);
        ctx.save(); ctx.strokeStyle = css.getPropertyValue('--text-3').trim() || '#64748B'; ctx.setLineDash([4, 4]); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(px, ca.top); ctx.lineTo(px, ca.bottom); ctx.stroke(); ctx.setLineDash([]);
        ctx.fillStyle = css.getPropertyValue('--text-2').trim() || '#94A3B8'; ctx.font = '12px Geist, system-ui, sans-serif';
        const txt = `İlk içe aktarma: ${dayLbl(d.trend[markIdx].Day)}`, w = ctx.measureText(txt).width;
        const right = px - ca.left > w + 8;
        ctx.textAlign = right ? 'right' : 'left';
        ctx.fillText(txt, right ? px - 6 : px + 6, ca.top + 12); ctx.restore();
      },
    };
    trendChart = new Chart(document.getElementById('trendChart'), {
      type: 'bar',
      data: { labels: d.trend.map((r) => dayLbl(r.Day)),
        datasets: [{ data: d.trend.map((r) => r.Added), backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--accent').trim(), borderRadius: 3, maxBarThickness: 14 }] },
      options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 6, maxRotation: 0, minRotation: 0, autoSkipPadding: 12 } }, y: { beginAtZero: true, ticks: { precision: 0 } } } },
      plugins: [marker],
    });

    document.getElementById('latest').innerHTML = d.latest.length ? TL.table([
      { label: 'IOC', primary: true, render: (r) => iocCell(r.Value, { href: `/iocs/${r.IndicatorID}` }) },
      { label: 'Tip', render: (r) => typeBadge(r.TypeCode) },
      { label: 'Önem', render: (r) => sev(r.SeverityCode) },
      { label: 'Zararlı ailesi', priority: 2, render: (r) => { const v = [r.MalwareName, r.CampaignName].filter(Boolean).join(' · ');
        return r.MalwarePlaceholder ? '<span class="faint">Ailesi belirlenmemiş</span>' : v ? `<span class="trunc" title="${esc(v)}">${esc(v)}</span>` : '<span class="faint">—</span>'; } },
      { label: 'Kaynak', render: (r) => sourceBadge(r.SourceName) },
      { label: 'Son görülme', render: (r) => `<span class="nowrap" title="${fmtDT(r.LastSeen)}">${ago(r.LastSeen)}</span>` },
    ], d.latest, { caption: 'Son istihbarat' }) : empty('Henüz IOC yok. Veri kaynaklarından içe aktarma yapın.', 'inbox');

    // Her satırda durum rozeti; son işin getirdiği yeni kayıt ve kaynağın toplamı, kaynağın kendi birimiyle
    const srcState = (x) => !x.IsActive ? '<span class="badge b-muted">Kapalı</span>' : x.LastRunStatus ? job(x.LastRunStatus) : '<span class="badge b-muted">Bekliyor</span>';
    document.getElementById('sources').innerHTML = d.sources.map((x) => `<li class="${x.IsActive ? '' : 'is-off'}"><a href="/sources?source=${x.SourceID}">
      <span><b>${esc(x.Name)}</b><br><small title="${x.LastRunAt ? `Son iş: ${fmtDT(x.LastRunAt)}` : ''}">${x.LastRunAt
        ? `+${fmtN(x.LastRowsInserted || 0)} yeni · toplam ${fmtN(x.UnitCount || 0)} ${esc(x.UnitLabel || 'IOC')} · ${ago(x.LastRunAt)}`
        : `Henüz içe aktarma yapılmadı · toplam ${fmtN(x.UnitCount || 0)} ${esc(x.UnitLabel || 'IOC')}`}</small></span>
      ${srcState(x)}</a></li>`).join('');

    // Teknik kodu ayrı dar sütunda, ad kesilmeden (gerekirse iki satıra sarılır)
    const tmax = Math.max(1, ...d.topTechniques.map((r) => r.ActorCount));
    document.getElementById('topTech').innerHTML = d.topTechniques.length ? d.topTechniques.map((r) => `<div class="bar-row tech-row">
      <span class="mono tcode">${esc(r.ExternalID)}</span><a class="tname" href="/attack?id=${r.TechniqueID}">${esc(r.Name)}</a>
      <span class="track" aria-hidden="true"><i style="width:${(r.ActorCount / tmax) * 100}%"></i></span><b>${fmtN(r.ActorCount)}</b></div>`).join('') : empty('Henüz veri yok.');
    bars(document.getElementById('topMal'), d.topMalware, (r) => r.Name, (r) => r.IndicatorCount, (r) => `/malware?id=${r.MalwareID}`);
    icons();
  }
  document.addEventListener('DOMContentLoaded', () => { document.getElementById('days').addEventListener('change', load); attention(); load(); });
})();
