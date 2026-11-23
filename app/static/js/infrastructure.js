/* Altyapı örtüşmesi: /api/infrastructure */
(() => {
  const { api, esc, fmtN, fmtDT, table, empty, loading, icons, toast } = TL;
  let regionNames;
  try { regionNames = new Intl.DisplayNames(['tr'], { type: 'region' }); } catch { regionNames = null; }
  const country = (cc) => (cc ? `${esc((regionNames && regionNames.of(cc)) || cc)} <span class="faint mono">${esc(cc)}</span>` : '—');
  TL.countryName = country;

  async function load() {
    ['subnets', 'asns'].forEach((k) => { document.getElementById(k).innerHTML = loading(); });
    let d;
    try { d = await api('/api/infrastructure'); } catch (e) { toast(e.message, 'err'); return; }
    const s = d.summary;
    document.getElementById('noRanges').hidden = s.Ranges > 0;
    document.getElementById('kpis').innerHTML = [
      ['network', '', 'IPv4 IOC', s.IpIOCs, 'sayısal adrese çevrildi'],
      ['building-2', 'c', 'ASN ile eşlenen', s.Enriched, s.IpIOCs ? `%${Math.round((s.Enriched / s.IpIOCs) * 100)}` : ''],
      ['server', 'a', 'Farklı ASN', s.DistinctASNs, 'IOC barındıran sağlayıcı'],
      ['database', '', 'IP aralığı', s.Ranges, s.RangesLoadedAt ? `yüklendi ${fmtDT(s.RangesLoadedAt)}` : 'yüklenmedi'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="val">${fmtN(v || 0)}</div><div class="lbl">${l}</div><div class="sub">${sub}</div></div></article>`).join('');

    document.getElementById('subnets').innerHTML = d.subnets.length ? table([
      { label: 'Alt ağ', primary: true, render: (r) => `<span class="mono">${esc(r.Subnet)}</span>` },
      { label: 'IOC', num: true, render: (r) => fmtN(r.IOCs) },
      { label: 'Aile', num: true, render: (r) => `<b class="${r.Families >= 2 ? 'cov-0' : ''}">${r.Families}</b>` },
      { label: 'Zararlı aileleri', render: (r) => esc(r.FamilyNames || '—') },
      { label: 'ASN', render: (r) => esc(r.ASName || '—') },
      { label: '', render: (r) => `<details><summary class="btn sm ghost">IOC'ler</summary><div class="chips" style="margin-top:6px;max-width:320px">${r.IndicatorIDs.map((id) => `<a class="badge b-muted" href="/iocs/${id}">#${id}</a>`).join('')}</div></details>` },
    ], d.subnets, { caption: 'Paylaşılan alt ağlar' }) : empty('Birden çok IOC barındıran /24 alt ağ yok.', 'network');

    document.getElementById('asns').innerHTML = d.asns.length ? table([
      { label: 'ASN', primary: true, render: (r) => `<span class="mono">AS${r.ASN}</span> ${esc(r.ASName)}` },
      { label: 'Ülke', render: (r) => country(r.CountryCode) },
      { label: 'IOC', num: true, render: (r) => `${fmtN(r.IOCs)} <small class="faint">${fmtN(r.ActiveIOCs)} aktif</small>` },
      { label: 'Aile', num: true, render: (r) => `<b>${r.Families}</b>` },
      { label: 'Aktör', num: true, render: (r) => r.Actors },
      { label: 'Zararlı aileleri', render: (r) => `<span style="display:block;max-width:420px;white-space:normal">${esc(r.FamilyNames || '—')}</span>` },
    ], d.asns, { caption: 'ASN örtüşmesi' }) : empty(s.Ranges ? 'Birden çok aileyi barındıran ASN bulunmadı.' : 'ASN eşlemesi için IP aralığı verisi gerekli.', 'server');

    const max = Math.max(1, ...d.countries.map((c) => c.IOCs));
    document.getElementById('countries').innerHTML = d.countries.length ? d.countries.slice(0, 15).map((c) => `<div class="bar-row"><span>${country(c.CountryCode)}</span>
      <span class="track" aria-hidden="true"><i style="width:${(c.IOCs / max) * 100}%"></i></span><b>${fmtN(c.IOCs)}</b></div>`).join('')
      : '<p class="faint" style="font-size:13px">Ülke bilgisi IP aralığı verisiyle gelir.</p>';
    icons();
  }

  document.addEventListener('DOMContentLoaded', load);
})();
