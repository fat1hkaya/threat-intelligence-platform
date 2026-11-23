/* Altyapı örtüşmesi: /api/infrastructure */
(() => {
  const { api, esc, fmtN, fmtDT, table, empty, loading, icons, toast } = TL;
  let regionNames;
  try { regionNames = new Intl.DisplayNames(['tr'], { type: 'region' }); } catch { regionNames = null; }
  // Uzun ülke adları kısaltılır (ABD, BAE); tam ad ipucunda
  const SHORT = { US: 'ABD', AE: 'BAE', GB: 'Birleşik Krallık', KR: 'Güney Kore', KP: 'Kuzey Kore', SA: 'S. Arabistan', ZA: 'G. Afrika',
    BA: 'Bosna-Hersek', CD: 'Kongo DC', CF: 'Orta Afrika', DO: 'Dominik C.', CZ: 'Çekya', RU: 'Rusya', HK: 'Hong Kong', TW: 'Tayvan', MD: 'Moldova', VG: 'Virjin Adaları' };
  const country = (cc) => {
    if (!cc) return '<span class="faint">—</span>';
    const full = (regionNames && regionNames.of(cc)) || cc, short = SHORT[cc] || full;
    return `<span class="cc" title="${esc(full)}">${esc(short)} <span class="faint mono">${esc(cc)}</span></span>`;
  };
  TL.countryName = country;
  /** ASN tek satır: "AS12345 · Blatant"; sağlayıcının tam adı ipucunda */
  const asShort = (name) => { let n = String(name || ''); if (n.includes(' - ')) n = n.split(' - ').slice(1).join(' - '); return n.split(',')[0].trim() || name; };
  const asn = (num, name) => num ? `<span class="trunc" title="AS${num}${name ? ` · ${esc(name)}` : ''}"><span class="mono">AS${num}</span>${name ? ` · ${esc(asShort(name))}` : ''}</span>`
    : name ? `<span class="trunc" title="${esc(name)}">${esc(asShort(name))}</span>` : '<span class="faint">—</span>';
  /** Aile adları en fazla 3 çip + "+N" (kalanlar ipucunda) */
  const families = (csv) => {
    const all = String(csv || '').split(', ').filter(Boolean);
    if (!all.length) return '<span class="faint">—</span>';
    const rest = all.slice(3);
    return `<span class="chips nowrap-chips">${all.slice(0, 3).map((f) => `<a class="chip" href="/malware?q=${encodeURIComponent(f)}">${esc(f)}</a>`).join('')}${rest.length ? `<span class="chip more" title="${esc(rest.join(', '))}">+${rest.length}</span>` : ''}</span>`;
  };

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
      { label: 'Aile', num: true, render: (r) => `<b>${r.Families}</b>` },
      { label: 'Zararlı aileleri', render: (r) => families(r.FamilyNames) },
      { label: 'ASN', priority: 2, render: (r) => asn(r.ASN, r.ASName) },
      { label: "IOC'ler", cls: 'actions', render: (r) => `<details class="ioc-pop"><summary class="btn sm ghost" aria-label="${esc(r.Subnet)} alt ağındaki IOC'ler">Göster (${fmtN(r.IndicatorIDs.length)})</summary><div class="chips" style="margin-top:6px;max-width:320px">${r.IndicatorIDs.map((id) => `<a class="badge b-muted" href="/iocs/${id}">#${id}</a>`).join('')}</div></details>` },
    ], d.subnets, { caption: 'Paylaşılan alt ağlar' }) : empty('Birden çok IOC barındıran /24 alt ağ yok.', 'network');

    document.getElementById('asns').innerHTML = d.asns.length ? table([
      { label: 'ASN', primary: true, render: (r) => asn(r.ASN, r.ASName) },
      { label: 'Ülke', render: (r) => country(r.CountryCode) },
      { label: 'IOC', num: true, render: (r) => `${fmtN(r.IOCs)} <small class="faint">${fmtN(r.ActiveIOCs)} aktif</small>` },
      { label: 'Aile', num: true, render: (r) => `<b>${r.Families}</b>` },
      { label: 'Aktör', num: true, render: (r) => r.Actors },
      { label: 'Zararlı aileleri', render: (r) => families(r.FamilyNames) },
    ], d.asns, { caption: 'ASN örtüşmesi' }) : empty(s.Ranges ? 'Birden çok aileyi barındıran ASN bulunmadı.' : 'ASN eşlemesi için IP aralığı verisi gerekli.', 'server');

    // en çok 8 ülke ve "Diğer" (kalanların toplamı); çubuk tek renk, sayı nötr
    const top = d.countries.slice(0, 8), rest = d.countries.slice(8);
    const rows = rest.length ? [...top, { CountryCode: null, IOCs: rest.reduce((a, c) => a + c.IOCs, 0), other: rest.length }] : top;
    const max = Math.max(1, ...rows.map((c) => c.IOCs));
    document.getElementById('countries').innerHTML = d.countries.length ? rows.map((c) => `<div class="bar-row"><span>${c.CountryCode ? country(c.CountryCode) : `Diğer <span class="faint">${fmtN(c.other)} ülke</span>`}</span>
      <span class="track" aria-hidden="true"><i style="width:${(c.IOCs / max) * 100}%"></i></span><b>${fmtN(c.IOCs)}</b></div>`).join('')
      : '<p class="faint" style="font-size:13px">Ülke bilgisi IP aralığı verisiyle gelir.</p>';
    icons();
  }

  document.addEventListener('DOMContentLoaded', load);
})();
