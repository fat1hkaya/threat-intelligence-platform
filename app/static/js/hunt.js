/* Log avı: /api/hunt */
(() => {
  const { api, esc, fmtN, fmtDT, sev, typeBadge, sourceBadge, table, empty, loading, icons, toast, can } = TL;
  const KIND = { exact: ['Birebir', 'b-warn'], host: ['URL ana bilgisayarı', 'b-cyan'], parent: ['Üst domain', 'b-muted'] };
  const HISTORY_SHOWN = 10;
  let usingSample = false, allHistory = false;

  /** Log satırında eşleşen değerin geçtiği yeri vurgular (büyük/küçük harf duyarsız) */
  const highlight = (line, needle) => {
    if (!line) return '<span class="faint">—</span>';
    const i = needle ? line.toLowerCase().indexOf(String(needle).toLowerCase()) : -1;
    return i < 0 ? esc(line) : `${esc(line.slice(0, i))}<mark>${esc(line.slice(i, i + needle.length))}</mark>${esc(line.slice(i + needle.length))}`;
  };

  function show(d) {
    const s = d.summary || {};
    document.getElementById('result').hidden = false;
    document.getElementById('huntKpis').innerHTML = [
      ['file-text', '', 'Taranan satır', s.LinesScanned, s.FileName ? esc(s.FileName) : esc(s.Location || '')],
      ['scan-search', 'c', 'IOC adayı', s.Candidates, d.candidatesByType ? Object.entries(d.candidatesByType).map(([k, v]) => `${esc(TL.TYPE_LABEL[k] || k)} ${fmtN(v)}`).join(' · ') : 'ayıklanan değer'],
      ['siren', 'r', 'Bilinen tehdit eşleşmesi', s.Matches, `${fmtN(s.HighRisk || 0)} yüksek/kritik önemde`],
      ['user-round-x', 'a', 'İlişkili tehdit aktörü', s.Actors, s.Recorded ? 'Görülme olarak kaydedildi' : 'Kaydedilmedi (yalnızca arama)'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="val">${fmtN(v || 0)}</div><div class="lbl">${l}</div><div class="sub">${sub}</div></div></article>`).join('');
    document.getElementById('resultTitle').textContent = `Av #${s.HuntID}: ${fmtN(s.Matches || 0)} eşleşme`;
    document.getElementById('resultNote').innerHTML = `${esc(fmtDT(s.StartedAt))} · ${esc(s.StartedBy || '')}<span class="tech"> · eşleme sp_RetroHunt ile tek set tabanlı sorguda yapıldı</span>`
      + (d.truncated ? ' · aday sınırına (20.000) ulaşıldı, logun bir kısmı taranmadı' : '');
    document.getElementById('matches').innerHTML = d.matches.length ? table([
      { label: 'Satır', num: true, render: (m) => `<span class="mono" title="${fmtN(m.Hits)} kez geçti">${fmtN(m.FirstLine)}</span>` },
      { label: 'IOC', primary: true, render: (m) => TL.iocCell(m.Value, { href: `/iocs/${m.IndicatorID}` }) },
      { label: 'Log satırındaki konum', priority: 2, render: (m) => `<span class="mono log-line" title="${esc(m.SampleLine || '')}">${highlight(m.SampleLine, m.LogValue)}</span>` },
      { label: 'Eşleşme', priority: 3, render: (m) => `<span class="badge ${KIND[m.MatchKind][1]}" title="Logdaki biçim: ${esc(m.LogValue)}">${KIND[m.MatchKind][0]}</span>` },
      { label: 'Risk', num: true, render: (m) => `<b>${m.RiskScore}</b>` },
      { label: 'Aile / aktör', render: (m) => m.MalwareName ? `<span class="trunc" title="${esc([m.MalwareName, m.ActorName].filter(Boolean).join(' → '))}">${esc(m.MalwareName)}${m.ActorName ? ` <span class="faint">→</span> <b>${esc(m.ActorName)}</b>` : ''}</span>` : '<span class="faint">—</span>' },
      { label: 'İşlemler', cls: 'actions', render: (m) => `${can('analyst') ? TL.caseBtn('indicator', m.IndicatorID, m.Value, 'btn sm') : ''}<a class="btn sm icon ghost" href="${TL.graphUrl('indicator', m.IndicatorID)}" aria-label="İlişki grafında aç" title="İlişki grafında aç"><i data-lucide="share-2"></i></a>` },
    ], d.matches, { caption: 'Av eşleşmeleri' })
      : empty('Bu logda veritabanındaki IOC\'lerden hiçbiri geçmiyor.', 'shield-check');
    // Tanınan ama eşleşmeyen göstergeler ve tanınamayan satırlar (yalnızca av anında hesaplanır; geçmiş avlarda sayı yok)
    const extra = document.getElementById('unmatched');
    if (d.unmatched) {
      extra.hidden = false;
      extra.innerHTML = `<div class="card-head"><div><h2>Eşleşmeyen göstergeler</h2><p>Logda tanınan, veritabanında karşılığı olmayan ${fmtN(d.unmatchedCount)} değer · ${fmtN(d.unrecognizedLines)} satırda gösterge bulunamadı</p></div></div>
        ${d.unmatched.length ? `<ul class="plain-list mono">${d.unmatched.map((u) => `<li><span class="faint">${String(u.line).padStart(5)}</span> ${typeBadge(u.type)} <span class="trunc" title="${esc(u.value)}">${esc(u.value)}</span></li>`).join('')}</ul>
          ${d.unmatchedCount > d.unmatched.length ? `<p class="faint" style="padding:0 16px 12px;font-size:12px">İlk ${fmtN(d.unmatched.length)} değer gösteriliyor.</p>` : ''}`
          : '<p class="faint" style="padding:0 16px 14px;font-size:13px">Tanınan her gösterge veritabanında eşleşti.</p>'}`;
    } else extra.hidden = true;
    icons();
    document.getElementById('result').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  async function history() {
    const rows = await api('/api/hunt');
    const shown = allHistory ? rows : rows.slice(0, HISTORY_SHOWN);
    // Eşleşmeli avlar turuncu, eşleşmesizler nötr: kırmızı yalnızca kritik/hata içindir
    document.getElementById('history').innerHTML = rows.length ? shown.map((h) => `<li><a href="#" data-hunt="${h.HuntID}">
        <span><b>#${h.HuntID}</b> ${esc(h.Location)}<br><small>${fmtDT(h.StartedAt)} · ${fmtN(h.LinesScanned)} satır · ${esc(h.StartedBy || '')}</small></span>
        <span class="badge ${h.Matches ? 'b-warn' : 'b-muted'}">${fmtN(h.Matches)} eşleşme</span></a></li>`).join('')
      : '<li class="faint" style="font-size:13px">Henüz av yapılmadı.</li>';
    const more = document.getElementById('historyAll');
    more.hidden = rows.length <= HISTORY_SHOWN;
    more.textContent = allHistory ? 'Son 10 avı göster' : `Tümünü gör (${fmtN(rows.length)})`;
  }

  document.addEventListener('DOMContentLoaded', () => {
    // /hunt?id=N: geçmiş bir avın sonucunu açar (Vakalar > Son log avları)
    const hid = +TL.qs.get('id'); if (hid) TL.api(`/api/hunt/${hid}`).then(show).catch((e) => TL.toast(e.message, 'err'));
    const form = document.getElementById('huntForm'), rec = document.getElementById('record'), note = document.getElementById('sampleNote');
    if (!can('analyst')) { rec.disabled = true; document.getElementById('recordWrap').title = 'Görülme kaydı için analist yetkisi gerekir'; }
    const setSample = (on, text) => {
      usingSample = on; note.hidden = !on;
      if (on) { note.querySelector('span').textContent = text; rec.checked = false; rec.disabled = true; }
      else if (can('analyst')) rec.disabled = false;
    };
    document.getElementById('logText').addEventListener('input', () => usingSample && setSample(false));
    TL.dropzone(document.getElementById('logFile'), { hint: '.log, .txt, .csv, .json · en çok 5 MB' });
    TL.dropText(document.getElementById('logText'));
    form.addEventListener('reset', () => setTimeout(() => { setSample(false); document.getElementById('result').hidden = true; }));
    document.getElementById('sampleBtn').onclick = async () => {
      try { const s = await api('/api/hunt/sample'); document.getElementById('logText').value = s.text; setSample(true, s.note); }
      catch (e) { toast(e.message, 'err'); }
    };
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData();
      const file = document.getElementById('logFile').files[0];
      if (file) fd.append('file', file); else fd.append('text', document.getElementById('logText').value);
      fd.append('location', document.getElementById('location').value);
      fd.append('record', rec.checked && !usingSample ? 'true' : 'false');
      const box = document.getElementById('matches'); document.getElementById('result').hidden = false; box.innerHTML = loading('Log taranıyor');
      try { show(await api('/api/hunt', { method: 'POST', body: fd })); history(); if (rec.checked) toast('Eşleşmeler görülme olarak kaydedildi.'); }
      catch (err) { TL.failed(box, err, () => form.requestSubmit()); }
    });
    document.getElementById('history').addEventListener('click', async (e) => {
      const a = e.target.closest('[data-hunt]'); if (!a) return; e.preventDefault();
      try { show(await api(`/api/hunt/${a.dataset.hunt}`)); } catch (err) { toast(err.message, 'err'); }
    });
    document.getElementById('historyAll').onclick = () => { allHistory = !allHistory; history(); };
    history();
  });
})();
