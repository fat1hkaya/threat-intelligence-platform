/* Log avı: /api/hunt */
(() => {
  const { api, esc, fmtN, fmtDT, sev, typeBadge, sourceBadge, table, empty, loading, icons, toast, can } = TL;
  const KIND = { exact: ['Birebir', 'b-bad'], host: ['URL ana bilgisayarı', 'b-warn'], parent: ['Üst domain', 'b-muted'] };
  let usingSample = false;

  function show(d) {
    const s = d.summary || {};
    document.getElementById('result').hidden = false;
    document.getElementById('huntKpis').innerHTML = [
      ['file-text', '', 'Taranan satır', s.LinesScanned, s.FileName ? esc(s.FileName) : esc(s.Location || '')],
      ['scan-search', 'c', 'IOC adayı', s.Candidates, d.candidatesByType ? Object.entries(d.candidatesByType).map(([k, v]) => `${esc(TL.TYPE_LABEL[k] || k)} ${fmtN(v)}`).join(' · ') : 'ayıklanan değer'],
      ['siren', 'r', 'Bilinen tehdit eşleşmesi', s.Matches, `${fmtN(s.HighRisk || 0)} yüksek/kritik önemde`],
      ['user-round-x', 'a', 'İlişkili tehdit aktörü', s.Actors, s.Recorded ? 'Görülme olarak kaydedildi' : 'Kaydedilmedi (yalnızca arama)'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="lbl">${l}</div><div class="val">${fmtN(v || 0)}</div><div class="sub">${sub}</div></div></article>`).join('');
    document.getElementById('resultTitle').textContent = `Av #${s.HuntID}: ${fmtN(s.Matches || 0)} eşleşme`;
    document.getElementById('resultNote').textContent = `${fmtDT(s.StartedAt)} · ${s.StartedBy || ''} · eşleme sp_RetroHunt ile tek set tabanlı sorguda yapıldı`
      + (d.truncated ? ' · aday sınırına (20.000) ulaşıldı, logun bir kısmı taranmadı' : '');
    document.getElementById('matches').innerHTML = d.matches.length ? table([
      { label: 'IOC', primary: true, render: (m) => `<a class="mono value" style="max-width:280px" href="/iocs/${m.IndicatorID}" title="${esc(m.Value)}">${esc(m.Value)}</a>` },
      { label: 'Tip', render: (m) => typeBadge(m.TypeCode) },
      { label: 'Önem', render: (m) => sev(m.SeverityCode) },
      { label: 'Risk', num: true, render: (m) => m.RiskScore },
      { label: 'Eşleşme', render: (m) => `<span class="badge ${KIND[m.MatchKind][1]}" title="Logdaki biçim: ${esc(m.LogValue)}">${KIND[m.MatchKind][0]}</span>` },
      { label: 'Logda', render: (m) => `<b>${fmtN(m.Hits)}</b> kez · ilk satır ${fmtN(m.FirstLine)}` },
      { label: 'Zararlı / aktör', render: (m) => m.MalwareName ? `${esc(m.MalwareName)}${m.ActorName ? ` <span class="faint">→</span> <b>${esc(m.ActorName)}</b>` : ''}` : '<span class="faint">—</span>' },
      { label: 'Kaynak', render: (m) => sourceBadge(m.SourceName) },
      { label: '', render: (m) => `<a class="btn sm icon ghost" href="${TL.graphUrl('indicator', m.IndicatorID)}" aria-label="İlişki grafında aç" title="İlişki grafında aç"><i data-lucide="share-2"></i></a>` },
    ], d.matches, { caption: 'Av eşleşmeleri' }) + `<details style="padding:12px 16px"><summary class="muted" style="cursor:pointer">Eşleşen log satırları</summary>
      <pre class="mono" style="white-space:pre-wrap;font-size:12px;color:var(--text-desc);margin-top:8px">${d.matches.map((m) => `${String(m.FirstLine).padStart(5)}  ${esc(m.SampleLine || '')}`).join('\n')}</pre></details>`
      : empty('Bu logda veritabanındaki IOC\'lerden hiçbiri geçmiyor. İyi haber.', 'shield-check');
    icons();
    document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function history() {
    const rows = await api('/api/hunt');
    document.getElementById('history').innerHTML = rows.length ? rows.map((h) => `<li><a href="#" data-hunt="${h.HuntID}">
        <span><b>#${h.HuntID}</b> ${esc(h.Location)}<br><small>${fmtDT(h.StartedAt)} · ${fmtN(h.LinesScanned)} satır · ${esc(h.StartedBy || '')}</small></span>
        <span class="badge ${h.Matches ? 'b-bad' : 'b-ok'}">${fmtN(h.Matches)} eşleşme</span></a></li>`).join('')
      : '<li class="faint" style="font-size:13px">Henüz av yapılmadı.</li>';
  }

  document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('huntForm'), rec = document.getElementById('record'), note = document.getElementById('sampleNote');
    if (!can('analyst')) { rec.disabled = true; document.getElementById('recordWrap').title = 'Görülme kaydı için analist yetkisi gerekir'; }
    const setSample = (on, text) => {
      usingSample = on; note.hidden = !on;
      if (on) { note.querySelector('span').textContent = text; rec.checked = false; rec.disabled = true; }
      else if (can('analyst')) rec.disabled = false;
    };
    document.getElementById('logText').addEventListener('input', () => usingSample && setSample(false));
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
      catch (err) { box.innerHTML = empty(err.message, 'circle-alert'); icons(); }
    });
    document.getElementById('history').addEventListener('click', async (e) => {
      const a = e.target.closest('[data-hunt]'); if (!a) return; e.preventDefault();
      try { show(await api(`/api/hunt/${a.dataset.hunt}`)); } catch (err) { toast(err.message, 'err'); }
    });
    history();
  });
})();
