/* Denetim kayıtları: /api/audit-logs */
(() => {
  const { api, esc, fmtN, fmtDT, empty } = TL;
  const ACTION = { I: ['Ekleme', 'b-ok', 'plus'], U: ['Güncelleme', 'b-warn', 'pencil'], D: ['Silme', 'b-bad', 'trash-2'] };
  const TABLE = { Indicator: 'IOC', ThreatActor: 'Tehdit aktörü', Malware: 'Zararlı yazılım', Campaign: 'Kampanya', AppUser: 'Kullanıcı' };
  const LINK = { Indicator: (id) => `/iocs/${id}`, ThreatActor: (id) => `/actors?id=${id}`, Malware: (id) => `/malware?id=${id}`, Campaign: (id) => `/campaigns?id=${id}`, AppUser: () => '/settings' };
  const badge = (a) => `<span class="badge ${ACTION[a][1]}"><i data-lucide="${ACTION[a][2]}" style="width:13px;height:13px"></i>${ACTION[a][0]}</span>`;
  const label = (r) => { const v = r.NewValues || r.OldValues || {}; return v.Value || v.Name || v.Username || ''; };
  let rows = [];

  const page = TL.listPage({
    endpoint: '/api/audit-logs', title: 'Olay detayı', unit: 'kayıt', size: 25, rowId: (r) => r.AuditID,
    onData: (d) => { rows = d.items; },   // detay paneli satırı yeniden sorgulamadan gösterir
    columns: [
      { label: 'Zaman', render: (r) => `<span class="mono" style="font-size:12.5px">${fmtDT(r.ChangedAt)}</span>` },
      { label: 'Kullanıcı', primary: true, render: (r) => r.ChangedBy ? `${esc(r.ChangedBy)}<br><small class="muted">${esc(r.RoleName || '')}</small>` : '<span class="faint">Sistem (SSMS / betik)</span>' },
      { label: 'İşlem', render: (r) => badge(r.Action) },
      { label: 'Tablo', render: (r) => `<span class="badge b-muted">${esc(TABLE[r.TableName] || r.TableName)}</span>` },
      { label: 'Kayıt', render: (r) => `<span class="mono">#${r.RecordID}</span> <span class="muted value" style="max-width:220px">${esc(label(r))}</span>` },
    ],
    async detail(id) {
      const r = rows.find((x) => String(x.AuditID) === String(id)) || (await api('/api/audit-logs', { params: { size: 200 } })).items.find((x) => String(x.AuditID) === String(id));
      if (!r) return empty('Kayıt bulunamadı.');
      const o = r.OldValues || {}, n = r.NewValues || {}, keys = [...new Set([...Object.keys(o), ...Object.keys(n)])];
      const changed = (k) => JSON.stringify(o[k]) !== JSON.stringify(n[k]);
      const side = (obj, cls) => keys.map((k) => `<div class="${r.Action === 'U' && changed(k) ? 'chg' : ''}">${esc(k)}: ${esc(obj[k] ?? '∅')}</div>`).join('') || '<span class="faint">—</span>';
      return `<section><div style="display:flex;gap:8px;align-items:center">${badge(r.Action)}<span class="badge b-muted">${esc(TABLE[r.TableName] || r.TableName)}</span></div>
          <dl class="kv"><dt>Olay no</dt><dd class="mono">${r.AuditID}</dd><dt>Zaman</dt><dd>${fmtDT(r.ChangedAt)}</dd>
          <dt>Kullanıcı</dt><dd>${esc(r.ChangedBy || 'Sistem')} ${r.Username ? `<span class="faint">@${esc(r.Username)}</span>` : ''}</dd>
          <dt>Kayıt</dt><dd><a href="${LINK[r.TableName] ? LINK[r.TableName](r.RecordID) : '#'}">${esc(r.TableName)} #${r.RecordID}</a></dd></dl></section>
        <section><h3>Değişiklik detayı</h3>
          <div class="diff"><div class="old" aria-label="Önceki değer"><small class="muted">Önceki değer</small>${r.Action === 'I' ? '<div class="faint">yeni kayıt</div>' : side(o)}</div>
          <div class="new" aria-label="Yeni değer"><small class="muted">Yeni değer</small>${r.Action === 'D' ? '<div class="faint">silindi</div>' : side(n)}</div></div>
          ${r.Action === 'U' ? `<p class="faint" style="font-size:12px">Değişen alanlar: ${keys.filter(changed).map(esc).join(', ') || '—'}</p>` : ''}</section>
        <section><p class="faint" style="font-size:12px">Bu kayıt ${esc(`trg_${r.TableName}_Audit`)} tetikleyicisiyle yazıldı. trg_AuditLog_Protect (INSTEAD OF) güncelleme ve silmeyi reddeder.</p></section>`;
    },
  });


  document.addEventListener('DOMContentLoaded', async () => {
    const s = await api('/api/audit-logs/stats'); const t = s.totals;
    document.getElementById('kpis').innerHTML = [
      ['file-clock', '', 'Toplam kayıt', t.Total, `${fmtN(t.Users)} farklı kullanıcı`], ['clock', 'c', 'Son 24 saat', t.Last24h, 'Tetikleyicilerin yazdığı olaylar'],
      ['pencil', 'a', 'Güncelleme', t.Updates, `${fmtN(t.Inserts)} ekleme`], ['trash-2', 'r', 'Silme', t.Deletes, 'Silinen kayıtların son hâli saklanır'],
    ].map(([i, c, l, v, sub]) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="lbl">${l}</div><div class="val">${fmtN(v)}</div><div class="sub">${sub}</div></div></article>`).join('');
    document.getElementById('table').insertAdjacentHTML('beforeend', s.byTable.map((x) => `<option value="${esc(x.TableName)}">${esc(TABLE[x.TableName] || x.TableName)} (${x.Total})</option>`).join(''));
    document.getElementById('user').insertAdjacentHTML('beforeend', s.users.map((u) => `<option value="${u.UserID}">${esc(u.FullName)}</option>`).join(''));
    const total = s.daily.reduce((a, d) => a + d.Total, 0);
    document.getElementById('dailyNote').textContent = `${fmtN(total)} olay · toplu içe aktarmalar satır başına kayıt üretmez (özet ImportJob'da)`;
    document.getElementById('dailySummary').textContent = `Son 30 günde ${total} denetim olayı.`;
    new Chart(document.getElementById('daily'), { type: 'bar',
      data: { labels: s.daily.map((d) => new Date(d.Day + 'T00:00:00').toLocaleDateString('tr-TR', { day: '2-digit', month: 'short' })), datasets: [{ data: s.daily.map((d) => d.Total), backgroundColor: '#7C5CFC', borderRadius: 3, maxBarThickness: 16 }] },
      options: { maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } }, y: { beginAtZero: true, ticks: { precision: 0 } } } } });
    TL.icons(); page.start();
  });
})();
