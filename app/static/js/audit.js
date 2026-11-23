/* Denetim kayıtları: /api/audit-logs, /api/audit-logs/logins, /api/maintenance/runs */
(() => {
  const { api, esc, fmtN, fmtDT, ago, empty, can } = TL;
  const ACTION = { I: ['Ekleme', 'b-ok', 'plus'], U: ['Güncelleme', 'b-warn', 'pencil'], D: ['Silme', 'b-bad', 'trash-2'] };
  const TABLE = { Indicator: 'IOC', ThreatActor: 'Tehdit aktörü', Malware: 'Zararlı yazılım', Campaign: 'Kampanya', AppUser: 'Kullanıcı', Investigation: 'Vaka', DetectionCoverage: 'Tespit kapsamı' };
  const LINK = { Indicator: (id) => `/iocs/${id}`, ThreatActor: (id) => `/actors?id=${id}`, Malware: (id) => `/malware?id=${id}`, Campaign: (id) => `/campaigns?id=${id}`,
    AppUser: () => '/settings', Investigation: (id) => `/cases?id=${id}`, DetectionCoverage: (id) => `/attack?id=${id}` };
  const badge = (a) => `<span class="badge ${ACTION[a][1]}"><i data-lucide="${ACTION[a][2]}" style="width:13px;height:13px"></i>${ACTION[a][0]}</span>`;
  const label = (r) => { const v = r.NewValues || r.OldValues || {}; return v.Value || v.Name || v.Title || v.Username || ''; };
  const hideAuto = () => (document.getElementById('hideAutomation')?.checked ? 'true' : 'false');
  const st = { days: 30, login: '', loginPage: 1, logins: null };
  let rows = [], chart;

  // ---------- veri değişiklikleri ----------
  const page = TL.listPage({
    endpoint: '/api/audit-logs', title: 'Olay detayı', unit: 'kayıt', size: 25, rowId: (r) => r.AuditID,
    // işaretsiz onay kutusu formda hiç gönderilmez: açıkça false gönderilir (API varsayılanı gizlemek)
    extra: () => ({ hideAutomation: hideAuto() === 'false' ? 'false' : null }),
    onData: (d) => { rows = d.items; },   // detay paneli satırı yeniden sorgulamadan gösterir
    columns: [
      { id: 'time', label: 'Zaman', render: (r) => `<span class="tabular nowrap" title="${fmtDT(r.ChangedAt)}">${fmtDT(r.ChangedAt)}</span>` },
      { id: 'user', label: 'Kullanıcı', primary: true, render: (r) => r.ChangedBy ? `<span class="nowrap" title="${esc(r.ChangedBy)}${r.RoleName ? ` · ${esc(r.RoleName)}` : ''}">${esc(r.ChangedBy)}</span>` : '<span class="faint nowrap">Sistem (SSMS / betik)</span>' },
      { id: 'action', label: 'İşlem', render: (r) => badge(r.Action) },
      { id: 'table', label: 'Tablo', priority: 2, render: (r) => `<span class="badge b-muted">${esc(TABLE[r.TableName] || r.TableName)}</span>` },
      { id: 'record', label: 'Kayıt', priority: 2, render: (r) => `<span class="mono">#${r.RecordID}</span> <span class="muted" title="${esc(label(r))}">${esc(TL.midTruncate(label(r), 24, 10))}</span>` },
    ],
    async detail(id) {
      const r = rows.find((x) => String(x.AuditID) === String(id)) || (await api('/api/audit-logs', { params: { size: 200 } })).items.find((x) => String(x.AuditID) === String(id));
      if (!r) return empty('Kayıt bulunamadı.');
      const o = r.OldValues || {}, n = r.NewValues || {}, keys = [...new Set([...Object.keys(o), ...Object.keys(n)])];
      const changed = (k) => JSON.stringify(o[k]) !== JSON.stringify(n[k]);
      const v = (x) => (x == null || x === '' ? '<span class="faint">boş</span>' : esc(x));
      // Alan bazında önce/sonra; güncellemede değişen alanlar önce ve vurgulu. Silmede "silinmeden önceki hâli".
      const order = r.Action === 'U' ? [...keys.filter(changed), ...keys.filter((k) => !changed(k))] : keys;
      const diffTbl = keys.length ? `<table class="diff"><thead><tr><th scope="col">Alan</th>${r.Action !== 'I' ? `<th scope="col">${r.Action === 'D' ? 'Silinmeden önceki hâli' : 'Önce'}</th>` : ''}${r.Action !== 'D' ? '<th scope="col">Sonra</th>' : ''}</tr></thead><tbody>
        ${order.map((k) => `<tr class="${r.Action === 'U' && changed(k) ? 'changed' : ''}"><th scope="row">${esc(k)}</th>${r.Action !== 'I' ? `<td class="old">${v(o[k])}</td>` : ''}${r.Action !== 'D' ? `<td class="new">${v(n[k])}</td>` : ''}</tr>`).join('')}</tbody></table>`
        : '<p class="faint">Alan ayrıntısı yok.</p>';
      const link = LINK[r.TableName] && r.Action !== 'D' ? `<a class="btn sm" href="${LINK[r.TableName](r.RecordID)}"><i data-lucide="external-link"></i>İlgili kayda git</a>` : '';
      return `<section><div style="display:flex;gap:8px;align-items:center">${badge(r.Action)}<span class="badge b-muted">${esc(TABLE[r.TableName] || r.TableName)}</span></div>
          <dl class="kv"><dt>Olay no</dt><dd class="mono">${r.AuditID}</dd><dt>Zaman</dt><dd>${fmtDT(r.ChangedAt)}</dd>
          <dt>Kullanıcı</dt><dd>${esc(r.ChangedBy || 'Sistem')} ${r.Username ? `<span class="faint">@${esc(r.Username)}</span>` : ''}${r.RoleName ? ` <span class="faint">· ${esc(r.RoleName)}</span>` : ''}</dd>
          <dt>Kayıt</dt><dd>${esc(TABLE[r.TableName] || r.TableName)} #${r.RecordID}${label(r) ? ` · ${esc(label(r))}` : ''}</dd></dl>${link}</section>
        <section><h3>${r.Action === 'U' ? `Değişiklik (${keys.filter(changed).length} alan)` : r.Action === 'D' ? 'Silinmeden önceki hâli' : 'Eklenen kayıt'}</h3>${diffTbl}</section>
        <section><p class="faint tech" style="font-size:12px">Bu kayıt ${esc(`trg_${r.TableName}_Audit`)} tetikleyicisiyle yazıldı. trg_AuditLog_Protect (INSTEAD OF) güncelleme ve silmeyi reddeder.</p></section>`;
    },
  });

  // Küçük yığılmış çubuk: ekleme / güncelleme / silme dağılımı
  const mix = (t) => { const tot = (t.Inserts || 0) + (t.Updates || 0) + (t.Deletes || 0) || 1;
    return `<span class="mix-bar" role="img" aria-label="Ekleme ${t.Inserts}, güncelleme ${t.Updates}, silme ${t.Deletes}">${[['Inserts', 'low'], ['Updates', 'medium'], ['Deletes', 'critical']].map(([k, c]) => `<i style="flex-grow:${t[k] || 0};background:var(--${c})" title="${k === 'Inserts' ? 'Ekleme' : k === 'Updates' ? 'Güncelleme' : 'Silme'}: ${fmtN(t[k] || 0)}"></i>`).join('')}</span>
      <span class="mix-legend"><span><i style="background:var(--low)"></i>${fmtN(t.Inserts || 0)} ekleme</span><span><i style="background:var(--medium)"></i>${fmtN(t.Updates || 0)} güncelleme</span><span><i style="background:var(--critical)"></i>${fmtN(t.Deletes || 0)} silme</span></span>`; };

  async function stats() {
    const s = await api('/api/audit-logs/stats', { params: { hideAutomation: hideAuto(), days: st.days } }); const t = s.totals;
    const lbl = document.getElementById('hideAutoLabel');
    if (lbl) lbl.textContent = t.AutomationRows ? `Otomasyon kayıtlarını gizle (${fmtN(t.AutomationRows)})` : 'Otomasyon kayıtlarını gizle';
    let failed = null;
    if (can('admin')) { try { st.logins = await api('/api/audit-logs/logins', { params: { hideAutomation: document.getElementById('loginHideAuto').checked } }); failed = st.logins.totals?.Failed24h ?? 0; } catch { /* yalnızca yönetici */ } }
    const kpi = (i, c, l, v, sub) => `<article class="card kpi"><span class="ic ${c}"><i data-lucide="${i}"></i></span><div><div class="val">${v}</div><div class="lbl">${l}</div><div class="sub">${sub}</div></div></article>`;
    document.getElementById('kpis').innerHTML = [
      kpi('file-clock', '', 'Toplam kayıt', fmtN(t.Total), `${fmtN(t.Users)} farklı kullanıcı`),
      kpi('clock', 'c', 'Son 24 saat', fmtN(t.Last24h), 'tetikleyicilerin yazdığı olay'),
      `<article class="card kpi mix"><span class="ic a"><i data-lucide="layers"></i></span><div><div class="lbl">İşlem dağılımı</div>${mix(t)}</div></article>`,
      failed == null ? kpi('users', '', 'Farklı kullanıcı', fmtN(t.Users), 'kayıt yazan hesap')
        : kpi('shield-alert', failed ? 'r' : '', 'Hatalı giriş', fmtN(failed), 'son 24 saat'),
    ].join('');
    const tableSel = document.getElementById('table'), cur = tableSel.value;
    tableSel.innerHTML = '<option value="">Tümü</option>' + s.byTable.map((x) => `<option value="${esc(x.TableName)}">${esc(TABLE[x.TableName] || x.TableName)} (${x.Total})</option>`).join('');
    tableSel.value = cur;
    const us = document.getElementById('user');
    if (!us.dataset.filled) { us.dataset.filled = '1'; us.insertAdjacentHTML('beforeend', s.users.map((u) => `<option value="${u.UserID}">${esc(u.FullName)}</option>`).join('')); }
    drawChart(s.daily);
    TL.icons();
  }

  // Günlük olaylar: işlem türüne göre yığılmış çubuk (ekleme yeşil, güncelleme sarı, silme kırmızı)
  function drawChart(daily) {
    const total = daily.reduce((a, d) => a + d.Total, 0);
    document.getElementById('dailyNote').textContent = `Son ${st.days} günde ${fmtN(total)} olay · toplu içe aktarmalar satır başına kayıt üretmez`;
    document.getElementById('dailySummary').textContent = `Son ${st.days} günde ${total} denetim olayı: ${daily.reduce((a, d) => a + d.Inserts, 0)} ekleme, ${daily.reduce((a, d) => a + d.Updates, 0)} güncelleme, ${daily.reduce((a, d) => a + d.Deletes, 0)} silme.`;
    chart?.destroy();
    const css = getComputedStyle(document.documentElement), c = (v, f) => css.getPropertyValue(v).trim() || f;
    chart = new Chart(document.getElementById('daily'), { type: 'bar',
      data: { labels: daily.map((d) => new Date(d.Day + 'T00:00:00').toLocaleDateString('tr-TR', { day: 'numeric', month: 'short' })),
        datasets: [['Ekleme', 'Inserts', c('--low', '#34D399')], ['Güncelleme', 'Updates', c('--medium', '#FBBF24')], ['Silme', 'Deletes', c('--critical', '#F87171')]]
          .map(([l, k, col]) => ({ label: l, data: daily.map((d) => d[k]), backgroundColor: col, borderRadius: 2, maxBarThickness: 18, stack: 'a' })) },
      options: { maintainAspectRatio: false, plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 10, boxHeight: 10 } } },
        scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 8, maxRotation: 0 } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } } });
  }

  // ---------- giriş denemeleri ----------
  const REASON = { bad_password: 'Hatalı parola', unknown_user: 'Bilinmeyen kullanıcı', locked: 'Kilitli hesap', inactive: 'Devre dışı hesap' };
  const LOGIN_PER_PAGE = 20;
  async function logins(refresh = false) {
    const box = document.getElementById('loginTbl');
    if (!can('admin')) { box.innerHTML = '<p class="muted" style="padding:16px 18px">Giriş denemelerini yalnızca yönetici görür.</p>'; return; }
    if (refresh || !st.logins) st.logins = await api('/api/audit-logs/logins', { params: { hideAutomation: document.getElementById('loginHideAuto').checked } });
    const L = st.logins, t = L.totals || {};
    document.getElementById('loginNote').textContent = `Son 24 saatte ${fmtN(t.Failed24h || 0)} hatalı deneme · kilit nedeniyle reddedilen ${fmtN(t.LockedAttempts || 0)} · 15 dakikada 5 hatalı deneme hesabı geçici olarak kilitler`;
    const f = st.login;
    const items = L.items.filter((a) => !f || (f === 'ok' ? a.Success : f === 'locked' ? a.Reason === 'locked' : !a.Success && a.Reason !== 'locked'));
    const pages = Math.max(1, Math.ceil(items.length / LOGIN_PER_PAGE)); st.loginPage = Math.min(st.loginPage, pages);
    box.innerHTML = items.length ? TL.table([
      { label: 'Zaman', render: (a) => `<span class="nowrap tabular" title="${fmtDT(a.AttemptedAt)}">${ago(a.AttemptedAt)}</span>` },
      { label: 'Kullanıcı adı', primary: true, render: (a) => `<span class="nowrap" title="${esc(a.FullName || '')}">${esc(a.Username)}</span>` },
      { label: 'Sonuç', render: (a) => a.Success ? '<span class="badge b-ok">Başarılı</span>' : `<span class="badge ${a.Reason === 'locked' ? 'b-warn' : 'b-bad'}">${esc(REASON[a.Reason] || 'Başarısız')}</span>` },
      { label: 'IP', render: (a) => `<span class="mono">${esc(a.ClientIP || '—')}</span>` },
    ], items.slice((st.loginPage - 1) * LOGIN_PER_PAGE, st.loginPage * LOGIN_PER_PAGE), { caption: 'Giriş denemeleri' }) : empty('Bu filtreye uyan deneme yok.', 'shield-check');
    TL.pager(document.getElementById('loginPager'), { page: st.loginPage, size: LOGIN_PER_PAGE, total: items.length }, (p) => { st.loginPage = p; logins(); }, 'deneme');
    TL.icons();
  }

  // ---------- bakım işleri ----------
  async function runs() {
    const el = document.getElementById('runs');
    try { el.innerHTML = TL.maintenanceRuns(await api('/api/maintenance/runs', { params: { limit: 200 } })); } catch (e) { el.innerHTML = empty(e.message); }
    TL.icons();
  }

  function tabs() {
    const bar = document.getElementById('auditTabs'), loaded = {};
    const show = (id) => {
      bar.querySelectorAll('[data-tab]').forEach((b) => { const on = b.dataset.tab === id; b.setAttribute('aria-selected', String(on)); b.setAttribute('aria-pressed', String(on)); b.tabIndex = on ? 0 : -1; });
      document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.id !== id; });
      TL.qs.set({ tab: id === 'changesTab' ? null : id.replace('Tab', '') });
      if (id === 'loginsTab' && !loaded.l) { loaded.l = 1; logins().catch((e) => TL.toast(e.message, 'err')); }
      if (id === 'runsTab' && !loaded.r) { loaded.r = 1; runs(); }
    };
    bar.addEventListener('click', (e) => { const b = e.target.closest('[data-tab]'); if (b) show(b.dataset.tab); });
    bar.addEventListener('keydown', (e) => { if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
      const bs = [...bar.querySelectorAll('[data-tab]')], i = bs.indexOf(document.activeElement); const n = bs[(i + (e.key === 'ArrowRight' ? 1 : bs.length - 1)) % bs.length]; n.focus(); show(n.dataset.tab); });
    const t = TL.qs.get('tab'); show(t === 'logins' ? 'loginsTab' : t === 'runs' ? 'runsTab' : 'changesTab');
  }

  document.addEventListener('DOMContentLoaded', async () => {
    if (TL.qs.get('hideAutomation') === 'false') document.getElementById('hideAutomation').checked = false;
    tabs();
    try { await stats(); } catch (e) { TL.failed(document.getElementById('kpis'), e, stats); }
    TL.icons(); page.start();
    // filtre çubuğu sayfayı yeniler; bu kutu ayrıca özeti de etkiler
    document.getElementById('hideAutomation')?.addEventListener('change', () => stats());
    document.getElementById('period').addEventListener('click', (e) => {
      const b = e.target.closest('[data-v]'); if (!b) return; st.days = +b.dataset.v;
      document.querySelectorAll('#period [data-v]').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); stats();
    });
    document.getElementById('loginFilter').addEventListener('click', (e) => {
      const b = e.target.closest('[data-v]'); if (!b) return; st.login = b.dataset.v; st.loginPage = 1;
      document.querySelectorAll('#loginFilter [data-v]').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); logins();
    });
    document.getElementById('loginHideAuto').addEventListener('change', () => { st.loginPage = 1; logins(true); });
  });
})();
