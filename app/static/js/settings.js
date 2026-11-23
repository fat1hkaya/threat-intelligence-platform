/* Ayarlar: /api/users, /api/system */
(() => {
  const { api, esc, fmtN, fmtDT, ago, table, empty, icons, toast, can, dialog, formData, job } = TL;
  const ROLE_NAME = { admin: 'Yönetici', analyst: 'Analist', viewer: 'İzleyici' };
  let userRows = [];
  const ROLES = [['admin', 'Yönetici'], ['analyst', 'Analist'], ['viewer', 'İzleyici']];
  const PERMS = [  // [yetki, yönetici, analist, izleyici]
    ['Genel bakış, arama, graf ve raporları görüntüleme', 1, 1, 1],
    ['IOC ekleme, düzenleme, silme', 1, 1, 0],
    ['İlişki (kanıtlı) ekleme ve kaldırma', 1, 1, 0],
    ['Görülme (sighting) kaydı ekleme', 1, 1, 0],
    ['Dosyadan içe aktarma, besleme senkronizasyonu', 1, 1, 0],
    ['MITRE ATT&CK verisini yeniden yükleme', 1, 0, 0],
    ['Kullanıcı ve rol yönetimi', 1, 0, 0],
    ['Kaynak tablosunu değiştirme|(Source, veritabanı rolü)', 1, 0, 0],
    ['Parola özetlerini okuma|(kolon düzeyi DENY)', 0, 0, 0],
    ['Denetim kaydını değiştirme/silme|(INSTEAD OF tetikleyici)', 0, 0, 0],
  ];
  const yes = (v) => v ? '<span class="perm-yes" aria-label="Evet"><i data-lucide="circle-check"></i></span>' : '<span class="perm-no" aria-label="Hayır"><i data-lucide="minus"></i></span>';

  async function users() {
    const box = document.getElementById('users');
    if (!can('admin')) { box.innerHTML = `<div style="padding:16px 18px"><p class="muted">Kullanıcı yönetimi yönetici yetkisi gerektirir. Oturumunuz: <b>${esc(TL.user.FullName)}</b> (${esc(TL.user.RoleName)}).</p></div>`; return; }
    const all = await api('/api/users');
    const inactive = all.filter((u) => !u.IsActive).length, wrap = document.getElementById('inactiveWrap'), chk = document.getElementById('showInactive');
    if (wrap) { wrap.hidden = !inactive; wrap.lastChild.textContent = `Devre dışı olanları göster (${inactive})`; }
    const rows = chk && chk.checked ? all : all.filter((u) => u.IsActive);
    userRows = all;
    box.innerHTML = table([
      { label: 'Kullanıcı', primary: true, render: (u) => `<span class="user-cell"><span class="avatar" style="width:28px;height:28px;font-size: 12px" aria-hidden="true">${esc(u.FullName.split(' ').map((x) => x[0]).join('').slice(0, 2).toUpperCase())}</span><b>${esc(u.FullName)}</b><small class="muted">@${esc(u.Username)}</small></span>` },
      { label: 'Rol', render: (u) => { const me = u.UserID === TL.user.UserID;
        return `<label class="sr-only" for="r${u.UserID}">${esc(u.Username)} rolü</label><select class="input role-sel" id="r${u.UserID}" data-role="${u.UserID}" data-cur="${u.Role}" ${me ? 'disabled title="Kendi rolünüzü değiştiremezsiniz"' : ''}>${ROLES.map(([c, l]) => `<option value="${c}" ${c === u.Role ? 'selected' : ''}>${l}</option>`).join('')}</select>`; } },
      { label: 'Durum', render: (u) => u.IsActive ? '<span class="badge b-ok">Aktif</span>' : '<span class="badge b-muted">Devre dışı</span>' },
      { label: 'Son giriş', priority: 2, render: (u) => u.LastLoginAt ? `<span class="nowrap" title="${fmtDT(u.LastLoginAt)}">${ago(u.LastLoginAt)}</span>` : '<span class="faint">Hiç</span>' },
      { label: 'Denetim olayı', num: true, priority: 3, render: (u) => fmtN(u.AuditCount) },
      { label: 'İşlemler', cls: 'actions', render: (u) => u.UserID === TL.user.UserID ? '<span class="faint" style="font-size:12px">Siz</span>'
        : `<details class="more-menu row-menu"><summary class="btn sm icon ghost" aria-label="${esc(u.Username)}: eylemler" title="Eylemler"><i data-lucide="ellipsis"></i></summary><div class="menu-pop" role="menu">
            <button type="button" class="btn" role="menuitem" data-reset="${u.UserID}" data-name="${esc(u.Username)}"><i data-lucide="key-round"></i>Parola sıfırla</button>
            <button type="button" class="btn" role="menuitem" data-active="${u.UserID}" data-v="${u.IsActive ? 0 : 1}"><i data-lucide="${u.IsActive ? 'user-x' : 'user-check'}"></i>${u.IsActive ? 'Devre dışı bırak' : 'Etkinleştir'}</button></div></details>` },
    ], rows, { caption: 'Kullanıcılar' });
    icons();
  }

  async function system() {
    const d = await api('/api/system'); const s = d.server;
    document.getElementById('server').innerHTML = `<dt>Sunucu</dt><dd>SQL Server ${esc(s.Version)}</dd><dt>Sürüm</dt><dd>${esc(s.Edition)}</dd>
      <dt>Veritabanı</dt><dd class="mono">${esc(s.DatabaseName)}</dd><dt>Harmanlama</dt><dd>${esc(s.Collation)}</dd><dt>Kurtarma modeli</dt><dd>${esc(s.RecoveryModel)}</dd>
      <dt>Boyut</dt><dd>${esc(s.SizeMB)} MB</dd><dt>ODBC sürücüsü</dt><dd>${esc(d.integrations.odbcDriver)}</dd>`;
    const KIND = { USER_TABLE: 'İlişkisel tablo', GRAPH_NODE: 'Graf düğüm tablosu', GRAPH_EDGE: 'Graf kenar tablosu', VIEW: 'Görünüm', SQL_STORED_PROCEDURE: 'Saklı yordam',
      SQL_SCALAR_FUNCTION: 'Skaler fonksiyon', SQL_INLINE_TABLE_VALUED_FUNCTION: 'Tablo değerli fonksiyon', SQL_TRIGGER: 'Tetikleyici', PRIMARY_KEY_CONSTRAINT: 'Birincil anahtar',
      FOREIGN_KEY_CONSTRAINT: 'Yabancı anahtar', CHECK_CONSTRAINT: 'CHECK kısıtı', UNIQUE_CONSTRAINT: 'UNIQUE kısıtı', DEFAULT_CONSTRAINT: 'DEFAULT kısıtı', EDGE_CONSTRAINT: 'Kenar kısıtı' };
    document.getElementById('objects').innerHTML = d.objects.map((o) => `<span class="chip">${esc(KIND[o.Kind] || o.Kind)}: <b>${o.Total}</b></span>`).join('') + `<span class="chip">İndeks: <b>${d.indexCount}</b></span>`;
    document.getElementById('dbroles').innerHTML = d.dbRoles.map((r) => `<div class="bar-row"><span class="mono">${esc(r.RoleName)}</span><span class="muted" style="font-size: 13px">${r.Grants} GRANT · ${r.Denies} DENY</span><span></span></div>`).join('');
    document.getElementById('graph').innerHTML = table([
      { label: 'Nesne', primary: true, render: (g) => `<span class="mono trunc" title="${esc(g.ObjectName)}">${esc(g.ObjectName.replace(/^dbo\./, ''))}</span>` },
      { label: 'Tür', priority: 2, render: (g) => g.Kind === 'node' ? 'Düğüm' : 'Kenar' },
      { label: 'İlişkisel', num: true, render: (g) => fmtN(g.Relational) }, { label: 'Graf', num: true, render: (g) => fmtN(g.Graph) },
      { label: 'Durum', render: (g) => g.IsConsistent ? '<span class="badge b-ok" title="Tutarlı">✓</span>' : '<span class="badge b-bad">Tutarsız</span>' }], d.graph, { caption: 'Graf tutarlılığı', cards: false });
    icons();
  }

  // Entegrasyonlar: 9 kaynağın tamamı; durum, anahtar, son başarılı senkron, bağlantı testi
  async function integrations() {
    const rows = await api('/api/integrations'), admin = can('admin');
    document.getElementById('integrations').innerHTML = table([
      { label: 'Kaynak', primary: true, render: (r) => `<span class="nowrap"><b>${esc(r.Name)}</b></span>` },
      { label: 'Durum', render: (r) => !r.IsActive ? '<span class="badge b-muted">Kapalı</span>' : !r.Feed ? '<span class="badge b-muted">Elle / dosya</span>'
        : r.NeedsKey && !r.KeyDefined ? '<span class="badge b-warn">Anahtar gerekli</span>' : r.LastStatus ? job(r.LastStatus) : '<span class="badge b-cyan">Hazır</span>' },
      { label: 'Anahtar', render: (r) => r.NeedsKey ? (r.KeyDefined ? '<span class="nowrap">Gerekli · <b>tanımlı</b></span>' : '<span class="nowrap">Gerekli · <span class="delta-down">tanımlı değil</span></span>') : '<span class="faint">Gerekmez</span>' },
      { label: 'Son başarılı senkron', render: (r) => r.LastSuccessAt ? `<span class="nowrap" title="${fmtDT(r.LastSuccessAt)}">${ago(r.LastSuccessAt)}</span>` : '<span class="faint">Hiç</span>' },
      { label: 'Bağlantı', cls: 'actions', render: (r) => r.Testable ? `<button type="button" class="btn sm" data-test="${esc(r.Feed)}" ${admin ? '' : 'disabled title="Yönetici yetkisi gerekir"'}><i data-lucide="plug-zap"></i>Bağlantıyı test et</button><span class="test-out" data-out="${esc(r.Feed)}" role="status"></span>` : '<span class="faint">—</span>' },
    ], rows, { caption: 'Entegrasyonlar' });
    icons();
  }

  async function runs() {
    document.getElementById('runs').innerHTML = TL.maintenanceRuns(await api('/api/maintenance/runs', { params: { limit: 200 } }));
    icons();
  }

  async function retention() {    icons();
  }

  async function retention() {
    const d = await api('/api/retention'); const admin = can('admin');
    document.getElementById('retention').innerHTML = table([
      { label: 'Kaynak', primary: true, render: (p) => p.SourceName ? `<span class="nowrap">${esc(p.SourceName)}</span>` : '<span class="muted nowrap">Tüm kaynaklar</span>' },
      { label: 'IOC tipi', render: (p) => p.TypeCode ? TL.typeBadge(p.TypeCode) : '<span class="muted nowrap">Tüm tipler</span>' },
      { label: 'Süre (gün)', num: true, render: (p) => admin ? `<label class="sr-only" for="rp${p.PolicyID}">Süre (gün)</label><input class="input days-in" id="rp${p.PolicyID}" data-policy="${p.PolicyID}" data-orig="${p.LifetimeDays}" type="number" min="1" max="3650" value="${p.LifetimeDays}">` : p.LifetimeDays },
      { label: 'Uygulandığı IOC', num: true, render: (p) => fmtN(p.AppliesTo) },
      { label: 'Not', cls: 'wrap', render: (p) => `<span class="muted" style="font-size: 13px">${esc(p.Note || '')}</span>` },
    ], d.policies, { caption: 'Yaşam döngüsü politikaları' });
    const total = d.upcoming.reduce((a, x) => a + x.Total, 0);
    document.getElementById('upcoming').textContent = total ? `Önümüzdeki 7 günde ${fmtN(total)} IOC'nin süresi dolacak.` : 'Önümüzdeki 7 günde süresi dolacak IOC yok.';
    if (admin) { ['retSave', 'retReset', 'retDirty'].forEach((k) => { document.getElementById(k).hidden = true; }); document.getElementById('retSave').hidden = false; markDirty(); }
  }
  const dirtyInputs = () => [...document.querySelectorAll('#retention [data-policy]')].filter((i) => i.value !== i.dataset.orig);
  function markDirty() {
    const n = dirtyInputs().length, save = document.getElementById('retSave');
    document.querySelectorAll('#retention [data-policy]').forEach((i) => i.classList.toggle('dirty', i.value !== i.dataset.orig));
    save.disabled = !n; document.getElementById('retReset').hidden = !n;
    const ind = document.getElementById('retDirty'); ind.hidden = !n; ind.textContent = n ? `${fmtN(n)} kaydedilmemiş değişiklik` : '';
  }
  async function saveRetention() {
    const items = dirtyInputs();
    const bad = items.find((i) => !(+i.value >= 1 && +i.value <= 3650));
    if (bad) { toast('Süre 1 ile 3650 gün arasında olmalı.', 'err'); bad.focus(); return; }
    try {
      for (const i of items) await api(`/api/retention/${i.dataset.policy}`, { method: 'PUT', body: { lifetimeDays: +i.value } });
      toast(`${fmtN(items.length)} süre kaydedildi. Yeni içe aktarmalara ve yeniden görülen IOC'lere uygulanır.`); retention();
    } catch (err) { toast(err.message, 'err'); }
  }

  function newUser() {
    const d = dialog(`<form><div class="dlg-head"><h2>Kullanıcı ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="form-grid"><div class="field"><label for="nu-u">Kullanıcı adı</label><input class="input" id="nu-u" name="username" required minlength="3" pattern="[A-Za-z0-9._\\-]+"></div>
      <div class="field"><label for="nu-n">Ad soyad</label><input class="input" id="nu-n" name="fullName" required minlength="2"></div>
      <div class="field"><label for="nu-e">E-posta (isteğe bağlı)</label><input class="input" id="nu-e" name="email" type="email"></div>
      <div class="field"><label for="nu-r">Rol</label><select class="input" id="nu-r" name="role">${ROLES.map(([c, l]) => `<option value="${c}" ${c === 'analyst' ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="field full"><label for="nu-p">Geçici parola (en az 8 karakter)</label><input class="input" id="nu-p" name="password" type="password" required minlength="8" autocomplete="new-password"></div></div>
      <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Kullanıcı ekle</button></div></form>`);
    d.querySelector('form').onsubmit = async (e) => { e.preventDefault(); const f = formData(e.target);
      try { await api('/api/users', { method: 'POST', body: { ...f, email: f.email || null } }); d.close(); toast('Kullanıcı eklendi.'); users(); }
      catch (err) { e.target.querySelector('.err').textContent = err.message; } };
  }

  // Sekmeler: Kullanıcılar ve roller · Risk ve yaşam döngüsü · Entegrasyonlar · Bakım işleri · Veritabanı (geliştirici modu)
  const TAB_KEY = { usersTab: null, riskTab: 'risk', intTab: 'integrations', runsTab: 'maintenance', dbTab: 'db' };
  function tabs() {
    const bar = document.getElementById('settingsTabs'); if (!bar) return;
    const show = (id) => {
      if (id === 'dbTab' && !document.documentElement.classList.contains('dev')) id = 'usersTab';
      bar.querySelectorAll('[data-tab]').forEach((b) => { const on = b.dataset.tab === id; b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; });
      document.querySelectorAll('.tab-panel').forEach((p) => { p.hidden = p.id !== id; });
      TL.qs.set({ tab: TAB_KEY[id] });
    };
    bar.addEventListener('click', (e) => { const b = e.target.closest('[data-tab]'); if (b) show(b.dataset.tab); });
    bar.addEventListener('keydown', (e) => { if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
      const bs = [...bar.querySelectorAll('[data-tab]')].filter((b) => b.offsetParent), i = bs.indexOf(document.activeElement); const n = bs[(i + (e.key === 'ArrowRight' ? 1 : bs.length - 1)) % bs.length]; n.focus(); show(n.dataset.tab); });
    // geliştirici modu kapanınca veritabanı sekmesinden çıkılır
    new MutationObserver(() => { if (!document.documentElement.classList.contains('dev') && !document.getElementById('dbTab').hidden) show('usersTab'); }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    const want = Object.entries(TAB_KEY).find(([, v]) => v && v === TL.qs.get('tab'));
    show(location.hash === '#risk' ? 'riskTab' : want ? want[0] : 'usersTab');
  }

  document.addEventListener('DOMContentLoaded', () => {
    tabs();
    document.getElementById('perm').innerHTML = PERMS.map(([p, a, b, c]) => { const [t, x] = p.split('|'); return [t, x, a, b, c]; }).map(([p, x, a, b, c]) => `<tr><td class="wrap">${esc(p)}${x ? `<span class="tech"> ${esc(x)}</span>` : ''}</td><td>${yes(a)}</td><td>${yes(b)}</td><td>${yes(c)}</td></tr>`).join('');
    if (can('admin')) { const b = document.getElementById('newUser'); b.hidden = false; b.onclick = newUser; }
    const box = document.getElementById('users');
    box.addEventListener('change', (e) => { const s = e.target.closest('[data-role]'); if (!s) return;
      const u = userRows.find((x) => String(x.UserID) === s.dataset.role), from = s.dataset.cur, to = s.value;
      const revert = () => { s.value = from; };
      const d = dialog(`<div class="dlg"><div class="dlg-head"><h2>Rol değiştirilsin mi?</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <p><b>${esc(u?.FullName || '')}</b> <span class="faint">@${esc(u?.Username || '')}</span>: ${esc(ROLE_NAME[from])} → <b>${esc(ROLE_NAME[to])}</b> olarak değiştirilsin mi?</p>
        <p class="muted" style="font-size:13px;margin-top:6px">Yeni yetkiler kullanıcının sonraki isteğinden itibaren geçerli olur; değişiklik denetim kaydına yazılır.</p>
        <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn primary" id="roleYes">Rolü değiştir</button></div></div>`);
      let done = false;
      d.addEventListener('close', () => { if (!done) revert(); });
      d.querySelector('#roleYes').onclick = async () => {
        try { await api(`/api/users/${s.dataset.role}`, { method: 'PATCH', body: { role: to } }); done = true; d.close(); toast('Rol güncellendi.'); users(); }
        catch (err) { toast(err.message, 'err'); }
      };
    });
    box.addEventListener('click', (e) => { const b = e.target.closest('[data-reset]'); if (!b) return;
      const d = dialog(`<form><div class="dlg-head"><h2>Parola sıfırla: @${esc(b.dataset.name)}</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <div class="field"><label for="rs-p">Geçici parola (en az 10 karakter)</label><input class="input" id="rs-p" name="password" type="password" minlength="10" required autocomplete="new-password"></div>
        <p class="faint" style="font-size: 13px">Kullanıcının tüm oturumları kapatılır; yeni parolayla giriş yapıp Parolamı değiştir menüsünden değiştirmesi önerilir.</p>
        <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Parolayı sıfırla</button></div></form>`);
      d.querySelector('form').onsubmit = async (ev) => { ev.preventDefault();
        try { await api(`/api/users/${b.dataset.reset}`, { method: 'PATCH', body: { password: formData(ev.target).password } }); d.close(); toast('Parola sıfırlandı, oturumları kapatıldı.'); }
        catch (x) { ev.target.querySelector('.err').textContent = x.message; } };
    });
    box.addEventListener('click', async (e) => { const b = e.target.closest('[data-active]'); if (!b) return;
      try { await api(`/api/users/${b.dataset.active}`, { method: 'PATCH', body: { isActive: b.dataset.v === '1' } }); toast('Kullanıcı durumu güncellendi.'); users(); } catch (err) { toast(err.message, 'err'); } });
    document.getElementById('showInactive')?.addEventListener('change', () => users().catch((e) => toast(e.message, 'err')));
    TL.meta().then((m) => {
      const el = document.getElementById('riskBands'); if (!el) return;
      const bands = m.riskBands || [];
      el.innerHTML = bands.map((b, i) => `<li><i class="sev-dot sev-${b.Code}"></i><span>${esc(b.Name)}</span><b>${b.MinScore}${i ? `–${bands[i - 1].MinScore - 1}` : '–100'}</b></li>`).join('');
    }).catch(() => {});
    users().catch((e) => toast(e.message, 'err')); system().catch((e) => toast(e.message, 'err')); retention().catch((e) => toast(e.message, 'err'));
    integrations().catch((e) => toast(e.message, 'err')); runs().catch((e) => toast(e.message, 'err'));
    document.getElementById('integrations').addEventListener('click', async (e) => {
      const b = e.target.closest('[data-test]'); if (!b) return;
      const out = document.querySelector(`[data-out="${b.dataset.test}"]`); b.disabled = true; out.className = 'test-out'; out.textContent = 'Deneniyor…';
      try { const r = await api(`/api/integrations/${b.dataset.test}/test`, { method: 'POST' }); out.className = `test-out ${r.ok ? 'ok' : 'bad'}`; out.textContent = r.message; out.title = r.message; }
      catch (err) { out.className = 'test-out bad'; out.textContent = err.message; }
      b.disabled = false;
    });
    if (can('admin')) api('/api/system/queries').then((rows) => {
      document.getElementById('qsCard').hidden = false;
      document.getElementById('qsTbl').innerHTML = rows.length ? table([
        { label: 'Sorgu', primary: true, render: (q) => `<details class="sql-clip"><summary><span class="mono trunc" title="${esc(q.QueryText.slice(0, 300))}">${esc(q.QueryText.replace(/\s+/g, ' ').trim())}</span><span class="link-btn">Göster</span></summary><pre class="mono">${esc(q.QueryText.trim())}</pre></details>` },
        { label: 'Çalışma', num: true, render: (q) => fmtN(q.Executions) },
        { label: 'Ort. ms', num: true, render: (q) => Number(q.AvgMs).toLocaleString('tr-TR') },
        { label: 'En çok ms', num: true, render: (q) => Number(q.MaxMs).toLocaleString('tr-TR') },
        { label: 'Ort. okuma', num: true, render: (q) => fmtN(Math.round(q.AvgReads)) },
        { label: 'Plan', num: true, render: (q) => q.Plans },
      ], rows, { caption: 'Query Store en pahalı sorgular' }) : empty('Query Store henüz ThreatLens sorgusu toplamadı.');
    }).catch((e) => toast(e.message, 'err'));
    document.getElementById('retention').addEventListener('input', (e) => { if (e.target.closest('[data-policy]')) markDirty(); });
    document.getElementById('retSave').addEventListener('click', saveRetention);
    document.getElementById('retReset').addEventListener('click', () => { document.querySelectorAll('#retention [data-policy]').forEach((i) => { i.value = i.dataset.orig; }); markDirty(); });
    // sayfadan çıkarken kaydedilmemiş süre değişikliği uyarısı
    window.addEventListener('beforeunload', (e) => { if (dirtyInputs().length) { e.preventDefault(); e.returnValue = ''; } });
    icons();
  });
})();
