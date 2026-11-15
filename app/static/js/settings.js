/* Ayarlar: /api/users, /api/system */
(() => {
  const { api, esc, fmtN, fmtDT, table, empty, icons, toast, can, dialog, formData } = TL;
  const ROLES = [['admin', 'Yönetici'], ['analyst', 'Analist'], ['viewer', 'İzleyici']];
  const PERMS = [  // [yetki, yönetici, analist, izleyici]
    ['Genel bakış, arama, graf ve raporları görüntüleme', 1, 1, 1],
    ['IOC ekleme, düzenleme, silme', 1, 1, 0],
    ['İlişki (kanıtlı) ekleme ve kaldırma', 1, 1, 0],
    ['Görülme (sighting) kaydı ekleme', 1, 1, 0],
    ['Dosyadan içe aktarma, besleme senkronizasyonu', 1, 1, 0],
    ['MITRE ATT&CK verisini yeniden yükleme', 1, 0, 0],
    ['Kullanıcı ve rol yönetimi', 1, 0, 0],
    ['Kaynak (Source) tablosunu değiştirme (veritabanı rolü)', 1, 0, 0],
    ['Parola özetlerini okuma (kolon düzeyi DENY)', 0, 0, 0],
    ['Denetim kaydını değiştirme/silme (INSTEAD OF tetikleyici)', 0, 0, 0],
  ];
  const yes = (v) => v ? '<span class="perm-yes" aria-label="Evet"><i data-lucide="circle-check"></i></span>' : '<span class="perm-no" aria-label="Hayır"><i data-lucide="minus"></i></span>';

  async function users() {
    const box = document.getElementById('users');
    if (!can('admin')) { box.innerHTML = `<div style="padding:16px 18px"><p class="muted">Kullanıcı yönetimi yönetici yetkisi gerektirir. Oturumunuz: <b>${esc(TL.user.FullName)}</b> (${esc(TL.user.RoleName)}).</p></div>`; return; }
    const rows = await api('/api/users');
    box.innerHTML = table([
      { label: 'Kullanıcı', primary: true, render: (u) => `<div style="display:flex;gap:10px;align-items:center"><span class="avatar" style="width:30px;height:30px;font-size:11px" aria-hidden="true">${esc(u.FullName.split(' ').map((x) => x[0]).join('').slice(0, 2).toUpperCase())}</span><span><b>${esc(u.FullName)}</b><br><small class="muted">@${esc(u.Username)}</small></span></div>` },
      { label: 'Rol', render: (u) => `<label class="sr-only" for="r${u.UserID}">${esc(u.Username)} rolü</label><select class="input" id="r${u.UserID}" data-role="${u.UserID}" style="width:auto;height:30px">${ROLES.map(([c, l]) => `<option value="${c}" ${c === u.Role ? 'selected' : ''}>${l}</option>`).join('')}</select>` },
      { label: 'Durum', render: (u) => u.IsActive ? '<span class="badge b-ok">Aktif</span>' : '<span class="badge b-muted">Devre dışı</span>' },
      { label: 'Son giriş', render: (u) => u.LastLoginAt ? fmtDT(u.LastLoginAt) : '<span class="faint">Hiç</span>' },
      { label: 'Denetim olayı', num: true, render: (u) => fmtN(u.AuditCount) },
      { label: '', render: (u) => u.UserID === TL.user.UserID ? '<span class="faint" style="font-size:12px">Siz</span>' : `<button class="btn sm" data-active="${u.UserID}" data-v="${u.IsActive ? 0 : 1}">${u.IsActive ? 'Devre dışı bırak' : 'Etkinleştir'}</button>` },
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
    document.getElementById('dbroles').innerHTML = d.dbRoles.map((r) => `<div class="bar-row"><span class="mono">${esc(r.RoleName)}</span><span class="muted" style="font-size:12.5px">${r.Grants} GRANT · ${r.Denies} DENY</span><span></span></div>`).join('');
    document.getElementById('graph').innerHTML = table([
      { label: 'Nesne', primary: true, render: (g) => `<span class="mono">${esc(g.ObjectName)}</span>` }, { label: 'Tür', render: (g) => g.Kind === 'node' ? 'Düğüm' : 'Kenar' },
      { label: 'İlişkisel', num: true, render: (g) => fmtN(g.Relational) }, { label: 'Graf', num: true, render: (g) => fmtN(g.Graph) },
      { label: 'Durum', render: (g) => g.IsConsistent ? '<span class="badge b-ok">Tutarlı</span>' : '<span class="badge b-bad">Tutarsız</span>' }], d.graph, { caption: 'Graf tutarlılığı' });
    const key = d.integrations.abusechKey;
    document.getElementById('integrations').innerHTML = [
      ['MITRE ATT&CK Enterprise', 'Yerel STIX 2.1 anlık görüntüsü (v20.1) · anahtar gerekmez', true, 'Yüklü'],
      ['abuse.ch ThreatFox / MalwareBazaar / URLhaus', key ? 'ABUSECH_AUTH_KEY tanımlı' : 'ABUSECH_AUTH_KEY tanımlı değil (.env)', key, key ? 'Hazır' : 'Anahtar gerekli'],
      ['abuse.ch Feodo Tracker', 'Herkese açık IP engelleme listesi · anahtar gerekmez', true, 'Hazır'],
      ['CISA KEV', 'Herkese açık zafiyet kataloğu · anahtar gerekmez', true, 'Hazır'],
    ].map(([n, s, ok, l]) => `<li><div><span><b>${esc(n)}</b><br><small>${esc(s)}</small></span><span class="badge ${ok ? 'b-ok' : 'b-warn'}">${l}</span></div></li>`).join('');
    icons();
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

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('perm').innerHTML = PERMS.map(([p, a, b, c]) => `<tr><td>${esc(p)}</td><td>${yes(a)}</td><td>${yes(b)}</td><td>${yes(c)}</td></tr>`).join('');
    if (can('admin')) { const b = document.getElementById('newUser'); b.hidden = false; b.onclick = newUser; }
    const box = document.getElementById('users');
    box.addEventListener('change', async (e) => { const s = e.target.closest('[data-role]'); if (!s) return;
      try { await api(`/api/users/${s.dataset.role}`, { method: 'PATCH', body: { role: s.value } }); toast('Rol güncellendi.'); } catch (err) { toast(err.message, 'err'); users(); } });
    box.addEventListener('click', async (e) => { const b = e.target.closest('[data-active]'); if (!b) return;
      try { await api(`/api/users/${b.dataset.active}`, { method: 'PATCH', body: { isActive: b.dataset.v === '1' } }); toast('Kullanıcı durumu güncellendi.'); users(); } catch (err) { toast(err.message, 'err'); } });
    users().catch((e) => toast(e.message, 'err')); system().catch((e) => toast(e.message, 'err'));
    icons();
  });
})();
