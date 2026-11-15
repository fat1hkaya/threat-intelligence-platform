/* IOC detay sayfası: /api/iocs/{id}, /api/iocs/{id}/relationships */
(() => {
  const { api, esc, fmtDT, sev, typeBadge, conf, status, sourceBadge, copyBtn, table, empty, icons, toast, dialog, formData, can, list } = TL;
  const root = document.getElementById('root'), id = +root.dataset.id;
  const ACTION = { I: ['Eklendi', 'b-ok'], U: ['Güncellendi', 'b-warn'], D: ['Silindi', 'b-bad'] };
  const ROLE = { c2: 'Komuta-kontrol (C2)', payload: 'Yük (payload)', dropper: 'Bırakıcı (dropper)', exfil: 'Veri sızdırma', phishing: 'Oltalama', other: 'Diğer' };

  // Açıklanabilir risk skoru: fn_RiskBreakdown bileşenleri
  const n = (x, k = 1) => Number(x).toLocaleString('tr-TR', { minimumFractionDigits: k, maximumFractionDigits: k });
  function riskCard(r, i) {
    if (!r) return '';
    const parts = [['Güven', r.ConfidencePart, `${i.Confidence} × 0,45`, 'var(--cyan)'], ['Önem', r.SeverityPart, `${r.SeverityWeight} × 0,35`, 'var(--purple)'],
      ['Görülme', r.SightingPart, `${i.SightingCount} × 2 (en çok 20)`, 'var(--medium)']];
    const factors = [['Kaynak güvenilirliği', r.ReliabilityFactor, `${i.Reliability} sınıfı`], ['Tazelik', r.FreshnessFactor, `${r.AgeDays} gün önce görüldü`],
      ['Durum', r.StatusFactor, i.Status === 'active' ? 'aktif' : 'aktif değil (yarıya iner)']];
    return `<article class="card"><div class="card-head"><div><h2>Risk skoru: ${r.Score} / 100</h2><p>Nasıl hesaplandı? (fn_RiskBreakdown)</p></div></div>
      <div style="display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--elev-2)" role="img" aria-label="Taban puanın bileşenleri">
        ${parts.map(([, v, , c]) => `<i style="width:${v}%;background:${c}"></i>`).join('')}</div>
      <dl class="kv" style="margin-top:12px">${parts.map(([l, v, how, c]) => `<dt><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${c};margin-right:6px"></span>${l}</dt><dd><b>${n(v)}</b> <span class="faint">(${how})</span></dd>`).join('')}
        <dt>Taban puan</dt><dd><b>${n(r.BasePoints)}</b></dd>
        ${factors.map(([l, v, how]) => `<dt>× ${l}</dt><dd><b>${n(v, 2)}</b> <span class="faint">(${esc(how)})</span></dd>`).join('')}
        <dt>= Skor</dt><dd><b>${r.Score}</b> <span class="faint">(${n(r.BasePoints)} × ${n(r.ReliabilityFactor, 2)} × ${n(r.FreshnessFactor, 2)} × ${n(r.StatusFactor, 1)}, yuvarlanmış)</span></dd></dl></article>`;
  }

  // Zaman yolculuğu: tarayıcıdaki yerel saat UTC'ye çevrilip gönderilir
  async function timeTravel() {
    const at = document.getElementById('asofAt');
    const local = new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    at.value = local; at.max = local;
    const vs = await api(`/api/iocs/${id}/versions`);
    const SEVN = TL.SEV;
    document.getElementById('versions').innerHTML = vs.map((v) => `<li><span class="dot ${v.IsCurrent ? 'done' : ''}"></span><div>
        <b>${fmtDT(v.ValidFrom)}</b>${v.ValidTo ? ` → ${fmtDT(v.ValidTo)}` : ' → şimdi'}<br>
        <small class="muted">${esc(v.Status)} · güven ${v.Confidence} · ${esc(SEVN[v.SeverityCode] || v.SeverityCode)} · son görülme ${fmtDT(v.LastSeen)} · bitiş ${fmtDT(v.ExpiresAt)}</small></div></li>`).join('');
    document.getElementById('asofForm').onsubmit = async (e) => {
      e.preventDefault();
      const out = document.getElementById('asofOut');
      const r = await api(`/api/iocs/${id}/asof`, { params: { at: new Date(at.value).toISOString() } });
      out.innerHTML = r.state
        ? `<p class="notice"><i data-lucide="history"></i><span>O anda: <b>${esc(r.state.Status)}</b>, güven ${r.state.Confidence}, ${esc(SEVN[r.state.SeverityCode] || '')}, son görülme ${fmtDT(r.state.LastSeen)}, bitiş ${fmtDT(r.state.ExpiresAt)}.
           Zararlı ilişkileri: ${r.malware.length ? r.malware.map((m) => esc(m.MalwareName)).join(', ') : 'yok'}. <span class="faint">(Bu sürüm ${fmtDT(r.state.ValidFrom)} itibarıyla geçerli.)</span></span></p>`
        : '<p class="notice warn"><i data-lucide="history"></i><span>Bu tarihte kayıt yok: IOC henüz eklenmemişti ya da sürüm takibi o tarihten sonra başladı.</span></p>';
      icons();
    };
  }

  async function load() {
    let d, rel;
    try { [d, rel] = await Promise.all([api(`/api/iocs/${id}`), api(`/api/iocs/${id}/relationships`)]); }
    catch (e) { root.innerHTML = empty(e.message, 'circle-alert'); icons(); return; }
    const i = d.indicator;
    document.getElementById('crumb').textContent = i.Value.length > 48 ? i.Value.slice(0, 48) + '…' : i.Value;
    document.title = `${i.Value.slice(0, 40)} · ThreatLens`;
    const writer = can('analyst');
    root.innerHTML = `
      <div class="page-head" style="margin-bottom:18px">
        <div class="entity-title">${TL.nodeIcon('indicator')}<div style="min-width:0">
          <h1 class="mono" style="font-size:18px;overflow-wrap:anywhere">${esc(i.Value)}</h1>
          <div class="chips" style="margin-top:8px">${typeBadge(i.TypeCode)}${sev(i.SeverityCode)}${status(i.Status)}<span class="badge b-muted">${esc(i.TLPCode)}</span>${sourceBadge(i.SourceName)}</div>
          <div class="chips" id="caseChips" style="margin-top:6px"></div>
          ${i.OriginalValue !== i.Value ? `<p class="faint" style="font-size:12.5px;margin-top:6px">Kaynaktaki yazımı: <span class="mono">${esc(i.OriginalValue)}</span></p>` : ''}
        </div></div>
        <div class="page-actions">${copyBtn(i.Value).replace('btn sm icon ghost', 'btn').replace('</i>', '</i>Kopyala')}
          <a class="btn" href="${TL.graphUrl('indicator', id)}"><i data-lucide="share-2"></i>İlişki grafı</a>${TL.caseBtn('indicator', id, i.Value, 'btn')}
          <a class="btn" href="/api/export/stix/indicator/${id}" download title="STIX 2.1 paketi: IOC, bağlı zararlı yazılımlar ve aktörler"><i data-lucide="download"></i>STIX</a>
          ${writer ? `<button class="btn" id="sightBtn"><i data-lucide="eye"></i>Görülme ekle</button><button class="btn" id="linkBtn"><i data-lucide="link"></i>İlişki ekle</button>
          <button class="btn primary" id="editBtn"><i data-lucide="pencil"></i>Düzenle</button><button class="btn danger" id="delBtn" aria-label="Sil"><i data-lucide="trash-2"></i></button>` : ''}</div>
      </div>
      <div class="grid g-main-side">
        <div class="grid" style="align-content:start">
          <article class="card"><div class="card-head"><div><h2>Atıf zinciri</h2><p>SQL Graph: vw_IndicatorAttribution görünümü (MATCH)</p></div></div>${TL.chains(i, rel.attribution)}</article>
          <article class="card flush"><div class="card-head"><div><h2>Çok adımlı MATCH: IOC → zararlı ← aktör → teknik</h2><p>sp_IndicatorKillChain sonucu (${rel.killchain.length} satır)</p></div></div>
            ${rel.killchain.length ? table([{ label: 'Zararlı', render: (r) => esc(r.Malware) }, { label: 'Aktör', render: (r) => esc(r.Actor) },
              { label: 'Teknik', primary: true, render: (r) => `<span class="mono">${esc(r.ExternalID)}</span> ${esc(r.Technique)}` }], rel.killchain.slice(0, 30), { caption: 'Kill chain' })
              + (rel.killchain.length > 30 ? `<p class="faint" style="padding:10px 16px;font-size:12.5px">İlk 30 satır gösteriliyor.</p>` : '') : empty('Zararlı yazılımı kullanan bilinen bir aktör yok.', 'git-branch')}</article>
          <article class="card flush"><div class="card-head"><h2>Değişiklik geçmişi</h2><p>AuditLog (tetikleyiciyle yazılır)</p></div>
            ${d.history.length ? table([{ label: 'Zaman', render: (h) => fmtDT(h.ChangedAt) }, { label: 'İşlem', render: (h) => `<span class="badge ${ACTION[h.Action][1]}">${ACTION[h.Action][0]}</span>` },
              { label: 'Kullanıcı', render: (h) => esc(h.ChangedBy || 'Sistem / toplu içe aktarma') },
              { label: 'Değişen alanlar', render: (h) => { const o = h.OldValues || {}, n = h.NewValues || {}; const keys = Object.keys({ ...o, ...n }).filter((k) => JSON.stringify(o[k]) !== JSON.stringify(n[k]));
                  return keys.length ? keys.map((k) => `<span class="mono" style="font-size:12px">${esc(k)}: ${esc(o[k] ?? '∅')} → ${esc(n[k] ?? '∅')}</span>`).join('<br>') : '<span class="faint">—</span>'; } }], d.history)
              : empty('Kayıt yok. Toplu içe aktarmalar satır başına denetim kaydı üretmez; özet ImportJob tablosundadır.', 'history')}</article>
        </div>
        <div class="grid" style="align-content:start">
          <article class="card"><h2 style="margin-bottom:12px">Özellikler</h2><dl class="kv">
            <dt>Güven skoru</dt><dd>${conf(i.Confidence)}</dd><dt>Risk skoru</dt><dd><b>${i.RiskScore}</b> / 100 <span class="faint">(fn_RiskScore)</span></dd>
            <dt>Kaynak</dt><dd>${esc(i.SourceName)} <span class="faint">(${esc(i.Reliability)})</span></dd>
            <dt>İlk görülme</dt><dd>${fmtDT(i.FirstSeen)}</dd><dt>Son görülme</dt><dd>${fmtDT(i.LastSeen)}</dd>
            <dt>Bitiş</dt><dd>${i.ExpiresAt ? fmtDT(i.ExpiresAt) : '—'}</dd><dt>Eklendi</dt><dd>${fmtDT(i.CreatedAt)}</dd><dt>Güncellendi</dt><dd>${fmtDT(i.UpdatedAt)}</dd>
            <dt>Sürüm (RowVer)</dt><dd class="mono">${esc(i.RowVer)}</dd>
            <dt>Etiketler</dt><dd>${i.Tags.length ? `<div class="chips">${i.Tags.map((t) => `<a class="chip" href="/iocs?tag=${encodeURIComponent(t)}">${esc(t)}</a>`).join('')}</div>` : '—'}</dd>
            <dt>Açıklama</dt><dd>${esc(i.Description || '—')}</dd></dl></article>
          ${riskCard(d.risk, i)}
          <article class="card" id="timeCard"><div class="card-head"><div><h2>Zaman yolculuğu</h2><p>Sistem sürümlü tablo: FOR SYSTEM_TIME AS OF / ALL</p></div></div>
            <form id="asofForm" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
              <div class="field" style="flex:1;min-width:180px"><label for="asofAt">Bu tarihteki hâli</label><input class="input" id="asofAt" type="datetime-local" required></div>
              <button class="btn">Göster</button></form>
            <div id="asofOut" style="margin-top:10px"></div>
            <h3 style="margin-top:14px">Sürümler</h3><ol class="timeline" id="versions" style="margin-top:8px"></ol></article>
          <article class="card"><h2 style="margin-bottom:10px">Kurum içi görülmeler (${d.sightings.length})</h2>
            ${list(d.sightings.slice(0, 8), (s) => `<li><div><span>${esc(s.Location || 'Konum yok')}<br><small>${fmtDT(s.SightedAt)} · ${esc(s.ReportedBy || '—')}</small></span><b>${s.Quantity}×</b></div></li>`, 'Bu IOC kurum içinde görülmedi.')}</article>
          <article class="card"><h2 style="margin-bottom:10px">Aynı zararlıya bağlı diğer IOC'ler</h2>
            ${list(d.related, (r) => `<li><a href="/iocs/${r.IndicatorID}"><span class="mono value" style="max-width:220px">${esc(r.Value)}</span>${sev(r.SeverityCode)}</a></li>`, 'İlişkili IOC yok.')}</article>
        </div>
      </div>`;
    icons();
    timeTravel();
    TL.caseChips('indicator', id).then((h) => { const el = document.getElementById('caseChips'); if (el && h) { el.innerHTML = h; icons(); } });
    if (!writer) return;
    document.getElementById('editBtn').onclick = () => TL.iocForm(i, load);
    document.getElementById('delBtn').onclick = () => {
      const dl = dialog(`<div class="dlg"><h2>IOC silinsin mi?</h2><p class="muted"><span class="mono">${esc(i.Value)}</span> kalıcı olarak silinir. Görülmeler, etiketler ve ilişkiler (graf kenarları dahil) birlikte silinir; işlem denetim kaydına yazılır.</p>
        <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn primary" id="yes">Kalıcı olarak sil</button></div></div>`);
      dl.querySelector('#yes').onclick = async () => { try { await api(`/api/iocs/${id}`, { method: 'DELETE' }); toast('IOC silindi.'); location.href = '/iocs'; } catch (e) { toast(e.message, 'err'); } };
    };
    document.getElementById('sightBtn').onclick = () => {
      const dl = dialog(`<form><div class="dlg-head"><h2>Görülme ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <div class="form-grid"><div class="field"><label for="sq">Adet</label><input class="input" id="sq" name="quantity" type="number" min="1" value="1"></div>
        <div class="field"><label for="sl">Nerede görüldü</label><input class="input" id="sl" name="location" maxlength="100" placeholder="EDR / WS-0142"></div>
        <div class="field full"><label for="sn">Not</label><textarea class="input" id="sn" name="note" maxlength="400"></textarea></div></div>
        <p class="faint" style="font-size:12.5px">trg_Sighting_AfterInsert tetikleyicisi IOC'nin son görülme zamanını ileri alır.</p>
        <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Görülme ekle</button></div></form>`);
      dl.querySelector('form').onsubmit = async (e) => { e.preventDefault(); const f = formData(e.target);
        try { await api(`/api/iocs/${id}/sightings`, { method: 'POST', body: { quantity: +f.quantity || 1, location: f.location || null, note: f.note || null } }); dl.close(); toast('Görülme eklendi.'); load(); }
        catch (err) { e.target.querySelector('.err').textContent = err.message; } };
    };
    document.getElementById('linkBtn').onclick = () => linkDialog();
  }

  function linkDialog() {
    const dl = dialog(`<form><div class="dlg-head"><h2>İlişki ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="notice"><i data-lucide="info"></i>Kanıtsız ilişki kurulamaz. Önce Evidence satırı, sonra ara tablo satırı yazılır; tetikleyici aynı transaction içinde graf kenarını oluşturur.</p>
      <div class="form-grid">
        <div class="field"><label for="lk-kind">Bağlanacak varlık</label><select class="input" id="lk-kind" name="kind"><option value="malware-indicator">Zararlı yazılım</option><option value="campaign-indicator">Kampanya</option></select></div>
        <div class="field"><label for="lk-role">Rol (zararlı için)</label><select class="input" id="lk-role" name="role">${Object.entries(ROLE).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select></div>
        <div class="field full"><label for="lk-q">Ara</label><input class="input" id="lk-q" autocomplete="off" placeholder="Ad yazın (ör. Emotet, SolarWinds)"><div id="lk-res" class="list" style="max-height:180px;overflow:auto"></div>
          <input type="hidden" name="target" id="lk-target"><small id="lk-sel" class="faint">Henüz seçilmedi</small></div>
        <div class="field"><label for="lk-conf">Güven (0–100)</label><input class="input" id="lk-conf" name="confidence" type="number" min="0" max="100" value="60"></div>
        <div class="field"><label for="lk-url">Kanıt bağlantısı (isteğe bağlı)</label><input class="input" id="lk-url" name="evidenceUrl" type="url" maxlength="400"></div>
        <div class="field full"><label for="lk-ev">Kanıt (bu ilişkiyi neye dayanarak kuruyorsunuz?)</label><textarea class="input" id="lk-ev" name="evidence" required minlength="5" maxlength="1000"></textarea></div>
      </div><p class="err" role="alert"></p>
      <div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">İlişkiyi kaydet</button></div></form>`);
    const q = dl.querySelector('#lk-q'), res = dl.querySelector('#lk-res'), kind = dl.querySelector('#lk-kind');
    const search = TL.debounce(async () => {
      if (q.value.trim().length < 2) { res.innerHTML = ''; return; }
      const url = kind.value === 'malware-indicator' ? '/api/malware' : '/api/campaigns';
      const r = await api(url, { params: { q: q.value.trim(), size: 8 } });
      res.innerHTML = r.items.map((x) => `<li><a href="#" data-id="${x.MalwareID || x.CampaignID}" data-name="${esc(x.Name)}">${esc(x.Name)}<small>${esc(x.TypeName || x.ActorName || '')}</small></a></li>`).join('') || '<li class="faint">Sonuç yok</li>';
    });
    q.addEventListener('input', search); kind.addEventListener('change', () => { res.innerHTML = ''; dl.querySelector('#lk-target').value = ''; dl.querySelector('#lk-sel').textContent = 'Henüz seçilmedi'; search(); });
    res.addEventListener('click', (e) => { const a = e.target.closest('a[data-id]'); if (!a) return; e.preventDefault();
      dl.querySelector('#lk-target').value = a.dataset.id; dl.querySelector('#lk-sel').textContent = `Seçilen: ${a.dataset.name}`; });
    dl.querySelector('form').onsubmit = async (e) => {
      e.preventDefault(); const f = formData(e.target);
      if (!f.target) { e.target.querySelector('.err').textContent = 'Listeden bir varlık seçin.'; return; }
      try { await api('/api/links', { method: 'POST', body: { kind: f.kind, a: +f.target, b: id, role: f.kind === 'malware-indicator' ? f.role : null,
          confidence: f.confidence === '' ? null : +f.confidence, evidence: f.evidence, evidenceUrl: f.evidenceUrl || null } });
        dl.close(); toast('İlişki kaydedildi.'); load(); }
      catch (err) { e.target.querySelector('.err').textContent = err.message; }
    };
  }
  document.addEventListener('DOMContentLoaded', load);
})();
