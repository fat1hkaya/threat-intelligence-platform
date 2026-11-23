/* IOC detay sayfası: /api/iocs/{id}, /api/iocs/{id}/relationships */
(() => {
  const { api, esc, fmtDT, sev, typeBadge, conf, status, sourceBadge, copyBtn, table, empty, icons, toast, dialog, formData, can, list } = TL;
  const root = document.getElementById('root'), id = +root.dataset.id;
  const ACTION = { I: ['Eklendi', 'b-ok'], U: ['Güncellendi', 'b-warn'], D: ['Silindi', 'b-bad'] };
  // Denetim kaydındaki alan adlarının kullanıcı dilindeki karşılığı
  const FIELD = { Status: 'Durum', Confidence: 'Güven', SeverityID: 'Önem', TLPID: 'TLP', Description: 'Açıklama', ExpiresAt: 'Geçerlilik sonu', LastSeen: 'Son görülme',
    FirstSeen: 'İlk görülme', SourceID: 'Kaynak', Value: 'Değer', NormalizedValue: 'Kanonik değer', TypeID: 'Tip' };
  const STATUS_TR = { active: 'Aktif', expired: 'Süresi doldu', revoked: 'İptal edildi', false_positive: 'Yanlış pozitif' };
  const val = (k, v) => v == null || v === '' ? '<span class="faint">boş</span>' : esc(k === 'Status' ? (STATUS_TR[v] || v) : v);
  /** Önce/sonra farkı: alan bazında; değişen alanlar vurgulu. Silinen kayıtta "silinmeden önceki hâli". */
  const diff = (h) => {
    const o = h.OldValues || {}, nv = h.NewValues || {};
    const keys = Object.keys({ ...o, ...nv });
    if (!keys.length) return '<span class="faint">Alan ayrıntısı yok</span>';
    const changed = (k) => JSON.stringify(o[k]) !== JSON.stringify(nv[k]);
    const shown = h.Action === 'U' ? keys.filter(changed) : keys;
    return `<table class="diff"><thead><tr><th scope="col">Alan</th>${h.Action !== 'I' ? `<th scope="col">${h.Action === 'D' ? 'Silinmeden önceki hâli' : 'Önce'}</th>` : ''}${h.Action !== 'D' ? '<th scope="col">Sonra</th>' : ''}</tr></thead><tbody>
      ${shown.map((k) => `<tr class="${h.Action === 'U' ? 'changed' : ''}"><th scope="row">${esc(FIELD[k] || k)}</th>${h.Action !== 'I' ? `<td class="old">${val(k, o[k])}</td>` : ''}${h.Action !== 'D' ? `<td class="new">${val(k, nv[k])}</td>` : ''}</tr>`).join('')}</tbody></table>`;
  };
  const ROLE = { c2: 'Komuta-kontrol (C2)', payload: 'Yük (payload)', dropper: 'Bırakıcı (dropper)', exfil: 'Veri sızdırma', phishing: 'Oltalama', other: 'Diğer' };

  // Açıklanabilir risk skoru: fn_RiskBreakdown bileşenleri
  const n = (x, k = 1) => Number(x).toLocaleString('tr-TR', { minimumFractionDigits: k, maximumFractionDigits: k });
  function riskCard(r, i) {
    if (!r) return '';
    const [code, band] = TL.riskBand(r.Score);
    const parts = [['Güven', r.ConfidencePart, `${i.Confidence} × 0,55`, 'var(--accent)'], ['Önem', r.SeverityPart, `${esc(TL.SEV[i.SeverityCode] || '')} ${r.SeverityWeight} × 0,45`, 'color-mix(in srgb, var(--accent) 50%, transparent)']];
    const factors = [['kaynak', r.ReliabilityFactor, `${i.Reliability} sınıfı`], ['tazelik', r.FreshnessFactor, `${r.AgeDays} gün önce görüldü`],
      ['durum', r.StatusFactor, i.Status === 'active' ? 'aktif' : 'aktif değil']];
    return `<div class="gauge"><svg viewBox="0 0 112 62" role="img" aria-label="Risk ${r.Score} / 100, ${esc(band)} bant">
        <path d="M8 56 A48 48 0 0 1 104 56" pathLength="100" class="g-track"/><path d="M8 56 A48 48 0 0 1 104 56" pathLength="100" class="g-val band-stroke-${code}" style="stroke-dasharray:${r.Score} 100"/></svg>
      <div><div class="g-big">${r.Score}<small> / 100</small></div><div class="g-band"><i class="band-${code}" aria-hidden="true"></i>${esc(band)} bant</div></div></div>
      <div class="pk-legend" style="margin-top:12px">${parts.map(([l, v, how, c]) => `<i style="background:${c}"></i><span>${l} <span class="faint">${how}</span></span><b>${n(v)}</b>`).join('')}
        <i style="background:var(--line-strong)"></i><span>Taban puan</span><b>${n(r.BasePoints)}</b>
        <span class="eq">${factors.map(([l, v, how]) => `<span title="${esc(how)}">× ${l} ${n(v, 2)}</span>`).join(' · ')}</span>
        <i style="background:var(--text-3)"></i><span>+ kurumda görülme <span class="faint">${i.SightingCount} × 2 (en çok 20)</span></span><b>${n(r.SightingPart)}</b>
        <span class="eq">= <b>${r.Score}</b> <span class="faint">(0–100, yuvarlanmış)</span><span class="tech"> · fn_RiskBreakdown</span></span></div>`;
  }
  /** Yatay atıf zinciri: IOC → zararlı → aktör düğüm kartları, aralarında oklar (ilk zincir; tümü İlişkiler sekmesinde) */
  function pathCard(i, attribution) {
    const node = (color, kind, title, sub, href) => `<${href ? `a href="${href}"` : 'div'} class="pnode"><small><i style="background:var(${color})" aria-hidden="true"></i>${kind}</small><b title="${esc(title)}">${esc(title)}</b><span title="${esc(sub)}">${esc(sub)}</span></${href ? 'a' : 'div'}>`;
    const arr = '<span class="parr" aria-hidden="true"><i data-lucide="arrow-right"></i></span>';
    const first = attribution[0];
    const actors = first ? [...new Set(attribution.filter((a) => a.ViaID === first.ViaID && a.ActorID).map((a) => a.ActorName))] : [];
    const firstActor = first ? attribution.find((a) => a.ViaID === first.ViaID && a.ActorID) : null;
    return `<ol class="ppath" aria-label="Atıf zinciri">
      <li>${node('--n-ioc', 'Gösterge', TL.TYPE_LABEL[i.TypeCode] || i.TypeCode, TL.sourceShort(i.SourceName))}</li><li aria-hidden="true">${arr}</li>
      <li>${first ? node(first.ViaType === 'malware' ? '--n-malware' : '--n-campaign', first.ViaType === 'malware' ? 'Zararlı yazılım' : 'Kampanya', first.ViaName, `kanıt: ${first.EvidenceSource || 'kaynak belirtilmemiş'}`, TL.entityUrl(first.ViaType, first.ViaID))
        : node('--line-strong', 'Zararlı yazılım', 'Ailesi belirlenmemiş', 'ilişki kaydı yok')}</li><li aria-hidden="true">${arr}</li>
      <li>${actors.length ? node('--n-actor', 'Tehdit aktörü', actors.join(', '), firstActor.ActorEvidenceSource || 'MITRE ATT&CK', TL.entityUrl('actor', firstActor.ActorID))
        : node('--line-strong', 'Tehdit aktörü', 'Bilinmiyor', 'aktör kaydı yok')}</li></ol>
      ${new Set(attribution.map((a) => `${a.ViaType}${a.ViaID}`)).size > 1 ? `<p class="faint" style="font-size:12px;margin-top:8px">${new Set(attribution.map((a) => `${a.ViaType}${a.ViaID}`)).size} zincir var; tümü İlişkiler sekmesinde.</p>` : ''}`;
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
    document.title = `${i.Value.slice(0, 40)} · ThreatLens`;
    const writer = can('analyst');
    const techs = [...new Map(rel.malwareTechniques.map((t) => [t.ExternalID, t])).values()];
    const relCount = new Set(rel.attribution.map((a) => `${a.ViaType}${a.ViaID}`)).size + d.related.length;
    const tab = (key, label, count) => `<button type="button" role="tab" id="tab-${key}" aria-controls="p-${key}" data-tab="${key}">${label}${count != null ? `<em>${TL.fmtN(count)}</em>` : ''}</button>`;
    root.innerHTML = `
      <div class="page-head file-head">
        <div class="ph-title file-title"><span class="pk-kind"><i data-lucide="hash" aria-hidden="true"></i>IOC · ${esc(TL.TYPE_LABEL[i.TypeCode] || i.TypeCode)}</span>
          <h1 class="mono">${esc(i.Value)}</h1>
          <div class="pk-tags">${sev(i.SeverityCode)}${status(i.Status)}<span class="badge" title="Kaynak ve güvenilirlik derecesi">${esc(TL.sourceShort(i.SourceName))} · ${esc(i.Reliability)}</span><span class="badge">Güven ${i.Confidence}</span><span class="badge">${esc(i.TLPCode)}</span></div>
          <div class="chips" id="caseChips"></div>
          ${i.OriginalValue !== i.Value ? `<p class="faint" style="font-size:12px">Kaynaktaki yazımı: <span class="mono">${esc(i.OriginalValue)}</span></p>` : ''}
        </div>
        <div class="page-actions">${copyBtn(i.Value).replace('btn sm icon ghost', 'btn').replace('</i>', '</i>Kopyala')}
          <a class="btn" href="${TL.graphUrl('indicator', id)}"><i data-lucide="share-2"></i>Grafta aç</a>${TL.caseBtn('indicator', id, i.Value, 'btn')}
          <a class="btn" href="/api/export/stix/indicator/${id}" download title="STIX 2.1 paketi: IOC, bağlı zararlı yazılımlar ve aktörler"><i data-lucide="download"></i>STIX</a>
          ${writer ? `<button class="btn" id="sightBtn"><i data-lucide="eye"></i>Görülme ekle</button><button class="btn" id="statusBtn"><i data-lucide="circle-dot"></i>Durumu değiştir</button><button class="btn" id="linkBtn"><i data-lucide="link"></i>İlişki ekle</button>
          <button class="btn icon danger" id="delBtn" aria-label="IOC'yi sil" title="IOC'yi sil"><i data-lucide="trash-2"></i></button><button class="btn primary" id="editBtn"><i data-lucide="pencil"></i>Düzenle</button>` : ''}</div>
      </div>
      <div class="ftabs" role="tablist" aria-label="IOC bölümleri">${tab('ozet', 'Özet')}${tab('iliskiler', 'İlişkiler', relCount)}${tab('gorulmeler', 'Görülmeler', d.sightings.length)}${tab('gecmis', 'Geçmiş', d.history.length)}</div>

      <div id="p-ozet" role="tabpanel" aria-labelledby="tab-ozet" class="file-grid">
        <div class="file-main">
          <article class="card"><div class="file-sum"><section aria-label="Risk puanı"><h2 class="sec-h">Risk puanı</h2>${riskCard(d.risk, i)}</section>
            <section aria-label="Atıf zinciri"><h2 class="sec-h">Atıf zinciri</h2>${pathCard(i, rel.attribution)}</section></div></article>
          <article class="card" id="netCard" hidden></article>
          ${i.Description ? `<article class="card"><h2 class="sec-h">Açıklama</h2>${TL.clampText(i.Description)}</article>` : ''}
        </div>
        <aside class="file-side" aria-label="Özellikler">
          <article class="card"><h2 class="sec-h">Özellikler</h2><dl class="kv kv-shodan">
            <dt>Tip</dt><dd>${esc(TL.TYPE_LABEL[i.TypeCode] || i.TypeCode)}</dd>
            <dt>Kaynak</dt><dd title="${esc(i.SourceName)}">${esc(i.SourceName)} <span class="faint">(${esc(i.Reliability)})</span></dd>
            <dt>Güven</dt><dd>${conf(i.Confidence)}</dd>
            <dt>İlk görülme</dt><dd>${fmtDT(i.FirstSeen)}</dd><dt>Son görülme</dt><dd title="${fmtDT(i.LastSeen)}">${TL.ago(i.LastSeen)}</dd>
            <dt>Geçerlilik sonu</dt><dd>${i.ExpiresAt ? fmtDT(i.ExpiresAt) : '—'}</dd>
            <dt>Kurumda görülme</dt><dd>${i.SightingCount ? `${TL.fmtN(i.SightingCount)} kez` : '<span class="faint">Görülmedi</span>'}</dd>
            <dt>Eklendi</dt><dd>${fmtDT(i.CreatedAt)}</dd><dt>Güncellendi</dt><dd>${fmtDT(i.UpdatedAt)}</dd>
            <dt class="tech">Sürüm (RowVer)</dt><dd class="mono tech">${esc(i.RowVer)}</dd>
            <dt>Etiketler</dt><dd>${i.Tags.length ? `<div class="chips">${i.Tags.map((t) => `<a class="chip" href="/iocs?tag=${encodeURIComponent(t)}">${esc(t)}</a>`).join('')}</div>` : '—'}</dd></dl></article>
          <article class="card"><h2 class="sec-h">Teknikler${techs.length ? ` (${techs.length})` : ''}</h2>
            ${techs.length ? `<div class="pk-tech">${techs.slice(0, 10).map((t) => `<a class="chip" href="/attack?id=${t.TechniqueID}" title="${esc(t.ExternalID)} ${esc(t.Technique)} (${esc(t.Malware)} üzerinden)"><span class="mono">${esc(t.ExternalID)}</span>${esc(t.Technique)}</a>`).join('')}
              ${techs.length > 10 ? `<button type="button" class="chip" data-goto="iliskiler">+${techs.length - 10}</button>` : ''}</div>` : '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>'}</article>
        </aside>
      </div>

      <div id="p-iliskiler" role="tabpanel" aria-labelledby="tab-iliskiler" hidden class="tab-panel">
        <article class="card chain-card"><div class="card-head"><div><h2>Atıf zincirleri</h2><p>IOC → zararlı yazılım → aktör; her bağlantının kanıtı ve kaynağı altında<span class="tech"> · vw_IndicatorAttribution (MATCH)</span></p></div></div>${TL.chains(i, rel.attribution)}</article>
        <div class="grid g-main-side">
          <article class="card flush"><div class="card-head"><div><h2>Olası teknikler: IOC → zararlı → aktör → teknik</h2><p>Bağlı aktörlerin kullandığı teknikler (${rel.killchain.length})<span class="tech"> · sp_IndicatorKillChain</span></p></div></div>
            ${rel.killchain.length ? table([{ label: 'Zararlı', render: (r) => esc(r.Malware) }, { label: 'Aktör', render: (r) => esc(r.Actor) },
              { label: 'Teknik', primary: true, render: (r) => `<span class="mono">${esc(r.ExternalID)}</span> ${esc(r.Technique)}` }], rel.killchain.slice(0, 30), { caption: 'Kill chain' })
              + (rel.killchain.length > 30 ? `<p class="faint" style="padding:10px 16px;font-size: 13px">İlk 30 satır gösteriliyor.</p>` : '') : empty('Zararlı yazılımı kullanan bilinen bir aktör yok.', 'git-branch')}</article>
          <article class="card"><h2 class="sec-h">Aynı zararlıya bağlı diğer IOC'ler</h2>
            ${list(d.related, (r) => `<li><a href="/iocs/${r.IndicatorID}"><span class="mono value" style="max-width:220px">${esc(r.Value)}</span>${sev(r.SeverityCode)}</a></li>`, 'İlişkili IOC yok.')}</article>
        </div>
      </div>

      <div id="p-gorulmeler" role="tabpanel" aria-labelledby="tab-gorulmeler" hidden class="tab-panel">
        <article class="card"><h2 class="sec-h">Kurum içi görülmeler (${d.sightings.length})</h2>
          ${list(d.sightings, (s) => `<li><div><span>${esc(s.Location || 'Konum yok')}<br><small>${fmtDT(s.SightedAt)} · ${esc(s.ReportedBy || '—')}</small></span><b>${s.Quantity}×</b></div></li>`, 'Bu IOC kurum içinde görülmedi. Kurum içi bir logda geçtiyse "Görülme ekle" ile kaydedin.')}</article>
      </div>

      <div id="p-gecmis" role="tabpanel" aria-labelledby="tab-gecmis" hidden class="file-grid">
        <div class="file-main"><article class="card"><div class="card-head"><div><h2>Değişiklik geçmişi</h2><p>Kim neyi ne zaman değiştirdi: alan bazında önce/sonra<span class="tech"> · AuditLog, tetikleyiciyle yazılır</span></p></div></div>
          ${d.history.length ? `<ol class="timeline history">${d.history.map((h) => `<li><span class="dot ${h.Action === 'I' ? 'done' : ''}"></span><div>
              <div class="hist-head"><span class="badge ${ACTION[h.Action][1]}">${ACTION[h.Action][0]}</span><b>${esc(h.ChangedBy || 'Sistem / toplu içe aktarma')}</b><small class="muted" title="${fmtDT(h.ChangedAt)}">${TL.ago(h.ChangedAt)}</small></div>
              ${diff(h)}</div></li>`).join('')}</ol>`
            : empty('Kayıt yok. Toplu içe aktarmalar satır başına denetim kaydı üretmez; özet içe aktarma işinde tutulur.', 'history')}</article></div>
        <aside class="file-side"><article class="card" id="timeCard"><div class="card-head"><div><h2>Zaman yolculuğu</h2><p>Bu IOC'nin geçmişteki bir andaki hâli<span class="tech"> · sistem sürümlü tablo: FOR SYSTEM_TIME AS OF / ALL</span></p></div></div>
          <form id="asofForm" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
            <div class="field" style="flex:1;min-width:180px"><label for="asofAt">Bu tarihteki hâli</label><input class="input" id="asofAt" type="datetime-local" required></div>
            <button class="btn">Göster</button></form>
          <div id="asofOut" style="margin-top:10px"></div>
          <h3 style="margin-top:14px">Sürümler</h3><ol class="timeline" id="versions" style="margin-top:8px"></ol></article></aside>
      </div>`;
    // Sekmeler: ok tuşlarıyla gezilir, seçim adres çubuğunda (?tab=)
    const tabs = [...root.querySelectorAll('[role=tab]')];
    const showTab = (key, focus) => {
      tabs.forEach((t) => { const on = t.dataset.tab === key; t.setAttribute('aria-selected', String(on)); t.tabIndex = on ? 0 : -1; document.getElementById(`p-${t.dataset.tab}`).hidden = !on; if (on && focus) t.focus(); });
      TL.qs.set({ tab: key === 'ozet' ? null : key });
    };
    root.querySelector('.ftabs').addEventListener('click', (e) => { const t = e.target.closest('[role=tab]'); if (t) showTab(t.dataset.tab); });
    root.querySelector('.ftabs').addEventListener('keydown', (e) => {
      const k = { ArrowRight: 1, ArrowLeft: -1 }[e.key]; if (!k) return;
      const idx = tabs.indexOf(document.activeElement); showTab(tabs[(idx + k + tabs.length) % tabs.length].dataset.tab, true);
    });
    root.addEventListener('click', (e) => { const g = e.target.closest('[data-goto]'); if (g) showTab(g.dataset.goto, true); });
    showTab(['iliskiler', 'gorulmeler', 'gecmis'].includes(TL.qs.get('tab')) ? TL.qs.get('tab') : 'ozet');
    icons();
    TL.overflowActions(root.querySelector('.page-actions'), 2);
    timeTravel();
    if (i.TypeCode === 'ipv4') network(id);
    TL.caseChips('indicator', id).then((h) => { const el = document.getElementById('caseChips'); if (el && h) { el.innerHTML = h; icons(); } });
    if (!writer) return;
    document.getElementById('editBtn').onclick = () => TL.iocForm(i, load);
    document.getElementById('delBtn').onclick = () => {
      const dl = dialog(`<div class="dlg"><div class="dlg-head"><h2>IOC silinsin mi?</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div><p class="muted"><span class="mono">${esc(i.Value)}</span> kalıcı olarak silinir. Görülmeler, etiketler ve ilişkiler (graf kenarları dahil) birlikte silinir; işlem denetim kaydına yazılır.</p>
        <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn danger" id="yes">Kalıcı olarak sil</button></div></div>`);
      dl.querySelector('#yes').onclick = async () => { try { await api(`/api/iocs/${id}`, { method: 'DELETE' }); toast('IOC silindi.'); location.href = '/iocs'; } catch (e) { toast(e.message, 'err'); } };
    };
    document.getElementById('sightBtn').onclick = () => {
      const dl = dialog(`<form><div class="dlg-head"><h2>Görülme ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <div class="form-grid"><div class="field"><label for="sq">Adet</label><input class="input" id="sq" name="quantity" type="number" min="1" value="1"></div>
        <div class="field"><label for="sl">Nerede görüldü</label><input class="input" id="sl" name="location" maxlength="100" placeholder="EDR / WS-0142"></div>
        <div class="field full"><label for="sn">Not</label><textarea class="input" id="sn" name="note" maxlength="400"></textarea></div></div>
        <p class="faint tech" style="font-size: 13px">trg_Sighting_AfterInsert tetikleyicisi IOC'nin son görülme zamanını ileri alır.</p>
        <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Görülme ekle</button></div></form>`);
      dl.querySelector('form').onsubmit = async (e) => { e.preventDefault(); const f = formData(e.target);
        try { await api(`/api/iocs/${id}/sightings`, { method: 'POST', body: { quantity: +f.quantity || 1, location: f.location || null, note: f.note || null } }); dl.close(); toast('Görülme eklendi.'); load(); }
        catch (err) { e.target.querySelector('.err').textContent = err.message; } };
    };
    document.getElementById('linkBtn').onclick = () => linkDialog();
    document.getElementById('statusBtn').onclick = () => {
      const dl = dialog(`<form><div class="dlg-head"><h2>Durumu değiştir</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
        <p class="muted">Şu anki durum: ${status(i.Status)}. Değişiklik denetim kaydına yazılır.</p>
        <div class="field"><label for="st-new">Yeni durum</label><select class="input" id="st-new" name="status">${Object.entries(STATUS_TR).map(([k, v]) => `<option value="${k}" ${k === i.Status ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
        <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Durumu değiştir</button></div></form>`);
      dl.querySelector('form').onsubmit = async (e) => {
        e.preventDefault(); const v = e.target.status.value;
        if (v === i.Status) { dl.close(); return; }
        try { await api('/api/iocs/bulk-status', { method: 'POST', body: { ids: [id], status: v } }); dl.close(); toast(`Durum: ${STATUS_TR[v]}.`); load(); }
        catch (err) { e.target.querySelector('.err').textContent = err.message; }
      };
    };
  }

  function linkDialog() {
    const dl = dialog(`<form><div class="dlg-head"><h2>İlişki ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="notice"><i data-lucide="info"></i><span>Kanıtsız ilişki kurulamaz: ilişkinin dayanağını yazmanız gerekir.<span class="tech"> Önce Evidence satırı, sonra ara tablo satırı yazılır; tetikleyici aynı transaction içinde graf kenarını oluşturur.</span></span></p>
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
  // IPv4 IOC: ASN, ülke, /24 komşuları (sp_IndicatorNetwork; aralık araması)
  async function network(id) {
    const el = document.getElementById('netCard'); if (!el) return;
    let d; try { d = await api(`/api/infrastructure/indicator/${id}`); } catch { return; }
    const n = d.network;
    let cname = n.CountryCode || '—';
    try { if (n.CountryCode) cname = new Intl.DisplayNames(['tr'], { type: 'region' }).of(n.CountryCode) + ` (${n.CountryCode})`; } catch { /* eski tarayıcı */ }
    el.hidden = false;
    el.innerHTML = `<h2 style="margin-bottom:10px">Ağ bilgisi</h2>
      <dl class="kv"><dt>ASN</dt><dd>${n.ASN ? `<span class="mono">AS${n.ASN}</span> ${esc(n.ASName || '')}` : '<span class="faint">IP aralığı verisi yüklenmemiş</span>'}</dd>
        <dt>Ülke</dt><dd>${esc(cname)}</dd><dt>Alt ağ</dt><dd class="mono">${esc(n.Subnet24)}</dd>
        <dt>Aynı ASN'de</dt><dd>${n.ASN ? `${n.SameASN - 1} başka IOC` : '—'}</dd><dt>Aynı /24'te</dt><dd>${n.SameSubnet - 1} başka IOC</dd></dl>
      ${d.subnetNeighbours.length ? `<h3 style="margin-top:12px;font-size:13px">Aynı alt ağdaki IOC'ler</h3>${TL.list(d.subnetNeighbours, (o) => `<li><a href="/iocs/${o.IndicatorID}"><span class="mono">${esc(o.Value)}</span><small>${esc(o.MalwareName || '')}</small></a></li>`)}
        <p style="margin-top:8px"><a class="btn sm" href="/infrastructure"><i data-lucide="network"></i>Altyapı örtüşmesi</a></p>` : ''}`;
    icons();
  }

  document.addEventListener('DOMContentLoaded', load);
})();
