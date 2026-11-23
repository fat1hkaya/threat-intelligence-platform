/* IOC ekleme/düzenleme formu (IOC listesi ve detay sayfası ortak kullanır). */
(() => {
  const { api, esc, dialog, formData, toast, debounce, TYPE_LABEL } = TL;
  const ROLES = [['other', 'Diğer'], ['c2', 'C2 sunucusu'], ['payload', 'Yük'], ['dropper', 'Bırakıcı'], ['exfil', 'Sızdırma'], ['phishing', 'Oltalama']];

  /** Etiket girişi: Enter veya virgül ekler, x kaldırır, Backspace son etiketi siler. Değer gizli alanda virgüllü durur. */
  function tagInput(box, initial = []) {
    const hidden = box.querySelector('input[type=hidden]'), inp = box.querySelector('.tag-entry'), list = box.querySelector('.tag-list');
    const tags = [...new Set(initial.filter(Boolean))];
    const draw = () => {
      list.innerHTML = tags.map((t, i) => `<span class="chip tag">${esc(t)}<button type="button" data-rm="${i}" aria-label="Etiketi kaldır: ${esc(t)}"><i data-lucide="x"></i></button></span>`).join('');
      hidden.value = tags.join(','); TL.icons();
    };
    const add = (v) => { v.split(',').map((x) => x.trim().toLowerCase()).filter((x) => x && x.length <= 50 && !tags.includes(x)).forEach((x) => tags.push(x)); inp.value = ''; draw(); };
    inp.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ',') && inp.value.trim()) { e.preventDefault(); add(inp.value); }
      else if (e.key === 'Enter') e.preventDefault();
      else if (e.key === 'Backspace' && !inp.value && tags.length) { tags.pop(); draw(); }
    });
    inp.addEventListener('blur', () => { if (inp.value.trim()) add(inp.value); });
    list.addEventListener('click', (e) => { const b = e.target.closest('[data-rm]'); if (b) { tags.splice(+b.dataset.rm, 1); draw(); inp.focus(); } });
    box.addEventListener('click', (e) => { if (e.target === box || e.target === list) inp.focus(); });
    draw();
    return { flush: () => { if (inp.value.trim()) add(inp.value); return tags; } };
  }

  /** Zararlı ailesi arama kutusu (combobox): seçilen kimlik gizli alana yazılır */
  function malwarePicker(box, onPick) {
    const inp = box.querySelector('input[type=search]'), hid = box.querySelector('input[type=hidden]'), lb = box.querySelector('[role=listbox]');
    let items = [], idx = -1;
    const close = () => { lb.hidden = true; inp.setAttribute('aria-expanded', 'false'); };
    const draw = () => {
      lb.innerHTML = items.length ? items.map((m, i) => `<li role="option" id="mw-opt-${i}" data-i="${i}" ${i === idx ? 'aria-selected="true"' : ''}>
        <span>${esc(m.DisplayName || m.Name)}</span><small class="faint">${esc(m.ExternalID || m.TypeName || '')}${m.IndicatorCount ? ` · ${TL.fmtN(m.IndicatorCount)} IOC` : ''}</small></li>`).join('')
        : '<li class="faint" role="presentation">Eşleşen aile yok</li>';
      lb.hidden = false; inp.setAttribute('aria-expanded', 'true');
      if (idx >= 0) inp.setAttribute('aria-activedescendant', `mw-opt-${idx}`); else inp.removeAttribute('aria-activedescendant');
    };
    const pick = (m) => { hid.value = m ? m.MalwareID : ''; inp.value = m ? (m.DisplayName || m.Name) : ''; close(); onPick(m); };
    const search = debounce(async () => {
      const q = inp.value.trim(); hid.value = ''; onPick(null);
      if (q.length < 2) { close(); return; }
      try { items = (await api('/api/malware', { params: { q, size: 8, sort: 'indicators' } })).items; idx = -1; draw(); } catch { close(); }
    }, 250);
    inp.addEventListener('input', search);
    inp.addEventListener('keydown', (e) => {
      if (lb.hidden) return;
      if (e.key === 'ArrowDown') { idx = Math.min(items.length - 1, idx + 1); draw(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { idx = Math.max(0, idx - 1); draw(); e.preventDefault(); }
      else if (e.key === 'Enter' && idx >= 0) { e.preventDefault(); pick(items[idx]); }
      else if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); close(); }
    });
    lb.addEventListener('mousedown', (e) => { const li = e.target.closest('[data-i]'); if (li) { e.preventDefault(); pick(items[+li.dataset.i]); } });
    inp.addEventListener('blur', () => setTimeout(close, 120));
  }

  TL.iocForm = async (ind = null, onSaved) => {
    const m = await TL.meta();
    const opt = (rows, val, key, label) => rows.map((r) => `<option value="${esc(r[key])}" ${String(r[key]) === String(val) ? 'selected' : ''}>${esc(label(r))}</option>`).join('');
    const analystSrc = m.sources.find((s) => s.Name === 'Analist girişi');
    const confVal = ind ? ind.Confidence : 60;
    const expires = ind && ind.ExpiresAt ? String(ind.ExpiresAt).slice(0, 10) : '';
    const d = dialog(`<form novalidate>
      <div class="dlg-head"><h2>${ind ? 'IOC düzenle' : 'Yeni IOC ekle'}</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="form-grid">
        <div class="field full"><label for="f-value">Değer</label>
          <input class="input mono" id="f-value" name="value" required maxlength="400" autocomplete="off" spellcheck="false" value="${esc(ind ? ind.OriginalValue : '')}" placeholder="ör. hxxp://evil[.]example/a, 203.0.113.7, sha256…" aria-describedby="f-preview">
          <div class="preview" id="f-preview" aria-live="polite"><span class="faint">Güvenli yazım (hxxp, [.]) çözülür; değer kaydedilmeden önce normalleştirilir.</span></div></div>
        <div class="field"><label for="f-type">Tip</label><select class="input" id="f-type" name="type"><option value="">Otomatik algıla</option>${opt(m.types, ind?.TypeCode, 'Code', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-sev">Önem</label><select class="input" id="f-sev" name="severity">${opt(m.severities, ind?.SeverityCode || 'medium', 'Code', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-conf">Güven puanı</label>
          <div class="slider-row"><input type="range" id="f-conf" name="confidence" min="0" max="100" step="5" value="${confVal}" aria-describedby="f-conf-help">
            <input class="input num-box" type="number" min="0" max="100" value="${confVal}" aria-label="Güven puanı (sayı)" id="f-conf-n"></div>
          <small class="faint" id="f-conf-help">0–49 düşük · 50–79 orta · 80–100 yüksek güven</small></div>
        <div class="field"><label for="f-tlp">TLP</label><select class="input" id="f-tlp" name="tlp">${opt(m.tlps, ind?.TLPCode || 'TLP:CLEAR', 'Code', (r) => r.Code)}</select></div>
        <div class="field"><label for="f-src">Kaynak</label><select class="input" id="f-src" name="sourceId">${opt(m.sources, ind?.SourceID || analystSrc?.SourceID, 'SourceID', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-status">Durum</label><select class="input" id="f-status" name="status">
          ${[['active', 'Aktif'], ['expired', 'Süresi doldu'], ['revoked', 'İptal edildi'], ['false_positive', 'Yanlış pozitif']].map(([v, l]) => `<option value="${v}" ${(ind?.Status || 'active') === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label for="f-exp">Geçerlilik sonu <span class="faint">(isteğe bağlı)</span></label><input class="input" id="f-exp" name="expiresAt" type="date" value="${esc(expires)}"></div>
        ${ind ? '' : `<div class="field mw-picker"><label for="f-mw">Zararlı ailesi <span class="faint">(isteğe bağlı)</span></label>
          <div class="combo"><input class="input" type="search" id="f-mw" role="combobox" aria-expanded="false" aria-controls="f-mw-list" aria-autocomplete="list" placeholder="Aile adı yazın (ör. Emotet)" autocomplete="off">
            <input type="hidden" name="malwareId"><ul class="combo-list" id="f-mw-list" role="listbox" hidden></ul></div></div>
        <div class="field" data-mw-extra hidden><label for="f-role">IOC'nin rolü</label><select class="input" id="f-role" name="role">${ROLES.map(([v, l]) => `<option value="${v}">${l}</option>`).join('')}</select></div>
        <div class="field" data-mw-extra hidden><label for="f-ev">Bağlantının dayanağı</label><input class="input" id="f-ev" name="evidence" maxlength="1000" placeholder="ör. sandbox raporu, kaynak bülteni"></div>`}
        <div class="field full"><label for="f-tag-entry">Etiketler</label>
          <div class="tag-box input"><input type="hidden" name="tags"><span class="tag-list"></span><input class="tag-entry" id="f-tag-entry" placeholder="Etiket yazıp Enter'a basın (ör. c2)" maxlength="50" autocomplete="off"></div></div>
        <div class="field full"><label for="f-desc">Açıklama</label><textarea class="input" id="f-desc" name="description" maxlength="1000" rows="2">${esc(ind?.Description || '')}</textarea></div>
      </div>
      <p class="err" role="alert"></p>
      <div class="dlg-foot"><small class="faint kbd-hint">Ctrl + Enter ile kaydedin</small><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary" type="submit">${ind ? 'Değişiklikleri kaydet' : 'IOC ekle'}</button></div>
    </form>`, { wide: true });
    const form = d.querySelector('form'), val = form.elements.value, typ = form.elements.type, prev = d.querySelector('#f-preview');
    const tags = tagInput(d.querySelector('.tag-box'), ind?.Tags || []);
    // güven: kaydırıcı ve sayı kutusu eşlenir
    const rng = d.querySelector('#f-conf'), nb = d.querySelector('#f-conf-n');
    rng.addEventListener('input', () => { nb.value = rng.value; });
    nb.addEventListener('input', () => { const v = Math.max(0, Math.min(100, +nb.value || 0)); rng.value = v; });
    // canlı önizleme: algılanan tip, kaydedilecek değer, biçim hatası, aynı IOC kayıtlı mı
    let check = { error: null };
    const preview = debounce(async () => {
      const v = val.value.trim();
      if (!v) { prev.innerHTML = '<span class="faint">Güvenli yazım (hxxp, [.]) çözülür; değer kaydedilmeden önce normalleştirilir.</span>'; val.removeAttribute('aria-invalid'); check = { error: 'Değer boş.' }; return; }
      try { check = await api('/api/iocs/check', { params: { value: v, type: typ.value } }); } catch { return; }
      const dup = check.existing && (!ind || check.existing.IndicatorID !== ind.IndicatorID);
      val.toggleAttribute('aria-invalid', !!check.error);
      prev.innerHTML = check.error ? `<span class="field-err"><i data-lucide="circle-alert"></i>${esc(check.error)}</span>`
        : `<span>Algılanan tip: <b>${esc(TYPE_LABEL[check.type] || check.type)}</b> · Kaydedilecek değer: <code>${esc(check.normalized)}</code></span>
           ${dup ? `<span class="field-warn"><i data-lucide="copy-check"></i>Bu IOC zaten kayıtlı. <a href="/iocs/${check.existing.IndicatorID}">Kaydı aç</a></span>` : ''}`;
      TL.icons();
    }, 300);
    val.addEventListener('input', preview); typ.addEventListener('change', preview);
    if (ind) preview();
    // zararlı ailesi (yalnızca yeni kayıtta): seçilince rol ve dayanak alanları açılır
    const mwBox = d.querySelector('.mw-picker');
    if (mwBox) malwarePicker(mwBox, (mw) => d.querySelectorAll('[data-mw-extra]').forEach((el) => { el.hidden = !mw; }));

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const err = form.querySelector('.err'); err.textContent = '';
      const f = formData(form);
      if (!f.value) { err.textContent = 'Değer boş olamaz.'; val.focus(); return; }
      if (check.error && check.error !== 'Değer boş.') { err.textContent = check.error; val.focus(); return; }
      if (f.malwareId && (f.evidence || '').length < 5) { err.textContent = 'Zararlı ailesiyle bağlantının dayanağını en az 5 karakterle yazın.'; form.elements.evidence.focus(); return; }
      const body = { value: f.value, type: f.type || null, severity: f.severity, confidence: +f.confidence, tlp: f.tlp, sourceId: +f.sourceId, status: f.status,
        description: f.description || null, expiresAt: f.expiresAt || null, tags: tags.flush(), rowVer: ind ? ind.RowVer : null };
      const btn = form.querySelector('[type=submit]'); btn.disabled = true;
      try {
        const r = await api(ind ? `/api/iocs/${ind.IndicatorID}` : '/api/iocs', { method: ind ? 'PUT' : 'POST', body });
        if (f.malwareId) {
          try { await api('/api/links', { method: 'POST', body: { kind: 'malware-indicator', a: +f.malwareId, b: r.IndicatorID, role: f.role, evidence: f.evidence } }); }
          catch (x) { toast(`IOC eklendi ama zararlı ailesine bağlanamadı: ${x.message}`, 'err'); }
        }
        d.close(); toast(ind ? 'IOC güncellendi.' : `IOC eklendi: ${r.normalized}`); onSaved && onSaved(r);
      } catch (x) { err.textContent = x.message; btn.disabled = false; }
    });
  };
})();

/* Atıf zinciri: IOC -> zararlı/kampanya -> aktör (veriler vw_IndicatorAttribution, yani MATCH sorgusundan) */
(() => {
  const { esc, entityUrl } = TL;
  const node = (type, id, label, kind) => `<a class="node n-${type}" href="${id ? entityUrl(type, id) : '#'}"><span class="k">${esc(kind)}</span><b title="${esc(label)}">${esc(label)}</b></a>`;
  TL.chains = (ind, attribution) => {
    if (!attribution.length) return '<p class="faint" style="font-size:13px">Bu IOC henüz bir zararlı yazılım veya kampanyayla ilişkilendirilmemiş.</p>';
    const seen = new Set();
    // Her halka: düğüm + altında o bağlantının kanıtı ve kaynağı
    const ev = (text, src, conf) => text ? `<span class="link-ev" title="${esc(text)}">${esc(src || 'Kaynak belirtilmemiş')}${conf != null ? ` · güven ${conf}` : ''}: ${esc(text.slice(0, 140))}${text.length > 140 ? '…' : ''}</span>`
      : '<span class="link-ev faint">Kanıt kaydı yok</span>';
    return attribution.filter((a) => { const k = `${a.ViaType}${a.ViaID}${a.ActorID}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 8).map((a) => `
      <ol class="chain big-chain" aria-label="Atıf zinciri: ${esc(ind.Value)} → ${esc(a.ViaName)}${a.ActorID ? ` → ${esc(a.ActorName)}` : ''}">
        <li>${node('indicator', ind.IndicatorID, TL.midTruncate(ind.Value, 16, 8), TL.TYPE_LABEL[ind.TypeCode] || 'IOC')}</li>
        <li class="link"><span class="arrow" aria-hidden="true">→</span>${ev(a.Evidence, a.EvidenceSource, a.Confidence)}</li>
        <li>${node(a.ViaType, a.ViaID, a.ViaName, a.ViaType === 'malware' ? 'Zararlı yazılım' : 'Kampanya')}</li>
        ${a.ActorID ? `<li class="link"><span class="arrow" aria-hidden="true">→</span>${ev(a.ActorEvidence, a.ActorEvidenceSource, a.ActorConfidence)}</li><li>${node('actor', a.ActorID, a.ActorName, 'Tehdit aktörü')}</li>`
          : '<li class="link"><span class="faint" style="font-size:12px">aktör bilinmiyor</span></li>'}
      </ol>`).join('');
  };
})();
