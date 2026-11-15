/* IOC ekleme/düzenleme formu (IOC listesi ve detay sayfası ortak kullanır). */
(() => {
  const { api, esc, dialog, formData, toast } = TL;

  TL.iocForm = async (ind = null, onSaved) => {
    const m = await TL.meta();
    const opt = (rows, val, key, label) => rows.map((r) => `<option value="${esc(r[key])}" ${String(r[key]) === String(val) ? 'selected' : ''}>${esc(label(r))}</option>`).join('');
    const analystSrc = m.sources.find((s) => s.Name === 'Analist girişi');
    const d = dialog(`<form>
      <div class="dlg-head"><h2>${ind ? 'IOC düzenle' : 'Yeni IOC ekle'}</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="form-grid">
        <div class="field full"><label for="f-value">Değer</label>
          <input class="input mono" id="f-value" name="value" required maxlength="400" value="${esc(ind ? ind.OriginalValue : '')}" placeholder="ör. hxxp://evil[.]example/a, 203.0.113.7, sha256...">
          <small class="faint">Güvenli yazım (hxxp, [.]) çözülür; değer kaydedilmeden önce normalleştirilir.</small></div>
        <div class="field"><label for="f-type">Tip</label><select class="input" id="f-type" name="type"><option value="">Otomatik algıla</option>${opt(m.types, ind?.TypeCode, 'Code', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-sev">Önem</label><select class="input" id="f-sev" name="severity">${opt(m.severities, ind?.SeverityCode || 'medium', 'Code', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-conf">Güven puanı (0–100)</label><input class="input" id="f-conf" name="confidence" type="number" min="0" max="100" value="${ind ? ind.Confidence : 60}" required></div>
        <div class="field"><label for="f-tlp">TLP</label><select class="input" id="f-tlp" name="tlp">${opt(m.tlps, ind?.TLPCode || 'TLP:CLEAR', 'Code', (r) => r.Code)}</select></div>
        <div class="field"><label for="f-src">Kaynak</label><select class="input" id="f-src" name="sourceId">${opt(m.sources, ind?.SourceID || analystSrc?.SourceID, 'SourceID', (r) => r.Name)}</select></div>
        <div class="field"><label for="f-status">Durum</label><select class="input" id="f-status" name="status">
          ${[['active', 'Aktif'], ['expired', 'Süresi doldu'], ['revoked', 'İptal edildi'], ['false_positive', 'Yanlış pozitif']].map(([v, l]) => `<option value="${v}" ${(ind?.Status || 'active') === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
        <div class="field full"><label for="f-tags">Etiketler (virgülle)</label><input class="input" id="f-tags" name="tags" value="${esc((ind?.Tags || []).join(', '))}" placeholder="c2, phishing"></div>
        <div class="field full"><label for="f-desc">Açıklama</label><textarea class="input" id="f-desc" name="description" maxlength="1000">${esc(ind?.Description || '')}</textarea></div>
      </div>
      <p class="err" role="alert"></p>
      <div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary" type="submit">${ind ? 'Değişiklikleri kaydet' : 'IOC ekle'}</button></div>
    </form>`);
    const form = d.querySelector('form');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = formData(form);
      const body = { value: f.value, type: f.type || null, severity: f.severity, confidence: +f.confidence, tlp: f.tlp, sourceId: +f.sourceId, status: f.status,
        description: f.description || null, tags: f.tags ? f.tags.split(',').map((t) => t.trim()).filter(Boolean) : [], rowVer: ind ? ind.RowVer : null };
      try {
        const r = await api(ind ? `/api/iocs/${ind.IndicatorID}` : '/api/iocs', { method: ind ? 'PUT' : 'POST', body });
        d.close(); toast(ind ? 'IOC güncellendi.' : `IOC eklendi: ${r.normalized}`); onSaved && onSaved(r);
      } catch (err) { form.querySelector('.err').textContent = err.message; }
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
    return attribution.filter((a) => { const k = `${a.ViaType}${a.ViaID}${a.ActorID}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 8).map((a) => `
      <div class="chain" role="group" aria-label="Atıf zinciri">
        ${node('indicator', ind.IndicatorID, ind.Value, TL.TYPE_LABEL[ind.TypeCode] || 'IOC')}<span class="arrow" aria-hidden="true">→</span>
        ${node(a.ViaType, a.ViaID, a.ViaName, a.ViaType === 'malware' ? 'Zararlı yazılım' : 'Kampanya')}
        ${a.ActorID ? `<span class="arrow" aria-hidden="true">→</span>${node('actor', a.ActorID, a.ActorName, 'Tehdit aktörü')}` : '<span class="faint" style="font-size:12px">aktör bilinmiyor</span>'}
      </div>
      ${a.Evidence ? `<p class="faint" style="font-size:12px;margin:-2px 0 6px">Kanıt (${esc(a.EvidenceSource)}${a.Confidence != null ? `, güven ${a.Confidence}` : ''}): ${esc(a.Evidence.slice(0, 180))}</p>` : ''}`).join('');
  };
})();
