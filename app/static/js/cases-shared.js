/* Vakaya ekle: IOC detayı, graf paneli ve varlık panellerinden çağrılır (TL.addToCase). */
(() => {
  const { api, esc, dialog, formData, toast, NODE } = TL;
  const STATUS = { open: 'Açık', investigating: 'İnceleniyor', closed: 'Kapalı' };

  /** id tek kimlik ya da kimlik dizisi olabilir (IOC listesindeki toplu işlem) */
  async function addToCase(type, id, label, onDone) {
    const many = Array.isArray(id);
    let cases = [];
    try { cases = (await api('/api/cases')).filter((c) => c.Status !== 'closed'); } catch (e) { toast(e.message, 'err'); return; }
    const opts = cases.map((c) => `<option value="${c.InvestigationID}">#${c.InvestigationID} ${esc(c.Title)} (${STATUS[c.Status]}, ${c.Items} öğe)</option>`).join('');
    const d = dialog(`<form><div class="dlg-head"><h2>Vakaya ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <p class="muted" style="font-size:13px">${many ? `Seçili <b>${esc(label)}</b> eklenecek; vakada zaten olanlar atlanır.` : `${esc(NODE[type].label)}: <b class="${type === 'indicator' ? 'mono' : ''}" style="overflow-wrap:anywhere">${esc(label)}</b>`}</p>
      <div class="field"><label for="ac-case">Vaka</label><select class="input" id="ac-case" name="case">${opts}<option value="new">+ Yeni vaka aç</option></select></div>
      <div class="field" id="ac-newwrap" ${cases.length ? 'hidden' : ''}><label for="ac-title">Yeni vakanın başlığı</label><input class="input" id="ac-title" name="title" maxlength="150" placeholder="ör. Muhasebe birimine yönelik oltalama"></div>
      <div class="field"><label for="ac-note">Neden eklendi? (isteğe bağlı)</label><input class="input" id="ac-note" name="note" maxlength="400" placeholder="ör. proxy logunda 3 kez görüldü"></div>
      <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">Vakaya ekle</button></div></form>`);
    const sel = d.querySelector('#ac-case'), wrap = d.querySelector('#ac-newwrap');
    if (!cases.length) sel.value = 'new';
    sel.onchange = () => { wrap.hidden = sel.value !== 'new'; };
    d.querySelector('form').onsubmit = async (e) => {
      e.preventDefault(); const f = formData(e.target), err = e.target.querySelector('.err');
      try {
        let caseId = +f.case;
        if (f.case === 'new') {
          if ((f.title || '').length < 3) { err.textContent = 'Vaka başlığı en az 3 karakter olmalı.'; return; }
          caseId = (await api('/api/cases', { method: 'POST', body: { title: f.title } })).InvestigationID;
        }
        if (many) {
          const r = await api(`/api/cases/${caseId}/items/batch`, { method: 'POST', body: { type, ids: id, note: f.note || null } });
          d.close(); toast(`Vaka #${caseId}: ${r.added} öğe eklendi${r.skipped ? `, ${r.skipped} öğe zaten vardı` : ''}.`);
        } else {
          await api(`/api/cases/${caseId}/items`, { method: 'POST', body: { type, id, note: f.note || null } });
          d.close(); toast(`Vaka #${caseId} içine eklendi.`);
        }
        if (onDone) onDone(caseId);
      } catch (x) { err.textContent = x.message; }
    };
  }

  // Varlığın içinde bulunduğu vakalar: küçük bağlantı listesi
  async function caseChips(type, id) {
    try {
      const rows = await api('/api/cases/for-entity', { params: { type, id } });
      return rows.map((c) => `<a class="badge ${c.Status === 'closed' ? 'b-muted' : 'b-purple'}" href="/cases?id=${c.InvestigationID}" title="${esc(STATUS[c.Status])}"><i data-lucide="briefcase" style="width:12px;height:12px"></i>#${c.InvestigationID} ${esc(c.Title)}</a>`).join('');
    } catch { return ''; }
  }

  // Panellerde kullanılan düğme; tıklama aşağıdaki ortak dinleyiciyle yakalanır
  const caseBtn = (type, id, label, cls = 'btn sm') => TL.can('analyst')
    ? `<button type="button" class="${cls}" data-add-case="${type}" data-id="${id}" data-label="${esc(label)}"><i data-lucide="briefcase"></i>Vakaya ekle</button>` : '';
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-add-case]'); if (!b) return;
    e.preventDefault(); addToCase(b.dataset.addCase, +b.dataset.id, b.dataset.label);
  });

  Object.assign(TL, { addToCase, caseChips, caseBtn, CASE_STATUS: STATUS });
})();
