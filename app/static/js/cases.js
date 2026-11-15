/* Vakalar: /api/cases/* */
(() => {
  const { api, esc, fmtDT, ago, fmtN, sev, table, bindTable, empty, loading, icons, toast, can, qs, dialog, formData, NODE, nodeIcon, entityUrl, CASE_STATUS } = TL;
  const STATUS_BADGE = { open: 'b-cyan', investigating: 'b-warn', closed: 'b-muted' };
  const statusBadge = (s) => `<span class="badge ${STATUS_BADGE[s] || 'b-muted'}">${esc(CASE_STATUS[s] || s)}</span>`;
  const SEV_OPTS = ['critical', 'high', 'medium', 'low', 'info'];
  const writer = can('analyst');
  let filter = '', cur = null;

  // ---------------- liste ----------------
  async function list() {
    document.getElementById('listView').hidden = false; document.getElementById('detailView').hidden = true;
    const el = document.getElementById('caseTbl'); el.innerHTML = loading();
    try {
      const rows = await api('/api/cases', { params: { status: filter } });
      const open = rows.filter((r) => r.Status !== 'closed').length;
      document.getElementById('listNote').textContent = `${fmtN(rows.length)} vaka · ${fmtN(open)} açık`;
      el.innerHTML = rows.length ? table([
        { label: 'Vaka', primary: true, render: (c) => `<b>#${c.InvestigationID}</b> ${esc(c.Title)}` },
        { label: 'Durum', render: (c) => statusBadge(c.Status) },
        { label: 'Önem', render: (c) => sev(c.SeverityCode) },
        { label: 'Öğe', num: true, render: (c) => fmtN(c.Items) },
        { label: 'Not', num: true, render: (c) => fmtN(c.Notes) },
        { label: 'Sorumlu', render: (c) => esc(c.AssignedTo || '—') },
        { label: 'Son değişiklik', render: (c) => `<span title="${fmtDT(c.UpdatedAt)}">${ago(c.UpdatedAt)}</span>` },
      ], rows, { rowId: 'InvestigationID', caption: 'Vakalar' })
        : empty(filter ? 'Bu durumda vaka yok.' : 'Henüz vaka açılmadı. Bir IOC ya da aktör sayfasında "Vakaya ekle" ile başlayabilir veya buradan yeni vaka açabilirsiniz.', 'briefcase');
      icons();
    } catch (e) { el.innerHTML = empty(e.message, 'circle-alert'); icons(); }
  }

  function caseForm(c, onSaved) {
    const users = api('/api/cases/assignees');
    const d = dialog(`<form><div class="dlg-head"><h2>${c ? 'Vakayı düzenle' : 'Yeni vaka'}</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="field"><label for="cf-title">Başlık</label><input class="input" id="cf-title" name="title" minlength="3" maxlength="150" required value="${esc(c?.Title || '')}" placeholder="ör. Muhasebe birimine yönelik oltalama"></div>
      <div class="field"><label for="cf-sum">Özet</label><textarea class="input" id="cf-sum" name="summary" rows="4" maxlength="2000" placeholder="Ne oldu, nereden fark edildi, kapsam ne?">${esc(c?.Summary || '')}</textarea></div>
      <div class="form-grid">
        <div class="field"><label for="cf-sev">Önem</label><select class="input" id="cf-sev" name="severity">${SEV_OPTS.map((s) => `<option value="${s}" ${(c?.SeverityCode || 'medium') === s ? 'selected' : ''}>${esc(TL.SEV[s])}</option>`).join('')}</select></div>
        <div class="field"><label for="cf-as">Sorumlu</label><select class="input" id="cf-as" name="assignedTo"></select></div>
      </div>
      <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary">${c ? 'Değişiklikleri kaydet' : 'Vakayı aç'}</button></div></form>`);
    users.then((u) => {
      const me = c?.AssignedToID || TL.user.UserID;
      d.querySelector('#cf-as').innerHTML = u.map((x) => `<option value="${x.UserID}" ${x.UserID === me ? 'selected' : ''}>${esc(x.FullName)}</option>`).join('');
    }).catch(() => {});
    d.querySelector('form').onsubmit = async (e) => {
      e.preventDefault(); const f = formData(e.target);
      const body = { title: f.title, summary: f.summary || null, severity: f.severity, assignedTo: f.assignedTo ? +f.assignedTo : null };
      try {
        const r = c ? await api(`/api/cases/${c.InvestigationID}`, { method: 'PATCH', body }) : await api('/api/cases', { method: 'POST', body });
        d.close(); toast(c ? 'Vaka güncellendi.' : `Vaka #${r.InvestigationID} açıldı.`); onSaved(c ? c.InvestigationID : r.InvestigationID);
      } catch (x) { e.target.querySelector('.err').textContent = x.message; }
    };
  }

  // ---------------- detay ----------------
  const itemLink = (it) => `<a href="${entityUrl(it.NodeType, it.NodeID)}" class="${it.NodeType === 'indicator' ? 'mono value' : ''}" style="${it.NodeType === 'indicator' ? 'max-width:300px' : ''}" title="${esc(it.Label)}">${esc(it.Label)}</a>`;

  async function detail(id) {
    document.getElementById('listView').hidden = true;
    const root = document.getElementById('detailView'); root.hidden = false; root.innerHTML = loading('Vaka yükleniyor');
    let d, g;
    try { [d, g] = await Promise.all([api(`/api/cases/${id}`), api(`/api/cases/${id}/graph`)]); }
    catch (e) { root.innerHTML = `<p><a href="/cases" data-back>← Vakalar</a></p>` + empty(e.message, 'circle-alert'); icons(); return; }
    const c = d.case, closed = c.Status === 'closed';
    const byType = Object.keys(NODE).map((t) => [t, d.items.filter((i) => i.NodeType === t)]).filter(([, v]) => v.length);
    root.innerHTML = `
      <p style="margin-bottom:10px"><a href="/cases" data-back><i data-lucide="arrow-left" style="width:14px;height:14px;vertical-align:-2px"></i> Vakalar</a></p>
      <div class="page-head" style="margin-bottom:18px">
        <div class="entity-title"><span class="ic" style="background:var(--purple-soft);color:#B9A8FF"><i data-lucide="briefcase"></i></span><div style="min-width:0">
          <h1 style="overflow-wrap:anywhere">#${c.InvestigationID} ${esc(c.Title)}</h1>
          <div class="chips" style="margin-top:8px">${statusBadge(c.Status)}${sev(c.SeverityCode)}<span class="badge b-muted"><i data-lucide="user" style="width:12px;height:12px"></i>${esc(c.AssignedTo || 'Atanmadı')}</span></div>
          <p class="faint" style="font-size:12.5px;margin-top:6px">${esc(c.CreatedBy || '—')} açtı, ${fmtDT(c.CreatedAt)}${c.ClosedAt ? ` · kapatıldı ${fmtDT(c.ClosedAt)}` : ''}</p>
        </div></div>
        <div class="page-actions">
          ${d.items.length ? `<a class="btn" href="/graph?case=${c.InvestigationID}"><i data-lucide="share-2"></i>Vaka grafı</a>` : ''}
          ${writer ? `${closed ? '<button class="btn" data-st="open"><i data-lucide="rotate-ccw"></i>Yeniden aç</button>'
            : `${c.Status === 'open' ? '<button class="btn" data-st="investigating"><i data-lucide="play"></i>İncelemeye al</button>' : ''}<button class="btn" data-st="closed"><i data-lucide="check"></i>Vakayı kapat</button>`}
            <button class="btn primary" id="editCase"><i data-lucide="pencil"></i>Düzenle</button><button class="btn danger" id="delCase" aria-label="Vakayı sil"><i data-lucide="trash-2"></i></button>` : ''}
        </div>
      </div>
      <div class="grid g-main-side">
        <div class="grid" style="align-content:start">
          ${c.Summary ? `<article class="card"><h2 style="margin-bottom:8px">Özet</h2><p class="desc" style="white-space:pre-wrap">${esc(c.Summary)}</p></article>` : ''}
          <article class="card flush"><div class="card-head"><div><h2>Vakadaki varlıklar (${d.items.length})</h2><p>InvestigationIncludes kenarları: MATCH(v-(e)->x), düğüm türü başına</p></div></div>
            ${d.items.length ? byType.map(([t, rows]) => `<div style="padding:4px 0 8px"><h3 style="padding:10px 16px 4px;font-size:13px" class="muted">${nodeIcon(t).replace('class="ic"', 'class="ic" style="display:inline-grid;width:22px;height:22px;border-radius:6px;vertical-align:middle;margin-right:6px"')}${esc(NODE[t].label)} (${rows.length})</h3>
              ${table([
                { label: 'Varlık', primary: true, render: itemLink },
                { label: 'Ek bilgi', render: (it) => esc(it.SubLabel || '—') },
                { label: 'Neden', render: (it) => it.Note ? esc(it.Note) : '<span class="faint">—</span>' },
                { label: 'Ekleyen', render: (it) => `${esc(it.AddedBy || '—')}<br><small class="faint">${ago(it.AddedAt)}</small>` },
                { label: '', render: (it) => writer && !closed ? `<button class="btn sm icon ghost" data-rm="${it.NodeType}:${it.NodeID}" aria-label="Vakadan çıkar" title="Vakadan çıkar"><i data-lucide="x"></i></button>` : '' },
              ], rows, { caption: NODE[t].label })}</div>`).join('')
              : empty('Vakada henüz varlık yok. IOC detayında, graf panelinde veya aktör/zararlı panellerinde "Vakaya ekle" düğmesini kullanın.', 'inbox')}
          </article>
          <article class="card flush"><div class="card-head"><div><h2>Ortak bağlantılar</h2><p>Vakada olmayan ama vakadaki en az iki varlığa birden bağlı olan düğümler: çoğu zaman bir sonraki ipucu buradadır</p></div></div>
            ${g.common.length ? table([
              { label: 'Varlık', primary: true, render: (x) => `${nodeIcon(x.NodeType).replace('class="ic"', 'class="ic" style="display:inline-grid;width:22px;height:22px;border-radius:6px;vertical-align:middle;margin-right:6px"')}<a href="${entityUrl(x.NodeType, x.NodeID)}" class="${x.NodeType === 'indicator' ? 'mono' : ''}">${esc(x.Label || x.NodeID)}</a>` },
              { label: 'Tür', render: (x) => esc(NODE[x.NodeType].label) },
              { label: 'Bağlandığı vaka öğesi', num: true, render: (x) => `<b>${x.Connects}</b>` },
              { label: '', render: (x) => writer && !closed ? `<button class="btn sm" data-add="${x.NodeType}:${x.NodeID}" data-label="${esc(x.Label || '')}"><i data-lucide="plus"></i>Vakaya ekle</button>` : '' },
            ], g.common, { caption: 'Ortak bağlantılar' })
              : empty(d.items.length < 2 ? 'Ortak bağlantı aramak için vakada en az iki varlık olmalı.' : 'Vakadaki varlıkları birbirine bağlayan, vakada olmayan bir düğüm bulunmadı.', 'git-merge')}
          </article>
        </div>
        <div class="grid" style="align-content:start">
          <article class="card"><h2 style="margin-bottom:10px">Notlar (${d.notes.length})</h2>
            ${writer ? `<form id="noteForm" class="grid" style="gap:8px;margin-bottom:14px"><label for="noteBody" class="sr-only">Not</label>
              <textarea class="input" id="noteBody" rows="3" maxlength="2000" required placeholder="Bulgu, karar veya sonraki adım"></textarea>
              <div><button class="btn sm primary"><i data-lucide="message-square-plus"></i>Not ekle</button></div></form>` : ''}
            ${d.notes.length ? `<ol class="timeline">${d.notes.map((n) => `<li><span class="dot"></span><div><small class="muted">${esc(n.Author || '—')} · ${fmtDT(n.CreatedAt)}</small><p style="white-space:pre-wrap;margin-top:2px;font-size:13.5px">${esc(n.Body)}</p></div></li>`).join('')}</ol>`
              : '<p class="faint" style="font-size:13px">Henüz not yok.</p>'}
          </article>
        </div>
      </div>`;
    icons();
    cur = c.InvestigationID;
    bind(c, d);
  }

  function bind(c, d) {
    const id = c.InvestigationID, root = document.getElementById('detailView'), reload = () => detail(id);
    root.querySelectorAll('[data-st]').forEach((b) => b.onclick = async () => {
      try { await api(`/api/cases/${id}`, { method: 'PATCH', body: { status: b.dataset.st } }); toast(`Vaka durumu: ${CASE_STATUS[b.dataset.st]}.`); reload(); }
      catch (e) { toast(e.message, 'err'); }
    });
    const ed = document.getElementById('editCase'); if (ed) ed.onclick = () => caseForm(c, reload);
    const del = document.getElementById('delCase');
    if (del) del.onclick = () => {
      const dl = dialog(`<div class="dlg"><div class="dlg-head"><h2>Vakayı sil</h2></div><p>#${id} ${esc(c.Title)} vakası, ${d.items.length} öğe bağlantısı ve ${d.notes.length} notuyla birlikte silinecek. Vakadaki IOC ve diğer kayıtlar silinmez.</p>
        <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn primary" id="yes">Vakayı sil</button></div></div>`);
      dl.querySelector('#yes').onclick = async () => {
        try { await api(`/api/cases/${id}`, { method: 'DELETE' }); dl.close(); toast('Vaka silindi.'); qs.set({ id: null }); list(); }
        catch (e) { toast(e.message, 'err'); }
      };
    };
    const nf = document.getElementById('noteForm');
    if (nf) nf.onsubmit = async (e) => {
      e.preventDefault(); const body = document.getElementById('noteBody').value.trim(); if (!body) return;
      try { await api(`/api/cases/${id}/notes`, { method: 'POST', body: { body } }); reload(); } catch (x) { toast(x.message, 'err'); }
    };
  }

  const go = (id) => { qs.set({ id }); id ? detail(id) : list(); };

  document.addEventListener('DOMContentLoaded', () => {
    const nb = document.getElementById('newCase');
    if (writer) { nb.hidden = false; nb.onclick = () => caseForm(null, go); }
    document.getElementById('statusSeg').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return; filter = b.dataset.v;
      document.querySelectorAll('#statusSeg button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); list();
    });
    bindTable(document.getElementById('caseTbl'), { onRow: (id) => go(+id) });
    document.getElementById('detailView').addEventListener('click', async (e) => {
      if (e.target.closest('[data-back]')) { e.preventDefault(); go(null); return; }
      const rm = e.target.closest('[data-rm]'), add = e.target.closest('[data-add]'), id = cur;
      if (rm) {
        const [type, nid] = rm.dataset.rm.split(':');
        try { await api(`/api/cases/${id}/items`, { method: 'DELETE', params: { type, id: nid } }); toast('Vakadan çıkarıldı.'); detail(id); } catch (x) { toast(x.message, 'err'); }
      } else if (add) {
        const [type, nid] = add.dataset.add.split(':');
        try { await api(`/api/cases/${id}/items`, { method: 'POST', body: { type, id: +nid, note: 'Ortak bağlantı önerisinden eklendi' } }); toast('Vakaya eklendi.'); detail(id); } catch (x) { toast(x.message, 'err'); }
      }
    });
    window.addEventListener('popstate', () => { const id = qs.get('id'); id ? detail(+id) : list(); });
    const id = qs.get('id'); id ? detail(+id) : list();
  });
})();
