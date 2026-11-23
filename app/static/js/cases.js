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
      const all = await api('/api/cases');
      const count = (v) => (v ? all.filter((r) => r.Status === v).length : all.length);
      document.querySelectorAll('#statusSeg button').forEach((b) => { b.textContent = `${b.dataset.name} (${fmtN(count(b.dataset.v))})`; });
      const rows = filter ? all.filter((r) => r.Status === filter) : all;
      const open = all.filter((r) => r.Status !== 'closed').length;
      document.getElementById('listNote').textContent = `${fmtN(all.length)} vaka · ${fmtN(open)} açık`;
      el.innerHTML = rows.length ? table([
        { label: 'Vaka', primary: true, render: (c) => `<b>#${c.InvestigationID}</b> ${esc(c.Title)}` },
        { label: 'Durum', render: (c) => statusBadge(c.Status) },
        { label: 'Önem', render: (c) => sev(c.SeverityCode) },
        { label: 'Öğe', num: true, render: (c) => fmtN(c.Items) },
        { label: 'Not', num: true, render: (c) => fmtN(c.Notes) },
        { label: 'Sorumlu', render: (c) => esc(c.AssignedTo || '—') },
        { label: 'Son değişiklik', render: (c) => `<span title="${fmtDT(c.UpdatedAt)}">${ago(c.UpdatedAt)}</span>` },
      ], rows, { rowId: 'InvestigationID', caption: 'Vakalar' })
        : filter ? empty('Bu durumda vaka yok.', 'briefcase') : howItWorks();
      icons();
    } catch (e) { el.innerHTML = empty(e.message, 'circle-alert'); icons(); }
  }

  // Boş durum: vaka nasıl çalışır (3 adım)
  const howItWorks = () => `<div class="how-steps"><h3>Vaka nasıl çalışır?</h3><ol>
      <li><b>Vaka açın</b><span>Bir olay ya da şüphe için başlık, önem ve sorumlu belirleyin.</span></li>
      <li><b>Varlık ekleyin</b><span>IOC, zararlı, aktör ve teknikleri vakaya bağlayın: listelerdeki "Vakaya ekle" ya da vaka sayfasındaki "Varlık ekle" ile.</span></li>
      <li><b>İnceleyin ve kapatın</b><span>Notlarla bulguları kaydedin, ortak bağlantılara bakın, iş bitince vakayı kapatın ve raporunu alın.</span></li>
    </ol>${writer ? '<button type="button" class="btn primary" data-new-case><i data-lucide="briefcase"></i>Yeni vaka</button>' : ''}</div>`;

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
    // Birincil düğme iş akışının sonraki adımı: Açık -> İncelemeye al, İnceleniyor -> Vakayı kapat, Kapalı -> Yeniden aç
    const NEXT = { open: ['investigating', 'play', 'İncelemeye al'], investigating: ['closed', 'check', 'Vakayı kapat'], closed: ['open', 'rotate-ccw', 'Yeniden aç'] };
    const [nextSt, nextIc, nextLbl] = NEXT[c.Status] || NEXT.open;
    const byType = Object.keys(NODE).map((t) => [t, d.items.filter((i) => i.NodeType === t)]).filter(([, v]) => v.length);
    root.innerHTML = `
      <p style="margin-bottom:10px"><a href="/cases" data-back><i data-lucide="arrow-left" style="width:14px;height:14px;vertical-align:-2px"></i> Vakalar</a></p>
      <div class="page-head" style="margin-bottom:18px">
        <div class="entity-title"><span class="ic" style="background:var(--purple-soft);color:var(--badge-purple-fg)"><i data-lucide="briefcase"></i></span><div style="min-width:0">
          <h1 style="overflow-wrap:anywhere">#${c.InvestigationID} ${esc(c.Title)}</h1>
          <div class="chips" style="margin-top:8px">${statusBadge(c.Status)}${sev(c.SeverityCode)}<span class="badge b-muted"><i data-lucide="user" style="width:12px;height:12px"></i>${esc(c.AssignedTo || 'Atanmadı')}</span></div>
          <p class="faint" style="font-size: 13px;margin-top:6px">${esc(c.CreatedBy || '—')} açtı, ${fmtDT(c.CreatedAt)}${c.ClosedAt ? ` · kapatıldı ${fmtDT(c.ClosedAt)}` : ''}</p>
        </div></div>
        <div class="page-actions">
          ${writer ? `<button class="btn icon danger" id="delCase" aria-label="Vakayı sil" title="Vakayı sil"><i data-lucide="trash-2"></i></button>
            <button class="btn" id="editCase"><i data-lucide="pencil"></i>Düzenle</button>` : ''}
          <button class="btn" id="caseReport" title="Özet, varlıklar, kanıtlar ve notlarla Markdown raporu"><i data-lucide="file-down"></i>Vaka raporu</button>
          ${d.items.length ? `<a class="btn" href="/graph?case=${c.InvestigationID}"><i data-lucide="share-2"></i>Vaka grafı</a>
            <a class="btn" href="/api/export/stix/case/${c.InvestigationID}" download title="STIX 2.1 paketi (grouping): vaka öğeleri, aralarındaki ilişkiler ve notlar"><i data-lucide="download"></i>STIX 2.1</a>` : ''}
          ${writer && !closed && c.Status === 'open' ? '<button class="btn" data-st="closed"><i data-lucide="check"></i>Vakayı kapat</button>' : ''}
          ${writer ? `<button class="btn primary" data-st="${nextSt}"><i data-lucide="${nextIc}"></i>${nextLbl}</button>` : ''}
        </div>
      </div>
      <div class="grid g-main-side">
        <div class="grid" style="align-content:start">
          ${c.Summary ? `<article class="card"><h2 style="margin-bottom:8px">Özet</h2><p class="desc" style="white-space:pre-wrap">${esc(c.Summary)}</p></article>` : ''}
          <article class="card flush"><div class="card-head"><div><h2>Vakadaki varlıklar (${d.items.length})</h2><p>Vakaya bağlanan göstergeler ve varlıklar<span class="tech"> · InvestigationIncludes kenarları, MATCH</span></p></div>
            ${writer && !closed ? '<button class="btn sm" id="addEntity"><i data-lucide="plus"></i>Varlık ekle</button>' : ''}</div>
            ${d.items.length ? byType.map(([t, rows]) => `<div style="padding:4px 0 8px"><h3 style="padding:10px 16px 4px;font-size:13px" class="muted">${nodeIcon(t).replace('class="ic"', 'class="ic" style="display:inline-grid;width:22px;height:22px;border-radius:6px;vertical-align:middle;margin-right:6px"')}${esc(NODE[t].label)} (${rows.length})</h3>
              ${table([
                { label: 'Varlık', primary: true, render: itemLink },
                { label: 'Ek bilgi', render: (it) => esc(it.SubLabel || '—') },
                { label: 'Neden', render: (it) => it.Note ? esc(it.Note) : '<span class="faint">—</span>' },
                { label: 'Ekleyen', render: (it) => `${esc(it.AddedBy || '—')}<br><small class="faint">${ago(it.AddedAt)}</small>` },
                { label: '', render: (it) => writer && !closed ? `<button class="btn sm icon ghost" data-rm="${it.NodeType}:${it.NodeID}" aria-label="Vakadan çıkar" title="Vakadan çıkar"><i data-lucide="x"></i></button>` : '' },
              ], rows, { caption: NODE[t].label })}</div>`).join('')
              : empty('Vakada henüz varlık yok. "Varlık ekle" ile arayıp ekleyin ya da IOC, graf ve aktör/zararlı panellerindeki "Vakaya ekle" düğmesini kullanın.', 'inbox')}
          </article>
          <article class="card flush${g.common.length ? '' : ' compact-empty'}"><div class="card-head"><div><h2>Ortak bağlantılar</h2><p>Vakada olmayan ama vakadaki en az iki varlığa birden bağlı olan düğümler: çoğu zaman bir sonraki ipucu buradadır</p></div></div>
            ${g.common.length ? table([
              { label: 'Varlık', primary: true, render: (x) => `${nodeIcon(x.NodeType).replace('class="ic"', 'class="ic" style="display:inline-grid;width:22px;height:22px;border-radius:6px;vertical-align:middle;margin-right:6px"')}<a href="${entityUrl(x.NodeType, x.NodeID)}" class="${x.NodeType === 'indicator' ? 'mono' : ''}">${esc(x.Label || x.NodeID)}</a>` },
              { label: 'Tür', render: (x) => esc(NODE[x.NodeType].label) },
              { label: 'Bağlandığı vaka öğesi', num: true, render: (x) => `<b>${x.Connects}</b>` },
              { label: '', render: (x) => writer && !closed ? `<button class="btn sm" data-add="${x.NodeType}:${x.NodeID}" data-label="${esc(x.Label || '')}"><i data-lucide="plus"></i>Vakaya ekle</button>` : '' },
            ], g.common, { caption: 'Ortak bağlantılar' })
              : `<p class="faint small-empty">${d.items.length < 2 ? 'Ortak bağlantı aramak için vakada en az iki varlık olmalı.' : 'Vakadaki varlıkları birbirine bağlayan, vakada olmayan bir düğüm bulunmadı.'}</p>`}
          </article>
        </div>
        <div class="grid" style="align-content:start">
          <article class="card"><h2 style="margin-bottom:10px">Etkinlik</h2>
            ${writer ? `<form id="noteForm" class="grid" style="gap:8px;margin-bottom:14px"><label for="noteBody" class="sr-only">Not</label>
              <textarea class="input" id="noteBody" rows="3" maxlength="2000" required placeholder="Bulgu, karar veya sonraki adım"></textarea>
              <div><button class="btn sm primary"><i data-lucide="message-square-plus"></i>Not ekle</button></div></form>` : ''}
            ${activity(d)}
          </article>
        </div>
      </div>`;
    icons();
    TL.overflowActions(root.querySelector('.page-actions'), 2);
    cur = c.InvestigationID;
    bind(c, d);
  }

  // Tek akış: durum değişiklikleri, eklenen varlıklar ve notlar (en yeni üstte)
  function activity(d) {
    const ev = [
      ...(d.statusEvents || []).map((x) => ({ at: x.At, icon: x.Action === 'I' ? 'briefcase' : 'circle-dot', who: x.Who,
        html: x.Action === 'I' ? 'Vakayı açtı' : `Durumu değiştirdi: ${statusBadge(x.OldStatus)} → ${statusBadge(x.NewStatus)}` })),
      ...d.items.map((it) => ({ at: it.AddedAt, icon: 'plus', who: it.AddedBy,
        html: `${esc(NODE[it.NodeType].label)} ekledi: ${itemLink(it)}${it.Note ? `<br><small class="muted">${esc(it.Note)}</small>` : ''}` })),
      ...d.notes.map((n) => ({ at: n.CreatedAt, icon: 'message-square', who: n.Author, html: `<span class="note-body">${esc(n.Body)}</span>`, note: true })),
    ].sort((a, b) => String(b.at).localeCompare(String(a.at)));
    return ev.length ? `<ol class="timeline activity">${ev.map((e) => `<li><span class="dot${e.note ? ' done' : ''}"></span><div>
        <small class="muted"><i data-lucide="${e.icon}" class="act-ic" aria-hidden="true"></i>${esc(e.who || '—')} · <span title="${fmtDT(e.at)}">${ago(e.at)}</span></small>
        <div class="act-body">${e.html}</div></div></li>`).join('')}</ol>` : '<p class="faint" style="font-size:13px">Henüz etkinlik yok.</p>';
  }

  // Vaka raporu (Markdown): özet, varlıklar, kanıt notları ve notlar; tarayıcıda oluşturulur, sunucuya bir şey yazılmaz
  function report(c, d) {
    const line = (s) => String(s ?? '').replace(/\r?\n/g, ' ');
    const md = [`# Vaka #${c.InvestigationID}: ${line(c.Title)}`, '',
      `- Durum: ${CASE_STATUS[c.Status] || c.Status}`, `- Önem: ${TL.SEV[c.SeverityCode] || c.SeverityCode}`, `- Sorumlu: ${c.AssignedTo || 'Atanmadı'}`,
      `- Açan: ${c.CreatedBy || '—'}, ${fmtDT(c.CreatedAt)}`, ...(c.ClosedAt ? [`- Kapatıldı: ${fmtDT(c.ClosedAt)}`] : []), `- Rapor tarihi: ${fmtDT(new Date().toISOString())}`, '',
      '## Özet', '', c.Summary || '_Özet girilmedi._', '',
      `## Varlıklar (${d.items.length})`, ''];
    Object.keys(NODE).forEach((t) => {
      const rows = d.items.filter((i) => i.NodeType === t); if (!rows.length) return;
      md.push(`### ${NODE[t].label} (${rows.length})`, '', '| Varlık | Ek bilgi | Neden eklendi (kanıt) | Ekleyen |', '|---|---|---|---|');
      rows.forEach((i) => md.push(`| \`${line(i.Label).replace(/\|/g, '\\|')}\` | ${line(i.SubLabel || '—')} | ${line(i.Note || '—').replace(/\|/g, '\\|')} | ${line(i.AddedBy || '—')}, ${fmtDT(i.AddedAt)} |`));
      md.push('');
    });
    md.push(`## Notlar (${d.notes.length})`, '');
    [...d.notes].reverse().forEach((n) => md.push(`- **${line(n.Author || '—')}**, ${fmtDT(n.CreatedAt)}: ${line(n.Body)}`));
    if (!d.notes.length) md.push('_Not yok._');
    md.push('', `## Durum geçmişi`, '');
    [...(d.statusEvents || [])].reverse().forEach((x) => md.push(`- ${fmtDT(x.At)} · ${line(x.Who || '—')}: ${x.Action === 'I' ? 'vaka açıldı' : `${CASE_STATUS[x.OldStatus] || x.OldStatus} → ${CASE_STATUS[x.NewStatus] || x.NewStatus}`}`));
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([md.join('\n') + '\n'], { type: 'text/markdown;charset=utf-8' }));
    a.download = `vaka-${c.InvestigationID}-rapor.md`; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('Vaka raporu indirildi.');
  }

  // Varlık ekle: küresel aramadan IOC / aktör / zararlı / teknik / kampanya / zafiyet seçimi
  function addEntity(id, onDone) {
    const d = dialog(`<form><div class="dlg-head"><h2>Varlık ekle</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div>
      <div class="field combo"><label for="ae-q">IOC, aktör, zararlı yazılım veya teknik</label>
        <input class="input" id="ae-q" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="ae-list" autocomplete="off" placeholder="ör. 185.220.101.4, APT29, T1059">
        <ul class="combo-list" id="ae-list" role="listbox" hidden></ul></div>
      <p class="muted" id="ae-picked" style="font-size:13px">Henüz seçilmedi.</p>
      <div class="field"><label for="ae-note">Neden ekleniyor? (isteğe bağlı)</label><input class="input" id="ae-note" maxlength="300" placeholder="ör. Proxy logunda görüldü"></div>
      <p class="err" role="alert"></p><div class="dlg-foot"><button type="button" class="btn" data-dismiss>Vazgeç</button><button class="btn primary" disabled id="ae-ok">Vakaya ekle</button></div></form>`);
    const q = d.querySelector('#ae-q'), list = d.querySelector('#ae-list'), ok = d.querySelector('#ae-ok');
    let items = [], pick = null, active = -1, timer;
    const paint = () => { list.innerHTML = items.map((x, k) => `<li role="option" id="ae-o${k}" data-i="${k}" aria-selected="${k === active}"><span class="trunc">${esc(x.Title)}</span><small class="faint">${esc(NODE[x.EntityType]?.label || x.EntityType)}</small></li>`).join('');
      list.hidden = !items.length; q.setAttribute('aria-expanded', String(!!items.length)); if (active >= 0) q.setAttribute('aria-activedescendant', `ae-o${active}`); };
    const choose = (x) => { pick = x; list.hidden = true; q.setAttribute('aria-expanded', 'false'); q.value = x.Title; ok.disabled = false;
      d.querySelector('#ae-picked').innerHTML = `Seçilen: <b>${esc(x.Title)}</b> <span class="faint">(${esc(NODE[x.EntityType].label)})</span>`; };
    q.addEventListener('input', () => { clearTimeout(timer); pick = null; ok.disabled = true; const v = q.value.trim(); if (v.length < 2) { items = []; paint(); return; }
      timer = setTimeout(async () => { try { items = (await api('/api/search', { params: { q: v } })).filter((x) => NODE[x.EntityType]); active = -1; paint(); } catch { items = []; paint(); } }, 200); });
    q.addEventListener('keydown', (e) => { if (list.hidden) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); active = (active + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; paint(); }
      else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); choose(items[active]); } else if (e.key === 'Escape') { e.stopPropagation(); list.hidden = true; } });
    list.addEventListener('mousedown', (e) => { const li = e.target.closest('[data-i]'); if (li) { e.preventDefault(); choose(items[+li.dataset.i]); } });
    d.querySelector('form').onsubmit = async (e) => {
      e.preventDefault(); if (!pick) return;
      try { await api(`/api/cases/${id}/items`, { method: 'POST', body: { type: pick.EntityType, id: pick.EntityID, note: d.querySelector('#ae-note').value.trim() || null } });
        d.close(); toast('Vakaya eklendi.'); onDone(); }
      catch (x) { e.target.querySelector('.err').textContent = x.message; }
    };
  }

  function bind(c, d) {
    const id = c.InvestigationID, root = document.getElementById('detailView'), reload = () => detail(id);
    root.querySelectorAll('[data-st]').forEach((b) => b.onclick = async () => {
      try { await api(`/api/cases/${id}`, { method: 'PATCH', body: { status: b.dataset.st } }); toast(`Vaka durumu: ${CASE_STATUS[b.dataset.st]}.`); reload(); }
      catch (e) { toast(e.message, 'err'); }
    });
    const ed = document.getElementById('editCase'); if (ed) ed.onclick = () => caseForm(c, reload);
    document.getElementById('caseReport').onclick = () => report(c, d);
    const ae = document.getElementById('addEntity'); if (ae) ae.onclick = () => addEntity(id, reload);
    const del = document.getElementById('delCase');
    if (del) del.onclick = () => {
      const dl = dialog(`<div class="dlg"><div class="dlg-head"><h2>Vakayı sil</h2><button type="button" class="btn icon ghost" data-dismiss aria-label="Kapat"><i data-lucide="x"></i></button></div><p>#${id} ${esc(c.Title)} vakası, ${d.items.length} öğe bağlantısı ve ${d.notes.length} notuyla birlikte silinecek. Vakadaki IOC ve diğer kayıtlar silinmez.</p>
        <p class="muted" style="font-size:13px;margin-top:8px">Bu işlem geri alınamaz; silme denetim kaydına yazılır.</p>
        <div class="dlg-foot"><button class="btn" data-dismiss>Vazgeç</button><button class="btn danger" id="yes">Vakayı sil</button></div></div>`);
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
    document.getElementById('caseTbl').addEventListener('click', (e) => { if (e.target.closest('[data-new-case]')) caseForm(null, go); });
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
