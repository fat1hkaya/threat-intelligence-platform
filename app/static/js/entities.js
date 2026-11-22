/* Liste + sağ detay paneli düzenindeki sayfalar (aktör, kampanya, zararlı) için ortak denetleyici. */
(() => {
  const { api, table, bindTable, markRow, pager, panel, panelHead, loading, empty, icons, qs, formData, toast } = TL;

  /** cfg: { endpoint, columns, rowId, unit, size, detail(id) -> Promise<html>, title, filters: [names], extra() } */
  TL.listPage = (cfg) => {
    const split = document.getElementById('split'), tbl = document.getElementById('tbl'), form = document.getElementById('filters');
    const st = { page: +(qs.get('page') || 1), selected: qs.get('id') };
    const params = () => { const f = form ? formData(form) : {}; const p = { page: st.page, size: cfg.size || 20, ...(cfg.extra ? cfg.extra() : {}) };
      Object.entries(f).forEach(([k, v]) => { if (v !== '') p[k] = v; }); return p; };

    async function load() {
      tbl.innerHTML = loading();
      const p = params(); qs.set({ ...p, size: null, id: st.selected });
      try {
        const d = await api(cfg.endpoint, { params: p });
        cfg.onData && cfg.onData(d);
        tbl.innerHTML = d.items.length ? table(cfg.columns, d.items, { rowId: cfg.rowId, selected: st.selected, caption: cfg.title }) : empty('Bu filtrelere uyan kayıt yok.');
        pager(document.getElementById('pager'), d, (n) => { st.page = n; load(); }, cfg.unit);
        icons();
      } catch (e) { tbl.innerHTML = empty(e.message, 'circle-alert'); icons(); }
    }
    async function show(id) {
      st.selected = id; qs.set({ id }); markRow(tbl, id);
      panel(split, panelHead(cfg.title) + loading());
      try { panel(split, panelHead(cfg.title) + await cfg.detail(id)); cfg.afterDetail && cfg.afterDetail(id); }
      catch (e) { panel(split, panelHead(cfg.title) + empty(e.message, 'circle-alert')); }
    }
    TL.onPanelClose = () => { st.selected = null; qs.set({ id: null }); markRow(tbl, -1); };
    bindTable(tbl, { onRow: show });
    if (form) {
      form.addEventListener('submit', (e) => { e.preventDefault(); st.page = 1; load(); });
      form.addEventListener('reset', () => setTimeout(() => { st.page = 1; load(); }));
      form.querySelectorAll('select').forEach((s) => s.addEventListener('change', () => { st.page = 1; load(); }));
    }
    const start = async () => {
      if (form) [...form.elements].forEach((el) => {
        const v = el.name && qs.get(el.name); if (!v) return;
        if (el.type === 'checkbox') el.checked = v === el.value; else el.value = v;
      });
      await load(); if (st.selected) show(st.selected);
    };
    return { load, show, start, toast };
  };

  /** Teknikleri taktiğe göre gruplar (panelde kullanılır) */
  TL.techByTactic = (rows, limit = 60) => {
    if (!rows.length) return '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>';
    const groups = new Map();
    rows.forEach((r) => { if (!groups.has(r.TacticName)) groups.set(r.TacticName, new Map()); groups.get(r.TacticName).set(r.ExternalID, r); });
    let n = 0;
    return [...groups.entries()].map(([tac, m]) => `<div><small class="muted">${TL.esc(tac)} (${m.size})</small><div class="chips" style="margin-top:4px">${[...m.values()].filter(() => n++ < limit)
      .map((t) => `<a class="chip" href="/attack?id=${t.TechniqueID}" title="${TL.esc(t.Name)}"><span class="mono">${TL.esc(t.ExternalID)}</span></a>`).join('')}</div></div>`).join('');
  };
})();
