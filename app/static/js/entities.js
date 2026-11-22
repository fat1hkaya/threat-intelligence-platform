/* Liste + sağ detay paneli düzenindeki sayfalar (aktör, kampanya, zararlı, teknik, denetim) için ortak denetleyici. */
(() => {
  const { api, table, bindTable, markRow, pager, panel, panelHead, loading, empty, icons, qs, toast } = TL;

  /** cfg: { endpoint, columns, rowId, unit, size, key, detail(id) -> Promise<html>, title, extra(), onData(d) } */
  TL.listPage = (cfg) => {
    const split = document.getElementById('split'), tbl = document.getElementById('tbl'), form = document.getElementById('filters');
    const key = cfg.key || cfg.endpoint.replace(/^\/api\//, '');
    let bar = document.getElementById('tblBar');
    if (!bar && tbl) { bar = document.createElement('div'); bar.id = 'tblBar'; bar.className = 'table-bar'; tbl.before(bar); }
    const st = { page: +(qs.get('page') || 1), size: cfg.size ? TL.pageSize(key, cfg.size) : TL.pageSize(key, 25), selected: qs.get('id'), last: null };
    let fb = null;
    const params = () => {
      const f = fb ? fb.values() : {};
      return { ...f, ...(cfg.extra ? cfg.extra() : {}), page: st.page, size: st.size };
    };
    const render = () => {
      const d = st.last; if (!d) return;
      tbl.innerHTML = d.items.length ? table(cfg.columns, d.items, { rowId: cfg.rowId, selected: st.selected, caption: cfg.title, key })
        : empty(fb && fb.activeCount() ? 'Bu filtrelere uyan kayıt yok.' : 'Henüz kayıt yok.', 'search-x',
          fb && fb.activeCount() ? { label: 'Filtreleri temizle', icon: 'filter-x' } : null);
      tbl.querySelector('[data-empty-action]')?.addEventListener('click', () => fb.reset());
      TL.tableBar(bar, { total: d.total, unit: cfg.unit, size: st.size, key, columns: cfg.columns, onCols: render,
        onSize: (n) => { st.size = n; st.page = 1; TL.pref.set(`tl-size:${key}`, n); load(); } });
      pager(document.getElementById('pager'), d, (n) => { st.page = n; load(); tbl.closest('section')?.scrollIntoView({ block: 'start', behavior: 'smooth' }); }, cfg.unit);
      icons();
    };

    async function load() {
      if (!st.last) tbl.innerHTML = loading(); else tbl.setAttribute('aria-busy', 'true');
      const p = params(); qs.set({ ...p, size: null, page: p.page > 1 ? p.page : null, id: st.selected });
      try {
        const d = await api(cfg.endpoint, { params: p });
        if (d.items.length === 0 && st.page > 1 && d.total > 0) { st.page = 1; return load(); }
        cfg.onData && cfg.onData(d);
        st.last = d; render();
      } catch (e) { st.last = null; bar.innerHTML = ''; TL.failed(tbl, e, load); }
      finally { tbl.removeAttribute('aria-busy'); }
    }
    async function show(id) {
      st.selected = id; qs.set({ id }); markRow(tbl, id);
      panel(split, panelHead(cfg.title) + loading());
      try { panel(split, panelHead(cfg.title) + await cfg.detail(id)); cfg.afterDetail && cfg.afterDetail(id); }
      catch (e) { const p = panel(split, panelHead(cfg.title) + '<div class="panel-err"></div>'); TL.failed(p.querySelector('.panel-err'), e, () => show(id)); }
    }
    TL.onPanelClose = () => { st.selected = null; qs.set({ id: null }); markRow(tbl, -1); };
    bindTable(tbl, { onRow: show });
    const start = async () => {
      fb = TL.filterBar(form, { onChange: () => { st.page = 1; load(); } });
      await load(); if (st.selected) show(st.selected);
    };
    return { load, show, start, toast, filters: () => fb };
  };

  /** Teknikleri taktiğe göre gruplar (panelde kullanılır) */
  TL.techByTactic = (rows, limit = 60) => {
    if (!rows.length) return '<p class="faint" style="font-size:13px">Teknik ilişkisi yok.</p>';
    const groups = new Map();
    rows.forEach((r) => { if (!groups.has(r.TacticName)) groups.set(r.TacticName, new Map()); groups.get(r.TacticName).set(r.ExternalID, r); });
    let n = 0;
    return [...groups.entries()].map(([tac, m]) => `<div><small class="muted">${TL.esc(tac)} (${m.size})</small><div class="chips" style="margin-top:4px">${[...m.values()].filter(() => n++ < limit)
      .map((t) => TL.techChip(t.TechniqueID, t.ExternalID, t.Name)).join('')}</div></div>`).join('');
  };
})();
