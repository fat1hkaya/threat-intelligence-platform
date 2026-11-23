/* İlişki grafı: /api/graph/* (vis-network). Düğüm/kenarlar yalnızca veritabanından gelir. */
(() => {
  const { api, esc, fmtN, fmtDT, fmtD, sev, conf, NODE, entityUrl, table, empty, loading, toast, icons, qs, sourceBadge, pager } = TL;
  const SHAPE = { indicator: 'dot', malware: 'diamond', campaign: 'square', actor: 'hexagon', technique: 'triangle', vulnerability: 'star' };
  const REL = { indicates: 'ilişkili', uses: 'kullanır', exploits: 'istismar eder', 'attributed-to': 'atfedilir', observed: 'içerir' };
  const st = { depth: 2, start: null, hidden: new Set(), group: true, layered: true, focus: null, hoverEdge: null, page: 1 };
  // Katmanlı yerleşimde (varsayılan) düğüm türünün sütunu: IOC -> zararlı -> kampanya -> aktör -> teknik
  const LEVEL = { indicator: 0, malware: 1, campaign: 2, actor: 3, technique: 4, vulnerability: 4 };
  const SHAPE_ICON = { dot: 'circle', diamond: 'diamond', square: 'square', hexagon: 'hexagon', triangle: 'triangle', star: 'star' };
  const typeMark = (t) => `<i data-lucide="${SHAPE_ICON[SHAPE[t]]}" class="type-mark" style="color:${NODE[t].color}" aria-hidden="true"></i><span class="sr-only">${esc(NODE[t].label)}: </span>`;
  const GROUPS_PER_PAGE = 15;
  // Sayı ile birlikte kullanılan küçük harfli ad ("45 aktör", "+22 ATT&CK tekniği")
  const COUNT_LABEL = { indicator: 'IOC', malware: 'zararlı yazılım', campaign: 'kampanya', actor: 'tehdit aktörü', technique: 'ATT&CK tekniği', vulnerability: 'zafiyet' };
  const EDGE_COLOR = '#3B4D72', CLUSTER_ID = 'cluster:technique';
  // isCluster() olmayan düğümde konsola hata yazar; önce varlığı denetlenir
  const clustered = () => !!(network && network.body.nodes[CLUSTER_ID]);
  let network, nodes, edges;

  const nid = (t, id) => `${t}:${id}`;
  const short = (s, n = 26) => (s && s.length > n ? s.slice(0, 12) + '…' + s.slice(-8) : s);
  const toNode = (n) => ({
    id: nid(n.NodeType, n.NodeID), type: n.NodeType, rid: n.NodeID, raw: n.Label, sub: n.SubLabel,
    label: n.NodeType === 'indicator' ? short(n.Label) : (n.NodeType === 'technique' ? `${n.SubLabel}\n${short(n.Label, 30)}` : short(n.Label, 30)),
    title: `${NODE[n.NodeType].label}: ${n.Label}`, shape: SHAPE[n.NodeType], hidden: st.hidden.has(n.NodeType), level: LEVEL[n.NodeType],
    size: n.Lvl === 0 ? 26 : n.NodeType === 'technique' ? 11 : 17,
    color: { background: NODE[n.NodeType].color, border: n.Lvl === 0 ? '#FFFFFF' : NODE[n.NodeType].color, highlight: { background: NODE[n.NodeType].color, border: '#FFFFFF' }, hover: { background: NODE[n.NodeType].color, border: '#FFFFFF' } },
    borderWidth: n.Lvl === 0 ? 3 : 1,
    font: { color: '#E2E8F0', size: n.Lvl === 0 ? 14 : 12, face: n.NodeType === 'indicator' ? 'JetBrains Mono' : 'Inter', strokeWidth: 4, strokeColor: '#0B1020' },
  });
  const toEdge = (e) => ({
    id: `${nid(e.SourceType, e.SourceID)}>${e.Relation}>${nid(e.TargetType, e.TargetID)}`, from: nid(e.SourceType, e.SourceID), to: nid(e.TargetType, e.TargetID),
    rel: e.Relation, conf: e.Confidence, lbl: REL[e.Relation] || e.Relation, label: '', main: e.Main !== 0,
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    color: { color: EDGE_COLOR, highlight: '#22D3EE', hover: '#94A3B8', opacity: e.Main === 0 ? 0.35 : 1 }, width: e.Confidence != null ? 1 + e.Confidence / 50 : 1.2,
    font: { color: '#94A3B8', size: 10, strokeWidth: 3, strokeColor: '#0B1020', align: 'middle' }, smooth: { type: 'continuous' },
  });

  function ensureNetwork() {
    if (network) return;
    nodes = new vis.DataSet(); edges = new vis.DataSet();
    network = new vis.Network(document.getElementById('network'), { nodes, edges }, {
      interaction: { hover: true, tooltipDelay: 150, keyboard: { enabled: true, bindToWindow: false }, multiselect: false },
      edges: { selectionWidth: 2 },
      ...layoutOptions(),
    });
    network.on('stabilizationIterationsDone', () => network.setOptions({ physics: { enabled: false } }));
    network.on('click', (p) => {
      if (p.nodes.length && network.isCluster(p.nodes[0])) { clusterInfo(p.nodes[0]); return; }
      if (p.nodes.length && nodes.get(p.nodes[0])?.type === 'more') { moreInfo(nodes.get(p.nodes[0])); return; }
      if (p.nodes.length) { st.focus = p.nodes[0]; highlight(st.focus); showNode(nodes.get(p.nodes[0])); }
      else if (p.edges.length) showEdge(edges.get(p.edges[0]));
      else { st.focus = null; highlight(null); }
    });
    network.on('doubleClick', (p) => {
      if (!p.nodes.length) return;
      if (network.isCluster(p.nodes[0])) { network.openCluster(p.nodes[0]); st.group = false; syncTools(); return; }
      const n = nodes.get(p.nodes[0]);
      n.type === 'more' ? openMore(n) : expand(n);
    });
    network.on('hoverNode', (p) => { if (!network.isCluster(p.node)) highlight(p.node); });
    network.on('blurNode', () => highlight(st.focus));
    // Kenar etiketi yalnızca seçili düğümün kenarlarında ve kenarın üzerine gelince
    network.on('hoverEdge', (p) => { const e = edges.get(p.edge); if (e) edges.update({ id: e.id, label: e.lbl }); });
    network.on('blurEdge', (p) => { const e = edges.get(p.edge); if (e && !(st.focus && network.getConnectedEdges(st.focus).includes(e.id))) edges.update({ id: e.id, label: '' }); });
  }

  // Odak: düğüm ve komşuları tam görünür, gerisi soluklaşır. Odak yokken asıl yol tam, çapraz kenarlar %35.
  function highlight(id) {
    if (!nodes || !network) return;
    const keep = id && nodes.get(id) ? new Set([id, ...network.getConnectedNodes(id)]) : null;
    const ce = keep ? new Set(network.getConnectedEdges(id)) : null;
    nodes.update(nodes.get().map((n) => ({ id: n.id, opacity: !keep || keep.has(n.id) ? 1 : 0.15 })));
    edges.update(edges.get().map((e) => ({ id: e.id,
      color: { color: ce && ce.has(e.id) ? '#22D3EE' : e.path ? '#22D3EE' : EDGE_COLOR, opacity: ce ? (ce.has(e.id) ? 1 : 0.1) : (e.main ? 1 : 0.35), highlight: '#22D3EE', hover: '#94A3B8' },
      label: ce && ce.has(e.id) ? e.lbl : '' })));
  }

  // ATT&CK teknikleri tek kümede: onlarca üçgen yerine tek düğüm; çift tıklayınca açılır
  function applyGrouping() {
    if (!network) return;
    if (clustered()) network.openCluster(CLUSTER_ID);
    const techs = nodes.get({ filter: (n) => n.type === 'technique' && !n.hidden }).length;
    if (st.group && techs > 12) {
      network.cluster({
        joinCondition: (n) => n.type === 'technique' && !n.hidden,
        clusterNodeProperties: { id: CLUSTER_ID, label: `${techs} ATT&CK tekniği\n(çift tıklayın)`, shape: 'triangle', size: 30, level: LEVEL.technique,
          color: { background: NODE.technique.color, border: '#FFFFFF' }, borderWidth: 2,
          font: { color: '#E2E8F0', size: 13, face: 'Inter', strokeWidth: 4, strokeColor: '#0B1020' } },
        clusterEdgeProperties: { color: { color: EDGE_COLOR, opacity: 0.6 } },
      });
    }
  }
  function clusterInfo() {
    document.getElementById('side').innerHTML = `<h2>ATT&amp;CK teknikleri (küme)</h2>
      <p class="muted" style="margin-top:8px">Okunabilirlik için teknikler tek düğümde toplandı. Tek tek görmek için kümeye çift tıklayın ya da graf araçlarından gruplamayı kapatın. Teknik ilişkileri aşağıdaki ilişki tablosunda da listelenir.</p>`;
  }

  function layoutOptions() {
    return st.layered
      ? { layout: { hierarchical: { enabled: true, direction: 'LR', levelSeparation: 240, nodeSpacing: 46, treeSpacing: 70, sortMethod: 'directed', shakeTowards: 'roots' } },
          physics: { enabled: true, solver: 'hierarchicalRepulsion', hierarchicalRepulsion: { nodeDistance: 60, avoidOverlap: 0.9 }, stabilization: { iterations: 120 } } }
      : { layout: { hierarchical: { enabled: false }, improvedLayout: true },
          physics: { enabled: true, solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 110, springConstant: 0.06, avoidOverlap: 0.6 }, stabilization: { iterations: 220 } } };
  }
  function setLayout() {
    if (!network) return;
    network.setOptions(layoutOptions());
    network.once('stabilizationIterationsDone', () => network.fit({ animation: { duration: 300 } }));
  }

  function syncTools() {
    const g = document.getElementById('gGroup'), l = document.getElementById('gLayout');
    if (g) g.setAttribute('aria-pressed', String(st.group));
    if (l) { l.setAttribute('aria-pressed', String(st.layered)); l.title = st.layered ? 'Katmanlı yerleşim açık: serbest (fizik) yerleşime geçmek için basın' : 'Serbest yerleşim: katmanlı yerleşime (IOC → zararlı → kampanya → aktör → teknik) geçmek için basın'; }
  }

  function status() {
    const real = nodes.get({ filter: (n) => n.type !== 'more' });
    const vis = real.filter((n) => !n.hidden).length;
    const realEdges = edges.get({ filter: (e) => !e.more });
    document.getElementById('gStatus').textContent = `${fmtN(real.length)} düğüm · ${fmtN(realEdges.length)} kenar${vis !== real.length ? ` · ${fmtN(vis)} görünür` : ''}`;
    document.getElementById('gViewNote').textContent = `${fmtN(real.length)} düğüm, ${fmtN(realEdges.length)} ilişki`;
    edgeTable();
  }

  // İlişki tablosu: hedef düğüme göre gruplu ("System Network Configuration Discovery ← 45 aktör"), sayfalı
  function edgeTable() {
    const box = document.getElementById('edgeTable');
    const rows = edges.get({ filter: (e) => !e.more });
    const groups = new Map();
    rows.forEach((e) => { if (!groups.has(e.to)) groups.set(e.to, []); groups.get(e.to).push(e); });
    const list = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);
    const pages = Math.max(1, Math.ceil(list.length / GROUPS_PER_PAGE));
    st.page = Math.min(st.page, pages);
    const name = (id) => { const n = nodes.get(id); return n ? `${typeMark(n.type)}<a href="#" data-focus="${esc(id)}" class="${n.type === 'indicator' ? 'mono' : ''}" title="${esc(n.raw)}">${esc(short(n.raw, 48))}</a>` : esc(id); };
    // özet satırının içinde etkileşimli öğe olmaz (nested-interactive): hedef adı düz metin
    const plain = (id) => { const n = nodes.get(id); return n ? `${typeMark(n.type)}<span class="${n.type === 'indicator' ? 'mono' : ''}" title="${esc(n.raw)}">${esc(short(n.raw, 48))}</span>` : esc(id); };
    const confCell = (e) => e.conf != null ? conf(e.conf)
      : '<span class="faint" title="Kaynak (ör. MITRE ATT&CK) bu ilişki için güven puanı vermiyor">belirtilmemiş</span>';
    const kinds = (es) => { const c = {}; es.forEach((e) => { const t = nodes.get(e.from)?.type; c[t] = (c[t] || 0) + 1; });
      return Object.entries(c).map(([t, k]) => `${fmtN(k)} ${esc(COUNT_LABEL[t] || t)}`).join(', '); };
    box.innerHTML = rows.length ? `<div class="edge-groups">${list.slice((st.page - 1) * GROUPS_PER_PAGE, st.page * GROUPS_PER_PAGE).map(([to, es]) => `
      <details class="edge-group"${list.length <= 4 ? ' open' : ''}><summary><span class="eg-target">${plain(to)}</span><span class="eg-count">← ${kinds(es)}</span></summary>
        <p class="eg-focus"><button type="button" class="link-btn" data-focus="${esc(to)}">Düğümü grafikte göster</button></p>
        <table class="data eg-table"><caption class="sr-only">${esc(nodes.get(to)?.raw || to)} düğümüne gelen ilişkiler</caption>
          <thead class="sr-only"><tr><th scope="col">Kaynak</th><th scope="col">İlişki</th><th scope="col">Güven</th><th scope="col"><span class="sr-only">Kanıt</span></th></tr></thead>
          <tbody>${es.map((e) => `<tr class="clickable" data-edge-row="${esc(e.id)}" tabindex="0"><td><span class="node-ref">${name(e.from)}</span></td>
            <td><span class="badge b-muted">${esc(REL[e.rel] || e.rel)}</span></td><td>${confCell(e)}</td>
            <td class="actions"><button type="button" class="btn sm icon ghost" data-edge="${esc(e.id)}" aria-label="Kanıtı göster" title="Kanıtı göster"><i data-lucide="file-search"></i></button></td></tr>`).join('')}</tbody></table>
      </details>`).join('')}</div>` : empty('Graf boş.');
    pager(document.getElementById('edgePager'), { page: st.page, pages, total: list.length, size: GROUPS_PER_PAGE }, (p) => { st.page = p; edgeTable(); }, 'hedef düğüm');
    icons();
  }

  // Tip başına sınırı aşan komşular: "+48 aktör" küme düğümü; çift tıklayınca açılır
  function moreNodes(clusters) {
    const ns = [], es = [];
    (clusters || []).forEach((c) => {
      const t = NODE[c.childType];
      ns.push({ id: c.id, type: 'more', parentType: c.parentType, parentId: c.parentId, childType: c.childType, count: c.count, offset: c.offset,
        label: `+${fmtN(c.count)} ${COUNT_LABEL[c.childType]}`, title: `Gösterilmeyen ${fmtN(c.count)} ${COUNT_LABEL[c.childType]}: açmak için çift tıklayın`,
        shape: SHAPE[c.childType], size: 14, level: LEVEL[c.childType], hidden: st.hidden.has(c.childType), borderWidth: 2, shapeProperties: { borderDashes: [3, 3] },
        color: { background: '#0B1020', border: t.color, highlight: { background: '#1F2D48', border: '#FFFFFF' }, hover: { background: '#1F2D48', border: '#FFFFFF' } },
        font: { color: '#CBD5E1', size: 12, face: 'Inter', strokeWidth: 4, strokeColor: '#0B1020' } });
      es.push({ id: `${nid(c.parentType, c.parentId)}>more>${c.id}`, from: nid(c.parentType, c.parentId), to: c.id, more: true, lbl: '', label: '', main: true,
        dashes: true, color: { color: EDGE_COLOR, opacity: 0.6 }, arrows: { to: { enabled: false } } });
    });
    nodes.update(ns); edges.update(es);
  }
  function moreInfo(n) {
    document.getElementById('side').innerHTML = `<h2>${esc(n.label)}</h2>
      <p class="muted" style="margin-top:8px;font-size:13px">Okunabilirlik için bir düğümün aynı tipteki komşuları sınırlıdır. Kalan ${fmtN(n.count)} kayıt bu kümede; çift tıklayarak ya da aşağıdaki düğmeyle 60'arlı gruplar hâlinde açabilirsiniz.</p>
      <div class="chips" style="margin-top:12px"><button class="btn sm" id="moreOpen"><i data-lucide="plus-circle"></i>Kümeyi aç</button></div>`;
    icons(); document.getElementById('moreOpen').onclick = () => openMore(n);
  }
  async function openMore(n) {
    try {
      const d = await api('/api/graph/neighborhood', { params: { type: n.parentType, id: n.parentId, only: n.childType, offset: n.offset, limit: 300 } });
      nodes.remove(n.id); edges.remove(edges.get({ filter: (e) => e.to === n.id }).map((e) => e.id));
      d.nodes.forEach((x) => { x.Lvl = Math.max(1, x.Lvl); });
      const before = nodes.length; merge(d);
      toast(`${fmtN(nodes.length - before)} düğüm eklendi.`);
    } catch (e) { toast(e.message, 'err'); }
  }

  // Sınıra ulaşıldığında bilgi satırı: kaç düğüm gösterilmedi, sınırı artır, tipe göre filtrele
  function info(d) {
    const el = document.getElementById('gInfo');
    if (!d || !d.truncated) { el.hidden = true; return; }
    const sel = document.getElementById('limit'), canRaise = sel.selectedIndex < sel.options.length - 1;
    el.hidden = false;
    el.innerHTML = `<i data-lucide="info" aria-hidden="true"></i><span>Düğüm sınırına ulaşıldı: ${fmtN(d.hidden)} düğüm gösterilmedi</span>
      ${canRaise ? `<button type="button" class="link-btn" data-info="raise">Sınırı artır</button>` : ''}<button type="button" class="link-btn" data-info="filter">Tipe göre filtrele</button>`;
    icons();
  }

  function merge(data, focusId) {
    ensureNetwork();
    nodes.update(data.nodes.filter((n) => !nodes.get(nid(n.NodeType, n.NodeID)) || n.Lvl === 0 && !st.start).map(toNode));
    edges.update(data.edges.map(toEdge));
    moreNodes(data.clusters);
    document.getElementById('gEmpty').hidden = nodes.length > 0;
    document.getElementById('gLayoutBox').classList.toggle('has-data', nodes.length > 0);
    network.setOptions({ physics: { enabled: true } });
    applyGrouping(); highlight(st.focus);
    status();
    if (focusId) {
      // Katmanlı yerleşimde konumlar hemen belli: önce hemen sığdır, kararlı hâle gelince yeniden
      requestAnimationFrame(() => network.fit());
      network.once('stabilizationIterationsDone', () => network.fit({ animation: { duration: 300 } }));
    }
  }

  async function open(type, id) {
    st.start = { type, id };
    qs.set({ type, id, q: null, case: null });
    document.getElementById('gStatus').textContent = 'Graf yükleniyor…';
    try {
      const d = await api('/api/graph/neighborhood', { params: { type, id, depth: st.depth, limit: document.getElementById('limit').value,
        indicators: document.getElementById('incIoc').checked, techniques: document.getElementById('incTech').checked } });
      ensureNetwork(); if (clustered()) network.openCluster(CLUSTER_ID); st.focus = null; st.page = 1; nodes.clear(); edges.clear(); merge(d, true);
      info(d);
      const s = nodes.get(nid(type, id)); if (s) showNode(s);
    } catch (e) { toast(e.message, 'err'); document.getElementById('gStatus').textContent = ''; }
  }

  // Vaka modu: vakadaki varlıklar (kalın çerçeve) + en az iki vaka öğesine bağlı ortak düğümler (kesikli çerçeve)
  async function openCase(caseId) {
    st.start = null;
    document.getElementById('gStatus').textContent = 'Vaka grafı yükleniyor…';
    try {
      const [c, d] = await Promise.all([api(`/api/cases/${caseId}`), api(`/api/cases/${caseId}/graph`)]);
      ensureNetwork(); if (clustered()) network.openCluster(CLUSTER_ID); st.focus = null; nodes.clear(); edges.clear();
      nodes.update(d.nodes.map((n) => ({ ...toNode(n), ...(n.Lvl === 0 ? {} : { shapeProperties: { borderDashes: [4, 4] }, borderWidth: 2,
        color: { background: '#0B1020', border: NODE[n.NodeType].color, highlight: { background: NODE[n.NodeType].color, border: '#FFFFFF' }, hover: { background: '#1F2D48', border: '#FFFFFF' } } }) })));
      edges.update(d.edges.map(toEdge));
      document.getElementById('gEmpty').hidden = nodes.length > 0;
      network.setOptions({ physics: { enabled: true } });
      applyGrouping(); highlight(null);
      status(); info(null);
      network.once('stabilizationIterationsDone', () => network.fit({ animation: { duration: 400 } }));
      const box = document.getElementById('side');
      box.innerHTML = `<div class="entity-title"><span class="ic" style="background:var(--purple-soft);color:var(--badge-purple-fg)"><i data-lucide="briefcase"></i></span><div style="min-width:0">
          <span class="muted" style="font-size:12px">Vaka grafı</span><h2 style="font-size: 18px">#${c.case.InvestigationID} ${esc(c.case.Title)}</h2></div></div>
        <dl class="kv" style="margin-top:14px"><dt>Vaka öğesi</dt><dd>${c.items.length}</dd><dt>Ortak bağlantı</dt><dd>${d.common.length}</dd><dt>Kenar</dt><dd>${d.edges.length}</dd></dl>
        <p class="faint" style="font-size: 13px;margin-top:10px">Kalın çerçeveli düğümler vakada. Kesikli çerçeveliler vakada değil ama vakadaki en az iki varlığa bağlı: incelemeye değer adaylar.</p>
        <div class="chips" style="margin-top:14px"><a class="btn sm" href="/cases?id=${c.case.InvestigationID}"><i data-lucide="arrow-left"></i>Vakaya dön</a></div>`;
      icons();
    } catch (e) { toast(e.message, 'err'); document.getElementById('gStatus').textContent = ''; }
  }

  async function expand(n) {
    try {
      const d = await api('/api/graph/neighborhood', { params: { type: n.type, id: n.rid, depth: 1, limit: 300, indicators: document.getElementById('incIoc').checked || n.type !== 'indicator' } });
      const before = nodes.length; d.nodes.forEach((x) => { x.Lvl = Math.max(1, x.Lvl); }); merge(d);
      toast(`${nodes.length - before} yeni düğüm eklendi.`);
    } catch (e) { toast(e.message, 'err'); }
  }

  async function showNode(n) {
    const side = document.getElementById('side');
    side.innerHTML = `<h2>${esc(NODE[n.type].label)}</h2>` + loading();
    let d; try { d = await api('/api/graph/node', { params: { type: n.type, id: n.rid } }); } catch (e) { side.innerHTML = empty(e.message); return; }
    const kv = (k, v) => (v == null || v === '' ? '' : `<dt>${k}</dt><dd>${v}</dd>`);
    const facts = {
      indicator: () => kv('Tip', esc(d.TypeName)) + kv('Önem', sev(d.SeverityCode)) + kv('Güven', conf(d.Confidence)) + kv('Risk skoru', `${d.RiskScore} <a class="hint-q" href="/settings#risk" title="Risk skoru nasıl hesaplanır? Güven, önem ağırlığı ve kurum içi görülme sayısından taban puan; kaynak güvenilirliği ve tazelik çarpanları; aktif değilse yarıya iner." aria-label="Risk skoru nasıl hesaplanır?"><i data-lucide="circle-help"></i></a>`) + kv('Kaynak', sourceBadge(d.SourceName)) + kv('Son görülme', fmtDT(d.LastSeen)),
      malware: () => kv('Tür', esc(d.TypeName)) + kv('Platform', esc(d.Platforms)) + kv('Aktör', d.ActorCount) + kv('Teknik', d.TechniqueCount) + kv('IOC', d.IndicatorCount),
      actor: () => kv('Köken', esc(d.CountryName)) + kv('Motivasyon', esc(d.Motivation)) + kv('Zararlı/araç', d.MalwareCount) + kv('Teknik', d.TechniqueCount) + kv('Kampanya', d.CampaignCount),
      campaign: () => kv('Aktör', esc(d.ActorName)) + kv('Başlangıç', fmtD(d.StartDate)) + kv('Bitiş', d.EndDate ? fmtD(d.EndDate) : 'Devam ediyor') + kv('IOC', d.IndicatorCount) + kv('Teknik', d.TechniqueCount),
      technique: () => kv('Taktik', esc(d.Tactics)),
      vulnerability: () => kv('Başlık', esc(d.Title)) + kv('Ürün', esc([d.Vendor, d.Product].filter(Boolean).join(' '))) + kv('CVSS', d.CvssScore) + kv('KEV', d.IsKnownExploited ? 'Evet' : 'Hayır'),
    }[n.type]();
    side.innerHTML = `<div class="entity-title">${TL.nodeIcon(n.type)}<div style="min-width:0"><span class="muted" style="font-size:12px">${esc(NODE[n.type].label)}${d.SubLabel ? ' · ' + esc(d.SubLabel) : ''}</span>
        <h2 class="${n.type === 'indicator' ? 'mono' : ''}" style="font-size:${n.type === 'indicator' ? 13 : 17}px">${esc(d.Label)}</h2></div></div>
      <dl class="kv" style="margin-top:14px">${facts}${kv('Bağlantı', `${d.OutDegree} giden · ${d.InDegree} gelen kenar`)}</dl>
      ${d.Description ? `<p class="desc" style="margin-top:12px">${esc(d.Description)}</p>` : ''}
      <div class="chips" style="margin-top:14px"><button class="btn sm" id="nExpand"><i data-lucide="plus-circle"></i>Komşuları ekle</button>
        <button class="btn sm" id="nStart"><i data-lucide="crosshair"></i>Buradan başlat</button><a class="btn sm" href="${entityUrl(n.type, n.rid)}"><i data-lucide="external-link"></i>Kayda git</a>${TL.caseBtn(n.type, n.rid, d.Label)}</div>`;
    icons();
    document.getElementById('nExpand').onclick = () => expand(n);
    document.getElementById('nStart').onclick = () => open(n.type, n.rid);
    network.selectNodes([n.id]);
  }

  async function showEdge(e) {
    const side = document.getElementById('side'); side.innerHTML = '<h2>İlişki</h2>' + loading();
    const [st_, sid] = e.from.split(':'), [tt, tid] = e.to.split(':');
    let d; try { d = await api('/api/graph/edge', { params: { sourceType: st_, sourceId: sid, targetType: tt, targetId: tid, relation: e.rel } }); } catch (err) { side.innerHTML = empty(err.message); return; }
    side.innerHTML = `<h2>İlişki: ${esc(REL[d.Relation] || d.Relation)}</h2>
      <div class="chain" style="margin:12px 0"><span class="node n-${d.SourceType}"><b>${esc(short(d.SourceLabel, 34))}</b></span><span class="arrow">→</span><span class="node n-${d.TargetType}"><b>${esc(short(d.TargetLabel, 34))}</b></span></div>
      <dl class="kv"><dt>Anlamı</dt><dd>${esc(d.Meaning)}</dd><dt>Kenar tablosu</dt><dd class="mono">${esc(d.EdgeTable)}</dd>
        ${d.Role ? `<dt>Rol</dt><dd>${esc(d.Role)}</dd>` : ''}<dt>Güven</dt><dd>${d.Confidence != null ? conf(d.Confidence) : '<span class="faint" title="Kaynak bu ilişki için güven puanı vermiyor (MITRE ATT&CK ilişkileri puansızdır)">belirtilmemiş</span>'}</dd>
        <dt>Doğrulama kaynağı</dt><dd>${d.EvidenceSource ? sourceBadge(d.EvidenceSource) + ` <span class="faint">(güvenilirlik ${esc(d.Reliability)})</span>` : '<span class="faint">kanıt kaydı yok</span>'}</dd>
        ${d.ExternalRef ? `<dt>Dış kimlik</dt><dd class="mono" style="font-size: 12px">${esc(d.ExternalRef)}</dd>` : ''}
        ${d.CollectedAt ? `<dt>Toplandı</dt><dd>${fmtDT(d.CollectedAt)}</dd>` : ''}</dl>
      <h3 style="margin-top:14px">Kanıt</h3><p class="desc" style="margin-top:6px">${esc(d.Evidence || 'Bu ilişki için kanıt metni yok.')}</p>
      ${d.EvidenceUrl && /^https?:\/\//i.test(d.EvidenceUrl) ? `<p style="margin-top:8px"><a href="${esc(d.EvidenceUrl)}" target="_blank" rel="noopener noreferrer">Kaynağı aç</a></p>` : ''}`;
    if (network && edges.get(e.id)) network.selectEdges([e.id]);
  }

  function combo() {
    const input = document.getElementById('gq'), list = document.getElementById('gqList');
    let items = [], active = -1, timer;
    const close = () => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); active = -1; };
    const paint = () => {
      list.innerHTML = items.map((x, k) => `<li role="option" id="gq-o${k}" data-i="${k}" aria-selected="${k === active}"><span class="trunc">${typeMark(x.EntityType)}${esc(x.Title)}</span><small class="faint">${esc(NODE[x.EntityType]?.label || x.EntityType)}</small></li>`).join('');
      list.hidden = !items.length; input.setAttribute('aria-expanded', String(!!items.length));
      if (active >= 0) input.setAttribute('aria-activedescendant', `gq-o${active}`); icons();
    };
    const pick = (x) => { close(); input.value = x.Title; open(x.EntityType, x.EntityID); };
    input.addEventListener('input', () => {
      clearTimeout(timer); const q = input.value.trim();
      if (q.length < 2) { items = []; close(); return; }
      timer = setTimeout(async () => { try { items = (await api('/api/search', { params: { q } })).filter((x) => NODE[x.EntityType]).slice(0, 8); active = -1; paint(); } catch { items = []; close(); } }, 200);
    });
    input.addEventListener('keydown', (e) => {
      if (list.hidden) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); active = (active + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length; paint(); }
      else if (e.key === 'Enter' && active >= 0) { e.preventDefault(); pick(items[active]); }
      else if (e.key === 'Escape') { e.stopPropagation(); close(); }
    });
    list.addEventListener('mousedown', (e) => { const li = e.target.closest('[data-i]'); if (li) { e.preventDefault(); pick(items[+li.dataset.i]); } });
    input.addEventListener('blur', () => setTimeout(close, 100));
  }

  async function search(q) {
    const c = document.getElementById('cands'); c.hidden = true;
    try {
      const r = await api('/api/graph/search', { params: { q } });
      if (r.exact) { open(r.exact.type, r.exact.id); return; }
      if (!r.candidates.length) { toast('Eşleşen düğüm bulunamadı.', 'err'); return; }
      if (r.candidates.length === 1) { open(r.candidates[0].type, r.candidates[0].id); return; }
      c.hidden = false;
      c.innerHTML = `<span class="muted" style="font-size: 13px">Birden çok eşleşme var, birini seçin:</span><div class="chips">${r.candidates.map((x) =>
        `<button type="button" class="chip" data-t="${x.type}" data-i="${x.id}"><i data-lucide="${NODE[x.type].icon}" style="width:14px;height:14px;color:${NODE[x.type].color}"></i>${esc(short(x.label, 40))}</button>`).join('')}</div>`;
      icons();
    } catch (e) { toast(e.message, 'err'); }
  }

  function legend() {
    document.getElementById('legend').innerHTML = Object.entries(NODE).map(([t, n]) =>
      `<button type="button" class="type-chip" data-type="${t}" aria-pressed="${!st.hidden.has(t)}" title="${esc(n.label)}: göster/gizle"><i style="background:${n.color}" aria-hidden="true"></i>${esc(n.label)}</button>`).join('');
  }

  async function examples() {
    const box = document.getElementById('examples');
    const ex = [{ label: 'APT29', q: 'APT29' }, { label: 'Cobalt Strike', q: 'Cobalt Strike' }];
    try {   // aktöre atfedilmiş gerçek bir IOC (IOC -> zararlı -> aktör zinciri olan)
      const r = await api('/api/iocs/examples');
      r.forEach((i) => ex.unshift({ label: `${TL.TYPE_LABEL[i.TypeCode] || 'IOC'} → ${i.MalwareName} → ${i.ActorName}`, type: 'indicator', id: i.IndicatorID, value: i.Value }));
    } catch { /* örnekler isteğe bağlı */ }
    box.innerHTML = ex.map((e, k) => `<button class="btn sm" data-ex="${k}">${esc(e.label)}</button>`).join('');
    box.onclick = (ev) => { const b = ev.target.closest('[data-ex]'); if (!b) return; const e = ex[+b.dataset.ex];
      document.getElementById('gq').value = e.value || e.q; e.type ? open(e.type, e.id) : search(e.q); };
  }

  async function path(ev) {
    ev.preventDefault();
    const out = document.getElementById('pathOut');
    const ids = Object.fromEntries([...document.querySelectorAll('#actorList option')].map((o) => [o.value.toLowerCase(), o.dataset.id]));
    const a = ids[document.getElementById('pa').value.trim().toLowerCase()], b = ids[document.getElementById('pb').value.trim().toLowerCase()];
    if (!a || !b) { out.innerHTML = '<p class="err">Listeden iki aktör seçin.</p>'; return; }
    out.innerHTML = loading('En kısa yol aranıyor');
    try {
      const r = await api('/api/graph/path', { params: { fromActor: a, toActor: b } });
      if (!r.found) { out.innerHTML = '<p class="notice warn"><i data-lucide="info"></i>En çok 5 adımda bağlantı bulunamadı: bu aktörler arasında ortak araç zinciri yok.</p>'; icons(); return; }
      out.innerHTML = `<p style="font-size:13px"><b>${r.hops}</b> adım:</p><ol class="timeline" style="margin-top:8px">${r.path.map((p, k) => `<li><span class="dot ${k ? '' : 'done'}"></span><div>
          <a href="/actors?id=${p.id}"><b>${esc(p.name)}</b></a>${r.steps[k] ? `<br><small class="muted">ortak: ${r.steps[k].shared.slice(0, 6).map((s) => esc(s.Name)).join(', ')}${r.steps[k].shared.length > 6 ? '…' : ''}</small>` : ''}</div></li>`).join('')}</ol>`;
      // Yolu grafta göster: aktörler + ortak araçlar (veritabanından gelen ActorMalware ilişkileri)
      ensureNetwork(); if (clustered()) network.openCluster(CLUSTER_ID); st.focus = null; nodes.clear(); edges.clear(); st.start = null;
      const ns = [], es = [];
      r.path.forEach((p, k) => ns.push({ NodeType: 'actor', NodeID: p.id, Label: p.name, SubLabel: '', Lvl: k === 0 ? 0 : 1 }));
      r.steps.forEach((s) => s.shared.slice(0, 5).forEach((m) => { ns.push({ NodeType: 'malware', NodeID: m.MalwareID, Label: m.Name, SubLabel: '', Lvl: 2 });
        es.push({ SourceType: 'actor', SourceID: s.from, TargetType: 'malware', TargetID: m.MalwareID, Relation: 'uses' }, { SourceType: 'actor', SourceID: s.to, TargetType: 'malware', TargetID: m.MalwareID, Relation: 'uses' }); }));
      merge({ nodes: ns, edges: es }, true);
      edges.update(edges.get().map((x) => ({ id: x.id, path: true, width: 3 }))); highlight(null); info(null);
      icons();
    } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }

  // Hata ayıklama ve tarayıcı testleri için salt okunur erişim
  TL.graph = { get network() { return network; }, get nodes() { return nodes; }, get edges() { return edges; } };

  document.addEventListener('DOMContentLoaded', async () => {
    legend(); examples();
    document.getElementById('legend').addEventListener('click', (e) => {
      const b = e.target.closest('[data-type]'); if (!b) return;
      const t = b.dataset.type, on = st.hidden.has(t);
      on ? st.hidden.delete(t) : st.hidden.add(t);
      b.setAttribute('aria-pressed', String(on));
      if (nodes) { if (clustered()) network.openCluster(CLUSTER_ID); nodes.update(nodes.get().map((n) => ({ id: n.id, hidden: st.hidden.has(n.type === 'more' ? n.childType : n.type) }))); applyGrouping(); status(); }
    });
    document.getElementById('gInfo').addEventListener('click', (e) => {
      const b = e.target.closest('[data-info]'); if (!b) return;
      if (b.dataset.info === 'raise') { const sel = document.getElementById('limit'); sel.selectedIndex = Math.min(sel.options.length - 1, sel.selectedIndex + 1); if (st.start) open(st.start.type, st.start.id); }
      else document.querySelector('#legend .type-chip')?.focus();
    });
    combo();
    document.getElementById('depth').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return; st.depth = +b.dataset.v;
      document.querySelectorAll('#depth button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      if (st.start) open(st.start.type, st.start.id);
    });
    ['limit', 'incIoc', 'incTech'].forEach((k) => document.getElementById(k).addEventListener('change', () => st.start && open(st.start.type, st.start.id)));
    document.getElementById('gform').addEventListener('submit', (e) => { e.preventDefault(); const q = document.getElementById('gq').value.trim(); if (q.length >= 2) search(q); });
    document.getElementById('cands').addEventListener('click', (e) => { const b = e.target.closest('[data-t]'); if (b) { document.getElementById('cands').hidden = true; open(b.dataset.t, +b.dataset.i); } });
    document.getElementById('zIn').onclick = () => network && network.moveTo({ scale: network.getScale() * 1.3 });
    document.getElementById('zOut').onclick = () => network && network.moveTo({ scale: network.getScale() / 1.3 });
    document.getElementById('zFit').onclick = () => network && network.fit({ animation: { duration: 300 } });
    document.getElementById('zReset').onclick = () => st.start ? open(st.start.type, st.start.id) : network && network.fit();
    document.getElementById('gGroup').onclick = () => { st.group = !st.group; syncTools(); if (network) { applyGrouping(); network.fit({ animation: { duration: 300 } }); } };
    document.getElementById('gLayout').onclick = () => { st.layered = !st.layered; syncTools(); setLayout(); };
    syncTools();
    // Telefonda graf varsayılan olarak ilişki tablosu görünümünde; düğme graf ile tablo arasında geçiş yapar
    document.getElementById('gViewBtn').addEventListener('click', (e) => {
      const b = e.currentTarget, on = document.getElementById('gLayoutBox').classList.toggle('show-graph');
      b.setAttribute('aria-pressed', String(on));
      b.innerHTML = on ? '<i data-lucide="table-2"></i>Tabloyu göster' : '<i data-lucide="share-2"></i>Grafiği göster'; icons();
      if (on && network) requestAnimationFrame(() => { network.redraw(); network.fit(); });
    });
    const et = document.getElementById('edgeTable');
    et.addEventListener('click', (e) => {
      const f = e.target.closest('[data-focus]'); if (f) { e.preventDefault(); network.focus(f.dataset.focus, { scale: 1.2, animation: true }); showNode(nodes.get(f.dataset.focus)); return; }
      const b = e.target.closest('[data-edge], [data-edge-row]'); if (b) showEdge(edges.get(b.dataset.edge || b.dataset.edgeRow));
    });
    et.addEventListener('keydown', (e) => { const r = e.target.closest('[data-edge-row]'); if (r && e.key === 'Enter') showEdge(edges.get(r.dataset.edgeRow)); });
    document.getElementById('pathForm').addEventListener('submit', path);
    api('/api/actors', { params: { size: 200, sort: 'name' } }).then((r) => {
      document.getElementById('actorList').innerHTML = r.items.map((a) => `<option value="${esc(a.Name)}" data-id="${a.ActorID}"></option>`).join('');
    });
    const t = qs.get('type'), id = qs.get('id'), q = qs.get('q'), cs = qs.get('case');
    if (cs) openCase(+cs);
    else if (t && id) open(t, +id); else if (q) { document.getElementById('gq').value = q; search(q); }
  });
})();
