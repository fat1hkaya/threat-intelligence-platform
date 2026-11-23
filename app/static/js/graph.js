/* İlişki grafı: /api/graph/* (vis-network). Düğüm/kenarlar yalnızca veritabanından gelir. */
(() => {
  const { api, esc, fmtDT, fmtD, sev, conf, NODE, entityUrl, table, empty, loading, toast, icons, qs, sourceBadge } = TL;
  const SHAPE = { indicator: 'dot', malware: 'diamond', campaign: 'square', actor: 'hexagon', technique: 'triangle', vulnerability: 'star' };
  const REL = { indicates: 'ilişkili', uses: 'kullanır', exploits: 'istismar eder', 'attributed-to': 'atfedilir', observed: 'içerir' };
  const st = { depth: 2, start: null, hidden: new Set(), labels: false, group: true, layered: false, focus: null };
  // Katmanlı yerleşimde düğüm türünün sütunu: IOC -> zararlı -> kampanya -> aktör -> teknik
  const LEVEL = { indicator: 0, vulnerability: 0, malware: 1, campaign: 2, actor: 3, technique: 4 };
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
    rel: e.Relation, conf: e.Confidence, lbl: REL[e.Relation] || e.Relation, label: st.labels ? (REL[e.Relation] || e.Relation) : '',
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    color: { color: EDGE_COLOR, highlight: '#22D3EE', hover: '#94A3B8' }, width: e.Confidence != null ? 1 + e.Confidence / 50 : 1.2,
    font: { color: '#94A3B8', size: 10, strokeWidth: 3, strokeColor: '#0B1020', align: 'middle' }, smooth: { type: 'continuous' },
  });

  function ensureNetwork() {
    if (network) return;
    nodes = new vis.DataSet(); edges = new vis.DataSet();
    network = new vis.Network(document.getElementById('network'), { nodes, edges }, {
      interaction: { hover: true, tooltipDelay: 150, keyboard: { enabled: true, bindToWindow: false }, multiselect: false },
      physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 110, springConstant: 0.06, avoidOverlap: 0.6 }, stabilization: { iterations: 220 } },
      edges: { selectionWidth: 2 }, layout: { improvedLayout: true },
    });
    network.on('stabilizationIterationsDone', () => network.setOptions({ physics: { enabled: false } }));
    network.on('click', (p) => {
      if (p.nodes.length && network.isCluster(p.nodes[0])) { clusterInfo(p.nodes[0]); return; }
      if (p.nodes.length) { st.focus = p.nodes[0]; highlight(st.focus); showNode(nodes.get(p.nodes[0])); }
      else if (p.edges.length) showEdge(edges.get(p.edges[0]));
      else { st.focus = null; highlight(null); }
    });
    network.on('doubleClick', (p) => {
      if (!p.nodes.length) return;
      if (network.isCluster(p.nodes[0])) { network.openCluster(p.nodes[0]); st.group = false; syncTools(); return; }
      expand(nodes.get(p.nodes[0]));
    });
    network.on('hoverNode', (p) => { if (!network.isCluster(p.node)) highlight(p.node); });
    network.on('blurNode', () => highlight(st.focus));
    network.on('zoom', () => syncLabels());
  }

  // Odak: düğüm ve komşuları tam görünür, gerisi soluklaşır (yoğun grafta ilişkiyi okumak için)
  function highlight(id) {
    if (!nodes || !network) return;
    const keep = id && nodes.get(id) ? new Set([id, ...network.getConnectedNodes(id)]) : null;
    const ce = keep ? new Set(network.getConnectedEdges(id)) : null;
    nodes.update(nodes.get().map((n) => ({ id: n.id, opacity: !keep || keep.has(n.id) ? 1 : 0.15 })));
    edges.update(edges.get().map((e) => ({ id: e.id,
      color: { color: ce && ce.has(e.id) ? '#22D3EE' : EDGE_COLOR, opacity: !ce || ce.has(e.id) ? 1 : 0.1, highlight: '#22D3EE', hover: '#94A3B8' },
      label: (ce && ce.has(e.id)) || st.labels ? e.lbl : '' })));
  }

  // Kenar etiketleri: uzaktan bakışta gürültü; yakınlaştırınca ya da az kenarda görünür
  function syncLabels(force = false) {
    if (!network) return;
    const want = edges.length <= 40 || network.getScale() >= 1.1;
    if (want === st.labels && !force) return;
    st.labels = want;
    highlight(st.focus);
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

  function setLayout() {
    if (!network) return;
    network.setOptions(st.layered
      ? { layout: { hierarchical: { enabled: true, direction: 'LR', levelSeparation: 260, nodeSpacing: 58, treeSpacing: 80, sortMethod: 'directed', shakeTowards: 'roots' } },
          physics: { enabled: true, solver: 'hierarchicalRepulsion', hierarchicalRepulsion: { nodeDistance: 70, avoidOverlap: 0.9 }, stabilization: { iterations: 220 } } }
      : { layout: { hierarchical: { enabled: false } },
          physics: { enabled: true, solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -60, springLength: 110, springConstant: 0.06, avoidOverlap: 0.6 }, stabilization: { iterations: 220 } } });
    network.once('stabilizationIterationsDone', () => network.fit({ animation: { duration: 300 } }));
  }

  function syncTools() {
    const g = document.getElementById('gGroup'), l = document.getElementById('gLayout');
    if (g) g.setAttribute('aria-pressed', String(st.group));
    if (l) l.setAttribute('aria-pressed', String(st.layered));
  }

  function status() {
    const vis = nodes.get({ filter: (n) => !n.hidden }).length;
    document.getElementById('gStatus').textContent = `${nodes.length} düğüm · ${edges.length} kenar${vis !== nodes.length ? ` · ${vis} görünür` : ''}`;
    document.getElementById('gViewNote').textContent = `${nodes.length} düğüm, ${edges.length} ilişki`;
    // erişilebilir ilişki tablosu
    const label = (id) => { const n = nodes.get(id); return n ? `<span class="node-ref"><a href="#" data-focus="${esc(id)}" class="${n.type === 'indicator' ? 'mono' : ''}">${esc(short(n.raw, 40))}</a><span class="faint">${esc(NODE[n.type].label)}</span></span>` : esc(id); };
    const rows = edges.get();
    document.getElementById('edgeTable').innerHTML = rows.length ? table([
      { label: 'Kaynak', primary: true, render: (e) => label(e.from) }, { label: 'İlişki', render: (e) => `<span class="badge b-muted">${esc(REL[e.rel] || e.rel)}</span>` },
      { label: 'Hedef', render: (e) => label(e.to) }, { label: 'Güven', num: true, render: (e) => e.conf ?? '—' },
      { label: '', render: (e) => `<button class="btn sm" data-edge="${esc(e.id)}">Kanıt</button>` }], rows.slice(0, 300), { caption: 'Graf kenarları' })
      + (rows.length > 300 ? `<p class="faint" style="padding:10px 16px">İlk 300 kenar listelendi.</p>` : '') : empty('Graf boş.');
  }

  function merge(data, focusId) {
    ensureNetwork();
    nodes.update(data.nodes.filter((n) => !nodes.get(nid(n.NodeType, n.NodeID)) || n.Lvl === 0 && !st.start).map(toNode));
    edges.update(data.edges.map(toEdge));
    document.getElementById('gEmpty').hidden = nodes.length > 0;
    document.getElementById('gLayoutBox').classList.toggle('has-data', nodes.length > 0);
    network.setOptions({ physics: { enabled: true } });
    applyGrouping(); syncLabels(true);
    status();
    if (focusId) network.once('stabilizationIterationsDone', () => network.fit({ animation: { duration: 400 } }));
  }

  async function open(type, id) {
    st.start = { type, id };
    qs.set({ type, id, q: null, case: null });
    document.getElementById('gStatus').textContent = 'Graf yükleniyor…';
    try {
      const d = await api('/api/graph/neighborhood', { params: { type, id, depth: st.depth, limit: document.getElementById('limit').value,
        indicators: document.getElementById('incIoc').checked, techniques: document.getElementById('incTech').checked } });
      ensureNetwork(); if (clustered()) network.openCluster(CLUSTER_ID); st.focus = null; nodes.clear(); edges.clear(); merge(d, true);
      if (d.truncated) toast(`Düğüm sınırına (${d.limit}) ulaşıldı. Komşuları görmek için bir düğüme çift tıklayın veya sınırı artırın.`);
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
      applyGrouping(); syncLabels(true);
      status();
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
      const d = await api('/api/graph/neighborhood', { params: { type: n.type, id: n.rid, depth: 1, limit: 60, indicators: document.getElementById('incIoc').checked || n.type !== 'indicator' } });
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
      indicator: () => kv('Tip', esc(d.TypeName)) + kv('Önem', sev(d.SeverityCode)) + kv('Güven', conf(d.Confidence)) + kv('Risk skoru', d.RiskScore) + kv('Kaynak', sourceBadge(d.SourceName)) + kv('Son görülme', fmtDT(d.LastSeen)),
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
        ${d.Role ? `<dt>Rol</dt><dd>${esc(d.Role)}</dd>` : ''}<dt>Güven</dt><dd>${d.Confidence != null ? conf(d.Confidence) : '<span class="faint">belirtilmemiş</span>'}</dd>
        <dt>Doğrulama kaynağı</dt><dd>${d.EvidenceSource ? sourceBadge(d.EvidenceSource) + ` <span class="faint">(güvenilirlik ${esc(d.Reliability)})</span>` : '<span class="faint">kanıt kaydı yok</span>'}</dd>
        ${d.ExternalRef ? `<dt>Dış kimlik</dt><dd class="mono" style="font-size: 12px">${esc(d.ExternalRef)}</dd>` : ''}
        ${d.CollectedAt ? `<dt>Toplandı</dt><dd>${fmtDT(d.CollectedAt)}</dd>` : ''}</dl>
      <h3 style="margin-top:14px">Kanıt</h3><p class="desc" style="margin-top:6px">${esc(d.Evidence || 'Bu ilişki için kanıt metni yok.')}</p>
      ${d.EvidenceUrl && /^https?:\/\//i.test(d.EvidenceUrl) ? `<p style="margin-top:8px"><a href="${esc(d.EvidenceUrl)}" target="_blank" rel="noopener noreferrer">Kaynağı aç</a></p>` : ''}`;
    network.selectEdges([e.id]);
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
      `<label><input type="checkbox" data-type="${t}" ${st.hidden.has(t) ? '' : 'checked'}><i style="background:${n.color}"></i>${esc(n.label)}</label>`).join('');
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
      icons();
    } catch (e) { out.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }

  // Hata ayıklama ve tarayıcı testleri için salt okunur erişim
  TL.graph = { get network() { return network; }, get nodes() { return nodes; }, get edges() { return edges; } };

  document.addEventListener('DOMContentLoaded', async () => {
    legend(); examples();
    document.getElementById('legend').addEventListener('change', (e) => {
      const t = e.target.dataset.type; if (!t) return;
      e.target.checked ? st.hidden.delete(t) : st.hidden.add(t);
      if (nodes) { if (clustered()) network.openCluster(CLUSTER_ID); nodes.update(nodes.get().map((n) => ({ id: n.id, hidden: st.hidden.has(n.type) }))); applyGrouping(); status(); }
    });
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
    document.getElementById('edgeTable').addEventListener('click', (e) => {
      const f = e.target.closest('[data-focus]'); if (f) { e.preventDefault(); network.focus(f.dataset.focus, { scale: 1.2, animation: true }); showNode(nodes.get(f.dataset.focus)); }
      const b = e.target.closest('[data-edge]'); if (b) showEdge(edges.get(b.dataset.edge));
    });
    document.getElementById('pathForm').addEventListener('submit', path);
    api('/api/actors', { params: { size: 200, sort: 'name' } }).then((r) => {
      document.getElementById('actorList').innerHTML = r.items.map((a) => `<option value="${esc(a.Name)}" data-id="${a.ActorID}"></option>`).join('');
    });
    const t = qs.get('type'), id = qs.get('id'), q = qs.get('q'), cs = qs.get('case');
    if (cs) openCase(+cs);
    else if (t && id) open(t, +id); else if (q) { document.getElementById('gq').value = q; search(q); }
  });
})();
