import cytoscape, { Core } from "cytoscape";
import { useEffect, useRef } from "react";
import { EntityType } from "../lib";

export interface GNode { NodeType: EntityType; NodeID: number; Label: string; SubLabel: string | null; Lvl: number }
export interface GEdge { SourceType: EntityType; SourceID: number; TargetType: EntityType; TargetID: number; Relation: string }

const REL: Record<string, string> = { uses: "kullanır", "attributed-to": "atfedilir", observed: "gözlendi", indicates: "göstergesi", exploits: "istismar eder" };
const TYPES: EntityType[] = ["actor", "campaign", "malware", "vulnerability", "technique", "indicator"];
const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export function GraphView({ nodes, edges, onSelect, onExpand, theme }: {
  nodes: GNode[]; edges: GEdge[]; theme?: string;
  onSelect?: (n: GNode | null) => void; onExpand?: (n: GNode) => void;
}) {
  const el = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const handlers = useRef({ onSelect, onExpand });
  handlers.current = { onSelect, onExpand };

  useEffect(() => {
    if (!el.current) return;
    const text = css("--text"), line = css("--line-strong"), bg = css("--surface");
    const big = nodes.length > 60;
    const instance = cytoscape({
      container: el.current,
      wheelSensitivity: 0.25,
      minZoom: 0.2, maxZoom: 2.5,
      elements: [
        ...nodes.map((n) => ({ data: { id: `${n.NodeType}:${n.NodeID}`, label: n.Label.length > 26 ? n.Label.slice(0, 24) + "…" : n.Label, type: n.NodeType, lvl: n.Lvl, raw: n } })),
        ...edges.map((e) => ({ data: { id: `${e.SourceType}:${e.SourceID}>${e.TargetType}:${e.TargetID}`, source: `${e.SourceType}:${e.SourceID}`, target: `${e.TargetType}:${e.TargetID}`, label: REL[e.Relation] ?? e.Relation } })),
      ],
      style: [
        { selector: "node", style: { label: "data(label)", color: text, "font-size": 10, "font-family": "IBM Plex Sans, sans-serif", "text-valign": "bottom", "text-margin-y": 5,
            width: 20, height: 20, "border-width": 2, "border-color": bg, "text-outline-color": bg, "text-outline-width": 2, "min-zoomed-font-size": 7 } },
        ...TYPES.map((t) => ({ selector: `node[type = "${t}"]`, style: { "background-color": css(`--c-${t}`) } })),
        { selector: 'node[type = "indicator"]', style: { width: 13, height: 13, "font-family": "JetBrains Mono, monospace", "font-size": 8.5 } },
        { selector: 'node[type = "actor"]', style: { width: 28, height: 28, "font-size": 11.5, "font-weight": 600 } },
        { selector: 'node[type = "technique"]', style: { shape: "round-rectangle", width: 16, height: 16 } },
        { selector: 'node[type = "vulnerability"]', style: { shape: "diamond" } },
        { selector: 'node[type = "campaign"]', style: { shape: "round-hexagon", width: 24, height: 24 } },
        { selector: "node[lvl = 0]", style: { "border-color": css("--accent"), "border-width": 4, width: 34, height: 34, "font-size": 12.5, "font-weight": 600 } },
        { selector: "node:selected", style: { "border-color": text, "border-width": 3 } },
        { selector: "edge", style: { width: 1, "line-color": line, "target-arrow-color": line, "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier", opacity: 0.75 } },
        { selector: "edge.near", style: { "line-color": css("--accent"), "target-arrow-color": css("--accent"), opacity: 1, width: 1.6, label: "data(label)", "font-size": 8.5, color: css("--muted"), "text-background-color": bg, "text-background-opacity": 1, "text-background-padding": "2px" } },
        { selector: ".dim", style: { opacity: 0.18 } },
      ] as any,
      layout: big
        ? ({ name: "concentric", concentric: (n: any) => 10 - n.data("lvl") * 3, levelWidth: () => 3, minNodeSpacing: 14, animate: false } as any)
        : ({ name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, gravity: 0.3, numIter: 1200, padding: 30, randomize: true } as any),
    });
    instance.on("tap", "node", (ev) => {
      const node = ev.target;
      instance.elements().removeClass("near dim");
      instance.elements().not(node.closedNeighborhood()).addClass("dim");
      node.connectedEdges().addClass("near");
      handlers.current.onSelect?.(node.data("raw"));
    });
    instance.on("tap", (ev) => { if (ev.target === instance) { instance.elements().removeClass("near dim"); handlers.current.onSelect?.(null); } });
    instance.on("dbltap", "node", (ev) => handlers.current.onExpand?.(ev.target.data("raw")));
    cy.current = instance;
    (window as any).__cy = instance;
    return () => instance.destroy();
  }, [nodes, edges, theme]);

  return <div className="cy" ref={el} />;
}

export function GraphLegend({ nodes }: { nodes: GNode[] }) {
  const counts = new Map<string, number>();
  nodes.forEach((n) => counts.set(n.NodeType, (counts.get(n.NodeType) ?? 0) + 1));
  const names: Record<string, string> = { actor: "aktör", campaign: "kampanya", malware: "zararlı", vulnerability: "zafiyet", technique: "teknik", indicator: "gösterge" };
  return <div className="hud">{TYPES.filter((t) => counts.has(t)).map((t) => <span key={t}><i className={`dot ${t}`} />{counts.get(t)} {names[t]}</span>)}</div>;
}
