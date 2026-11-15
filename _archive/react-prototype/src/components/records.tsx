// Kayıt (aktör, zararlı, kampanya) sayfalarının ortak parçaları
import { ReactNode, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Risk, TypeTag } from "./ui";

export function useDebounced(value: string, ms = 250) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

/** Teknikleri taktik sütunlarına göre gruplar */
export function TechniqueGrid({ rows }: { rows: { TechniqueID: number; ExternalID: string; Name: string; TacticID: number; TacticName: string; DisplayOrder: number }[] }) {
  const groups = new Map<number, { name: string; order: number; items: typeof rows }>();
  rows.forEach((r) => {
    if (!groups.has(r.TacticID)) groups.set(r.TacticID, { name: r.TacticName, order: r.DisplayOrder, items: [] });
    groups.get(r.TacticID)!.items.push(r);
  });
  if (rows.length === 0) return <p className="muted">Kayıtlı teknik yok.</p>;
  return (
    <div className="tgrid">{[...groups.values()].sort((a, b) => a.order - b.order).map((g) => (
      <div key={g.name}>
        <h3>{g.name} <span className="faint num">{g.items.length}</span></h3>
        {g.items.map((t) => <Link key={t.TechniqueID} to={`/attack?technique=${t.TechniqueID}`}><small>{t.ExternalID}</small>{t.Name}</Link>)}
      </div>))}</div>
  );
}

export function IndicatorRows({ rows, extra }: { rows: any[]; extra?: (r: any) => ReactNode }) {
  if (rows.length === 0) return <p className="muted">Bağlı gösterge yok.</p>;
  return (
    <div className="list">{rows.map((r) => (
      <div key={r.IndicatorID} style={r.IsActive === false ? { opacity: 0.55 } : undefined}>
        <span className="left"><TypeTag code={r.TypeCode} /><Link className="mono" to={`/indicators/${r.IndicatorID}`} title={r.Value}>{r.Value}</Link></span>
        <span style={{ display: "flex", gap: 10, alignItems: "center", flex: "none" }}>
          {extra?.(r)}
          {r.SightingCount > 0 && <span className="badge" style={{ color: "var(--accent)", borderColor: "var(--accent)" }}>{r.SightingCount} görülme</span>}
          <Risk score={r.RiskScore} />
        </span>
      </div>))}</div>
  );
}

export const Stat = ({ value, label }: { value: ReactNode; label: string }) => <div><b className="num">{value}</b><span>{label}</span></div>;
