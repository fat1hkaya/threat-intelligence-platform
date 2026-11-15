import { ReactNode } from "react";
import { fmtNum } from "../lib";

/** Son 30 gün: alan = ilk kez görülen gösterge, çubuk = kurum içi görülme */
export function TrendChart({ data }: { data: { Day: string; Added: number; Sightings: number }[] }) {
  const W = 760, H = 220, L = 36, R = 36, T = 12, B = 26;
  const maxA = Math.max(4, ...data.map((d) => d.Added));
  const maxS = Math.max(4, ...data.map((d) => d.Sightings));
  const x = (i: number) => L + (i * (W - L - R)) / Math.max(1, data.length - 1);
  const yA = (v: number) => T + (H - T - B) * (1 - v / maxA);
  const yS = (v: number) => T + (H - T - B) * (1 - v / maxS);
  const line = data.map((d, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${yA(d.Added).toFixed(1)}`).join(" ");
  const area = `${line} L${x(data.length - 1)},${H - B} L${x(0)},${H - B} Z`;
  const bw = Math.max(3, (W - L - R) / data.length - 6);
  const ticks = [0, 0.5, 1];
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Son 30 günde ilk kez görülen göstergeler ve kurum içi görülmeler">
      {ticks.map((t) => (
        <g key={t}>
          <line x1={L} x2={W - R} y1={yA(maxA * t)} y2={yA(maxA * t)} stroke="var(--line)" strokeDasharray={t ? "3 4" : undefined} />
          <text x={L - 6} y={yA(maxA * t) + 4} textAnchor="end">{Math.round(maxA * t)}</text>
          <text x={W - R + 6} y={yS(maxS * t) + 4}>{Math.round(maxS * t)}</text>
        </g>
      ))}
      {data.map((d, i) => d.Sightings > 0 && (
        <rect key={d.Day} x={x(i) - bw / 2} y={yS(d.Sightings)} width={bw} height={H - B - yS(d.Sightings)} rx="2" fill="var(--accent)" opacity="0.55">
          <title>{`${d.Day}: ${d.Sightings} görülme`}</title>
        </rect>
      ))}
      <path d={area} fill="var(--c-indicator)" opacity="0.14" />
      <path d={line} fill="none" stroke="var(--c-indicator)" strokeWidth="2" strokeLinejoin="round" />
      {data.map((d, i) => (
        <circle key={d.Day} cx={x(i)} cy={yA(d.Added)} r="7" fill="transparent"><title>{`${d.Day}: ${d.Added} yeni gösterge`}</title></circle>
      ))}
      {data.map((d, i) => (i % 5 === 0 || i === data.length - 1) && (
        <text key={d.Day} x={x(i)} y={H - 8} textAnchor="middle">{d.Day.slice(8, 10)}.{d.Day.slice(5, 7)}</text>
      ))}
    </svg>
  );
}

export function BarList({ rows, color }: { rows: { key: string | number; label: ReactNode; value: number; note?: ReactNode }[]; color?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="barlist">
      {rows.map((r) => (
        <div className="row" key={r.key}>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.label}</span>
          <span className="num muted">{r.note ?? fmtNum(r.value)}</span>
          <span className="track"><i style={{ width: `${(r.value / max) * 100}%`, background: color }} /></span>
        </div>
      ))}
    </div>
  );
}

const SEV_COLOR: Record<string, string> = { critical: "var(--risk-crit)", high: "var(--risk-high)", medium: "var(--risk-med)", low: "var(--risk-low)", info: "var(--faint)" };
export function SeverityBar({ rows }: { rows: { Code: string; Name: string; Total: number }[] }) {
  const total = rows.reduce((s, r) => s + r.Total, 0) || 1;
  return (
    <div>
      <div className="sevbar" role="img" aria-label="Önem düzeyine göre aktif gösterge dağılımı">
        {rows.filter((r) => r.Total > 0).map((r) => <i key={r.Code} style={{ flex: r.Total, background: SEV_COLOR[r.Code] }} title={`${r.Name}: ${r.Total}`} />)}
      </div>
      <div className="legend">
        {rows.map((r) => (
          <span key={r.Code} className={`sev ${r.Code}`}><i />{r.Name} <b className="num" style={{ color: "var(--text)", fontWeight: 500 }}>{fmtNum(r.Total)}</b>
            <span className="faint num">%{Math.round((r.Total / total) * 100)}</span></span>
        ))}
      </div>
    </div>
  );
}
