import { useEffect, useState } from "react";
import { api, onTraces, TraceRef, traces } from "../api";
import { Icon } from "./ui";

interface Statement { sql: string; params: unknown[]; ms: number; rows: number | null }
interface Trace { id: string; method: string; path: string; ms: number; statements: Statement[] }

const KEYWORDS = /\b(SELECT|FROM|WHERE|AND|OR|NOT|IN|EXISTS|JOIN|LEFT|RIGHT|INNER|OUTER|FULL|CROSS|APPLY|ON|AS|GROUP BY|ORDER BY|HAVING|TOP|DISTINCT|UNION ALL|UNION|EXCEPT|INTERSECT|INSERT INTO|INSERT|VALUES|UPDATE|SET|DELETE|MERGE|OUTPUT|EXEC|WITH|CASE|WHEN|THEN|ELSE|END|IS|NULL|LIKE|BETWEEN|DESC|ASC|OFFSET|ROWS|FETCH NEXT|ONLY|OVER|PARTITION BY|BEGIN TRANSACTION|COMMIT TRANSACTION|ROLLBACK TRANSACTION|OPTION|MAXRECURSION)\b/g;

function escapeHtml(s: string) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

/** Çok küçük bir T-SQL renklendirici: yorum, metin, anahtar sözcük, fonksiyon, parametre */
export function highlightSql(sql: string): string {
  return sql.split("\n").map((line) => {
    const cut = line.indexOf("--");
    const code = cut >= 0 ? line.slice(0, cut) : line;
    const comment = cut >= 0 ? line.slice(cut) : "";
    const parts = code.split(/(N?'[^']*')/g).map((part, i) => {
      if (i % 2 === 1) return `<span class="str">${escapeHtml(part)}</span>`;
      return escapeHtml(part)
        .replace(KEYWORDS, '<span class="kw">$1</span>')
        .replace(/\b([A-Z_]{3,}|dbo\.(?:fn|sp)_\w+)(?=\()/g, '<span class="fn">$1</span>')
        .replace(/\?/g, '<span class="pm">?</span>');
    });
    return parts.join("") + (comment ? `<span class="cm">${escapeHtml(comment)}</span>` : "");
  }).join("\n");
}

function Request({ refItem }: { refItem: TraceRef }) {
  const [trace, setTrace] = useState<Trace | null | undefined>(undefined);
  useEffect(() => { api<Trace>(`/trace/${refItem.id}`).then(setTrace).catch(() => setTrace(null)); }, [refItem.id]);
  if (!trace) return null;
  return (
    <div className="sql-req">
      <div className="h"><span>{trace.method} /api{refItem.path.split("?")[0]}</span><span>{trace.statements.length} sorgu, {trace.ms} ms</span></div>
      {trace.statements.map((s, i) => (
        <div key={i}>
          <pre className="sql" dangerouslySetInnerHTML={{ __html: highlightSql(s.sql) }} />
          {(s.params.length > 0 || s.rows !== null) && (
            <div className="sql-meta">
              {s.params.length > 0 && <span>? = [{s.params.map((p) => JSON.stringify(p)).join(", ")}]</span>}
              {s.rows !== null && <span>{s.rows} satır</span>}
              {s.ms > 0 && <span>{s.ms} ms</span>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export function SqlDrawer({ onClose }: { onClose: () => void }) {
  const [, bump] = useState(0);
  useEffect(() => onTraces(() => bump((n) => n + 1)), []);
  return (
    <aside className="drawer" aria-label="Bu sayfanın SQL sorguları">
      <header>
        <div>
          <h2>Bu sayfanın arkasındaki SQL</h2>
          <p className="muted" style={{ fontSize: 12.5 }}>Sunucunun az önce SQL Server'a gönderdiği sorgular. ORM yok, hepsi elle yazıldı.</p>
        </div>
        <button className="btn ghost sm" onClick={onClose} aria-label="Kapat"><Icon name="x" /></button>
      </header>
      <div className="body">
        {traces.length === 0 && <p className="muted">Henüz sorgu yok. Sayfada bir işlem yapın veya sayfayı yenileyin.</p>}
        {traces.map((t) => <Request key={t.id} refItem={t} />)}
      </div>
    </aside>
  );
}
