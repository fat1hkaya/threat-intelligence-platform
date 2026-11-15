import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Meta, User } from "../api";
import { EntityType, entityHref, riskBand } from "../lib";

/* ---------- Uygulama bağlamı ---------- */
export interface AppCtx { user: User; meta: Meta; canEdit: boolean; toast: (msg: string, kind?: "ok" | "error") => void; reloadMeta: () => void }
export const AppContext = createContext<AppCtx>(null as unknown as AppCtx);
export const useApp = () => useContext(AppContext);

/* ---------- Simgeler (tek renk, 24'lük ızgara) ---------- */
const PATHS: Record<string, string> = {
  home: "M3 11l9-7 9 7M5 10v10h14V10",
  ioc: "M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  actor: "M12 12a4 4 0 100-8 4 4 0 000 8zM4 21c0-4 3.6-6 8-6s8 2 8 6",
  bug: "M9 9h6v6a3 3 0 01-6 0zM9 9a3 3 0 016 0M4 13h5M15 13h5M5 7l4 3M19 7l-4 3M5 19l4-3M19 19l-4-3",
  flag: "M5 21V4M5 4h12l-2 4 2 4H5",
  vuln: "M12 3l10 18H2zM12 10v5M12 18h.01",
  grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
  graph: "M6 8a2 2 0 100-4 2 2 0 000 4zM18 8a2 2 0 100-4 2 2 0 000 4zM12 20a2 2 0 100-4 2 2 0 000 4zM7.5 7.5l3.5 9M16.5 7.5l-3.5 9M8 6h8",
  feed: "M4 11a9 9 0 019 9M4 4a16 16 0 0116 16M5 19h.01",
  log: "M6 3h9l4 4v14H6zM14 3v5h5M9 13h7M9 17h7",
  db: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6",
  search: "M11 19a8 8 0 100-16 8 8 0 000 16zM21 21l-4.3-4.3",
  sql: "M8 6l-5 6 5 6M16 6l5 6-5 6M14 4l-4 16",
  sun: "M12 17a5 5 0 100-10 5 5 0 000 10zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4",
  moon: "M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z",
  plus: "M12 5v14M5 12h14",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  x: "M6 6l12 12M18 6L6 18",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z",
  users: "M9 11a4 4 0 100-8 4 4 0 000 8zM2 21c0-3.5 3-5.5 7-5.5s7 2 7 5.5M17 3.5a4 4 0 010 7.5M22 21c0-2.6-1.6-4.3-4-5",
  check: "M4 12l5 5L20 6",
};
export function Icon({ name }: { name: keyof typeof PATHS | string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={PATHS[name] ?? ""} />
    </svg>
  );
}
export const Lighthouse = ({ size = 30 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
    <path d="M13 27l1.6-13h2.8L19 27z" fill="var(--text)" />
    <rect x="12.5" y="9" width="7" height="5" rx="1" fill="var(--accent)" />
    <path d="M20 10.2l8-3.2v9l-8-3.2zM12 10.2L4 7v9l8-3.2z" fill="var(--accent)" opacity=".4" />
  </svg>
);

/* ---------- Küçük parçalar ---------- */
export function Risk({ score }: { score: number }) {
  return (
    <span className={`risk ${riskBand(score)}`} title={`Risk skoru ${score}/100`}>
      <b>{score}</b>
      <span className="bar"><i style={{ width: `${score}%` }} /></span>
    </span>
  );
}
export const Sev = ({ code, name }: { code: string; name: string }) => <span className={`sev ${code}`}><i />{name}</span>;
export const Tlp = ({ code }: { code: string }) => <span className={`tlp ${code.replace("TLP:", "")}`}>{code}</span>;
export const TypeTag = ({ code }: { code: string }) => <span className="type-tag">{code}</span>;
export const Cc = ({ code }: { code?: string | null }) => (code ? <span className="cc" title="Köken ülke">{code}</span> : null);

export function EntityLink({ type, id, children }: { type: EntityType; id: number | string; children: ReactNode }) {
  return <Link to={entityHref(type, id)}>{children}</Link>;
}

export function Copy({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn ghost sm" title="Kopyala" onClick={() => { navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); }}>
      <Icon name={done ? "check" : "copy"} />{done ? "Kopyalandı" : "Kopyala"}
    </button>
  );
}

export function Panel({ title, note, action, children, flush }: { title?: ReactNode; note?: ReactNode; action?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className="panel">
      {(title || action) && (
        <header>
          <div><h2>{title}</h2>{note && <p>{note}</p>}</div>
          {action}
        </header>
      )}
      <div className="body" style={flush ? { padding: "8px 6px 4px" } : undefined}>{children}</div>
    </section>
  );
}

export const Empty = ({ title, children }: { title: string; children?: ReactNode }) => (
  <div className="empty-state"><b>{title}</b>{children}</div>
);

export function Loading({ error }: { error?: string | null }) {
  return error ? <div className="panel"><Empty title="Veri yüklenemedi">{error}</Empty></div> : <div className="skeleton" />;
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  const from = total ? (page - 1) * size + 1 : 0;
  return (
    <div className="pager">
      <span className="num">{from}-{Math.min(page * size, total)} / {total.toLocaleString("tr-TR")} kayıt</span>
      <span className="actions">
        <button className="btn sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Önceki</button>
        <span className="num">{page} / {pages}</span>
        <button className="btn sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>Sonraki</button>
      </span>
    </div>
  );
}

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} style={wide ? { width: "min(820px, 94vw)" } : undefined}>
        <header><h2>{title}</h2><button className="btn ghost sm" onClick={onClose} aria-label="Kapat"><Icon name="x" /></button></header>
        <div className="body">{children}</div>
        {footer && <footer>{footer}</footer>}
      </div>
    </div>
  );
}

export function Field({ label, hint, wide, children }: { label: string; hint?: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={`field${wide ? " wide" : ""}`}>
      <label>{label}</label>
      {children}
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

/** Virgül veya Enter ile ayrılan serbest metin listesi (etiket, takma ad) */
export function TokenInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState("");
  const commit = () => {
    const parts = draft.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) onChange([...new Set([...value, ...parts])]);
    setDraft("");
  };
  return (
    <div>
      {value.length > 0 && (
        <div className="chips" style={{ marginBottom: 6 }}>
          {value.map((v) => (
            <span key={v} className="chip static">{v}<button type="button" aria-label={`${v} kaldır`} onClick={() => onChange(value.filter((x) => x !== v))}>×</button></span>
          ))}
        </div>
      )}
      <input className="input" value={draft} placeholder={placeholder} onChange={(e) => setDraft(e.target.value)} onBlur={commit}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === ",") { e.preventDefault(); commit(); } }} />
    </div>
  );
}

export function useConfirmDelete(toast: AppCtx["toast"]) {
  return useCallback(async (what: string, run: () => Promise<unknown>, after: () => void) => {
    if (!window.confirm(`${what} silinsin mi? Bu işlem geri alınamaz.`)) return;
    try { await run(); toast(`${what} silindi.`); after(); } catch (e: any) { toast(e.message, "error"); }
  }, [toast]);
}
