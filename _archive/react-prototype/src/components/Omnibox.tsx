import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { ENTITY, EntityType, entityHref, guessType, refang } from "../lib";

interface Hit { EntityType: EntityType; EntityID: number; Title: string; Subtitle: string | null }

const PAGES: { title: string; to: string }[] = [
  { title: "Genel bakış", to: "/" }, { title: "Göstergeler", to: "/indicators" }, { title: "Toplu sorgu", to: "/lookup" },
  { title: "Aktörler", to: "/actors" }, { title: "Zararlı yazılımlar", to: "/malware" }, { title: "Kampanyalar", to: "/campaigns" },
  { title: "Zafiyetler", to: "/vulnerabilities" }, { title: "ATT&CK matrisi", to: "/attack" }, { title: "İlişki grafı", to: "/graph" },
  { title: "Kaynaklar", to: "/sources" }, { title: "Denetim kaydı", to: "/audit" }, { title: "Veritabanı", to: "/schema" },
];

export function Omnibox({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState(0);
  const navigate = useNavigate();
  const seq = useRef(0);

  const clean = refang(q.trim());
  useEffect(() => {
    if (clean.length < 2) { setHits([]); return; }
    const mine = ++seq.current;
    setBusy(true);
    const timer = setTimeout(() => {
      api<Hit[]>(`/search?q=${encodeURIComponent(clean)}`)
        .then((r) => { if (mine === seq.current) { setHits(r); setSel(0); } })
        .catch(() => {})
        .finally(() => { if (mine === seq.current) setBusy(false); });
    }, 160);
    return () => clearTimeout(timer);
  }, [clean]);

  const pages = clean.length < 2 ? PAGES : PAGES.filter((p) => p.title.toLocaleLowerCase("tr").includes(clean.toLocaleLowerCase("tr")));
  const rows: { key: string; group: string; title: string; sub?: string | null; type?: EntityType; to: string }[] = [
    ...hits.map((h) => ({ key: `${h.EntityType}${h.EntityID}`, group: ENTITY[h.EntityType].many, title: h.Title, sub: h.Subtitle, type: h.EntityType, to: entityHref(h.EntityType, h.EntityID) })),
    ...pages.map((p) => ({ key: p.to, group: "Sayfalar", title: p.title, to: p.to })),
  ];
  const guessed = guessType(clean);
  const unknownIoc = guessed && !busy && clean.length > 3 && !hits.some((h) => h.EntityType === "indicator" && h.Title.toLowerCase() === clean.toLowerCase());

  const go = (to: string) => { onClose(); navigate(to); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(rows.length - 1, s + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
    else if (e.key === "Enter" && rows[sel]) go(rows[sel].to);
    else if (e.key === "Escape") onClose();
  };

  let lastGroup = "";
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="omni" role="dialog" aria-label="Arama">
        <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
          placeholder="IP, alan adı, özet, aktör, zararlı, T1059 veya CVE yazın ya da yapıştırın" aria-label="Arama" />
        <div className="results">
          {unknownIoc && (
            <div className="empty">
              <b style={{ color: "var(--text)" }}>Bu {guessed} kayıtlarımızda yok.</b>{" "}
              Bilinen bir tehdide bağlı değil; bu, temiz olduğu anlamına gelmez.{" "}
              <a href="#" onClick={(e) => { e.preventDefault(); go(`/indicators?new=${encodeURIComponent(clean)}`); }}>Gösterge olarak ekle</a>
            </div>
          )}
          {rows.map((r, i) => {
            const head = r.group !== lastGroup ? <div className="group">{r.group}</div> : null;
            lastGroup = r.group;
            return (
              <div key={r.key}>
                {head}
                <div className={`item${i === sel ? " sel" : ""}`} onMouseEnter={() => setSel(i)} onClick={() => go(r.to)}>
                  <span className={`dot ${r.type ?? ""}`} />
                  <span className={`t${r.type === "indicator" ? " mono" : ""}`}>{r.title}</span>
                  <small>{r.sub}</small>
                </div>
              </div>
            );
          })}
          {rows.length === 0 && !unknownIoc && <div className="empty">{busy ? "Aranıyor..." : "Eşleşen kayıt yok."}</div>}
        </div>
        <div className="foot"><span><kbd>↑</kbd> <kbd>↓</kbd> gezin</span><span><kbd>Enter</kbd> aç</span><span><kbd>Esc</kbd> kapat</span>
          <span style={{ marginLeft: "auto" }}>1.2.3[.]4 ve hxxp:// yazımı otomatik çözülür</span></div>
      </div>
    </div>
  );
}
