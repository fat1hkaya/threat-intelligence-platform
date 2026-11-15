import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { qs, useData } from "../api";
import { IndicatorForm } from "../components/forms";
import { Empty, Icon, Loading, Pager, Risk, Sev, Tlp, TypeTag, useApp } from "../components/ui";
import { ago } from "../lib";

const COLS: { key: string; label: string; right?: boolean }[] = [
  { key: "risk", label: "Risk" }, { key: "value", label: "Gösterge" }, { key: "", label: "Bağlı tehdit" },
  { key: "", label: "Önem" }, { key: "confidence", label: "Güven", right: true }, { key: "sightings", label: "Görülme", right: true },
  { key: "", label: "Kaynak" }, { key: "lastSeen", label: "Son görülme", right: true },
];

export function Indicators() {
  const { meta, canEdit } = useApp();
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const get = (k: string, d = "") => params.get(k) ?? d;
  const [search, setSearch] = useState(get("q"));
  const [form, setForm] = useState<any | null>(params.get("new") ? { Value: params.get("new") } : null);

  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    Object.entries(patch).forEach(([k, v]) => (v ? next.set(k, v) : next.delete(k)));
    if (!("page" in patch)) next.delete("page");
    next.delete("new");
    setParams(next, { replace: true });
  };
  useEffect(() => { const t = setTimeout(() => { if (search !== get("q")) set({ q: search }); }, 250); return () => clearTimeout(t); }, [search]); // eslint-disable-line

  const sort = get("sort", "lastSeen"), dir = get("dir", "desc"), page = Number(get("page", "1"));
  const path = "/indicators" + qs({ q: get("q"), type: get("type"), severity: get("severity"), tlp: get("tlp"), source: get("source"), tag: get("tag"),
    active: get("active"), sighted: get("sighted"), minRisk: get("minRisk"), sort, dir, page, size: 25 });
  const { data, error, reload } = useData<any>(path);
  const filtered = ["q", "type", "severity", "tlp", "source", "tag", "active", "sighted", "minRisk"].some((k) => params.get(k));

  return (
    <>
      <div className="page-head">
        <div><h1>Göstergeler</h1><p>Tehditle ilişkilendirilmiş IP adresleri, alan adları, URL'ler ve dosya özetleri. Risk skoru güven, önem, görülme, kaynak güvenilirliği ve tazelikten hesaplanır.</p></div>
        <div className="actions">
          <Link className="btn" to="/lookup"><Icon name="list" />Toplu sorgu</Link>
          {canEdit && <button className="btn primary" onClick={() => setForm({})}><Icon name="plus" />Gösterge ekle</button>}
        </div>
      </div>

      <div className="filters">
        <input className="input grow" placeholder="Değerde ara: 198.51, .example, a3f9..." value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Göstergelerde ara" />
        <select className="input" value={get("severity")} onChange={(e) => set({ severity: e.target.value })} aria-label="Önem"><option value="">Her önem</option>{meta.severities.slice().reverse().map((s) => <option key={s.Code} value={s.Code}>{s.Name}</option>)}</select>
        <select className="input" value={get("source")} onChange={(e) => set({ source: e.target.value })} aria-label="Kaynak"><option value="">Her kaynak</option>{meta.sources.map((s) => <option key={s.SourceID} value={s.SourceID}>{s.Name}</option>)}</select>
        <select className="input" value={get("tag")} onChange={(e) => set({ tag: e.target.value })} aria-label="Etiket"><option value="">Her etiket</option>{meta.tags.map((t) => <option key={t.TagID} value={t.Name}>{t.Name}</option>)}</select>
        <select className="input" value={get("minRisk")} onChange={(e) => set({ minRisk: e.target.value })} aria-label="En düşük risk"><option value="">Her risk</option><option value="35">Risk 35 ve üzeri</option><option value="55">Risk 55 ve üzeri</option><option value="75">Risk 75 ve üzeri</option></select>
      </div>
      <div className="filters">
        <div className="chips">
          <button className={`chip${!get("type") ? " on" : ""}`} onClick={() => set({ type: "" })}>Tüm tipler</button>
          {meta.types.map((t) => <button key={t.Code} className={`chip${get("type") === t.Code ? " on" : ""}`} onClick={() => set({ type: get("type") === t.Code ? "" : t.Code })}>{t.Code}</button>)}
        </div>
        <span style={{ flex: 1 }} />
        <button className={`chip${get("sighted") ? " on" : ""}`} onClick={() => set({ sighted: get("sighted") ? "" : "1" })}>Kurumda görülenler</button>
        <button className={`chip${get("active") === "true" ? " on" : ""}`} onClick={() => set({ active: get("active") === "true" ? "" : "true" })}>Yalnızca aktif</button>
        {filtered && <button className="btn ghost sm" onClick={() => { setSearch(""); setParams({}, { replace: true }); }}>Filtreleri temizle</button>}
      </div>

      {!data ? <Loading error={error} /> : (
        <div className="panel">
          {data.items.length === 0 ? (
            <Empty title={filtered ? "Bu filtrelerle eşleşen gösterge yok" : "Henüz gösterge yok"}>
              {filtered ? "Filtreleri gevşetmeyi deneyin." : "Gösterge ekleyin ya da scripts/ingest_feeds.py ile açık kaynaklardan veri çekin."}
            </Empty>
          ) : (
            <div className="table-wrap"><table className="data">
              <thead><tr>{COLS.map((c, i) => (
                <th key={i} className={`${c.right ? "r " : ""}${c.key ? "sortable" : ""}`} aria-sort={c.key === sort ? (dir === "asc" ? "ascending" : "descending") : undefined}
                  onClick={() => c.key && set({ sort: c.key, dir: sort === c.key && dir === "desc" ? "asc" : "desc" })}>
                  {c.label}{c.key === sort && (dir === "asc" ? " ↑" : " ↓")}
                </th>))}</tr></thead>
              <tbody>{data.items.map((r: any) => (
                <tr key={r.IndicatorID} className={r.IsActive ? "" : "dim"} onDoubleClick={() => navigate(`/indicators/${r.IndicatorID}`)}>
                  <td><Risk score={r.RiskScore} /></td>
                  <td>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}><TypeTag code={r.TypeCode} /><Link to={`/indicators/${r.IndicatorID}`} className="value mono" title={r.Value}>{r.Value}</Link></div>
                    {r.Tags.length > 0 && <div className="faint" style={{ fontSize: 11.5, marginTop: 2 }}>{r.Tags.join(", ")}{!r.IsActive && ", pasif"}</div>}
                  </td>
                  <td>{r.ViaName ?? <span className="faint">-</span>}</td>
                  <td><Sev code={r.SeverityCode} name={r.SeverityName} /> <Tlp code={r.TLPCode} /></td>
                  <td className="r num">{r.Confidence}</td>
                  <td className="r num">{r.SightingCount > 0 ? <b style={{ color: "var(--accent)" }}>{r.SightingCount}</b> : <span className="faint">0</span>}</td>
                  <td className="muted">{r.SourceName}</td>
                  <td className="r muted" style={{ whiteSpace: "nowrap" }}>{ago(r.LastSeen)}</td>
                </tr>))}</tbody>
            </table></div>
          )}
          <Pager page={data.page} size={data.size} total={data.total} onPage={(p) => set({ page: String(p) })} />
        </div>
      )}
      {form && <IndicatorForm initial={form} onClose={() => { setForm(null); set({}); }} onSaved={(id) => { setForm(null); reload(); navigate(`/indicators/${id}`); }} />}
    </>
  );
}
