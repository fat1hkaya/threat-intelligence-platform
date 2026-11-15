import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, useData } from "../api";
import { IndicatorForm, LinkAdder, Unlink } from "../components/forms";
import { GraphLegend, GraphView } from "../components/GraphView";
import { Copy, Empty, Icon, Loading, Panel, Risk, Sev, Tlp, TypeTag, useApp, useConfirmDelete } from "../components/ui";
import { ago, defang, fmtDateTime, RELIABILITY, riskBand, riskLabel, ROLE_LABEL } from "../lib";

const FIELD_LABEL: Record<string, string> = { Value: "Değer", Confidence: "Güven", SeverityID: "Önem", TLPID: "TLP", SourceID: "Kaynak", IsActive: "Aktif", ExpiresAt: "Geçerlilik sonu", Description: "Açıklama" };
const ACTION: Record<string, string> = { I: "Oluşturuldu", U: "Güncellendi", D: "Silindi" };

export function Changes({ before, after }: { before: any; after: any }) {
  if (!before || !after) return null;
  const keys = Object.keys({ ...before, ...after }).filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k]));
  return (
    <div className="diff">{keys.map((k) => (
      <div key={k}>{FIELD_LABEL[k] ?? k}: <span className="old">{String(before[k] ?? "boş")}</span> <span className="new">{String(after[k] ?? "boş")}</span></div>
    ))}</div>
  );
}

export function IndicatorDetail({ theme }: { theme: string }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const { canEdit, toast } = useApp();
  const confirmDelete = useConfirmDelete(toast);
  const { data, error, reload } = useData<any>(`/indicators/${id}`);
  const graph = useData<any>(`/graph?type=indicator&id=${id}&depth=2&limit=40`);
  const [editing, setEditing] = useState(false);
  const [sighting, setSighting] = useState({ quantity: 1, location: "", note: "" });
  if (!data) return <Loading error={error} />;
  const i = data.indicator;
  const band = riskBand(i.RiskScore);

  // Zincirleri "aracı" (zararlı / kampanya) başına grupla
  const chains = new Map<string, { type: string; id: number; name: string; role?: string; actors: { id: number; name: string }[] }>();
  data.attribution.forEach((a: any) => {
    const key = `${a.ViaType}:${a.ViaID}`;
    if (!chains.has(key)) chains.set(key, { type: a.ViaType, id: a.ViaID, name: a.ViaName, role: a.Role, actors: [] });
    if (a.ActorID) chains.get(key)!.actors.push({ id: a.ActorID, name: a.ActorName });
  });

  const addSighting = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api(`/indicators/${id}/sightings`, { method: "POST", body: sighting });
      toast("Görülme kaydedildi. Son görülme tarihi tetikleyiciyle güncellendi.");
      setSighting({ quantity: 1, location: "", note: "" }); reload();
    } catch (err: any) { toast(err.message, "error"); }
  };

  return (
    <>
      <div className="crumb"><Link to="/indicators">Göstergeler</Link> / {i.TypeName}</div>
      <div className="record-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <h1 className="mono">{i.Value}</h1>
          <div className="meta">
            <TypeTag code={i.TypeCode} /><Sev code={i.SeverityCode} name={i.SeverityName} /><Tlp code={i.TLPCode} />
            <span className="badge"><i className={`dot ${i.IsActive ? "ok" : ""}`} />{i.IsActive ? "Aktif" : "Pasif"}</span>
            {i.Tags.map((t: string) => <Link key={t} className="chip" to={`/indicators?tag=${encodeURIComponent(t)}`}>{t}</Link>)}
          </div>
          <div className="actions" style={{ marginTop: 14 }}>
            <Copy text={i.Value} />
            <button className="btn ghost sm" title="Güvenli yazımı kopyala" onClick={() => { navigator.clipboard?.writeText(defang(i.Value)); toast(`Kopyalandı: ${defang(i.Value)}`); }}>Güvenli yazımla kopyala</button>
            <Link className="btn ghost sm" to={`/graph?type=indicator&id=${i.IndicatorID}`}><Icon name="graph" />Grafikte aç</Link>
            {canEdit && <button className="btn sm" onClick={() => setEditing(true)}><Icon name="edit" />Düzenle</button>}
            {canEdit && <button className="btn sm danger" onClick={() => confirmDelete("Gösterge", () => api(`/indicators/${id}`, { method: "DELETE" }), () => navigate("/indicators"))}><Icon name="trash" />Sil</button>}
          </div>
        </div>
        <div className={`score ${band}`} title="güven x 0,45 + önem x 0,35 + görülme (en çok 20); kaynak güvenilirliği ve tazelikle çarpılır">
          <b className="num">{i.RiskScore}</b><span>{riskLabel(i.RiskScore)} risk</span>
        </div>
      </div>

      <Panel title="Bunun arkasında kim var?" note="Gösterge, bağlı olduğu zararlı yazılım veya kampanya üzerinden aktöre atfedilir"
        action={<span className="actions"><LinkAdder kind="malware-indicator" selfId={i.IndicatorID} selfFirst={false} type="malware" withRole onDone={reload} /></span>}>
        {chains.size === 0 ? (
          <p className="muted">Bu gösterge henüz bir zararlı yazılıma veya kampanyaya bağlanmadı; kime ait olduğu bilinmiyor.{canEdit && " Sağ üstteki Bağla ile bir zararlı yazılım seçin."}</p>
        ) : (
          <div className="chain">{[...chains.values()].map((c) => (
            <div className="line" key={`${c.type}${c.id}`}>
              <span className="node indicator"><small>Gösterge</small><span className="mono">{i.Value.length > 30 ? i.Value.slice(0, 28) + "…" : i.Value}</span></span>
              <span className="link">{c.type === "malware" ? ROLE_LABEL[c.role ?? "other"] : "gözlendi"}</span>
              <Link className={`node ${c.type}`} to={`/${c.type === "malware" ? "malware" : "campaigns"}/${c.id}`}><small>{c.type === "malware" ? "Zararlı yazılım" : "Kampanya"}</small>{c.name}</Link>
              <span className="link">{c.type === "malware" ? "kullanan" : "atfedilen"}</span>
              {c.actors.length === 0 ? <span className="node unknown"><small>Aktör</small>Bilinmiyor</span> : (
                <span style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{c.actors.slice(0, 5).map((a) => <Link key={a.id} className="node actor" to={`/actors/${a.id}`}><small>Aktör</small>{a.name}</Link>)}
                  {c.actors.length > 5 && <span className="node unknown"><small>ve</small>{c.actors.length - 5} aktör daha</span>}</span>)}
              {c.type === "malware" && <Unlink kind="malware-indicator" a={c.id} b={i.IndicatorID} onDone={reload} />}
            </div>))}</div>
        )}
      </Panel>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <div className="stack">
          <Panel title="Özellikler">
            <dl className="props">
              <dt>Risk skoru</dt><dd><Risk score={i.RiskScore} /></dd>
              <dt>Güven</dt><dd className="num">{i.Confidence} / 100</dd>
              <dt>Kaynak</dt><dd>{i.SourceName} <span className="badge" title={RELIABILITY[i.Reliability]}>{i.Reliability}: {RELIABILITY[i.Reliability]}</span></dd>
              <dt>İlk görülme</dt><dd>{fmtDateTime(i.FirstSeen)}</dd>
              <dt>Son görülme</dt><dd>{fmtDateTime(i.LastSeen)} <span className="faint">({ago(i.LastSeen)})</span></dd>
              <dt>Geçerlilik sonu</dt><dd>{i.ExpiresAt ? fmtDateTime(i.ExpiresAt) : <span className="faint">Süresiz</span>}</dd>
              <dt>Kurumda görülme</dt><dd className="num">{i.SightingCount}</dd>
              {i.Description && <><dt>Açıklama</dt><dd>{i.Description}</dd></>}
            </dl>
          </Panel>
          <Panel title="Kurum içi görülmeler" note="Bu göstergeye kendi ağınızda rastlandıysa kaydedin; risk skoru yükselir">
            {canEdit && (
              <form onSubmit={addSighting} style={{ display: "grid", gridTemplateColumns: "70px 1fr 1fr auto", gap: 8, marginBottom: 14 }}>
                <input className="input" type="number" min={1} value={sighting.quantity} onChange={(e) => setSighting({ ...sighting, quantity: Number(e.target.value) })} aria-label="Adet" />
                <input className="input" placeholder="Nerede? SIEM, EDR / WS-0142" value={sighting.location} onChange={(e) => setSighting({ ...sighting, location: e.target.value })} aria-label="Konum" />
                <input className="input" placeholder="Not" value={sighting.note} onChange={(e) => setSighting({ ...sighting, note: e.target.value })} aria-label="Not" />
                <button className="btn">Görülme ekle</button>
              </form>)}
            {data.sightings.length === 0 ? <p className="muted">Bu göstergeye kurum içinde henüz rastlanmadı.</p> : (
              <div className="timeline">{data.sightings.map((s: any) => (
                <div key={s.SightingID}><i /><div>
                  <b>{s.Location ?? "Konum belirtilmedi"}</b>{s.Quantity > 1 && <span className="muted">, {s.Quantity} kez</span>}
                  <div className="faint" style={{ fontSize: 12.5 }}>{fmtDateTime(s.SightedAt)}{s.ReportedBy && `, ${s.ReportedBy}`}</div>
                  {s.Note && <div className="muted">{s.Note}</div>}
                </div></div>))}</div>)}
          </Panel>
        </div>
        <div className="stack">
          <Panel title="Çevresi" note="İki adım uzaklığa kadar ilişkiler. Düğüme çift tıklayınca kaydı açılır.">
            <div className="graph-canvas graph-mini">
              {graph.data && graph.data.nodes.length > 1 ? <>
                <GraphView theme={theme} nodes={graph.data.nodes} edges={graph.data.edges}
                  onExpand={(n) => navigate(n.NodeType === "indicator" ? `/indicators/${n.NodeID}` : n.NodeType === "technique" ? `/attack?technique=${n.NodeID}` : `/${n.NodeType === "actor" ? "actors" : n.NodeType === "campaign" ? "campaigns" : n.NodeType === "vulnerability" ? "vulnerabilities" : "malware"}/${n.NodeID}`)} />
                <GraphLegend nodes={graph.data.nodes} /></> : <Empty title="Bağlantı yok">Bu göstergenin başka kayıtlarla ilişkisi bulunmuyor.</Empty>}
            </div>
          </Panel>
          {data.related.length > 0 && (
            <Panel title="Bunu gördüyseniz şunlara da bakın" note="Aynı zararlı yazılıma bağlı diğer aktif göstergeler">
              <div className="list">{data.related.map((r: any) => (
                <div key={r.IndicatorID}>
                  <span className="left"><TypeTag code={r.TypeCode} /><Link className="mono" to={`/indicators/${r.IndicatorID}`}>{r.Value}</Link></span>
                  <span style={{ display: "flex", gap: 10, alignItems: "center" }}><span className="faint" style={{ fontSize: 12 }}>{r.MalwareName}</span><Risk score={r.RiskScore} /></span>
                </div>))}</div>
            </Panel>)}
          <Panel title="Değişiklik geçmişi" note="dbo.AuditLog tablosundan; kayıtları trg_Indicator_Audit tetikleyicisi yazar">
            {data.history.length === 0 ? <p className="muted">Kayıt yok. Toplu içe aktarılan göstergeler için satır bazlı denetim kaydı tutulmaz.</p> : (
              <div className="timeline">{data.history.map((h: any) => (
                <div key={h.AuditID}><i style={{ background: h.Action === "D" ? "var(--risk-crit)" : h.Action === "I" ? "var(--ok)" : "var(--accent)" }} /><div>
                  <b>{ACTION[h.Action]}</b> <span className="muted">{h.ChangedBy ?? "sistem"}, {fmtDateTime(h.ChangedAt)}</span>
                  {h.Action === "U" && <Changes before={h.OldValues} after={h.NewValues} />}
                </div></div>))}</div>)}
          </Panel>
        </div>
      </div>
      {editing && <IndicatorForm initial={i} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); reload(); }} />}
    </>
  );
}
