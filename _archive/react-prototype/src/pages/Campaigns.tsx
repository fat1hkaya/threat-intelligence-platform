import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, qs, useData } from "../api";
import { CampaignForm, LinkAdder, Unlink } from "../components/forms";
import { IndicatorRows, Stat, TechniqueGrid, useDebounced } from "../components/records";
import { Empty, Icon, Loading, Pager, Panel, useApp, useConfirmDelete } from "../components/ui";
import { fmtDate } from "../lib";

const span = (c: any) => `${fmtDate(c.StartDate)} - ${c.EndDate ? fmtDate(c.EndDate) : "sürüyor"}`;

export function Campaigns() {
  const { canEdit } = useApp();
  const navigate = useNavigate();
  const [q, setQ] = useState(""); const [ongoing, setOngoing] = useState(false); const [page, setPage] = useState(1); const [form, setForm] = useState(false);
  const dq = useDebounced(q);
  const { data, error } = useData<any>("/campaigns" + qs({ q: dq, ongoing, page, size: 30 }));
  return (
    <>
      <div className="page-head">
        <div><h1>Kampanyalar</h1><p>Belirli bir zaman aralığında, belirli hedeflere yönelik yürütülen saldırı dalgaları.</p></div>
        {canEdit && <button className="btn primary" onClick={() => setForm(true)}><Icon name="plus" />Kampanya ekle</button>}
      </div>
      <div className="filters">
        <input className="input grow" placeholder="Kampanya ya da aktör adı" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Kampanyalarda ara" />
        <button className={`chip${ongoing ? " on" : ""}`} onClick={() => { setOngoing(!ongoing); setPage(1); }}>Bitiş tarihi olmayanlar</button>
      </div>
      {!data ? <Loading error={error} /> : (
        <div className="panel">
          {data.items.length === 0 ? <Empty title="Eşleşen kampanya yok" /> : (
            <div className="table-wrap"><table className="data">
              <thead><tr><th>Kampanya</th><th>Atfedilen aktör</th><th>Dönem</th><th className="r">Zararlı</th><th className="r">Teknik</th><th className="r">Gösterge</th></tr></thead>
              <tbody>{data.items.map((c: any) => (
                <tr key={c.CampaignID}>
                  <td><span style={{ display: "flex", gap: 8, alignItems: "center" }}><i className="dot campaign" /><Link to={`/campaigns/${c.CampaignID}`} style={{ fontWeight: 500 }}>{c.Name}</Link></span></td>
                  <td>{c.ActorID ? <Link to={`/actors/${c.ActorID}`}>{c.ActorName}</Link> : <span className="faint">Atfedilmedi</span>}</td>
                  <td className="muted" style={{ whiteSpace: "nowrap" }}>{span(c)}</td>
                  <td className="r num">{c.MalwareCount}</td><td className="r num">{c.TechniqueCount}</td><td className="r num">{c.IndicatorCount}</td>
                </tr>))}</tbody>
            </table></div>)}
          <Pager page={data.page} size={data.size} total={data.total} onPage={setPage} />
        </div>)}
      {form && <CampaignForm onClose={() => setForm(false)} onSaved={(id) => navigate(`/campaigns/${id}`)} />}
    </>
  );
}

export function CampaignDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { canEdit, toast } = useApp();
  const confirmDelete = useConfirmDelete(toast);
  const { data, error, reload } = useData<any>(`/campaigns/${id}`);
  const [editing, setEditing] = useState(false);
  if (!data) return <Loading error={error} />;
  const c = data.campaign;
  return (
    <>
      <div className="crumb"><Link to="/campaigns">Kampanyalar</Link>{c.ExternalID && ` / ${c.ExternalID}`}</div>
      <div className="record-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}><i className="dot campaign" style={{ width: 12, height: 12 }} />{c.Name}</h1>
          <div className="meta"><span>{span(c)}</span>
            {c.ActorID ? <span>Atfedilen aktör: <Link to={`/actors/${c.ActorID}`}>{c.ActorName}</Link></span> : <span className="faint">Bir aktöre atfedilmedi</span>}</div>
        </div>
        <div className="actions">
          <Link className="btn sm" to={`/attack?campaign=${c.CampaignID}`}><Icon name="grid" />Matriste göster</Link>
          <Link className="btn sm" to={`/graph?type=campaign&id=${c.CampaignID}`}><Icon name="graph" />Grafikte aç</Link>
          {canEdit && <button className="btn sm" onClick={() => setEditing(true)}><Icon name="edit" />Düzenle</button>}
          {canEdit && <button className="btn sm danger" onClick={() => confirmDelete("Kampanya", () => api(`/campaigns/${id}`, { method: "DELETE" }), () => navigate("/campaigns"))}><Icon name="trash" />Sil</button>}
        </div>
      </div>
      <div className="stat-row"><Stat value={c.MalwareCount} label="zararlı yazılım ve araç" /><Stat value={c.TechniqueCount} label="teknik" /><Stat value={c.IndicatorCount} label="gösterge" /></div>
      <div className="grid cols-21">
        <div className="stack">
          <Panel title="Özet"><p className="prose">{c.Description ?? <span className="muted">Açıklama girilmemiş.</span>}</p></Panel>
          <Panel title="Kullanılan teknikler" action={<LinkAdder kind="campaign-technique" selfId={c.CampaignID} selfFirst type="technique" onDone={reload} />}><TechniqueGrid rows={data.techniques} /></Panel>
        </div>
        <div className="stack">
          <Panel title="Zararlı yazılımlar ve araçlar" action={<LinkAdder kind="campaign-malware" selfId={c.CampaignID} selfFirst type="malware" onDone={reload} />}>
            {data.malware.length === 0 ? <p className="muted">Kayıt yok.</p> : (
              <div className="list">{data.malware.map((m: any) => (
                <div key={m.MalwareID}><span className="left"><i className="dot malware" /><Link to={`/malware/${m.MalwareID}`}>{m.Name}</Link><span className="faint" style={{ fontSize: 12 }}>{m.TypeName}</span></span>
                  <Unlink kind="campaign-malware" a={c.CampaignID} b={m.MalwareID} onDone={reload} /></div>))}</div>)}
          </Panel>
          <Panel title="Gözlenen göstergeler" action={<LinkAdder kind="campaign-indicator" selfId={c.CampaignID} selfFirst type="indicator" onDone={reload} />}>
            <IndicatorRows rows={data.indicators} extra={(r) => <Unlink kind="campaign-indicator" a={c.CampaignID} b={r.IndicatorID} onDone={reload} />} />
          </Panel>
        </div>
      </div>
      {editing && <CampaignForm initial={data} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); reload(); }} />}
    </>
  );
}
