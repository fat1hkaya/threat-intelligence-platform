import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, qs, useData } from "../api";
import { LinkAdder, Unlink, VulnerabilityForm } from "../components/forms";
import { useDebounced } from "../components/records";
import { Cc, Empty, Icon, Loading, Pager, Panel, useApp, useConfirmDelete } from "../components/ui";
import { fmtDate } from "../lib";

const cvssBand = (s: number | null) => (s == null ? "" : s >= 9 ? "crit" : s >= 7 ? "high" : s >= 4 ? "med" : "low");
const Cvss = ({ score }: { score: number | null }) => score == null ? <span className="faint">-</span> : <span className={`risk ${cvssBand(score)}`}><b>{score.toFixed(1)}</b></span>;

export function Vulnerabilities() {
  const { canEdit } = useApp();
  const navigate = useNavigate();
  const [q, setQ] = useState(""); const [kev, setKev] = useState(false); const [page, setPage] = useState(1); const [form, setForm] = useState(false);
  const dq = useDebounced(q);
  const { data, error } = useData<any>("/vulnerabilities" + qs({ q: dq, kev, page, size: 30 }));
  return (
    <>
      <div className="page-head">
        <div><h1>Zafiyetler</h1><p>Zararlı yazılımların istismar ettiği CVE kayıtları. Tüm CISA KEV kataloğunu yüklemek için: <span className="mono">python scripts/ingest_feeds.py kev</span></p></div>
        {canEdit && <button className="btn primary" onClick={() => setForm(true)}><Icon name="plus" />Zafiyet ekle</button>}
      </div>
      <div className="filters">
        <input className="input grow" placeholder="CVE numarası, başlık, üretici veya ürün" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Zafiyetlerde ara" />
        <button className={`chip${kev ? " on" : ""}`} onClick={() => { setKev(!kev); setPage(1); }}>Sahada istismar edilenler</button>
      </div>
      {!data ? <Loading error={error} /> : (
        <div className="panel">
          {data.items.length === 0 ? <Empty title="Eşleşen zafiyet yok" /> : (
            <div className="table-wrap"><table className="data">
              <thead><tr><th>CVE</th><th>Başlık</th><th>Ürün</th><th className="r">CVSS</th><th className="r">Zararlı</th><th className="r">Yayın</th></tr></thead>
              <tbody>{data.items.map((v: any) => (
                <tr key={v.VulnerabilityID}>
                  <td style={{ whiteSpace: "nowrap" }}><Link className="mono" to={`/vulnerabilities/${v.VulnerabilityID}`}>{v.CveID}</Link>{v.IsKnownExploited && <span className="badge" style={{ marginLeft: 8, color: "var(--risk-high)", borderColor: "var(--risk-high)" }}>istismar ediliyor</span>}</td>
                  <td>{v.Title}</td>
                  <td className="muted">{[v.Vendor, v.Product].filter(Boolean).join(" ") || "-"}</td>
                  <td className="r"><Cvss score={v.CvssScore} /></td>
                  <td className="r num">{v.MalwareCount || <span className="faint">0</span>}</td>
                  <td className="r muted" style={{ whiteSpace: "nowrap" }}>{fmtDate(v.PublishedDate)}</td>
                </tr>))}</tbody>
            </table></div>)}
          <Pager page={data.page} size={data.size} total={data.total} onPage={setPage} />
        </div>)}
      {form && <VulnerabilityForm onClose={() => setForm(false)} onSaved={(id) => navigate(`/vulnerabilities/${id}`)} />}
    </>
  );
}

export function VulnerabilityDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { canEdit, toast } = useApp();
  const confirmDelete = useConfirmDelete(toast);
  const { data, error, reload } = useData<any>(`/vulnerabilities/${id}`);
  const [editing, setEditing] = useState(false);
  if (!data) return <Loading error={error} />;
  const v = data.vulnerability;
  return (
    <>
      <div className="crumb"><Link to="/vulnerabilities">Zafiyetler</Link></div>
      <div className="record-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <h1 className="mono">{v.CveID}</h1>
          <p style={{ fontSize: 16, marginTop: 6 }}>{v.Title}</p>
          <div className="meta">{(v.Vendor || v.Product) && <span>{[v.Vendor, v.Product].filter(Boolean).join(" ")}</span>}<span>Yayın: {fmtDate(v.PublishedDate)}</span>
            {v.IsKnownExploited && <span className="badge" style={{ color: "var(--risk-high)", borderColor: "var(--risk-high)" }}>Sahada istismar ediliyor</span>}</div>
          <div className="actions" style={{ marginTop: 14 }}>
            <a className="btn ghost sm" href={`https://nvd.nist.gov/vuln/detail/${v.CveID}`} target="_blank" rel="noreferrer">NVD kaydını aç</a>
            <Link className="btn ghost sm" to={`/graph?type=vulnerability&id=${v.VulnerabilityID}`}><Icon name="graph" />Grafikte aç</Link>
            {canEdit && <button className="btn sm" onClick={() => setEditing(true)}><Icon name="edit" />Düzenle</button>}
            {canEdit && <button className="btn sm danger" onClick={() => confirmDelete("Zafiyet", () => api(`/vulnerabilities/${id}`, { method: "DELETE" }), () => navigate("/vulnerabilities"))}><Icon name="trash" />Sil</button>}
          </div>
        </div>
        {v.CvssScore != null && <div className={`score ${cvssBand(v.CvssScore)}`}><b className="num">{v.CvssScore.toFixed(1)}</b><span>CVSS</span></div>}
      </div>
      <div className="grid cols-2">
        <Panel title="Bu zafiyeti istismar eden yazılımlar" action={<LinkAdder kind="malware-vulnerability" selfId={v.VulnerabilityID} selfFirst={false} type="malware" onDone={reload} />}>
          {v.Description && <p className="prose" style={{ marginBottom: 14 }}>{v.Description}</p>}
          {data.malware.length === 0 ? <p className="muted">Kayıtlı yazılım yok.</p> : (
            <div className="list">{data.malware.map((m: any) => (
              <div key={m.MalwareID}><span className="left"><i className="dot malware" /><Link to={`/malware/${m.MalwareID}`}>{m.Name}</Link><span className="faint" style={{ fontSize: 12 }}>{m.TypeName}</span></span>
                <Unlink kind="malware-vulnerability" a={m.MalwareID} b={v.VulnerabilityID} onDone={reload} /></div>))}</div>)}
        </Panel>
        <Panel title="Bu yazılımları kullanan aktörler" note="İki ara tablo üzerinden: zafiyet, zararlı, aktör">
          {data.actors.length === 0 ? <p className="muted">Bağlı aktör yok.</p> : (
            <div className="list">{data.actors.map((a: any) => <div key={a.ActorID}><span className="left"><i className="dot actor" /><Link to={`/actors/${a.ActorID}`}>{a.Name}</Link></span><Cc code={a.CountryCode} /></div>)}</div>)}
        </Panel>
      </div>
      {editing && <VulnerabilityForm initial={v} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); reload(); }} />}
    </>
  );
}
