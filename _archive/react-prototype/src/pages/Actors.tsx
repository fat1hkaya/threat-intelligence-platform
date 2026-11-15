import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, qs, useData } from "../api";
import { ActorForm, LinkAdder, Unlink } from "../components/forms";
import { IndicatorRows, Stat, TechniqueGrid, useDebounced } from "../components/records";
import { Cc, Empty, Icon, Loading, Pager, Panel, useApp, useConfirmDelete } from "../components/ui";
import { fmtDate } from "../lib";

export function Actors() {
  const { meta, canEdit } = useApp();
  const navigate = useNavigate();
  const [q, setQ] = useState(""); const [country, setCountry] = useState(""); const [motivation, setMotivation] = useState("");
  const [sort, setSort] = useState("techniques"); const [page, setPage] = useState(1); const [form, setForm] = useState(false);
  const dq = useDebounced(q);
  const { data, error } = useData<any>("/actors" + qs({ q: dq, country, motivation, sort, page, size: 24 }));
  return (
    <>
      <div className="page-head">
        <div><h1>Tehdit aktörleri</h1><p>Saldırıların arkasındaki gruplar. Köken ülke ve motivasyon, MITRE ATT&CK açıklamalarından çıkarılmıştır; emin olunamayanlar boş bırakıldı.</p></div>
        {canEdit && <button className="btn primary" onClick={() => setForm(true)}><Icon name="plus" />Aktör ekle</button>}
      </div>
      <div className="filters">
        <input className="input grow" placeholder="Ad, takma ad veya G0007" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} aria-label="Aktörlerde ara" />
        <select className="input" value={country} onChange={(e) => { setCountry(e.target.value); setPage(1); }} aria-label="Köken ülke"><option value="">Her köken</option>{meta.countries.map((c) => <option key={c.CountryCode} value={c.CountryCode}>{c.Name}</option>)}</select>
        <select className="input" value={motivation} onChange={(e) => { setMotivation(e.target.value); setPage(1); }} aria-label="Motivasyon"><option value="">Her motivasyon</option>{meta.motivations.map((m) => <option key={m.MotivationID} value={m.Name}>{m.Name}</option>)}</select>
        <select className="input" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sıralama"><option value="techniques">En çok teknik</option><option value="malware">En çok zararlı</option><option value="campaigns">En çok kampanya</option><option value="name">Ada göre</option></select>
      </div>
      {!data ? <Loading error={error} /> : data.items.length === 0 ? <div className="panel"><Empty title="Eşleşen aktör yok">Aramayı ya da filtreleri değiştirin.</Empty></div> : (
        <>
          <div className="cards">{data.items.map((a: any) => (
            <Link className="card" key={a.ActorID} to={`/actors/${a.ActorID}`}>
              <h2><i className="dot actor" />{a.Name}<span style={{ flex: 1 }} /><Cc code={a.CountryCode} /></h2>
              {a.Aliases && <div className="faint" style={{ fontSize: 12.5, marginTop: -6 }}>{a.Aliases}</div>}
              <p className="sum">{a.Summary}</p>
              <div className="foot">
                <span><b className="num">{a.TechniqueCount}</b> teknik</span><span><b className="num">{a.MalwareCount}</b> zararlı</span><span><b className="num">{a.CampaignCount}</b> kampanya</span>
                <span style={{ marginLeft: "auto" }}>{a.Motivation ?? ""}</span>
              </div>
            </Link>))}</div>
          <div className="panel" style={{ marginTop: 14 }}><Pager page={data.page} size={data.size} total={data.total} onPage={setPage} /></div>
        </>)}
      {form && <ActorForm onClose={() => setForm(false)} onSaved={(id) => navigate(`/actors/${id}`)} />}
    </>
  );
}

export function ActorDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { canEdit, toast } = useApp();
  const confirmDelete = useConfirmDelete(toast);
  const { data, error, reload } = useData<any>(`/actors/${id}`);
  const [editing, setEditing] = useState(false);
  if (!data) return <Loading error={error} />;
  const a = data.actor;
  return (
    <>
      <div className="crumb"><Link to="/actors">Aktörler</Link>{a.ExternalID && ` / ${a.ExternalID}`}</div>
      <div className="record-head">
        <div style={{ minWidth: 0, flex: 1 }}>
          <h1 style={{ display: "flex", alignItems: "center", gap: 10 }}><i className="dot actor" style={{ width: 12, height: 12 }} />{a.Name}</h1>
          <div className="meta">
            {a.CountryName && <span><Cc code={a.CountryCode} /> {a.CountryName} kökenli</span>}
            {a.Motivation && <span className="badge">{a.Motivation}</span>}
            {!a.IsActive && <span className="badge">Etkin değil</span>}
          </div>
          {data.aliases.length > 0 && <div className="chips" style={{ marginTop: 12 }}><span className="faint" style={{ fontSize: 12.5, alignSelf: "center" }}>Diğer adları</span>{data.aliases.map((x: string) => <span key={x} className="chip static">{x}</span>)}</div>}
        </div>
        <div className="actions">
          <Link className="btn sm" to={`/attack?actor=${a.ActorID}`}><Icon name="grid" />Matriste göster</Link>
          <Link className="btn sm" to={`/graph?type=actor&id=${a.ActorID}`}><Icon name="graph" />Grafikte aç</Link>
          {canEdit && <button className="btn sm" onClick={() => setEditing(true)}><Icon name="edit" />Düzenle</button>}
          {canEdit && <button className="btn sm danger" onClick={() => confirmDelete("Aktör", () => api(`/actors/${id}`, { method: "DELETE" }), () => navigate("/actors"))}><Icon name="trash" />Sil</button>}
        </div>
      </div>
      <div className="stat-row">
        <Stat value={a.TechniqueCount} label="teknik" /><Stat value={a.MalwareCount} label="zararlı yazılım ve araç" />
        <Stat value={a.CampaignCount} label="kampanya" /><Stat value={data.indicators.length >= 12 ? "12+" : data.indicators.length} label="bağlı gösterge" />
      </div>
      <div className="grid cols-21">
        <div className="stack">
          <Panel title="Profil">
            <p className="prose">{a.Description ?? <span className="muted">Açıklama girilmemiş.</span>}</p>
            {(data.sectors.length > 0 || data.targetCountries.length > 0) && <dl className="props" style={{ marginTop: 16 }}>
              {data.sectors.length > 0 && <><dt>Hedef sektörler</dt><dd><div className="chips">{data.sectors.map((s: any) => <span key={s.SectorID} className="chip static">{s.Name}</span>)}</div></dd></>}
              {data.targetCountries.length > 0 && <><dt>Hedef ülkeler</dt><dd><div className="chips">{data.targetCountries.map((c: any) => <span key={c.CountryCode} className="chip static">{c.Name}</span>)}</div></dd></>}
            </dl>}
          </Panel>
          <Panel title="Kullandığı teknikler" note="MITRE ATT&CK taktiklerine göre; dbo.fn_ActorTechniques fonksiyonundan"
            action={<LinkAdder kind="actor-technique" selfId={a.ActorID} selfFirst type="technique" onDone={reload} />}>
            <TechniqueGrid rows={data.techniques} />
          </Panel>
        </div>
        <div className="stack">
          <Panel title="Zararlı yazılımlar ve araçlar" action={<LinkAdder kind="actor-malware" selfId={a.ActorID} selfFirst type="malware" onDone={reload} />}>
            {data.malware.length === 0 ? <p className="muted">Kayıt yok.</p> : (
              <div className="list" style={{ maxHeight: 330, overflowY: "auto" }}>{data.malware.map((m: any) => (
                <div key={m.MalwareID}>
                  <span className="left"><i className="dot malware" /><Link to={`/malware/${m.MalwareID}`}>{m.Name}</Link><span className="faint" style={{ fontSize: 12 }}>{m.TypeName}</span></span>
                  <span style={{ display: "flex", gap: 6, alignItems: "center" }}>{m.IndicatorCount > 0 && <span className="num muted">{m.IndicatorCount} gösterge</span>}<Unlink kind="actor-malware" a={a.ActorID} b={m.MalwareID} onDone={reload} /></span>
                </div>))}</div>)}
          </Panel>
          {data.campaigns.length > 0 && <Panel title="Kampanyalar">
            <div className="timeline">{data.campaigns.map((c: any) => (
              <div key={c.CampaignID}><i style={{ background: "var(--c-campaign)" }} /><div>
                <Link to={`/campaigns/${c.CampaignID}`}>{c.Name}</Link>
                <div className="faint" style={{ fontSize: 12.5 }}>{fmtDate(c.StartDate)} - {c.EndDate ? fmtDate(c.EndDate) : "sürüyor"}</div>
              </div></div>))}</div>
          </Panel>}
          <Panel title="Bağlı göstergeler" note="Zararlı yazılım veya kampanya üzerinden atfedilen en riskli göstergeler"><IndicatorRows rows={data.indicators} /></Panel>
          {data.similar.length > 0 && <Panel title="Benzer çalışan aktörler" note="Ortak teknik sayısının birleşime oranı (Jaccard)">
            <div className="list">{data.similar.map((s: any) => (
              <div key={s.ActorID}><span className="left"><i className="dot actor" /><Link to={`/actors/${s.ActorID}`}>{s.Name}</Link><Cc code={s.CountryCode} /></span>
                <span className="muted num">%{s.Similarity}, {s.Shared} ortak</span></div>))}</div>
          </Panel>}
        </div>
      </div>
      {editing && <ActorForm initial={data} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); reload(); }} />}
    </>
  );
}
