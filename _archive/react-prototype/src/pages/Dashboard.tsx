import { Link } from "react-router-dom";
import { useData } from "../api";
import { BarList, SeverityBar, TrendChart } from "../components/charts";
import { Empty, Icon, Loading, Panel, Risk, TypeTag } from "../components/ui";
import { ago, fmtNum, RELIABILITY } from "../lib";

export function Dashboard({ openSearch }: { openSearch: () => void }) {
  const { data, error } = useData<any>("/dashboard");
  if (!data) return <Loading error={error} />;
  const c = data.counts;
  const delta = c.NewPrev7d ? Math.round(((c.New7d - c.NewPrev7d) / c.NewPrev7d) * 100) : null;
  return (
    <>
      <button className="ask" onClick={openSearch}>
        <Icon name="search" /><span>Şüpheli bir IP, alan adı ya da dosya özeti mi var? Buraya yapıştırın.</span><kbd>/</kbd>
      </button>

      <div className="week">
        <div><b className="num">{fmtNum(c.New7d)}{delta !== null && <span className={`delta ${delta >= 0 ? "up" : "down"}`}>{delta >= 0 ? "+" : ""}{delta}%</span>}</b><span>son 7 günde ilk kez görülen gösterge</span></div>
        <div><b className="num">{fmtNum(c.Sightings7d)}</b><span>son 7 günde kurum içinde görülme</span></div>
        <div><b className="num">{fmtNum(c.ActiveIndicators)}<span className="faint" style={{ fontSize: 14, fontWeight: 400 }}> / {fmtNum(c.Indicators)}</span></b><span>aktif gösterge</span></div>
        <div><b className="num">{fmtNum(c.Actors)}</b><span>izlenen aktör, {fmtNum(c.Malware)} zararlı, {fmtNum(c.Techniques)} teknik</span></div>
      </div>

      <div className="grid cols-21">
        <Panel title="Son 30 gün" note={<><span style={{ color: "var(--c-indicator)" }}>Çizgi</span>: ilk kez görülen gösterge (sol eksen). <span style={{ color: "var(--accent)" }}>Çubuk</span>: kurum içi görülme (sağ eksen).</>}>
          <TrendChart data={data.trend} />
        </Panel>
        <Panel title="Aktif göstergeler">
          <SeverityBar rows={data.bySeverity} />
          <div style={{ height: 18 }} />
          <BarList rows={data.byType.map((t: any) => ({ key: t.Code, label: <Link to={`/indicators?type=${t.Code}`} style={{ color: "var(--text)" }}>{t.Name}</Link>, value: t.Total }))} />
        </Panel>
      </div>

      <div className="grid cols-21" style={{ marginTop: 16 }}>
        <Panel title="Önce bunlara bakın" note="Ağınızda görülmüş, hâlâ aktif ve en yüksek riskli göstergeler" flush
          action={<Link className="btn ghost sm" to="/indicators?sighted=1&sort=risk">Tümü</Link>}>
          {data.topRisk.length === 0 ? <Empty title="Kurum içinde görülen gösterge yok">Bir göstergenin sayfasından görülme kaydı ekleyebilirsiniz.</Empty> : (
            <div className="table-wrap"><table className="data">
              <thead><tr><th>Risk</th><th>Gösterge</th><th>Bağlı olduğu tehdit</th><th className="r">Görülme</th><th className="r">Son</th></tr></thead>
              <tbody>{data.topRisk.map((r: any) => (
                <tr key={r.IndicatorID}>
                  <td><Risk score={r.RiskScore} /></td>
                  <td><Link to={`/indicators/${r.IndicatorID}`} className="value mono">{r.Value}</Link></td>
                  <td>{r.ViaName ?? <span className="faint">bağlantı yok</span>}{r.ActorName && <span className="muted"> / {r.ActorName}</span>}</td>
                  <td className="r num">{fmtNum(r.SightingCount)}</td>
                  <td className="r muted" style={{ whiteSpace: "nowrap" }}>{ago(r.LastSeen)}</td>
                </tr>))}</tbody>
            </table></div>)}
        </Panel>
        <div className="stack">
          <Panel title="Göstergelerin arkasındaki aktörler" note="Atıf zinciri: gösterge, zararlı veya kampanya, aktör">
            {data.topActors.length === 0 ? <p className="muted">Henüz aktöre bağlanan gösterge yok.</p> :
              <BarList color="var(--c-actor)" rows={data.topActors.map((a: any) => ({ key: a.ActorID, value: a.IndicatorCount,
                label: <Link to={`/actors/${a.ActorID}`} style={{ color: "var(--text)" }}>{a.ActorName}</Link>,
                note: <>{fmtNum(a.IndicatorCount)} gösterge{a.SightedCount > 0 && <span style={{ color: "var(--accent)" }}>, {a.SightedCount} görüldü</span>}</> }))} />}
          </Panel>
        </div>
      </div>

      <div className="grid cols-3" style={{ marginTop: 16 }}>
        <Panel title="Son görülmeler">
          {data.recentSightings.length === 0 ? <p className="muted">Kayıt yok.</p> : (
            <div className="feed">{data.recentSightings.map((s: any) => (
              <Link key={s.SightingID} to={`/indicators/${s.IndicatorID}`}>
                <TypeTag code={s.TypeCode} />
                <span style={{ minWidth: 0 }}><span className="value mono" style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.Value}</span>
                  <span className="faint" style={{ fontSize: 12 }}>{s.Location ?? "Konum belirtilmedi"}{s.Quantity > 1 && `, ${s.Quantity} kez`}</span></span>
                <span className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>{ago(s.SightedAt)}</span>
              </Link>))}</div>)}
        </Panel>
        <Panel title="En çok göstergesi olan zararlılar">
          <BarList color="var(--c-malware)" rows={data.topMalware.map((m: any) => ({ key: m.MalwareID, value: m.IndicatorCount,
            label: <><Link to={`/malware/${m.MalwareID}`} style={{ color: "var(--text)" }}>{m.Name}</Link> <span className="faint" style={{ fontSize: 12 }}>{m.TypeName}</span></> }))} />
        </Panel>
        <Panel title="Kaynaklar" action={<Link className="btn ghost sm" to="/sources">Ayrıntı</Link>}>
          <div className="list">{data.sources.map((s: any) => (
            <div key={s.SourceID}>
              <span className="left"><i className={`dot ${s.LastRunStatus === "failed" ? "bad" : s.LastRunStatus === "running" ? "run" : "ok"}`} title={s.LastRunStatus ?? ""} />
                <span>{s.Name}</span><span className="badge" title={RELIABILITY[s.Reliability]}>{s.Reliability}</span></span>
              <span className="num muted">{fmtNum(s.IndicatorCount)}</span>
            </div>))}</div>
        </Panel>
      </div>
    </>
  );
}
