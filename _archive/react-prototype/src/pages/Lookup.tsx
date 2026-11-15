import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Empty, Panel, Risk, TypeTag } from "../components/ui";
import { ago, refang } from "../lib";

export function Lookup() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const values = [...new Set(text.split(/[\s,;]+/).map((v) => refang(v.trim())).filter(Boolean))];

  const run = async () => {
    setBusy(true); setError("");
    try { setResult(await api("/indicators/lookup", { method: "POST", body: { values } })); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <div className="page-head"><div><h1>Toplu sorgu</h1>
        <p>Güvenlik duvarı kaydından, e-postadan ya da bir rapordan kopyaladığınız listeyi yapıştırın. Hangilerinin bilinen bir tehdide bağlı olduğunu tek sorguda görün.</p></div></div>
      <div className="grid cols-12">
        <Panel title="Liste">
          <textarea className="input mono" style={{ minHeight: 280 }} value={text} onChange={(e) => setText(e.target.value)}
            placeholder={"Her satıra bir değer ya da virgülle ayırın:\n198.51.100.23\nupdate-emotet3.example\nhxxp://cdn-qakbot1[.]test/gate.php"} aria-label="Sorgulanacak değerler" />
          <div className="actions" style={{ marginTop: 10, justifyContent: "space-between" }}>
            <span className="muted num">{values.length} benzersiz değer</span>
            <button className="btn primary" disabled={busy || values.length === 0 || values.length > 2000} onClick={run}>{busy ? "Sorgulanıyor..." : "Sorgula"}</button>
          </div>
          {values.length > 2000 && <p className="err">Tek seferde en çok 2000 değer sorgulanabilir.</p>}
          {error && <p className="err" role="alert">{error}</p>}
        </Panel>
        <Panel title={result ? `${result.matches.length} eşleşme, ${result.unknown.length} bilinmeyen` : "Sonuç"} flush={!!result && result.matches.length > 0}>
          {!result ? <Empty title="Henüz sorgu yapılmadı">Sonuçlar risk skoruna göre sıralanır.</Empty> : (
            <>
              {result.matches.length === 0 ? <Empty title="Hiçbiri kayıtlarımızda yok">Bu, değerlerin temiz olduğu anlamına gelmez; yalnızca bilinen bir tehdide bağlı değiller.</Empty> : (
                <div className="table-wrap"><table className="data">
                  <thead><tr><th>Risk</th><th>Gösterge</th><th>Bağlı tehdit</th><th>Kaynak</th><th className="r">Son görülme</th></tr></thead>
                  <tbody>{result.matches.map((m: any) => (
                    <tr key={m.IndicatorID} className={m.IsActive ? "" : "dim"}>
                      <td><Risk score={m.RiskScore} /></td>
                      <td><span style={{ display: "flex", gap: 8, alignItems: "center" }}><TypeTag code={m.TypeCode} /><Link className="value mono" to={`/indicators/${m.IndicatorID}`}>{m.Value}</Link></span></td>
                      <td>{m.ViaName ?? <span className="faint">-</span>}{m.ActorName && <span className="muted"> / {m.ActorName}</span>}</td>
                      <td className="muted">{m.SourceName}</td>
                      <td className="r muted">{ago(m.LastSeen)}</td>
                    </tr>))}</tbody>
                </table></div>)}
              {result.unknown.length > 0 && (
                <div style={{ padding: "14px 12px 8px" }}>
                  <h3 style={{ marginBottom: 6 }}>Kayıtlarımızda olmayanlar</h3>
                  <div className="mono muted break" style={{ fontSize: 12.5, maxHeight: 160, overflowY: "auto" }}>{result.unknown.join("\n").split("\n").map((u: string) => <div key={u}>{u}</div>)}</div>
                </div>)}
            </>)}
        </Panel>
      </div>
    </>
  );
}
