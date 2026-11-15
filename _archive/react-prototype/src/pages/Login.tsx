import { useState } from "react";
import { api, User } from "../api";
import { Field, Lighthouse } from "../components/ui";

export function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setError("");
    try { onLogin(await api<User>("/auth/login", { method: "POST", body: { username, password } })); }
    catch (err: any) { setError(err.message); }
    finally { setBusy(false); }
  };
  return (
    <div className="login">
      <div className="scene">
        <div className="beam" /><div className="lamp" />
        <h1>Karanlıkta kimin dolaştığını görün.</h1>
        <p>Gözcü; göstergeleri, zararlı yazılımları, kampanyaları ve aktörleri tek bir ilişkisel veritabanında birbirine bağlar. Bir IP yapıştırın, arkasındaki zinciri izleyin.</p>
      </div>
      <form className="form" onSubmit={submit}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}><Lighthouse size={34} /><h2>Gözcü'ye giriş yapın</h2></div>
        <Field label="Kullanıcı adı"><input className="input" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></Field>
        <Field label="Parola"><input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        {error && <p className="err" role="alert">{error}</p>}
        <button className="btn primary" disabled={busy || !username || !password} style={{ justifyContent: "center", padding: "10px 14px" }}>{busy ? "Giriş yapılıyor..." : "Giriş yap"}</button>
        <p className="faint" style={{ fontSize: 12.5 }}>Hesabınız yoksa platform yöneticinizden isteyin.</p>
      </form>
    </div>
  );
}
