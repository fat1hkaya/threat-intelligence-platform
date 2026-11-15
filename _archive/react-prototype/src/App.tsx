import { useCallback, useEffect, useState } from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { api, clearTraces, Meta, setUnauthorizedHandler, User } from "./api";
import { Omnibox } from "./components/Omnibox";
import { SqlDrawer } from "./components/SqlDrawer";
import { AppContext, Icon, Lighthouse } from "./components/ui";
import { ActorDetail, Actors } from "./pages/Actors";
import { Attack } from "./pages/Attack";
import { CampaignDetail, Campaigns } from "./pages/Campaigns";
import { Dashboard } from "./pages/Dashboard";
import { GraphPage } from "./pages/Graph";
import { IndicatorDetail } from "./pages/IndicatorDetail";
import { Indicators } from "./pages/Indicators";
import { Login } from "./pages/Login";
import { Lookup } from "./pages/Lookup";
import { MalwareDetail, MalwareList } from "./pages/Malware";
import { Audit, Schema, Sources } from "./pages/System";
import { Vulnerabilities, VulnerabilityDetail } from "./pages/Vulnerabilities";

const NAV: { group: string; items: { to: string; icon: string; label: string }[] }[] = [
  { group: "İzleme", items: [
    { to: "/", icon: "home", label: "Genel bakış" },
    { to: "/indicators", icon: "ioc", label: "Göstergeler" },
    { to: "/lookup", icon: "list", label: "Toplu sorgu" },
  ] },
  { group: "Bilgi tabanı", items: [
    { to: "/actors", icon: "actor", label: "Aktörler" },
    { to: "/malware", icon: "bug", label: "Zararlı yazılımlar" },
    { to: "/campaigns", icon: "flag", label: "Kampanyalar" },
    { to: "/vulnerabilities", icon: "vuln", label: "Zafiyetler" },
    { to: "/attack", icon: "grid", label: "ATT&CK matrisi" },
  ] },
  { group: "Keşif", items: [{ to: "/graph", icon: "graph", label: "İlişki grafı" }] },
  { group: "Sistem", items: [
    { to: "/sources", icon: "feed", label: "Kaynaklar" },
    { to: "/audit", icon: "log", label: "Denetim kaydı" },
    { to: "/schema", icon: "db", label: "Veritabanı" },
  ] },
];

type Toast = { id: number; msg: string; kind: "ok" | "error" };

export default function App() {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [omni, setOmni] = useState(false);
  const [sql, setSql] = useState(false);
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem("gozcu-theme") ?? "dark"; } catch { return "dark"; } });
  const [toasts, setToasts] = useState<Toast[]>([]);
  const location = useLocation();

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("gozcu-theme", theme); } catch { /* özel pencere */ }
  }, [theme]);

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    api<User>("/auth/me").then(setUser).catch(() => setUser(null));
  }, []);

  const reloadMeta = useCallback(() => { api<Meta>("/meta").then(setMeta).catch(() => {}); }, []);
  useEffect(() => { if (user) reloadMeta(); }, [user, reloadMeta]);

  // Sayfa değişince SQL çekmecesi yalnızca yeni sayfanın sorgularını göstersin
  useEffect(() => { clearTraces(); }, [location.pathname]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setOmni(true); }
      const tag = (e.target as HTMLElement)?.tagName;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(tag)) { e.preventDefault(); setOmni(true); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const toast = useCallback((msg: string, kind: "ok" | "error" = "ok") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 6000 : 3200);
  }, []);

  if (user === undefined) return null;
  if (!user) return <Login onLogin={setUser} />;
  if (!meta) return null;

  const logout = async () => { await api("/auth/logout", { method: "POST" }).catch(() => {}); setUser(null); setMeta(null); };

  return (
    <AppContext.Provider value={{ user, meta, canEdit: user.Role !== "viewer", toast, reloadMeta }}>
      <div className="shell">
        <nav className="sidebar" aria-label="Ana menü">
          <Link to="/" className="brand"><Lighthouse /><span><b>Gözcü</b><small>tehdit istihbaratı</small></span></Link>
          {NAV.map((g) => (
            <div className="nav-group" key={g.group}>
              <span>{g.group}</span>
              {g.items.map((i) => (
                <NavLink key={i.to} to={i.to} end={i.to === "/"} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`} title={i.label}>
                  <Icon name={i.icon} /><span>{i.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
          <div className="sidebar-foot">
            <div className="who">
              <span><b>{user.FullName}</b><br /><span className="faint">{user.RoleName}</span></span>
              <button className="btn ghost sm" onClick={logout}>Çıkış</button>
            </div>
          </div>
        </nav>
        <div className="main">
          <div className="topbar">
            <button className="omni-trigger" onClick={() => setOmni(true)}>
              <Icon name="search" /><span>Gösterge, aktör, zararlı, teknik veya CVE ara</span><kbd>Ctrl K</kbd>
            </button>
            <span className="spacer" />
            <button className={`btn sm${sql ? " on" : ""}`} onClick={() => setSql((s) => !s)} title="Bu sayfanın çalıştırdığı SQL sorgularını göster">
              <Icon name="sql" />SQL
            </button>
            <button className="btn ghost sm" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} title="Görünümü değiştir" aria-label="Görünümü değiştir">
              <Icon name={theme === "dark" ? "sun" : "moon"} />
            </button>
          </div>
          <main className="page">
            <Routes>
              <Route path="/" element={<Dashboard openSearch={() => setOmni(true)} />} />
              <Route path="/indicators" element={<Indicators />} />
              <Route path="/indicators/:id" element={<IndicatorDetail theme={theme} />} />
              <Route path="/lookup" element={<Lookup />} />
              <Route path="/actors" element={<Actors />} />
              <Route path="/actors/:id" element={<ActorDetail />} />
              <Route path="/malware" element={<MalwareList />} />
              <Route path="/malware/:id" element={<MalwareDetail />} />
              <Route path="/campaigns" element={<Campaigns />} />
              <Route path="/campaigns/:id" element={<CampaignDetail />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
              <Route path="/vulnerabilities/:id" element={<VulnerabilityDetail />} />
              <Route path="/attack" element={<Attack />} />
              <Route path="/graph" element={<GraphPage theme={theme} />} />
              <Route path="/sources" element={<Sources />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/schema" element={<Schema />} />
              <Route path="*" element={<div className="panel"><div className="empty-state"><b>Sayfa bulunamadı</b><Link to="/">Genel bakışa dön</Link></div></div>} />
            </Routes>
          </main>
        </div>
      </div>
      {omni && <Omnibox onClose={() => setOmni(false)} />}
      {sql && <SqlDrawer onClose={() => setSql(false)} />}
      <div className="toasts" aria-live="polite">{toasts.map((t) => <div key={t.id} className={`toast ${t.kind}`}>{t.msg}</div>)}</div>
    </AppContext.Provider>
  );
}
