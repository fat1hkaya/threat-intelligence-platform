import { ReactNode, useEffect, useState } from "react";
import { api } from "../api";
import { ENTITY, EntityType, guessType, refang } from "../lib";
import { Field, Modal, TokenInput, useApp } from "./ui";

/** Kaydet düğmesi, hata satırı ve gönderim durumu olan ortak form penceresi */
export function FormModal({ title, onClose, onSubmit, children, submitLabel = "Kaydet" }: {
  title: string; onClose: () => void; onSubmit: () => Promise<void>; children: ReactNode; submitLabel?: string;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true); setError("");
    try { await onSubmit(); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal title={title} onClose={onClose} footer={<>
      {error && <span className="err" role="alert">{error}</span>}
      <button className="btn" onClick={onClose}>Vazgeç</button>
      <button className="btn primary" disabled={busy} onClick={submit}>{busy ? "Kaydediliyor..." : submitLabel}</button>
    </>}>
      <form className="form-grid" onSubmit={(e) => { e.preventDefault(); submit(); }}>{children}<button type="submit" hidden /></form>
    </Modal>
  );
}

export function IndicatorForm({ initial, onClose, onSaved }: { initial?: any; onClose: () => void; onSaved: (id: number) => void }) {
  const { meta, toast, reloadMeta } = useApp();
  const analystSource = meta.sources.find((s) => s.Name === "Analist girişi")?.SourceID ?? meta.sources[0]?.SourceID;
  const [f, setF] = useState({
    type: initial?.TypeCode ?? guessType(initial?.Value ?? "") ?? "ipv4",
    value: initial?.Value ?? "",
    confidence: initial?.Confidence ?? 70,
    severity: initial?.SeverityCode ?? "medium",
    tlp: initial?.TLPCode ?? "TLP:AMBER",
    sourceId: initial?.SourceID ?? analystSource,
    description: initial?.Description ?? "",
    expiresAt: initial?.ExpiresAt ? String(initial.ExpiresAt).slice(0, 10) : "",
    isActive: initial?.IsActive ?? true,
    tags: (initial?.Tags as string[]) ?? [],
  });
  const set = (patch: Partial<typeof f>) => setF((old) => ({ ...old, ...patch }));
  const editing = !!initial?.IndicatorID;
  const onValue = (raw: string) => {
    const value = refang(raw.trim());
    const guessed = guessType(value);
    set(guessed && !editing ? { value, type: guessed } : { value });
  };
  const save = async () => {
    const res = await api(editing ? `/indicators/${initial.IndicatorID}` : "/indicators", { method: editing ? "PUT" : "POST", body: { ...f, confidence: Number(f.confidence) } });
    toast(editing ? "Gösterge güncellendi." : "Gösterge eklendi.");
    reloadMeta();
    onSaved(res.IndicatorID);
  };
  return (
    <FormModal title={editing ? "Göstergeyi düzenle" : "Gösterge ekle"} onClose={onClose} onSubmit={save}>
      <Field label="Değer" wide hint="Yapıştırdığınız değerin tipi otomatik seçilir. 1.2.3[.]4 gibi yazımlar çözülür.">
        <input className="input mono" autoFocus value={f.value} onChange={(e) => onValue(e.target.value)} placeholder="198.51.100.23, ornek.example, 44d88612fea8a8f36de82e1278abb02f..." />
      </Field>
      <Field label="Tip">
        <select className="input" value={f.type} onChange={(e) => set({ type: e.target.value })}>{meta.types.map((t) => <option key={t.Code} value={t.Code}>{t.Name}</option>)}</select>
      </Field>
      <Field label="Kaynak">
        <select className="input" value={f.sourceId} onChange={(e) => set({ sourceId: Number(e.target.value) })}>{meta.sources.map((s) => <option key={s.SourceID} value={s.SourceID}>{s.Name} ({s.Reliability})</option>)}</select>
      </Field>
      <Field label={`Güven: ${f.confidence}`} hint="Bu göstergenin gerçekten kötü amaçlı olduğundan ne kadar eminsiniz?">
        <input type="range" min={0} max={100} step={5} value={f.confidence} onChange={(e) => set({ confidence: Number(e.target.value) })} />
      </Field>
      <Field label="Önem">
        <select className="input" value={f.severity} onChange={(e) => set({ severity: e.target.value })}>{meta.severities.map((s) => <option key={s.Code} value={s.Code}>{s.Name}</option>)}</select>
      </Field>
      <Field label="Paylaşım (TLP)" hint={meta.tlps.find((t) => t.Code === f.tlp)?.Description}>
        <select className="input" value={f.tlp} onChange={(e) => set({ tlp: e.target.value })}>{meta.tlps.map((t) => <option key={t.Code} value={t.Code}>{t.Code}</option>)}</select>
      </Field>
      <Field label="Geçerlilik sonu" hint="Bu tarihten sonra gösterge pasife alınır. Boş bırakılabilir.">
        <input className="input" type="date" value={f.expiresAt} onChange={(e) => set({ expiresAt: e.target.value })} />
      </Field>
      <Field label="Etiketler" wide><TokenInput value={f.tags} onChange={(tags) => set({ tags })} placeholder="c2, botnet... (Enter ile ekleyin)" /></Field>
      <Field label="Açıklama" wide><textarea className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
      {editing && <label className="wide" style={{ display: "flex", gap: 8, alignItems: "center" }}><input type="checkbox" checked={f.isActive} onChange={(e) => set({ isActive: e.target.checked })} /> Gösterge aktif</label>}
    </FormModal>
  );
}

export function ActorForm({ initial, onClose, onSaved }: { initial?: any; onClose: () => void; onSaved: (id: number) => void }) {
  const { meta, toast } = useApp();
  const a = initial?.actor;
  const [f, setF] = useState({
    name: a?.Name ?? "", description: a?.Description ?? "", motivationId: a?.MotivationID ?? "", countryCode: a?.CountryCode ?? "",
    isActive: a?.IsActive ?? true, aliases: (initial?.aliases as string[]) ?? [],
    sectorIds: ((initial?.sectors ?? []) as any[]).map((s) => s.SectorID as number),
    targetCountries: ((initial?.targetCountries ?? []) as any[]).map((c) => c.CountryCode as string),
  });
  const set = (patch: Partial<typeof f>) => setF((old) => ({ ...old, ...patch }));
  const toggle = <T,>(list: T[], item: T) => (list.includes(item) ? list.filter((x) => x !== item) : [...list, item]);
  const save = async () => {
    const body = { ...f, motivationId: f.motivationId ? Number(f.motivationId) : null, countryCode: f.countryCode || null };
    const res = await api(a ? `/actors/${a.ActorID}` : "/actors", { method: a ? "PUT" : "POST", body });
    toast(a ? "Aktör güncellendi." : "Aktör eklendi.");
    onSaved(res.ActorID);
  };
  return (
    <FormModal title={a ? "Aktörü düzenle" : "Aktör ekle"} onClose={onClose} onSubmit={save}>
      <Field label="Ad" wide><input className="input" autoFocus value={f.name} onChange={(e) => set({ name: e.target.value })} /></Field>
      <Field label="Motivasyon">
        <select className="input" value={f.motivationId} onChange={(e) => set({ motivationId: e.target.value })}><option value="">Belirtilmedi</option>{meta.motivations.map((m) => <option key={m.MotivationID} value={m.MotivationID}>{m.Name}</option>)}</select>
      </Field>
      <Field label="Köken ülke">
        <select className="input" value={f.countryCode} onChange={(e) => set({ countryCode: e.target.value })}><option value="">Bilinmiyor</option>{meta.countries.map((c) => <option key={c.CountryCode} value={c.CountryCode}>{c.Name}</option>)}</select>
      </Field>
      <Field label="Diğer adları" wide hint="Farklı firmalar aynı gruba farklı adlar verir."><TokenInput value={f.aliases} onChange={(aliases) => set({ aliases })} placeholder="Fancy Bear, Sofacy..." /></Field>
      <Field label="Hedef aldığı sektörler" wide>
        <div className="chips">{meta.sectors.map((s) => <button type="button" key={s.SectorID} className={`chip${f.sectorIds.includes(s.SectorID) ? " on" : ""}`} onClick={() => set({ sectorIds: toggle(f.sectorIds, s.SectorID) })}>{s.Name}</button>)}</div>
      </Field>
      <Field label="Hedef aldığı ülkeler" wide>
        <select className="input" value="" onChange={(e) => e.target.value && set({ targetCountries: toggle(f.targetCountries, e.target.value) })}>
          <option value="">Ülke ekle...</option>{meta.countries.filter((c) => !f.targetCountries.includes(c.CountryCode)).map((c) => <option key={c.CountryCode} value={c.CountryCode}>{c.Name}</option>)}
        </select>
        <div className="chips">{f.targetCountries.map((c) => <span key={c} className="chip static">{meta.countries.find((x) => x.CountryCode === c)?.Name ?? c}<button type="button" onClick={() => set({ targetCountries: toggle(f.targetCountries, c) })}>×</button></span>)}</div>
      </Field>
      <Field label="Açıklama" wide><textarea className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
      <label className="wide" style={{ display: "flex", gap: 8, alignItems: "center" }}><input type="checkbox" checked={f.isActive} onChange={(e) => set({ isActive: e.target.checked })} /> Hâlâ etkin</label>
    </FormModal>
  );
}

export function MalwareForm({ initial, onClose, onSaved }: { initial?: any; onClose: () => void; onSaved: (id: number) => void }) {
  const { meta, toast } = useApp();
  const m = initial?.malware;
  const [f, setF] = useState({ name: m?.Name ?? "", malwareTypeId: m?.MalwareTypeID ?? meta.malwareTypes.find((t) => t.Code === "malware")?.MalwareTypeID ?? 1,
    description: m?.Description ?? "", platforms: m?.Platforms ?? "", aliases: (initial?.aliases as string[]) ?? [] });
  const set = (patch: Partial<typeof f>) => setF((old) => ({ ...old, ...patch }));
  const save = async () => {
    const res = await api(m ? `/malware/${m.MalwareID}` : "/malware", { method: m ? "PUT" : "POST", body: { ...f, malwareTypeId: Number(f.malwareTypeId) } });
    toast(m ? "Zararlı yazılım güncellendi." : "Zararlı yazılım eklendi.");
    onSaved(res.MalwareID);
  };
  return (
    <FormModal title={m ? "Zararlı yazılımı düzenle" : "Zararlı yazılım ekle"} onClose={onClose} onSubmit={save}>
      <Field label="Ad"><input className="input" autoFocus value={f.name} onChange={(e) => set({ name: e.target.value })} /></Field>
      <Field label="Tür"><select className="input" value={f.malwareTypeId} onChange={(e) => set({ malwareTypeId: Number(e.target.value) })}>{meta.malwareTypes.map((t) => <option key={t.MalwareTypeID} value={t.MalwareTypeID}>{t.Name}</option>)}</select></Field>
      <Field label="Platformlar" wide><input className="input" value={f.platforms} onChange={(e) => set({ platforms: e.target.value })} placeholder="Windows, Linux" /></Field>
      <Field label="Diğer adları" wide><TokenInput value={f.aliases} onChange={(aliases) => set({ aliases })} /></Field>
      <Field label="Açıklama" wide><textarea className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
    </FormModal>
  );
}

export function CampaignForm({ initial, onClose, onSaved }: { initial?: any; onClose: () => void; onSaved: (id: number) => void }) {
  const { toast } = useApp();
  const c = initial?.campaign;
  const [f, setF] = useState({ name: c?.Name ?? "", description: c?.Description ?? "", startDate: c?.StartDate?.slice(0, 10) ?? "", endDate: c?.EndDate?.slice(0, 10) ?? "" });
  const [actor, setActor] = useState<{ id: number; name: string } | null>(c?.ActorID ? { id: c.ActorID, name: c.ActorName } : null);
  const set = (patch: Partial<typeof f>) => setF((old) => ({ ...old, ...patch }));
  const save = async () => {
    const res = await api(c ? `/campaigns/${c.CampaignID}` : "/campaigns", { method: c ? "PUT" : "POST", body: { ...f, actorId: actor?.id ?? null } });
    toast(c ? "Kampanya güncellendi." : "Kampanya eklendi.");
    onSaved(res.CampaignID);
  };
  return (
    <FormModal title={c ? "Kampanyayı düzenle" : "Kampanya ekle"} onClose={onClose} onSubmit={save}>
      <Field label="Ad" wide><input className="input" autoFocus value={f.name} onChange={(e) => set({ name: e.target.value })} /></Field>
      <Field label="Atfedilen aktör" wide>
        {actor ? <div className="chips"><span className="chip static"><i className="dot actor" />{actor.name}<button type="button" onClick={() => setActor(null)}>×</button></span></div>
          : <EntityPicker type="actor" onPick={(id, name) => setActor({ id, name })} placeholder="Aktör ara..." />}
      </Field>
      <Field label="Başlangıç"><input className="input" type="date" value={f.startDate} onChange={(e) => set({ startDate: e.target.value })} /></Field>
      <Field label="Bitiş" hint="Sürüyorsa boş bırakın."><input className="input" type="date" value={f.endDate} onChange={(e) => set({ endDate: e.target.value })} /></Field>
      <Field label="Açıklama" wide><textarea className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
    </FormModal>
  );
}

export function VulnerabilityForm({ initial, onClose, onSaved }: { initial?: any; onClose: () => void; onSaved: (id: number) => void }) {
  const { toast } = useApp();
  const v = initial;
  const [f, setF] = useState({ cveId: v?.CveID ?? "", title: v?.Title ?? "", description: v?.Description ?? "", vendor: v?.Vendor ?? "", product: v?.Product ?? "",
    cvssScore: v?.CvssScore ?? "", publishedDate: v?.PublishedDate?.slice(0, 10) ?? "", isKnownExploited: v?.IsKnownExploited ?? false });
  const set = (patch: Partial<typeof f>) => setF((old) => ({ ...old, ...patch }));
  const save = async () => {
    const body = { ...f, cveId: f.cveId.trim().toUpperCase(), cvssScore: f.cvssScore === "" ? null : Number(f.cvssScore) };
    const res = await api(v ? `/vulnerabilities/${v.VulnerabilityID}` : "/vulnerabilities", { method: v ? "PUT" : "POST", body });
    toast(v ? "Zafiyet güncellendi." : "Zafiyet eklendi.");
    onSaved(res.VulnerabilityID);
  };
  return (
    <FormModal title={v ? "Zafiyeti düzenle" : "Zafiyet ekle"} onClose={onClose} onSubmit={save}>
      <Field label="CVE numarası"><input className="input mono" autoFocus value={f.cveId} onChange={(e) => set({ cveId: e.target.value })} placeholder="CVE-2024-12345" /></Field>
      <Field label="CVSS puanı" hint="0 ile 10 arasında"><input className="input" type="number" min={0} max={10} step={0.1} value={f.cvssScore} onChange={(e) => set({ cvssScore: e.target.value })} /></Field>
      <Field label="Başlık" wide><input className="input" value={f.title} onChange={(e) => set({ title: e.target.value })} /></Field>
      <Field label="Üretici"><input className="input" value={f.vendor} onChange={(e) => set({ vendor: e.target.value })} /></Field>
      <Field label="Ürün"><input className="input" value={f.product} onChange={(e) => set({ product: e.target.value })} /></Field>
      <Field label="Yayın tarihi"><input className="input" type="date" value={f.publishedDate} onChange={(e) => set({ publishedDate: e.target.value })} /></Field>
      <label style={{ display: "flex", gap: 8, alignItems: "center", alignSelf: "end", paddingBottom: 8 }}><input type="checkbox" checked={f.isKnownExploited} onChange={(e) => set({ isKnownExploited: e.target.checked })} /> Sahada istismar ediliyor</label>
      <Field label="Açıklama" wide><textarea className="input" value={f.description} onChange={(e) => set({ description: e.target.value })} /></Field>
    </FormModal>
  );
}

/** Arama kutusundan tek bir varlık seçtirir (ilişki kurmak için) */
export function EntityPicker({ type, onPick, placeholder }: { type: EntityType; onPick: (id: number, name: string) => void; placeholder?: string }) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<any[]>([]);
  useEffect(() => {
    if (q.trim().length < 2) { setHits([]); return; }
    const timer = setTimeout(() => api<any[]>(`/search?q=${encodeURIComponent(q.trim())}`).then((r) => setHits(r.filter((h) => h.EntityType === type))).catch(() => {}), 180);
    return () => clearTimeout(timer);
  }, [q, type]);
  return (
    <div style={{ position: "relative" }}>
      <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder={placeholder ?? `${ENTITY[type].one} ara...`} />
      {hits.length > 0 && (
        <div className="panel" style={{ position: "absolute", zIndex: 5, left: 0, right: 0, top: "calc(100% + 4px)", padding: 4, boxShadow: "var(--shadow-pop)" }}>
          {hits.map((h) => (
            <button type="button" key={h.EntityID} className="btn ghost" style={{ width: "100%", justifyContent: "flex-start" }}
              onClick={() => { onPick(h.EntityID, h.Title); setQ(""); setHits([]); }}>
              <i className={`dot ${type}`} /><span className={type === "indicator" ? "mono" : ""}>{h.Title}</span><small className="faint">{h.Subtitle}</small>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Kayıt sayfalarındaki "bağla" denetimi: ara tabloya satır ekler */
export function LinkAdder({ kind, selfId, selfFirst, type, onDone, withRole }: {
  kind: string; selfId: number; selfFirst: boolean; type: EntityType; onDone: () => void; withRole?: boolean;
}) {
  const { canEdit, toast } = useApp();
  const [open, setOpen] = useState(false);
  const [role, setRole] = useState("c2");
  if (!canEdit) return null;
  if (!open) return <button className="btn ghost sm" onClick={() => setOpen(true)}>Bağla</button>;
  const pick = async (id: number, name: string) => {
    try {
      await api("/links", { method: "POST", body: { kind, a: selfFirst ? selfId : id, b: selfFirst ? id : selfId, role: withRole ? role : null } });
      toast(`${name} bağlandı.`); setOpen(false); onDone();
    } catch (e: any) { toast(e.message, "error"); }
  };
  return (
    <div style={{ display: "flex", gap: 6, minWidth: 260 }}>
      {withRole && <select className="input" style={{ width: 120 }} value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="c2">C2</option><option value="payload">Yük</option><option value="dropper">Bırakıcı</option><option value="exfil">Sızdırma</option><option value="phishing">Oltalama</option><option value="other">Diğer</option></select>}
      <div style={{ flex: 1 }}><EntityPicker type={type} onPick={pick} /></div>
      <button className="btn ghost sm" onClick={() => setOpen(false)}>Kapat</button>
    </div>
  );
}

export function Unlink({ kind, a, b, onDone }: { kind: string; a: number; b: number; onDone: () => void }) {
  const { canEdit, toast } = useApp();
  if (!canEdit) return null;
  return (
    <button className="btn ghost sm" title="Bağlantıyı kaldır" aria-label="Bağlantıyı kaldır"
      onClick={async () => { try { await api(`/links?kind=${kind}&a=${a}&b=${b}`, { method: "DELETE" }); onDone(); } catch (e: any) { toast(e.message, "error"); } }}>×</button>
  );
}
