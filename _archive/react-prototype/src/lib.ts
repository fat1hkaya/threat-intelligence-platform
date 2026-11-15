export type EntityType = "indicator" | "actor" | "malware" | "campaign" | "technique" | "vulnerability";

export const ENTITY: Record<EntityType, { one: string; many: string; path: string }> = {
  indicator: { one: "Gösterge", many: "Göstergeler", path: "/indicators" },
  actor: { one: "Aktör", many: "Aktörler", path: "/actors" },
  malware: { one: "Zararlı yazılım", many: "Zararlı yazılımlar", path: "/malware" },
  campaign: { one: "Kampanya", many: "Kampanyalar", path: "/campaigns" },
  technique: { one: "Teknik", many: "Teknikler", path: "/attack?technique=" },
  vulnerability: { one: "Zafiyet", many: "Zafiyetler", path: "/vulnerabilities" },
};

export const entityHref = (type: EntityType, id: number | string) =>
  type === "technique" ? `/attack?technique=${id}` : `${ENTITY[type].path}/${id}`;

export const riskBand = (score: number) => (score >= 75 ? "crit" : score >= 55 ? "high" : score >= 35 ? "med" : "low");
export const riskLabel = (score: number) => ({ crit: "Kritik", high: "Yüksek", med: "Orta", low: "Düşük" })[riskBand(score)];

const parse = (v: string | null | undefined) => (v ? new Date(/[zZ]|[+-]\d\d:\d\d$/.test(v) || v.length <= 10 ? v : v + "Z") : null);
const dateFmt = new Intl.DateTimeFormat("tr-TR", { day: "numeric", month: "short", year: "numeric" });
const dateTimeFmt = new Intl.DateTimeFormat("tr-TR", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
export const fmtDate = (v?: string | null) => { const d = parse(v); return d ? dateFmt.format(d) : "-"; };
export const fmtDateTime = (v?: string | null) => { const d = parse(v); return d ? dateTimeFmt.format(d) : "-"; };
export const fmtNum = (n: number | null | undefined) => (n ?? 0).toLocaleString("tr-TR");

export function ago(v?: string | null): string {
  const d = parse(v);
  if (!d) return "-";
  const mins = Math.round((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return "az önce";
  if (mins < 60) return `${mins} dk önce`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} sa önce`;
  const days = Math.round(hours / 24);
  if (days < 31) return `${days} gün önce`;
  const months = Math.round(days / 30);
  return months < 12 ? `${months} ay önce` : `${Math.round(months / 12)} yıl önce`;
}

export const ROLE_LABEL: Record<string, string> = {
  c2: "Komuta-kontrol", payload: "Yük", dropper: "Bırakıcı", exfil: "Veri sızdırma", phishing: "Oltalama", other: "Diğer",
};
export const RELIABILITY: Record<string, string> = {
  A: "Tamamen güvenilir", B: "Genellikle güvenilir", C: "Oldukça güvenilir", D: "Genellikle güvenilmez", E: "Güvenilmez", F: "Değerlendirilemez",
};

// Yapıştırılan metnin gösterge tipini tahmin eder (form ve arama için)
export function guessType(v: string): string | null {
  const s = v.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return "ipv4";
  if (/^[0-9a-f]{64}$/i.test(s)) return "sha256";
  if (/^[0-9a-f]{40}$/i.test(s)) return "sha1";
  if (/^[0-9a-f]{32}$/i.test(s)) return "md5";
  if (/^(https?|ftp):\/\//i.test(s)) return "url";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return "email";
  if (s.includes(":") && /^[0-9a-f:.]+$/i.test(s)) return "ipv6";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return "domain";
  return null;
}

// "Defang": zararlı adreslerin yanlışlıkla tıklanmasını önleyen yazım (1.2.3[.]4, hxxp://)
export const defang = (v: string) => v.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
export const refang = (v: string) => v.replace(/\[\.\]|\(\.\)|\[dot\]/gi, ".").replace(/^hxxp/i, "http").replace(/\[:\]/g, ":");
