// Sunucuyla konuşan tek yer. Her yanıtın X-Trace-Id başlığı saklanır;
// SQL çekmecesi bu kimliklerle o istekte çalışan sorguları getirir.
import { useCallback, useEffect, useRef, useState } from "react";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export interface TraceRef { id: string; method: string; path: string; at: number }
export const traces: TraceRef[] = [];
const traceListeners = new Set<() => void>();
export const onTraces = (fn: () => void) => { traceListeners.add(fn); return () => { traceListeners.delete(fn); }; };
export const clearTraces = () => { traces.length = 0; traceListeners.forEach((f) => f()); };

let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn; };

const UNTRACED = ["/meta", "/auth/", "/trace/"];

export async function api<T = any>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const res = await fetch("/api" + path, {
    method,
    credentials: "same-origin",
    headers: options.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const traceId = res.headers.get("X-Trace-Id");
  if (traceId && !UNTRACED.some((p) => path.startsWith(p))) {
    traces.unshift({ id: traceId, method, path, at: Date.now() });
    traces.length = Math.min(traces.length, 30);
    traceListeners.forEach((f) => f());
  }
  if (res.status === 401 && !path.startsWith("/auth/")) onUnauthorized();
  if (!res.ok) {
    let message = `İstek başarısız (${res.status}).`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (Array.isArray(data.detail)) message = "Formdaki bazı alanlar geçersiz: " + data.detail.map((d: any) => d.loc?.slice(-1)[0]).join(", ");
    } catch { /* gövde JSON değil */ }
    throw new ApiError(res.status, message);
  }
  return res.json();
}

export function qs(params: Record<string, unknown>): string {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== "" && v !== null && v !== undefined && v !== false)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  return parts.length ? "?" + parts.join("&") : "";
}

export function useData<T = any>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(!!path);
  const seq = useRef(0);
  const load = useCallback(() => {
    if (!path) return;
    const mine = ++seq.current;
    setLoading(true);
    api<T>(path)
      .then((d) => { if (mine === seq.current) { setData(d); setError(null); } })
      .catch((e) => { if (mine === seq.current) setError(e.message); })
      .finally(() => { if (mine === seq.current) setLoading(false); });
  }, [path]);
  useEffect(load, [load]);
  return { data, error, loading, reload: load };
}

export interface Meta {
  types: { TypeID: number; Code: string; Name: string }[];
  severities: { SeverityID: number; Code: string; Name: string }[];
  tlps: { TLPID: number; Code: string; Description: string }[];
  sources: { SourceID: number; Name: string; Reliability: string }[];
  motivations: { MotivationID: number; Name: string }[];
  malwareTypes: { MalwareTypeID: number; Code: string; Name: string }[];
  countries: { CountryCode: string; Name: string }[];
  sectors: { SectorID: number; Name: string }[];
  tags: { TagID: number; Name: string }[];
}
export interface User { UserID: number; Username: string; FullName: string; Role: "viewer" | "analyst" | "admin"; RoleName: string }
