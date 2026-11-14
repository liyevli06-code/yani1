import { cacheGet, cacheSet } from "./cache";

export type IpInfo = { ip: string; org: string | null; country: string | null; error?: string };

const TTL_MS = 24 * 60 * 60_000;

/**
 * Hosting provider / ASN ("org", e.g. "AS15169 Google LLC") and country for one IP address,
 * via ipinfo.io's free, keyless endpoint. Results are cached per IP for a day since this data
 * barely changes and the free tier is rate-limited.
 */
export async function lookupIpInfo(ip: string): Promise<IpInfo> {
  const key = `ipinfo:${ip}`;
  const cached = cacheGet<IpInfo>(key);
  if (cached) return cached;

  try {
    const res = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
      headers: { "user-agent": "SubScope/1.0", accept: "application/json" },
      signal: AbortSignal.timeout(5000),
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as { org?: string; country?: string; bogon?: boolean };
    const info: IpInfo = { ip, org: data.org ?? null, country: data.country ?? null };
    cacheSet(key, info, TTL_MS);
    return info;
  } catch (err) {
    const info: IpInfo = { ip, org: null, country: null, error: err instanceof Error ? err.message : "lookup failed" };
    cacheSet(key, info, 5 * 60_000); // Cache failures briefly too, so a flaky lookup isn't retried on every render.
    return info;
  }
}

export async function lookupIpInfoBatch(ips: string[]): Promise<Record<string, IpInfo>> {
  const unique = [...new Set(ips)].slice(0, 60);
  const results = await Promise.all(unique.map(lookupIpInfo));
  const out: Record<string, IpInfo> = {};
  for (const r of results) out[r.ip] = r;
  return out;
}
