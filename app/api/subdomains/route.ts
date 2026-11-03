import { NextRequest, NextResponse } from "next/server";
import { cacheGet, cacheSet } from "@/lib/cache";
import { checkWildcardDns, normalizeDomain } from "@/lib/net";
import { discoverSubdomains, Discovered, SourceReport } from "@/lib/sources";
import { clientIp, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const CACHE_TTL_MS = 10 * 60_000;

type CachedResult = {
  hosts: Discovered[];
  reports: SourceReport[];
  wildcard: { detected: boolean; ips: string[] };
};

export async function GET(req: NextRequest) {
  const limited = rateLimit(`subdomains:${clientIp(req)}`, 10, 60_000);
  if (!limited.ok) {
    return NextResponse.json(
      { error: "Too many requests. Try again shortly." },
      { status: 429, headers: { "retry-after": String(limited.retryAfter) } }
    );
  }

  const raw = req.nextUrl.searchParams.get("domain") ?? "";
  const domain = normalizeDomain(raw);
  if (!domain) {
    return NextResponse.json(
      { error: "Enter a valid domain, for example example.com." },
      { status: 400 }
    );
  }

  const started = Date.now();
  const cacheKey = `subdomains:${domain}`;
  let cached = true;
  let result = cacheGet<CachedResult>(cacheKey);

  if (!result) {
    cached = false;
    const [discovery, wildcard] = await Promise.all([discoverSubdomains(domain), checkWildcardDns(domain)]);
    result = { hosts: discovery.hosts, reports: discovery.reports, wildcard };

    const hasAnyData = result.hosts.length > 0 || result.reports.some((r) => r.ok);
    if (hasAnyData) cacheSet(cacheKey, result, CACHE_TTL_MS);
  }

  const { hosts, reports, wildcard } = result;

  if (hosts.length === 0 && reports.every((r) => !r.ok)) {
    return NextResponse.json(
      {
        error: "None of the data sources responded. Check your connection and try again.",
        sources: reports,
      },
      { status: 502 }
    );
  }

  return NextResponse.json({
    domain,
    tookMs: Date.now() - started,
    total: hosts.length,
    subdomains: hosts,
    sources: reports,
    wildcard,
    cached,
  });
}
