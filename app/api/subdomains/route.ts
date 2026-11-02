import { NextRequest, NextResponse } from "next/server";
import { normalizeDomain } from "@/lib/net";
import { discoverSubdomains } from "@/lib/sources";
import { clientIp, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

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
  const { hosts, reports } = await discoverSubdomains(domain);

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
  });
}
