import { NextRequest, NextResponse } from "next/server";
import { isIP } from "node:net";
import { lookupIpInfoBatch } from "@/lib/ipinfo";
import { clientIp, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const LIMIT = 30;
const WINDOW_MS = 60_000;

export async function POST(req: NextRequest) {
  const limited = rateLimit(`ipinfo:${clientIp(req)}`, LIMIT, WINDOW_MS);
  if (!limited.ok) {
    return NextResponse.json(
      { error: "Too many requests. Try again shortly." },
      { status: 429, headers: { "retry-after": String(limited.retryAfter) } }
    );
  }

  let body: { ips?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send a JSON body with an ips array." }, { status: 400 });
  }

  if (!Array.isArray(body.ips)) {
    return NextResponse.json({ error: "Send a JSON body with an ips array." }, { status: 400 });
  }

  const ips = [...new Set(body.ips.map((ip) => String(ip).trim()))].filter((ip) => isIP(ip) !== 0).slice(0, 60);
  if (ips.length === 0) {
    return NextResponse.json({ results: {} });
  }

  const results = await lookupIpInfoBatch(ips);
  return NextResponse.json({ results });
}
