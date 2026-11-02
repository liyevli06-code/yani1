import { NextRequest, NextResponse } from "next/server";
import { isValidHostname } from "@/lib/net";
import { probeHost } from "@/lib/probe";
import { clientIp, rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const MAX_HOSTS_PER_REQUEST = 12;

// The UI sends batches of 6 hosts from 4 parallel workers, so one full scan of a large
// domain needs many requests. 120 requests per minute per IP leaves room for that.
const LIMIT = 120;
const WINDOW_MS = 60_000;

export async function POST(req: NextRequest) {
  const limited = rateLimit(`probe:${clientIp(req)}`, LIMIT, WINDOW_MS);
  if (!limited.ok) {
    return NextResponse.json(
      { error: "Too many requests. Try again shortly." },
      { status: 429, headers: { "retry-after": String(limited.retryAfter) } }
    );
  }

  let body: { hosts?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send a JSON body with a hosts array." }, { status: 400 });
  }

  if (!Array.isArray(body.hosts)) {
    return NextResponse.json({ error: "Send a JSON body with a hosts array." }, { status: 400 });
  }

  const hosts = [...new Set(body.hosts.map((h) => String(h).trim().toLowerCase()))].filter(
    isValidHostname
  );

  if (hosts.length === 0 || hosts.length > MAX_HOSTS_PER_REQUEST) {
    return NextResponse.json(
      { error: `Send between 1 and ${MAX_HOSTS_PER_REQUEST} valid hostnames per request.` },
      { status: 400 }
    );
  }

  const results = await Promise.all(hosts.map((h) => probeHost(h)));
  return NextResponse.json({ results });
}
