import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import type { LookupFunction } from "node:net";
import { isPrivateAddress } from "./net";

export type ProbeResult = {
  host: string;
  ips: string[];
  status: number | null;
  scheme: "https" | "http" | null;
  server: string | null;
  tech: string[];
  title: string | null;
  redirect: string | null;
  error?: string;
};

/** DNS lookup that refuses non-public addresses, so a probe can never reach internal services. */
const safeLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return (callback as any)(err, "", 4);
    const list = Array.isArray(addresses) ? addresses : [];
    const publicOnes = list.filter((a) => !isPrivateAddress(a.address));
    if (publicOnes.length === 0) {
      return (callback as any)(new Error("blocked: non-public address"), "", 4);
    }
    if ((options as any)?.all) return (callback as any)(null, publicOnes);
    return (callback as any)(null, publicOnes[0].address, publicOnes[0].family);
  });
};

function detectTech(headers: http.IncomingHttpHeaders, body: string): string[] {
  const tech = new Set<string>();
  const h = (name: string) => {
    const v = headers[name];
    return (Array.isArray(v) ? v.join(" ") : v ?? "").toLowerCase();
  };
  const server = h("server");

  if (headers["cf-ray"] || server.includes("cloudflare")) tech.add("Cloudflare");
  if (server.includes("nginx")) tech.add("Nginx");
  if (server.includes("apache")) tech.add("Apache");
  if (server.includes("microsoft-iis")) tech.add("IIS");
  if (server.includes("litespeed")) tech.add("LiteSpeed");
  if (server.includes("caddy")) tech.add("Caddy");
  if (server.includes("openresty")) tech.add("OpenResty");
  if (server.includes("gws") || server.includes("esf")) tech.add("Google");
  if (server.includes("amazons3")) tech.add("Amazon S3");
  if (server.includes("akamai")) tech.add("Akamai");
  if (server.includes("vercel") || headers["x-vercel-id"]) tech.add("Vercel");
  if (server.includes("netlify") || headers["x-nf-request-id"]) tech.add("Netlify");
  if (headers["x-amz-cf-id"] || h("via").includes("cloudfront")) tech.add("CloudFront");
  if (headers["x-amz-request-id"] || headers["x-amz-id-2"]) tech.add("AWS");
  if (headers["x-github-request-id"] || server.includes("github.com")) tech.add("GitHub Pages");
  if (h("x-served-by").includes("cache-") || h("via").includes("varnish")) tech.add("Fastly/Varnish");
  if (headers["x-azure-ref"]) tech.add("Azure Front Door");
  if (headers["x-shopify-stage"] || h("powered-by").includes("shopify")) tech.add("Shopify");

  const powered = h("x-powered-by");
  if (powered.includes("php")) tech.add("PHP");
  if (powered.includes("express")) tech.add("Express");
  if (powered.includes("asp.net") || headers["x-aspnet-version"]) tech.add("ASP.NET");
  if (powered.includes("next.js") || headers["x-nextjs-cache"]) tech.add("Next.js");
  if (h("x-drupal-cache") || h("x-generator").includes("drupal")) tech.add("Drupal");
  if (h("x-pingback") || h("link").includes("wp-json")) tech.add("WordPress");

  const b = body.toLowerCase();
  if (b.includes("/wp-content/") || b.includes("/wp-includes/")) tech.add("WordPress");
  if (b.includes("__next_data__") || b.includes("/_next/static")) tech.add("Next.js");
  if (b.includes("data-reactroot") || b.includes("react-dom")) tech.add("React");
  if (b.includes("ng-version=")) tech.add("Angular");
  if (b.includes("cdn.shopify.com")) tech.add("Shopify");
  if (/<meta[^>]+generator[^>]+joomla/.test(b)) tech.add("Joomla");

  return [...tech];
}

function request(
  host: string,
  scheme: "https" | "http",
  timeoutMs: number
): Promise<Omit<ProbeResult, "host" | "ips">> {
  return new Promise((resolve, reject) => {
    const lib = scheme === "https" ? https : http;
    const req = lib.request(
      {
        host,
        port: scheme === "https" ? 443 : 80,
        path: "/",
        method: "GET",
        lookup: safeLookup,
        timeout: timeoutMs,
        rejectUnauthorized: false, // Many subdomains carry expired or mismatched certificates; we still want their status.
        headers: {
          "user-agent": "Mozilla/5.0 (compatible; SubScope/1.0)",
          accept: "text/html,*/*;q=0.8",
          "accept-encoding": "identity",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size <= 65536) chunks.push(chunk);
          else res.destroy(); // Only the first 64 KB is needed for detection.
        });
        const finish = () => {
          const body = Buffer.concat(chunks).toString("utf8");
          const title = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(body)?.[1]?.replace(/\s+/g, " ").trim() ?? null;
          const server = (res.headers["server"] as string | undefined) ?? null;
          const location = (res.headers["location"] as string | undefined) ?? null;
          resolve({
            status: res.statusCode ?? null,
            scheme,
            server,
            tech: detectTech(res.headers, body),
            title: title || null,
            redirect: location,
          });
        };
        res.on("end", finish);
        res.on("close", finish);
        res.on("error", finish);
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

async function resolveIps(host: string): Promise<string[]> {
  const [v4, v6] = await Promise.allSettled([
    dns.promises.resolve4(host),
    dns.promises.resolve6(host),
  ]);
  const ips = [
    ...(v4.status === "fulfilled" ? v4.value : []),
    ...(v6.status === "fulfilled" ? v6.value : []),
  ];
  if (ips.length > 0) return ips;
  // CNAME-only or search-list hosts: fall back to the system resolver.
  try {
    const all = await dns.promises.lookup(host, { all: true });
    return all.map((a) => a.address);
  } catch {
    return [];
  }
}

export async function probeHost(host: string): Promise<ProbeResult> {
  const empty: ProbeResult = {
    host,
    ips: [],
    status: null,
    scheme: null,
    server: null,
    tech: [],
    title: null,
    redirect: null,
  };

  const ips = await resolveIps(host);
  if (ips.length === 0) return { ...empty, error: "no DNS record" };
  if (ips.every(isPrivateAddress)) return { ...empty, ips, error: "private address, not probed" };

  try {
    const result = await request(host, "https", 6000);
    return { host, ips, ...result };
  } catch (httpsError) {
    try {
      const result = await request(host, "http", 6000);
      return { host, ips, ...result };
    } catch (httpError) {
      const message = (httpError as Error).message || (httpsError as Error).message;
      return { ...empty, ips, error: message };
    }
  }
}
