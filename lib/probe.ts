import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import type { LookupFunction } from "node:net";
import type { TLSSocket } from "node:tls";
import { isPrivateAddress } from "./net";
import { faviconHash } from "./mmh3";
import { detectTakeover, TakeoverFinding } from "./takeover";

export type SecurityHeaders = { present: string[]; missing: string[] };
export type RobotsInfo = { robotsTxt: boolean; sitemapXml: boolean };
export type FaviconInfo = { hash: number; bytes: number };

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
  securityHeaders?: SecurityHeaders;
  /** Days until the TLS certificate expires; negative if already expired. Only set for https. */
  tlsDaysLeft?: number | null;
  /** CNAME target, if this host is an alias rather than a direct A/AAAA record. */
  cname?: string | null;
  /** Set only when a dangling-CNAME subdomain-takeover pattern was matched — see lib/takeover.ts. */
  takeover?: TakeoverFinding | null;
  favicon?: FaviconInfo | null;
  robots?: RobotsInfo | null;
};

/** A compact, well-known subset of response headers that harden a browser's handling of the page. */
const SECURITY_HEADERS: { id: string; header: string }[] = [
  { id: "HSTS", header: "strict-transport-security" },
  { id: "CSP", header: "content-security-policy" },
  { id: "X-Frame-Options", header: "x-frame-options" },
  { id: "X-Content-Type-Options", header: "x-content-type-options" },
  { id: "Referrer-Policy", header: "referrer-policy" },
  { id: "Permissions-Policy", header: "permissions-policy" },
];

function checkSecurityHeaders(headers: http.IncomingHttpHeaders): SecurityHeaders {
  const present: string[] = [];
  const missing: string[] = [];
  for (const { id, header } of SECURITY_HEADERS) {
    (headers[header] ? present : missing).push(id);
  }
  return { present, missing };
}

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

type RawRequestResult = Omit<ProbeResult, "host" | "ips" | "cname" | "takeover" | "favicon" | "robots"> & {
  body: string;
};

function request(host: string, scheme: "https" | "http", timeoutMs: number): Promise<RawRequestResult> {
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
        // The certificate has to be read as soon as headers arrive: truncating a large body
        // below calls res.destroy(), which tears down the TLS socket, and a destroyed socket's
        // getPeerCertificate() comes back empty. Reading it now, before any of that, is safe.
        let tlsDaysLeft: number | null = null;
        if (scheme === "https") {
          try {
            const cert = (res.socket as TLSSocket | undefined)?.getPeerCertificate?.();
            if (cert?.valid_to) {
              tlsDaysLeft = Math.round((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
            }
          } catch {
            // No certificate available — leave it unset.
          }
        }

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
            securityHeaders: checkSecurityHeaders(res.headers),
            tlsDaysLeft,
            body,
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

/** Small, bounded GET used for favicon.ico and robots.txt/sitemap.xml — reuses the SSRF-safe
 *  lookup, but doesn't need headers/cert/tech detection, so it's kept separate from `request`. */
function smallGet(
  host: string,
  scheme: "https" | "http",
  path: string,
  timeoutMs: number,
  maxBytes: number
): Promise<{ status: number; body: Buffer; contentType: string | null }> {
  return new Promise((resolve, reject) => {
    const lib = scheme === "https" ? https : http;
    const req = lib.request(
      {
        host,
        port: scheme === "https" ? 443 : 80,
        path,
        method: "GET",
        lookup: safeLookup,
        timeout: timeoutMs,
        rejectUnauthorized: false,
        headers: { "user-agent": "Mozilla/5.0 (compatible; SubScope/1.0)", "accept-encoding": "identity" },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size <= maxBytes) chunks.push(chunk);
          else res.destroy();
        });
        const finish = () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks),
            contentType: (res.headers["content-type"] as string | undefined) ?? null,
          });
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

async function fetchFavicon(host: string, scheme: "https" | "http"): Promise<FaviconInfo | null> {
  try {
    const res = await smallGet(host, scheme, "/favicon.ico", 3500, 262144);
    if (res.status !== 200 || res.body.length === 0) return null;
    return { hash: faviconHash(res.body), bytes: res.body.length };
  } catch {
    return null;
  }
}

async function checkRobots(host: string, scheme: "https" | "http"): Promise<RobotsInfo | null> {
  try {
    const [robots, sitemap] = await Promise.allSettled([
      smallGet(host, scheme, "/robots.txt", 3000, 20000),
      smallGet(host, scheme, "/sitemap.xml", 3000, 2000),
    ]);
    return {
      robotsTxt: robots.status === "fulfilled" && robots.value.status === 200,
      sitemapXml: sitemap.status === "fulfilled" && sitemap.value.status === 200,
    };
  } catch {
    return null;
  }
}

/** Resolves the CNAME chain, returning the final target, or null if this is a direct A/AAAA
 *  record (most names) or the lookup fails outright. */
async function resolveCname(host: string): Promise<string | null> {
  try {
    const chain = await dns.promises.resolveCname(host);
    return chain.length > 0 ? chain[chain.length - 1] : null;
  } catch {
    return null;
  }
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

  const cname = await resolveCname(host);

  let main: RawRequestResult | null = null;
  let requestFailed = false;
  let lastError = "";
  try {
    main = await request(host, "https", 6000);
  } catch (httpsError) {
    try {
      main = await request(host, "http", 6000);
    } catch (httpError) {
      requestFailed = true;
      lastError = (httpError as Error).message || (httpsError as Error).message;
    }
  }

  const takeover = detectTakeover(cname, main?.body ?? "", requestFailed);

  if (!main) {
    return {
      ...empty,
      ips,
      error: lastError || "no response",
      cname,
      takeover: takeover.vulnerable ? takeover : null,
    };
  }

  const [favicon, robots] = await Promise.allSettled([
    fetchFavicon(host, main.scheme as "https" | "http"),
    checkRobots(host, main.scheme as "https" | "http"),
  ]);

  const { body: _body, ...rest } = main;
  return {
    host,
    ips,
    ...rest,
    cname,
    takeover: takeover.vulnerable ? takeover : null,
    favicon: favicon.status === "fulfilled" ? favicon.value : null,
    robots: robots.status === "fulfilled" ? robots.value : null,
  };
}
