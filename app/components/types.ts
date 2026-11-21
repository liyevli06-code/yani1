export type SecurityHeaders = { present: string[]; missing: string[] };
export type RobotsInfo = { robotsTxt: boolean; sitemapXml: boolean };
export type FaviconInfo = { hash: number; bytes: number };
export type TakeoverFinding = { vulnerable: boolean; service: string | null; cname: string | null };

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
  tlsDaysLeft?: number | null;
  tlsProtocol?: string | null;
  tlsCipher?: string | null;
  tlsWeak?: boolean;
  cname?: string | null;
  takeover?: TakeoverFinding | null;
  favicon?: FaviconInfo | null;
  robots?: RobotsInfo | null;
};

/**
 * A single letter-grade summary of a host's security posture, rolled up from the header
 * checks, TLS protocol/cipher and certificate expiry already gathered by the live probe.
 * This is a heuristic scoring rubric for a quick read at a glance — not a substitute for a
 * real audit, and nothing here is tested beyond the one page request already made.
 */
export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";
export type GradeResult = { grade: Grade; score: number };

const HEADER_WEIGHTS: Record<string, number> = {
  HSTS: 15,
  CSP: 15,
  "X-Frame-Options": 10,
  "X-Content-Type-Options": 10,
  "Referrer-Policy": 5,
  "Permissions-Policy": 5,
};

export function securityGrade(probe?: ProbeResult): GradeResult | null {
  if (!probe || probe.status === null) return null;

  let score = 100;
  if (probe.securityHeaders) {
    for (const id of probe.securityHeaders.missing) score -= HEADER_WEIGHTS[id] ?? 5;
  }
  if (probe.scheme === "https") {
    if (probe.tlsWeak) score -= 20;
    if (typeof probe.tlsDaysLeft === "number") {
      if (probe.tlsDaysLeft < 0) score -= 20;
      else if (probe.tlsDaysLeft < 14) score -= 5;
    }
  } else if (probe.scheme === "http") {
    score -= 25; // No TLS at all.
  }
  score = Math.max(0, Math.min(100, score));

  const grade: Grade =
    score >= 97 ? "A+" : score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  return { grade, score };
}

export type IpInfo = { ip: string; org: string | null; country: string | null; error?: string };

/** Rough "how sure are we this host is real" signal from the number of independent sources
 *  that reported it. Purely a count-based heuristic, not a verification of anything. */
export type Confidence = "high" | "medium" | "low";

export function confidenceOf(sourceCount: number): Confidence {
  if (sourceCount >= 3) return "high";
  if (sourceCount === 2) return "medium";
  return "low";
}

export type SourceReport = { name: string; ok: boolean; count: number; error?: string };
export type Discovered = { host: string; sources: string[] };
export type Wildcard = { detected: boolean; ips: string[] };
export type DomainExpiry = { expiresAt: string | null; registrar: string | null; error?: string };

export type SubdomainsResponse = {
  domain: string;
  tookMs: number;
  total: number;
  subdomains: Discovered[];
  sources: SourceReport[];
  wildcard: Wildcard;
  cached: boolean;
  registration: DomainExpiry;
};

export type Category = "live" | "client" | "server" | "none" | "pending";

export function categorize(probe?: ProbeResult): Category {
  if (!probe) return "pending";
  if (probe.status === null) return "none";
  if (probe.status >= 500) return "server";
  if (probe.status >= 400) return "client";
  return "live";
}

/**
 * Prefixes that often point to a more sensitive or higher-value host (admin panels,
 * internal tools, environments not meant for the public). This is a naming-convention
 * heuristic only — it does not probe or confirm anything, it just surfaces these hosts
 * first so a reviewer looks at them before the long tail of ordinary names.
 */
const NOTABLE_PREFIXES = [
  "admin",
  "administrator",
  "cpanel",
  "webmail",
  "mail",
  "vpn",
  "internal",
  "intranet",
  "staging",
  "stage",
  "dev",
  "test",
  "qa",
  "uat",
  "preprod",
  "beta",
  "demo",
  "api",
  "portal",
  "panel",
  "dashboard",
  "backend",
  "manage",
  "sso",
  "auth",
  "login",
  "git",
  "jenkins",
  "jira",
  "grafana",
  "kibana",
  "db",
  "database",
  "sql",
  "backup",
  "ftp",
  "ssh",
  "remote",
  "secure",
  "old",
  "legacy",
  "dr",
];

export function notableLabel(host: string, domain: string): string | null {
  if (host === domain) return null;
  const prefix = host.slice(0, host.length - domain.length - 1).toLowerCase();
  const firstLabel = prefix.split(".").pop() ?? prefix;
  return NOTABLE_PREFIXES.includes(firstLabel) ? firstLabel : null;
}
