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
  cname?: string | null;
  takeover?: TakeoverFinding | null;
  favicon?: FaviconInfo | null;
  robots?: RobotsInfo | null;
};

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
