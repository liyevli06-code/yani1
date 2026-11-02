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

export type SourceReport = { name: string; ok: boolean; count: number; error?: string };
export type Discovered = { host: string; sources: string[] };

export type SubdomainsResponse = {
  domain: string;
  tookMs: number;
  total: number;
  subdomains: Discovered[];
  sources: SourceReport[];
};

export type Category = "live" | "client" | "server" | "none" | "pending";

export function categorize(probe?: ProbeResult): Category {
  if (!probe) return "pending";
  if (probe.status === null) return "none";
  if (probe.status >= 500) return "server";
  if (probe.status >= 400) return "client";
  return "live";
}
