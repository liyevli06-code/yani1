import { fetchJson, fetchText } from "./net";

export type SourceName =
  | "crt.sh"
  | "HackerTarget"
  | "AlienVault OTX"
  | "Anubis"
  | "CertSpotter"
  | "urlscan.io"
  | "RapidDNS"
  | "VirusTotal"
  | "SecurityTrails";

export type SourceReport = {
  name: SourceName;
  ok: boolean;
  count: number;
  error?: string;
};

type SourceResult = { hosts: string[] };

type Source = {
  name: SourceName;
  enabled: () => boolean;
  run: (domain: string) => Promise<SourceResult>;
};

const SOURCES: Source[] = [
  {
    // Certificate Transparency logs
    name: "crt.sh",
    enabled: () => true,
    run: async (domain) => {
      const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;
      let rows: { name_value: string }[];
      try {
        rows = await fetchJson<{ name_value: string }[]>(url, {}, 22000);
      } catch {
        // crt.sh is often overloaded; one retry usually succeeds.
        rows = await fetchJson<{ name_value: string }[]>(url, {}, 22000);
      }
      return { hosts: rows.flatMap((r) => r.name_value.split("\n")) };
    },
  },
  {
    // Certificate Transparency, independent of crt.sh
    name: "CertSpotter",
    enabled: () => true,
    run: async (domain) => {
      const rows = await fetchJson<{ dns_names?: string[] }[]>(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(
          domain
        )}&include_subdomains=true&expand=dns_names`,
        {},
        20000
      );
      return { hosts: (Array.isArray(rows) ? rows : []).flatMap((r) => r.dns_names ?? []) };
    },
  },
  {
    // Hostnames seen by urlscan.io scans
    name: "urlscan.io",
    enabled: () => true,
    run: async (domain) => {
      const data = await fetchJson<{
        results?: { page?: { domain?: string }; task?: { domain?: string } }[];
      }>(`https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(domain)}&size=100`);
      return {
        hosts: (data.results ?? []).flatMap((r) => [r.page?.domain ?? "", r.task?.domain ?? ""]),
      };
    },
  },
  {
    name: "RapidDNS",
    enabled: () => true,
    run: async (domain) => {
      const html = await fetchText(
        `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`,
        20000
      );
      const escaped = domain.replace(/\./g, "\\.");
      const matches = html.match(new RegExp(`[a-z0-9][a-z0-9._-]*\\.${escaped}`, "gi")) ?? [];
      return { hosts: matches };
    },
  },
  {
    name: "HackerTarget",
    enabled: () => true,
    run: async (domain) => {
      const text = await fetchText(
        `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`
      );
      if (/^error|API count exceeded/i.test(text)) throw new Error(text.slice(0, 80));
      return { hosts: text.split("\n").map((line) => line.split(",")[0]) };
    },
  },
  {
    name: "AlienVault OTX",
    enabled: () => true,
    run: async (domain) => {
      const data = await fetchJson<{ passive_dns?: { hostname: string }[] }>(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`
      );
      return { hosts: (data.passive_dns ?? []).map((r) => r.hostname) };
    },
  },
  {
    name: "Anubis",
    enabled: () => true,
    run: async (domain) => {
      const data = await fetchJson<string[]>(
        `https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`
      );
      return { hosts: Array.isArray(data) ? data : [] };
    },
  },
  {
    name: "VirusTotal",
    enabled: () => Boolean(process.env.VIRUSTOTAL_API_KEY),
    run: async (domain) => {
      const hosts: string[] = [];
      let url: string | null = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(
        domain
      )}/subdomains?limit=40`;
      for (let page = 0; url && page < 5; page++) {
        const data: { data?: { id: string }[]; links?: { next?: string } } = await fetchJson(url, {
          headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY as string },
        });
        hosts.push(...(data.data ?? []).map((d) => d.id));
        url = data.links?.next ?? null;
      }
      return { hosts };
    },
  },
  {
    name: "SecurityTrails",
    enabled: () => Boolean(process.env.SECURITYTRAILS_API_KEY),
    run: async (domain) => {
      const data = await fetchJson<{ subdomains?: string[] }>(
        `https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`,
        { headers: { apikey: process.env.SECURITYTRAILS_API_KEY as string } }
      );
      return { hosts: (data.subdomains ?? []).map((s) => `${s}.${domain}`) };
    },
  },
];

export type Discovered = { host: string; sources: SourceName[] };

export async function discoverSubdomains(domain: string) {
  const active = SOURCES.filter((s) => s.enabled());
  const settled = await Promise.allSettled(active.map((s) => s.run(domain)));

  const found = new Map<string, Set<SourceName>>();
  const reports: SourceReport[] = [];

  settled.forEach((result, i) => {
    const name = active[i].name;
    if (result.status === "rejected") {
      const message =
        result.reason instanceof Error
          ? result.reason.name === "AbortError"
            ? "timed out"
            : result.reason.message
          : "failed";
      reports.push({ name, ok: false, count: 0, error: message });
      return;
    }
    let count = 0;
    for (const raw of result.value.hosts) {
      const host = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (!host || host.includes("*") || host.includes(" ")) continue;
      if (host !== domain && !host.endsWith(`.${domain}`)) continue;
      if (!found.has(host)) found.set(host, new Set());
      found.get(host)!.add(name);
      count++;
    }
    reports.push({ name, ok: true, count });
  });

  const hosts: Discovered[] = [...found.entries()]
    .map(([host, sources]) => ({ host, sources: [...sources] }))
    .sort((a, b) => a.host.localeCompare(b.host));

  return { hosts, reports };
}
