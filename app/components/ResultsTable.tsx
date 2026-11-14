"use client";

import type { Dict } from "../i18n";
import { fill } from "../i18n";
import { confidenceOf, Discovered, ProbeResult, categorize } from "./types";

function SecurityCell({ probe, t }: { probe?: ProbeResult; t: Dict }) {
  const headers = probe?.securityHeaders;
  const cert = probe?.tlsDaysLeft;

  if (!headers && cert === undefined) return <span className="text-ink-faint">—</span>;

  const score = headers?.present.length ?? 0;
  const headerColor =
    score >= 5 ? "border-ok/40 bg-ok/10 text-ok" : score >= 3 ? "border-warn/40 bg-warn/10 text-warn" : "border-bad/40 bg-bad/10 text-bad";

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {headers && (
        <span
          title={
            headers.missing.length > 0
              ? fill(t.securityMissing, { list: headers.missing.join(", ") })
              : t.securityGood
          }
          className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[11.5px] font-semibold ${headerColor}`}
        >
          {score}/6
        </span>
      )}
      {typeof cert === "number" && (
        <span
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11.5px] font-medium ${
            cert < 0
              ? "border-bad/40 bg-bad/10 text-bad"
              : cert < 14
              ? "border-warn/40 bg-warn/10 text-warn"
              : "border-line text-ink-faint"
          }`}
        >
          {cert < 0 ? t.certExpired : fill(t.certDaysLeft, { n: cert })}
        </span>
      )}
    </div>
  );
}

function SignalsCell({ probe, t }: { probe?: ProbeResult; t: Dict }) {
  const chips: { key: string; label: string; cls: string; title?: string }[] = [];
  if (probe?.takeover?.vulnerable) {
    chips.push({
      key: "takeover",
      label: fill(t.takeoverBadge, { service: probe.takeover.service ?? "?" }),
      cls: "border-bad/40 bg-bad/10 text-bad",
      title: t.takeoverHint,
    });
  }
  if (probe?.robots?.robotsTxt) chips.push({ key: "robots", label: t.robotsYes, cls: "border-line text-ink-faint" });
  if (probe?.robots?.sitemapXml) chips.push({ key: "sitemap", label: t.sitemapYes, cls: "border-line text-ink-faint" });
  if (chips.length === 0) return <span className="text-ink-faint">—</span>;
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {chips.map((c) => (
        <span
          key={c.key}
          title={c.title}
          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${c.cls}`}
        >
          {c.label}
        </span>
      ))}
    </div>
  );
}

function ConfidenceDot({ count, t }: { count: number; t: Dict }) {
  const level = confidenceOf(count);
  const cls = level === "high" ? "bg-ok" : level === "medium" ? "bg-warn" : "bg-ink-faint";
  const label = level === "high" ? t.confidenceHigh : level === "medium" ? t.confidenceMedium : t.confidenceLow;
  return (
    <span title={`${label} — ${t.confidenceHint}`} className="inline-flex items-center gap-1.5">
      <span className={`h-1.5 w-1.5 rounded-full ${cls}`} aria-hidden="true" />
    </span>
  );
}

export type SortKey = "host" | "status" | "ip";
export type SortState = { key: SortKey; dir: "asc" | "desc" };

function StatusCell({ probe, t }: { probe?: ProbeResult; t: Dict }) {
  const category = categorize(probe);
  if (category === "pending") {
    return <span className="text-ink-faint">{t.pending}…</span>;
  }
  if (category === "none") {
    return (
      <span className="text-ink-faint" title={probe?.error}>
        {t.noResponse}
      </span>
    );
  }
  const status = probe!.status as number;
  const color =
    status >= 500 ? "bg-bad" : status >= 400 ? "bg-warn" : status >= 300 ? "bg-redir" : "bg-ok";
  return (
    <span
      className="inline-flex items-center gap-2 font-mono text-[13px] font-medium"
      title={probe?.redirect ? `→ ${probe.redirect}` : undefined}
    >
      <span className={`h-2 w-2 rounded-full ${color}`} aria-hidden="true" />
      {status}
    </span>
  );
}

function HostCell({
  host,
  domain,
  notable,
  notableTooltip,
}: {
  host: string;
  domain: string;
  notable: boolean;
  notableTooltip: string;
}) {
  const prefix = host === domain ? "" : host.slice(0, host.length - domain.length);
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[13.5px]">
      {notable && (
        <span
          title={notableTooltip}
          className="h-1.5 w-1.5 shrink-0 rounded-full bg-signal"
          aria-label={notableTooltip}
        />
      )}
      <span>
        <span className="font-semibold text-ink">{prefix}</span>
        <span className={prefix ? "text-ink-faint" : "font-semibold text-ink"}>{domain}</span>
      </span>
    </span>
  );
}

export default function ResultsTable({
  rows,
  probes,
  domain,
  t,
  sort,
  onSort,
  visible,
  onMore,
  notableHosts,
  ipInfo,
}: {
  rows: Discovered[];
  probes: Record<string, ProbeResult>;
  domain: string;
  t: Dict;
  sort: SortState;
  onSort: (key: SortKey) => void;
  visible: number;
  onMore: () => void;
  notableHosts: Set<string>;
  ipInfo?: Record<string, { org: string | null; country: string | null }>;
}) {
  const shown = rows.slice(0, visible);
  const remaining = rows.length - shown.length;

  const header = (key: SortKey, label: string, first?: boolean) => (
    <th
      scope="col"
      aria-sort={sort.key === key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
      className={`whitespace-nowrap py-3 pr-6 text-left text-[13px] font-semibold text-ink-soft ${
        first ? "pl-5" : ""
      }`}
    >
      <button
        type="button"
        onClick={() => onSort(key)}
        className="inline-flex items-center gap-1.5 hover:text-ink"
      >
        {label}
        <span aria-hidden="true" className={sort.key === key ? "text-signal" : "text-line"}>
          {sort.key === key && sort.dir === "desc" ? "▼" : "▲"}
        </span>
      </button>
    </th>
  );

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse">
          <thead className="border-b border-line bg-paper/60">
            <tr>
              {header("host", t.colHost, true)}
              {header("status", t.colStatus)}
              {header("ip", t.colIp)}
              <th scope="col" className="py-3 pr-6 text-left text-[13px] font-semibold text-ink-soft">
                {t.colTech}
              </th>
              <th scope="col" className="py-3 pr-6 text-left text-[13px] font-semibold text-ink-soft">
                {t.colAsn}
              </th>
              <th scope="col" className="py-3 pr-6 text-left text-[13px] font-semibold text-ink-soft">
                {t.colSecurity}
              </th>
              <th scope="col" className="py-3 pr-6 text-left text-[13px] font-semibold text-ink-soft">
                {t.colSignals}
              </th>
              <th scope="col" className="py-3 pr-2 text-left text-[13px] font-semibold text-ink-soft" title={t.confidenceHint}>
                {t.colSources}
              </th>
              <th scope="col" className="w-8 py-3 pr-5" aria-hidden="true" />
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => {
              const probe = probes[row.host];
              const tech = probe?.tech.length ? probe.tech.join(", ") : probe?.server ?? "";
              const extraIps = probe && probe.ips.length > 1 ? ` +${probe.ips.length - 1}` : "";
              const isNotable = notableHosts.has(row.host);
              return (
                <tr
                  key={row.host}
                  className={`border-b border-line/70 align-top transition-colors last:border-b-0 hover:bg-paper/70 ${
                    isNotable ? "bg-signal/[0.05]" : ""
                  }`}
                >
                  <td className="py-3 pl-5 pr-6">
                    <HostCell
                      host={row.host}
                      domain={domain}
                      notable={isNotable}
                      notableTooltip={t.notableTooltip}
                    />
                    {probe?.title ? (
                      <div className="mt-0.5 max-w-[34ch] truncate text-xs text-ink-faint" title={probe.title}>
                        {probe.title}
                      </div>
                    ) : null}
                  </td>
                  <td className="py-3 pr-6">
                    <StatusCell probe={probe} t={t} />
                  </td>
                  <td className="py-3 pr-6 font-mono text-[13px] text-ink-soft">
                    {probe?.ips[0] ? `${probe.ips[0]}${extraIps}` : <span className="text-ink-faint">—</span>}
                  </td>
                  <td className="py-3 pr-6 text-sm text-ink-soft">
                    {tech || <span className="text-ink-faint">—</span>}
                  </td>
                  <td className="py-3 pr-6 text-xs text-ink-soft">
                    {(() => {
                      const info = probe?.ips[0] ? ipInfo?.[probe.ips[0]] : undefined;
                      if (!info || (!info.org && !info.country)) return <span className="text-ink-faint">—</span>;
                      return (
                        <span>
                          {info.org ? <span className="block truncate max-w-[18ch]" title={info.org}>{info.org}</span> : null}
                          {info.country ? <span className="text-ink-faint">{info.country}</span> : null}
                        </span>
                      );
                    })()}
                  </td>
                  <td className="py-3 pr-6">
                    <SecurityCell probe={probe} t={t} />
                  </td>
                  <td className="py-3 pr-6">
                    <SignalsCell probe={probe} t={t} />
                  </td>
                  <td className="py-3 pr-2 text-xs text-ink-faint">
                    <span className="inline-flex items-center gap-1.5">
                      <ConfidenceDot count={row.sources.length} t={t} />
                      {row.sources.join(", ")}
                    </span>
                  </td>
                  <td className="py-2.5 pr-5 text-right">
                    <a
                      href={`https://${row.host}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      aria-label={fill(t.open, { host: row.host })}
                      className="inline-flex h-7 w-7 items-center justify-center rounded-md text-ink-faint transition-colors hover:bg-ink hover:text-paper"
                    >
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                        <path d="M5 2.5H2.5v9h9V9M8 2.5h3.5V6M11.5 2.5 6.5 7.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </a>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {remaining > 0 && (
        <div className="border-t border-line bg-paper/40 p-4 text-center">
          <button
            type="button"
            onClick={onMore}
            className="rounded-lg border border-ink px-4 py-2 text-sm font-semibold transition-colors hover:bg-ink hover:text-paper"
          >
            {fill(t.showMore, { n: Math.min(200, remaining) })}
          </button>
        </div>
      )}
    </div>
  );
}
