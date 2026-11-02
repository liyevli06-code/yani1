"use client";

import type { Dict } from "../i18n";
import { fill } from "../i18n";
import { Discovered, ProbeResult, categorize } from "./types";

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
              <th scope="col" className="py-3 pr-2 text-left text-[13px] font-semibold text-ink-soft">
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
                  <td className="py-3 pr-2 text-xs text-ink-faint">{row.sources.join(", ")}</td>
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
