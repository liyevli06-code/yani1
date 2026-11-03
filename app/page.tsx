"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import ResultsTable, { SortKey, SortState } from "./components/ResultsTable";
import { downloadCsv, downloadTxt } from "./components/export";
import {
  Category,
  Discovered,
  ProbeResult,
  SourceReport,
  SubdomainsResponse,
  Wildcard,
  categorize,
  notableLabel,
} from "./components/types";
import { Lang, dictionaries, fill } from "./i18n";

type Phase = "idle" | "searching" | "done" | "error";
type Filter = "all" | Exclude<Category, "pending">;

const PAGE_SIZE = 200;
const BATCH_SIZE = 6;
const WORKERS = 4;
const HISTORY_KEY = "subscope-history";
const HISTORY_MAX = 8;

const SAMPLE = [
  { prefix: "api.", status: "200", dot: "bg-ok" },
  { prefix: "blog.", status: "301", dot: "bg-redir" },
  { prefix: "dev.", status: "403", dot: "bg-warn" },
  { prefix: "mail.", status: "—", dot: "bg-ink-faint" },
  { prefix: "staging.", status: "200", dot: "bg-ok" },
];

function Mark() {
  return (
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" aria-hidden="true">
      <rect x="1" y="1" width="24" height="24" rx="5" fill="#0B1F33" />
      <circle cx="7.5" cy="7.5" r="2" fill="#EEF1F3" />
      <path d="M7.5 9.5v9h4.5M7.5 13.5H12" stroke="#EEF1F3" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="15" cy="13.5" r="1.8" fill="#EEF1F3" />
      <circle cx="15" cy="18.5" r="1.8" fill="#C84A04" />
    </svg>
  );
}

export default function Page() {
  const [lang, setLang] = useState<Lang>("en");
  const t = dictionaries[lang];

  const [input, setInput] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [errorKey, setErrorKey] = useState<"invalid" | "noSources" | "generic" | null>(null);
  const [domain, setDomain] = useState("");
  const [tookMs, setTookMs] = useState(0);
  const [cached, setCached] = useState(false);
  const [wildcard, setWildcard] = useState<Wildcard | null>(null);
  const [reports, setReports] = useState<SourceReport[]>([]);
  const [rows, setRows] = useState<Discovered[]>([]);
  const [probes, setProbes] = useState<Record<string, ProbeResult>>({});
  const [checking, setChecking] = useState(false);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [hideEmpty, setHideEmpty] = useState(false);
  const [sort, setSort] = useState<SortState>({ key: "host", dir: "asc" });
  const [visible, setVisible] = useState(PAGE_SIZE);
  const [history, setHistory] = useState<string[]>([]);

  const searchAbort = useRef<AbortController | null>(null);
  const probeAbort = useRef<AbortController | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("subscope-lang");
      if (saved === "en" || saved === "az") return setLang(saved);
    } catch {}
    if (navigator.language?.toLowerCase().startsWith("az")) setLang("az");
  }, []);

  useEffect(() => {
    document.documentElement.lang = lang;
    try {
      localStorage.setItem("subscope-lang", lang);
    } catch {}
  }, [lang]);

  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
      if (Array.isArray(saved)) setHistory(saved.filter((x) => typeof x === "string").slice(0, HISTORY_MAX));
    } catch {}
  }, []);

  function rememberDomain(value: string) {
    setHistory((prev) => {
      const next = [value, ...prev.filter((d) => d !== value)].slice(0, HISTORY_MAX);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      } catch {}
      return next;
    });
  }

  function clearHistory() {
    setHistory([]);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch {}
  }

  async function runProbes(hosts: string[], signal: AbortSignal) {
    const queue = [...hosts];
    setChecking(true);

    const worker = async () => {
      while (queue.length > 0 && !signal.aborted) {
        const batch = queue.splice(0, BATCH_SIZE);
        let results: ProbeResult[] | null = null;
        try {
          const res = await fetch("/api/probe", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ hosts: batch }),
            signal,
          });
          if (res.ok) results = ((await res.json()) as { results: ProbeResult[] }).results;
        } catch {
          if (signal.aborted) return;
        }
        const finished: ProbeResult[] =
          results ??
          batch.map((host) => ({
            host,
            ips: [],
            status: null,
            scheme: null,
            server: null,
            tech: [],
            title: null,
            redirect: null,
            error: "check failed",
          }));
        setProbes((prev) => {
          const next = { ...prev };
          for (const r of finished) next[r.host] = r;
          return next;
        });
      }
    };

    await Promise.all(Array.from({ length: WORKERS }, worker));
    if (probeAbort.current?.signal === signal) setChecking(false);
  }

  async function runSearch(value: string) {
    if (!value || phase === "searching") return;

    searchAbort.current?.abort();
    probeAbort.current?.abort();
    const search = new AbortController();
    searchAbort.current = search;

    setPhase("searching");
    setErrorKey(null);
    setRows([]);
    setProbes({});
    setChecking(false);
    setQuery("");
    setFilter("all");
    setHideEmpty(false);
    setVisible(PAGE_SIZE);
    setWildcard(null);
    setCached(false);

    try {
      const res = await fetch(`/api/subdomains?domain=${encodeURIComponent(value)}`, {
        signal: search.signal,
      });
      const data = (await res.json().catch(() => null)) as SubdomainsResponse | null;
      if (!res.ok || !data) {
        setErrorKey(res.status === 400 ? "invalid" : res.status === 502 ? "noSources" : "generic");
        setPhase("error");
        return;
      }
      setDomain(data.domain);
      setTookMs(data.tookMs);
      setCached(data.cached);
      setWildcard(data.wildcard);
      setReports(data.sources);
      setRows(data.subdomains);
      setPhase("done");
      setInput(data.domain);
      rememberDomain(data.domain);

      if (data.subdomains.length > 0) {
        const probe = new AbortController();
        probeAbort.current = probe;
        void runProbes(
          data.subdomains.map((s) => s.host),
          probe.signal
        );
      }
    } catch {
      if (!search.signal.aborted) {
        setErrorKey("generic");
        setPhase("error");
      }
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void runSearch(input.trim());
  }

  function stopChecking() {
    probeAbort.current?.abort();
    setChecking(false);
  }

  function changeSort(key: SortKey) {
    setSort((prev) => (prev.key === key ? { key, dir: prev.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  }

  const checkedCount = useMemo(() => Object.keys(probes).length, [probes]);

  const stats = useMemo(() => {
    const ips = new Set<string>();
    let responding = 0;
    const counts: Record<Filter, number> = { all: rows.length, live: 0, client: 0, server: 0, none: 0 };
    for (const row of rows) {
      const p = probes[row.host];
      const c = categorize(p);
      if (c !== "pending") counts[c]++;
      if (p) {
        if (p.status !== null) responding++;
        p.ips.forEach((ip) => ips.add(ip));
      }
    }
    return { responding, ips: ips.size, counts };
  }, [rows, probes]);

  const notable = useMemo(
    () =>
      rows
        .map((r) => ({ row: r, label: notableLabel(r.host, domain) }))
        .filter((x): x is { row: Discovered; label: string } => x.label !== null)
        .sort((a, b) => a.row.host.localeCompare(b.row.host)),
    [rows, domain]
  );
  const notableHosts = useMemo(() => new Set(notable.map((n) => n.row.host)), [notable]);

  const view = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = rows.filter((r) => {
      if (q && !r.host.includes(q)) return false;
      const cat = categorize(probes[r.host]);
      if (filter !== "all" && cat !== filter) return false;
      if (hideEmpty && filter !== "none" && cat === "none") return false;
      return true;
    });
    const mul = sort.dir === "asc" ? 1 : -1;
    list.sort((a, b) => {
      // Notable-by-name hosts (admin panels, internal tools, non-prod environments) stay
      // pinned above the rest regardless of the chosen sort, so they're seen first.
      const notableDiff = Number(notableHosts.has(b.host)) - Number(notableHosts.has(a.host));
      if (notableDiff !== 0) return notableDiff;
      const pa = probes[a.host];
      const pb = probes[b.host];
      let result = 0;
      if (sort.key === "host") result = a.host.localeCompare(b.host);
      else if (sort.key === "status") result = (pa ? pa.status ?? 999 : 1000) - (pb ? pb.status ?? 999 : 1000);
      else result = (pa?.ips[0] ?? "~").localeCompare(pb?.ips[0] ?? "~", undefined, { numeric: true });
      return result * mul || a.host.localeCompare(b.host);
    });
    return list;
  }, [rows, probes, query, filter, hideEmpty, sort, notableHosts]);

  const busy = phase === "searching";
  const progress = rows.length ? checkedCount / rows.length : 0;
  const errorText =
    errorKey === "invalid" ? t.errInvalid : errorKey === "noSources" ? t.errNoSources : t.errGeneric;

  const filters: { id: Filter; label: string }[] = [
    { id: "all", label: t.filterAll },
    { id: "live", label: t.filterLive },
    { id: "client", label: t.filterClient },
    { id: "server", label: t.filterServer },
    { id: "none", label: t.filterNone },
  ];

  return (
    <div className="mx-auto max-w-6xl px-5 pb-24 sm:px-8">
      <header className="sticky top-0 z-10 -mx-5 flex items-center justify-between border-b border-ink/10 bg-paper/85 px-5 py-4 backdrop-blur sm:-mx-8 sm:px-8">
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="text-lg font-bold tracking-tight">SubScope</span>
        </div>
        <div className="flex gap-1 rounded-full border border-ink/10 bg-white/70 p-1 text-sm" role="group" aria-label="Language">
          {(["en", "az"] as Lang[]).map((code) => (
            <button
              key={code}
              type="button"
              onClick={() => setLang(code)}
              aria-pressed={lang === code}
              className={`rounded-full px-2.5 py-1 font-semibold transition-colors ${
                lang === code ? "bg-ink text-paper" : "text-ink-soft hover:text-ink"
              }`}
            >
              {code === "en" ? "EN" : "AZ"}
            </button>
          ))}
        </div>
      </header>

      <section className="relative grid items-center gap-12 pb-12 pt-14 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,0.75fr)] lg:pt-20">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -left-24 -top-16 -z-10 h-[26rem] w-[26rem] rounded-full bg-signal/[0.08] blur-[90px]"
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -right-10 top-24 -z-10 hidden h-72 w-72 rounded-full bg-redir/[0.07] blur-[80px] lg:block"
        />
        <div>
          <h1 className="max-w-[16ch] text-[2.6rem] font-extrabold leading-[1.02] tracking-[-0.035em] sm:text-6xl lg:text-[4.25rem]">
            {t.headline}
          </h1>
          <p className="mt-5 max-w-[52ch] text-lg leading-relaxed text-ink-soft">{t.lead}</p>

          <form onSubmit={onSubmit} className="mt-9 flex flex-col gap-3 sm:flex-row" noValidate>
            <label htmlFor="domain" className="sr-only">
              {t.inputLabel}
            </label>
            <input
              id="domain"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={t.placeholder}
              aria-invalid={phase === "error" && errorKey === "invalid"}
              aria-describedby={phase === "error" ? "search-error" : undefined}
              className="h-14 min-w-0 flex-1 rounded-xl border-2 border-ink bg-white px-4 font-mono text-lg shadow-sm placeholder:text-ink-faint/70 focus:shadow-md"
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className="h-14 rounded-xl bg-signal px-7 text-base font-bold text-white shadow-sm transition-colors hover:bg-signal-dark hover:shadow-md disabled:cursor-not-allowed disabled:opacity-60 disabled:shadow-none"
            >
              {busy ? t.searching : t.search}
            </button>
          </form>

          {history.length > 0 && phase !== "searching" && (
            <div className="mt-4 flex flex-wrap items-center gap-1.5 text-[13px]">
              <span className="text-ink-faint">{t.historyLabel}:</span>
              {history.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => {
                    setInput(d);
                    void runSearch(d);
                  }}
                  className="rounded-full border border-ink/15 bg-white/70 px-2.5 py-1 font-mono text-ink-soft transition-colors hover:border-ink hover:text-ink"
                >
                  {d}
                </button>
              ))}
              <button
                type="button"
                onClick={clearHistory}
                className="px-1.5 py-1 text-ink-faint underline underline-offset-2 hover:text-ink-soft"
              >
                {t.historyClear}
              </button>
            </div>
          )}

          <div className="mt-4 min-h-[1.5rem]" aria-live="polite">
            {busy && (
              <div>
                <div className="h-[3px] w-full overflow-hidden rounded-full bg-line">
                  <div className="sweep h-full w-1/4 rounded-full bg-signal" />
                </div>
                <p className="mt-2 text-sm text-ink-soft">{t.searchingNote}</p>
              </div>
            )}
            {phase === "error" && (
              <p id="search-error" role="alert" className="text-sm font-medium text-bad">
                {errorText}
              </p>
            )}
          </div>
        </div>

        <div className="hidden lg:block" aria-hidden="true">
          <div className="rounded-xl border border-line bg-white/60 p-5 shadow-sm">
            <p className="text-sm text-ink-faint">{t.sampleLabel}</p>
            <ul className="mt-3 divide-y divide-line font-mono text-[13.5px]">
              {SAMPLE.map((s) => (
                <li key={s.prefix} className="flex items-center justify-between py-2.5">
                  <span>
                    <span className="font-semibold">{s.prefix}</span>
                    <span className="text-ink-faint">example.com</span>
                  </span>
                  <span className="inline-flex items-center gap-2 text-[13px] font-medium">
                    <span className={`h-2 w-2 rounded-full ${s.dot}`} />
                    {s.status}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {phase === "done" && (
        <section aria-label={domain} className="border-t-2 border-ink pt-7">
          <div className="flex flex-wrap items-stretch justify-between gap-4">
            <div className="flex min-w-0 flex-1 flex-wrap gap-3">
              <div className="flex items-center rounded-xl border border-ink/10 bg-white px-4 py-3 shadow-sm">
                <h2 className="truncate font-mono text-lg font-semibold tracking-tight">{domain}</h2>
              </div>
              {[
                [t.statFound, rows.length.toLocaleString()],
                [t.statResponding, stats.responding.toLocaleString()],
                [t.statIps, stats.ips.toLocaleString()],
                [t.statTime, `${(tookMs / 1000).toFixed(1)} ${t.seconds}`],
              ].map(([label, value]) => (
                <div key={label} className="rounded-xl border border-line bg-white px-4 py-2.5 shadow-sm">
                  <dt className="text-[12px] text-ink-soft">{label}</dt>
                  <dd className="text-xl font-bold tabular-nums tracking-tight">{value}</dd>
                </div>
              ))}
              {cached && (
                <div
                  title={t.cachedNote}
                  className="flex items-center rounded-xl border border-line bg-white px-3 py-2.5 text-[12px] font-medium text-ink-faint shadow-sm"
                >
                  {t.cachedNote}
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={view.length === 0}
                title={t.exportHint}
                onClick={() => downloadCsv(domain, view, probes)}
                className="rounded-xl bg-ink px-4 py-2.5 text-sm font-semibold text-paper shadow-sm transition-colors hover:bg-ink-soft disabled:opacity-50 disabled:shadow-none"
              >
                {t.exportCsv}
              </button>
              <button
                type="button"
                disabled={view.length === 0}
                title={t.exportHint}
                onClick={() => downloadTxt(domain, view)}
                className="rounded-xl border border-ink bg-white px-4 py-2.5 text-sm font-semibold shadow-sm transition-colors hover:bg-ink hover:text-paper disabled:opacity-50 disabled:shadow-none"
              >
                {t.exportTxt}
              </button>
            </div>
          </div>

          <p className="mt-5 flex flex-wrap items-center gap-x-1.5 gap-y-2 text-[13px] leading-relaxed text-ink-soft">
            <span className="font-semibold text-ink">{t.sources}:</span>
            {reports.map((r) =>
              r.ok ? (
                <span
                  key={r.name}
                  className="rounded-full border border-line bg-white px-2.5 py-0.5 font-medium text-ink-soft"
                >
                  {r.name} <span className="font-mono text-ink-faint">{r.count.toLocaleString()}</span>
                </span>
              ) : (
                <span
                  key={r.name}
                  title={r.error}
                  className="rounded-full border border-warn/30 bg-warn/10 px-2.5 py-0.5 font-medium text-warn"
                >
                  {r.name} ({t.sourceFailed})
                </span>
              )
            )}
          </p>

          {wildcard?.detected && (
            <div className="mt-6 rounded-xl border border-bad/30 bg-bad/[0.06] p-5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-bad" aria-hidden="true" />
                <h3 className="text-sm font-bold tracking-tight text-bad">{t.wildcardTitle}</h3>
              </div>
              <p className="mt-1.5 max-w-[68ch] text-[13px] leading-relaxed text-ink-soft">{t.wildcardHint}</p>
            </div>
          )}

          {notable.length > 0 && (
            <div className="mt-7 rounded-xl border border-signal/30 bg-signal/[0.06] p-5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-signal" aria-hidden="true" />
                <h3 className="text-sm font-bold tracking-tight">
                  {t.notableTitle} <span className="font-mono font-normal text-ink-faint">{notable.length}</span>
                </h3>
              </div>
              <p className="mt-1.5 max-w-[62ch] text-[13px] leading-relaxed text-ink-soft">{t.notableHint}</p>
              <ul className="mt-3.5 flex flex-wrap gap-2">
                {notable.map(({ row, label }) => {
                  const probe = probes[row.host];
                  const cat = categorize(probe);
                  const dot =
                    cat === "live"
                      ? "bg-ok"
                      : cat === "client"
                      ? "bg-warn"
                      : cat === "server"
                      ? "bg-bad"
                      : cat === "none"
                      ? "bg-ink-faint"
                      : "bg-line";
                  return (
                    <li key={row.host}>
                      <a
                        href={`https://${row.host}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={t.notableTooltip}
                        className="inline-flex items-center gap-1.5 rounded-full border border-ink/15 bg-white px-3 py-1.5 font-mono text-[13px] font-medium text-ink shadow-sm transition-colors hover:border-signal hover:text-signal"
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${dot}`} aria-hidden="true" />
                        {label}
                        <span className="text-ink-faint">.{domain}</span>
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {rows.length > 0 && (
            <div className="mt-6" aria-live="polite">
              <div className="flex items-center justify-between gap-4 text-sm text-ink-soft">
                <span>
                  {checking
                    ? fill(t.checking, { n: checkedCount, total: rows.length })
                    : checkedCount >= rows.length
                    ? fill(t.checkedAll, { total: rows.length })
                    : fill(t.stopped, { n: checkedCount, total: rows.length })}
                </span>
                {checking && (
                  <button type="button" onClick={stopChecking} className="font-semibold text-ink underline underline-offset-4">
                    {t.stop}
                  </button>
                )}
              </div>
              <div
                className="mt-2 h-[3px] w-full overflow-hidden rounded-full bg-line"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={rows.length}
                aria-valuenow={checkedCount}
              >
                <div
                  className="h-full rounded-full bg-ink transition-[width] duration-300"
                  style={{ width: `${progress * 100}%` }}
                />
              </div>
            </div>
          )}

          {rows.length === 0 ? (
            <p className="py-14 text-ink-soft">{fill(t.empty, { domain })}</p>
          ) : (
            <>
              <div className="mt-7 flex flex-wrap items-center gap-3">
                <label htmlFor="filter" className="sr-only">
                  {t.filterPlaceholder}
                </label>
                <input
                  id="filter"
                  type="search"
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setVisible(PAGE_SIZE);
                  }}
                  placeholder={t.filterPlaceholder}
                  className="h-10 w-full rounded-lg border border-ink/30 bg-white px-3 font-mono text-sm shadow-sm sm:w-64"
                />
                <div className="flex flex-wrap gap-2">
                  {filters.map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      aria-pressed={filter === f.id}
                      onClick={() => {
                        setFilter(f.id);
                        setVisible(PAGE_SIZE);
                      }}
                      className={`rounded-full border px-3.5 py-1.5 text-[13px] font-semibold transition-colors ${
                        filter === f.id
                          ? "border-ink bg-ink text-paper shadow-sm"
                          : "border-ink/20 bg-white text-ink-soft hover:border-ink hover:text-ink"
                      }`}
                    >
                      {f.label}
                      <span className="ml-1.5 font-mono font-normal opacity-70">{stats.counts[f.id]}</span>
                    </button>
                  ))}
                  <button
                    type="button"
                    aria-pressed={hideEmpty}
                    onClick={() => {
                      setHideEmpty((v) => !v);
                      setVisible(PAGE_SIZE);
                    }}
                    className={`rounded-full border px-3.5 py-1.5 text-[13px] font-semibold transition-colors ${
                      hideEmpty
                        ? "border-ink bg-ink text-paper shadow-sm"
                        : "border-ink/20 bg-white text-ink-soft hover:border-ink hover:text-ink"
                    }`}
                  >
                    {t.colHideEmpty}
                  </button>
                </div>
              </div>

              <div className="mt-4">
                {view.length === 0 ? (
                  <p className="py-12 text-ink-soft">{t.noMatch}</p>
                ) : (
                  <div className="overflow-hidden rounded-xl border border-line bg-white shadow-sm">
                    <ResultsTable
                      rows={view}
                      probes={probes}
                      domain={domain}
                      t={t}
                      sort={sort}
                      onSort={changeSort}
                      visible={visible}
                      onMore={() => setVisible((v) => v + PAGE_SIZE)}
                      notableHosts={notableHosts}
                    />
                  </div>
                )}
              </div>
            </>
          )}
        </section>
      )}

      {(phase === "idle" || phase === "error") && (
        <section className="grid gap-5 border-t border-line pt-10 md:grid-cols-3">
          {t.notes.map((note) => (
            <div key={note.title} className="rounded-xl border border-line bg-white/60 p-5">
              <h2 className="text-base font-bold tracking-tight">{note.title}</h2>
              <p className="mt-2 max-w-[44ch] text-[15px] leading-relaxed text-ink-soft">{note.body}</p>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
