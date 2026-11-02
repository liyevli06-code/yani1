import type { Discovered, ProbeResult } from "./types";

function save(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Quotes a CSV cell and neutralizes spreadsheet formulas (a page title could start with "="). */
function cell(value: string | number | null | undefined): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

export function downloadTxt(domain: string, rows: Discovered[]) {
  save(rows.map((r) => r.host).join("\n") + "\n", `${domain}-subdomains.txt`, "text/plain;charset=utf-8");
}

export function downloadCsv(domain: string, rows: Discovered[], probes: Record<string, ProbeResult>) {
  const header = ["subdomain", "status", "scheme", "ip_addresses", "server", "technology", "page_title", "redirect", "found_in"];
  const lines = rows.map((row) => {
    const p = probes[row.host];
    return [
      cell(row.host),
      cell(p?.status ?? (p ? "no response" : "not checked")),
      cell(p?.scheme),
      cell(p?.ips.join(" ")),
      cell(p?.server),
      cell(p?.tech.join(", ")),
      cell(p?.title),
      cell(p?.redirect),
      cell(row.sources.join(", ")),
    ].join(",");
  });
  // The BOM makes Excel read the file as UTF-8.
  save("﻿" + [header.map(cell).join(","), ...lines].join("\r\n") + "\r\n", `${domain}-subdomains.csv`, "text/csv;charset=utf-8");
}
