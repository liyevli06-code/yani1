export type DomainExpiry = {
  expiresAt: string | null;
  registrar: string | null;
  error?: string;
};

type RdapEvent = { eventAction?: string; eventDate?: string };
type RdapVcardField = [string, Record<string, unknown>, string, ...unknown[]];
type RdapEntity = {
  roles?: string[];
  vcardArray?: [string, RdapVcardField[]];
  publicIds?: { type?: string; identifier?: string }[];
};
type RdapDomain = { events?: RdapEvent[]; entities?: RdapEntity[] };
type RdapBootstrap = { services?: [string[], string[], ...unknown[]][] };

const REQUEST_HEADERS = {
  // Several RDAP servers sit behind bot-protection that rejects requests with no (or a
  // default) User-Agent, so this has to be set explicitly on every call here.
  "user-agent": "SubScope/1.0 (+subdomain research tool)",
  accept: "application/rdap+json, application/json",
};

function registrarName(entities: RdapEntity[] | undefined): string | null {
  const registrar = entities?.find((e) => e.roles?.includes("registrar"));
  if (!registrar) return null;
  const fn = registrar.vcardArray?.[1]?.find((field) => field[0] === "fn");
  if (fn && typeof fn[3] === "string") return fn[3];
  return registrar.publicIds?.[0]?.identifier ?? null;
}

function expiryFrom(data: RdapDomain): DomainExpiry | null {
  const expiresAt = data.events?.find((e) => e.eventAction === "expiration")?.eventDate ?? null;
  if (!expiresAt) return null;
  return { expiresAt, registrar: registrarName(data.entities) };
}

/** Fetches one RDAP domain record. Returns null for a clean 404 (domain not registered there). */
async function fetchRdapDomain(url: string): Promise<RdapDomain | null> {
  const res = await fetch(url, {
    headers: REQUEST_HEADERS,
    signal: AbortSignal.timeout(10_000),
    cache: "no-store",
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as RdapDomain;
}

// IANA's own bootstrap registry maps each TLD to the RDAP server(s) that are authoritative
// for it. It changes rarely, so one process keeps it in memory rather than fetching it per
// lookup. This is the fallback path used when rdap.org itself can't be reached.
let bootstrap: RdapBootstrap | null = null;
let bootstrapFetchedAt = 0;
const BOOTSTRAP_TTL_MS = 24 * 60 * 60_000;

async function rdapServersFor(tld: string): Promise<string[]> {
  if (!bootstrap || Date.now() - bootstrapFetchedAt > BOOTSTRAP_TTL_MS) {
    const res = await fetch("https://data.iana.org/rdap/dns.json", {
      headers: REQUEST_HEADERS,
      signal: AbortSignal.timeout(8_000),
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`bootstrap HTTP ${res.status}`);
    bootstrap = (await res.json()) as RdapBootstrap;
    bootstrapFetchedAt = Date.now();
  }
  const match = bootstrap?.services?.find(([tlds]) => tlds.includes(tld));
  return match?.[1] ?? [];
}

/**
 * Looks up when the domain's own registration expires (the yearly/multi-year renewal with
 * the registrar) via RDAP, the modern JSON replacement for raw WHOIS text.
 *
 * Tries rdap.org first — a public redirector that resolves the right registry for any TLD
 * in one request — then falls back to querying that TLD's authoritative RDAP server
 * directly, found via IANA's bootstrap registry, in case rdap.org is unreachable or a
 * particular registry isn't listed there.
 */
export async function lookupDomainExpiry(domain: string): Promise<DomainExpiry> {
  let lastError = "lookup failed";

  try {
    const data = await fetchRdapDomain(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
    if (data) {
      const expiry = expiryFrom(data);
      if (expiry) return expiry;
      lastError = "no expiration date in registry record";
    } else {
      lastError = "not found in registry";
    }
  } catch (err) {
    lastError = err instanceof Error ? err.message : "rdap.org lookup failed";
  }

  try {
    const tld = domain.split(".").pop()?.toLowerCase() ?? "";
    const servers = await rdapServersFor(tld);
    if (servers.length === 0) {
      return { expiresAt: null, registrar: null, error: `no RDAP server listed for .${tld}` };
    }
    for (const base of servers) {
      try {
        const url = `${base.replace(/\/$/, "")}/domain/${encodeURIComponent(domain)}`;
        const data = await fetchRdapDomain(url);
        if (data) {
          const expiry = expiryFrom(data);
          if (expiry) return expiry;
        }
      } catch {
        // Try the next server IANA lists for this TLD, if any.
      }
    }
  } catch (err) {
    lastError = err instanceof Error ? err.message : "bootstrap lookup failed";
  }

  return { expiresAt: null, registrar: null, error: lastError };
}
