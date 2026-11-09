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

function registrarName(entities: RdapEntity[] | undefined): string | null {
  const registrar = entities?.find((e) => e.roles?.includes("registrar"));
  if (!registrar) return null;
  const fn = registrar.vcardArray?.[1]?.find((field) => field[0] === "fn");
  if (fn && typeof fn[3] === "string") return fn[3];
  return registrar.publicIds?.[0]?.identifier ?? null;
}

/**
 * Looks up when the domain's registration itself expires (the yearly/multi-year renewal
 * with the registrar), via RDAP — the modern, JSON replacement for raw WHOIS. rdap.org
 * resolves the right registry for any TLD and redirects there, so one request covers all.
 */
export async function lookupDomainExpiry(domain: string): Promise<DomainExpiry> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: "application/rdap+json, application/json" },
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    });
    if (res.status === 404) {
      return { expiresAt: null, registrar: null, error: "not found in registry" };
    }
    if (!res.ok) {
      return { expiresAt: null, registrar: null, error: `HTTP ${res.status}` };
    }
    const data = (await res.json()) as RdapDomain;
    const expiry = data.events?.find((e) => e.eventAction === "expiration")?.eventDate ?? null;
    return { expiresAt: expiry, registrar: registrarName(data.entities) };
  } catch (err) {
    return { expiresAt: null, registrar: null, error: err instanceof Error ? err.message : "lookup failed" };
  }
}
