type Entry<T> = { value: T; expiresAt: number };

const store = new Map<string, Entry<unknown>>();
let lastSweep = 0;

/**
 * Tiny in-memory TTL cache. On serverless hosts each warm instance keeps its own copy,
 * so this cuts repeat calls to the free lookup APIs without being a hard global cache.
 */
export function cacheGet<T>(key: string): T | null {
  const entry = store.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    store.delete(key);
    return null;
  }
  return entry.value as T;
}

export function cacheSet<T>(key: string, value: T, ttlMs: number): void {
  const now = Date.now();
  if (now - lastSweep > 60_000) {
    lastSweep = now;
    for (const [k, e] of store) if (e.expiresAt <= now) store.delete(k);
  }
  store.set(key, { value, expiresAt: now + ttlMs });
}
