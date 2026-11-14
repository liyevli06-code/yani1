/**
 * MurmurHash3 (x86, 32-bit) — the same algorithm Shodan and similar tools use to fingerprint
 * a site's favicon, applied here purely so two subdomains that serve byte-identical icons can
 * be recognized as the same underlying app/panel. Returns a signed 32-bit integer, matching
 * the common convention for this hash elsewhere.
 */
export function mmh3x86_32(key: Buffer, seed = 0): number {
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let h1 = seed | 0;
  const len = key.length;
  const roundedEnd = len & ~3;

  for (let i = 0; i < roundedEnd; i += 4) {
    let k1 =
      (key[i] & 0xff) |
      ((key[i + 1] & 0xff) << 8) |
      ((key[i + 2] & 0xff) << 16) |
      ((key[i + 3] & 0xff) << 24);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;
  const rem = len & 3;
  if (rem === 3) k1 ^= (key[roundedEnd + 2] & 0xff) << 16;
  if (rem >= 2) k1 ^= (key[roundedEnd + 1] & 0xff) << 8;
  if (rem >= 1) {
    k1 ^= key[roundedEnd] & 0xff;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0;
}

/** MIME-style base64 (76-char lines) over the raw bytes, then hashed — matches the common
 *  favicon-hash convention so results line up with what other tools report for the same icon. */
export function faviconHash(bytes: Buffer): number {
  const b64 = bytes.toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) lines.push(b64.slice(i, i + 76));
  const mime = lines.join("\n") + "\n";
  return mmh3x86_32(Buffer.from(mime, "utf8"));
}
