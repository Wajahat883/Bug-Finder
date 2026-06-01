/**
 * SPA Fallback Detector
 *
 * Single-Page Applications (React, Vue, Angular) serve the same index.html for
 * every unknown route. Without this check, scanners report fake vulnerabilities
 * on non-existent endpoints because the HTML response contains the injected
 * probe payload reflected inside script/meta tags of the shell page.
 *
 * Usage:
 *   const sig  = await fetchSpaSignature(targetUrl);   // once at scan start
 *   const isFP = isSpaFallbackResponse(body, sig);     // per probe
 */

import { logger } from "../../lib/logger";

// ── SPA Signature ─────────────────────────────────────────────────────────────

export interface SpaSignature {
  /** Extracted <title> text from the baseline response */
  title: string;
  /** Body byte-length of the baseline response */
  bodyLength: number;
  /** true if the root response itself looks like a SPA shell */
  isSpa: boolean;
}

// Known SPA framework mount-point patterns
const SPA_MOUNT_PATTERNS = [
  /<div\s+id=["']root["']/i,
  /<div\s+id=["']app["']/i,
  /<div\s+id=["']__next["']/i,     // Next.js
  /<div\s+id=["']nuxt["']/i,       // Nuxt.js
  /<app-root>/i,                    // Angular
];

// Bundler-generated script chunks (webpack, vite, rollup)
const BUNDLER_SCRIPT_PATTERN = /src=["'][^"']*\/(main|index|app|bundle|chunk)[.-][a-z0-9]{6,}\.(js|mjs)["']/i;

// Well-known SPA title strings — extend as needed
const KNOWN_SPA_TITLES = [
  "tasklytics", "react app", "vue app", "angular app",
  "my app", "vite app", "next.js app", "create react app",
];

/**
 * Lightweight body-only heuristic — usable without a baseline fetch.
 * Returns true when the response body looks like a SPA shell page.
 */
export function isSpaBody(body: string): boolean {
  const lower = body.slice(0, 4000).toLowerCase();
  if (!lower.includes("<!doctype html")) return false;

  // Must have at least one strong SPA signal
  const hasMount   = SPA_MOUNT_PATTERNS.some(p => p.test(body));
  const hasChunk   = BUNDLER_SCRIPT_PATTERN.test(body);
  const hasKnownTitle = KNOWN_SPA_TITLES.some(t => lower.includes(`<title>${t}`));

  return hasMount || hasChunk || hasKnownTitle;
}

/**
 * Extracts <title> text from an HTML body (first 2 KB only).
 */
export function extractTitle(body: string): string {
  const m = body.slice(0, 2000).match(/<title[^>]*>([^<]{0,200})<\/title>/i);
  return m?.[1]?.trim().toLowerCase() ?? "";
}

/**
 * Fetch the SPA baseline signature from the target root URL.
 * Call once before the scan pipeline starts; store result in ScanContext.
 * Returns null on network error — callers should treat null as "unknown, skip SPA check".
 */
export async function fetchSpaSignature(targetUrl: string): Promise<SpaSignature | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      headers: { Accept: "text/html" },
    }).finally(() => clearTimeout(timer));

    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("text/html")) {
      // Root is not HTML — almost certainly a pure API, no SPA
      return { title: "", bodyLength: 0, isSpa: false };
    }

    const body = await res.text();
    const sig: SpaSignature = {
      title: extractTitle(body),
      bodyLength: body.length,
      isSpa: isSpaBody(body),
    };
    logger.info({ title: sig.title, bodyLength: sig.bodyLength, isSpa: sig.isSpa }, "[SPA] Baseline signature captured");
    return sig;
  } catch (err) {
    logger.warn({ err }, "[SPA] Failed to fetch baseline — SPA check disabled for this scan");
    return null;
  }
}

/**
 * Core check: returns true when `body` is a SPA fallback response.
 *
 * Two detection layers:
 *   1. Baseline match — if signature is provided, check title + body-length proximity.
 *   2. Heuristic — even without a baseline, detect obvious SPA shells.
 *
 * The length tolerance (±10%) handles gzip/chunked variation and dynamic injections.
 */
export function isSpaFallbackResponse(body: string, signature?: SpaSignature | null): boolean {
  // Layer 1: baseline comparison (most accurate)
  if (signature?.isSpa) {
    const titleMatch  = signature.title.length > 0 && extractTitle(body) === signature.title;
    const lengthClose = Math.abs(body.length - signature.bodyLength) / Math.max(signature.bodyLength, 1) < 0.10;
    if (titleMatch && lengthClose) return true;
    // Title alone is enough when the baseline confirmed SPA and titles are non-trivial
    if (titleMatch && signature.title.length > 3) return true;
  }

  // Layer 2: heuristic (always runs as a safety net)
  return isSpaBody(body);
}

/**
 * Convenience wrapper for scanner modules:
 * returns true when the HTTP response appears to be a SPA fallback.
 *
 * Usage in scanner modules:
 *   const body = await res.text();
 *   if (isSpaFallback(res, body, ctx.spaSignature)) { ctx.emit(...); continue; }
 */
export function isSpaFallback(
  res: Response | null,
  body: string,
  signature?: SpaSignature | null,
): boolean {
  if (!res) return false;
  const ct = res.headers.get("content-type") ?? "";
  // Only HTML responses can be SPA fallbacks — skip JSON/binary probes
  if (!ct.includes("text/html") && ct !== "") return false;
  return isSpaFallbackResponse(body, signature);
}

/**
 * Annotates a finding's evidence string with a SPA-fallback warning.
 * The confidence value is downgraded to 0.05 (near-certain FP).
 */
export function annotateSpaFalsePositive(
  evidence: string,
  endpointUrl: string,
): { evidence: string; confidence: number; validation_status: string } {
  return {
    evidence: `[SPA-FALLBACK DETECTED]\nEndpoint "${endpointUrl}" returned the SPA index.html shell instead of a real API response. This finding is likely a false positive — the route does not exist and the app served its client-side entry point.\n\nOriginal evidence:\n${evidence}`,
    confidence: 0.05,
    validation_status: "false_positive",
  };
}
