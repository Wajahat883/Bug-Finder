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

// Titles that are a DEFINITIVE match — no additional heuristics needed.
// When a response carries one of these titles the result is certain (confidence 1.0).
const DEFINITIVE_SPA_TITLES = [
  "tasklytics",
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

// ── SPA fallback check result ─────────────────────────────────────────────────

export interface SpaFallbackResult {
  /** true when this response is a SPA shell, not the real resource */
  isFallback: boolean;
  /** human-readable reason for the classification */
  reason: string;
  /**
   * 1.0 = certain (definitive title match e.g. "Tasklytics")
   * 0.9 = high confidence (baseline title + length match)
   * 0.7 = heuristic (mount-point / bundler chunk patterns)
   */
  confidence: number;
}

const NOT_FALLBACK: SpaFallbackResult = { isFallback: false, reason: "", confidence: 0 };

/**
 * Core check: returns a SpaFallbackResult describing whether `body` is a SPA
 * fallback response and how certain we are.
 *
 * Three detection layers (most → least specific):
 *   1. Definitive title match  — "Tasklytics" etc. → confidence 1.0, certain FP.
 *   2. Baseline comparison     — title + body-length proximity → confidence 0.9.
 *   3. Heuristic               — mount-point / bundler patterns → confidence 0.7.
 */
export function isSpaFallbackResponse(body: string, signature?: SpaSignature | null): boolean {
  return checkSpaFallbackBody(body, signature).isFallback;
}

export function checkSpaFallbackBody(
  body: string,
  signature?: SpaSignature | null,
): SpaFallbackResult {
  const lower = body.slice(0, 4000).toLowerCase();
  const hasDoctype = lower.includes("<!doctype html");

  // Layer 1: definitive title match — no ambiguity, confidence 1.0
  if (hasDoctype) {
    const title = extractTitle(body);
    if (title && DEFINITIVE_SPA_TITLES.some(t => title === t || title.includes(t))) {
      return {
        isFallback: true,
        reason: `SPA fallback detected — response contains <!doctype html> and <title>${title}</title> (definitive SPA shell)`,
        confidence: 1.0,
      };
    }
  }

  // Layer 2: baseline comparison
  if (signature?.isSpa) {
    const title = extractTitle(body);
    const titleMatch = signature.title.length > 0 && title === signature.title;
    const lengthClose = Math.abs(body.length - signature.bodyLength) / Math.max(signature.bodyLength, 1) < 0.10;
    if (titleMatch && (lengthClose || signature.title.length > 3)) {
      return {
        isFallback: true,
        reason: `SPA fallback detected — response title "${title}" matches baseline SPA signature`,
        confidence: 0.9,
      };
    }
  }

  // Layer 3: structural heuristics
  if (isSpaBody(body)) {
    return {
      isFallback: true,
      reason: "SPA fallback detected — response body contains SPA mount-point or bundler chunk patterns",
      confidence: 0.7,
    };
  }

  return NOT_FALLBACK;
}

/**
 * Full convenience check for scanner modules.
 * Incorporates Content-Type gating: only HTML responses can be SPA fallbacks.
 *
 * Usage:
 *   const body = await res.text();
 *   const spa = checkSpaFallback(res, body, ctx.spaSignature);
 *   if (spa.isFallback) { ctx.emit(...); continue; }
 */
export function checkSpaFallback(
  res: Response | null,
  body: string,
  signature?: SpaSignature | null,
): SpaFallbackResult {
  if (!res) return NOT_FALLBACK;
  const ct = res.headers.get("content-type") ?? "";
  // Only HTML responses can be SPA fallbacks — JSON/binary probes are never SPAs
  if (ct !== "" && !ct.includes("text/html")) return NOT_FALLBACK;
  return checkSpaFallbackBody(body, signature);
}

/**
 * Boolean shorthand — backwards-compatible with existing callers.
 */
export function isSpaFallback(
  res: Response | null,
  body: string,
  signature?: SpaSignature | null,
): boolean {
  return checkSpaFallback(res, body, signature).isFallback;
}

/**
 * Annotates a finding that passed the initial scanner but was caught by the
 * post-scan SPA re-verification pass in index.ts.
 * Sets validation_status: "false_positive" and confidence: 1.0 (certain FP).
 */
export function annotateSpaFalsePositive(
  evidence: string,
  endpointUrl: string,
): { evidence: string; confidence: number; validation_status: string; fp_reason: string } {
  return {
    evidence: `[SPA-FALLBACK DETECTED]\nEndpoint "${endpointUrl}" returned the SPA index.html shell instead of a real resource. This is a false positive — the route does not exist and the application served its client-side entry point.\n\nOriginal evidence:\n${evidence}`,
    confidence: 1.0,
    validation_status: "false_positive",
    fp_reason: "SPA fallback detected",
  };
}
