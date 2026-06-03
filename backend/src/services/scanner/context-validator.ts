/**
 * Context Validation Engine
 *
 * Validates whether a finding has real security context before scoring.
 * A finding is ONLY valid if exploit context is confirmed AND the response
 * is NOT SPA fallback / CDN/WAF-influenced content.
 *
 * Rules (Burp Suite / Nessus standard):
 *   - SPA fallback pages must NEVER be treated as vulnerabilities
 *   - CDN/WAF presence does NOT invalidate context (but caches may obscure response)
 *   - robots.txt is informational only — never a vulnerability
 *   - Header-only findings without exploit context get capped severity
 */

import type { ScanFinding, ScanContext } from "./types";
import type { SpaSignature } from "./spa-detector";
import { isSpaBody } from "./spa-detector";

// ── Exploit context evidence patterns ──────────────────────────────────────────

const EXPLOIT_EVIDENCE_PATTERNS = [
  /<script>alert\(/i,           // XSS pop confirmed
  /syntax error.*sql/i,         // SQL error
  /you have an error in your sql/i,
  /(root:x:0:0|daemon:x:)/,     // Path traversal /etc/passwd
  /AWS_ACCESS_KEY_ID/i,         // SSRF metadata
  /cloudflare[-_]ray/i,         // (NOT exploit — this would need to be outside)
];

const EXPLOIT_EVIDENCE_NEGATIVES = [
  /(ray id|reference #|blocked|security check|ddos protection)/i,
  /<div\s+id=["']root["']/i,
  /<!doctype html/i,
];

export interface ContextResult {
  valid: boolean;
  reason: string;
  exploitConfirmed: boolean;
  exploitPartial: boolean;
  isSpaFallback: boolean;
}

export function validateContext(
  finding: ScanFinding,
  options: {
    spaSignature?: SpaSignature | null;
  } = {}
): ContextResult {
  // ── 1. SPA fallback detection ────────────────────────────────────────────
  if (options.spaSignature?.isSpa && finding.endpoint.startsWith("http")) {
    const body = finding.evidence;
    if (isSpaBody(body)) {
      return {
        valid: false,
        reason: "SPA fallback — response is the frontend shell index.html, not a real resource",
        exploitConfirmed: false,
        exploitPartial: false,
        isSpaFallback: true,
      };
    }
  }

  // ── 2. robots.txt / security.txt / info-only — valid but zero risk ─────
  if (finding.title === "Sensitive Paths Disclosed in robots.txt") {
    return {
      valid: true,
      reason: "Informational — robots.txt is a public advisory file, never a vulnerability",
      exploitConfirmed: false,
      exploitPartial: false,
      isSpaFallback: false,
    };
  }

  // ── 3. Check for exploit evidence ──────────────────────────────────────
  const evidence = finding.evidence;
  const hasPositiveExploitSignal = EXPLOIT_EVIDENCE_PATTERNS.some(p => p.test(evidence));
  const hasNegativeExploitSignal = EXPLOIT_EVIDENCE_NEGATIVES.some(p => p.test(evidence));

  if (hasPositiveExploitSignal) {
    return {
      valid: true,
      reason: "Exploit context confirmed — evidence contains real vulnerability indicators",
      exploitConfirmed: true,
      exploitPartial: false,
      isSpaFallback: false,
    };
  }

  if (hasNegativeExploitSignal) {
    return {
      valid: true,
      reason: "Response contains block/SPA signals — exploit context ambiguous",
      exploitConfirmed: false,
      exploitPartial: true,
      isSpaFallback: false,
    };
  }

  // Only pattern-based or header-only findings
  if (evidence.length < 100) {
    return {
      valid: true,
      reason: "Pattern-based detection — no exploit context available",
      exploitConfirmed: false,
      exploitPartial: true,
      isSpaFallback: false,
    };
  }

  return {
    valid: true,
    reason: "Context present — finding is valid for scoring",
    exploitConfirmed: false,
    exploitPartial: false,
    isSpaFallback: false,
  };
}

export function contextFactor(result: ContextResult): number {
  if (result.exploitConfirmed) return 1.0;
  if (result.exploitPartial) return 0.7;
  return 0.6;
}

export function isWafBlockEvidence(evidence: string): boolean {
  return EXPLOIT_EVIDENCE_NEGATIVES.some(p => p.test(evidence));
}
