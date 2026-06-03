/**
 * False Positive Reduction Engine
 *
 * Centralized FP reduction logic consumed by scanner modules and the orchestrator.
 * Provides:
 *   - Case-insensitive HTTP header parsing (RFC 7230 §3.2 compliance)
 *   - SPA fallback annotation for fake admin panel / sensitive path findings
 *   - robots.txt classification as INFORMATIONAL only (never a vulnerability)
 *   - WAF/CDN context injection for confidence reduction
 *   - Context-aware validation (is there actual exploit evidence?)
 *   - Duplicate suppression metadata
 */

import { rfcHeaderContains, rfcHeaderGet } from "./normalize-engine";
import type { ScanFinding } from "./types";

export interface FpContext {
  wafDetected: string[];
  cdnDetected: string[];
  isSpa: boolean;
  hasExploitContext: boolean;
  probeResponseStatus: number;
  probeResponseBody: string;
}

export function createFpContext(): FpContext {
  return {
    wafDetected: [],
    cdnDetected: [],
    isSpa: false,
    hasExploitContext: true,
    probeResponseStatus: 200,
    probeResponseBody: "",
  };
}

const INFO_ONLY_CATEGORIES = new Set([
  "robots.txt",
  "security.txt",
  "WAF detection",
  "CDN detection",
  "Technology fingerprint",
]);

const INFO_ONLY_TITLES = new Set([
  "Sensitive Paths Disclosed in robots.txt",
  "Security.txt Not Configured",
]);

export function isInformationalOnly(finding: ScanFinding): boolean {
  if (finding.severity === "info") return true;
  if (INFO_ONLY_TITLES.has(finding.title)) return true;
  if (finding.category === "Infrastructure" && finding.cvss_score === 0) return true;
  return false;
}

export function shouldDowngradeToInfo(finding: ScanFinding): boolean {
  return isInformationalOnly(finding);
}

export function classifyRobotsTxtFinding(
  rawFinding: ScanFinding
): ScanFinding {
  return {
    ...rawFinding,
    severity: "info",
    cvss_score: 0,
    description:
      rawFinding.description +
      " NOTE: robots.txt is a public advisory file — its contents are NOT a security vulnerability. " +
      "This finding is informational only.",
    confidence: 1.0,
  };
}

export function checkCaseInsensitiveHeader(
  headers: Headers,
  headerName: string
): string | null {
  return rfcHeaderGet(
    Object.fromEntries(
      Array.from((headers as unknown as Iterable<[string, string]>)).map(
        ([k, v]) => [k.toLowerCase(), v]
      )
    ),
    headerName
  );
}

export function headerHasDirectiveCi(
  headers: Headers,
  headerName: string,
  directive: string
): boolean {
  return rfcHeaderContains(
    Object.fromEntries(
      Array.from((headers as unknown as Iterable<[string, string]>)).map(
        ([k, v]) => [k.toLowerCase(), v]
      )
    ),
    headerName,
    directive
  );
}

export interface FpReductionResult {
  shouldSuppress: boolean;
  adjustedConfidence: number;
  adjustedSeverity: ScanFinding["severity"];
  fpReason: string | null;
}

export function reduceFalsePositive(
  finding: ScanFinding,
  fpCtx: FpContext
): FpReductionResult {
  let confidence = finding.confidence;
  let severity = finding.severity;
  const reasons: string[] = [];

  if (shouldDowngradeToInfo(finding)) {
    severity = "info";
    confidence = Math.min(confidence, 0.3);
    reasons.push("Informational classification — no security risk");
  }

  if (fpCtx.isSpa && !fpCtx.hasExploitContext) {
    confidence = Math.min(confidence, 0.4);
    reasons.push("SPA fallback detected — response is frontend shell, not real resource");
    if (finding.category === "Information Disclosure") {
      return {
        shouldSuppress: true,
        adjustedConfidence: 0,
        adjustedSeverity: "info",
        fpReason: "SPA fallback — endpoint returned SPA index.html shell (false positive)",
      };
    }
  }

  if (fpCtx.wafDetected.length > 0) {
    confidence = Math.min(confidence, 0.7);
    reasons.push(`WAF detected (${fpCtx.wafDetected.join(", ")}) — reduced confidence`);
    if (finding.category === "Infrastructure") {
      severity = severity === "high" ? "medium" : severity;
      severity = severity === "critical" ? "high" : severity;
    }
  }

  if (fpCtx.cdnDetected.length > 0) {
    confidence = Math.min(confidence, 0.75);
    reasons.push(`CDN detected (${fpCtx.cdnDetected.join(", ")}) — may obscure true server response`);
  }

  if (!fpCtx.hasExploitContext && finding.severity !== "info") {
    confidence = Math.min(confidence, 0.5);
    reasons.push("No exploit context confirmed — finding is pattern-based only");
  }

  return {
    shouldSuppress: false,
    adjustedConfidence: Math.round(confidence * 100) / 100,
    adjustedSeverity: severity,
    fpReason: reasons.length > 0 ? reasons.join("; ") : null,
  };
}

export function annotateFpEvidence(
  originalEvidence: string,
  endpointUrl: string,
  fpResult: FpReductionResult
): string {
  if (!fpResult.fpReason) return originalEvidence;
  return [
    `[FP-REDUCTION] ${fpResult.fpReason}`,
    `Endpoint: ${endpointUrl}`,
    `Adjusted confidence: ${fpResult.adjustedConfidence} (was higher)`,
    `Adjusted severity: ${fpResult.adjustedSeverity}`,
    "",
    "Original evidence:",
    originalEvidence,
  ].join("\n");
}

export { rfcHeaderGet, rfcHeaderContains };
