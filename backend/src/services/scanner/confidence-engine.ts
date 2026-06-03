/**
 * Confidence Scoring Engine (Revised)
 *
 * Confidence adjustments are based SOLELY on exploit evidence quality.
 * CDN, WAF, cache headers, and other infrastructure signals DO NOT
 * affect confidence. Those are classified separately via signal-classifier.ts
 * and scored at zero risk by risk-scorer.ts.
 *
 * Confidence decreasers (exploit-evidence only):
 *   - Injection payload reflected but not executed     → ×0.85
 *   - Response body truncated / incomplete             → ×0.80
 *   - Pattern-only match (no body evidence)            → ×0.75
 *
 * Confidence boosters (exploit confirmation):
 *   - OAST/Interactsh callback received                → ×1.20
 *   - Data extracted (SQL, file content, etc.)         → ×1.15
 *   - Reproduction curl confirms finding               → ×1.10
 *   - CVE match with version confirmation              → ×1.10
 *   - Multiple scanners agree on same finding          → ×1.08
 */

import type { ScanFinding } from "./types";
import type { ContextResult } from "./context-validator";

export type ConfidenceTier = "definitive" | "high" | "medium" | "low" | "negligible";

export function getConfidenceTier(confidence: number): ConfidenceTier {
  if (confidence >= 0.95) return "definitive";
  if (confidence >= 0.80) return "high";
  if (confidence >= 0.60) return "medium";
  if (confidence >= 0.40) return "low";
  return "negligible";
}

export const CONFIDENCE_LABELS: Record<ConfidenceTier, string> = {
  definitive: "Exploit verified — real vulnerability with confirmed impact",
  high: "Strong exploit signal — likely real, review recommended",
  medium: "Moderate signal — needs triage review",
  low: "Weak signal — may be false positive, verify manually",
  negligible: "Informational or pattern-only — no confirmed risk",
};

export function scoreConfidence(
  finding: ScanFinding,
  context: ContextResult,
  options: {
    hasOastCallback?: boolean;
    hasDataExtraction?: boolean;
    hasCveMatch?: boolean;
    multiScannerAgreement?: number;
  } = {}
): number {
  let confidence = finding.confidence;

  // EXPLOIT-EVIDENCE-BASED reductions ONLY
  if (context.exploitPartial) {
    confidence *= 0.85;
  }

  if (finding.evidence.length < 100 && !context.exploitConfirmed) {
    confidence *= 0.80;
  }

  if (finding.evidence.length < 50) {
    confidence *= 0.75;
  }

  // EXPLOIT-EVIDENCE-BASED boosters ONLY
  if (options.hasOastCallback) {
    confidence *= 1.20;
  }

  if (options.hasDataExtraction) {
    confidence *= 1.15;
  }

  if (context.exploitConfirmed && finding.reproduction_curl) {
    confidence *= 1.10;
  }

  if (options.hasCveMatch) {
    confidence *= 1.10;
  }

  if ((options.multiScannerAgreement ?? 0) >= 2) {
    confidence *= 1.08;
  }

  return Math.round(Math.max(0, Math.min(1, confidence)) * 100) / 100;
}
