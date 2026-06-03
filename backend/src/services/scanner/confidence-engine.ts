/**
 * Confidence Scoring Engine
 *
 * Weighted risk scoring system that dynamically adjusts confidence based on
 * real-world exploit signals and false positive indicators.
 *
 * Confidence modifiers:
 *   REDUCERS (lower confidence):
 *     - SPA detected                     → -0.35
 *     - WAF detected                     → -0.20
 *     - CDN detected                     → -0.15
 *     - No exploit context               → -0.25
 *     - Duplicate finding exists          → -0.10
 *     - Informational category           → cap at 0.30
 *     - Pattern-only match (no evidence)  → -0.15
 *
 *   BOOSTERS (increase confidence):
 *     - Real exploit confirmed (XSS pop, SQLi data extracted, SSRF OOB) → +0.25
 *     - Reproducible with curl           → +0.10
 *     - Raw evidence captured            → +0.05
 *     - CVE correlation confirmed         → +0.20
 *     - Multiple scanners agree           → +0.15
 *     - OAST/Interactsh callback            → +0.30
 *
 * Scoring tiers:
 *   ≥ 0.95  → DEFINITIVE   (exploit verified)
 *   ≥ 0.80  → HIGH         (strong signal, likely real)
 *   ≥ 0.60  → MEDIUM       (moderate signal, needs review)
 *   ≥ 0.40  → LOW          (weak signal, likely false positive)
 *   < 0.40  → NEGLIGIBLE   (informational / pattern-only)
 */

import type { ScanFinding } from "./types";
import { isInformationalOnly } from "./fp-engine";

export function scoreConfidence(
  finding: ScanFinding,
  options: {
    isSpa?: boolean;
    wafDetected?: string[];
    cdnDetected?: string[];
    hasExploitContext?: boolean;
    isDuplicate?: boolean;
    hasRawEvidence?: boolean;
    hasCveMatch?: boolean;
    hasOastCallback?: boolean;
    hasCurlReproducer?: boolean;
    multiScannerAgreement?: number;
  } = {}
): number {
  let confidence = finding.confidence;

  const reducers = [
    { condition: options.isSpa === true, weight: 0.35 },
    { condition: (options.wafDetected?.length ?? 0) > 0, weight: 0.20 },
    { condition: (options.cdnDetected?.length ?? 0) > 0, weight: 0.15 },
    { condition: options.hasExploitContext === false, weight: 0.25 },
    { condition: options.isDuplicate === true, weight: 0.10 },
    { condition: finding.evidence.length < 50, weight: 0.15 },
  ];

  for (const reducer of reducers) {
    if (reducer.condition) {
      confidence = confidence - reducer.weight;
    }
  }

  const boosters = [
    { condition: options.hasExploitContext === true, weight: 0.25 },
    { condition: options.hasCurlReproducer === true, weight: 0.10 },
    { condition: options.hasRawEvidence === true, weight: 0.05 },
    { condition: options.hasCveMatch === true, weight: 0.20 },
    { condition: (options.multiScannerAgreement ?? 0) >= 2, weight: 0.15 },
    { condition: options.hasOastCallback === true, weight: 0.30 },
  ];

  for (const booster of boosters) {
    if (booster.condition) {
      confidence = confidence + booster.weight;
    }
  }

  if (isInformationalOnly(finding)) {
    confidence = Math.min(confidence, 0.30);
  }

  return Math.round(Math.max(0, Math.min(1, confidence)) * 100) / 100;
}

export type ConfidenceTier = "definitive" | "high" | "medium" | "low" | "negligible";

export function getConfidenceTier(confidence: number): ConfidenceTier {
  if (confidence >= 0.95) return "definitive";
  if (confidence >= 0.80) return "high";
  if (confidence >= 0.60) return "medium";
  if (confidence >= 0.40) return "low";
  return "negligible";
}

export const CONFIDENCE_LABELS: Record<ConfidenceTier, string> = {
  definitive: "Exploit verified — real vulnerability",
  high: "Strong signal — likely real, review recommended",
  medium: "Moderate signal — needs triage review",
  low: "Weak signal — likely false positive, verify manually",
  negligible: "Informational / pattern-only — no confirmed risk",
};
