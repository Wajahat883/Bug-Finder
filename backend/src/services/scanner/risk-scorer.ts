/**
 * Perfect Risk Scoring Engine
 *
 * Deterministic, enterprise-grade scoring model (Burp Suite / Nessus / Qualys style).
 *
 * Formula:
 *   Risk Score = Base Severity × Context Factor × Confidence Score × Exploitability Score
 *
 *   Base Severity:     Critical=10, High=7, Medium=5, Low=3, Info=0
 *   Context Factor:    Confirmed exploit=1.0, Partial evidence=0.7, No exploit=0.6, SPA fallback=0.0
 *   Confidence:        1.0 (default), reduced ONLY for ambiguous/incomplete exploit evidence
 *   Exploitability:    Remote=1.0, Auth-required=0.6, User-interaction=0.4, None=0.0
 *
 * INFRASTRUCTURE SIGNALS (CDN, WAF, cache, server fingerprint) are NEVER scored.
 * They are classified as risk=0, severity=info regardless of any other factor.
 * CDN/WAF presence must NEVER reduce confidence for real vulnerabilities.
 */

import type { ScanFinding } from "./types";
import type { ContextResult } from "./context-validator";
import { classifySignal, type SignalType } from "./signal-classifier";
import { validateContext } from "./context-validator";
import type { SpaSignature } from "./spa-detector";

// ── Exported types ──────────────────────────────────────────────────────────────

export interface ScoringInput {
  finding: ScanFinding;
  spaSignature?: SpaSignature | null;
  hasAuthRequired?: boolean;
  hasUserInteraction?: boolean;
}

export interface ScoringResult {
  riskScore: number;
  adjustedSeverity: ScanFinding["severity"];
  adjustedConfidence: number;
  signalType: SignalType;
  contextFactor: number;
  exploitabilityScore: number;
  baseSeverity: number;
  verdict: string;
}

// ── Base severity map ───────────────────────────────────────────────────────────

const BASE_SEVERITY: Record<ScanFinding["severity"], number> = {
  critical: 10,
  high: 7,
  medium: 5,
  low: 3,
  info: 0,
};

// ── Exploitability score ────────────────────────────────────────────────────────

function exploitabilityScore(options: { authRequired?: boolean; userInteraction?: boolean }): number {
  if (options.userInteraction && options.authRequired) return 0.4;
  if (options.authRequired) return 0.6;
  if (options.userInteraction) return 0.6;
  return 1.0; // Remote, unauthenticated
}

// ── Confidence — ONLY drops for ambiguous exploit evidence ─────────────────────

function confidenceScore(
  finding: ScanFinding,
  context: ContextResult,
): number {
  let confidence = finding.confidence;

  // EXPLOIT-EVIDENCE-BASED reductions only
  if (context.exploitConfirmed) {
    confidence = Math.max(confidence, 0.95);
  } else if (context.exploitPartial) {
    confidence = confidence * 0.85; // Slight reduction — evidence ambiguous
  } else if (finding.evidence.length < 50) {
    confidence = confidence * 0.75; // Pattern-only, no body captured
  }

  // BOOSTERS — confirm exploit evidence exists
  if (context.exploitConfirmed) {
    confidence = Math.min(1.0, confidence + 0.05);
    if (finding.reproduction_curl) confidence = Math.min(1.0, confidence + 0.05);
    if (finding.raw_request && finding.raw_response) confidence = Math.min(1.0, confidence + 0.05);
  }

  return Math.round(Math.max(0, Math.min(1, confidence)) * 100) / 100;
}

// ── Main scoring function ──────────────────────────────────────────────────────

export function computeRiskScore(input: ScoringInput): ScoringResult {
  const { finding, spaSignature, hasAuthRequired, hasUserInteraction } = input;

  // ── Step 1: Classify the signal ──────────────────────────────────────
  const sig = classifySignal(finding);

  // ── Step 2: Infrastructure & Informational → zero score, always ──────
  if (!sig.riskRelevant) {
    return {
      riskScore: 0,
      adjustedSeverity: "info",
      adjustedConfidence: finding.confidence, // Never reduce infra confidence
      signalType: sig.type,
      contextFactor: 0,
      exploitabilityScore: 0,
      baseSeverity: BASE_SEVERITY[finding.severity],
      verdict: sig.label,
    };
  }

  // ── Step 3: Validate exploit context ─────────────────────────────────
  const context = validateContext(finding, { spaSignature });

  if (context.isSpaFallback) {
    return {
      riskScore: 0,
      adjustedSeverity: "info",
      adjustedConfidence: 0.0,
      signalType: sig.type,
      contextFactor: 0,
      exploitabilityScore: 0,
      baseSeverity: BASE_SEVERITY[finding.severity],
      verdict: "SPA fallback — index.html shell, not a real resource",
    };
  }

  // ── Step 4: Compute the formula ──────────────────────────────────────
  const base = BASE_SEVERITY[finding.severity];
  const ctxFactor = context.exploitConfirmed ? 1.0 : context.exploitPartial ? 0.7 : 0.6;
  const conf = confidenceScore(finding, context);
  const exploit = exploitabilityScore({
    authRequired: hasAuthRequired,
    userInteraction: hasUserInteraction,
  });

  const rawScore = base * ctxFactor * conf * exploit;
  const riskScore = Math.round(rawScore * 10) / 10;

  // ── Step 5: Adjusted severity from the risk score ────────────────────
  const adjustedSeverity = riskScoreToSeverity(riskScore);

  let verdict: string;
  if (riskScore >= 9.0) verdict = "Critical — confirmed exploit, immediate remediation required";
  else if (riskScore >= 6.5) verdict = "High — real risk, prioritize remediation";
  else if (riskScore >= 4.0) verdict = "Medium — moderate risk, schedule remediation";
  else if (riskScore >= 2.0) verdict = "Low — limited risk, remediate when possible";
  else verdict = "Info — informational finding, no immediate risk";

  return {
    riskScore,
    adjustedSeverity,
    adjustedConfidence: conf,
    signalType: sig.type,
    contextFactor: ctxFactor,
    exploitabilityScore: exploit,
    baseSeverity: base,
    verdict,
  };
}

// ── Severity from risk score ──────────────────────────────────────────────────

function riskScoreToSeverity(score: number): ScanFinding["severity"] {
  if (score >= 9.0) return "critical";
  if (score >= 6.5) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 2.0) return "low";
  return "info";
}

// ── Convenience exports ───────────────────────────────────────────────────────

export { BASE_SEVERITY };

export function isInfraOrInfo(finding: ScanFinding): boolean {
  const sig = classifySignal(finding);
  return sig.type === "infrastructure" || sig.type === "informational";
}
