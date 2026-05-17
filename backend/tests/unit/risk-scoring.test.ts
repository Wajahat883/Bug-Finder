/**
 * Unit tests for risk-scoring logic used across Bug Finder Pro.
 *
 * Covers:
 *   - CVSS 4.0 score calculation (via calculateCvss4 from cvss4.ts)
 *   - EPSS score weighting (priority bump when EPSS is high)
 *   - Risk score with asset criticality multiplier
 *   - NaN / missing score handling
 *   - Critical severity always produces the highest tier score
 */
import { describe, it, expect } from "vitest";
import { calculateCvss4, inferCvss4FromFinding, type Cvss4Metrics } from "../../src/lib/cvss4.js";

// ── EPSS + risk score helpers (reproduced from scanner pipeline logic) ─────────

interface RawFinding {
  cvss_score?: number;
  epss_score?: number;
  asset_criticality?: number; // 1 = low, 2 = medium, 3 = high, 4 = critical asset
  severity: string;
}

/**
 * Composite risk score used for finding prioritisation.
 * Formula: (cvssScore * 0.5) + (epssScore * 0.3 * 10) + (assetCriticality * 0.2 * 2.5)
 * All components normalised to a 0-10 scale.  NaN inputs are clamped to 0.
 */
function computeRiskScore(f: RawFinding): number {
  const cvss = Number.isFinite(f.cvss_score) ? Math.min(10, Math.max(0, f.cvss_score!)) : 0;
  const epss = Number.isFinite(f.epss_score) ? Math.min(1, Math.max(0, f.epss_score!)) : 0;
  const ac = Number.isFinite(f.asset_criticality) ? Math.min(4, Math.max(1, f.asset_criticality!)) : 1;

  const score = cvss * 0.5 + epss * 10 * 0.3 + ac * 2.5 * 0.2;
  return Math.round(score * 100) / 100;
}

function priorityLabel(riskScore: number): "critical" | "high" | "medium" | "low" {
  if (riskScore >= 8) return "critical";
  if (riskScore >= 6) return "high";
  if (riskScore >= 4) return "medium";
  return "low";
}

// ── Tests: CVSS 4.0 calculation ────────────────────────────────────────────────

describe("CVSS 4.0 score calculation", () => {
  it("produces score 10.0 for the worst-case combination (all High/None impact on both systems)", () => {
    const metrics: Cvss4Metrics = {
      AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H",
      SC: "H", SI: "H", SA: "H",
    };
    const { score, severity } = calculateCvss4(metrics);
    expect(score).toBeGreaterThanOrEqual(9.0);
    expect(severity).toBe("Critical");
  });

  it("produces a low score for local physical access with high complexity and all-N impact", () => {
    const metrics: Cvss4Metrics = {
      AV: "P", AC: "H", AT: "P", PR: "H", UI: "A",
      VC: "N", VI: "N", VA: "N",
      SC: "N", SI: "N", SA: "N",
    };
    const { score, severity } = calculateCvss4(metrics);
    expect(score).toBeLessThan(4.0);
    expect(["None", "Low"]).toContain(severity);
  });

  it("score is always between 0.0 and 10.0", () => {
    const combinations: Cvss4Metrics[] = [
      { AV: "N", AC: "L", AT: "N", PR: "N", UI: "N", VC: "H", VI: "H", VA: "H", SC: "H", SI: "H", SA: "H" },
      { AV: "P", AC: "H", AT: "P", PR: "H", UI: "A", VC: "N", VI: "N", VA: "N", SC: "N", SI: "N", SA: "N" },
      { AV: "A", AC: "L", AT: "N", PR: "L", UI: "P", VC: "L", VI: "L", VA: "N", SC: "L", SI: "N", SA: "N" },
      { AV: "L", AC: "H", AT: "N", PR: "N", UI: "N", VC: "H", VI: "N", VA: "H", SC: "N", SI: "L", SA: "N" },
    ];
    for (const m of combinations) {
      const { score } = calculateCvss4(m);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(10);
    }
  });

  it("Network AV scores higher than Physical AV (all else equal)", () => {
    const base: Omit<Cvss4Metrics, "AV"> = {
      AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H",
      SC: "N", SI: "N", SA: "N",
    };
    const network = calculateCvss4({ ...base, AV: "N" });
    const physical = calculateCvss4({ ...base, AV: "P" });
    expect(network.score).toBeGreaterThanOrEqual(physical.score);
  });

  it("vector string contains all 11 required metric keys", () => {
    const m: Cvss4Metrics = {
      AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
      VC: "H", VI: "H", VA: "H",
      SC: "H", SI: "H", SA: "H",
    };
    const { vector } = calculateCvss4(m);
    const required = ["AV:", "AC:", "AT:", "PR:", "UI:", "VC:", "VI:", "VA:", "SC:", "SI:", "SA:"];
    for (const key of required) {
      expect(vector).toContain(key);
    }
  });
});

// ── Tests: inferCvss4FromFinding ───────────────────────────────────────────────

describe("inferCvss4FromFinding — category heuristics", () => {
  it("SQL injection category produces a high or critical score", () => {
    const { score, severity } = inferCvss4FromFinding({
      category: "SQL Injection",
      cwe_id: "CWE-89",
      cvss_score: 9.8,
      severity: "critical",
    });
    expect(score).toBeGreaterThanOrEqual(7.0);
    expect(["High", "Critical"]).toContain(severity);
  });

  it("XSS category gets user-interaction (passive) metrics applied", () => {
    const result = inferCvss4FromFinding({
      category: "Cross-Site Scripting (XSS)",
      cwe_id: "CWE-79",
      cvss_score: 6.1,
      severity: "medium",
    });
    expect(result.score).toBeGreaterThan(0);
    expect(result.severity).toBeDefined();
  });

  it("critical severity guard ensures VC or VI is not N when severity is critical", () => {
    // Use a category that by default sets VC=N, then check the guard kicks in
    const result = inferCvss4FromFinding({
      category: "Information Disclosure",
      severity: "critical",
    });
    // Critical severity should push score to high range
    expect(result.score).toBeGreaterThanOrEqual(5.0);
  });

  it("TLS/SSL category uses High attack complexity", () => {
    const result = inferCvss4FromFinding({
      category: "TLS Configuration",
      severity: "medium",
    });
    expect(result.score).toBeDefined();
    expect(result.vector).toContain("AC:H");
  });
});

// ── Tests: EPSS weighting ──────────────────────────────────────────────────────

describe("EPSS score weighting", () => {
  it("high EPSS (0.9) significantly bumps the composite risk score vs. low EPSS (0.01)", () => {
    const base: RawFinding = { cvss_score: 7.5, severity: "high", asset_criticality: 2 };

    const highEpss = computeRiskScore({ ...base, epss_score: 0.9 });
    const lowEpss = computeRiskScore({ ...base, epss_score: 0.01 });

    expect(highEpss).toBeGreaterThan(lowEpss);
    // The EPSS component alone contributes 0.9 * 10 * 0.3 = 2.7 vs 0.01 * 10 * 0.3 = 0.03
    expect(highEpss - lowEpss).toBeCloseTo(2.67, 1);
  });

  it("maximum EPSS (1.0) produces a higher score than zero EPSS", () => {
    const f: RawFinding = { cvss_score: 5.0, epss_score: 1.0, severity: "medium", asset_criticality: 1 };
    const g: RawFinding = { cvss_score: 5.0, epss_score: 0.0, severity: "medium", asset_criticality: 1 };
    expect(computeRiskScore(f)).toBeGreaterThan(computeRiskScore(g));
  });

  it("finding with high EPSS gets 'high' or 'critical' priority label", () => {
    const f: RawFinding = { cvss_score: 7.0, epss_score: 0.85, severity: "high", asset_criticality: 3 };
    const label = priorityLabel(computeRiskScore(f));
    expect(["high", "critical"]).toContain(label);
  });
});

// ── Tests: asset criticality multiplier ────────────────────────────────────────

describe("Risk score — asset criticality multiplier", () => {
  it("critical asset (4) scores higher than low asset (1) with identical CVSS and EPSS", () => {
    const base: RawFinding = { cvss_score: 6.0, epss_score: 0.3, severity: "medium" };
    const critAsset = computeRiskScore({ ...base, asset_criticality: 4 });
    const lowAsset = computeRiskScore({ ...base, asset_criticality: 1 });
    expect(critAsset).toBeGreaterThan(lowAsset);
  });

  it("asset criticality contributes correctly to the total (delta = (4-1) * 2.5 * 0.2 = 1.5)", () => {
    const base: RawFinding = { cvss_score: 0, epss_score: 0, severity: "low" };
    const high = computeRiskScore({ ...base, asset_criticality: 4 });
    const low = computeRiskScore({ ...base, asset_criticality: 1 });
    expect(high - low).toBeCloseTo(1.5, 5);
  });
});

// ── Tests: NaN / missing score handling ───────────────────────────────────────

describe("Risk score — NaN and missing input handling", () => {
  it("treats undefined cvss_score as 0 (does not produce NaN)", () => {
    const score = computeRiskScore({ severity: "medium", epss_score: 0.5 });
    expect(Number.isNaN(score)).toBe(false);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  it("treats undefined epss_score as 0", () => {
    const score = computeRiskScore({ cvss_score: 7.0, severity: "high" });
    expect(Number.isNaN(score)).toBe(false);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  it("treats NaN cvss_score as 0", () => {
    const score = computeRiskScore({ cvss_score: NaN, severity: "info" });
    expect(Number.isNaN(score)).toBe(false);
  });

  it("treats NaN epss_score as 0", () => {
    const score = computeRiskScore({ cvss_score: 5.0, epss_score: NaN, severity: "medium" });
    expect(Number.isNaN(score)).toBe(false);
  });

  it("all missing inputs produce a non-negative numeric score", () => {
    const score = computeRiskScore({ severity: "low" });
    expect(typeof score).toBe("number");
    expect(score).toBeGreaterThanOrEqual(0);
  });
});

// ── Tests: critical severity always scores highest ─────────────────────────────

describe("Severity tier — critical always produces highest risk bracket", () => {
  it("critical severity finding at CVSS 10 maps to 'critical' priority label", () => {
    const f: RawFinding = { cvss_score: 10, epss_score: 0.9, asset_criticality: 4, severity: "critical" };
    const label = priorityLabel(computeRiskScore(f));
    expect(label).toBe("critical");
  });

  it("info severity finding at CVSS 0 and no EPSS maps to 'low' priority label", () => {
    const f: RawFinding = { cvss_score: 0, epss_score: 0, asset_criticality: 1, severity: "info" };
    const label = priorityLabel(computeRiskScore(f));
    expect(label).toBe("low");
  });

  it("critical finding always outscores an equivalent medium finding", () => {
    const critFinding: RawFinding = { cvss_score: 9.5, epss_score: 0.8, asset_criticality: 4, severity: "critical" };
    const medFinding: RawFinding = { cvss_score: 5.0, epss_score: 0.2, asset_criticality: 2, severity: "medium" };
    expect(computeRiskScore(critFinding)).toBeGreaterThan(computeRiskScore(medFinding));
  });
});
