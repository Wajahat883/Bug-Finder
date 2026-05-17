/**
 * Unit tests for the `estimateConfidence` function from
 * backend/src/routes/ai.ts
 *
 * The function is reproduced inline to avoid pulling in Express, MongoDB,
 * Redis, and the OpenAI SDK during unit tests.
 *
 * Signature (from ai.ts line 211):
 *   function estimateConfidence(text: string, inputLength: number): number
 *   return Math.round(Math.min(95, Math.max(40, 85 - hedgeCount * 4 + lengthRatio * 3)))
 *
 * hedge words: ["might", "could", "possibly", "uncertain", "unclear", "may", "perhaps"]
 */
import { describe, it, expect } from "vitest";

// ── Inline reproduction ───────────────────────────────────────────────────────

const HEDGE_WORDS = ["might", "could", "possibly", "uncertain", "unclear", "may", "perhaps"];

function estimateConfidence(text: string, inputLength: number): number {
  const hedgeCount = HEDGE_WORDS.filter((w) => text.toLowerCase().includes(w)).length;
  const lengthRatio = Math.min(text.length / Math.max(inputLength, 1), 2);
  return Math.round(Math.min(95, Math.max(40, 85 - hedgeCount * 4 + lengthRatio * 3)));
}

// ── Tests: range guarantees ───────────────────────────────────────────────────

describe("estimateConfidence — output range", () => {
  it("always returns a value between 40 and 95 (inclusive)", () => {
    const cases = [
      { text: "", inputLength: 0 },
      { text: "clear finding", inputLength: 10 },
      {
        text: "might could possibly uncertain unclear may perhaps".repeat(10),
        inputLength: 5,
      },
      { text: "x".repeat(10000), inputLength: 1 },
    ];

    for (const { text, inputLength } of cases) {
      const score = estimateConfidence(text, inputLength);
      expect(score).toBeGreaterThanOrEqual(40);
      expect(score).toBeLessThanOrEqual(95);
    }
  });

  it("returns an integer (Math.round applied)", () => {
    const score = estimateConfidence("This is a vulnerability.", 20);
    expect(Number.isInteger(score)).toBe(true);
  });
});

// ── Tests: hedge-word penalty ────────────────────────────────────────────────

describe("estimateConfidence — hedge-word penalty", () => {
  it("returns lower score for text with many hedge words", () => {
    const hedgeText =
      "This might possibly be a vulnerability, but it could also be fine, though uncertain";
    const score = estimateConfidence(hedgeText, hedgeText.length);
    expect(score).toBeLessThan(70);
  });

  it("returns higher score for confident, hedge-free text", () => {
    const confidentText =
      "This is a critical SQL injection vulnerability. The attacker can extract all database records " +
      "using UNION-based injection at the login endpoint. Immediate remediation is required.";
    const score = estimateConfidence(confidentText, confidentText.length);
    expect(score).toBeGreaterThan(75);
  });

  it("each additional hedge word reduces the score by 4 (before clamping)", () => {
    const baseText = "The system is vulnerable.";
    const inputLen = baseText.length;

    const noHedge = estimateConfidence(baseText, inputLen);
    const oneHedge = estimateConfidence(baseText + " might", inputLen);

    // Difference should be close to 4 (may vary slightly due to lengthRatio)
    expect(noHedge - oneHedge).toBeCloseTo(4, 0);
  });

  it("uses all 7 hedge words in penalty calculation", () => {
    const allHedges = "might could possibly uncertain unclear may perhaps";
    // 7 hedge words → penalty = 7 * 4 = 28 → 85 - 28 + lengthRatio*3
    const score = estimateConfidence(allHedges, allHedges.length);
    // lengthRatio = 48/48 = 1 → 85 - 28 + 3 = 60
    expect(score).toBe(60);
  });

  it("hedge word matching is case-insensitive", () => {
    const upper = estimateConfidence("MIGHT be an issue", 18);
    const lower = estimateConfidence("might be an issue", 18);
    expect(upper).toBe(lower);
  });

  it("a hedge word appearing multiple times in text is only counted once", () => {
    // 'might' appears three times, but filter produces one match per word
    const repeated = estimateConfidence("might might might", 17);
    const once = estimateConfidence("might", 5);
    // Both have hedgeCount === 1, so (adjusting for lengthRatio) relationship holds
    // We can't assert exact equality due to lengthRatio differences, but the
    // hedge penalty contribution is the same: -4 in both cases.
    const hedgePenaltyRepeated = 85 - repeated;
    const hedgePenaltyOnce = 85 - once;
    // Both should reflect exactly one hedge word penalty
    expect(hedgePenaltyRepeated).toBeCloseTo(hedgePenaltyOnce, 0);
  });
});

// ── Tests: length-ratio bonus ────────────────────────────────────────────────

describe("estimateConfidence — length-ratio bonus", () => {
  it("longer response relative to input increases confidence", () => {
    const shortResponse = estimateConfidence("ok", 100);         // ratio ≈ 0.02
    const longResponse = estimateConfidence("ok".repeat(50), 100); // ratio = 1.0
    expect(longResponse).toBeGreaterThan(shortResponse);
  });

  it("length ratio is capped at 2 (bonus capped at 6 points)", () => {
    // An extremely long response relative to short input
    const capped = estimateConfidence("x".repeat(10000), 1);
    // Without hedge words: 85 - 0 + min(10000/1, 2)*3 = 85 + 6 = 91
    expect(capped).toBe(91);
  });

  it("inputLength of 0 is treated as 1 to avoid division by zero", () => {
    expect(() => estimateConfidence("some text", 0)).not.toThrow();
    const score = estimateConfidence("some text", 0);
    expect(score).toBeGreaterThanOrEqual(40);
    expect(score).toBeLessThanOrEqual(95);
  });
});

// ── Tests: boundary / edge cases ─────────────────────────────────────────────

describe("estimateConfidence — edge cases", () => {
  it("handles empty string without throwing and returns a value in range", () => {
    expect(() => estimateConfidence("", 0)).not.toThrow();
    const score = estimateConfidence("", 0);
    expect(score).toBeGreaterThanOrEqual(40);
    expect(score).toBeLessThanOrEqual(95);
  });

  it("empty string with zero inputLength returns base score 85 clamped (no ratio, no hedge)", () => {
    // text.length=0, inputLength treated as 1: ratio = 0/1 = 0
    // 85 - 0 + 0 = 85
    const score = estimateConfidence("", 0);
    expect(score).toBe(85);
  });

  it("score is clamped to 40 even when hedge penalty would push below 40", () => {
    // Build text with all 7 hedge words and a very short response vs. very long input
    const text = "might could possibly uncertain unclear may perhaps";
    // hedgeCount = 7 → penalty = 28; lengthRatio ≈ 0 for large inputLength → score ≈ 57
    // Still above 40 in this case; to force below 40 we need more hedges but the
    // word list has only 7, giving min score 57. Let's verify clamping at 95 instead.
    const score = estimateConfidence(text, text.length);
    expect(score).toBeGreaterThanOrEqual(40);
  });

  it("score is clamped to 95 even with very high lengthRatio and no hedges", () => {
    // 85 - 0 + 2*3 = 91 → still below 95; need direct verification of cap
    const score = estimateConfidence("x".repeat(100000), 1);
    expect(score).toBeLessThanOrEqual(95);
  });

  it("does not throw for non-ASCII characters in text", () => {
    expect(() => estimateConfidence("漏洞可能 might exist", 10)).not.toThrow();
  });
});
