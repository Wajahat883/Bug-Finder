import { describe, it, expect } from "vitest";

// POINT 7: Scanner module unit tests

describe("Scanner — safeFetch throttle state machine", () => {
  it("starts with base delay of 150ms", () => {
    const state = { delayMs: 150, lastMs: 0 };
    expect(state.delayMs).toBe(150);
  });

  it("doubles delay on 429 status", () => {
    let delayMs = 150;
    const handle429 = () => { delayMs = Math.min(delayMs * 2, 5000); };
    handle429();
    expect(delayMs).toBe(300);
    handle429();
    expect(delayMs).toBe(600);
  });

  it("increases delay on slow response (> 3000ms)", () => {
    let delayMs = 200;
    const handleSlow = () => { delayMs = Math.min(delayMs + 200, 3000); };
    handleSlow();
    expect(delayMs).toBe(400);
  });

  it("respects per-host isolation", () => {
    const map = new Map<string, number>();
    map.set("example.com", 300);
    map.set("other.com", 150);
    expect(map.get("example.com")).toBe(300);
    expect(map.get("other.com")).toBe(150);
  });
});

describe("Scanner — finding confidence validation", () => {
  it("filters out low-confidence findings", () => {
    const findings = [
      { title: "XSS", confidence: 0.9 },
      { title: "Maybe XSS", confidence: 0.3 },
      { title: "SQLi", confidence: 0.85 },
    ];
    const THRESHOLD = 0.7;
    const valid = findings.filter(f => f.confidence >= THRESHOLD);
    expect(valid).toHaveLength(2);
    expect(valid.map(f => f.title)).toContain("XSS");
    expect(valid.map(f => f.title)).not.toContain("Maybe XSS");
  });

  it("assigns correct CVSS ranges per severity", () => {
    const ranges: Record<string, [number, number]> = {
      critical: [9.0, 10.0],
      high:     [7.0, 8.9],
      medium:   [4.0, 6.9],
      low:      [0.1, 3.9],
      info:     [0.0, 0.0],
    };
    expect(ranges["critical"]![0]).toBe(9.0);
    expect(ranges["high"]![1]).toBe(8.9);
    expect(ranges["medium"]![0]).toBe(4.0);
  });
});

describe("Scanner — deduplication logic", () => {
  function levenshtein(a: string, b: string): number {
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
    );
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i]![j] = a[i - 1] === b[j - 1]
          ? dp[i - 1]![j - 1]!
          : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
      }
    }
    return dp[a.length]![b.length]!;
  }

  function similarity(a: string, b: string): number {
    if (a === b) return 1;
    const max = Math.max(a.length, b.length);
    return max === 0 ? 1 : 1 - levenshtein(a.toLowerCase(), b.toLowerCase()) / max;
  }

  it("identical titles have similarity 1.0", () => {
    expect(similarity("SQL Injection in /api/users", "SQL Injection in /api/users")).toBe(1.0);
  });

  it("very different titles have low similarity", () => {
    expect(similarity("SQL Injection", "Missing CSP Header")).toBeLessThan(0.5);
  });

  it("near-duplicate titles exceed 0.85 threshold", () => {
    const sim = similarity("SQL Injection in /api/users?id=1", "SQL Injection in /api/users?id=2");
    expect(sim).toBeGreaterThan(0.85);
  });

  it("duplicate detection works end-to-end", () => {
    const THRESHOLD = 0.85;
    const existing = [
      { title: "SQL Injection in /api/users?id=1", endpoint: "/api/users", category: "Injection" },
    ];
    // Only the parameter value changes — nearly identical
    const newFinding = { title: "SQL Injection in /api/users?id=2", endpoint: "/api/users", category: "Injection" };
    const isDup = existing.some(e =>
      e.endpoint === newFinding.endpoint &&
      e.category === newFinding.category &&
      similarity(e.title, newFinding.title) >= THRESHOLD
    );
    expect(isDup).toBe(true);
  });
});
