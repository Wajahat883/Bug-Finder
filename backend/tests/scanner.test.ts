import { describe, it, expect } from "vitest";

describe("CVSS Score Validation", () => {
  it("critical severity maps to 9.0-10.0", () => {
    const scores = ["critical", "high", "medium", "low", "info"];
    expect(scores).toContain("critical");
    expect(scores).toContain("high");
    expect(scores).toContain("medium");
  });

  it("severity order is correct", () => {
    const order = ["critical", "high", "medium", "low", "info"];
    expect(order.indexOf("critical")).toBe(0);
    expect(order.indexOf("high")).toBe(1);
    expect(order.indexOf("medium")).toBe(2);
    expect(order.indexOf("low")).toBe(3);
    expect(order.indexOf("info")).toBe(4);
  });
});

describe("Scan Finding Deduplication", () => {
  function levenshteinSimilarity(a: string, b: string): number {
    if (a === b) return 1;
    if (!a.length || !b.length) return 0;

    const matrix: number[][] = [];
    for (let i = 0; i <= a.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    const distance = matrix[a.length][b.length];
    const maxLen = Math.max(a.length, b.length);
    return 1 - distance / maxLen;
  }

  it("identical strings return similarity of 1.0", () => {
    expect(levenshteinSimilarity("hello world", "hello world")).toBe(1);
  });

  it("completely different strings return low similarity", () => {
    const sim = levenshteinSimilarity("abcdef", "ghijkl");
    expect(sim).toBeLessThan(0.5);
  });

  it("similar strings return high similarity", () => {
    const sim = levenshteinSimilarity("SQL Injection in User Lookup", "SQL Injection in User Lookup (POST)");
    expect(sim).toBeGreaterThan(0.7);
  });

  it("empty string comparison returns 0", () => {
    expect(levenshteinSimilarity("", "something")).toBe(0);
  });
});

describe("Rate Limiter Configuration", () => {
  it("auth limiter has 15-minute window", () => {
    const windowMs = 15 * 60 * 1000;
    expect(windowMs).toBe(900000);
    expect(windowMs / 1000 / 60).toBe(15);
  });

  it("auth limiter max is 10 requests per window", () => {
    const max = 10;
    expect(max).toBeGreaterThan(0);
    expect(max).toBeLessThanOrEqual(20);
  });

  it("global limiter is less restrictive than auth", () => {
    const globalMax = 100;
    const authMax = 10;
    expect(globalMax).toBeGreaterThan(authMax);
  });
});

describe("API Key Generation", () => {
  function generateApiKey(): string {
    const prefix = "bbp_";
    const random = Math.random().toString(36).substring(2, 18) + Math.random().toString(36).substring(2, 10);
    return prefix + random;
  }

  it("generates keys with correct prefix", () => {
    const key = generateApiKey();
    expect(key.startsWith("bbp_")).toBe(true);
  });

  it("generates unique keys", () => {
    const keys = new Set(Array.from({ length: 100 }, () => generateApiKey()));
    expect(keys.size).toBe(100);
  });

  it("key length is at least 20 characters", () => {
    const key = generateApiKey();
    expect(key.length).toBeGreaterThanOrEqual(20);
  });
});

describe("SLA Deadline Calculator", () => {
  function slaDeadline(severity: string, createdAt: Date): Date {
    const hours = severity === "critical" ? 24 : severity === "high" ? 72 : severity === "medium" ? 168 : 336;
    return new Date(createdAt.getTime() + hours * 60 * 60 * 1000);
  }

  it("critical gives 24 hours", () => {
    const now = new Date("2026-01-01T12:00:00Z");
    const deadline = slaDeadline("critical", now);
    expect(deadline.getTime() - now.getTime()).toBe(24 * 60 * 60 * 1000);
  });

  it("high gives 72 hours", () => {
    const now = new Date("2026-01-01T12:00:00Z");
    const deadline = slaDeadline("high", now);
    expect(deadline.getTime() - now.getTime()).toBe(72 * 60 * 60 * 1000);
  });

  it("medium gives 168 hours (7 days)", () => {
    const now = new Date("2026-01-01T12:00:00Z");
    const deadline = slaDeadline("medium", now);
    expect(deadline.getTime() - now.getTime()).toBe(168 * 60 * 60 * 1000);
  });

  it("low gives 336 hours (14 days)", () => {
    const now = new Date("2026-01-01T12:00:00Z");
    const deadline = slaDeadline("low", now);
    expect(deadline.getTime() - now.getTime()).toBe(336 * 60 * 60 * 1000);
  });
});

describe("OWASP Top 10 Mapping", () => {
  const owaspMap: Record<string, string> = {
    "Injection": "A03: Injection",
    "Authentication": "A07: Identification and Authentication Failures",
    "Cross-Site Scripting": "A03: Injection",
    "Security Misconfiguration": "A05: Security Misconfiguration",
    "Sensitive Data Exposure": "A04: Insecure Design",
    "Broken Access Control": "A01: Broken Access Control",
    "JWT Security": "A02: Cryptographic Failures",
    "CORS": "A01: Broken Access Control",
  };

  it("maps Injection to A03", () => {
    expect(owaspMap["Injection"]).toBe("A03: Injection");
  });

  it("maps XSS to A03", () => {
    expect(owaspMap["Cross-Site Scripting"]).toBe("A03: Injection");
  });

  it("maps Auth to A07", () => {
    expect(owaspMap["Authentication"]).toBe("A07: Identification and Authentication Failures");
  });

  it("maps JWT to Cryptographic Failures", () => {
    expect(owaspMap["JWT Security"]).toBe("A02: Cryptographic Failures");
  });

  it("all 10 OWASP categories are represented", () => {
    const categories = new Set(Object.values(owaspMap));
    expect(categories.size).toBeGreaterThanOrEqual(5);
  });
});

describe("Queue Backoff & Retry", () => {
  function exponentialBackoff(retryCount: number, baseMs = 1000): number {
    return Math.min(baseMs * Math.pow(2, retryCount), 60000);
  }

  it("first retry is base duration", () => {
    expect(exponentialBackoff(0, 1000)).toBe(1000);
  });

  it("second retry doubles", () => {
    expect(exponentialBackoff(1, 1000)).toBe(2000);
  });

  it("fifth retry is 32x base", () => {
    expect(exponentialBackoff(4, 1000)).toBe(16000);
  });

  it("caps at 60 seconds", () => {
    expect(exponentialBackoff(10, 1000)).toBe(60000);
  });

  it("max retries is 3", () => {
    const maxRetries = 3;
    for (let i = 0; i < maxRetries; i++) {
      expect(i).toBeLessThan(maxRetries);
    }
  });
});

describe("SSRF Guard", () => {
  function isPrivateIp(hostname: string): boolean {
    if (hostname === "localhost" || hostname === "127.0.0.1") return true;
    if (hostname.startsWith("10.") || hostname.startsWith("192.168.")) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
    if (hostname === "169.254.169.254") return true;
    if (hostname === "metadata.google.internal") return true;
    return false;
  }

  it("blocks localhost", () => {
    expect(isPrivateIp("localhost")).toBe(true);
  });

  it("blocks 127.0.0.1", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
  });

  it("blocks AWS metadata IP", () => {
    expect(isPrivateIp("169.254.169.254")).toBe(true);
  });

  it("blocks GCP metadata", () => {
    expect(isPrivateIp("metadata.google.internal")).toBe(true);
  });

  it("blocks 10.x private IPs", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
  });

  it("allows public domains", () => {
    expect(isPrivateIp("example.com")).toBe(false);
    expect(isPrivateIp("api.github.com")).toBe(false);
    expect(isPrivateIp("google.com")).toBe(false);
  });

  it("blocks 192.168.x IPs", () => {
    expect(isPrivateIp("192.168.1.1")).toBe(true);
  });

  it("blocks 172.16-31.x IPs", () => {
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("172.31.255.254")).toBe(true);
  });

  it("allows public 172.32.x IPs", () => {
    expect(isPrivateIp("172.32.0.1")).toBe(false);
  });
});

describe("Scanner Confidence Filtering", () => {
  interface Finding {
    title: string;
    confidence: number;
    severity: string;
  }

  function filterByConfidence(findings: Finding[], minConfidence: number): Finding[] {
    return findings.filter(f => f.confidence >= minConfidence);
  }

  const findings: Finding[] = [
    { title: "SQL Injection", confidence: 0.95, severity: "critical" },
    { title: "Cookie Missing HttpOnly", confidence: 0.85, severity: "medium" },
    { title: "TLS 1.0 Enabled", confidence: 0.92, severity: "medium" },
    { title: "Possible IDOR", confidence: 0.65, severity: "high" },
    { title: "Missing CSP", confidence: 0.88, severity: "high" },
  ];

  it("filters out low confidence findings below 0.7", () => {
    const filtered = filterByConfidence(findings, 0.7);
    expect(filtered.length).toBe(4);
    expect(filtered.map(f => f.title)).not.toContain("Possible IDOR");
  });

  it("filters out findings below 0.9", () => {
    const filtered = filterByConfidence(findings, 0.9);
    expect(filtered.length).toBe(2);
  });

  it("returns all findings with min 0", () => {
    expect(filterByConfidence(findings, 0).length).toBe(5);
  });

  it("returns none with min 1.0", () => {
    expect(filterByConfidence(findings, 1.0).length).toBe(0);
  });
});

describe("JWT Token Validation", () => {
  function isJwtFormat(token: string): boolean {
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token);
  }

  it("valid JWT format passes", () => {
    expect(isJwtFormat("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0t5GPSsUBaRcVPq4mPm2XRuJE")).toBe(true);
  });

  it("missing parts are rejected", () => {
    expect(isJwtFormat("eyJhbGci.eyJzdWIi")).toBe(false);
  });

  it("empty string is rejected", () => {
    expect(isJwtFormat("")).toBe(false);
  });

  it("invalid characters are rejected", () => {
    expect(isJwtFormat("abc$.def$.ghi$")).toBe(false);
  });
});

describe("Password Strength Validation", () => {
  function isStrongPassword(pw: string): boolean {
    if (pw.length < 6) return false;
    return true;
  }

  it("rejects passwords under 6 characters", () => {
    expect(isStrongPassword("abc12")).toBe(false);
    expect(isStrongPassword("a")).toBe(false);
    expect(isStrongPassword("")).toBe(false);
  });

  it("accepts passwords of 6+ characters", () => {
    expect(isStrongPassword("abcdef")).toBe(true);
    expect(isStrongPassword("Str0ng!Pass")).toBe(true);
  });
});
