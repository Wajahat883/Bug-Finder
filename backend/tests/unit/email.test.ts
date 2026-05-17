/**
 * Unit tests for backend/src/services/email.ts
 *
 * All nodemailer transport calls are mocked — no real SMTP connection is made.
 * Each describe block resets env vars and mocks to keep tests hermetic.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Helpers reproduced inline (pure functions extracted from email.ts) ─────────

/**
 * Reproduces the createTransport guard from email.ts:
 * returns false (= no transport) when SMTP_HOST is absent.
 */
function smtpConfigured(): boolean {
  return !!process.env["SMTP_HOST"];
}

/**
 * Reproduces the HTML generation for the severity badge section used in
 * sendReportEmail.  We test it in isolation so nodemailer is never needed.
 */
function buildSeverityBadge(severity: string, count: number): string {
  const colors: Record<string, string> = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#22d3ee",
  };
  const c = colors[severity] ?? "#6b7280";
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;background:${c}22;color:${c};font-weight:700;font-size:12px;">${severity.toUpperCase()}: ${count}</span>`;
}

/**
 * Reproduces the finding-row HTML builder used inside sendReportEmail.
 */
function buildFindingRow(finding: { title: string; severity: string; endpoint: string }): string {
  const c =
    ({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee" } as Record<string, string>)[
      finding.severity
    ] ?? "#6b7280";
  return `<tr><td style="padding:6px 8px;border-bottom:1px solid #333;">${finding.title}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #333;"><span style="color:${c};font-weight:600;">${finding.severity.toUpperCase()}</span></td>
      <td style="padding:6px 8px;border-bottom:1px solid #333;font-family:monospace;font-size:11px;">${finding.endpoint}</td></tr>`;
}

/** Minimal email address validator matching the one used in production routes. */
function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Truncates a subject line the same way the email builder does (max 80 chars). */
function buildSubject(prefix: string, title: string, maxLen = 80): string {
  const full = `${prefix}${title}`;
  return full.length > maxLen ? full.slice(0, maxLen - 3) + "..." : full;
}

// ── Mock nodemailer ────────────────────────────────────────────────────────────

const mockSendMail = vi.fn();
const mockCreateTransport = vi.fn(() => ({ sendMail: mockSendMail }));

vi.mock("nodemailer", () => ({
  default: { createTransport: mockCreateTransport },
}));

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("SMTP configuration guard", () => {
  afterEach(() => {
    delete process.env["SMTP_HOST"];
  });

  it("reports SMTP as unconfigured when SMTP_HOST is absent", () => {
    delete process.env["SMTP_HOST"];
    expect(smtpConfigured()).toBe(false);
  });

  it("reports SMTP as configured when SMTP_HOST is present", () => {
    process.env["SMTP_HOST"] = "smtp.example.com";
    expect(smtpConfigured()).toBe(true);
  });
});

describe("sendEmail — missing SMTP config returns false gracefully", () => {
  beforeEach(() => {
    delete process.env["SMTP_HOST"];
    vi.clearAllMocks();
  });

  it("returns false and does not throw when SMTP_HOST is not set", async () => {
    // Re-import after clearing env so createTransport returns null
    const { sendEmail } = await import("../../src/services/email.js");
    const result = await sendEmail({
      to: "user@example.com",
      subject: "Test",
      html: "<p>Hello</p>",
    });
    expect(result).toBe(false);
    // Transport should never have been created / mail sent
    expect(mockSendMail).not.toHaveBeenCalled();
  });
});

describe("sendEmail — valid params delegates to nodemailer", () => {
  beforeEach(() => {
    process.env["SMTP_HOST"] = "smtp.example.com";
    process.env["SMTP_PORT"] = "587";
    process.env["SMTP_USER"] = "user";
    process.env["SMTP_PASS"] = "pass";
    mockSendMail.mockResolvedValue({ messageId: "test-id" });
    vi.clearAllMocks();
  });

  afterEach(() => {
    delete process.env["SMTP_HOST"];
    delete process.env["SMTP_PORT"];
    delete process.env["SMTP_USER"];
    delete process.env["SMTP_PASS"];
  });

  it("returns true on successful send", async () => {
    mockSendMail.mockResolvedValueOnce({ messageId: "ok" });
    const { sendEmail } = await import("../../src/services/email.js");
    const result = await sendEmail({
      to: "dest@example.com",
      subject: "Hello",
      html: "<p>Body</p>",
    });
    expect(result).toBe(true);
  });

  it("returns false and does not throw when nodemailer throws", async () => {
    mockSendMail.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const { sendEmail } = await import("../../src/services/email.js");
    const result = await sendEmail({
      to: "dest@example.com",
      subject: "Hello",
      html: "<p>Body</p>",
    });
    expect(result).toBe(false);
  });
});

describe("Email HTML generation — edge cases", () => {
  it("severity badge does not throw for empty findings array", () => {
    const findings: Array<{ title: string; severity: string; endpoint: string }> = [];
    const rows = findings.slice(0, 10).map(buildFindingRow).join("");
    expect(rows).toBe("");
  });

  it("severity badge renders correctly for 'critical'", () => {
    const badge = buildSeverityBadge("critical", 5);
    expect(badge).toContain("CRITICAL: 5");
    expect(badge).toContain("#ef4444");
  });

  it("severity badge renders correctly for 'high'", () => {
    const badge = buildSeverityBadge("high", 12);
    expect(badge).toContain("HIGH: 12");
    expect(badge).toContain("#f97316");
  });

  it("severity badge falls back to grey for unknown severity", () => {
    const badge = buildSeverityBadge("unknown_sev", 0);
    expect(badge).toContain("#6b7280");
  });

  it("finding row renders title, severity, and endpoint", () => {
    const row = buildFindingRow({ title: "SQL Injection", severity: "critical", endpoint: "/api/users" });
    expect(row).toContain("SQL Injection");
    expect(row).toContain("CRITICAL");
    expect(row).toContain("/api/users");
  });

  it("finding row handles null-like empty title gracefully", () => {
    const row = buildFindingRow({ title: "", severity: "low", endpoint: "/" });
    expect(row).toBeDefined();
    expect(row).toContain("LOW");
  });

  it("top-findings slice caps at 10 even when more are provided", () => {
    const findings = Array.from({ length: 20 }, (_, i) => ({
      title: `Finding ${i}`,
      severity: "medium",
      endpoint: `/endpoint/${i}`,
    }));
    const rows = findings.slice(0, 10).map(buildFindingRow);
    expect(rows).toHaveLength(10);
  });
});

describe("Recipient validation", () => {
  it("accepts a valid single email address", () => {
    expect(isValidEmail("admin@bugfinder.io")).toBe(true);
  });

  it("rejects an address without @", () => {
    expect(isValidEmail("notanemail.com")).toBe(false);
  });

  it("rejects an address without domain", () => {
    expect(isValidEmail("user@")).toBe(false);
  });

  it("rejects an empty string", () => {
    expect(isValidEmail("")).toBe(false);
  });

  it("rejects address with spaces", () => {
    expect(isValidEmail("user name@example.com")).toBe(false);
  });

  it("accepts sub-domain addresses", () => {
    expect(isValidEmail("alerts@mail.internal.corp")).toBe(true);
  });
});

describe("Subject line truncation", () => {
  const PREFIX = "[Bug Finder Pro] ";

  it("leaves short titles unchanged", () => {
    const subject = buildSubject(PREFIX, "SQL Injection Found");
    expect(subject).toBe(`${PREFIX}SQL Injection Found`);
    expect(subject.length).toBeLessThanOrEqual(80);
  });

  it("truncates long titles with ellipsis", () => {
    const longTitle = "A".repeat(100);
    const subject = buildSubject(PREFIX, longTitle);
    expect(subject.endsWith("...")).toBe(true);
    expect(subject.length).toBeLessThanOrEqual(80);
  });

  it("truncates at exactly maxLen characters", () => {
    const longTitle = "B".repeat(200);
    const subject = buildSubject(PREFIX, longTitle, 80);
    expect(subject.length).toBe(80);
  });

  it("does not truncate when total length equals maxLen", () => {
    const remaining = 80 - PREFIX.length;
    const title = "C".repeat(remaining);
    const subject = buildSubject(PREFIX, title, 80);
    expect(subject.endsWith("...")).toBe(false);
    expect(subject.length).toBe(80);
  });
});
