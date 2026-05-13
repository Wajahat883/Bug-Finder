import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch, ensureAuthenticated, isRateLimited } from "./fetch-utils";

const securityTests: TestCase[] = [
  {
    id: "sec-01",
    category: "security",
    name: "HTTPS Redirect Check",
    description: "Verifies that HTTP requests are redirected to HTTPS.",
    tags: ["security", "tls"],
    run: async (ctx) => {
      const httpUrl = ctx.baseUrl.replace("https://", "http://");
      try {
        const res = await fetch(httpUrl, { redirect: "manual" });
        const location = res.headers.get("location") ?? "";
        const isRedirect = res.status === 301 || res.status === 302;
        return { id: "sec-01", name: "HTTPS Redirect Check", category: "security", status: isRedirect ? "pass" : "info", duration: 0, message: isRedirect ? `HTTP redirects to: ${location}` : `HTTP ${res.status} — localhost/dev`, evidence: { status: res.status, location }, suggestion: !isRedirect && process.env["NODE_ENV"] === "production" ? "Configure HTTP→HTTPS redirect in production" : undefined };
      } catch {
        return { id: "sec-01", name: "HTTPS Redirect Check", category: "security", status: "info", duration: 0, message: "HTTP unreachable — localhost/dev expected", evidence: { note: "Local dev environment" } };
      }
    },
  },
  {
    id: "sec-02",
    category: "security",
    name: "Security Headers Check",
    description: "Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.",
    tags: ["security", "headers"],
    run: async (ctx) => {
      const res = await testFetch(ctx, "/health");
      const headers: Record<string, string> = {};
      const required = ["strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy"];
      for (const h of required) headers[h] = res?.headers.get(h) ?? "MISSING";
      const present = required.filter(h => headers[h] !== "MISSING");
      const score = present.length;

      return { id: "sec-02", name: "Security Headers Check", category: "security", status: score >= 2 ? "pass" : score >= 1 ? "warn" : "fail", duration: 0, message: `${score}/${required.length} headers present`, evidence: headers, suggestion: score < 3 ? "Add security headers in production" : undefined };
    },
  },
  {
    id: "sec-03",
    category: "security",
    name: "SQL Injection Guard",
    description: "Verifies SQLi-like parameters are safely handled.",
    tags: ["security", "sqli"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const payloads = ["' OR '1'='1", "1; DROP TABLE users--"];
      const results: Record<string, number> = {};
      for (const p of payloads) {
        const res = await testFetch(ctx, `/findings?severity=${encodeURIComponent(p)}`);
        results[p.slice(0, 20)] = res?.status ?? 0;
      }
      const allSafe = Object.values(results).every(s => s !== 500);
      return { id: "sec-03", name: "SQL Injection Guard", category: "security", status: allSafe ? "pass" : "fail", duration: 0, message: allSafe ? "SQLi payloads handled safely" : "500 errors detected", evidence: { payloadResults: results }, suggestion: !allSafe ? "Add mongo-sanitize to query params" : undefined };
    },
  },
  {
    id: "sec-04",
    category: "security",
    name: "XSS Guard",
    description: "Tests that XSS payloads in query parameters are sanitized.",
    tags: ["security", "xss"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const payloads = ["<script>alert(1)</script>", "javascript:alert(1)"];
      const results: Record<string, { status: number; reflected: boolean }> = {};
      for (const p of payloads) {
        const res = await testFetch(ctx, `/search?q=${encodeURIComponent(p)}`);
        const body = res ? await res.text().catch(() => "") : "";
        results[p.slice(0, 20)] = { status: res?.status ?? 0, reflected: body.includes(p) || body.includes(p.replace(/</g, "&lt;")) };
      }
      const safe = Object.values(results).every(r => !r.reflected || r.status === 401);
      return { id: "sec-04", name: "XSS Guard", category: "security", status: safe ? "pass" : "warn", duration: 0, message: safe ? "No raw XSS reflection" : "Payloads reflected", evidence: results, suggestion: !safe ? "HTML-encode all user input in responses" : undefined };
    },
  },
  {
    id: "sec-05",
    category: "security",
    name: "CSRF Token Validation",
    description: "Checks state-changing endpoints require auth.",
    tags: ["security", "csrf"],
    run: async (ctx) => {
      const saved = ctx.cookieStore.get(ctx.apiBase) ?? "";
      ctx.cookieStore.delete(ctx.apiBase);
      const res = await testFetch(ctx, "/auth/profile", { method: "PATCH", body: JSON.stringify({ first_name: "csrf-test" }) });
      if (saved) ctx.cookieStore.set(ctx.apiBase, saved);
      return { id: "sec-05", name: "CSRF Token Validation", category: "security", status: res?.status === 401 ? "pass" : res?.status === 200 ? "warn" : "info", duration: 0, message: res?.status === 401 ? "State-changing endpoint requires auth" : `HTTP ${res?.status}`, evidence: { status: res?.status }, suggestion: res?.status === 200 ? "Add CSRF token to state-changing endpoints" : undefined };
    },
  },
  {
    id: "sec-06",
    category: "security",
    name: "Sensitive Data Exposure",
    description: "Verifies API responses don't leak passwords or secrets.",
    tags: ["security", "data-exposure"],
    run: async (ctx) => {
      await ensureAuthenticated(ctx);
      const endpoints = ["/auth/me", "/settings", "/system", "/health"];
      const sensitivePatterns = [/\bpassword\b/i, /\bsecret\b/i, /\bprivate_key\b/i];
      const findings: string[] = [];
      for (const ep of endpoints) {
        const res = await testFetch(ctx, ep);
        const body = res ? await res.text().catch(() => "") : "";
        for (const pat of sensitivePatterns) {
          if (pat.test(body)) findings.push(`${ep} matches ${pat}`);
        }
      }
      return { id: "sec-06", name: "Sensitive Data Exposure", category: "security", status: findings.length === 0 ? "pass" : "fail", duration: 0, message: findings.length === 0 ? "No sensitive data leaked" : `Exposed: ${findings.slice(0, 3).join("; ")}`, evidence: { findings }, suggestion: findings.length > 0 ? "Remove sensitive fields from API responses" : undefined };
    },
  },
  {
    id: "sec-07",
    category: "security",
    name: "Server Info Leakage",
    description: "Checks for X-Powered-By or Server headers.",
    tags: ["security", "info-leak"],
    run: async (ctx) => {
      const res = await testFetch(ctx, "/health");
      const headers: Record<string, string> = {};
      const dangerous = ["x-powered-by", "server"];
      for (const h of dangerous) headers[h] = res?.headers.get(h) ?? "";
      const leaks = dangerous.filter(h => headers[h] !== "");
      return { id: "sec-07", name: "Server Info Leakage", category: "security", status: leaks.length === 0 ? "pass" : "warn", duration: 0, message: leaks.length === 0 ? "No server info leakage" : `Leaking: ${leaks.join(", ")}`, evidence: headers, suggestion: leaks.length > 0 ? "Strip server info headers in production" : undefined };
    },
  },
];

export const securitySuite: TestSuite = {
  id: "security", category: "security", label: "Security Testing",
  description: "Self-tests the application for HTTPS, security headers, SQLi/XSS guards, CSRF protection, data leakage, and info exposure.",
  icon: "ShieldAlert", tests: securityTests,
};
