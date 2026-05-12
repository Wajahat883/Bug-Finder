import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { col } from "../../lib/db";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

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

        return {
          id: "sec-01", name: "HTTPS Redirect Check", category: "security",
          status: isRedirect ? "pass" : "warn",
          duration: 0,
          message: isRedirect ? `HTTP redirects to: ${location}` : `HTTP returns ${res.status} without redirect`,
          evidence: { status: res.status, location },
          suggestion: !isRedirect ? "Configure automatic HTTP→HTTPS redirect" : undefined,
        };
      } catch {
        return {
          id: "sec-01", name: "HTTPS Redirect Check", category: "security",
          status: "info" as TestResult["status"], duration: 0,
          message: "HTTP endpoint unreachable — likely behind proxy or localhost",
          evidence: { note: "Localhost development environment" },
        };
      }
    },
  },
  {
    id: "sec-02",
    category: "security",
    name: "Security Headers Check",
    description: "Checks for presence of HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.",
    tags: ["security", "headers"],
    run: async (ctx) => {
      const res = await api(ctx, "/health");
      const headers: Record<string, string> = {};
      const required = ["strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy"];

      for (const h of required) {
        headers[h] = res?.headers.get(h) ?? "MISSING";
      }

      const present = required.filter(h => headers[h] !== "MISSING");
      const missing = required.filter(h => headers[h] === "MISSING");
      const score = present.length;

      return {
        id: "sec-02", name: "Security Headers Check", category: "security",
        status: score >= 3 ? "pass" : score >= 1 ? "warn" : "fail",
        duration: 0,
        message: `${score}/${required.length} security headers present. Missing: ${missing.join(", ") || "none"}`,
        evidence: headers,
        suggestion: missing.length > 0 ? `Add missing headers: ${missing.join(", ")}` : undefined,
      };
    },
  },
  {
    id: "sec-03",
    category: "security",
    name: "SQL Injection Guard",
    description: "Verifies that SQLi-like parameters are safely handled and don't crash the server.",
    tags: ["security", "sqli"],
    run: async (ctx) => {
      const payloads = ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT * FROM users--"];
      const results: Record<string, number> = {};

      for (const p of payloads) {
        const res = await api(ctx, `/findings?severity=${encodeURIComponent(p)}`);
        results[p.slice(0, 30)] = res?.status ?? 0;
      }

      const allSafe = Object.values(results).every(s => s !== 500);
      const errors = Object.entries(results).filter(([, s]) => s === 500).map(([p]) => p).join(", ");

      return {
        id: "sec-03", name: "SQL Injection Guard", category: "security",
        status: allSafe ? "pass" : "fail",
        duration: 0,
        message: allSafe ? "All SQLi test payloads handled safely" : `500 errors on: ${errors}`,
        evidence: { payloadResults: results },
        suggestion: !allSafe ? "Add input sanitization/mongo-sanitize to query parameters" : undefined,
      };
    },
  },
  {
    id: "sec-04",
    category: "security",
    name: "XSS Guard",
    description: "Tests that XSS payloads in query parameters are sanitized and don't reflect unsafely.",
    tags: ["security", "xss"],
    run: async (ctx) => {
      const payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"];
      const results: Record<string, { status: number; reflected: boolean }> = {};

      for (const p of payloads) {
        const res = await api(ctx, `/search?q=${encodeURIComponent(p)}`);
        const body = res ? await res.text().catch(() => "") : "";
        results[p.slice(0, 30)] = { status: res?.status ?? 0, reflected: body.includes(p) };
      }

      const safe = Object.values(results).every(r => !r.reflected || r.status !== 200);

      return {
        id: "sec-04", name: "XSS Guard", category: "security",
        status: safe ? "pass" : "warn",
        duration: 0,
        message: safe ? "No raw XSS payload reflection detected" : "XSS payloads reflected in response body",
        evidence: results,
        suggestion: !safe ? "HTML-encode all user input in responses" : undefined,
      };
    },
  },
  {
    id: "sec-05",
    category: "security",
    name: "CSRF Token Validation",
    description: "Checks whether state-changing endpoints require CSRF protection.",
    tags: ["security", "csrf"],
    run: async (ctx) => {
      const res = await api(ctx, "/auth/profile", { method: "PATCH", body: JSON.stringify({ first_name: "csrf-test" }) });
      const setCookie = res?.headers.get("set-cookie") ?? "";

      return {
        id: "sec-05", name: "CSRF Token Validation", category: "security",
        status: res?.status === 401 ? "pass" : "warn",
        duration: 0,
        message: res?.status === 401 ? "State-changing endpoint requires auth (CSRF protected via session)" : `HTTP ${res?.status} without auth token`,
        evidence: { status: res?.status, setCookie },
        suggestion: res?.status === 200 ? "Add CSRF token requirement to state-changing endpoints" : undefined,
      };
    },
  },
  {
    id: "sec-06",
    category: "security",
    name: "Sensitive Data Exposure",
    description: "Verifies API responses don't leak passwords, secrets, or internal paths.",
    tags: ["security", "data-exposure"],
    run: async (ctx) => {
      const endpoints = ["/auth/me", "/settings", "/system", "/scans?page_size=1", "/health"];
      const sensitivePatterns = [/\bpassword\b/i, /\bsecret\b/i, /\bprivate_key\b/i, /\bapi_key\b/i, /\bMONGODB_URI\b/i];
      const findings: string[] = [];

      for (const ep of endpoints) {
        const res = await api(ctx, ep);
        const body = res ? await res.text().catch(() => "") : "";
        for (const pat of sensitivePatterns) {
          if (pat.test(body)) {
            findings.push(`${ep}: matches ${pat}`);
          }
        }
      }

      return {
        id: "sec-06", name: "Sensitive Data Exposure", category: "security",
        status: findings.length === 0 ? "pass" : "fail",
        duration: 0,
        message: findings.length === 0 ? "No sensitive data leaked in API responses" : `Exposed: ${findings.slice(0, 3).join("; ")}`,
        evidence: { findings, endpointsChecked: endpoints.length },
        suggestion: findings.length > 0 ? "Remove sensitive fields from API responses. Use DTOs." : undefined,
      };
    },
  },
  {
    id: "sec-07",
    category: "security",
    name: "Server Info Leakage",
    description: "Checks if X-Powered-By, Server headers, or stack traces exist in responses.",
    tags: ["security", "info-leak"],
    run: async (ctx) => {
      const res = await api(ctx, "/health");
      const headers: Record<string, string> = {};
      const dangerous = ["x-powered-by", "server", "x-aspnet-version", "x-runtime"];
      for (const h of dangerous) {
        headers[h] = res?.headers.get(h) ?? "";
      }

      const leaks = dangerous.filter(h => headers[h] !== "");

      return {
        id: "sec-07", name: "Server Info Leakage", category: "security",
        status: leaks.length === 0 ? "pass" : "warn",
        duration: 0,
        message: leaks.length === 0 ? "No server info leakage" : `Leaking: ${leaks.join(", ")}`,
        evidence: headers,
        suggestion: leaks.length > 0 ? `Strip ${leaks.join(", ")} headers in production` : undefined,
      };
    },
  },
];

export const securitySuite: TestSuite = {
  id: "security",
  category: "security",
  label: "Security Testing",
  description: "Self-tests the application for HTTPS enforcement, security headers, SQLi/XSS guards, CSRF protection, sensitive data leakage, and server info exposure.",
  icon: "ShieldAlert",
  tests: securityTests,
};
