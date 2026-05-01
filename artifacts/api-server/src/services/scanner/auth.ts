import { ScanContext, ScanFinding, safeFetch } from "./types";

const PROTECTED_PATHS = [
  { path: "/admin", label: "Admin Panel" },
  { path: "/api/admin", label: "Admin API" },
  { path: "/api/users", label: "User List API" },
  { path: "/api/v1/users", label: "User List API v1" },
  { path: "/api/settings", label: "Settings API" },
  { path: "/api/config", label: "Config API" },
  { path: "/api/keys", label: "API Keys endpoint" },
  { path: "/api/secrets", label: "Secrets endpoint" },
  { path: "/dashboard", label: "Dashboard" },
  { path: "/api/reports", label: "Reports API" },
];

const DEFAULT_CREDENTIALS = [
  { username: "admin", password: "admin" },
  { username: "admin", password: "password" },
  { username: "admin", password: "admin123" },
  { username: "admin", password: "123456" },
  { username: "root", password: "root" },
  { username: "test", password: "test" },
];

export async function runAuthCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Burp Suite/Auth", message: "Checking authentication and access control" });

  const base = new URL(targetUrl);

  // Check for rate limiting on login
  emit({ type: "log", message: "Testing login rate limiting..." });
  const loginUrl = `${base.origin}/api/auth/login`;
  const loginPayload = { username: "probe@test.com", password: "wrongpassword" };

  const attempts: number[] = [];
  for (let i = 0; i < 5; i++) {
    const res = await safeFetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginPayload),
    });
    if (res) attempts.push(res.status);
  }

  const has429 = attempts.includes(429);
  const has200 = attempts.includes(200);
  if (!has429 && !has200) {
    // Check if all returned 401/403 without blocking
    const allFailed = attempts.every(s => s === 401 || s === 403 || s === 400);
    if (allFailed && attempts.length >= 5) {
      findings.push({
        title: "No Rate Limiting on Login Endpoint",
        category: "Authentication",
        severity: "high",
        endpoint: loginUrl,
        description: "The login endpoint does not appear to rate-limit repeated failed attempts. This allows brute-force attacks against user accounts.",
        evidence: `5 POST requests to ${loginUrl}\nAll returned ${attempts.join(", ")} without HTTP 429 or account lockout`,
        recommended_fix: "Implement rate limiting (e.g., 5 attempts per minute per IP). Consider CAPTCHA after repeated failures. Return 429 Too Many Requests when exceeded.",
        cvss_score: 7.5,
        cwe_id: "CWE-307",
        scanner_name: "Burp Suite",
        scanner_family: "web",
        confidence: 0.75,
      });
      emit({ type: "log", message: "No rate limiting detected on login endpoint" });
    }
  }

  // Check unauthenticated access to protected resources
  emit({ type: "log", message: "Checking unauthenticated access to protected paths..." });
  const budget = profile === "quick" ? 4 : profile === "standard" ? 7 : PROTECTED_PATHS.length;

  for (const { path, label } of PROTECTED_PATHS.slice(0, budget)) {
    const url = `${base.origin}${path}`;
    const res = await safeFetch(url, {
      headers: { "Accept": "application/json" },
    });

    if (!res) continue;

    if (res.status === 200) {
      const body = await res.text().catch(() => "");
      const hasData = body.length > 50 && (body.includes("{") || body.includes("[") || body.includes("<"));

      if (hasData) {
        findings.push({
          title: `Unauthenticated Access to ${label}`,
          category: "Broken Access Control",
          severity: "high",
          endpoint: url,
          description: `The ${label} (${path}) is accessible without authentication. This may expose sensitive administrative functions or user data.`,
          evidence: `GET ${url}\nHTTP 200 OK (no auth header)\n\nResponse preview:\n${body.slice(0, 300)}`,
          recommended_fix: "Implement authentication middleware on all protected routes. Return HTTP 401 or 403 for unauthenticated access.",
          cvss_score: 7.5,
          cwe_id: "CWE-306",
          scanner_name: "Burp Suite",
          scanner_family: "web",
          confidence: 0.85,
        });
        emit({ type: "log", message: `  [AUTH] Unauthenticated access: ${path}` });
      } else {
        emit({ type: "log", message: `  ${path} — 200 but empty/redirect (likely auth'd)` });
      }
    } else {
      emit({ type: "log", message: `  ${path} — ${res.status} (protected)` });
    }
  }

  // Default credential check on admin endpoints (passive)
  if (profile === "deep") {
    emit({ type: "log", message: "Probing for default credentials on admin endpoints..." });
    const adminLoginPaths = ["/api/admin/login", "/admin/login", "/api/auth/login"];

    for (const loginPath of adminLoginPaths) {
      const url = `${base.origin}${loginPath}`;
      for (const cred of DEFAULT_CREDENTIALS.slice(0, 3)) {
        const res = await safeFetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: cred.username, password: cred.password }),
        });
        if (res && res.status === 200) {
          const body = await res.text().catch(() => "");
          if (body.includes("token") || body.includes("success") || body.includes("authenticated")) {
            findings.push({
              title: `Default Credentials Accepted: ${cred.username}/${cred.password}`,
              category: "Authentication",
              severity: "critical",
              endpoint: url,
              description: `The admin login endpoint accepts default credentials (${cred.username}/${cred.password}), allowing unauthorized administrator access.`,
              evidence: `POST ${url}\nBody: ${JSON.stringify(cred)}\nHTTP ${res.status} — Authentication succeeded`,
              recommended_fix: "Change all default credentials immediately. Enforce strong password policies. Implement MFA for admin accounts.",
              cvss_score: 9.8,
              cwe_id: "CWE-798",
              scanner_name: "Burp Suite",
              scanner_family: "web",
              confidence: 0.97,
            });
            emit({ type: "log", message: `  [CRITICAL] Default creds work: ${cred.username}/${cred.password}` });
          }
        }
      }
    }
  }

  emit({
    type: "engine_done",
    engine: "Burp Suite/Auth",
    message: `Auth check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
