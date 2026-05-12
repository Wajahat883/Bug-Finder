import { ScanContext, ScanFinding, ctxFetch } from "./types";

const STATE_CHANGING_PATHS = [
  "/api/user", "/api/users", "/api/profile", "/api/settings", "/api/account",
  "/api/password", "/api/email", "/api/preferences", "/api/delete",
  "/profile", "/settings", "/account", "/password/change",
];

const FORM_ACTION_PATTERNS = [
  /action=["'][^"']*["']/gi,
  /<form[^>]*method=["']post["'][^>]*>/gi,
];

export async function runCsrfCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Burp Suite/CSRF", message: "Analyzing CSRF protection on state-changing endpoints" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : STATE_CHANGING_PATHS.length;
  const seen = new Set<string>();

  // Check main page for forms without CSRF tokens
  const mainRes = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (mainRes) {
    const body = await mainRes.text().catch(() => "");
    const forms = body.match(/<form[^>]*>[\s\S]*?<\/form>/gi) ?? [];

    for (const form of forms) {
      const hasPost = /method=["']post["']/i.test(form);
      const hasCsrfToken = /csrf|_token|authenticity_token|__requestverificationtoken/i.test(form);

      if (hasPost && !hasCsrfToken) {
        const actionMatch = form.match(/action=["']([^"']*)["']/i);
        const action = actionMatch?.[1] ?? targetUrl;
        const endpoint = action.startsWith("http") ? action : `${base}${action}`;

        if (!seen.has(endpoint)) {
          seen.add(endpoint);
          findings.push({
            title: "HTML Form Missing CSRF Token",
            category: "CSRF",
            severity: "medium",
            endpoint: targetUrl,
            description: `An HTML form with method="POST" does not include a CSRF token. Attackers can create malicious pages that submit this form on behalf of authenticated users, potentially changing account settings, passwords, or performing unauthorized actions.`,
            evidence: `Form found at ${targetUrl}\nForm action: ${endpoint}\nCSRF token field: [NOT FOUND]\n\nForm snippet:\n${form.slice(0, 400)}`,
            recommended_fix: "Add a CSRF token to all state-changing forms. Use SameSite=Strict on session cookies as an additional layer. Validate the Origin/Referer header on the server.",
            cvss_score: 6.5,
            cwe_id: "CWE-352",
            scanner_name: "Burp Suite",
            scanner_family: "web",
            confidence: 0.82,
          });
          emit({ type: "log", message: `  [CSRF] Form missing token at ${endpoint}` });
        }
      }
    }
  }

  // Test API endpoints for CSRF protection
  const endpoints = [
    ...STATE_CHANGING_PATHS.slice(0, budget).map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, budget),
  ];

  for (const endpoint of endpoints.slice(0, budget)) {
    if (seen.has(endpoint)) continue;

    // Send a state-changing request without CSRF token/credentials
    const r = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.com", Referer: "https://evil.com" },
      body: JSON.stringify({ test: "csrf-probe" }),
    });

    if (!r) continue;

    // If the server doesn't check Origin and returns 200/201/400 (not 403/401)
    // it may be accepting cross-origin requests without CSRF validation
    if (r.status === 200 || r.status === 201 || r.status === 400) {
      const corsAllowOrigin = r.headers.get("access-control-allow-origin");
      if (corsAllowOrigin === "*" || corsAllowOrigin === "https://evil.com") {
        seen.add(endpoint);
        findings.push({
          title: "API Endpoint Potentially Vulnerable to CSRF",
          category: "CSRF",
          severity: "medium",
          endpoint,
          description: `The endpoint ${endpoint} accepted a POST request from an evil.com origin without rejecting it. Combined with permissive CORS, this could enable CSRF attacks against authenticated users.`,
          evidence: `POST ${endpoint}\nOrigin: https://evil.com\nReferer: https://evil.com\nHTTP ${r.status}\nAccess-Control-Allow-Origin: ${corsAllowOrigin}`,
          recommended_fix: "Validate the Origin and Referer headers on all state-changing endpoints. Require authentication tokens that cannot be set by third-party pages.",
          cvss_score: 6.1,
          cwe_id: "CWE-352",
          scanner_name: "Burp Suite",
          scanner_family: "web",
          confidence: 0.65,
        });
        emit({ type: "log", message: `  [CSRF?] ${endpoint} accepted cross-origin POST (${r.status})` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No obvious CSRF vulnerabilities detected" });
  }

  emit({ type: "engine_done", engine: "Burp Suite/CSRF", message: `CSRF check complete — ${findings.length} finding(s)` });
  return findings;
}
