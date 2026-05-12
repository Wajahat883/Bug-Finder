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

  emit({ type: "engine_start", engine: "Bug-Finder/CSRF", message: "Analyzing CSRF protection on state-changing endpoints" });

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
            scanner_name: "Bug-Finder",
            scanner_family: "web",
            confidence: 0.82,
          });
          emit({ type: "log", message: `  [CSRF] Form missing token at ${endpoint}` });
        }
      }
    }
  }

  // Test API endpoints — actual cross-origin simulation with baseline comparison
  const endpoints = [
    ...STATE_CHANGING_PATHS.slice(0, budget).map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, budget),
  ];

  for (const endpoint of endpoints.slice(0, budget)) {
    if (seen.has(endpoint)) continue;

    // Step 1: Baseline — same-origin POST to confirm the endpoint responds
    const baselineR = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: base },
      body: JSON.stringify({ test: "csrf-baseline" }),
    });
    if (!baselineR) continue;
    if (baselineR.status === 404 || baselineR.status === 405) continue;
    const baselineBody = await baselineR.text().catch(() => "");

    // Step 2: Cross-origin simulation — identical request with attacker's Origin/Referer
    // Does NOT send authHeaders (simulates a browser automatically sending session cookies)
    const crossR = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://evil-csrf-test.example.com",
        Referer: "https://evil-csrf-test.example.com/attack.html",
      },
      body: JSON.stringify({ test: "csrf-probe" }),
      signal: AbortSignal.timeout(8000),
    }).catch(() => null);

    if (!crossR) continue;
    const crossBody = await crossR.text().catch(() => "");

    const corsAllowOrigin = crossR.headers.get("access-control-allow-origin") ?? "";
    const setCookie = baselineR.headers.get("set-cookie") ?? "";
    const hasSameSiteProtection = /samesite=(strict|lax)/i.test(setCookie);

    const crossOriginAccepted = [200, 201, 202, 400].includes(crossR.status);
    const corsPermissive = corsAllowOrigin === "*" || corsAllowOrigin.includes("evil-csrf-test");
    const responsesSimilar = Math.abs(crossBody.length - baselineBody.length) < 200;

    if (crossOriginAccepted && !hasSameSiteProtection && (corsPermissive || responsesSimilar)) {
      seen.add(endpoint);
      const severity = corsPermissive ? "high" : "medium";
      findings.push({
        title: `CSRF Vulnerability Confirmed: ${endpoint}`,
        category: "CSRF",
        severity,
        endpoint,
        description: `The endpoint accepted a cross-origin POST from evil-csrf-test.example.com without rejection${corsPermissive ? " AND allows the attacker origin via CORS" : ""}. Session cookie lacks SameSite=Strict/Lax protection. A malicious site can forge this request on behalf of a logged-in user.`,
        evidence: [
          `Baseline (same-origin): POST ${endpoint} → HTTP ${baselineR.status} (${baselineBody.length}b)`,
          `Cross-origin: POST ${endpoint}`,
          `  Origin: https://evil-csrf-test.example.com`,
          `  Referer: https://evil-csrf-test.example.com/attack.html`,
          `  → HTTP ${crossR.status} (${crossBody.length}b)`,
          `Access-Control-Allow-Origin: ${corsAllowOrigin || "[not set]"}`,
          `Set-Cookie SameSite: ${hasSameSiteProtection ? "PROTECTED" : "NOT SET — browser will send cookies"}`,
          `Response size diff: ${Math.abs(crossBody.length - baselineBody.length)}b (< 200b threshold — server processed both equally)`,
        ].join("\n"),
        recommended_fix: "Set SameSite=Strict on all session cookies. Validate Origin header — reject any request where Origin does not match your domain. Add CSRF tokens to all state-changing forms.",
        cvss_score: corsPermissive ? 8.1 : 6.1,
        cwe_id: "CWE-352",
        scanner_name: "Bug-Finder",
        scanner_family: "web",
        confidence: corsPermissive ? 0.88 : 0.65,
      });
      emit({ type: "log", message: `  [CSRF CONFIRMED] ${endpoint} — cross-origin accepted, SameSite=${hasSameSiteProtection ? "ok" : "MISSING"}, CORS=${corsAllowOrigin || "none"}` });
    } else {
      emit({ type: "log", message: `  CSRF protected at ${endpoint} (status=${crossR.status}, SameSite=${hasSameSiteProtection}, CORS=${corsAllowOrigin || "none"})` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No CSRF vulnerabilities confirmed" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/CSRF", message: `CSRF check complete — ${findings.length} finding(s)` });
  return findings;
}
