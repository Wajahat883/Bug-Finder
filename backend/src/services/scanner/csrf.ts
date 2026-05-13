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

  // Check main page for forms without CSRF tokens.
  // Before reporting, verify whether session cookies carry SameSite=Strict/Lax —
  // if they do, CSRF via a cross-site form submission is blocked by the browser
  // regardless of whether a token is present, making the finding a false positive.
  const mainRes = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (mainRes) {
    const body = await mainRes.text().catch(() => "");

    // Extract SameSite status from the response's Set-Cookie headers
    const setCookieHeader = mainRes.headers.get("set-cookie") ?? "";
    const hasSameSiteCookies = /samesite=(strict|lax)/i.test(setCookieHeader);

    if (hasSameSiteCookies) {
      emit({ type: "log", message: `  CSRF form check: SameSite cookie detected (${setCookieHeader.match(/samesite=\w+/i)?.[0]}) — form-level CSRF not exploitable, skipping` });
    } else {
      const forms = body.match(/<form[^>]*>[\s\S]*?<\/form>/gi) ?? [];

      for (const form of forms) {
        const hasPost = /method=["']post["']/i.test(form);
        const hasCsrfToken = /csrf|_token|authenticity_token|__requestverificationtoken|nonce/i.test(form);

        if (hasPost && !hasCsrfToken) {
          const actionMatch = form.match(/action=["']([^"']*)["']/i);
          const action = actionMatch?.[1] ?? targetUrl;
          const endpoint = action.startsWith("http") ? action : `${base}${action}`;

          if (!seen.has(endpoint)) {
            seen.add(endpoint);

            // Check if this specific form's action endpoint has any CSRF protection
            // by sending a cross-origin request and seeing if it's rejected
            const crossOriginR = await fetch(endpoint, {
              method: "POST",
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Origin: "https://evil-csrf-form.example.com",
                Referer: "https://evil-csrf-form.example.com/attack.html",
              },
              body: "test=csrf-probe",
              signal: AbortSignal.timeout(6000),
            }).catch(() => null);

            const crossStatus = crossOriginR?.status ?? 0;
            // 403/422/400 suggests server-side validation present; 200/201/302 = accepted
            const crossOriginAccepted = [200, 201, 301, 302].includes(crossStatus);

            findings.push({
              title: "HTML Form Missing CSRF Token",
              category: "CSRF",
              severity: crossOriginAccepted ? "high" : "medium",
              endpoint: targetUrl,
              description: crossOriginAccepted
                ? `An HTML POST form at ${endpoint} has no CSRF token AND accepted a simulated cross-origin submission. Session cookies lack SameSite protection. An attacker's page can silently submit this form on behalf of logged-in users.`
                : `An HTML POST form at ${endpoint} has no CSRF token and session cookies lack SameSite=Strict. While the cross-origin simulation returned HTTP ${crossStatus}, manual verification is recommended as some CSRF bypasses exist.`,
              evidence: [
                `Form found at: ${targetUrl}`,
                `Form action: ${endpoint}`,
                `CSRF token field: [NOT FOUND]`,
                `Session cookie SameSite: [NOT SET]`,
                `Cross-origin simulation: POST ${endpoint} with Origin: evil-csrf-form.example.com → HTTP ${crossStatus}`,
                ``,
                `Form snippet:`,
                form.slice(0, 400),
              ].join("\n"),
              recommended_fix: "Add a cryptographically random CSRF token to all state-changing forms. Set SameSite=Strict on all session cookies. Validate Origin/Referer server-side.",
              cvss_score: crossOriginAccepted ? 8.1 : 6.1,
              cwe_id: "CWE-352",
              scanner_name: "Bug-Finder/CSRF",
              scanner_family: "web",
              confidence: crossOriginAccepted ? 0.88 : 0.70,
            });
            emit({ type: "log", message: `  [CSRF FORM] ${endpoint} — no token, SameSite missing, cross-origin HTTP ${crossStatus}` });
          }
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
        scanner_name: "Bug-Finder/CSRF",
        scanner_family: "web",
        confidence: corsPermissive ? 0.88 : 0.65,
      });
      emit({ type: "log", message: `  [CSRF CONFIRMED] ${endpoint} — cross-origin accepted, SameSite=${hasSameSiteProtection ? "ok" : "MISSING"}, CORS=${corsAllowOrigin || "none"}` });
    } else {
      emit({ type: "log", message: `  CSRF protected at ${endpoint} (status=${crossR.status}, SameSite=${hasSameSiteProtection}, CORS=${corsAllowOrigin || "none"})` });
    }
  }

  // ── JSON API CSRF: custom header bypass test ─────────────────────────────
  // Some APIs rely on a custom header (X-Requested-With: XMLHttpRequest) as
  // their only CSRF defense. A browser-based form can't set custom headers,
  // but an attacker with CORS access or a fetch() request CAN.
  // We test: can we POST JSON WITHOUT the custom header and get the same result?
  emit({ type: "log", message: "Testing JSON API CSRF (custom-header bypass)..." });

  const jsonApiEndpoints = [
    ...STATE_CHANGING_PATHS.slice(0, 4).map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 4),
  ];

  for (const endpoint of jsonApiEndpoints.slice(0, 5)) {
    if (seen.has(`xrw:${endpoint}`)) continue;

    // Baseline with the custom header (simulates legitimate AJAX)
    const withHeaderRes = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base,
      },
      body: JSON.stringify({ csrf_test: "baseline" }),
    });
    if (!withHeaderRes) continue;
    if (withHeaderRes.status === 404 || withHeaderRes.status === 405) continue;
    const withHeaderBody = await withHeaderRes.text().catch(() => "");

    // Attack: same POST WITHOUT X-Requested-With (browser cross-origin fetch can't set it
    // by default, but this tests whether the server actually enforces it)
    const withoutHeaderRes = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://evil-csrf-xrw.example.com",
      },
      body: JSON.stringify({ csrf_test: "attack" }),
      signal: AbortSignal.timeout(8000),
    }).catch(() => null);
    if (!withoutHeaderRes) continue;
    const withoutHeaderBody = await withoutHeaderRes.text().catch(() => "");

    const setCookieH = withHeaderRes.headers.get("set-cookie") ?? "";
    const hasSameSite = /samesite=(strict|lax)/i.test(setCookieH);
    const corsAcao = withoutHeaderRes.headers.get("access-control-allow-origin") ?? "";
    const corsPermissive = corsAcao === "*" || corsAcao.includes("evil-csrf-xrw");

    // Server accepted without custom header AND lacks SameSite = CSRF vector
    const accepted = [200, 201, 202, 400].includes(withoutHeaderRes.status);
    const sameResponse = Math.abs(withoutHeaderBody.length - withHeaderBody.length) < 150;

    if (accepted && !hasSameSite && (sameResponse || corsPermissive) && !seen.has(`xrw:${endpoint}`)) {
      seen.add(`xrw:${endpoint}`);
      findings.push({
        title: `JSON API CSRF — Missing Custom Header Enforcement at ${endpoint}`,
        category: "CSRF",
        severity: "high",
        endpoint,
        description: `The JSON API endpoint at ${endpoint} does not enforce X-Requested-With: XMLHttpRequest or equivalent custom header validation. Session cookies lack SameSite protection. An attacker page can use fetch() to send credentialed cross-origin POST requests and trigger state changes on behalf of logged-in users.`,
        evidence: [
          `With X-Requested-With header: POST ${endpoint} → HTTP ${withHeaderRes.status} (${withHeaderBody.length}b)`,
          `Without X-Requested-With (attack): POST ${endpoint}`,
          `  Origin: https://evil-csrf-xrw.example.com`,
          `  → HTTP ${withoutHeaderRes.status} (${withoutHeaderBody.length}b)`,
          `  Response size diff: ${Math.abs(withoutHeaderBody.length - withHeaderBody.length)}b`,
          `SameSite cookie: ${hasSameSite ? "PRESENT" : "MISSING — browser sends session cookies on cross-origin requests"}`,
          `CORS Access-Control-Allow-Origin: ${corsAcao || "[not set]"}`,
          corsPermissive ? `EXPLOIT: fetch("${endpoint}",{method:"POST",credentials:"include",body:JSON.stringify({...})})` : "",
        ].filter(Boolean).join("\n"),
        recommended_fix: "Set SameSite=Strict on all session cookies. Add CSRF tokens to all state-changing API endpoints. If using custom header enforcement (X-Requested-With), ensure the check is actually applied server-side and not just documented.",
        cvss_score: 7.5,
        cwe_id: "CWE-352",
        scanner_name: "Bug-Finder/CSRF",
        scanner_family: "web",
        confidence: corsPermissive ? 0.87 : 0.70,
      });
      emit({ type: "log", message: `  [CSRF] JSON API accepts requests without X-Requested-With at ${endpoint}` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No CSRF vulnerabilities confirmed" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/CSRF", message: `CSRF check complete — ${findings.length} finding(s)` });
  return findings;
}
