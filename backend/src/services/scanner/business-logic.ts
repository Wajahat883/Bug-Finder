import { ScanContext, ScanFinding, ctxFetch } from "./types";

const CART_PATHS = ["/api/cart", "/api/order", "/api/checkout", "/cart", "/order", "/api/purchase", "/api/payment"];
const PRIV_PATHS = ["/admin", "/api/admin", "/dashboard/admin", "/api/users/all", "/api/reports/all", "/api/settings/all"];

// Known admin-content indicators — content that a login page would NOT have
const ADMIN_CONTENT_INDICATORS = [
  "user_list", "user-list", "userList", "allUsers", "all_users",
  "\"role\"", "\"is_admin\"", "\"isAdmin\"", "\"permissions\"",
  "deleteUser", "delete_user", "banUser", "ban_user",
  "dashboard-stats", "totalRevenue", "total_revenue",
  "reportDownload", "auditLog", "audit_log",
];

// Login-page indicators — these mean the endpoint is protected (not a bypass)
const LOGIN_PAGE_INDICATORS = [
  "login", "sign in", "signin", "authenticate", "password", "username",
  "email", "<form", "input type=\"password\"",
];

export async function runBusinessLogicCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Logic", message: "Testing price manipulation, race conditions, and privilege escalation" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const seen = new Set<string>();

  // ── 1. Price / Quantity Manipulation ────────────────────────────────────────
  emit({ type: "log", message: "Testing price/quantity manipulation..." });
  const allCartPaths = [
    ...CART_PATHS.map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("cart") || ep.includes("order") || ep.includes("checkout")).slice(0, 3),
  ];

  for (const endpoint of allCartPaths.slice(0, budget)) {
    // Negative price — confirm with a second validation request
    const negRes = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: "1", quantity: 1, price: -99.99, amount: -99.99 }),
    });

    if (negRes && (negRes.status === 200 || negRes.status === 201)) {
      const body = await negRes.text().catch(() => "");
      const bodyLower = body.toLowerCase();
      const rejected = bodyLower.includes("invalid") || bodyLower.includes("error") ||
        bodyLower.includes("negative") || bodyLower.includes("must be positive");

      if (!rejected && !seen.has(`price:${endpoint}`)) {
        // Confirm: send a follow-up GET to see if the item was actually added with negative price
        const checkRes = await ctxFetch(ctx, endpoint.replace(/\/(checkout|payment)$/, ""), { method: "GET" });
        const checkBody = checkRes ? await checkRes.text().catch(() => "") : "";
        const negativeReflected = checkBody.includes("-99") || checkBody.includes("-0.99");

        seen.add(`price:${endpoint}`);
        findings.push({
          title: "Price Manipulation — Negative Price Accepted",
          category: "Business Logic",
          severity: negativeReflected ? "critical" : "high",
          endpoint,
          description: `The endpoint accepted a negative price value (-99.99) in the POST body without validation error. ${negativeReflected ? "The negative value was reflected in a subsequent GET, confirming the server stored it." : "The server returned 200/201 without rejecting the negative value."} This can allow fraudulent purchases or account credit manipulation.`,
          evidence: [
            `POST ${endpoint}`,
            `Payload: {"price": -99.99, "amount": -99.99}`,
            `HTTP ${negRes.status}`,
            `No rejection keyword in response`,
            `Response: ${body.slice(0, 300)}`,
            negativeReflected ? `\nConfirmation GET shows negative value in cart/order state` : "",
          ].filter(Boolean).join("\n"),
          recommended_fix: "Validate all price and quantity values server-side. Enforce positive values only. Never trust client-supplied prices — always recalculate from your product catalog server-side.",
          cvss_score: negativeReflected ? 9.1 : 7.5,
          cwe_id: "CWE-840",
          scanner_name: "Bug-Finder/Logic",
          scanner_family: "web",
          confidence: negativeReflected ? 0.92 : 0.70,
        });
        emit({ type: "log", message: `  [Price Manip] Negative price accepted at ${endpoint}${negativeReflected ? " — CONFIRMED in state" : ""}` });
      }
    }

    // Zero quantity
    const zeroRes = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: "1", quantity: 0, count: 0 }),
    });
    if (zeroRes && (zeroRes.status === 200 || zeroRes.status === 201)) {
      const body = await zeroRes.text().catch(() => "");
      const rejected = body.toLowerCase().includes("invalid") || body.toLowerCase().includes("error") ||
        body.toLowerCase().includes("must be");
      if (!rejected && !seen.has(`qty:${endpoint}`)) {
        seen.add(`qty:${endpoint}`);
        findings.push({
          title: "Business Logic — Zero Quantity Accepted",
          category: "Business Logic",
          severity: "medium",
          endpoint,
          description: `The endpoint accepted quantity=0 without validation. This may allow placing zero-cost orders or exploiting inventory logic.`,
          evidence: `POST ${endpoint}\nPayload: {"quantity": 0}\nHTTP ${zeroRes.status}\nResponse: ${body.slice(0, 200)}`,
          recommended_fix: "Validate that quantity is a positive integer ≥ 1 on the server side.",
          cvss_score: 5.3,
          cwe_id: "CWE-840",
          scanner_name: "Bug-Finder/Logic",
          scanner_family: "web",
          confidence: 0.65,
        });
      }
    }
  }

  // ── 2. Privilege Escalation — anti-false-positive two-step check ────────────
  emit({ type: "log", message: "Testing privilege escalation..." });
  const allPrivPaths = [
    ...PRIV_PATHS.map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("admin") || ep.includes("/all")).slice(0, 3),
  ];

  for (const endpoint of allPrivPaths.slice(0, budget)) {
    const r = await ctxFetch(ctx, endpoint, { redirect: "follow" });
    if (!r || r.status !== 200) continue;

    const body = await r.text().catch(() => "");
    const bodyLower = body.toLowerCase();

    // Reject login pages — a 200 with a login form is NOT a privilege escalation
    const isLoginPage = LOGIN_PAGE_INDICATORS.some(i => bodyLower.includes(i));
    if (isLoginPage) {
      emit({ type: "log", message: `  ${endpoint} → 200 but looks like a login page — not a bypass` });
      continue;
    }

    // Must contain actual admin content to confirm
    const adminContentHit = ADMIN_CONTENT_INDICATORS.find(i => body.includes(i));
    // Or is an API endpoint returning JSON with data (not an HTML shell)
    const ct = r.headers.get("content-type") ?? "";
    const isJsonWithData = ct.includes("application/json") && body.length > 50 && body.startsWith("{");

    if ((adminContentHit || isJsonWithData) && !seen.has(`priv:${endpoint}`)) {
      seen.add(`priv:${endpoint}`);

      // Step 2: Try with a random bad token to confirm the endpoint doesn't accept anything
      const badTokenRes = await ctxFetch(ctx, endpoint, {
        headers: { Authorization: "Bearer invalidtoken123abc" },
        redirect: "follow",
      });
      // If same status with bad token, the endpoint ignores auth entirely
      const ignoresAuth = badTokenRes?.status === 200;

      findings.push({
        title: "Privilege Escalation — Admin Resource Accessible Without Auth",
        category: "Business Logic",
        severity: "critical",
        endpoint,
        description: `The privileged endpoint ${endpoint} returned HTTP 200 with admin content without valid authentication. ${ignoresAuth ? "A request with an invalid Bearer token also received 200 — the endpoint completely ignores authentication." : "No auth credentials were sent."}`,
        evidence: [
          `GET ${endpoint}`,
          `Authorization: [none]`,
          `HTTP ${r.status}`,
          `Content-Type: ${ct}`,
          `Response size: ${body.length} bytes`,
          adminContentHit ? `Admin content indicator found: "${adminContentHit}"` : "API JSON response with data",
          ``,
          `Response preview:`,
          body.slice(0, 400),
          ignoresAuth ? `\nConfirmation: GET with "Authorization: Bearer invalidtoken123abc" also returned HTTP ${badTokenRes?.status}` : "",
        ].filter(Boolean).join("\n"),
        recommended_fix: "Add authentication middleware to all admin routes. Verify both authentication (valid token) and authorization (admin role) on every request. Return 401 for unauthenticated requests and 403 for unauthorized roles.",
        cvss_score: 9.8,
        cwe_id: "CWE-269",
        scanner_name: "Bug-Finder/Logic",
        scanner_family: "web",
        confidence: ignoresAuth ? 0.97 : 0.85,
      });
      emit({ type: "log", message: `  [PRIV-ESC CONFIRMED] ${endpoint} — admin content accessible, auth ignored=${ignoresAuth}` });
    } else {
      emit({ type: "log", message: `  ${endpoint} → 200 but no admin content indicators — skipping` });
    }
  }

  // ── 3. Race Condition — verify with response body diff, not just status ──────
  emit({ type: "log", message: "Testing race conditions..." });
  const raceEndpoints = [
    `${base}/api/redeem`, `${base}/api/coupon/apply`, `${base}/api/referral/claim`,
    `${base}/api/bonus/claim`, `${base}/api/credit/apply`,
    ...discoveredEndpoints.filter(ep =>
      ep.includes("redeem") || ep.includes("claim") || ep.includes("coupon")
    ).slice(0, 2),
  ];

  for (const endpoint of raceEndpoints.slice(0, Math.min(budget, 3))) {
    // First: send a sequential request to establish baseline
    const baselineRes = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: "TESTRACE", coupon: "TESTRACE", voucher: "TESTRACE" }),
    });
    if (!baselineRes || baselineRes.status === 404 || baselineRes.status === 405) continue;

    // Fire 6 truly concurrent requests using Promise.all
    const promises = Array.from({ length: 6 }, () =>
      ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: "TESTRACE", coupon: "TESTRACE", voucher: "TESTRACE" }),
      })
    );
    const results = await Promise.all(promises);

    const responses = await Promise.all(
      results.map(async r => ({
        status: r?.status ?? 0,
        body: r ? await r.text().catch(() => "") : "",
      }))
    );

    const successes = responses.filter(r => r.status === 200 || r.status === 201);

    // Only flag if multiple successes AND their response bodies differ
    // (same body = server returned identical "already applied" — may be idempotent)
    // Different bodies = different amounts/IDs were issued — real race condition
    const uniqueBodies = new Set(successes.map(r => r.body.slice(0, 100))).size;
    const isRealRace = successes.length > 1 && uniqueBodies > 1;

    if (isRealRace && !seen.has(`race:${endpoint}`)) {
      seen.add(`race:${endpoint}`);
      findings.push({
        title: "Race Condition — Multiple Concurrent Redemptions Succeeded",
        category: "Business Logic",
        severity: "high",
        endpoint,
        description: `${successes.length} of 6 concurrent POST requests to ${endpoint} returned success, with ${uniqueBodies} distinct response bodies — confirming the server processed multiple redemptions for the same resource instead of applying it once. An attacker can claim one-use coupons/credits multiple times.`,
        evidence: [
          `6 concurrent POST ${endpoint}`,
          `Successful responses: ${successes.length}/6`,
          `Distinct response bodies among successes: ${uniqueBodies}`,
          `Response samples:`,
          ...successes.slice(0, 3).map((r, i) => `  [${i + 1}] HTTP ${r.status} — ${r.body.slice(0, 100)}`),
          ``,
          `Multiple distinct responses confirm different state was issued, not idempotent behavior.`,
        ].join("\n"),
        recommended_fix: "Use database-level atomic operations (SELECT ... FOR UPDATE, compare-and-swap). Implement distributed locking with Redis SET NX PX. Apply idempotency keys on the client and validate them server-side in a single transaction.",
        cvss_score: 7.5,
        cwe_id: "CWE-362",
        scanner_name: "Bug-Finder/Logic",
        scanner_family: "web",
        confidence: 0.88,
      });
      emit({ type: "log", message: `  [Race CONFIRMED] ${successes.length}/6 succeeded with ${uniqueBodies} distinct bodies at ${endpoint}` });
    } else if (successes.length > 1) {
      emit({ type: "log", message: `  ${endpoint}: ${successes.length} successes but identical bodies — likely idempotent, not a race condition` });
    }
  }

  // ── 4. Mass Assignment / Parameter Pollution ──────────────────────────────
  emit({ type: "log", message: "Testing mass assignment..." });
  const profileEndpoints = [
    `${base}/api/user`, `${base}/api/profile`, `${base}/api/me`, `${base}/api/account`,
    ...discoveredEndpoints.filter(ep => ep.includes("/profile") || ep.includes("/me")).slice(0, 2),
  ];

  for (const endpoint of profileEndpoints.slice(0, 3)) {
    // Try to set privileged fields in a profile update
    const massAssignRes = await ctxFetch(ctx, endpoint, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "test",
        role: "admin",
        isAdmin: true,
        is_admin: true,
        admin: true,
        plan: "enterprise",
        subscription: "unlimited",
        credits: 99999,
      }),
    });

    if (!massAssignRes || massAssignRes.status === 404 || massAssignRes.status === 405) continue;

    // Check if the response reflects the privileged fields back
    const massBody = await massAssignRes.text().catch(() => "");
    const reflected = massBody.includes('"role":"admin"') || massBody.includes('"isAdmin":true') ||
      massBody.includes('"is_admin":true') || massBody.includes('"plan":"enterprise"') ||
      massBody.includes('"credits":99999');

    if (reflected && !seen.has(`mass:${endpoint}`)) {
      seen.add(`mass:${endpoint}`);
      findings.push({
        title: "Mass Assignment — Privileged Fields Accepted in PUT Body",
        category: "Business Logic",
        severity: "critical",
        endpoint,
        description: `The endpoint reflected privileged fields (role, isAdmin, credits, plan) back in the response after a PUT request containing them. This indicates the server applies user-supplied JSON directly to the model without filtering, allowing privilege escalation by any authenticated user.`,
        evidence: [
          `PUT ${endpoint}`,
          `Payload: {"role":"admin","isAdmin":true,"is_admin":true,"credits":99999}`,
          `HTTP ${massAssignRes.status}`,
          ``,
          `Privileged field reflected in response:`,
          massBody.slice(0, 400),
        ].join("\n"),
        recommended_fix: "Use an explicit allowlist of fields that users may update. Never bind request bodies directly to database models. In ORMs, use strong parameters or DTOs that exclude privileged fields.",
        cvss_score: 9.1,
        cwe_id: "CWE-915",
        scanner_name: "Bug-Finder/Logic",
        scanner_family: "web",
        confidence: 0.90,
      });
      emit({ type: "log", message: `  [MASS ASSIGN CONFIRMED] Privileged fields accepted at ${endpoint}` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No business logic vulnerabilities detected" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/Logic", message: `Business logic check complete — ${findings.length} finding(s)` });
  return findings;
}
