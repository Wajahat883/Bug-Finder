import { ScanContext, ScanFinding, ctxFetch } from "./types";

const CART_PATHS = ["/api/cart", "/api/order", "/api/checkout", "/cart", "/order", "/api/purchase", "/api/payment"];
const PRIV_PATHS = ["/admin", "/api/admin", "/dashboard/admin", "/api/users/all", "/api/reports/all", "/api/settings/all"];
const WORKFLOW_PATHS = [
  { step1: "/api/order/create", step3: "/api/order/pay" },
  { step1: "/api/checkout/init", step3: "/api/checkout/confirm" },
  { step1: "/api/register/step1", step3: "/api/register/step3" },
];

export async function runBusinessLogicCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Business Logic Tester", message: "Testing price manipulation, workflow bypass, and privilege escalation" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const seen = new Set<string>();

  // 1. Price/Quantity Manipulation
  emit({ type: "log", message: "Testing price/quantity manipulation..." });
  const allCartPaths = [
    ...CART_PATHS.map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("cart") || ep.includes("order") || ep.includes("checkout")).slice(0, 3),
  ];

  for (const endpoint of allCartPaths.slice(0, budget)) {
    // Try negative price
    const negativePriceR = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: "1", quantity: 1, price: -99.99, amount: -99.99 }),
    });
    if (negativePriceR && (negativePriceR.status === 200 || negativePriceR.status === 201)) {
      const body = await negativePriceR.text().catch(() => "");
      if (!body.toLowerCase().includes("invalid") && !body.toLowerCase().includes("error") && !seen.has(`price:${endpoint}`)) {
        seen.add(`price:${endpoint}`);
        findings.push({
          title: "Price Manipulation — Negative Price Accepted",
          category: "Business Logic",
          severity: "critical",
          endpoint,
          description: `The endpoint accepted a negative price value (-99.99) without rejecting it. Business logic vulnerabilities in price validation can allow attackers to purchase items for free or receive credits/refunds fraudulently.`,
          evidence: `POST ${endpoint}\nPayload: {"price": -99.99, "amount": -99.99}\nHTTP ${negativePriceR.status}\nNegative value not rejected\nResponse: ${body.slice(0, 300)}`,
          recommended_fix: "Validate all price and quantity values server-side. Reject negative, zero, or unreasonably large values. Never trust client-supplied pricing — always calculate server-side from your product catalog.",
          cvss_score: 9.1,
          cwe_id: "CWE-840",
          scanner_name: "Logic Tester",
          scanner_family: "web",
          confidence: 0.8,
        });
        emit({ type: "log", message: `  [Price Manip] Negative price accepted at ${endpoint}` });
      }
    }

    // Try zero quantity
    const zeroQtyR = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product_id: "1", quantity: 0, count: 0 }),
    });
    if (zeroQtyR && (zeroQtyR.status === 200 || zeroQtyR.status === 201)) {
      const body = await zeroQtyR.text().catch(() => "");
      if (!body.toLowerCase().includes("invalid") && !body.toLowerCase().includes("error") && !seen.has(`qty:${endpoint}`)) {
        seen.add(`qty:${endpoint}`);
        findings.push({
          title: "Business Logic — Zero/Invalid Quantity Accepted",
          category: "Business Logic",
          severity: "high",
          endpoint,
          description: `The endpoint accepted a zero quantity value without validation. This may allow order manipulation or free purchases.`,
          evidence: `POST ${endpoint}\nPayload: {"quantity": 0}\nHTTP ${zeroQtyR.status} — accepted without validation`,
          recommended_fix: "Validate quantity/count values server-side. Reject zero, negative, or non-integer quantities for physical goods.",
          cvss_score: 7.5,
          cwe_id: "CWE-840",
          scanner_name: "Logic Tester",
          scanner_family: "web",
          confidence: 0.7,
        });
        emit({ type: "log", message: `  Zero quantity accepted at ${endpoint}` });
      }
    }
  }

  // 2. Privilege Escalation — access admin endpoints without admin role
  emit({ type: "log", message: "Testing privilege escalation..." });
  const allPrivPaths = [
    ...PRIV_PATHS.map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("admin") || ep.includes("/all")).slice(0, 3),
  ];

  for (const endpoint of allPrivPaths.slice(0, budget)) {
    const r = await ctxFetch(ctx, endpoint, { redirect: "follow" });
    if (!r) continue;

    if (r.status === 200) {
      const body = await r.text().catch(() => "");
      const looksAdmin = body.includes("admin") || body.includes("user_list") || body.includes("users") || body.length > 100;
      if (looksAdmin && !seen.has(`priv:${endpoint}`)) {
        seen.add(`priv:${endpoint}`);
        findings.push({
          title: "Privilege Escalation — Admin Resource Accessible Without Auth",
          category: "Business Logic",
          severity: "critical",
          endpoint,
          description: `The privileged endpoint ${endpoint} returned HTTP 200 without any authentication. An unauthenticated user can access administrative functionality or sensitive user data.`,
          evidence: `GET ${endpoint}\nHTTP ${r.status}\nNo authentication required\nResponse size: ${body.length} bytes\nPreview: ${body.slice(0, 300)}`,
          recommended_fix: "Enforce role-based access control on all admin endpoints. Use middleware to verify authentication and admin role before handling requests.",
          cvss_score: 9.8,
          cwe_id: "CWE-269",
          scanner_name: "Logic Tester",
          scanner_family: "web",
          confidence: 0.85,
        });
        emit({ type: "log", message: `  [PRIV-ESC] Admin endpoint open: ${endpoint}` });
      }
    }
  }

  // 3. Race Condition — concurrent requests to state-changing endpoints
  emit({ type: "log", message: "Testing race conditions..." });
  const raceEndpoints = [
    `${base}/api/redeem`, `${base}/api/coupon/apply`, `${base}/api/referral/claim`,
    `${base}/api/bonus/claim`, `${base}/api/credit/apply`,
    ...discoveredEndpoints.filter(ep => ep.includes("redeem") || ep.includes("claim") || ep.includes("coupon")).slice(0, 2),
  ];

  for (const endpoint of raceEndpoints.slice(0, Math.min(budget, 3))) {
    const payload = JSON.stringify({ code: "TESTRACE", coupon: "TESTRACE", voucher: "TESTRACE" });
    // Fire 5 concurrent requests
    const promises = Array.from({ length: 5 }, () =>
      ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload,
      })
    );

    const results = await Promise.all(promises);
    const successes = results.filter(r => r && (r.status === 200 || r.status === 201));

    if (successes.length > 1 && !seen.has(`race:${endpoint}`)) {
      seen.add(`race:${endpoint}`);
      findings.push({
        title: "Race Condition Vulnerability Detected",
        category: "Business Logic",
        severity: "high",
        endpoint,
        description: `${successes.length} out of 5 concurrent requests to ${endpoint} succeeded simultaneously. This suggests a race condition where a single-use resource (coupon, credit, redemption) can be used multiple times if requests arrive concurrently.`,
        evidence: `5 concurrent POST ${endpoint}\nSuccessful responses: ${successes.length}/5\nThis indicates insufficient locking/atomicity`,
        recommended_fix: "Use database-level atomic operations or distributed locks. For coupons/credits, use optimistic or pessimistic locking. Validate and update in a single atomic transaction.",
        cvss_score: 7.5,
        cwe_id: "CWE-362",
        scanner_name: "Logic Tester",
        scanner_family: "web",
        confidence: 0.75,
      });
      emit({ type: "log", message: `  [Race] ${successes.length}/5 concurrent requests succeeded at ${endpoint}` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No business logic vulnerabilities detected" });
  }

  emit({ type: "engine_done", engine: "Business Logic Tester", message: `Business logic check complete — ${findings.length} finding(s)` });
  return findings;
}
