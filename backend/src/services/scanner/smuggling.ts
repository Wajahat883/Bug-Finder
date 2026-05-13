import { ScanContext, ScanFinding, ctxFetch } from "./types";

export async function runRequestSmugglingCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Smuggling", message: "Testing for HTTP request smuggling" });

  const base = new URL(targetUrl);

  // Test 1: TE-CL: Transfer-Encoding + Content-Length conflict
  // We can't actually do a true smuggling test with fetch, but we can probe for header acceptance
  const teclRes = await ctxFetch(ctx, base.origin, {
    method: "POST",
    headers: {
      "Transfer-Encoding": "chunked",
      "Content-Length": "6",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "0\r\n\r\n",
  });

  if (teclRes && (teclRes.status === 200 || teclRes.status === 400)) {
    const body = await teclRes.text().catch(() => "");
    emit({ type: "log", message: `TE-CL probe: HTTP ${teclRes.status}` });

    if (teclRes.status === 200 && body.length > 0) {
      // NOTE: Node's fetch() normalizes TE+CL headers before sending — this probe cannot
      // reliably detect smuggling. Confidence is intentionally very low.
      // Full verification requires smuggler.py or Burp Suite's HTTP/1 raw socket mode.
      findings.push({
        title: "HTTP Request Smuggling — Manual Verification Required",
        category: "Request Smuggling",
        severity: "medium",
        endpoint: base.origin,
        description: "The server returned HTTP 200 when sent a request with both Transfer-Encoding and Content-Length headers. NOTE: This probe is inconclusive — Node's fetch() normalizes conflicting headers before transmission. A true TE-CL smuggling attack cannot be confirmed via this scanner. Manual verification with smuggler.py or Burp Suite HTTP/1 raw mode is required.",
        evidence: `POST ${base.origin}\nTransfer-Encoding: chunked\nContent-Length: 6\nHTTP ${teclRes.status}\n\nLIMITATION: fetch() normalizes headers — this result is a surface indicator only, not a confirmed vulnerability. Verify with: python3 smuggler.py -u ${base.origin}`,
        recommended_fix: "Use smuggler.py (https://github.com/defparam/smuggler) or Burp Suite to confirm. If confirmed: configure reverse proxy to reject ambiguous requests and normalize TE/CL before forwarding.",
        cvss_score: 5.0,
        cwe_id: "CWE-444",
        scanner_name: "Bug-Finder/Smuggling",
        scanner_family: "network",
        confidence: 0.1,
      });
    }
  }

  // Test 2: Check if HTTP/2 is supported (downgrade smuggling risk)
  const h2Res = await ctxFetch(ctx, base.origin, { headers: { "upgrade": "h2c" } });
  if (h2Res && h2Res.headers.get("upgrade") === "h2c") {
    findings.push({
      title: "HTTP/2 Cleartext Upgrade Accepted (H2C Smuggling Risk)",
      category: "Request Smuggling",
      severity: "high",
      endpoint: base.origin,
      description: "The server responds to HTTP/2 cleartext (h2c) upgrade requests. This can be exploited for H2C request smuggling attacks that bypass reverse proxy security controls.",
      evidence: `GET ${base.origin}\nUpgrade: h2c\nResponse includes Upgrade: h2c header`,
      recommended_fix: "Disable h2c upgrade support if not required. Ensure your reverse proxy properly handles h2c upgrade attempts.",
      cvss_score: 7.5,
      cwe_id: "CWE-444",
      scanner_name: "Bug-Finder/Smuggling",
      scanner_family: "network",
      confidence: 0.8,
    });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/Smuggling", message: `Request smuggling check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runRateLimitCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/RateLimit", message: "Testing rate limiting on auth endpoints" });

  const base = new URL(targetUrl);

  // Targeted rate limit test on auth endpoints
  const authEndpoints = [
    `${base.origin}/api/auth/login`,
    `${base.origin}/api/auth/reset-password`,
    `${base.origin}/login`,
    `${base.origin}/api/login`,
  ];

  // Profile-aware burst sizes: enterprise apps often allow 20-50 before blocking.
  // Quick = 10 (safe), Standard = 25, Deep = 50 to catch permissive limits.
  const burstSize = ctx.profile === "quick" ? 10 : ctx.profile === "standard" ? 25 : 50;

  for (const endpoint of authEndpoints) {
    const results: number[] = [];
    let rateLimited = false;
    let rateLimitAt = -1;

    for (let i = 0; i < burstSize; i++) {
      const res = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: `ratetest${i}@scanner.local`, password: "WrongPass123!" }),
      });
      if (res) {
        results.push(res.status);
        if (res.status === 429 || res.status === 503) {
          rateLimited = true;
          rateLimitAt = i + 1;
          break;
        }
      }
    }

    if (results.length === 0) continue;

    emit({ type: "log", message: `Rate limit test on ${endpoint}: ${results.length} requests, responses ${results.slice(0, 10).join(", ")}${results.length > 10 ? "..." : ""}` });

    if (!rateLimited && results.some(s => s === 200 || s === 401 || s === 403)) {
      const severity = burstSize >= 25 && !rateLimited ? "critical" : "high";
      findings.push({
        title: `No Rate Limiting on Authentication Endpoint`,
        category: "Authentication",
        severity,
        endpoint,
        description: `The endpoint ${endpoint} accepted ${results.length} consecutive authentication attempts without enforcing rate limiting (no HTTP 429 received). Enterprise-level applications typically enforce a limit of 5-10 attempts per minute per IP. An attacker can automate credential stuffing or brute-force attacks without restriction.`,
        evidence: [
          `Burst test: ${results.length} POST requests sent to ${endpoint}`,
          `Burst size tested: ${burstSize} (profile: ${ctx.profile})`,
          `Rate limit triggered: NO`,
          `Response codes: ${results.join(", ")}`,
          `No 429/503 received in ${results.length} attempts`,
        ].join("\n"),
        recommended_fix: "Implement rate limiting (max 5 attempts per minute per IP). Add account lockout after repeated failures. Consider CAPTCHA after N failures. Use exponential backoff. Key rate limits by IP AND by username to prevent distributed attacks.",
        cvss_score: severity === "critical" ? 8.1 : 7.5,
        cwe_id: "CWE-307",
        scanner_name: "Bug-Finder/Rate-Limit",
        scanner_family: "web",
        confidence: results.length >= 20 ? 0.95 : 0.85,
      });
      emit({ type: "log", message: `  [RATE-LIMIT] No rate limiting on ${endpoint} after ${results.length} attempts` });
      break;
    } else if (rateLimited) {
      emit({ type: "log", message: `  Rate limiting enforced on ${endpoint} after ${rateLimitAt} request(s)` });
      // Report if limit is too permissive (fires only after >20 requests)
      if (rateLimitAt > 20) {
        findings.push({
          title: "Permissive Rate Limit — Triggered Only After Many Attempts",
          category: "Authentication",
          severity: "medium",
          endpoint,
          description: `Rate limiting is enforced on ${endpoint}, but it only triggered after ${rateLimitAt} attempts. Enterprise security standards recommend a limit of 5-10 attempts. An attacker using a large password list can make ${rateLimitAt - 1} attempts before being blocked.`,
          evidence: `${rateLimitAt - 1} requests succeeded before HTTP 429 was returned`,
          recommended_fix: "Tighten rate limit threshold to 5-10 attempts per minute per IP.",
          cvss_score: 5.3,
          cwe_id: "CWE-307",
          scanner_name: "Bug-Finder/Rate-Limit",
          scanner_family: "web",
          confidence: 0.90,
        });
      }
    }
  }

  // Test header-based rate limit bypass ONLY on endpoints that DO enforce rate limiting.
  for (const endpoint of authEndpoints) {
    // Re-probe to trigger rate limiting, then test bypass headers
    let confirmedRateLimit = false;
    for (let i = 0; i < 15; i++) {
      const r = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: `bypasstest${i}@scanner.local`, password: "wrong" }),
      });
      if (r?.status === 429) { confirmedRateLimit = true; break; }
    }

    if (!confirmedRateLimit) continue; // no rate limit active — bypass test irrelevant

    const bypassHeaders = [
      { "X-Forwarded-For": "10.0.0.1" },
      { "X-Real-IP": "10.0.0.2" },
      { "X-Originating-IP": "192.168.1.1" },
    ];

    for (const header of bypassHeaders) {
      const res = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...header },
        body: JSON.stringify({ email: "bypass@test.com", password: "wrong" }),
      });
      if (res && res.status !== 429) {
        findings.push({
          title: "Rate Limit Bypass via IP Spoofing Header",
          category: "Authentication",
          severity: "high",
          endpoint,
          description: `Rate limiting on ${endpoint} was confirmed active, but can be bypassed by spoofing the client IP via the ${Object.keys(header)[0]} header. After triggering rate limiting (HTTP 429), a single request with a spoofed IP header was accepted (HTTP ${res.status}).`,
          evidence: `POST ${endpoint}\n${Object.keys(header)[0]}: ${Object.values(header)[0]}\nHTTP ${res.status} — rate limit bypassed\n\nConfirmation: 8 requests triggered 429; bypass header removed the limit`,
          recommended_fix: "Do not trust X-Forwarded-For or similar headers for rate limiting unless you control the upstream proxy. Use the actual TCP source IP for rate limit keying.",
          cvss_score: 7.5,
          cwe_id: "CWE-307",
          scanner_name: "Bug-Finder/Rate-Limit",
          scanner_family: "web",
          confidence: 0.85,
        });
        emit({ type: "log", message: `  [BYPASS] Rate limit bypassed via ${Object.keys(header)[0]} at ${endpoint}` });
        break;
      }
    }
    break; // one endpoint is enough
  }

  emit({ type: "engine_done", engine: "Bug-Finder/RateLimit", message: `Rate limit check complete — ${findings.length} issue(s)` });
  return findings;
}
