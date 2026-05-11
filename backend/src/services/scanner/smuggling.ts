import { ScanContext, ScanFinding, safeFetch } from "./types";

export async function runRequestSmugglingCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Smuggling Probe", message: "Testing for HTTP request smuggling" });

  const base = new URL(targetUrl);

  // Test 1: TE-CL: Transfer-Encoding + Content-Length conflict
  // We can't actually do a true smuggling test with fetch, but we can probe for header acceptance
  const teclRes = await safeFetch(base.origin, {
    method: "POST",
    headers: {
      "Transfer-Encoding": "chunked",
      "Content-Length": "6",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "0\r\n\r\n",
  });

  if (teclRes && (teclRes.status === 200 || teclRes.status === 400)) {
    // If 400 — good, server rejected. If 200 — may be misconfigured
    const body = await teclRes.text().catch(() => "");
    emit({ type: "log", message: `TE-CL probe: HTTP ${teclRes.status}` });

    if (teclRes.status === 200 && body.length > 0) {
      findings.push({
        title: "Potential HTTP Request Smuggling: TE-CL Ambiguity",
        category: "Request Smuggling",
        severity: "high",
        endpoint: base.origin,
        description: "The server accepted a request with both Transfer-Encoding and Content-Length headers. This creates ambiguity that can be exploited for HTTP request smuggling attacks, potentially bypassing security controls, poisoning caches, or hijacking user sessions.",
        evidence: `POST ${base.origin}\nTransfer-Encoding: chunked\nContent-Length: 6\nHTTP ${teclRes.status}`,
        recommended_fix: "Configure the front-end server to reject requests with both Transfer-Encoding and Content-Length headers. Normalize requests between reverse proxy and backend.",
        cvss_score: 8.1,
        cwe_id: "CWE-444",
        scanner_name: "Smuggling Probe",
        scanner_family: "network",
        confidence: 0.6,
      });
    }
  }

  // Test 2: Check if HTTP/2 is supported (downgrade smuggling risk)
  const http2headers = new Headers({ "host": base.hostname });
  const h2Res = await safeFetch(base.origin, { headers: { "upgrade": "h2c" } });
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
      scanner_name: "Smuggling Probe",
      scanner_family: "network",
      confidence: 0.8,
    });
  }

  emit({ type: "engine_done", engine: "Smuggling Probe", message: `Request smuggling check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runRateLimitCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Rate Limit Tester", message: "Testing rate limiting on auth endpoints" });

  const base = new URL(targetUrl);

  // Targeted rate limit test on auth endpoints
  const authEndpoints = [
    `${base.origin}/api/auth/login`,
    `${base.origin}/api/auth/reset-password`,
    `${base.origin}/login`,
    `${base.origin}/api/login`,
  ];

  for (const endpoint of authEndpoints) {
    // Send 6 rapid requests and check for rate limit response
    const results: number[] = [];
    let rateLimited = false;

    for (let i = 0; i < 6; i++) {
      const res = await safeFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: `test${i}@test.com`, password: "wrongpassword" }),
      });
      if (res) {
        results.push(res.status);
        if (res.status === 429) { rateLimited = true; break; }
      }
    }

    if (results.length === 0) continue;

    emit({ type: "log", message: `Rate limit test on ${endpoint}: responses ${results.join(", ")}` });

    if (!rateLimited && results.some(s => s === 200 || s === 401 || s === 403)) {
      findings.push({
        title: `No Rate Limiting on Authentication Endpoint`,
        category: "Authentication",
        severity: "high",
        endpoint,
        description: `The endpoint ${endpoint} does not enforce rate limiting. An attacker can make unlimited login attempts, enabling brute-force password attacks, credential stuffing, and account enumeration.`,
        evidence: `6 rapid POST requests to ${endpoint}\nResponses: ${results.join(", ")}\nNo 429 (Too Many Requests) returned`,
        recommended_fix: "Implement rate limiting (max 5 attempts per minute per IP). Add account lockout after repeated failures. Consider CAPTCHA after N failures. Use exponential backoff.",
        cvss_score: 7.5,
        cwe_id: "CWE-307",
        scanner_name: "Rate Limit Tester",
        scanner_family: "web",
        confidence: 0.85,
      });
      emit({ type: "log", message: `  [RATE-LIMIT] No rate limiting on ${endpoint}` });
      break; // Report once
    } else if (rateLimited) {
      emit({ type: "log", message: `  Rate limiting properly enforced on ${endpoint}` });
    }
  }

  // Also test for header-based rate limit bypass
  for (const f of findings.filter(f => f.category === "Authentication")) {
    const bypassHeaders = [
      { "X-Forwarded-For": "127.0.0.1" },
      { "X-Real-IP": "10.0.0.1" },
      { "X-Originating-IP": "192.168.1.1" },
      { "X-Remote-IP": "127.0.0.1" },
    ];

    for (const header of bypassHeaders) {
      const res = await safeFetch(f.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...header },
        body: JSON.stringify({ email: "test@test.com", password: "wrong" }),
      });
      if (res && res.status !== 429) {
        findings.push({
          title: "Rate Limit Bypass via IP Spoofing Header",
          category: "Authentication",
          severity: "high",
          endpoint: f.endpoint,
          description: `Rate limits on ${f.endpoint} can be bypassed by spoofing the client IP via the ${Object.keys(header)[0]} header. An attacker can reset their request count by changing this header value.`,
          evidence: `Header: ${Object.keys(header)[0]}: ${Object.values(header)[0]}\nServer accepted the request without rate limiting`,
          recommended_fix: "Do not trust X-Forwarded-For or similar headers for rate limiting unless you control the proxy layer. Use the actual TCP connection IP for rate limit keys.",
          cvss_score: 7.5,
          cwe_id: "CWE-307",
          scanner_name: "Rate Limit Tester",
          scanner_family: "web",
          confidence: 0.75,
        });
        break;
      }
    }
  }

  emit({ type: "engine_done", engine: "Rate Limit Tester", message: `Rate limit check complete — ${findings.length} issue(s)` });
  return findings;
}
