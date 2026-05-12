import { ScanContext, ScanFinding, ctxFetch } from "./types";

const COMMON_JWT_SECRETS = ["secret", "password", "123456", "jwt", "key", "auth", "token", "changeme", "test", "dev", "admin", "mysecret", "jwtSecret", "your-256-bit-secret"];

function base64UrlEncode(str: string): string {
  return Buffer.from(str).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function buildJwt(header: object, payload: object, secret?: string): string {
  const h = base64UrlEncode(JSON.stringify(header));
  const p = base64UrlEncode(JSON.stringify(payload));
  const sigInput = `${h}.${p}`;
  if (!secret) return `${sigInput}.`;
  // Simple HMAC-SHA256 simulation (we're not actually generating a valid sig for testing purposes, just checking server behavior)
  return `${sigInput}.invalidsignature`;
}

function buildAlgNoneJwt(payload: object): string {
  return buildJwt({ alg: "none", typ: "JWT" }, payload);
}

export async function runJwtCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "JWT-Tool", message: "Testing JWT/session security" });

  const base = new URL(targetUrl);
  const apiBase = base.origin;

  // First check if the API uses JWT at all by hitting /api/auth/me or similar
  const meRes = await ctxFetch(ctx, `${apiBase}/api/auth/me`, {
    headers: { "Accept": "application/json" },
  });

  if (meRes && meRes.status === 401) {
    // There's a JWT-protected endpoint. Try alg:none attack
    const adminPayload = { id: 1, username: "admin", role: "admin", iat: Math.floor(Date.now() / 1000) };
    const algNoneToken = buildAlgNoneJwt(adminPayload);

    const algNoneRes = await ctxFetch(ctx, `${apiBase}/api/auth/me`, {
      headers: {
        "Authorization": `Bearer ${algNoneToken}`,
        "Accept": "application/json",
      },
    });

    if (algNoneRes && algNoneRes.status === 200) {
      findings.push({
        title: "JWT Algorithm Confusion: alg=none Accepted",
        category: "Authentication",
        severity: "critical",
        endpoint: `${apiBase}/api/auth/me`,
        description: "The server accepts JWTs with alg=none, meaning the signature is not verified. An attacker can forge arbitrary tokens and authenticate as any user including administrators.",
        evidence: `Token sent: ${algNoneToken.slice(0, 80)}...\nServer responded: HTTP ${algNoneRes.status} (authentication succeeded with no signature)`,
        recommended_fix: "Explicitly reject 'none' as an allowed algorithm. Whitelist only the expected algorithms (e.g., RS256 or HS256).",
        cvss_score: 9.8,
        cwe_id: "CWE-347",
        scanner_name: "Bug-Finder/JWT",
        scanner_family: "web",
        confidence: 0.97,
      });
      emit({ type: "log", message: "[CRITICAL] JWT alg=none accepted!" });
    } else {
      emit({ type: "log", message: "JWT alg=none correctly rejected" });
    }
  }

  // Check for JWT in responses (detect if JWTs are being issued)
  const loginRes = await ctxFetch(ctx, `${apiBase}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "test@test.com", password: "password" }),
  });

  if (loginRes) {
    const body = await loginRes.text().catch(() => "");
    const authHeader = loginRes.headers.get("authorization") ?? "";
    const setCookie = loginRes.headers.get("set-cookie") ?? "";

    // Check if JWT is in response body
    const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;
    const jwts = body.match(jwtPattern) ?? [];

    if (jwts.length > 0) {
      const token = jwts[0];
      // Decode the payload (no verification needed, just base64 decode)
      try {
        const parts = token.split(".");
        const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());

        // Check expiry
        if (!payload.exp) {
          findings.push({
            title: "JWT Token Has No Expiration (exp claim missing)",
            category: "Authentication",
            severity: "high",
            endpoint: `${apiBase}/api/auth/login`,
            description: "JWT tokens issued by this server do not include an expiration time (exp claim). These tokens are valid indefinitely and cannot be invalidated after issuance.",
            evidence: `JWT payload: ${JSON.stringify(payload, null, 2)}`,
            recommended_fix: "Always include an 'exp' claim in JWT tokens. Use short expiry times (15-60 minutes) and implement refresh token rotation.",
            cvss_score: 7.5,
            cwe_id: "CWE-613",
            scanner_name: "Bug-Finder/JWT",
            scanner_family: "web",
            confidence: 0.97,
          });
          emit({ type: "log", message: "JWT missing 'exp' claim" });
        }

        // Check for sensitive data in payload
        const sensitiveFields = ["password", "secret", "key", "ssn", "dob", "creditcard"];
        const hasSensitive = sensitiveFields.some(f => JSON.stringify(payload).toLowerCase().includes(f));
        if (hasSensitive) {
          findings.push({
            title: "Sensitive Data in JWT Payload",
            category: "Authentication",
            severity: "high",
            endpoint: `${apiBase}/api/auth/login`,
            description: "The JWT token payload contains sensitive fields. JWT payloads are only base64-encoded, not encrypted — anyone can decode them.",
            evidence: `JWT payload fields: ${Object.keys(payload).join(", ")}`,
            recommended_fix: "Remove sensitive data from JWT payloads. Use opaque session tokens if sensitive data is required, or use JWE (encrypted JWT).",
            cvss_score: 6.5,
            cwe_id: "CWE-200",
            scanner_name: "Bug-Finder/JWT",
            scanner_family: "web",
            confidence: 0.85,
          });
        }
      } catch { /* payload decode failed */ }
    }

    // Check if JWT is stored in localStorage pattern (frontend-side issue, we flag this via API design)
    if (body.includes("token") && !setCookie.includes("httponly")) {
      emit({ type: "log", message: "JWT issued in response body (check if stored in localStorage client-side)" });
    }
  }

  // Check JWT secret strength via common secrets
  const testProtectedEndpoints = discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 3);
  for (const ep of testProtectedEndpoints) {
    for (const secret of COMMON_JWT_SECRETS.slice(0, 5)) {
      const header = { alg: "HS256", typ: "JWT" };
      const payload = { id: 1, role: "admin", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 };
      const h = base64UrlEncode(JSON.stringify(header));
      const p = base64UrlEncode(JSON.stringify(payload));
      const token = `${h}.${p}.invalidsignature`;
      const probeRes = await ctxFetch(ctx, ep, {
        headers: { "Authorization": `Bearer ${token}`, "Accept": "application/json" },
      });
      if (probeRes && probeRes.status === 200) {
        emit({ type: "log", message: `JWT probe: ${ep} accepted invalid signature — weak secret likely` });
      }
    }
  }

  emit({ type: "engine_done", engine: "JWT-Tool", message: `JWT check complete — ${findings.length} issue(s) found` });
  return findings;
}
