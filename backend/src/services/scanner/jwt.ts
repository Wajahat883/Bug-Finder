import { createHmac } from "crypto";
import { ScanContext, ScanFinding, ctxFetch, curlReproducer } from "./types";

const COMMON_JWT_SECRETS = [
  "secret", "password", "123456", "jwt", "key", "auth", "token",
  "changeme", "test", "dev", "admin", "mysecret", "jwtSecret",
  "your-256-bit-secret", "supersecret", "s3cr3t", "qwerty",
  "letmein", "pass", "jwt_secret", "JWT_SECRET", "app_secret",
];

function base64UrlEncode(str: string): string {
  return Buffer.from(str).toString("base64url");
}

// Builds a properly signed HS256 JWT using a real HMAC-SHA256 computation
function buildSignedJwt(payload: object, secret: string): string {
  const h = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = base64UrlEncode(JSON.stringify(payload));
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

// Builds an alg=none JWT (no signature — tests whether server enforces algorithm)
function buildAlgNoneJwt(payload: object): string {
  const h = base64UrlEncode(JSON.stringify({ alg: "none", typ: "JWT" }));
  const p = base64UrlEncode(JSON.stringify(payload));
  return `${h}.${p}.`;
}

// Detects JWT-protected endpoints by probing common auth paths
async function findJwtEndpoint(ctx: ScanContext, base: string): Promise<string | null> {
  const candidates = [
    `${base}/api/auth/me`, `${base}/api/me`, `${base}/api/user`,
    `${base}/api/profile`, `${base}/api/v1/me`, `${base}/api/account`,
  ];
  for (const ep of candidates) {
    const r = await ctxFetch(ctx, ep, { headers: { Accept: "application/json" } });
    if (r && r.status === 401) return ep;
  }
  return null;
}

export async function runJwtCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/JWT", message: "Testing JWT security: alg=none, weak secrets, missing claims" });

  const apiBase = new URL(targetUrl).origin;

  // ── 1. Find a JWT-protected endpoint ──────────────────────────────────────
  const protectedEp = await findJwtEndpoint(ctx, apiBase);
  if (protectedEp) {
    emit({ type: "log", message: `Found JWT-protected endpoint: ${protectedEp}` });

    const adminPayload = {
      id: 1, sub: "1", username: "admin", role: "admin", email: "admin@admin.com",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    };

    // ── 1a. alg=none attack ────────────────────────────────────────────────
    const algNoneToken = buildAlgNoneJwt(adminPayload);
    const algNoneRes = await ctxFetch(ctx, protectedEp, {
      headers: { Authorization: `Bearer ${algNoneToken}`, Accept: "application/json" },
    });

    if (algNoneRes && algNoneRes.status === 200) {
      const body = await algNoneRes.text().catch(() => "");
      findings.push({
        title: "JWT Algorithm Confusion: alg=none Accepted",
        category: "Authentication",
        severity: "critical",
        endpoint: protectedEp,
        description: "The server accepts JWTs with alg=none, meaning the signature is not verified at all. An attacker can forge tokens for any user, including administrators, with zero knowledge of the signing secret.",
        evidence: [
          `Forged JWT sent to: GET ${protectedEp}`,
          `Token header: {"alg":"none","typ":"JWT"}`,
          `Token payload: ${JSON.stringify(adminPayload)}`,
          `Signature: [empty — no signature]`,
          `HTTP response: ${algNoneRes.status}`,
          `Response body (${body.length}b): ${body.slice(0, 300)}`,
          ``,
          `Server authenticated the unsigned token — signature verification is disabled.`,
        ].join("\n"),
        recommended_fix: "Explicitly reject 'none' as an allowed algorithm. Maintain a server-side allowlist of accepted algorithms (e.g., only HS256 or RS256). Never trust the algorithm from the token header.",
        cvss_score: 9.8,
        cwe_id: "CWE-347",
        scanner_name: "Bug-Finder/JWT",
        scanner_family: "web",
        confidence: 0.99,
        reproduction_curl: curlReproducer("GET", protectedEp, { Authorization: `Bearer ${algNoneToken}`, Accept: "application/json" }),
      });
      emit({ type: "log", message: "[CRITICAL] JWT alg=none accepted — full authentication bypass" });
    } else {
      emit({ type: "log", message: `alg=none correctly rejected (HTTP ${algNoneRes?.status ?? "no response"})` });
    }

    // ── 1b. Real HMAC brute-force with candidate secrets ───────────────────
    // Each candidate secret is used to compute a real, valid HMAC-SHA256 signature.
    // If the server accepts it, the secret is confirmed.
    emit({ type: "log", message: `Brute-forcing ${COMMON_JWT_SECRETS.length} common JWT secrets against ${protectedEp}...` });
    let weakSecretFound = false;

    for (const secret of COMMON_JWT_SECRETS) {
      if (weakSecretFound) break;
      const token = buildSignedJwt(adminPayload, secret);
      const probeRes = await ctxFetch(ctx, protectedEp, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      });

      if (probeRes && probeRes.status === 200) {
        weakSecretFound = true;
        const body = await probeRes.text().catch(() => "");
        findings.push({
          title: "JWT Signed with Weak / Common Secret",
          category: "Authentication",
          severity: "critical",
          endpoint: protectedEp,
          description: `The JWT secret key is "${secret}" — a common, guessable value. An attacker who discovers or guesses the secret can forge valid tokens for any user. This was confirmed by constructing a real HMAC-SHA256 signed JWT with this secret and receiving an authenticated response.`,
          evidence: [
            `Secret tested: "${secret}"`,
            `Real HMAC-SHA256 signed token sent to: GET ${protectedEp}`,
            `Token (first 80 chars): ${token.slice(0, 80)}...`,
            `HTTP response: ${probeRes.status} (authenticated)`,
            `Response body: ${body.slice(0, 200)}`,
            ``,
            `Verification: token was computed as HMAC-SHA256("${secret}", header+"."+payload)`,
            `Server accepted it — the secret is confirmed as "${secret}"`,
          ].join("\n"),
          recommended_fix: "Rotate the JWT secret immediately to a cryptographically random value of at least 256 bits. Use `openssl rand -hex 32` to generate one. Store it in an environment variable, never in source code.",
          cvss_score: 9.8,
          cwe_id: "CWE-798",
          scanner_name: "Bug-Finder/JWT",
          scanner_family: "web",
          confidence: 0.99,
        });
        emit({ type: "log", message: `[CRITICAL] JWT weak secret confirmed: "${secret}"` });
      }
    }

    if (!weakSecretFound) {
      emit({ type: "log", message: `JWT secret not in common list (${COMMON_JWT_SECRETS.length} secrets tested)` });
    }
  } else {
    emit({ type: "log", message: "No JWT-protected endpoint found — testing login endpoint for token issuance" });
  }

  // ── 2. Inspect issued JWTs from login response ────────────────────────────
  const loginRes = await ctxFetch(ctx, `${apiBase}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "test@test.com", password: "password" }),
  });

  if (loginRes) {
    const body = await loginRes.text().catch(() => "");
    const setCookie = loginRes.headers.get("set-cookie") ?? "";

    const jwtPattern = /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;
    const jwts = body.match(jwtPattern) ?? [];

    if (jwts.length > 0) {
      const token = jwts[0]!;
      try {
        const parts = token.split(".");
        const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
        const payload = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());

        emit({ type: "log", message: `JWT issued: alg=${header.alg}, exp=${payload.exp ? new Date(payload.exp * 1000).toISOString() : "MISSING"}` });

        // Check missing expiry
        if (!payload.exp) {
          findings.push({
            title: "JWT Token Has No Expiration (exp claim missing)",
            category: "Authentication",
            severity: "high",
            endpoint: `${apiBase}/api/auth/login`,
            description: "Issued JWTs have no expiration time. They remain valid forever and cannot be invalidated after issuance — meaning a stolen token gives permanent access.",
            evidence: [
              `POST ${apiBase}/api/auth/login`,
              `HTTP ${loginRes.status}`,
              `Decoded JWT header: ${JSON.stringify(header)}`,
              `Decoded JWT payload: ${JSON.stringify(payload, null, 2)}`,
              `exp claim: MISSING`,
            ].join("\n"),
            recommended_fix: "Always include an 'exp' claim. Use short expiry (15–60 minutes) and implement refresh token rotation. Maintain a server-side revocation list for sensitive operations.",
            cvss_score: 7.5,
            cwe_id: "CWE-613",
            scanner_name: "Bug-Finder/JWT",
            scanner_family: "web",
            confidence: 0.97,
          });
          emit({ type: "log", message: "JWT missing 'exp' claim" });
        }

        // Check expiry too long (> 7 days)
        if (payload.exp && payload.iat) {
          const ttlHours = (payload.exp - payload.iat) / 3600;
          if (ttlHours > 168) {
            findings.push({
              title: "JWT Expiry Too Long (> 7 Days)",
              category: "Authentication",
              severity: "medium",
              endpoint: `${apiBase}/api/auth/login`,
              description: `JWT tokens are valid for ${Math.round(ttlHours / 24)} days. Long-lived tokens increase the window of exposure if a token is stolen.`,
              evidence: [
                `iat: ${payload.iat} (${new Date(payload.iat * 1000).toISOString()})`,
                `exp: ${payload.exp} (${new Date(payload.exp * 1000).toISOString()})`,
                `TTL: ${Math.round(ttlHours)} hours (${Math.round(ttlHours / 24)} days)`,
              ].join("\n"),
              recommended_fix: "Set JWT expiry to 15–60 minutes. Implement refresh tokens for long sessions. Provide a token revocation endpoint.",
              cvss_score: 5.3,
              cwe_id: "CWE-613",
              scanner_name: "Bug-Finder/JWT",
              scanner_family: "web",
              confidence: 0.95,
            });
          }
        }

        // Check sensitive data in payload
        const payloadStr = JSON.stringify(payload).toLowerCase();
        const sensitiveFields = ["password", "secret", "key", "ssn", "dob", "creditcard", "cvv", "pin"];
        const hitField = sensitiveFields.find(f => payloadStr.includes(f));
        if (hitField) {
          findings.push({
            title: "Sensitive Data in JWT Payload",
            category: "Authentication",
            severity: "high",
            endpoint: `${apiBase}/api/auth/login`,
            description: `The JWT payload contains a field matching "${hitField}". JWT payloads are base64-encoded only — anyone who obtains the token can decode and read all fields without any key.`,
            evidence: [
              `Decoded JWT payload fields: ${Object.keys(payload).join(", ")}`,
              `Sensitive field detected: "${hitField}"`,
              `Full payload: ${JSON.stringify(payload, null, 2)}`,
            ].join("\n"),
            recommended_fix: "Remove sensitive data from JWT payloads. Store only non-sensitive identifiers (user ID, role). Use JWE (JSON Web Encryption) if sensitive claims are required.",
            cvss_score: 6.5,
            cwe_id: "CWE-200",
            scanner_name: "Bug-Finder/JWT",
            scanner_family: "web",
            confidence: 0.90,
          });
        }

        // Check weak algorithm
        if (header.alg === "HS256" || header.alg === "HS384") {
          emit({ type: "log", message: `JWT uses ${header.alg} — symmetric algorithm (acceptable, but RS256 preferred for distributed systems)` });
        }
        if (header.alg === "none" || !header.alg) {
          findings.push({
            title: "JWT Issued with alg=none",
            category: "Authentication",
            severity: "critical",
            endpoint: `${apiBase}/api/auth/login`,
            description: "The server is issuing JWTs with alg=none, meaning tokens are unsigned. Any attacker can forge a token for any user.",
            evidence: `Decoded header: ${JSON.stringify(header)}\nNo signature algorithm specified`,
            recommended_fix: "Always sign JWTs with a strong algorithm (HS256 minimum, RS256 preferred).",
            cvss_score: 9.8,
            cwe_id: "CWE-347",
            scanner_name: "Bug-Finder/JWT",
            scanner_family: "web",
            confidence: 0.99,
          });
        }

      } catch {
        emit({ type: "log", message: "JWT decode failed — non-standard encoding" });
      }
    }

    // Token in body without HttpOnly cookie — likely localStorage
    if (body.includes("token") && !setCookie.toLowerCase().includes("httponly")) {
      findings.push({
        title: "JWT Returned in Response Body — Likely Stored in localStorage",
        category: "Authentication",
        severity: "medium",
        endpoint: `${apiBase}/api/auth/login`,
        description: "The login response returns a token in the JSON body, and no HttpOnly cookie was set. Tokens stored in localStorage are accessible via JavaScript and stolen by XSS attacks. HttpOnly cookies prevent this.",
        evidence: [
          `POST ${apiBase}/api/auth/login → HTTP ${loginRes.status}`,
          `Token found in response body (not in Set-Cookie: HttpOnly)`,
          `Set-Cookie header: ${setCookie || "[not set]"}`,
        ].join("\n"),
        recommended_fix: "Store session tokens in HttpOnly, Secure, SameSite=Strict cookies instead of returning them in JSON bodies for localStorage storage.",
        cvss_score: 5.3,
        cwe_id: "CWE-922",
        scanner_name: "Bug-Finder/JWT",
        scanner_family: "web",
        confidence: 0.75,
      });
      emit({ type: "log", message: "JWT in body without HttpOnly cookie — likely localStorage storage" });
    }
  }

  emit({ type: "engine_done", engine: "Bug-Finder/JWT", message: `JWT check complete — ${findings.length} issue(s) found` });
  return findings;
}
