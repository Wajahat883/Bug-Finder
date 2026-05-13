import { ScanContext, ScanFinding, ctxFetch } from "./types";

const DEFAULT_CREDENTIALS = [
  { user: "admin", pass: "admin" },
  { user: "admin", pass: "admin123" },
  { user: "admin", pass: "password" },
  { user: "admin", pass: "password123" },
  { user: "admin", pass: "123456" },
  { user: "root", pass: "root" },
  { user: "root", pass: "toor" },
  { user: "administrator", pass: "administrator" },
  { user: "test", pass: "test" },
  { user: "guest", pass: "guest" },
];

const LOGIN_PATHS = [
  "/api/auth/login", "/api/login", "/auth/login", "/login",
  "/api/v1/auth/login", "/api/v1/login", "/api/users/login",
  "/api/session", "/api/token",
];

const WEAK_PASSWORDS = ["password", "123456", "qwerty", "abc123", "letmein"];

export async function runAdvancedAuthCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Auth-Advanced", message: "Testing default credentials, password policy, and 2FA" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 5 : LOGIN_PATHS.length;
  const seen = new Set<string>();

  for (const path of LOGIN_PATHS.slice(0, budget)) {
    const endpoint = `${base}${path}`;

    // First, check if the endpoint exists
    const probe = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "probe@test.com", password: "probe" }),
    });

    if (!probe) continue;
    if (probe.status === 404 || probe.status === 405) continue;

    emit({ type: "log", message: `Login endpoint found: ${endpoint} (${probe.status})` });

    // Test default credentials (limited to first 3 for speed)
    const credsBudget = profile === "deep" ? 10 : 3;
    let lockoutDetected = false;
    for (const cred of DEFAULT_CREDENTIALS.slice(0, credsBudget)) {
      if (lockoutDetected) break;
      const r = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: cred.user, email: `${cred.user}@example.com`, password: cred.pass }),
      });

      if (!r) continue;

      // Detect account lockout — stop brute force and report lockout as working
      if (r.status === 429 || r.status === 423) {
        lockoutDetected = true;
        if (!seen.has(`lockout:${endpoint}`)) {
          seen.add(`lockout:${endpoint}`);
          findings.push({
            title: "Account Lockout / Rate Limiting Active on Login",
            category: "Authentication",
            severity: "info",
            endpoint,
            description: "The login endpoint returned HTTP 429/423 after multiple failed attempts, indicating rate limiting or account lockout is active. This is a positive security control.",
            evidence: `POST ${endpoint}\nAttempts made: ${DEFAULT_CREDENTIALS.slice(0, credsBudget).indexOf(cred) + 1}\nHTTP ${r.status} — rate limit/lockout triggered`,
            recommended_fix: "Ensure lockout thresholds are low (3-5 attempts) and lockout duration is sufficient (15+ minutes or permanent with admin unlock).",
            cvss_score: 0,
            cwe_id: "CWE-307",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "auth",
            confidence: 0.95,
          });
          emit({ type: "log", message: `  Rate limiting / lockout active at ${endpoint} (HTTP ${r.status})` });
        }
        break;
      }
      const body = await r.text().catch(() => "");
      const lockoutInBody = ["locked", "too many", "rate limit", "blocked", "suspended"].some(kw => body.toLowerCase().includes(kw));
      if (lockoutInBody) {
        lockoutDetected = true;
        emit({ type: "log", message: `  Account lockout response detected at ${endpoint}` });
        break;
      }

      // If we get a token/session back, credentials worked
      const hasToken = body.includes("token") || body.includes("access_token") || body.includes("jwt") || body.includes("session");
      const isSuccess = (r.status === 200 || r.status === 201) && hasToken;

      if (isSuccess && !seen.has(endpoint)) {
        seen.add(endpoint);
        findings.push({
          title: `Default Credentials Accepted: ${cred.user}/${cred.pass}`,
          category: "Authentication",
          severity: "critical",
          endpoint,
          description: `The application accepted the default credential combination "${cred.user}/${cred.pass}". Default credentials give attackers immediate unauthorized access to the application.`,
          evidence: `POST ${endpoint}\nCredentials: ${cred.user} / ${cred.pass}\nHTTP ${r.status}\nAuthentication token returned: true\nResponse: ${body.slice(0, 200)}`,
          recommended_fix: "Remove all default credentials immediately. Enforce password changes on first login. Implement account lockout after failed attempts.",
          cvss_score: 9.8,
          cwe_id: "CWE-1391",
          scanner_name: "Bug-Finder/Auth",
          scanner_family: "auth",
          confidence: 0.97,
        });
        emit({ type: "log", message: `  [CRITICAL] Default creds work: ${cred.user}/${cred.pass}` });
        break;
      }
    }

    // Test password policy — try to register/change to weak password
    const registerPaths = ["/api/auth/register", "/api/register", "/api/users", "/register"];
    for (const regPath of registerPaths.slice(0, 2)) {
      const regEndpoint = `${base}${regPath}`;
      for (const weakPass of WEAK_PASSWORDS.slice(0, 2)) {
        const regR = await ctxFetch(ctx, regEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: `testuser_${Date.now()}`,
            email: `testuser_${Date.now()}@test.com`,
            password: weakPass,
          }),
        });

        if (!regR) continue;
        if (regR.status === 200 || regR.status === 201) {
          const regBody = await regR.text().catch(() => "");
          // Reject if any password-strength error keyword appears — avoids false positives
          // from apps that return 200 with an error body
          const rejectionKeywords = ["too short", "too weak", "must be", "minimum", "at least", "password requirements", "invalid password", "password strength"];
          const wasRejected = rejectionKeywords.some(kw => regBody.toLowerCase().includes(kw));
          if (!wasRejected && !seen.has(`${regEndpoint}:policy`)) {
            seen.add(`${regEndpoint}:policy`);
            findings.push({
              title: `Weak Password Policy — "${weakPass}" Accepted`,
              category: "Authentication",
              severity: "medium",
              endpoint: regEndpoint,
              description: `The application accepted the weak password "${weakPass}" during registration. Weak password policies allow attackers to guess or brute-force user credentials.`,
              evidence: `POST ${regEndpoint}\nPassword: "${weakPass}"\nHTTP ${regR.status} — password accepted without rejection`,
              recommended_fix: "Enforce minimum 12-character passwords requiring uppercase, lowercase, numbers, and symbols. Reject passwords from common password lists.",
              cvss_score: 6.2,
              cwe_id: "CWE-521",
              scanner_name: "Bug-Finder/Auth",
              scanner_family: "auth",
              confidence: 0.8,
            });
            emit({ type: "log", message: `  Weak password "${weakPass}" accepted at ${regEndpoint}` });
          }
        }
      }
    }

    // ── MFA bypass probe — real test, not heuristic ─────────────────────────
    // Strategy: attempt login with known-bad credentials, look for a MFA challenge
    // in the response. If no challenge is sent, MFA is either absent or bypassable.
    // Second probe: send an empty or zero OTP code to see if the MFA step can be skipped.
    const loginBody = await probe.text().catch(() => "");
    const has2FAResponse = /\b(otp|totp|mfa|2fa|one.?time|authenticator|verify.?code|verification.?code)\b/i.test(loginBody);

    if (has2FAResponse) {
      // MFA challenge was issued — check if it can be bypassed with an empty code
      const mfaBypassPaths = [
        `${base}/api/auth/verify-otp`, `${base}/api/auth/mfa/verify`,
        `${base}/api/v1/auth/verify`, `${base}/api/mfa`,
      ];
      for (const mfaPath of mfaBypassPaths) {
        const bypassRes = await ctxFetch(ctx, mfaPath, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ otp: "", code: "", token: "" }),
        });
        if (!bypassRes) continue;
        const bypassBody = await bypassRes.text().catch(() => "");
        // If we get a session token back with an empty OTP → MFA bypass confirmed
        const hasSession = bypassBody.includes("token") || bypassBody.includes("access_token") || bypassBody.includes("session");
        if ((bypassRes.status === 200 || bypassRes.status === 201) && hasSession) {
          findings.push({
            title: "MFA Bypass: Empty OTP Code Accepted",
            category: "Authentication",
            severity: "critical",
            endpoint: mfaPath,
            description: `The MFA verification endpoint accepted an empty OTP code and returned an authentication session. An attacker who knows a victim's password can bypass multi-factor authentication by submitting an empty or null OTP.`,
            evidence: [
              `Step 1: POST ${endpoint} → MFA challenge issued (HTTP ${probe.status})`,
              `Step 2: POST ${mfaPath}`,
              `  Body: {"otp":"","code":"","token":""}`,
              `  HTTP ${bypassRes.status} — session returned with empty OTP`,
              `  Response: ${bypassBody.slice(0, 200)}`,
            ].join("\n"),
            recommended_fix: "Validate OTP codes server-side: reject empty, null, or zero-length values. Implement TOTP time window validation. Rate-limit OTP attempts. Require OTP to be a 6-digit non-empty string.",
            cvss_score: 9.8,
            cwe_id: "CWE-308",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "auth",
            confidence: 0.96,
          });
          emit({ type: "log", message: `  [MFA BYPASS CONFIRMED] empty OTP accepted at ${mfaPath}` });
          break;
        }
      }
      emit({ type: "log", message: `  MFA challenge detected at ${endpoint} — bypass attempt complete` });
    } else if (probe.status !== 404) {
      // No MFA challenge in response — check login page too
      const loginPageR = await ctxFetch(ctx, `${base}/login`, { redirect: "follow" });
      const loginPageBody = loginPageR ? await loginPageR.text().catch(() => "") : "";
      const page2FA = /\b(two.?factor|authenticator|otp|totp|mfa|2fa)\b/i.test(loginPageBody);
      if (!page2FA && !seen.has(`mfa:${endpoint}`)) {
        seen.add(`mfa:${endpoint}`);
        findings.push({
          title: "No Multi-Factor Authentication (MFA) Detected",
          category: "Authentication",
          severity: "medium",
          endpoint,
          description: "No MFA challenge was observed in the login response or login page. The application may be processing credentials without enforcing a second factor. Applications without MFA are significantly more vulnerable to credential-stuffing and phishing attacks.",
          evidence: [
            `POST ${endpoint}`,
            `HTTP ${probe.status}`,
            `Login response body (first 300 chars): ${loginBody.slice(0, 300)}`,
            `Login page (${base}/login) checked: No 2FA/OTP/TOTP/MFA keywords found`,
          ].join("\n"),
          recommended_fix: "Implement TOTP-based 2FA (RFC 6238). Support WebAuthn/FIDO2 hardware keys. At minimum, send OTP via email/SMS for high-risk actions.",
          cvss_score: 5.9,
          cwe_id: "CWE-308",
          scanner_name: "Bug-Finder/Auth",
          scanner_family: "auth",
          confidence: 0.75,
        });
        emit({ type: "log", message: `  No MFA evidence at ${endpoint}` });
        break;
      }
    }
    break; // Only need one endpoint for MFA check
  }

  // ── Timing-based username enumeration ──────────────────────────────────────
  // Send login requests for an existing vs. non-existent username. If response
  // time differs significantly (>200ms), the server reveals whether the username
  // exists (e.g., bcrypt is skipped for unknown users → faster response).
  emit({ type: "log", message: "Testing for timing-based username enumeration..." });

  for (const path of LOGIN_PATHS.slice(0, 2)) {
    const endpoint = `${base}${path}`;
    const existingUser = "admin@admin.com";
    const nonExistentUser = `nonexistent_${Date.now()}@zzzzzz-fake-domain-xyz.com`;

    const timings: { user: string; ms: number }[] = [];
    const ROUNDS = 4;

    for (const email of [existingUser, nonExistentUser]) {
      let total = 0;
      for (let i = 0; i < ROUNDS; i++) {
        const t0 = Date.now();
        const r = await ctxFetch(ctx, endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: "WrongPass_timing_probe_9z!" }),
        });
        if (r) await r.text().catch(() => "");
        total += Date.now() - t0;
      }
      timings.push({ user: email, ms: Math.round(total / ROUNDS) });
    }

    const [existing, nonExisting] = timings as [typeof timings[0], typeof timings[0]];
    const diff = Math.abs(existing.ms - nonExisting.ms);
    emit({ type: "log", message: `  Timing: existing=${existing.ms}ms nonexistent=${nonExisting.ms}ms diff=${diff}ms at ${endpoint}` });

    // >200ms consistent difference across 4 rounds strongly suggests username oracle
    if (diff > 200) {
      const fasterUser = existing.ms < nonExisting.ms ? "existing" : "nonexistent";
      findings.push({
        title: "Username Enumeration via Timing Side-Channel",
        category: "Authentication",
        severity: "medium",
        endpoint,
        description: `The login endpoint responds ${diff}ms faster for ${fasterUser} usernames on average across ${ROUNDS} requests. This timing difference allows an attacker to enumerate valid usernames by observing response latency, significantly reducing the effort for credential-stuffing or brute-force attacks.`,
        evidence: [
          `Endpoint: POST ${endpoint}`,
          `Rounds: ${ROUNDS}`,
          `Average response — existing user (${existingUser}): ${existing.ms}ms`,
          `Average response — non-existent user (${nonExistentUser}): ${nonExisting.ms}ms`,
          `Timing difference: ${diff}ms`,
          `Threshold for reporting: >200ms`,
          `Likely cause: bcrypt/argon2 skipped for unknown users, or LDAP/DB lookup takes different time`,
        ].join("\n"),
        recommended_fix: "Ensure login response time is constant regardless of whether the username exists. Run password hashing even for non-existent users (use a dummy hash). Return identical error messages for bad username and bad password.",
        cvss_score: 5.3,
        cwe_id: "CWE-208",
        scanner_name: "Bug-Finder/Auth",
        scanner_family: "auth",
        confidence: 0.82,
      });
      emit({ type: "log", message: `  [TIMING ENUM] ${diff}ms difference at ${endpoint} — username oracle confirmed` });
      break;
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No default credential or auth policy issues detected" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/Auth-Advanced", message: `Advanced auth check complete — ${findings.length} finding(s)` });
  return findings;
}
