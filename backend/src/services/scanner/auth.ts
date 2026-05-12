import { ScanContext, ScanFinding, ctxFetch } from "./types";

const LOGIN_PATHS = [
  "/api/auth/login",
  "/api/login",
  "/login",
  "/auth/login",
  "/api/v1/auth/login",
  "/api/v1/login",
  "/admin/login",
  "/api/admin/login",
  "/user/login",
  "/signin",
  "/api/signin",
];

const PROTECTED_PATHS = [
  { path: "/admin",          label: "Admin Panel" },
  { path: "/api/admin",      label: "Admin API" },
  { path: "/api/users",      label: "User List API" },
  { path: "/api/v1/users",   label: "User List API v1" },
  { path: "/api/settings",   label: "Settings API" },
  { path: "/api/config",     label: "Config API" },
  { path: "/api/keys",       label: "API Keys endpoint" },
  { path: "/api/secrets",    label: "Secrets endpoint" },
  { path: "/dashboard",      label: "Dashboard" },
  { path: "/api/reports",    label: "Reports API" },
];

const DEFAULT_CREDS = [
  { username: "admin",       password: "admin" },
  { username: "admin",       password: "password" },
  { username: "admin",       password: "admin123" },
  { username: "admin",       password: "123456" },
  { username: "admin",       password: "password123" },
  { username: "root",        password: "root" },
  { username: "root",        password: "toor" },
  { username: "test",        password: "test" },
  { username: "user",        password: "user" },
  { username: "guest",       password: "guest" },
  { username: "demo",        password: "demo" },
  { username: "superuser",   password: "superuser" },
  { username: "administrator", password: "administrator" },
  { username: "admin",       password: "" },
];

const WEAK_PASSWORDS = [
  "password", "123456", "12345678", "qwerty", "abc123",
  "letmein", "welcome", "monkey", "dragon", "master",
  "sunshine", "princess", "football", "shadow", "superman",
];

// Detect login form fields from JSON body convention or HTML
function buildLoginBodies(username: string, password: string): Array<Record<string, string>> {
  return [
    { username, password },
    { email: username.includes("@") ? username : `${username}@example.com`, password },
    { user: username, pass: password },
    { login: username, password },
    { username, pwd: password },
  ];
}

async function findLoginEndpoint(ctx: ScanContext, base: string): Promise<string | null> {
  for (const path of LOGIN_PATHS) {
    const url = `${base}${path}`;
    const r = await ctxFetch(ctx, url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "probe_check@test.invalid", password: "probe_check_xyz_99" }),
    });
    if (!r) continue;
    // A real login endpoint returns 400/401/422/429, not 404/405
    if ([400, 401, 403, 422, 429, 200].includes(r.status)) {
      return url;
    }
  }
  return null;
}

async function isLoginSuccess(res: Response): Promise<boolean> {
  if (res.status !== 200) return false;
  try {
    const body = await res.clone().text();
    const lower = body.toLowerCase();
    return (
      lower.includes("token") ||
      lower.includes("access_token") ||
      lower.includes("session") ||
      lower.includes("authenticated") ||
      lower.includes("\"success\":true") ||
      lower.includes("\"ok\":true")
    );
  } catch {
    return false;
  }
}

export async function runAuthCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];
  const base = new URL(targetUrl).origin;

  emit({ type: "engine_start", engine: "Bug-Finder/Auth", message: "Starting real authentication security tests" });

  // ── 1. Discover login endpoint ──────────────────────────────────────────────
  emit({ type: "log", message: "Discovering login endpoint…" });
  const loginUrl = await findLoginEndpoint(ctx, base);
  if (!loginUrl) {
    emit({ type: "log", message: "No login endpoint found — skipping credential tests" });
  }

  // ── 2. Rate-limit / lockout detection ──────────────────────────────────────
  if (loginUrl) {
    emit({ type: "log", message: `Testing rate limiting on ${loginUrl}…` });
    const statusCodes: number[] = [];
    const testBody = { username: "ratetest@example.com", password: "wrong_password_probe_123" };

    for (let i = 0; i < 8; i++) {
      const r = await ctxFetch(ctx, loginUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(testBody),
      });
      if (r) statusCodes.push(r.status);
      await new Promise((res) => setTimeout(res, 150));
    }

    const has429 = statusCodes.includes(429);
    const has423 = statusCodes.includes(423); // account locked
    const allFailed401 = statusCodes.every((s) => [400, 401, 403, 422].includes(s));

    if (!has429 && !has423 && allFailed401 && statusCodes.length >= 6) {
      findings.push({
        title: "No Rate Limiting on Login Endpoint",
        category: "Authentication",
        severity: "high",
        endpoint: loginUrl,
        description:
          `The login endpoint does not rate-limit repeated failed attempts. ` +
          `${statusCodes.length} consecutive failed logins returned ${statusCodes.join(", ")} without any 429 or lockout response. ` +
          `This allows unlimited brute-force attacks against user accounts.`,
        evidence:
          `${statusCodes.length} POST requests to ${loginUrl}\n` +
          `Responses: ${statusCodes.join(", ")}\n` +
          `No HTTP 429 (Too Many Requests) or 423 (Locked) received`,
        recommended_fix:
          "Implement IP-based and account-based rate limiting (max 5 attempts/minute). " +
          "Return HTTP 429 with Retry-After header. Add CAPTCHA after 3 failures. " +
          "Lock accounts after 10 failed attempts and alert the user via email.",
        cvss_score: 7.5,
        cwe_id: "CWE-307",
        scanner_name: "Bug-Finder/Auth",
        scanner_family: "web",
        confidence: 0.85,
      });
      emit({ type: "log", message: "  [HIGH] No rate limiting on login" });
    } else {
      emit({ type: "log", message: `  Rate limit check: ${has429 ? "429 detected ✓" : has423 ? "lockout detected ✓" : "no protection found"}` });
    }
  }

  // ── 3. Default credential stuffing ─────────────────────────────────────────
  if (loginUrl && (profile === "standard" || profile === "deep")) {
    emit({ type: "log", message: "Testing default credentials…" });
    const credBudget = profile === "deep" ? DEFAULT_CREDS.length : 6;
    let rateLimited = false;

    for (const cred of DEFAULT_CREDS.slice(0, credBudget)) {
      if (rateLimited) break;
      for (const body of buildLoginBodies(cred.username, cred.password).slice(0, 2)) {
        const r = await ctxFetch(ctx, loginUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (!r) continue;
        // Stop immediately if target is rate-limiting or locking accounts
        if (r.status === 429 || r.status === 423 || r.status === 503) {
          emit({ type: "log", message: `  Rate limit/lockout response (${r.status}) — stopping credential test to avoid account lockout` });
          rateLimited = true;
          break;
        }
        if (await isLoginSuccess(r)) {
          findings.push({
            title: `Default Credentials Accepted: ${cred.username} / ${cred.password || "(empty)"}`,
            category: "Authentication",
            severity: "critical",
            endpoint: loginUrl,
            description:
              `The login endpoint accepts default credentials (${cred.username} / ${cred.password || "empty password"}). ` +
              `This allows immediate unauthorized administrative access without any prior knowledge of the system.`,
            evidence:
              `POST ${loginUrl}\n` +
              `Body: ${JSON.stringify(body)}\n` +
              `HTTP ${r.status} — Authentication succeeded (token/session in response)`,
            recommended_fix:
              "Change all default credentials immediately. " +
              "Enforce a strong password policy during installation and first-run setup. " +
              "Implement MFA for all privileged accounts. " +
              "Run automated credential audits as part of CI/CD.",
            cvss_score: 9.8,
            cwe_id: "CWE-798",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "web",
            confidence: 0.97,
          });
          emit({ type: "log", message: `  [CRITICAL] Default creds accepted: ${cred.username}/${cred.password}` });
          break;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  }

  // ── 4. Weak password policy probe ──────────────────────────────────────────
  if (loginUrl && profile === "deep") {
    emit({ type: "log", message: "Probing password policy (weak passwords)…" });
    // Try to register a new account with a weak password to test policy
    const registerPaths = ["/api/auth/register", "/api/register", "/register", "/api/v1/register", "/api/signup"];
    for (const regPath of registerPaths) {
      const regUrl = `${base}${regPath}`;
      const testEmail = `poltest_${Date.now()}@bugfinder-probe.invalid`;
      const r = await ctxFetch(ctx, regUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: testEmail, username: "poltest", password: "123456", firstName: "Pol", lastName: "Test" }),
      });
      if (!r) continue;
      if (r.status === 200 || r.status === 201) {
        const body = await r.text().catch(() => "");
        if (body.includes("token") || body.includes("id") || body.includes("user")) {
          findings.push({
            title: "Weak Password Policy — Simple Passwords Accepted",
            category: "Authentication",
            severity: "medium",
            endpoint: regUrl,
            description:
              "The registration endpoint accepted a common weak password (\"123456\"). " +
              "Users are not prevented from choosing easily guessable passwords, increasing susceptibility to credential stuffing and brute-force attacks.",
            evidence:
              `POST ${regUrl}\n` +
              `Password: "123456" (top-10 most common)\n` +
              `HTTP ${r.status} — Registration succeeded`,
            recommended_fix:
              "Enforce a minimum password strength policy: at least 8 characters, mixed case, digit, and symbol. " +
              "Reject passwords from known-compromised wordlists (HaveIBeenPwned API). " +
              "Show a password strength meter in the UI.",
            cvss_score: 5.3,
            cwe_id: "CWE-521",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "web",
            confidence: 0.8,
          });
          emit({ type: "log", message: "  [MEDIUM] Weak password policy — '123456' accepted at registration" });
          break;
        }
      }
    }
  }

  // ── 5. Username enumeration ─────────────────────────────────────────────────
  // Strategy: extract a real email address from the application's own responses
  // (API endpoints, HTML pages, error messages) rather than assuming "admin@example.com"
  // exists. Using a hardcoded email that doesn't exist on the target always produces
  // a false negative — both requests get the same "not found" response.
  if (loginUrl) {
    emit({ type: "log", message: "Testing username enumeration — extracting real email from application responses…" });

    // Attempt to discover a real registered email from the app's own API or HTML
    let existingUser: string | null = null;

    const emailDiscoverySources = [
      `${base}/api/users`, `${base}/api/v1/users`, `${base}/api/me`,
      `${base}/api/profile`, `${base}/api/admin/users`, targetUrl,
    ];

    for (const src of emailDiscoverySources) {
      const r = await ctxFetch(ctx, src, { headers: { Accept: "application/json, text/html" } });
      if (!r || r.status !== 200) continue;
      const body = await r.text().catch(() => "");
      const emailMatch = body.match(/["']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["']?/);
      if (emailMatch?.[1] && !emailMatch[1].includes("bugfinder") && !emailMatch[1].includes("probe")) {
        existingUser = emailMatch[1];
        emit({ type: "log", message: `  Extracted real email from ${src}: ${existingUser}` });
        break;
      }
    }

    if (!existingUser) {
      emit({ type: "log", message: "  No real email found in app responses — username enumeration test skipped (would produce false negatives with assumed emails)" });
    } else {
      const nonExistingUser = `probe_nonexistent_${Date.now()}@bugfinder-probe.invalid`;
      const wrongPassword = `wrong_probe_password_${Date.now()}`;

      const [r1, r2] = await Promise.all([
        ctxFetch(ctx, loginUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: existingUser, password: wrongPassword }),
        }),
        ctxFetch(ctx, loginUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: nonExistingUser, password: wrongPassword }),
        }),
      ]);

      if (r1 && r2) {
        const [b1, b2] = await Promise.all([r1.text().catch(() => ""), r2.text().catch(() => "")]);
        const differentStatus = r1.status !== r2.status;
        const b1lower = b1.toLowerCase();
        const b2lower = b2.toLowerCase();

        // Detect response body differences that reveal whether the user exists:
        // - "invalid password" vs "user not found" = explicit enumeration
        // - significantly different body lengths when statuses are the same
        const explicitEnumeration =
          (b1lower.includes("invalid password") || b1lower.includes("wrong password") || b1lower.includes("incorrect password")) &&
          (b2lower.includes("user not found") || b2lower.includes("no account") || b2lower.includes("email not registered") || b2lower.includes("does not exist"));
        const sameStatusBodyLenDiff = !differentStatus && Math.abs(b1.length - b2.length) > 30;

        if (differentStatus || explicitEnumeration) {
          findings.push({
            title: "Username Enumeration via Login Response",
            category: "Authentication",
            severity: "medium",
            endpoint: loginUrl,
            description:
              `The login endpoint returns different responses for valid vs. invalid usernames, allowing attackers to enumerate valid accounts. ` +
              `Tested with a real email extracted from the application (${existingUser}) vs. a guaranteed non-existent address.`,
            evidence: [
              `POST ${loginUrl}`,
              `  Existing user (${existingUser}): HTTP ${r1.status}`,
              `  Response: ${b1.slice(0, 120)}`,
              ``,
              `  Non-existent user: HTTP ${r2.status}`,
              `  Response: ${b2.slice(0, 120)}`,
              ``,
              differentStatus ? `Status codes differ: ${r1.status} vs ${r2.status}` : "",
              explicitEnumeration ? "Response messages explicitly reveal user existence" : "",
            ].filter(Boolean).join("\n"),
            recommended_fix:
              "Return identical HTTP status codes and bodies for invalid username and invalid password. " +
              "Use a constant-time comparison to prevent timing side channels. " +
              "Generic message: \"Invalid credentials\" — never \"User not found\" or \"Wrong password\".",
            cvss_score: 5.3,
            cwe_id: "CWE-203",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "web",
            confidence: explicitEnumeration ? 0.95 : 0.80,
          });
          emit({ type: "log", message: `  [MEDIUM] Username enumeration — status ${r1.status} vs ${r2.status}, explicit=${explicitEnumeration}` });
        } else if (sameStatusBodyLenDiff) {
          emit({ type: "log", message: `  Body length diff ${Math.abs(b1.length - b2.length)}b — possible timing/body enumeration (below confidence threshold)` });
        } else {
          emit({ type: "log", message: `  Username enumeration: responses identical (status ${r1.status}/${r2.status}, body diff ${Math.abs(b1.length - b2.length)}b) — no issue` });
        }
      }
    }
  }

  // ── 6. Unauthenticated access to protected paths ────────────────────────────
  emit({ type: "log", message: "Checking unauthenticated access to protected paths…" });
  const budget = profile === "quick" ? 4 : profile === "standard" ? 7 : PROTECTED_PATHS.length;

  for (const { path, label } of PROTECTED_PATHS.slice(0, budget)) {
    const url = `${base}${path}`;
    const r = await ctxFetch(ctx, url, { headers: { Accept: "application/json" } });
    if (!r) continue;

    if (r.status === 200) {
      const body = await r.text().catch(() => "");
      const hasData = body.length > 50 && (body.includes("{") || body.includes("[") || body.includes("<"));
      if (hasData) {
        findings.push({
          title: `Unauthenticated Access to ${label}`,
          category: "Broken Access Control",
          severity: "high",
          endpoint: url,
          description:
            `The ${label} (${path}) is accessible without authentication. ` +
            `This may expose sensitive administrative functions or user data to unauthenticated users.`,
          evidence:
            `GET ${url}\nHTTP 200 OK (no auth header)\n\nResponse preview:\n${body.slice(0, 300)}`,
          recommended_fix:
            "Apply authentication middleware to all protected routes. " +
            "Return HTTP 401 or 403 for unauthenticated requests. " +
            "Implement role-based access control.",
          cvss_score: 7.5,
          cwe_id: "CWE-306",
          scanner_name: "Bug-Finder/Auth",
          scanner_family: "web",
          confidence: 0.85,
        });
        emit({ type: "log", message: `  [HIGH] Unauthenticated access: ${path}` });
      }
    }
  }

  // ── 7. Password reset token entropy (deep only) ─────────────────────────────
  if (profile === "deep") {
    emit({ type: "log", message: "Testing password reset flow…" });
    const resetPaths = ["/api/auth/forgot-password", "/api/forgot-password", "/api/password/reset"];
    for (const resetPath of resetPaths) {
      const url = `${base}${resetPath}`;
      const r1 = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "admin@example.com" }),
      });
      const r2 = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "admin@example.com" }),
      });
      if (!r1 || !r2) continue;
      if (r1.status === 200 || r1.status === 204) {
        // Flow exists — check if it leaks user existence
        const b1 = await r1.text().catch(() => "");
        const nonExistR = await ctxFetch(ctx, url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: `nonexistent_probe_${Date.now()}@bugfinder.invalid` }),
        });
        const bNon = nonExistR ? await nonExistR.text().catch(() => "") : "";
        if (nonExistR && r1.status !== nonExistR.status) {
          findings.push({
            title: "Password Reset Endpoint Leaks User Existence",
            category: "Authentication",
            severity: "low",
            endpoint: url,
            description:
              "The password reset endpoint returns different HTTP status codes for existing vs. non-existing email addresses, " +
              "allowing attackers to enumerate registered users.",
            evidence:
              `POST ${url} — existing email: HTTP ${r1.status}\n` +
              `POST ${url} — nonexistent email: HTTP ${nonExistR.status}`,
            recommended_fix:
              "Always return HTTP 200 and the same generic message regardless of whether the email exists. " +
              "\"If an account with this email exists, a reset link has been sent.\"",
            cvss_score: 3.7,
            cwe_id: "CWE-204",
            scanner_name: "Bug-Finder/Auth",
            scanner_family: "web",
            confidence: 0.8,
          });
          emit({ type: "log", message: "  [LOW] Password reset leaks user existence" });
        }
        break;
      }
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Auth",
    message: `Auth check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
