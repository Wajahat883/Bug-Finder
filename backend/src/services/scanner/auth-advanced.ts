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

  emit({ type: "engine_start", engine: "Hydra/AuthTester", message: "Testing default credentials, password policy, and 2FA" });

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
    for (const cred of DEFAULT_CREDENTIALS.slice(0, credsBudget)) {
      const r = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: cred.user, email: `${cred.user}@example.com`, password: cred.pass }),
      });

      if (!r) continue;

      // If we get a token/session back, credentials worked
      const body = await r.text().catch(() => "");
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
          scanner_name: "Hydra",
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
          const accepted = !regBody.toLowerCase().includes("password") || regBody.toLowerCase().includes("token") || regBody.toLowerCase().includes("created");
          if (accepted && !seen.has(`${regEndpoint}:policy`)) {
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
              scanner_name: "Hydra",
              scanner_family: "auth",
              confidence: 0.8,
            });
            emit({ type: "log", message: `  Weak password "${weakPass}" accepted at ${regEndpoint}` });
          }
        }
      }
    }

    // Check for 2FA enforcement detection
    const loginBody = await probe.text().catch(() => "");
    const has2FA = loginBody.toLowerCase().includes("otp") || loginBody.toLowerCase().includes("2fa") || loginBody.toLowerCase().includes("totp") || loginBody.toLowerCase().includes("mfa");
    if (!has2FA && probe.status !== 404) {
      // Check login page for 2FA indicators
      const loginPageR = await ctxFetch(ctx, `${base}/login`, { redirect: "follow" });
      const loginPageBody = loginPageR ? await loginPageR.text().catch(() => "") : "";
      const page2FA = loginPageBody.toLowerCase().includes("two-factor") || loginPageBody.toLowerCase().includes("authenticator") || loginPageBody.toLowerCase().includes("otp");
      if (!page2FA) {
        findings.push({
          title: "No Multi-Factor Authentication (MFA) Detected",
          category: "Authentication",
          severity: "medium",
          endpoint,
          description: "No indication of multi-factor authentication was found on the login endpoint. Applications without MFA are significantly more vulnerable to credential-based attacks.",
          evidence: `POST ${endpoint}\nHTTP ${probe.status}\nNo OTP/TOTP/2FA field or response indicator found`,
          recommended_fix: "Implement TOTP-based 2FA (Google Authenticator, Authy). Consider hardware key support (WebAuthn/FIDO2). At minimum, send OTP via email/SMS.",
          cvss_score: 5.9,
          cwe_id: "CWE-308",
          scanner_name: "Hydra",
          scanner_family: "auth",
          confidence: 0.7,
        });
        emit({ type: "log", message: `  No MFA detected at ${endpoint}` });
        break;
      }
    }
    break; // Only need one endpoint for 2FA check
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No default credential or auth policy issues detected" });
  }

  emit({ type: "engine_done", engine: "Hydra/AuthTester", message: `Advanced auth check complete — ${findings.length} finding(s)` });
  return findings;
}
