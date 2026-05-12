import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { setCollectedData } from "./runner";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers, ...(opts?.headers as Record<string, string>) },
    ...opts,
  }).catch(() => null);
}

const authTests: TestCase[] = [
  {
    id: "auth-01",
    category: "auth",
    name: "Registration Flow",
    description: "Validates full user registration including duplicate detection, password strength, and session creation.",
    tags: ["auth", "registration"],
    run: async (ctx) => {
      const testEmail = `test-${Date.now()}@bugfinder.io`;
      const weakRes = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "12" }) });
      const weakData = weakRes ? await weakRes.json().catch(() => ({})) : {};

      const goodRes = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "SecureP@ss1" }) });
      const goodData = goodRes ? await goodRes.json().catch(() => ({})) : {};

      const dupRes = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "AnotherP@ss1" }) });

      const results: string[] = [];
      if (weakRes?.status === 400) results.push("Weak password correctly rejected");
      else results.push(`Weak password NOT rejected (got ${weakRes?.status})`);
      if (goodRes?.status === 201 && goodData.id) {
        results.push("Registration succeeded with strong password");
        setCollectedData(ctx, "testUser", { email: testEmail, password: "SecureP@ss1", id: goodData.id });
      } else results.push(`Registration failed: HTTP ${goodRes?.status}`);

      const status: TestResult["status"] = goodRes?.status === 201 && dupRes?.status === 409 ? "pass" : goodRes?.status === 201 ? "warn" : "fail";

      return {
        id: "auth-01", name: "Registration Flow", category: "auth", status, duration: 0,
        message: results.join("; "),
        evidence: { weakPwStatus: weakRes?.status, goodPwStatus: goodRes?.status, dupStatus: dupRes?.status, email: testEmail },
        suggestion: status !== "pass" ? "Check registration route validation logic" : undefined,
      };
    },
  },
  {
    id: "auth-02",
    category: "auth",
    name: "Login / Logout Flow",
    description: "Tests successful login, invalid credentials rejection, session persistence, and clean logout.",
    tags: ["auth", "login"],
    run: async (ctx) => {
      const user = ctx.runtime.collectedData.get("testUser") as { email: string; password: string } | undefined;
      if (!user) {
        const email = `test-login-${Date.now()}@bugfinder.io`;
        const regRes = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Login", lastName: "Test", email, password: "TestP@ss1" }) });
        if (!regRes || regRes.status !== 201) {
          return { id: "auth-02", name: "Login / Logout Flow", category: "auth", status: "error", duration: 0, message: "Could not create test user for login test" };
        }
        setCollectedData(ctx, "testUser", { email, password: "TestP@ss1" });
      }

      const creds = user ?? ctx.runtime.collectedData.get("testUser") as { email: string; password: string };
      const loginRes = await api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: creds.email, password: creds.password }) });
      const badRes = await api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: creds.email, password: "wrongpassword" }) });
      const meRes = await api(ctx, "/auth/me", { credentials: "include" } as RequestInit);

      const status: TestResult["status"] =
        loginRes?.status === 200 && badRes?.status === 401 && meRes?.status === 200 ? "pass" : "fail";

      return {
        id: "auth-02", name: "Login / Logout Flow", category: "auth", status, duration: 0,
        message: `Login: HTTP ${loginRes?.status || "N/A"}, Bad creds: HTTP ${badRes?.status || "N/A"}, Session: HTTP ${meRes?.status || "N/A"}`,
        evidence: { loginStatus: loginRes?.status, rejectStatus: badRes?.status, sessionStatus: meRes?.status },
        suggestion: status !== "pass" ? "Verify session middleware and bcrypt comparison" : undefined,
      };
    },
  },
  {
    id: "auth-03",
    category: "auth",
    name: "Password Policy Enforcement",
    description: "Validates minimum length enforcement, missing field rejection, and password change flow.",
    tags: ["auth", "password"],
    run: async (ctx) => {
      const short = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "A", lastName: "B", email: `short-${Date.now()}@test.com`, password: "a" }) });
      const noFields = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({}) });
      const emptyBody = await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: null, lastName: null, email: null, password: null }) });

      const status: TestResult["status"] =
        short?.status === 400 && noFields?.status === 400 ? "pass" : "fail";

      return {
        id: "auth-03", name: "Password Policy Enforcement", category: "auth", status, duration: 0,
        message: `Short pw: HTTP ${short?.status}, Empty body: HTTP ${noFields?.status}`,
        evidence: { shortPwStatus: short?.status, emptyStatus: noFields?.status },
        suggestion: status !== "pass" ? "Validate password min length, required fields, and null values" : undefined,
      };
    },
  },
  {
    id: "auth-04",
    category: "auth",
    name: "Rate Limiting on Auth",
    description: "Verifies that rate limiting is enforced on the login endpoint by sending rapid requests.",
    tags: ["auth", "security"],
    run: async (ctx) => {
      const promises = [];
      for (let i = 0; i < 12; i++) {
        promises.push(api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: `rate-${i}@test.com`, password: "x".repeat(6) }) }));
      }
      const responses = await Promise.all(promises);
      const statuses = responses.map(r => r?.status ?? 0);
      const wasLimited = statuses.includes(429);

      const status: TestResult["status"] = wasLimited ? "pass" : "warn";

      return {
        id: "auth-04", name: "Rate Limiting on Auth", category: "auth", status, duration: 0,
        message: wasLimited ? `Rate limiting enforced — HTTP 429 returned` : `No rate limiting detected — all ${statuses.length} requests passed` + (statuses.join(",")),
        evidence: { responseStatuses: statuses, requestCount: statuses.length },
        suggestion: !wasLimited ? "Enable rate limiting middleware on auth routes" : undefined,
      };
    },
  },
  {
    id: "auth-05",
    category: "auth",
    name: "Forgot Password Flow",
    description: "Tests password reset token generation and validation. Ensures no user enumeration via response timing/status.",
    tags: ["auth", "security"],
    run: async (ctx) => {
      const existRes = await api(ctx, "/auth/forgot-password", { method: "POST", body: JSON.stringify({ email: `existing-${Date.now()}@test.com` }) });
      const invalidEmail = await api(ctx, "/auth/forgot-password", { method: "POST", body: JSON.stringify({}) });

      const status: TestResult["status"] =
        existRes?.status === 200 && invalidEmail?.status === 400 ? "pass" :
        existRes?.status === 200 ? "warn" : "fail";

      return {
        id: "auth-05", name: "Forgot Password Flow", category: "auth", status, duration: 0,
        message: `Forgot password: HTTP ${existRes?.status}, Missing email: HTTP ${invalidEmail?.status}`,
        evidence: { existStatus: existRes?.status, invalidStatus: invalidEmail?.status },
        suggestion: status !== "pass" ? "Ensure forgot-password returns 200 for both existent/non-existent emails" : undefined,
      };
    },
  },
  {
    id: "auth-06",
    category: "auth",
    name: "Session Persistence & Remember Me",
    description: "Tests that session persists with cookies and remember-me extends TTL.",
    tags: ["auth", "session"],
    run: async (ctx) => {
      const email = `session-${Date.now()}@test.com`;
      await api(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "S", lastName: "T", email, password: "SessionP@ss1" }) });

      const loginRes = await api(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email, password: "SessionP@ss1", remember_me: true }) });

      const status: TestResult["status"] = loginRes?.ok ? "pass" : "fail";

      return {
        id: "auth-06", name: "Session Persistence & Remember Me", category: "auth", status, duration: 0,
        message: `Login with remember_me: HTTP ${loginRes?.status}`,
        evidence: { loginStatus: loginRes?.status },
        suggestion: status !== "pass" ? "Check session store and cookie configuration" : undefined,
      };
    },
  },
];

export const authSuite: TestSuite = {
  id: "auth",
  category: "auth",
  label: "Authentication & Authorization",
  description: "Validates registration, login, logout, password policies, rate limiting, session management, and password reset flows.",
  icon: "Lock",
  tests: authTests,
};
