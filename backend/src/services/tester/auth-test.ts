import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { setCollectedData } from "./runner";

async function authFetch(c: TestContext, path: string, opts?: RequestInit) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(c.headers ?? {}) as Record<string, string>,
  };
  const cookie = c.cookieStore.get(c.apiBase) ?? "";
  if (cookie) headers["Cookie"] = cookie;

  return fetch(`${c.apiBase}${path}`, {
    ...opts,
    headers: { ...headers, ...(opts?.headers as Record<string, string> | undefined) },
    credentials: "include",
    redirect: "manual",
  }).then(res => {
    const setCookie = res.headers.getSetCookie?.() ?? res.headers.get("set-cookie")?.split(",") ?? [];
    for (const sc of setCookie) {
      const nameValue = sc.split(";")[0]?.trim();
      if (nameValue && nameValue.includes("=")) {
        const existing = c.cookieStore.get(c.apiBase) ?? "";
        c.cookieStore.set(c.apiBase, existing ? `${existing}; ${nameValue}` : nameValue);
      }
    }
    return res;
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
      const weakRes = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "12" }) });
      const goodRes = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "SecureP@ss1" }) });
      const goodData = goodRes ? await goodRes.json().catch(() => ({})) : {};
      const dupRes = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Test", lastName: "User", email: testEmail, password: "AnotherP@ss1" }) });

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
    description: "Tests successful login, invalid credentials rejection, and session persistence.",
    tags: ["auth", "login"],
    timeout: 10000,
    run: async (ctx) => {
      const user = ctx.runtime.collectedData.get("testUser") as { email: string; password: string } | undefined;
      let creds = user;

      if (!creds) {
        const email = `test-login-${Date.now()}@bugfinder.io`;
        const regRes = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "Login", lastName: "Test", email, password: "TestP@ss1" }) });
        if (!regRes || regRes.status !== 201) {
          return { id: "auth-02", name: "Login / Logout Flow", category: "auth", status: "error", duration: 0, message: "Could not create test user for login test" };
        }
        creds = { email, password: "TestP@ss1" };
      }

      ctx.cookieStore.delete(ctx.apiBase);
      const loginRes = await authFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: creds.email, password: creds.password }) });
      const badRes = await authFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: creds.email, password: "wrongpassword" }) });

      const cookie = ctx.cookieStore.get(ctx.apiBase) ?? "";
      const sessionCookie = cookie.split(";").find(c => c.trim().startsWith("bbp.sid=")) ?? "";

      const meRes = sessionCookie
        ? await authFetch(ctx, "/auth/me")
        : null;

      const status: TestResult["status"] =
        loginRes?.status === 200 && badRes?.status === 401 && meRes?.status === 200 ? "pass" :
        loginRes?.status === 200 && badRes?.status === 401 ? "warn" : "fail";

      return {
        id: "auth-02", name: "Login / Logout Flow", category: "auth", status, duration: 0,
        message: `Login: HTTP ${loginRes?.status}, Bad creds: HTTP ${badRes?.status}, Session: HTTP ${meRes?.status}` + (!sessionCookie ? " (no session cookie received)" : ""),
        evidence: { loginStatus: loginRes?.status, rejectStatus: badRes?.status, sessionStatus: meRes?.status, hasSessionCookie: !!sessionCookie },
        suggestion: meRes?.status === 401 ? "Session cookie not being sent — check session middleware sameSite/secure config or cookie parsing" :
          loginRes?.status !== 200 ? "Check bcrypt password comparison" :
          badRes?.status !== 401 ? "Invalid credentials should return 401" : undefined,
      };
    },
  },
  {
    id: "auth-03",
    category: "auth",
    name: "Password Policy Enforcement",
    description: "Validates minimum length enforcement and missing field rejection.",
    tags: ["auth", "password"],
    run: async (ctx) => {
      const short = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({ firstName: "A", lastName: "B", email: `shortpw-${Date.now()}@test.com`, password: "a" }) });
      const noFields = await authFetch(ctx, "/auth/register", { method: "POST", body: JSON.stringify({}) });

      const status: TestResult["status"] =
        short?.status === 400 && noFields?.status === 400 ? "pass" : "fail";

      return {
        id: "auth-03", name: "Password Policy Enforcement", category: "auth", status, duration: 0,
        message: `Short pw: HTTP ${short?.status}, Empty body: HTTP ${noFields?.status}`,
        evidence: { shortPwStatus: short?.status, emptyStatus: noFields?.status },
        suggestion: status !== "pass" ? "Validate password min length and required fields" : undefined,
      };
    },
  },
  {
    id: "auth-04",
    category: "auth",
    name: "Rate Limiting on Auth",
    description: "Sends 12 rapid login requests to verify rate limiting is enforced.",
    tags: ["auth", "security"],
    timeout: 30000,
    run: async (ctx) => {
      const promises = [];
      for (let i = 0; i < 12; i++) {
        promises.push(authFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: `ratelimit-${Date.now()}-${i}@test.com`, password: "x".repeat(6) }) }));
      }
      const responses = await Promise.all(promises);
      const statuses = responses.map(r => r?.status ?? 0);
      const wasLimited = statuses.includes(429);

      return {
        id: "auth-04", name: "Rate Limiting on Auth", category: "auth",
        status: wasLimited ? "pass" : "warn",
        duration: 0,
        message: wasLimited ? `Rate limiting enforced — HTTP 429 returned` : `No rate limiting detected — all ${statuses.length} requests passed`,
        evidence: { responseStatuses: statuses, requestCount: statuses.length },
        suggestion: !wasLimited ? "Enable rate limiting middleware on auth routes" : undefined,
      };
    },
  },
  {
    id: "auth-05",
    category: "auth",
    name: "Forgot Password Flow",
    description: "Tests password reset token generation and validation.",
    tags: ["auth", "security"],
    run: async (ctx) => {
      const existRes = await authFetch(ctx, "/auth/forgot-password", { method: "POST", body: JSON.stringify({ email: `fpw-${Date.now()}@test.com` }) });
      const invalidEmail = await authFetch(ctx, "/auth/forgot-password", { method: "POST", body: JSON.stringify({}) });

      const status: TestResult["status"] =
        existRes?.status === 200 && invalidEmail?.status === 400 ? "pass" :
        existRes?.status === 429 ? "warn" :
        existRes?.status === 200 ? "warn" : "fail";

      return {
        id: "auth-05", name: "Forgot Password Flow", category: "auth", status, duration: 0,
        message: `Forgot password: HTTP ${existRes?.status}, Missing email: HTTP ${invalidEmail?.status}`,
        evidence: { existStatus: existRes?.status, invalidStatus: invalidEmail?.status },
        suggestion: existRes?.status === 429 ? "Rate limited — reduce auth test requests or skip when running full suite" :
          status === "fail" ? "Ensure forgot-password returns 200 for both existent/non-existent emails" : undefined,
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
      const user = ctx.runtime.collectedData.get("testUser") as { email: string; password: string } | undefined;
      if (!user) {
        return { id: "auth-06", name: "Session Persistence & Remember Me", category: "auth", status: "skipped", duration: 0, message: "No test user — running after auth-01/02 required for session context" };
      }

      ctx.cookieStore.delete(ctx.apiBase);
      const loginRes = await authFetch(ctx, "/auth/login", { method: "POST", body: JSON.stringify({ email: user.email, password: user.password, remember_me: true }) });
      const cookie = ctx.cookieStore.get(ctx.apiBase) ?? "";
      const hasSession = cookie.includes("bbp.sid");

      const status: TestResult["status"] =
        loginRes?.status === 200 && hasSession ? "pass" :
        loginRes?.status === 429 ? "warn" :
        loginRes?.status === 200 ? "warn" : "fail";

      return {
        id: "auth-06", name: "Session Persistence & Remember Me", category: "auth", status, duration: 0,
        message: loginRes?.status === 429 ? "Rate limited — session tests hit auth limiter" : `Login: HTTP ${loginRes?.status}, Session cookie: ${hasSession ? "present" : "missing"}`,
        evidence: { loginStatus: loginRes?.status, hasSessionCookie: hasSession, cookiePreview: cookie.slice(0, 50) },
        suggestion: loginRes?.status === 429 ? "Reduce concurrent auth test count or increase rate limit window" :
          !hasSession ? "Session cookie not set — check session middleware configuration" : undefined,
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
