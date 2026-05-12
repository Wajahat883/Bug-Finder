import { TestContext } from "./types";

export async function testFetch(c: TestContext, path: string, opts?: RequestInit) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(c.headers ?? {}) as Record<string, string>,
  };
  const cookie = c.cookieStore.get(c.apiBase) ?? "";
  if (cookie) headers["Cookie"] = cookie;

  const res = await fetch(`${c.apiBase}${path}`, {
    ...opts,
    headers: { ...headers, ...(opts?.headers as Record<string, string> | undefined) },
    redirect: "manual",
  }).catch(() => null);

  if (res) {
    const setCookie = res.headers.getSetCookie?.() ?? res.headers.get("set-cookie")?.split(",") ?? [];
    for (const sc of setCookie) {
      const nameValue = sc.split(";")[0]?.trim();
      if (nameValue && nameValue.includes("=")) {
        const existing = c.cookieStore.get(c.apiBase) ?? "";
        c.cookieStore.set(c.apiBase, existing ? `${existing}; ${nameValue}` : nameValue);
      }
    }
  }
  return res;
}

export function isRateLimited(status: number | undefined): boolean {
  return status === 429 || status === 0;
}

export function rateLimitWarn(testName: string): { status: "warn"; message: string } {
  return { status: "warn" as const, message: `${testName}: rate limited (429) — reduce test count or increase auth window` };
}

export async function ensureAuthenticated(c: TestContext): Promise<boolean> {
  const cookie = c.cookieStore.get(c.apiBase) ?? "";
  if (cookie.includes("bbp.sid")) {
    const me = await testFetch(c, "/auth/me");
    if (me?.status === 200) return true;
  }

  const user = c.runtime.collectedData.get("testUser") as { email: string; password: string } | undefined;
  if (!user) return false;

  c.cookieStore.delete(c.apiBase);
  const loginRes = await testFetch(c, "/auth/login", {
    method: "POST",
    body: JSON.stringify({ email: user.email, password: user.password }),
  });

  if (loginRes?.status === 429) return false;
  return loginRes?.status === 200;
}
