import { ScanContext } from "./types";
import { logger } from "../../lib/logger";

interface SessionState {
  cookies: Map<string, string>;
  tokens: { type: string; value: string }[];
  recordedSteps: { method: string; url: string; status: number }[];
  loginUrl: string;
  loginPayload: Record<string, string>;
  loggedIn: boolean;
  expiresAt?: number;
}

export async function recordSession(
  loginUrl: string,
  loginPayload: Record<string, string>,
  tokenField?: string
): Promise<SessionState | null> {
  const session: SessionState = {
    cookies: new Map(),
    tokens: [],
    recordedSteps: [],
    loginUrl,
    loginPayload,
    loggedIn: false,
  };

  try {
    logger.info({ loginUrl }, "Recording authenticated session");

    const res = await fetch(loginUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginPayload),
      redirect: "manual",
    });

    session.recordedSteps.push({ method: "POST", url: loginUrl, status: res.status });

    const setCookies = res.headers.getSetCookie?.() ?? res.headers.get("set-cookie")?.split(",") ?? [];
    for (const c of setCookies) {
      const [nameValue] = c.split(";");
      if (nameValue?.includes("=")) {
        const [name, ...valueParts] = nameValue.split("=");
        const value = valueParts.join("=");
        session.cookies.set(name.trim(), value.trim());
      }
    }

    try {
      const body = await res.json().catch(() => ({}));
      const tokenSource = tokenField ? body[tokenField] : body.token ?? body.access_token ?? body.jwt;
      if (tokenSource) {
        session.tokens.push({ type: "bearer", value: String(tokenSource) });
      }

      if (typeof body === "object" && body.role) {
        (session as any).userRole = body.role;
      }
    } catch { /* ignore */ }

    const hasAuthCookies = session.cookies.size > 0;
    const hasAuthToken = session.tokens.length > 0;
    session.loggedIn = hasAuthCookies || hasAuthToken || res.status === 200;

    if (session.loggedIn) {
      session.expiresAt = Date.now() + 30 * 60 * 1000;
      logger.info({ cookies: session.cookies.size, tokens: session.tokens.length }, "Session recorded successfully");
    }

    return session.loggedIn ? session : null;
  } catch (err) {
    logger.error({ err, loginUrl }, "Session recording failed");
    return null;
  }
}

export function applySessionToContext(ctx: ScanContext, session: SessionState): void {
  if (!session.loggedIn) return;
  if (session.expiresAt && Date.now() > session.expiresAt) {
    logger.warn("Session expired — re-authentication needed");
    return;
  }

  const cookieHeader = [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

  if (cookieHeader) {
    ctx.customHeaders = {
      ...(ctx.customHeaders ?? {}),
      Cookie: cookieHeader,
    };
    ctx.sessionCookie = cookieHeader;
  }

  for (const token of session.tokens) {
    if (token.type === "bearer") {
      ctx.customHeaders = {
        ...(ctx.customHeaders ?? {}),
        Authorization: `Bearer ${token.value}`,
      };
      ctx.authToken = token.value;
    }
  }

  logger.info("Applied authenticated session to scan context");
}
