import { ScanContext, ScanFinding, ctxFetch } from "./types";

export async function runCookieCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Cookies", message: "Checking cookie security flags" });

  const res = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (!res) {
    emit({ type: "engine_done", engine: "Bug-Finder/Cookies", message: "Cookie check skipped (unreachable)" });
    return findings;
  }

  const setCookieHeaders: string[] = [];
  res.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") {
      setCookieHeaders.push(value);
    }
  });

  if (setCookieHeaders.length === 0) {
    emit({ type: "log", message: "No Set-Cookie headers found on root" });
    // Try login page
    const loginRes = await ctxFetch(ctx, `${new URL(targetUrl).origin}/login`, { redirect: "follow" });
    if (loginRes) {
      loginRes.headers.forEach((value, key) => {
        if (key.toLowerCase() === "set-cookie") setCookieHeaders.push(value);
      });
    }
  }

  if (setCookieHeaders.length === 0) {
    emit({ type: "log", message: "No cookies set by target" });
    emit({ type: "engine_done", engine: "Bug-Finder/Cookies", message: "No cookies found to analyze" });
    return findings;
  }

  emit({ type: "log", message: `Found ${setCookieHeaders.length} cookie(s) to analyze` });

  for (const cookie of setCookieHeaders) {
    const cookieLower = cookie.toLowerCase();
    const cookieName = cookie.split("=")[0]?.trim() ?? "unknown";

    if (!cookieLower.includes("httponly")) {
      findings.push({
        title: `Cookie Missing HttpOnly Flag: ${cookieName}`,
        category: "Session Management",
        severity: "medium",
        endpoint: targetUrl,
        description: `Cookie "${cookieName}" does not have the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based session theft.`,
        evidence: `Set-Cookie: ${cookie}`,
        recommended_fix: `Add HttpOnly flag: Set-Cookie: ${cookieName}=<value>; HttpOnly; Secure; SameSite=Strict`,
        cvss_score: 5.4,
        cwe_id: "CWE-1004",
        scanner_name: "Bug-Finder",
        scanner_family: "web",
        confidence: 0.98,
      });
      emit({ type: "log", message: `Cookie missing HttpOnly: ${cookieName}` });
    }

    const isHttps = targetUrl.startsWith("https://");
    if (isHttps && !cookieLower.includes("secure")) {
      findings.push({
        title: `Cookie Missing Secure Flag: ${cookieName}`,
        category: "Session Management",
        severity: "medium",
        endpoint: targetUrl,
        description: `Cookie "${cookieName}" does not have the Secure flag. It may be transmitted over unencrypted HTTP connections.`,
        evidence: `Set-Cookie: ${cookie}`,
        recommended_fix: `Add Secure flag: Set-Cookie: ${cookieName}=<value>; HttpOnly; Secure; SameSite=Strict`,
        cvss_score: 5.3,
        cwe_id: "CWE-614",
        scanner_name: "Bug-Finder",
        scanner_family: "web",
        confidence: 0.95,
      });
      emit({ type: "log", message: `Cookie missing Secure flag: ${cookieName}` });
    }

    if (!cookieLower.includes("samesite")) {
      findings.push({
        title: `Cookie Missing SameSite Attribute: ${cookieName}`,
        category: "Session Management",
        severity: "medium",
        endpoint: targetUrl,
        description: `Cookie "${cookieName}" does not set the SameSite attribute, potentially allowing cross-site request forgery.`,
        evidence: `Set-Cookie: ${cookie}`,
        recommended_fix: `Add SameSite=Strict or SameSite=Lax to the cookie.`,
        cvss_score: 4.3,
        cwe_id: "CWE-352",
        scanner_name: "Bug-Finder",
        scanner_family: "web",
        confidence: 0.9,
      });
      emit({ type: "log", message: `Cookie missing SameSite: ${cookieName}` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Cookies",
    message: `Cookie check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
