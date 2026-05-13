import { ScanContext, ScanFinding } from "./types";
import { logger } from "../../lib/logger";

const PLAYWRIGHT_URL = process.env["PLAYWRIGHT_URL"] ?? "http://localhost:3005";

export async function runPlaywrightScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const targetUrl = ctx.targetUrl;

  try {
    logger.info({ targetUrl }, "Starting Playwright automated browser scan");

    // Try to connect to Playwright service
    const response = await fetch(`${PLAYWRIGHT_URL}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: targetUrl, waitForNetworkIdle: true }),
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      logger.warn({ status: response.status }, "Playwright service unavailable — skipping browser scan");
      return runFallbackCheck(ctx);
    }

    const data = await response.json() as Record<string, unknown>;

    // Check for DOM-based XSS
    if (data["dom_xss_sinks"] && Array.isArray(data["dom_xss_sinks"])) {
      for (const sink of data["dom_xss_sinks"] as Array<{ element: string; source: string; line: number }>) {
        findings.push({
          title: `Potential DOM XSS in ${sink.element}`,
          severity: "high",
          category: "Cross-Site Scripting",
          endpoint: `${targetUrl}:${sink.line}`,
          cwe_id: "CWE-79",
          description: `DOM-based XSS sink detected in ${sink.element}. Source: ${sink.source}. An attacker may inject malicious scripts that execute in the user's browser.`,
          evidence: `Sink: ${sink.source} at line ${sink.line}`,
          recommended_fix: "Use textContent instead of innerHTML. Sanitize with DOMPurify before insertion.",
          cvss_score: 6.1,
          scanner_name: "Bug-Finder/Playwright",
          scanner_family: "browser",
          confidence: 0.7,
        });
      }
    }

    // Check for exposed console errors (info leakage)
    if (data["console_errors"] && Array.isArray(data["console_errors"]) && data["console_errors"].length > 0) {
      const sensitiveErrors = (data["console_errors"] as Array<{ message: string }>)
        .filter((e) => /token|key|secret|password|credential|sql|stack trace/i.test(e.message));

      if (sensitiveErrors.length > 0) {
        findings.push({
          title: "Sensitive Information in Browser Console",
          severity: "medium",
          category: "Information Disclosure",
          endpoint: targetUrl,
          cwe_id: "CWE-200",
          description: `${sensitiveErrors.length} console messages contain potentially sensitive information: ${sensitiveErrors.slice(0, 2).map((e) => e.message).join("; ")}`,
          evidence: sensitiveErrors[0]?.message ?? "Console error detected",
          recommended_fix: "Remove debug logging in production. Implement error boundaries that don't leak stack traces.",
          cvss_score: 4.3,
          scanner_name: "Bug-Finder/Playwright",
          scanner_family: "browser",
          confidence: 0.6,
        });
      }
    }

    // Check for missing security headers visible in browser
    if (data["headers"] && typeof data["headers"] === "object") {
      const headers = data["headers"] as Record<string, string>;
      if (!headers["content-security-policy"]) {
        findings.push({
          title: "Content Security Policy Not Enforced",
          severity: "high",
          category: "Security Misconfiguration",
          endpoint: targetUrl,
          cwe_id: "CWE-693",
          description: "CSP header not present in browser response. This allows inline scripts and makes XSS exploitation easier.",
          evidence: "Browser response headers missing Content-Security-Policy",
          recommended_fix: "Add strict CSP: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
          cvss_score: 7.5,
          scanner_name: "Bug-Finder/Playwright",
          scanner_family: "browser",
          confidence: 0.9,
        });
      }
    }

    // Check localStorage for sensitive data
    if (data["local_storage_keys"] && Array.isArray(data["local_storage_keys"])) {
      const sensitiveKeys = (data["local_storage_keys"] as string[])
        .filter((k) => /token|secret|key|auth|session|jwt|password|credential/i.test(k));

      if (sensitiveKeys.length > 0) {
        findings.push({
          title: "Sensitive Data Stored in localStorage",
          severity: "medium",
          category: "Information Disclosure",
          endpoint: targetUrl,
          cwe_id: "CWE-922",
          description: `Sensitive keys found in localStorage: ${sensitiveKeys.join(", ")}. localStorage is accessible via XSS and persists indefinitely.`,
          evidence: `localStorage keys: ${sensitiveKeys.join(", ")}`,
          recommended_fix: "Store sensitive tokens in httpOnly cookies. Use sessionStorage for ephemeral data.",
          cvss_score: 5.3,
          scanner_name: "Bug-Finder/Playwright",
          scanner_family: "browser",
          confidence: 0.8,
        });
      }
    }

  } catch (err) {
    logger.warn({ err, targetUrl }, "Playwright scan failed — using fallback");
    return runFallbackCheck(ctx);
  }

  return findings;
}

function runFallbackCheck(ctx: ScanContext): ScanFinding[] {
  const findings: ScanFinding[] = [];

  // Basic DOM check via regex on the target if accessible
  findings.push({
    title: "Browser Automation Not Available — Skipping Client-Side Checks",
    severity: "info",
    category: "Scanner Info",
    endpoint: ctx.targetUrl,
    cwe_id: "N/A",
    description: "Playwright browser automation service is not running. DOM-based XSS, client-side storage, and SPA crawling checks were skipped. Run the Playwright service for full browser-based security testing.",
    evidence: "Playwright service at " + PLAYWRIGHT_URL + " is unreachable",
    recommended_fix: "Start Playwright service: docker run -p 3005:3005 playwright-service",
    cvss_score: 0,
    scanner_name: "Bug-Finder/Playwright",
    scanner_family: "browser",
    confidence: 1.0,
  });

  return findings;
}
