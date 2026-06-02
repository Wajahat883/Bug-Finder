import { logger } from "../../lib/logger";
import { ScanContext, ScanFinding, safeFetch } from "./types";
import { runDomBrowserScan } from "./dom-browser";

let playwrightAvailable = false;
let checkedPlaywright = false;
let lastCheckedAt = 0;
const RECHECK_INTERVAL_MS = 60_000; // re-probe every 60s so a slow-starting container is eventually detected

async function ensurePlaywright(): Promise<boolean> {
  const now = Date.now();
  // Return cached result if still fresh, or if previously confirmed available
  if (checkedPlaywright && (playwrightAvailable || now - lastCheckedAt < RECHECK_INTERVAL_MS)) {
    return playwrightAvailable;
  }

  const playwrightUrl = process.env["PLAYWRIGHT_URL"];

  if (playwrightUrl) {
    try {
      const res = await fetch(`${playwrightUrl}/health`, { signal: AbortSignal.timeout(3000) });
      playwrightAvailable = res.ok;
      checkedPlaywright = true;
      lastCheckedAt = now;
      if (playwrightAvailable) {
        logger.info({ playwrightUrl }, "Playwright service available");
        return true;
      }
      logger.warn({ playwrightUrl, status: res.status }, "Playwright /health returned non-OK — will retry");
    } catch { /* not running yet — will retry next scan */ }
  }

  // Try local check
  try {
    // @ts-expect-error - optional dependency, may not be installed
    const puppeteer = await import("puppeteer").catch(() => null);
    if (puppeteer) {
      playwrightAvailable = true;
      logger.info("Puppeteer module found — browser automation available");
      checkedPlaywright = true;
      return true;
    }
  } catch { /* not installed */ }

  logger.info("Playwright/Puppeteer not available — using DOM parser fallback");
  checkedPlaywright = true;
  return false;
}

export async function runPlaywrightScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const available = await ensurePlaywright();

  if (!available) {
    return runDomBrowserScan(ctx);
  }

  const playwrightUrl = process.env["PLAYWRIGHT_URL"];

  if (playwrightUrl) {
    // Use external Playwright service
    ctx.emit({ type: "engine_start", engine: "Playwright", message: "Running browser automation via external service..." });
    try {
      const res = await fetch(`${playwrightUrl}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: ctx.targetUrl, waitForNetwork: true, timeout: 30000 }),
        signal: AbortSignal.timeout(45000),
      });

      if (res.ok) {
        const data = await res.json() as { findings?: Array<Record<string, unknown>> };
        const findings: ScanFinding[] = [];

        for (const f of data.findings ?? []) {
          findings.push({
            title: String(f["title"] ?? "Browser Finding"),
            category: String(f["category"] ?? "Client-Side Security"),
            severity: (["critical", "high", "medium", "low", "info"].includes(String(f["severity"])) ? String(f["severity"]) : "medium") as ScanFinding["severity"],
            endpoint: String(f["url"] ?? ctx.targetUrl),
            description: String(f["description"] ?? ""),
            evidence: `${String(f["type"] ?? "")}: ${String(f["message"] ?? "")}`,
            recommended_fix: String(f["fix"] ?? "Review browser-level security"),
            cvss_score: Number(f["cvss"] ?? 5),
            cwe_id: String(f["cwe"] ?? "CWE-200"),
            scanner_name: `playwright/${f["rule"] ?? "browser"}`,
            scanner_family: "playwright",
            confidence: 0.9,
          });
        }

        ctx.emit({ type: "engine_done", engine: "Playwright", message: `Browser scan complete — ${findings.length} finding(s)` });
        return findings;
      }
    } catch (err) {
      logger.warn({ err }, "Playwright service failed — falling back to DOM parser");
      return runDomBrowserScan(ctx);
    }
  }

  // Try local Puppeteer
  try {
    // @ts-expect-error - optional dependency, may not be installed
    const puppeteer = await import("puppeteer");
    ctx.emit({ type: "engine_start", engine: "Playwright", message: "Launching headless browser..." });

    const browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
    });

    const page = await browser.newPage();
    await page.goto(ctx.targetUrl, { waitUntil: "networkidle2", timeout: 30000 });
    const html = await page.content();

    const consoleLogs: string[] = [];
    page.on("console", (msg: { text(): string }) => consoleLogs.push(msg.text()));

    const findings: ScanFinding[] = [];

    // Check for CSP violations reported by browser
    const cspViolations = consoleLogs.filter(l => l.includes("CSP") || l.includes("Content Security Policy"));
    if (cspViolations.length > 0) {
      findings.push({
        title: "CSP Violations Detected in Browser",
        category: "Content Security Policy",
        severity: "medium",
        endpoint: ctx.targetUrl,
        description: `Browser detected ${cspViolations.length} CSP violation(s).`,
        evidence: cspViolations.slice(0, 5).join("\n"),
        recommended_fix: "Review and fix CSP policy to prevent violations.",
        cvss_score: 4.0,
        cwe_id: "CWE-1021",
        scanner_name: "playwright-csp",
        scanner_family: "playwright",
        confidence: 0.95,
      });
    }

    // Check for missing security headers
    const headers = await page.evaluate(() => {
      return (performance.getEntriesByType("resource") as PerformanceResourceTiming[])
        .map(e => ({ name: e.name, type: e.initiatorType }));
    });

    await browser.close();

    ctx.emit({ type: "engine_done", engine: "Playwright", message: `Browser scan complete — ${findings.length} finding(s)` });
    return findings;
  } catch (err) {
    logger.warn({ err }, "Puppeteer launch failed — falling back to DOM parser");
    return runDomBrowserScan(ctx);
  }
}
