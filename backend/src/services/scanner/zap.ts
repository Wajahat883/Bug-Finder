import { exec } from "child_process";
import { logger } from "../../lib/logger";
import { ScanContext, ScanFinding } from "./types";

let isZapAvailable = false;
let isZapStarting = false;
let startupPromise: Promise<boolean> | null = null;

export async function ensureZapRunning(): Promise<boolean> {
  if (isZapAvailable) return true;
  if (isZapStarting && startupPromise) return startupPromise;

  const zapUrl = process.env["ZAP_URL"] ?? "http://localhost:8080";

  // Step 1: Check if ZAP is already running
  try {
    const res = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      isZapAvailable = true;
      logger.info({ zapUrl }, "OWASP ZAP is running");
      return true;
    }
  } catch {
    logger.info({ zapUrl }, "ZAP not responding — attempting auto-start");
  }

  isZapStarting = true;
  startupPromise = startZapContainer(zapUrl);
  isZapStarting = false;
  return startupPromise;
}

async function startZapContainer(zapUrl: string): Promise<boolean> {
  const zapPort = new URL(zapUrl).port || "8080";

  // Try Docker
  logger.info("Attempting to start ZAP via Docker...");
  try {
    await execShell(`docker run -d --name zap-scanner -p ${zapPort}:8080 -i ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true 2>/dev/null`);
    logger.info("ZAP Docker container started — waiting for readiness...");

    // Wait up to 30s for ZAP to be ready
    for (let i = 0; i < 15; i++) {
      await new Promise(r => setTimeout(r, 2000));
      try {
        const res = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          isZapAvailable = true;
          logger.info({ zapUrl }, "OWASP ZAP is now ready");
          return true;
        }
      } catch { /* still starting */ }
      logger.info(`Waiting for ZAP... (${(i + 1) * 2}s)`);
    }
    logger.warn("ZAP container started but not responding within 30s");
    return false;
  } catch (dockerErr) {
    logger.warn({ dockerErr }, "Docker not available — trying local ZAP installation...");
  }

  // Try local ZAP binary
  try {
    const zapPath = process.env["ZAP_PATH"] ?? "zap.sh";
    exec(`${zapPath} -daemon -port ${zapPort} -config api.disablekey=true &`, (err) => {
      if (err) logger.warn({ err }, "Failed to start local ZAP");
    });

    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 2000));
      try {
        const res = await fetch(`${zapUrl}/JSON/core/view/version/`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          isZapAvailable = true;
          return true;
        }
      } catch { /* still starting */ }
    }
  } catch { /* no local ZAP */ }

  logger.warn("OWASP ZAP not available — active scanning will use fallback HTTP probes");
  return false;
}

export async function runZapScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFindings[] = [];
  const zapUrl = process.env["ZAP_URL"] ?? "http://localhost:8080";

  const available = await ensureZapRunning();

  if (!available) {
    // Fallback: run basic HTTP probe checks instead of full ZAP scan
    return runZapFallback(ctx);
  }

  ctx.emit({ type: "engine_start", engine: "OWASP ZAP", message: "Running ZAP spider + active scan..." });

  try {
    // Start spider
    const spiderRes = await fetch(`${zapUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(ctx.targetUrl)}&maxChildren=3`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!spiderRes.ok) throw new Error("Spider failed to start");

    const spiderData = await spiderRes.json() as Record<string, unknown>;
    const spiderId = String(spiderData["scan"] ?? "");

    // Wait for spider
    let spiderDone = false;
    for (let i = 0; i < 30 && !spiderDone; i++) {
      await new Promise(r => setTimeout(r, 1000));
      const statusRes = await fetch(`${zapUrl}/JSON/spider/view/status/?scanId=${spiderId}`, { signal: AbortSignal.timeout(5000) });
      if (statusRes.ok) {
        const statusData = await statusRes.json() as Record<string, unknown>;
        const progress = String(statusData["status"] ?? "0");
        if (i % 5 === 0) ctx.emit({ type: "log", message: `  ZAP Spider progress: ${progress}%` });
        if (progress === "100") spiderDone = true;
      }
    }

    // Active scan
    const scanRes = await fetch(`${zapUrl}/JSON/ascan/action/scan/?url=${encodeURIComponent(ctx.targetUrl)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (scanRes.ok) {
      const scanData = await scanRes.json() as Record<string, unknown>;
      const scanId = String(scanData["scan"] ?? "");

      let scanDone = false;
      for (let i = 0; i < 60 && !scanDone; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const statusRes = await fetch(`${zapUrl}/JSON/ascan/view/status/?scanId=${scanId}`, { signal: AbortSignal.timeout(5000) });
        if (statusRes.ok) {
          const statusData = await statusRes.json() as Record<string, unknown>;
          const progress = String(statusData["status"] ?? "0");
          if (i % 5 === 0) ctx.emit({ type: "log", message: `  ZAP Active Scan: ${progress}%` });
          if (progress === "100") scanDone = true;
        }
      }

      // Get alerts
      const alertsRes = await fetch(`${zapUrl}/JSON/core/view/alerts/?baseurl=${encodeURIComponent(ctx.targetUrl)}`, {
        signal: AbortSignal.timeout(10000),
      });
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json() as { alerts: Array<Record<string, unknown>> };

        const seen = new Set<string>();
        for (const alert of (alertsData["alerts"] ?? [])) {
          const dedupKey = `${alert["alert"] ?? ""}|${alert["url"] ?? ""}`;
          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          findings.push({
            title: String(alert["alert"] ?? "ZAP Finding"),
            category: String(alert["alert"] ?? "Security").slice(0, 50),
            severity: mapZapRisk(alert["risk"]),
            endpoint: String(alert["url"] ?? ctx.targetUrl),
            description: String(alert["description"] ?? ""),
            evidence: `ZAP Alert: ${alert["alert"]}\nURL: ${alert["url"]}\nParameter: ${alert["param"] ?? "N/A"}\nEvidence: ${alert["evidence"] ?? "N/A"}\nAttack: ${alert["attack"] ?? "N/A"}`,
            recommended_fix: String(alert["solution"] ?? "Review and fix based on OWASP guidance"),
            cvss_score: mapZapToCvss(alert["risk"]),
            cwe_id: String(alert["cweid"] ?? String(alert["pluginId"] ?? "N/A")),
            scanner_name: `zap/${alert["pluginId"] ?? "active"}`,
            scanner_family: "zap",
            confidence: 0.92,
          });
        }
      }
    }
  } catch (err) {
    logger.error({ err }, "ZAP scan error — running fallback");
    return runZapFallback(ctx);
  }

  ctx.emit({ type: "engine_done", engine: "OWASP ZAP", message: `ZAP scan complete — ${findings.length} finding(s)` });
  return findings;
}

function mapZapRisk(risk: unknown): ScanFinding["severity"] {
  const r = String(risk ?? "").toLowerCase();
  if (r === "high" || r === "3") return "high";
  if (r === "medium" || r === "2") return "medium";
  if (r === "low" || r === "1") return "low";
  if (r === "informational" || r === "0") return "info";
  return "medium";
}

function mapZapToCvss(risk: unknown): number {
  const r = String(risk ?? "").toLowerCase();
  if (r === "high" || r === "3") return 7.5;
  if (r === "medium" || r === "2") return 5.0;
  if (r === "low" || r === "1") return 3.0;
  return 1.0;
}

async function runZapFallback(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  ctx.emit({ type: "engine_start", engine: "ZAP Fallback", message: "Running basic HTTP vulnerability probes..." });

  const base = new URL(ctx.targetUrl);
  const probes = [
    { path: "/.env", title: "Environment File Exposure", severity: "critical", cwe: "CWE-538" },
    { path: "/.git/config", title: "Git Repository Exposure", severity: "high", cwe: "CWE-538" },
    { path: "/wp-config.php.bak", title: "WordPress Config Backup", severity: "critical", cwe: "CWE-538" },
    { path: "/phpinfo.php", title: "PHP Info Exposure", severity: "medium", cwe: "CWE-200" },
    { path: "/actuator/env", title: "Spring Actuator Exposure", severity: "high", cwe: "CWE-200" },
    { path: "/swagger.json", title: "API Documentation Exposure", severity: "low", cwe: "CWE-200" },
    { path: "/graphql", title: "GraphQL Endpoint", severity: "info", cwe: "CWE-200" },
    { path: "/metrics", title: "Metrics Endpoint", severity: "low", cwe: "CWE-200" },
  ];

  for (const probe of probes) {
    try {
      const url = `${base.protocol}//${base.host}${probe.path}`;
      const res = await fetch(url, { method: "GET", signal: AbortSignal.timeout(6000), redirect: "manual" });
      if (res.status === 200) {
        const body = await res.text().catch(() => "");
        if (body.length > 10) {
          findings.push({
            title: probe.title,
            category: "Security Misconfiguration",
            severity: probe.severity as ScanFinding["severity"],
            endpoint: url,
            description: `Sensitive path ${probe.path} is publicly accessible.`,
            evidence: `HTTP 200 — ${body.length} bytes: ${body.slice(0, 300)}`,
            recommended_fix: "Restrict access to sensitive paths via web server configuration.",
            cvss_score: probe.severity === "critical" ? 9.1 : probe.severity === "high" ? 7.5 : 5.0,
            cwe_id: probe.cwe,
            scanner_name: "zap-fallback",
            scanner_family: "zap",
            confidence: 0.85,
          });
          ctx.emit({ type: "finding", finding: findings[findings.length - 1] });
        }
      }
    } catch { /* skip unreachable */ }
  }

  ctx.emit({ type: "engine_done", engine: "ZAP Fallback", message: `Fallback scan complete — ${findings.length} issue(s)` });
  return findings;
}

function execShell(cmd: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
      if (err) reject(err);
      else resolve({ stdout, stderr });
    });
  });
}
