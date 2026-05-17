import { exec, spawn, execSync } from "child_process";
import fs from "fs";
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
  const findings: ScanFinding[] = [];
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

// ---------------------------------------------------------------------------
// Docker-based ZAP scan (report mode) — runs zap-baseline.py / zap-full-scan.py
// ---------------------------------------------------------------------------

function isDockerAvailable(): boolean {
  try { execSync("docker --version", { stdio: "pipe" }); return true; } catch { return false; }
}

function hasZapImage(): boolean {
  try {
    const result = execSync("docker images zaproxy/zap-stable -q", { stdio: "pipe" }).toString().trim();
    return result.length > 0;
  } catch { return false; }
}

interface ZapDockerFinding {
  title: string; severity: string; description: string; solution: string;
  reference: string; evidence: string; endpoint: string; cwe_id?: string; wascid?: string;
}

function parseZapJsonReport(report: unknown): ZapDockerFinding[] {
  const findings: ZapDockerFinding[] = [];
  const r = report as Record<string, unknown>;
  for (const site of ((r["site"] ?? []) as Array<Record<string, unknown>>)) {
    for (const alert of ((site["alerts"] ?? []) as Array<Record<string, unknown>>)) {
      const instances = (alert["instances"] ?? []) as Array<Record<string, unknown>>;
      findings.push({
        title: String(alert["name"] ?? "Unknown"),
        severity: zapRiskCodeToSeverity(String(alert["riskcode"] ?? "0")),
        description: String(alert["desc"] ?? ""),
        solution: String(alert["solution"] ?? ""),
        reference: String(alert["reference"] ?? ""),
        evidence: String(instances[0]?.["evidence"] ?? ""),
        endpoint: String(instances[0]?.["uri"] ?? site["@name"] ?? ""),
        cwe_id: alert["cweid"] ? `CWE-${alert["cweid"]}` : undefined,
        wascid: alert["wascid"] ? String(alert["wascid"]) : undefined,
      });
    }
  }
  return findings;
}

function zapRiskCodeToSeverity(riskcode: string): string {
  const map: Record<string, string> = { "3": "high", "2": "medium", "1": "low", "0": "info" };
  return map[riskcode] ?? "info";
}

/**
 * Run ZAP via Docker in report mode (zap-baseline.py / zap-full-scan.py).
 * Falls back to simulation (empty array) when Docker is unavailable.
 * This is separate from the daemon-mode scan used by runZapScan().
 */
export async function runZapDockerScan(
  target: string,
  mode: "baseline" | "attack" = "baseline"
): Promise<ZapDockerFinding[]> {
  if (!isDockerAvailable()) {
    logger.warn("Docker not available — ZAP docker scan skipped");
    return [];
  }

  if (!hasZapImage()) {
    logger.warn("zaproxy/zap-stable image not found — pulling may be required");
  }

  const reportFile = `zap-report-${Date.now()}.json`;
  const reportPath = `/tmp/${reportFile}`;
  const script = mode === "baseline" ? "zap-baseline.py" : "zap-full-scan.py";

  return new Promise((resolve) => {
    const args = [
      "run", "--rm",
      "-v", "/tmp:/zap/wrk",
      "zaproxy/zap-stable",
      "python", script,
      "-t", target,
      "-J", `/zap/wrk/${reportFile}`,
      "-I", // ignore failures / non-zero exit
    ];

    logger.info({ target, mode, script }, "Starting ZAP Docker scan");
    const proc = spawn("docker", args, { stdio: "pipe" });
    let stderr = "";

    proc.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });

    proc.on("close", (code: number | null) => {
      try {
        if (fs.existsSync(reportPath)) {
          const report = JSON.parse(fs.readFileSync(reportPath, "utf-8")) as unknown;
          try { fs.unlinkSync(reportPath); } catch { /* best-effort cleanup */ }
          const findings = parseZapJsonReport(report);
          logger.info({ count: findings.length }, "ZAP Docker scan complete");
          resolve(findings);
        } else {
          logger.warn({ code, stderr: stderr.slice(0, 500) }, "ZAP Docker report not generated");
          resolve([]);
        }
      } catch (err) {
        logger.error({ err }, "ZAP Docker report parse error");
        resolve([]);
      }
    });

    proc.on("error", (err) => {
      logger.error({ err }, "ZAP Docker process error");
      resolve([]);
    });

    // Timeout after 10 minutes
    const timer = setTimeout(() => {
      proc.kill();
      logger.warn("ZAP Docker scan timed out after 10 minutes");
      resolve([]);
    }, 600_000);

    proc.on("close", () => clearTimeout(timer));
  });
}
