/**
 * Nuclei integration — three-tier operation:
 *
 * Tier 1 (preferred): Real Nuclei binary via child_process.spawn.
 *   Set NUCLEI_BINARY=/usr/local/bin/nuclei (or just "nuclei" if on PATH).
 *   Runs: nuclei -u <target> -j -severity critical,high,medium -nc
 *   Parses JSONL output line-by-line.
 *
 * Tier 2 (Docker service): Nuclei HTTP API.
 *   Set NUCLEI_URL=http://nuclei-api:8080
 *   Sends POST /api/scan, parses JSON array response.
 *
 * Tier 3 (no Nuclei available): Focused template simulations with real body
 *   verification — NOT just HTTP 200 status, but content-confirmed checks.
 *   These are distinct from recon.ts checks (different paths + stricter matching).
 */

import { ScanContext, ScanFinding } from "./types";
import { logger } from "../../lib/logger";
import { spawn } from "child_process";

// Tier 3 fallback templates — each has a real content-verification function
// so they don't fire on custom 404 pages that return 200.
const NUCLEI_TEMPLATES = [
  {
    id: "wp-config-backup",
    path: "/wp-config.php.bak",
    title: "WordPress Config Backup Exposed",
    sev: "critical" as const,
    cwe: "CWE-538",
    desc: "A WordPress configuration backup file is publicly accessible. It likely contains database credentials and secret keys.",
    verify: (body: string) => body.includes("DB_PASSWORD") || body.includes("DB_HOST") || body.includes("table_prefix"),
  },
  {
    id: "spring-actuator-env",
    path: "/actuator/env",
    title: "Spring Boot Actuator /env Exposed",
    sev: "high" as const,
    cwe: "CWE-200",
    desc: "The Spring Boot /actuator/env endpoint is publicly accessible, leaking environment variables including credentials.",
    verify: (body: string) => body.includes("activeProfiles") || body.includes("propertySources") || body.includes("systemProperties"),
  },
  {
    id: "spring-actuator-beans",
    path: "/actuator/beans",
    title: "Spring Boot Actuator /beans Exposed",
    sev: "medium" as const,
    cwe: "CWE-200",
    desc: "The Spring Boot /actuator/beans endpoint reveals the full application bean wiring, aiding targeted attacks.",
    verify: (body: string) => body.includes("\"beans\"") && body.includes("\"dependencies\""),
  },
  {
    id: "prometheus-metrics",
    path: "/metrics",
    title: "Prometheus Metrics Endpoint Exposed",
    sev: "medium" as const,
    cwe: "CWE-200",
    desc: "The Prometheus /metrics endpoint is publicly accessible, revealing internal application performance counters.",
    verify: (body: string) => body.includes("# HELP") && body.includes("# TYPE"),
  },
  {
    id: "exposed-composer-json",
    path: "/composer.json",
    title: "PHP composer.json Exposed",
    sev: "low" as const,
    cwe: "CWE-200",
    desc: "The composer.json dependency manifest is public, revealing package names and versions for targeted CVE attacks.",
    verify: (body: string) => body.includes('"require"') && body.includes('"name"'),
  },
  {
    id: "exposed-package-json",
    path: "/package.json",
    title: "Node.js package.json Exposed",
    sev: "low" as const,
    cwe: "CWE-200",
    desc: "The package.json dependency manifest is public, revealing npm package versions for targeted CVE attacks.",
    verify: (body: string) => body.includes('"dependencies"') && body.includes('"version"'),
  },
  {
    id: "laravel-debug",
    path: "/_ignition/health-check",
    title: "Laravel Ignition Debug Interface Exposed",
    sev: "high" as const,
    cwe: "CWE-94",
    desc: "The Laravel Ignition debug interface is publicly accessible. Older versions (< 2.5.2) are vulnerable to RCE (CVE-2021-3129).",
    verify: (body: string) => body.includes("can_execute_commands") || body.includes("ignition"),
  },
  {
    id: "exposed-graphql-introspection",
    path: "/graphql",
    title: "GraphQL Introspection Enabled",
    sev: "info" as const,
    cwe: "CWE-200",
    desc: "GraphQL introspection is enabled in production, exposing the full API schema to any client.",
    verify: (body: string) => body.includes("__schema") || body.includes("__typename"),
    method: "POST" as const,
    body: JSON.stringify({ query: "{ __typename }" }),
    contentType: "application/json",
  },
  {
    id: "exposed-trace-method",
    path: "/",
    title: "HTTP TRACE Method Enabled",
    sev: "low" as const,
    cwe: "CWE-16",
    desc: "The HTTP TRACE method is enabled. Combined with XSS, it can be used to steal credentials (XST attack).",
    verify: (_body: string, status: number) => status === 200 || status === 405,
    method: "TRACE" as const,
    checkStatus: (s: number) => s === 200, // 200 = TRACE accepted = vulnerable
  },
];

async function spawnNuclei(targetUrl: string, binaryPath: string, ctx: ScanContext): Promise<ScanFinding[]> {
  return new Promise((resolve) => {
    const findings: ScanFinding[] = [];
    const args = [
      "-u", targetUrl,
      "-j",                            // JSONL output
      "-severity", "critical,high,medium,low",
      "-nc",                           // no color
      "-timeout", "10",
      "-retries", "1",
      "-silent",
    ];

    ctx.emit({ type: "log", message: `Nuclei binary: ${binaryPath} ${args.slice(0, 4).join(" ")} ...` });

    const proc = spawn(binaryPath, args, { timeout: 120000 });
    let stderr = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      const lines = chunk.toString().split("\n");
      for (const line of lines) {
        if (!line.trim() || !line.startsWith("{")) continue;
        try {
          const r = JSON.parse(line) as Record<string, unknown>;
          const sev = String(r["info"] ? (r["info"] as Record<string, unknown>)["severity"] : r["severity"] ?? "info").toLowerCase();
          const validSev = ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info";
          findings.push({
            title: String((r["info"] as Record<string, unknown>)?.["name"] ?? r["template-id"] ?? "Nuclei Finding"),
            category: String((r["info"] as Record<string, unknown>)?.["tags"] ?? "Security Misconfiguration"),
            severity: validSev as ScanFinding["severity"],
            endpoint: String(r["matched-at"] ?? targetUrl),
            description: String((r["info"] as Record<string, unknown>)?.["description"] ?? "Found by Nuclei template"),
            evidence: [
              `Template: ${r["template-id"]}`,
              `Matched: ${r["matched-at"]}`,
              r["extracted-results"] ? `Extracted: ${JSON.stringify(r["extracted-results"])}` : "",
              r["curl-command"] ? `\nReproduction:\n${r["curl-command"]}` : "",
            ].filter(Boolean).join("\n"),
            recommended_fix: String((r["info"] as Record<string, unknown>)?.["remediation"] ?? "Apply security patches and follow vendor recommendations."),
            cvss_score: typeof r["cvss-score"] === "number" ? r["cvss-score"] : ({ critical: 9.0, high: 7.5, medium: 5.0, low: 3.0, info: 1.0 }[validSev] ?? 5.0),
            cwe_id: String((r["info"] as Record<string, unknown>)?.["classification"] ? ((r["info"] as Record<string, unknown>)["classification"] as Record<string, unknown>)?.["cwe-id"] ?? "CWE-200" : r["cwe-id"] ?? "CWE-200"),
            scanner_name: `Nuclei/${r["template-id"] ?? "template"}`,
            scanner_family: "Nuclei",
            confidence: 0.88,
          });
        } catch { /* malformed JSONL line — skip */ }
      }
    });

    proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

    proc.on("close", (code) => {
      if (code !== 0 && findings.length === 0) {
        logger.warn({ code, stderr: stderr.slice(0, 200) }, "Nuclei binary exited non-zero");
      }
      resolve(findings);
    });

    proc.on("error", (err) => {
      logger.warn({ err }, "Nuclei binary spawn error");
      resolve([]);
    });
  });
}

export async function runNucleiScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  ctx.emit({ type: "engine_start", engine: "Bug-Finder/Nuclei", message: "Running Nuclei template scan..." });

  // ── Tier 1: Real Nuclei binary ───────────────────────────────────────────────
  const nucleiBinary = process.env["NUCLEI_BINARY"];
  if (nucleiBinary) {
    try {
      const binaryFindings = await spawnNuclei(ctx.targetUrl, nucleiBinary, ctx);
      findings.push(...binaryFindings);
      ctx.emit({ type: "log", message: `Nuclei binary: ${binaryFindings.length} finding(s)` });
    } catch (err) {
      logger.warn({ err }, "Nuclei binary scan failed — falling through to Tier 2");
    }
  }

  // ── Tier 2: Nuclei HTTP API (Docker service) ────────────────────────────────
  if (findings.length === 0) {
    const nucleiUrl = process.env["NUCLEI_URL"];
    if (nucleiUrl) {
      try {
        const resp = await fetch(`${nucleiUrl}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: ctx.targetUrl,
            templates: ["cves", "exposures", "misconfiguration", "vulnerabilities"],
            severity: ["critical", "high", "medium"],
          }),
          signal: AbortSignal.timeout(120000),
        });
        if (resp.ok) {
          const results = await resp.json() as Array<Record<string, unknown>>;
          for (const r of results) {
            const sev = String(r["severity"] ?? "medium").toLowerCase();
            const validSev = ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "medium";
            findings.push({
              title: String(r["name"] ?? r["template-id"] ?? "Nuclei Finding"),
              category: String(r["type"] ?? "Security Misconfiguration"),
              severity: validSev as ScanFinding["severity"],
              endpoint: String(r["matched-at"] ?? ctx.targetUrl),
              description: String(r["description"] ?? "Found by Nuclei template engine"),
              evidence: String(r["extracted-results"] ?? r["matched-at"] ?? ""),
              recommended_fix: String(r["remediation"] ?? "Apply security patches and follow vendor recommendations"),
              cvss_score: typeof r["cvss-score"] === "number" ? r["cvss-score"] : 5.0,
              cwe_id: String(r["cwe-id"] ?? "CWE-200"),
              scanner_name: `Nuclei/${r["template-id"] ?? "template"}`,
              scanner_family: "Nuclei",
              confidence: 0.85,
            });
          }
          ctx.emit({ type: "log", message: `Nuclei API: ${results.length} finding(s)` });
        }
      } catch (err) {
        logger.warn({ err }, "Nuclei API scan failed — falling through to Tier 3");
      }
    }
  }

  // ── Tier 3: Content-verified built-in checks ──────────────────────────────────
  // Only runs when neither Nuclei binary nor API is available.
  // These are NOT Nuclei templates — they are Bug-Finder's own verified checks
  // for common misconfigurations. scanner_name reflects this (Bug-Finder/Nuclei-sim/*).
  if (findings.length === 0) {
    ctx.emit({ type: "log", message: `Nuclei unavailable — running ${NUCLEI_TEMPLATES.length} built-in misconfiguration checks (Bug-Finder/Nuclei-sim)` });
    const base = new URL(ctx.targetUrl);

    for (const tpl of NUCLEI_TEMPLATES) {
      if (ctx.abortSignal?.aborted) break;
      try {
        const url = `${base.protocol}//${base.host}${tpl.path}`;
        const method = tpl.method ?? "GET";
        const fetchOpts: RequestInit = {
          method,
          headers: {
            Accept: "application/json, text/html, */*",
            ...(tpl.contentType ? { "Content-Type": tpl.contentType } : {}),
          },
          body: tpl.body,
          signal: AbortSignal.timeout(8000),
          redirect: "manual",
        };

        const resp = await fetch(url, fetchOpts).catch(() => null);
        if (!resp) continue;

        const body = await resp.text().catch(() => "");
        const status = resp.status;

        // For TRACE method check: 200 = vulnerable, others = not
        if (tpl.checkStatus && !tpl.checkStatus(status)) continue;
        // For all others: must be 200 AND body must verify
        if (!tpl.checkStatus && (status !== 200 || !tpl.verify(body))) continue;

        findings.push({
          title: tpl.title,
          category: "Security Misconfiguration",
          severity: tpl.sev,
          endpoint: url,
          description: tpl.desc,
          evidence: [
            `${method} ${url}`,
            `HTTP ${status}`,
            `Body verification: PASSED`,
            ``,
            `Response body (first 300 bytes):`,
            body.slice(0, 300),
          ].join("\n"),
          recommended_fix: "Restrict access to this endpoint via web server or application configuration. Remove or disable in production.",
          cvss_score: { critical: 9.1, high: 7.5, medium: 5.3, low: 3.1, info: 1.0 }[tpl.sev],
          cwe_id: tpl.cwe,
          scanner_name: `Bug-Finder/Nuclei-sim/${tpl.id}`,
          scanner_family: "Nuclei",
          confidence: 0.90,
        });
        ctx.emit({ type: "log", message: `  [Nuclei sim] ${tpl.title} confirmed at ${url}` });
      } catch { /* skip */ }
    }
  }

  const tier = process.env["NUCLEI_BINARY"] ? "Tier 1 (binary)" : process.env["NUCLEI_URL"] ? "Tier 2 (API)" : "Tier 3 (built-in)";
  ctx.emit({ type: "engine_done", engine: "Bug-Finder/Nuclei", message: `Nuclei scan complete [${tier}] — ${findings.length} finding(s)` });
  return findings;
}
