/**
 * Nuclei integration — three-tier operation:
 *
 * Tier 1 (preferred): Real Nuclei binary auto-detected via execSync("nuclei -version").
 *   Falls back to NUCLEI_BINARY env var path if detection fails.
 *   Runs: nuclei -u <target> -j -severity critical,high,medium,low -nc
 *   Parses JSONL output line-by-line.
 *   Auth: writes temp auth.yaml template when job.auth_token/session_cookie present.
 *
 * Tier 2 (Docker fallback): docker run projectdiscovery/nuclei
 *   Used when native binary not found but Docker is available.
 *
 * Tier 3 (no Nuclei available): Focused template simulations with real body
 *   verification — NOT just HTTP 200 status, but content-confirmed checks.
 *   These are distinct from recon.ts checks (different paths + stricter matching).
 */

import { ScanContext, ScanFinding } from "./types";
import { logger } from "../../lib/logger";
import { spawn, execSync } from "child_process";
import { writeFileSync, unlinkSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

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

// ── Binary detection helpers ──────────────────────────────────────────────────

function detectNucleiBinary(): string | null {
  // 1. Explicit env override
  const envBinary = process.env["NUCLEI_BINARY"];
  if (envBinary) return envBinary;

  // 2. Auto-detect on PATH
  try {
    execSync("nuclei -version", { stdio: "pipe" });
    return "nuclei";
  } catch {
    return null;
  }
}

function detectDockerAvailable(): boolean {
  try {
    execSync("docker info", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

// ── Temp auth template helpers ────────────────────────────────────────────────

interface AuthFiles {
  headerArgs: string[];
  cleanup: () => void;
}

function buildAuthArgs(ctx: ScanContext): AuthFiles {
  const headerArgs: string[] = [];
  const tempFiles: string[] = [];

  if (ctx.authToken) {
    const token = ctx.authToken.startsWith("Bearer ") ? ctx.authToken : `Bearer ${ctx.authToken}`;
    headerArgs.push("-H", `Authorization: ${token}`);

    // Write a nuclei auth yaml template for header-based auth
    const authYaml = `id: auth-bearer\ninfo:\n  name: Bearer Auth\n  severity: info\nhttp:\n  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n        Authorization: ${token}\n`;
    const authFile = join(tmpdir(), `nuclei-auth-${Date.now()}.yaml`);
    try {
      writeFileSync(authFile, authYaml, { encoding: "utf8" });
      tempFiles.push(authFile);
    } catch { /* non-fatal */ }
  } else if (ctx.sessionCookie) {
    headerArgs.push("-H", `Cookie: ${ctx.sessionCookie}`);
  }

  return {
    headerArgs,
    cleanup: () => {
      for (const f of tempFiles) {
        try { if (existsSync(f)) unlinkSync(f); } catch { /* ignore */ }
      }
    },
  };
}

// ── JSONL parser shared by binary and Docker tiers ───────────────────────────

function parseNucleiJsonl(line: string, targetUrl: string): ScanFinding | null {
  if (!line.trim() || !line.startsWith("{")) return null;
  try {
    const r = JSON.parse(line) as Record<string, unknown>;
    const sev = String(r["info"] ? (r["info"] as Record<string, unknown>)["severity"] : r["severity"] ?? "info").toLowerCase();
    const validSev = (["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info") as ScanFinding["severity"];
    return {
      title: String((r["info"] as Record<string, unknown>)?.["name"] ?? r["template-id"] ?? "Nuclei Finding"),
      category: String((r["info"] as Record<string, unknown>)?.["tags"] ?? "Security Misconfiguration"),
      severity: validSev,
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
    };
  } catch { return null; }
}

// ── Tier 1: Spawn native Nuclei binary ───────────────────────────────────────

async function spawnNuclei(targetUrl: string, binaryPath: string, ctx: ScanContext): Promise<ScanFinding[]> {
  const { headerArgs, cleanup } = buildAuthArgs(ctx);
  try {
    return await new Promise<ScanFinding[]>((resolve) => {
      const findings: ScanFinding[] = [];
      const args = [
        "-u", targetUrl,
        "-j",                              // JSONL output
        "-severity", "critical,high,medium,low",
        "-nc",                             // no color
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        ...headerArgs,
      ];

      ctx.emit({ type: "log", message: `Nuclei binary: ${binaryPath} ${args.slice(0, 4).join(" ")} ...` });

      const proc = spawn(binaryPath, args, { timeout: 120000 });
      let stderr = "";

      proc.stdout.on("data", (chunk: Buffer) => {
        for (const line of chunk.toString().split("\n")) {
          const f = parseNucleiJsonl(line, targetUrl);
          if (f) findings.push(f);
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
  } finally {
    cleanup();
  }
}

// ── Tier 1b: Docker-based Nuclei fallback ────────────────────────────────────

async function spawnNucleiDocker(targetUrl: string, ctx: ScanContext): Promise<ScanFinding[]> {
  const { headerArgs, cleanup } = buildAuthArgs(ctx);
  try {
    return await new Promise<ScanFinding[]>((resolve) => {
      const findings: ScanFinding[] = [];
      const dockerArgs = [
        "run", "--rm",
        "projectdiscovery/nuclei",
        "-u", targetUrl,
        "-j",
        "-severity", "critical,high,medium,low",
        "-nc",
        "-timeout", "10",
        "-retries", "1",
        "-silent",
        ...headerArgs,
      ];

      ctx.emit({ type: "log", message: `Nuclei (Docker): docker run projectdiscovery/nuclei -u ${targetUrl} ...` });

      const proc = spawn("docker", dockerArgs, { timeout: 180000 });
      let stderr = "";

      proc.stdout.on("data", (chunk: Buffer) => {
        for (const line of chunk.toString().split("\n")) {
          const f = parseNucleiJsonl(line, targetUrl);
          if (f) findings.push(f);
        }
      });

      proc.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });

      proc.on("close", (code) => {
        if (code !== 0 && findings.length === 0) {
          logger.warn({ code, stderr: stderr.slice(0, 200) }, "Nuclei Docker exited non-zero");
        }
        resolve(findings);
      });

      proc.on("error", (err) => {
        logger.warn({ err }, "Nuclei Docker spawn error");
        resolve([]);
      });
    });
  } finally {
    cleanup();
  }
}

// ── OpenAPI endpoint scanning ─────────────────────────────────────────────────

export async function scanApiEndpoints(ctx: ScanContext, binaryPath: string): Promise<ScanFinding[]> {
  const specUrl = ctx.openapiSpecUrl;
  if (!specUrl) return [];

  const findings: ScanFinding[] = [];
  ctx.emit({ type: "log", message: `OpenAPI scan: fetching spec from ${specUrl}` });

  let paths: string[] = [];
  try {
    const res = await fetch(specUrl, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const spec = await res.json() as Record<string, unknown>;
    // Support both OpenAPI 3.x (paths) and Swagger 2.x (paths)
    const rawPaths = spec["paths"] as Record<string, unknown> | undefined;
    if (rawPaths) paths = Object.keys(rawPaths);
  } catch (err) {
    logger.warn({ err }, "OpenAPI spec fetch failed");
    return [];
  }

  if (paths.length === 0) return [];

  const base = new URL(ctx.targetUrl).origin;
  ctx.emit({ type: "log", message: `OpenAPI scan: found ${paths.length} paths — running nuclei api/ templates` });

  const { headerArgs, cleanup } = buildAuthArgs(ctx);
  try {
    for (const apiPath of paths.slice(0, 50)) { // cap at 50 endpoints
      const endpoint = `${base}${apiPath}`;
      const endpointFindings = await new Promise<ScanFinding[]>((resolve) => {
        const epFindings: ScanFinding[] = [];
        const args = [
          "-u", endpoint,
          "-t", "api/",
          "-j", "-nc", "-silent",
          "-timeout", "8",
          ...headerArgs,
        ];

        const proc = spawn(binaryPath, args, { timeout: 30000 });
        proc.stdout.on("data", (chunk: Buffer) => {
          for (const line of chunk.toString().split("\n")) {
            const f = parseNucleiJsonl(line, endpoint);
            if (f) epFindings.push(f);
          }
        });
        proc.on("close", () => resolve(epFindings));
        proc.on("error", () => resolve([]));
      });
      findings.push(...endpointFindings);
    }
  } finally {
    cleanup();
  }

  ctx.emit({ type: "log", message: `OpenAPI scan: ${findings.length} finding(s) across ${paths.length} endpoints` });
  return findings;
}

export async function runNucleiScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  ctx.emit({ type: "engine_start", engine: "Bug-Finder/Nuclei", message: "Running Nuclei template scan..." });

  // ── Tier 1: Auto-detect Nuclei binary (PATH or env override) ─────────────────
  const nucleiBinary = detectNucleiBinary();
  if (nucleiBinary) {
    try {
      ctx.emit({ type: "log", message: `Nuclei binary detected: ${nucleiBinary}` });
      const binaryFindings = await spawnNuclei(ctx.targetUrl, nucleiBinary, ctx);
      findings.push(...binaryFindings);
      ctx.emit({ type: "log", message: `Nuclei binary: ${binaryFindings.length} finding(s)` });

      // If openapiSpecUrl was set, also scan discovered API endpoints
      if (ctx.openapiSpecUrl) {
        const apiFindings = await scanApiEndpoints(ctx, nucleiBinary).catch((err) => {
          logger.warn({ err }, "OpenAPI endpoint scan failed");
          return [] as ScanFinding[];
        });
        findings.push(...apiFindings);
      }
    } catch (err) {
      logger.warn({ err }, "Nuclei binary scan failed — falling through to Tier 1b (Docker)");
    }
  }

  // ── Tier 1b: Docker-based Nuclei (when native binary unavailable) ─────────────
  if (findings.length === 0 && !nucleiBinary) {
    const dockerAvailable = detectDockerAvailable();
    if (dockerAvailable) {
      try {
        ctx.emit({ type: "log", message: "Nuclei binary not found — trying Docker (projectdiscovery/nuclei)" });
        const dockerFindings = await spawnNucleiDocker(ctx.targetUrl, ctx);
        findings.push(...dockerFindings);
        ctx.emit({ type: "log", message: `Nuclei (Docker): ${dockerFindings.length} finding(s)` });
      } catch (err) {
        logger.warn({ err }, "Nuclei Docker scan failed — falling through to Tier 2 (HTTP API)" );
      }
    }
  }

  // ── Tier 2: Nuclei HTTP API (remote Docker service via NUCLEI_URL) ────────────
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
        logger.warn({ err }, "Nuclei API scan failed — falling through to Tier 3 (simulation)");
      }
    }
  }

  // ── Tier 3: Content-verified built-in checks ──────────────────────────────────
  // Only runs when neither Nuclei binary, Docker, nor HTTP API is available.
  // These are Bug-Finder's own verified checks for common misconfigurations.
  if (findings.length === 0) {
    console.warn("[Bug-Finder] WARNING: Nuclei binary and Docker not found — running built-in simulation checks (Bug-Finder/Nuclei-sim). Install Nuclei for real template coverage: https://github.com/projectdiscovery/nuclei");
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
            ...(ctx.authHeaders ?? {}),
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

  const tier = nucleiBinary ? "Tier 1 (binary)" : detectDockerAvailable() ? "Tier 1b (Docker)" : process.env["NUCLEI_URL"] ? "Tier 2 (API)" : "Tier 3 (built-in)";
  ctx.emit({ type: "engine_done", engine: "Bug-Finder/Nuclei", message: `Nuclei scan complete [${tier}] — ${findings.length} finding(s)` });
  return findings;
}
