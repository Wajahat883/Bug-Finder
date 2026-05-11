import { ScanContext, ScanFinding } from "./types";
import { logger } from "../../lib/logger";

// Nuclei integration — calls Nuclei via HTTP API if available, otherwise runs simulated template checks
export async function runNucleiScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  ctx.emit({ type: "engine_start", engine: "Nuclei", message: "Running Nuclei template scan..." });

  const nucleiUrl = process.env["NUCLEI_URL"];

  if (nucleiUrl) {
    // Real Nuclei API mode
    try {
      const resp = await fetch(`${nucleiUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: ctx.targetUrl, templates: ["cves", "exposures", "misconfiguration", "vulnerabilities"], severity: ["critical", "high", "medium"] }),
        signal: AbortSignal.timeout(120000),
      });
      if (resp.ok) {
        const results = await resp.json() as Array<Record<string,unknown>>;
        for (const r of results) {
          findings.push({
            title: String(r["name"] ?? r["template-id"] ?? "Nuclei Finding"),
            category: String(r["type"] ?? "Security Misconfiguration"),
            severity: (["critical","high","medium","low"].includes(String(r["severity"])) ? String(r["severity"]) : "medium") as any,
            endpoint: String(r["matched-at"] ?? ctx.targetUrl),
            description: String(r["description"] ?? r["info"]?.description ?? "Found by Nuclei template engine"),
            evidence: String(r["extracted-results"] ?? r["matched-at"] ?? ""),
            recommended_fix: String(r["remediation"] ?? r["info"]?.remediation ?? "Apply security patches and follow vendor recommendations"),
            cvss_score: r["cvss-score"] ? Number(r["cvss-score"]) : 5.0,
            cwe_id: r["cwe-id"] ? String(r["cwe-id"]) : "CWE-200",
            scanner_name: `Nuclei/${r["template-id"] ?? "template"}`,
            scanner_family: "Nuclei",
            confidence: 85,
          });
        }
      }
    } catch(err) {
      logger.warn({ err }, "Nuclei API scan failed — running template simulations");
    }
  }

  // Template-based checks that simulate common Nuclei templates
  const templates = [
    { id: "exposed-git", path: "/.git/config", title: "Exposed Git Repository", sev: "high", cwe: "CWE-538", desc: "Git repository files are publicly accessible, potentially exposing source code and secrets." },
    { id: "exposed-env", path: "/.env", title: "Exposed Environment File", sev: "critical", cwe: "CWE-538", desc: "Environment configuration file is publicly accessible, potentially exposing API keys and credentials." },
    { id: "exposed-phpinfo", path: "/phpinfo.php", title: "PHP Info Page Exposed", sev: "medium", cwe: "CWE-200", desc: "PHP configuration information is publicly accessible." },
    { id: "exposed-wp-config", path: "/wp-config.php.bak", title: "WordPress Config Backup Exposed", sev: "critical", cwe: "CWE-538", desc: "WordPress configuration backup may contain database credentials." },
    { id: "exposed-swagger", path: "/swagger.json", title: "API Documentation Exposed", sev: "low", cwe: "CWE-200", desc: "API documentation is publicly accessible without authentication." },
    { id: "exposed-actuator", path: "/actuator/env", title: "Spring Boot Actuator Exposed", sev: "high", cwe: "CWE-200", desc: "Spring Boot actuator endpoints are publicly accessible." },
    { id: "exposed-graphql", path: "/graphql", title: "GraphQL Endpoint Detected", sev: "info", cwe: "CWE-200", desc: "GraphQL endpoint detected — check for introspection and field exposure." },
    { id: "exposed-metrics", path: "/metrics", title: "Prometheus Metrics Exposed", sev: "medium", cwe: "CWE-200", desc: "Application metrics endpoint is publicly accessible." },
  ];

  const base = new URL(ctx.targetUrl);

  for (const tpl of templates) {
    if (ctx.abortSignal?.aborted) break;
    try {
      const url = `${base.protocol}//${base.host}${tpl.path}`;
      const resp = await fetch(url, { method: "GET", signal: AbortSignal.timeout(6000), redirect: "manual" }).catch(() => null);
      if (resp && resp.status === 200) {
        const body = await resp.text().catch(() => "");
        if (body.length > 0) {
          findings.push({
            title: tpl.title,
            category: "Security Misconfiguration",
            severity: tpl.sev as any,
            endpoint: url,
            description: tpl.desc,
            evidence: `HTTP 200 response (${body.length} bytes): ${body.slice(0, 200)}`,
            recommended_fix: "Restrict access to this path via web server configuration. Add authentication or remove the file.",
            cvss_score: tpl.sev === "critical" ? 9.1 : tpl.sev === "high" ? 7.5 : tpl.sev === "medium" ? 5.3 : 3.1,
            cwe_id: tpl.cwe,
            scanner_name: `Nuclei/${tpl.id}`,
            scanner_family: "Nuclei",
            confidence: 90,
          });
          ctx.emit({ type: "finding", finding: findings[findings.length - 1] });
        }
      }
    } catch { /* skip */ }
  }

  ctx.emit({ type: "engine_done", engine: "Nuclei", message: `Nuclei scan complete. ${findings.length} finding(s).` });
  return findings;
}
