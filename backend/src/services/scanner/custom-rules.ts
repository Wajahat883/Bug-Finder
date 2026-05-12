import { col } from "../../lib/db";
import { logger } from "../../lib/logger";
import { ScanFinding } from "./types";

export async function runCustomRules(targetUrl: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  try {
    const rules = await col("custom_scanner_rules").find({ enabled: true }).toArray() as Array<Record<string, unknown>>;
    for (const r of rules) {
      const url = targetUrl.replace(/\/$/, "") + (String(r["path_pattern"] ?? "").startsWith("/") ? String(r["path_pattern"]) : "/" + String(r["path_pattern"]));
      try {
        const fetchOpts: RequestInit = { method: String(r["method"] ?? "GET"), signal: AbortSignal.timeout(8000) };
        if (r["payload"]) { fetchOpts.headers = { "Content-Type": "application/x-www-form-urlencoded" }; fetchOpts.body = String(r["payload"]); }
        const response = await fetch(url, fetchOpts);
        const body = await response.text().catch(() => "");
        const statusMatch = r["expected_status"] ? response.status === Number(r["expected_status"]) : false;
        const responseMatch = r["expected_response"] ? body.includes(String(r["expected_response"])) : true;
        const isVuln = r["fail_if_found"] ? !statusMatch && !responseMatch : statusMatch || responseMatch;
        if (isVuln) {
          findings.push({
            title: `[Custom Rule] ${String(r["name"])}`,
            category: String(r["category"] ?? "Custom"),
            severity: String(r["severity"] ?? "medium") as ScanFinding["severity"],
            endpoint: url,
            description: String(r["description"] ?? ""),
            evidence: `Status: ${response.status}, Body: ${body.slice(0, 200)}`,
            recommended_fix: String(r["remediation"] ?? ""),
            cvss_score: { critical: 9, high: 7.5, medium: 5, low: 3, info: 1 }[String(r["severity"] ?? "medium")] ?? 5,
            cwe_id: String(r["cwe_id"] ?? "N/A"),
            scanner_name: `custom-rule-${String(r["name"]).toLowerCase().replace(/\s+/g, "-")}`,
            scanner_family: "custom",
            confidence: 0.8,
          });
          await col("custom_scanner_rules").updateOne(
            { _id: r["_id"] } as Record<string, unknown>,
            { $inc: { usage_count: 1 } }
          );
        }
      } catch { /* skip unreachable */ }
    }
  } catch (err) {
    logger.warn({ err }, "Custom rules execution error");
  }
  return findings;
}
