import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { ScanFinding } from "../services/scanner/types";

const router = Router();

interface ScannerRule {
  name: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD";
  pathPattern: string;
  headerCheck?: string;
  bodyCheck?: string;
  payload?: string;
  expectedStatus?: number;
  expectedResponse?: string;
  failIfFound?: boolean;
  cwe_id?: string;
  description: string;
  remediation: string;
}

// GET /scanner/rules — List all custom rules
router.get("/scanner/rules", async (_req, res) => {
  try {
    const rules = await col("custom_scanner_rules").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(rules.map((r) => ({
      id: String(r["_id"]),
      name: r["name"],
      category: r["category"],
      severity: r["severity"],
      method: r["method"],
      pathPattern: r["path_pattern"],
      enabled: r["enabled"] ?? true,
      usage_count: r["usage_count"] ?? 0,
      created_at: r["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List rules error");
    res.status(500).json({ error: "Failed to list rules" });
  }
});

// GET /scanner/rules/:id — Get single rule
router.get("/scanner/rules/:id", async (req, res) => {
  try {
    const rule = await col("custom_scanner_rules").findOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!rule) return res.status(404).json({ error: "Rule not found" });
    res.json({ ...rule, id: String(rule["_id"]) });
  } catch (err) {
    res.status(500).json({ error: "Failed to get rule" });
  }
});

// POST /scanner/rules — Create new custom rule
router.post("/scanner/rules", async (req, res) => {
  try {
    const rule = req.body as ScannerRule;
    if (!rule.name || !rule.method || !rule.pathPattern) {
      return res.status(400).json({ error: "name, method, and pathPattern are required" });
    }
    const insert = await col("custom_scanner_rules").insertOne({
      name: rule.name,
      category: rule.category ?? "Custom",
      severity: rule.severity ?? "medium",
      method: rule.method,
      path_pattern: rule.pathPattern,
      header_check: rule.headerCheck ?? null,
      body_check: rule.bodyCheck ?? null,
      payload: rule.payload ?? null,
      expected_status: rule.expectedStatus ?? null,
      expected_response: rule.expectedResponse ?? null,
      fail_if_found: rule.failIfFound ?? false,
      cwe_id: rule.cwe_id ?? null,
      description: rule.description ?? "",
      remediation: rule.remediation ?? "",
      enabled: true,
      usage_count: 0,
      created_at: new Date(),
      updated_at: new Date(),
    });
    res.status(201).json({ id: String(insert.insertedId), ...rule });
  } catch (err) {
    logger.error({ err }, "Create rule error");
    res.status(500).json({ error: "Failed to create rule" });
  }
});

// PATCH /scanner/rules/:id — Update rule
router.patch("/scanner/rules/:id", async (req, res) => {
  try {
    const updates = req.body as Partial<ScannerRule & { enabled: boolean }>;
    const set: Record<string, unknown> = { updated_at: new Date() };
    if (updates.name) set["name"] = updates.name;
    if (updates.severity) set["severity"] = updates.severity;
    if (updates.method) set["method"] = updates.method;
    if (updates.pathPattern) set["path_pattern"] = updates.pathPattern;
    if (updates.payload !== undefined) set["payload"] = updates.payload;
    if (updates.expectedStatus !== undefined) set["expected_status"] = updates.expectedStatus;
    if (updates.description) set["description"] = updates.description;
    if (updates.remediation) set["remediation"] = updates.remediation;
    if (updates.enabled !== undefined) set["enabled"] = updates.enabled;
    await col("custom_scanner_rules").updateOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>, { $set: set });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Update rule error");
    res.status(500).json({ error: "Failed to update rule" });
  }
});

// DELETE /scanner/rules/:id — Delete rule
router.delete("/scanner/rules/:id", async (req, res) => {
  try {
    await col("custom_scanner_rules").deleteOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete rule" });
  }
});

// POST /scanner/rules/test — Test a rule against a target without saving findings
router.post("/scanner/rules/test", async (req, res) => {
  try {
    const { rule, targetUrl } = req.body as { rule: ScannerRule; targetUrl: string };
    if (!rule || !targetUrl) return res.status(400).json({ error: "rule and targetUrl required" });

    const findings: ScanFinding[] = [];
    const url = targetUrl.replace(/\/$/, "") + (rule.pathPattern.startsWith("/") ? rule.pathPattern : "/" + rule.pathPattern);

    try {
      const fetchOpts: RequestInit = { method: rule.method, signal: AbortSignal.timeout(8000) };
      if (rule.payload) {
        fetchOpts.headers = { "Content-Type": "application/x-www-form-urlencoded" };
        fetchOpts.body = rule.payload;
      }
      const response = await fetch(url, fetchOpts);
      const body = await response.text().catch(() => "");

      const statusMatch = rule.expectedStatus ? response.status === rule.expectedStatus : false;
      const responseMatch = rule.expectedResponse ? body.includes(rule.expectedResponse) : true;
      const headerMatch = rule.headerCheck ? (response.headers.get(rule.headerCheck.split(":")[0]?.trim() ?? "") ?? "").includes(rule.headerCheck.split(":")[1]?.trim() ?? "") : true;

      const isVulnerable = rule.failIfFound
        ? !statusMatch && !responseMatch
        : statusMatch || responseMatch;

      // Only flag if header condition also matches
      const shouldFlag = isVulnerable && headerMatch;

      if (shouldFlag) {
        findings.push({
          title: `[Custom Rule] ${rule.name}`,
          category: rule.category ?? "Custom",
          severity: rule.severity ?? "medium",
          endpoint: url,
          description: rule.description || `Custom scanner rule detected: ${rule.name}. Status: ${response.status}`,
          evidence: `Status: ${response.status}, Body snippet: ${body.slice(0, 200)}`,
          recommended_fix: rule.remediation || "Review and fix based on rule description.",
          cvss_score: rule.severity === "critical" ? 9.0 : rule.severity === "high" ? 7.5 : rule.severity === "medium" ? 5.0 : rule.severity === "low" ? 3.0 : 1.0,
          cwe_id: rule.cwe_id ?? "N/A",
          scanner_name: `custom-rule-${rule.name.toLowerCase().replace(/\s+/g, "-")}`,
          scanner_family: "custom",
          confidence: 0.85,
        });
      }
    } catch { /* target unreachable — not a finding */ }

    res.json({ tested: true, findings, status: findings.length > 0 ? "vulnerable" : "clean" });
  } catch (err) {
    logger.error({ err }, "Test rule error");
    res.status(500).json({ error: "Rule test failed" });
  }
});

// Execute custom rules for a target (used by scanner pipeline)
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

export default router;
