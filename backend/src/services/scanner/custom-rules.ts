/**
 * Custom Scanner Rules — real execution engine.
 *
 * Rule schema (stored in `custom_scanner_rules` collection):
 * {
 *   name:              string          — display name
 *   description:       string          — what the rule checks
 *   category:          string          — finding category
 *   severity:          "critical"|"high"|"medium"|"low"|"info"
 *   cwe_id:            string          — e.g. "CWE-200"
 *   remediation:       string          — recommended fix text
 *   enabled:           boolean
 *
 *   // Request spec
 *   path_pattern:      string          — URL path, e.g. "/admin/export"
 *   method:            "GET"|"POST"|"PUT"|"DELETE"|"HEAD"|"OPTIONS"
 *   content_type:      string?         — defaults to "application/json" for POST/PUT
 *   payload_json:      object?         — JSON body (serialized to string)
 *   payload_form:      string?         — raw application/x-www-form-urlencoded body
 *   headers:           object?         — additional request headers
 *
 *   // Match conditions (all that are set must match = AND logic)
 *   expected_status:   number?         — exact HTTP status match
 *   status_range:      [number,number]?— inclusive range e.g. [200,299]
 *   body_contains:     string?         — literal substring match
 *   body_regex:        string?         — regex match against response body
 *   body_not_contains: string?         — must NOT be present (false-positive guard)
 *   header_contains:   { name, value }?— response header name+value check
 *   min_body_length:   number?         — body must be at least N bytes
 *
 *   fail_if_found:     boolean?        — invert: flag when conditions are NOT met
 * }
 */

import { col } from "../../lib/db";
import { logger } from "../../lib/logger";
import { ScanContext, ScanFinding } from "./types";

interface CustomRule {
  _id: unknown;
  name: string;
  description?: string;
  category?: string;
  severity?: string;
  cwe_id?: string;
  remediation?: string;
  enabled: boolean;
  path_pattern?: string;
  method?: string;
  content_type?: string;
  payload_json?: Record<string, unknown>;
  payload_form?: string;
  headers?: Record<string, string>;
  expected_status?: number;
  status_range?: [number, number];
  body_contains?: string;
  body_regex?: string;
  body_not_contains?: string;
  header_contains?: { name: string; value: string };
  min_body_length?: number;
  fail_if_found?: boolean;
}

function matchesRule(
  rule: CustomRule,
  status: number,
  body: string,
  resHeaders: Headers,
): boolean {
  let matched = true;

  if (rule.expected_status !== undefined) {
    matched = matched && status === rule.expected_status;
  }
  if (rule.status_range) {
    const [lo, hi] = rule.status_range;
    matched = matched && status >= lo && status <= hi;
  }
  if (rule.body_contains) {
    matched = matched && body.includes(rule.body_contains);
  }
  if (rule.body_regex) {
    try {
      matched = matched && new RegExp(rule.body_regex, "i").test(body);
    } catch {
      // Invalid regex — skip this condition
    }
  }
  if (rule.body_not_contains) {
    matched = matched && !body.includes(rule.body_not_contains);
  }
  if (rule.header_contains) {
    const hv = resHeaders.get(rule.header_contains.name) ?? "";
    matched = matched && hv.toLowerCase().includes(rule.header_contains.value.toLowerCase());
  }
  if (rule.min_body_length !== undefined) {
    matched = matched && body.length >= rule.min_body_length;
  }

  return rule.fail_if_found ? !matched : matched;
}

export async function runCustomRules(targetUrl: string, ctx?: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  try {
    const rawRules = await col("custom_scanner_rules").find({ enabled: true }).toArray() as Array<Record<string, unknown>>;
    const rules = rawRules as unknown as CustomRule[];

    if (rules.length === 0) return findings;
    ctx?.emit({ type: "engine_start", engine: "Bug-Finder/CustomRules", message: `Running ${rules.length} custom rule(s)` });

    for (const rule of rules) {
      const pathPattern = String(rule.path_pattern ?? "").trim();
      if (!pathPattern) continue;

      const url = targetUrl.replace(/\/$/, "") + (pathPattern.startsWith("/") ? pathPattern : `/${pathPattern}`);
      const method = (rule.method ?? "GET").toUpperCase();

      try {
        const reqHeaders: Record<string, string> = {
          Accept: "application/json, text/html, */*",
          ...(rule.headers ?? {}),
        };

        // Merge auth headers from scan context if available
        if (ctx?.authHeaders) {
          Object.assign(reqHeaders, ctx.authHeaders);
        }

        let body: string | undefined;
        if (rule.payload_json && ["POST", "PUT", "PATCH"].includes(method)) {
          reqHeaders["Content-Type"] = rule.content_type ?? "application/json";
          body = JSON.stringify(rule.payload_json);
        } else if (rule.payload_form && ["POST", "PUT", "PATCH"].includes(method)) {
          reqHeaders["Content-Type"] = "application/x-www-form-urlencoded";
          body = rule.payload_form;
        }

        const fetchOpts: RequestInit = {
          method,
          headers: reqHeaders,
          signal: AbortSignal.timeout(10000),
          redirect: "follow",
          ...(body !== undefined ? { body } : {}),
        };

        const response = await fetch(url, fetchOpts);
        const responseBody = await response.text().catch(() => "");

        const isVuln = matchesRule(rule, response.status, responseBody, response.headers);

        if (isVuln) {
          const sev = (["critical", "high", "medium", "low", "info"].includes(rule.severity ?? "")
            ? rule.severity
            : "medium") as ScanFinding["severity"];

          const evidenceParts = [
            `${method} ${url}`,
            `HTTP ${response.status}`,
            rule.body_contains ? `Body contains: "${rule.body_contains}"` : "",
            rule.body_regex ? `Body matches regex: /${rule.body_regex}/i` : "",
            rule.header_contains ? `Response header ${rule.header_contains.name}: ${response.headers.get(rule.header_contains.name) ?? "(not present)"}` : "",
            ``,
            `Response body (first 400 bytes):`,
            responseBody.slice(0, 400),
          ].filter(Boolean).join("\n");

          findings.push({
            title: `[Custom Rule] ${rule.name}`,
            category: rule.category ?? "Custom",
            severity: sev,
            endpoint: url,
            description: rule.description ?? `Custom rule "${rule.name}" matched.`,
            evidence: evidenceParts,
            recommended_fix: rule.remediation ?? "Review and remediate according to your security policy.",
            cvss_score: { critical: 9.0, high: 7.5, medium: 5.0, low: 3.0, info: 1.0 }[sev] ?? 5.0,
            cwe_id: rule.cwe_id ?? "N/A",
            scanner_name: `Bug-Finder/CustomRule-${rule.name.toLowerCase().replace(/\s+/g, "-").slice(0, 30)}`,
            scanner_family: "custom",
            confidence: 0.85,
          });

          ctx?.emit({ type: "log", message: `  [Custom Rule MATCHED] "${rule.name}" at ${url}` });

          // Increment usage counter
          await col("custom_scanner_rules").updateOne(
            { _id: rule._id } as Record<string, unknown>,
            { $inc: { usage_count: 1 }, $set: { last_matched_at: new Date() } } as Record<string, unknown>
          );
        } else {
          ctx?.emit({ type: "log", message: `  [Custom Rule] "${rule.name}" — no match at ${url} (HTTP ${response.status})` });
        }
      } catch (err) {
        ctx?.emit({ type: "log", message: `  [Custom Rule] "${rule.name}" — error: ${err instanceof Error ? err.message : String(err)}` });
      }
    }

    ctx?.emit({ type: "engine_done", engine: "Bug-Finder/CustomRules", message: `Custom rules complete — ${findings.length} finding(s)` });
  } catch (err) {
    logger.warn({ err }, "Custom rules execution error");
  }
  return findings;
}
