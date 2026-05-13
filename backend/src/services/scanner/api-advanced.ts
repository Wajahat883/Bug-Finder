import { ScanContext, ScanFinding, ctxFetch } from "./types";

const API_PREFIXES = ["/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3", "/api/1.0", "/api/2.0"];
const RESOURCE_PATHS = ["/users", "/user", "/profile", "/account", "/admin", "/settings", "/roles"];
const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT"];
const MASS_ASSIGN_FIELDS = [
  { field: "role", value: "admin" },
  { field: "is_admin", value: true },
  { field: "admin", value: true },
  { field: "superuser", value: true },
  { field: "verified", value: true },
  { field: "active", value: true },
  { field: "credit", value: 99999 },
  { field: "balance", value: 99999 },
  { field: "price", value: 0.01 },
  { field: "discount", value: 100 },
];

export async function runApiAdvancedCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/API-Advanced", message: "Testing API versioning, mass assignment, and method tampering" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const seen = new Set<string>();

  // 1. API Version Abuse — try older API versions
  emit({ type: "log", message: "Testing API version abuse..." });
  const v1Endpoints: string[] = [];
  for (const prefix of API_PREFIXES) {
    for (const resource of RESOURCE_PATHS.slice(0, 3)) {
      const url = `${base}${prefix}${resource}`;
      const r = await ctxFetch(ctx, url, { redirect: "follow" });
      if (!r) continue;
      if (r.status !== 404 && r.status !== 405) {
        v1Endpoints.push(url);
        emit({ type: "log", message: `  API version endpoint found: ${url} (${r.status})` });

        if (r.status === 200) {
          const body = await r.text().catch(() => "");
          // Confirm the response contains actual user/resource data — not just any JSON array
          const dataFieldHints = ["email", "username", "user_id", "userId", "id", "name", "phone", "address", "role", "created_at", "token"];
          const hasUserData = dataFieldHints.some(field => body.includes(`"${field}"`));
          const hasNoAuth = !r.headers.get("www-authenticate") && r.status === 200 && hasUserData;
          if (hasNoAuth && !seen.has(`version:${url}`)) {
            seen.add(`version:${url}`);
            findings.push({
              title: `API Version Abuse — Unauthenticated Access via ${prefix}`,
              category: "API Security",
              severity: "high",
              endpoint: url,
              description: `An older API version at ${url} returns data without requiring authentication. Older API versions often lack the security controls implemented in newer versions and may expose sensitive data or functionality.`,
              evidence: `GET ${url}\nHTTP ${r.status}\nNo authentication required\nResponse preview: ${body.slice(0, 300)}`,
              recommended_fix: "Enforce authentication and authorization on all API versions. Decommission old API versions. Apply the same security controls to every version.",
              cvss_score: 7.5,
              cwe_id: "CWE-285",
              scanner_name: "Bug-Finder/API",
              scanner_family: "api",
              confidence: 0.8,
            });
          }
        }
      }
    }
    if (v1Endpoints.length >= budget) break;
  }

  // 2. Mass Assignment — send privileged fields in POST/PUT
  emit({ type: "log", message: "Testing mass assignment vulnerabilities..." });
  const testEndpoints = [
    ...discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 4),
    `${base}/api/users`, `${base}/api/profile`, `${base}/api/account`,
  ];

  for (const endpoint of testEndpoints.slice(0, budget)) {
    for (const field of MASS_ASSIGN_FIELDS.slice(0, 4)) {
      const body = { [field.field]: field.value, name: "test", email: `mass_${Date.now()}@test.com` };
      const r = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r) continue;

      const respBody = await r.text().catch(() => "");
      const fieldStr = String(field.value);
      // Both field name AND injected value must appear in response — prevents false positives
      // from error messages that mention the field name but reject the value
      const fieldReflected = respBody.includes(`"${field.field}"`) || respBody.includes(`'${field.field}'`);
      const valueReflected = respBody.includes(`"${fieldStr}"`) || respBody.includes(`:${fieldStr}`) || respBody.includes(`:${fieldStr},`) || respBody === fieldStr || respBody.includes(`"${fieldStr}"`);
      const noRejectionKeyword = !respBody.toLowerCase().includes("cannot") && !respBody.toLowerCase().includes("not allowed") && !respBody.toLowerCase().includes("forbidden") && !respBody.toLowerCase().includes("invalid");
      if ((r.status === 200 || r.status === 201) && fieldReflected && valueReflected && noRejectionKeyword && !seen.has(`mass:${endpoint}:${field.field}`)) {
        // ── Persistence verification: GET the created resource and confirm field is stored ──
        // Reflection in the POST response alone is weak — the server may just echo
        // back what we sent without storing it. We extract the ID from the POST
        // response and GET the resource to see if the privileged field persists.
        let persisted = false;
        let persistEvidence = "GET verification: resource ID not extractable from POST response";
        let confidence = 0.72;

        const idMatch = respBody.match(/"id"\s*:\s*"?([A-Za-z0-9_-]{1,40})"?/);
        if (idMatch?.[1]) {
          const resourceId = idMatch[1];
          const getUrl = `${endpoint}/${resourceId}`;
          const getRes = await ctxFetch(ctx, getUrl, { headers: { Accept: "application/json" } });
          if (getRes && getRes.status === 200) {
            const getBody = await getRes.text().catch(() => "");
            const fieldInGet = getBody.includes(`"${field.field}"`) || getBody.includes(`'${field.field}'`);
            const valueInGet = getBody.includes(`"${fieldStr}"`) || getBody.includes(`:${fieldStr}`) || getBody.includes(`:${fieldStr},`);
            persisted = fieldInGet && valueInGet;
            persistEvidence = [
              `GET ${getUrl} → HTTP ${getRes.status}`,
              `Field "${field.field}" in GET response: ${fieldInGet}`,
              `Value "${fieldStr}" in GET response: ${valueInGet}`,
              `PERSISTED: ${persisted}`,
              `GET body: ${getBody.slice(0, 300)}`,
            ].join("\n");
            confidence = persisted ? 0.95 : 0.65;
          }
        }

        seen.add(`mass:${endpoint}:${field.field}`);
        findings.push({
          title: `Mass Assignment — Privileged Field "${field.field}" ${persisted ? "PERSISTED" : "Accepted (persistence unconfirmed)"}`,
          category: "API Security",
          severity: persisted ? "critical" : "high",
          endpoint,
          description: persisted
            ? `The API endpoint accepted a POST request containing the privileged field "${field.field}=${fieldStr}" AND the value persisted in the database — confirmed via a subsequent GET request. An attacker can escalate privileges or manipulate business-critical data.`
            : `The API endpoint accepted a POST request containing the privileged field "${field.field}=${fieldStr}" and reflected it in the response. Persistence was not confirmed (resource ID not extractable). Manual verification is recommended.`,
          evidence: [
            `POST ${endpoint}`,
            `Payload: ${JSON.stringify(body)}`,
            `HTTP ${r.status}`,
            `Field "${field.field}" in POST response: ${fieldReflected}`,
            `Value "${fieldStr}" in POST response: ${valueReflected}`,
            `POST response: ${respBody.slice(0, 300)}`,
            ``,
            persistEvidence,
          ].join("\n"),
          recommended_fix: "Use an allowlist (whitelist) of permitted fields. Never blindly bind all request body fields to your data model. Use DTOs/schemas to explicitly permit only safe fields.",
          cvss_score: persisted ? 9.1 : 7.5,
          cwe_id: "CWE-915",
          scanner_name: "Bug-Finder/API",
          scanner_family: "api",
          confidence,
        });
        emit({ type: "log", message: `  [Mass Assign] ${field.field}=${fieldStr} at ${endpoint} — persisted=${persisted}` });
        break;
      }
    }
  }

  // 3. HTTP Method Tampering
  emit({ type: "log", message: "Testing HTTP method tampering..." });
  const methodTestEndpoints = [
    targetUrl, `${base}/api/users`, `${base}/api/settings`, `${base}/admin`,
    ...discoveredEndpoints.slice(0, 3),
  ];

  for (const endpoint of methodTestEndpoints.slice(0, budget)) {
    const methodResults: Record<string, number> = {};

    for (const method of ["GET", "PUT", "DELETE", "TRACE", "PATCH"]) {
      const r = await ctxFetch(ctx, endpoint, { method });
      if (r) methodResults[method] = r.status;
    }

    // TRACE method should always be disabled (CVE for cross-site tracing)
    if (methodResults["TRACE"] && methodResults["TRACE"] !== 405 && methodResults["TRACE"] !== 404 && !seen.has(`trace:${endpoint}`)) {
      seen.add(`trace:${endpoint}`);
      findings.push({
        title: "HTTP TRACE Method Enabled",
        category: "API Security",
        severity: "medium",
        endpoint,
        description: "The HTTP TRACE method is enabled. TRACE can be exploited in Cross-Site Tracing (XST) attacks to steal cookies and authentication headers by reading the server's echo of the request.",
        evidence: `TRACE ${endpoint}\nHTTP ${methodResults["TRACE"]} — method not rejected`,
        recommended_fix: "Disable TRACE method in your web server configuration. In Apache: TraceEnable Off. In Nginx: if ($request_method = TRACE) { return 405; }",
        cvss_score: 5.4,
        cwe_id: "CWE-16",
        scanner_name: "Bug-Finder/API",
        scanner_family: "api",
        confidence: 0.9,
      });
      emit({ type: "log", message: `  HTTP TRACE enabled at ${endpoint}` });
    }

    // DELETE returning non-401/403 on protected resource
    if (methodResults["DELETE"] === 200 || methodResults["DELETE"] === 204) {
      if (!seen.has(`delete:${endpoint}`)) {
        seen.add(`delete:${endpoint}`);
        findings.push({
          title: "HTTP DELETE Method Accepted Without Authentication",
          category: "API Security",
          severity: "high",
          endpoint,
          description: `The HTTP DELETE method succeeded (${methodResults["DELETE"]}) without authentication. An unauthenticated attacker may be able to delete resources.`,
          evidence: `DELETE ${endpoint}\nHTTP ${methodResults["DELETE"]} — deletion succeeded without auth token`,
          recommended_fix: "Require authentication and authorization for all DELETE requests. Validate that the requesting user owns the resource.",
          cvss_score: 8.1,
          cwe_id: "CWE-306",
          scanner_name: "Bug-Finder/API",
          scanner_family: "api",
          confidence: 0.8,
        });
        emit({ type: "log", message: `  DELETE without auth at ${endpoint} (${methodResults["DELETE"]})` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No API version abuse, mass assignment, or method tampering issues found" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/API-Advanced", message: `API advanced check complete — ${findings.length} finding(s)` });
  return findings;
}
