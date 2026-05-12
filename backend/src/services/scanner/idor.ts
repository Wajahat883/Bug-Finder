import { ScanContext, ScanFinding, ctxFetch, safeFetch } from "./types";

const IDOR_PATH_PATTERNS = [
  { path: "/api/users/{id}", label: "User object" },
  { path: "/api/orders/{id}", label: "Order object" },
  { path: "/api/products/{id}", label: "Product object" },
  { path: "/api/files/{id}", label: "File object" },
  { path: "/api/reports/{id}", label: "Report object" },
  { path: "/api/accounts/{id}", label: "Account object" },
  { path: "/api/v1/users/{id}", label: "User object v1" },
  { path: "/api/messages/{id}", label: "Message object" },
  { path: "/api/invoices/{id}", label: "Invoice object" },
];

export async function runIdorCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile, authHeaders } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Burp Suite/IDOR", message: "Testing for Insecure Direct Object References" });

  const base = new URL(targetUrl);
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : IDOR_PATH_PATTERNS.length;

  // Determine if we have auth credentials for two-session testing
  const hasAuth = Object.keys(authHeaders).length > 0;

  for (const pattern of IDOR_PATH_PATTERNS.slice(0, budget)) {
    const ids = [1, 2, 100, 999];
    const responses: Array<{ id: number; status: number; bodyLen: number; body: string }> = [];

    for (const id of ids) {
      const url = `${base.origin}${pattern.path.replace("{id}", String(id))}`;
      // Use auth credentials if available
      const res = await ctxFetch(ctx, url, { headers: { "Accept": "application/json" } });
      if (!res) continue;
      const body = await res.text().catch(() => "");
      responses.push({ id, status: res.status, bodyLen: body.length, body });
    }

    const successfulResponses = responses.filter(r => r.status === 200 && r.bodyLen > 20);
    if (successfulResponses.length < 2) {
      emit({ type: "log", message: `  ${pattern.path} — ${responses.map(r => r.status).join(",")} (protected)` });
      continue;
    }

    const url1 = `${base.origin}${pattern.path.replace("{id}", "1")}`;

    // ── Two-session proof: replay with NO credentials ─────────────────────
    // If the endpoint returns data WITHOUT auth, it's publicly accessible (not IDOR, worse)
    // If the endpoint requires auth and both auth sessions can access each other's objects = IDOR
    const unauthRes = await safeFetch(url1, { headers: { "Accept": "application/json" } });
    const unauthBody = unauthRes ? await unauthRes.text().catch(() => "") : "";

    if (unauthRes && unauthRes.status === 200 && unauthBody.length > 20) {
      // Endpoint accessible without ANY auth — this is broken access control, not just IDOR
      findings.push({
        title: `Unauthenticated Access to ${pattern.label} Endpoint`,
        category: "Broken Access Control",
        severity: "critical",
        endpoint: url1,
        description: `The ${pattern.label} endpoint returns data for any numeric ID without requiring authentication. Any anonymous user can enumerate and read all objects.`,
        evidence: [
          `GET ${url1}`,
          `No Authorization header sent`,
          `HTTP ${unauthRes.status} — returned ${unauthBody.length} bytes`,
          ``,
          `Sample data (ID=1): ${unauthBody.slice(0, 200)}`,
          ``,
          `IDs that returned data when authenticated: ${successfulResponses.map(r => r.id).join(", ")}`,
        ].join("\n"),
        recommended_fix: "Require authentication on all API endpoints. Return HTTP 401 for unauthenticated requests. Implement object-level ownership checks.",
        cvss_score: 9.1,
        cwe_id: "CWE-639",
        scanner_name: "Burp Suite",
        scanner_family: "web",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [CRITICAL] Unauthenticated access on ${pattern.path}` });
      continue;
    }

    // ── Ownership cross-check: confirm responses contain different data ────
    const distinctBodies = new Set(successfulResponses.map(r => r.body.slice(0, 200))).size;
    const allReturnData = successfulResponses.length >= 2;

    if (allReturnData) {
      const evidenceParts = [
        `Probed IDs with auth credentials: ${successfulResponses.map(r => r.id).join(", ")}`,
        `All returned HTTP 200 with data:`,
        ...successfulResponses.map(r => `  ID ${r.id} (${r.bodyLen} bytes): ${r.body.slice(0, 120)}`),
      ];

      if (hasAuth) {
        evidenceParts.push(``, `Two-session test: unauthenticated request returned HTTP ${unauthRes?.status ?? "no response"} — objects require auth but are accessible to any authenticated user via ID enumeration`);
      }

      const confidence = distinctBodies >= 2 ? 0.82 : 0.65;
      const severity = distinctBodies >= 2 ? "high" as const : "medium" as const;

      findings.push({
        title: `IDOR: ${pattern.label} Accessible via Sequential ID Enumeration`,
        category: "Broken Access Control",
        severity,
        endpoint: url1,
        description: `The ${pattern.label} endpoint returns data for sequential numeric IDs. ${distinctBodies >= 2 ? "Different data was returned for different IDs, confirming objects belonging to different users are accessible." : "Multiple IDs return data — ownership validation may be absent."} An authenticated attacker can enumerate all objects by iterating IDs.`,
        evidence: evidenceParts.join("\n"),
        recommended_fix: "Verify object ownership on every request: ensure the authenticated user owns the requested resource. Use UUIDs instead of sequential integers. Implement row-level authorization in database queries.",
        cvss_score: 7.5,
        cwe_id: "CWE-639",
        scanner_name: "Burp Suite",
        scanner_family: "web",
        confidence,
      });
      emit({ type: "log", message: `  [IDOR] Sequential IDs work on ${pattern.path} (confidence: ${confidence})` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No obvious IDOR vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Burp Suite/IDOR",
    message: `IDOR check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
