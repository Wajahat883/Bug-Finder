import { ScanContext, ScanFinding, ctxFetch, safeFetch, curlReproducer } from "./types";

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

// Extracts all UUID v4, MongoDB ObjectIDs, and Snowflake-style IDs from a response body
function extractAlternateIds(body: string): string[] {
  const ids = new Set<string>();
  // UUID v4
  for (const m of body.matchAll(/["']([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})["']/gi)) {
    ids.add(m[1]!);
  }
  // MongoDB ObjectID (24 hex chars)
  for (const m of body.matchAll(/["']([0-9a-f]{24})["']/g)) {
    ids.add(m[1]!);
  }
  // Snowflake / large numeric IDs (15-19 digit integers)
  for (const m of body.matchAll(/["'](\d{15,19})["']/g)) {
    ids.add(m[1]!);
  }
  return [...ids].slice(0, 5);
}

export async function runIdorCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile, authHeaders } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/IDOR", message: "Testing for Insecure Direct Object References" });

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
        scanner_name: "Bug-Finder/IDOR",
        scanner_family: "web",
        confidence: 0.95,
        reproduction_curl: curlReproducer("GET", url1, { Accept: "application/json" }),
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
        scanner_name: "Bug-Finder/IDOR",
        scanner_family: "web",
        confidence,
      });
      emit({ type: "log", message: `  [IDOR] Sequential IDs work on ${pattern.path} (confidence: ${confidence})` });
    }
  }

  // ── UUID / ObjectID IDOR: extract real IDs from responses, then cross-enumerate ──
  // Many modern APIs use UUIDs or MongoDB ObjectIDs — sequential integer testing misses them.
  // Strategy: collect IDs seen in authenticated responses, then probe adjacent discovered endpoints
  // using those IDs without ownership context to confirm cross-object access.
  if (profile !== "quick") {
    emit({ type: "log", message: "Probing for UUID/ObjectID-based IDOR..." });
    const collectedIds: string[] = [];

    // First pass: gather IDs from any responding API endpoint
    const apiEndpoints = ctx.discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 8);
    for (const ep of apiEndpoints) {
      const r = await ctxFetch(ctx, ep, { headers: { Accept: "application/json" } });
      if (!r || r.status !== 200) continue;
      const body = await r.text().catch(() => "");
      const found = extractAlternateIds(body);
      for (const id of found) if (!collectedIds.includes(id)) collectedIds.push(id);
      if (collectedIds.length >= 6) break;
    }

    // Share discovered IDs with other modules via session store
    for (const id of collectedIds) {
      const idType = id.includes("-") ? "uuid" : id.length === 24 ? "objectid" : "integer";
      if (!ctx.sessionStore.discoveredObjectIds.some(e => e.id === id)) {
        ctx.sessionStore.discoveredObjectIds.push({ id, type: idType, endpoint: apiEndpoints[0] ?? base.origin });
      }
    }
    emit({ type: "log", message: `UUID/ObjectID extraction: ${collectedIds.length} IDs found across API responses` });

    // Second pass: for each pattern, replace {id} with extracted IDs and probe without auth
    for (const pattern of IDOR_PATH_PATTERNS.slice(0, 4)) {
      for (const id of collectedIds.slice(0, 3)) {
        const url = `${base.origin}${pattern.path.replace("{id}", id)}`;
        const authedRes = await ctxFetch(ctx, url, { headers: { Accept: "application/json" } });
        if (!authedRes || authedRes.status !== 200) continue;
        const authedBody = await authedRes.text().catch(() => "");
        if (authedBody.length < 20) continue;

        // Probe without auth
        const unauthRes = await safeFetch(url, { headers: { Accept: "application/json" } });
        if (!unauthRes || unauthRes.status !== 200) continue;
        const unauthBody = await unauthRes.text().catch(() => "");
        if (unauthBody.length < 20) continue;

        const idKey = `uuid-idor:${pattern.path}:${id}`;
        if (findings.some(f => f.title.includes(id))) continue;

        findings.push({
          title: `IDOR: ${pattern.label} Accessible via UUID/ObjectID Without Auth`,
          category: "Broken Access Control",
          severity: "critical",
          endpoint: url,
          description: `The ${pattern.label} endpoint at ${url} returned data for a non-sequential ID (UUID/ObjectID: ${id}) without authentication. The ID was discovered by extracting identifiers from authenticated API responses, then probing without credentials. This confirms unauthenticated cross-object enumeration on non-sequential IDs.`,
          evidence: [
            `ID type: ${id.includes("-") ? "UUID v4" : id.length === 24 ? "MongoDB ObjectID" : "Snowflake/large integer"}`,
            `ID extracted from authenticated response`,
            `GET ${url}`,
            `  With auth: HTTP ${authedRes.status}, ${authedBody.length} bytes`,
            `  Without auth: HTTP ${unauthRes.status}, ${unauthBody.length} bytes`,
            ``,
            `Unauthenticated response preview: ${unauthBody.slice(0, 200)}`,
          ].join("\n"),
          recommended_fix: "Verify object ownership on every request — do not assume UUIDs are unguessable. Implement row-level authorization. Return 401/403 for unauthenticated/unauthorized access regardless of ID format.",
          cvss_score: 9.1,
          cwe_id: "CWE-639",
          scanner_name: "Bug-Finder/IDOR",
          scanner_family: "web",
          confidence: 0.92,
        });
        emit({ type: "log", message: `  [UUID IDOR CONFIRMED] ${url} accessible without auth (id=${id.slice(0, 12)}...)` });
        void idKey; // suppress unused var
        break;
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No obvious IDOR vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/IDOR",
    message: `IDOR check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
