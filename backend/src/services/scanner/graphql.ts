import { ScanContext, ScanFinding, ctxFetch } from "./types";

const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql", "/api/v1/graphql"];

const INTROSPECTION_QUERY = JSON.stringify({
  query: `{ __schema { types { name } } }`,
});

const BATCH_QUERY = JSON.stringify([
  { query: "{ __typename }" },
  { query: "{ __typename }" },
  { query: "{ __typename }" },
  { query: "{ __typename }" },
  { query: "{ __typename }" },
]);

export async function runGraphQLCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/GraphQL", message: "Probing for GraphQL endpoints and misconfigurations" });

  const base = new URL(targetUrl);

  for (const path of GRAPHQL_PATHS) {
    const url = `${base.origin}${path}`;

    // Test introspection
    const introRes = await ctxFetch(ctx, url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: INTROSPECTION_QUERY,
    });

    if (!introRes || introRes.status === 404) continue;

    const introBody = await introRes.text().catch(() => "");

    if (introRes.status === 200 && introBody.includes("__schema")) {
      emit({ type: "log", message: `  GraphQL endpoint found at ${path}` });

      findings.push({
        title: "GraphQL Introspection Enabled in Production",
        category: "API Security",
        severity: "medium",
        endpoint: url,
        description: "GraphQL introspection is enabled, allowing attackers to enumerate the entire API schema including all types, queries, mutations, and arguments.",
        evidence: `POST ${url}\n${INTROSPECTION_QUERY}\n\nResponse: HTTP ${introRes.status}\n${introBody.slice(0, 300)}`,
        recommended_fix: "Disable introspection in production. Most GraphQL libraries support this: e.g., Apollo Server's `introspection: false` option.",
        cvss_score: 5.3,
        cwe_id: "CWE-200",
        scanner_name: "Bug-Finder/GraphQL",
        scanner_family: "web",
        confidence: 0.97,
      });

      // Test query batching
      const batchRes = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: BATCH_QUERY,
      });

      if (batchRes && batchRes.status === 200) {
        const batchBody = await batchRes.text().catch(() => "");
        if (batchBody.includes("[") && batchBody.includes("__typename")) {
          findings.push({
            title: "GraphQL Query Batching Enabled",
            category: "API Security",
            severity: "medium",
            endpoint: url,
            description: "GraphQL query batching is enabled. An attacker can send a single HTTP request containing thousands of queries, bypassing rate limits and enabling brute-force or DoS attacks.",
            evidence: `POST ${url}\nBatch payload: ${BATCH_QUERY.slice(0, 100)}...\nResponse: HTTP ${batchRes.status} — multiple results returned`,
            recommended_fix: "Disable query batching or implement per-batch rate limiting and query depth limits.",
            cvss_score: 5.3,
            cwe_id: "CWE-770",
            scanner_name: "Bug-Finder/GraphQL",
            scanner_family: "web",
            confidence: 0.9,
          });
          emit({ type: "log", message: `  GraphQL batching enabled at ${path}` });
        }
      }

      // Test field suggestions (info disclosure)
      const typoRes = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ usr { email } }" }),
      });
      if (typoRes) {
        const typoBody = await typoRes.text().catch(() => "");
        if (typoBody.includes("Did you mean") || typoBody.includes("suggestions")) {
          findings.push({
            title: "GraphQL Field Suggestions Leak Schema Info",
            category: "API Security",
            severity: "low",
            endpoint: url,
            description: "GraphQL returns field suggestions on typos, leaking valid field names even without introspection enabled.",
            evidence: `Query: { usr { email } }\nResponse: ${typoBody.slice(0, 200)}`,
            recommended_fix: "Disable field suggestions in production GraphQL configuration.",
            cvss_score: 3.1,
            cwe_id: "CWE-200",
            scanner_name: "Bug-Finder/GraphQL",
            scanner_family: "web",
            confidence: 0.85,
          });
        }
      }
      // ── Query depth limit abuse ─────────────────────────────────────────────
      // Send deeply nested query; if server evaluates it without error/timeout → no depth limit
      const deepQuery = JSON.stringify({
        query: `{ __type(name:"Query") { fields { type { fields { type { fields { type { fields { type { name } } } } } } } } } }`,
      });
      const depthRes = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: deepQuery,
      });
      if (depthRes && depthRes.status === 200) {
        const depthBody = await depthRes.text().catch(() => "");
        // Server returned 200 with data (not a complexity/depth error) → no depth limit enforced
        if (depthBody.includes('"data"') && !depthBody.includes("complexity") && !depthBody.includes("depth limit") && !depthBody.includes("max depth")) {
          findings.push({
            title: "GraphQL No Query Depth Limit",
            category: "API Security",
            severity: "high",
            endpoint: url,
            description: "The GraphQL endpoint does not enforce a query depth limit. An attacker can send a deeply nested query that causes exponential resolver calls, resulting in a denial-of-service condition.",
            evidence: `POST ${url}\nNested query depth: 7 levels\nResponse: HTTP ${depthRes.status} — server processed without depth error\nQuery: ${deepQuery.slice(0, 200)}`,
            recommended_fix: "Implement query depth limiting (e.g., graphql-depth-limit). Set max depth to 5-7 for most APIs. Also consider query complexity analysis.",
            cvss_score: 7.5,
            cwe_id: "CWE-770",
            scanner_name: "Bug-Finder/GraphQL",
            scanner_family: "web",
            confidence: 0.85,
          });
          emit({ type: "log", message: `  GraphQL no depth limit at ${path}` });
        }
      }

      // ── Mutation injection probe ────────────────────────────────────────────
      // Try common mutations to discover exposed write operations
      const mutationProbes = [
        { query: `mutation { createUser(email:"xsstest@bugfinder.test", password:"P@ss1234!") { id email } }`, label: "createUser" },
        { query: `mutation { register(username:"bugfindertest", email:"test@bugfinder.test", password:"P@ss1234!") { token } }`, label: "register" },
        { query: `mutation { login(email:"admin@test.com", password:"admin") { token user { role } } }`, label: "login" },
      ];

      for (const mutProbe of mutationProbes) {
        const mutRes = await ctxFetch(ctx, url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: mutProbe.query }),
        });
        if (!mutRes) continue;
        const mutBody = await mutRes.text().catch(() => "");
        // If we get actual data back (not just errors), the mutation exists and is accessible
        // Only confirmed if "data" key has non-null content AND "errors" array is absent or empty
        let mutData: Record<string, unknown> | null = null;
        try { mutData = JSON.parse(mutBody) as Record<string, unknown>; } catch { /* not JSON */ }
        const dataIsNull = mutData?.["data"] === null || mutData?.["data"] === undefined;
        const hasErrors = Array.isArray(mutData?.["errors"]) && (mutData["errors"] as unknown[]).length > 0;
        if (mutRes.status === 200 && mutBody.includes('"data"') && !dataIsNull && !hasErrors) {
          findings.push({
            title: `GraphQL Mutation Accessible Without Auth: ${mutProbe.label}`,
            category: "API Security",
            severity: "critical",
            endpoint: url,
            description: `The GraphQL mutation "${mutProbe.label}" is accessible without authentication and returned a success response. This may allow unauthenticated user registration, login brute-force, or account creation.`,
            evidence: `POST ${url}\nMutation: ${mutProbe.query}\nHTTP ${mutRes.status}\nResponse: ${mutBody.slice(0, 300)}`,
            recommended_fix: "Require authentication for sensitive mutations. Implement rate limiting on auth mutations. Validate and sanitize all mutation inputs.",
            cvss_score: 9.1,
            cwe_id: "CWE-306",
            scanner_name: "Bug-Finder/GraphQL",
            scanner_family: "web",
            confidence: 0.88,
          });
          emit({ type: "log", message: `  [GraphQL] Unauthenticated mutation: ${mutProbe.label}` });
          break;
        }
      }

      break; // Found one GraphQL endpoint, don't test more
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No GraphQL endpoints found or introspection disabled" });

  emit({ type: "engine_done", engine: "Bug-Finder/GraphQL", message: `GraphQL check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runWebSocketCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/WebSocket", message: "Detecting WebSocket endpoints" });

  // Detect WebSocket by checking upgrade headers and known paths
  const wsRes = await ctxFetch(ctx, targetUrl, {
    headers: { "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Version": "13" },
  });

  if (wsRes && wsRes.status === 101) {
    findings.push({
      title: "WebSocket Endpoint Detected — Origin Validation Required",
      category: "WebSocket Security",
      severity: "medium",
      endpoint: targetUrl,
      description: "A WebSocket endpoint is available. Without proper Origin header validation, malicious websites can establish WebSocket connections and interact with the server on behalf of authenticated users.",
      evidence: `GET ${targetUrl}\nConnection: Upgrade\nHTTP ${wsRes.status} — WebSocket upgrade accepted`,
      recommended_fix: "Validate the Origin header on WebSocket handshake. Reject connections from unexpected origins. Use authentication tokens in the WebSocket handshake.",
      cvss_score: 5.4,
      cwe_id: "CWE-346",
      scanner_name: "Bug-Finder/WebSocket",
      scanner_family: "web",
      confidence: 0.9,
    });
    emit({ type: "log", message: `WebSocket endpoint detected at ${targetUrl}` });
  } else {
    emit({ type: "log", message: "No WebSocket endpoint found at root" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/WebSocket", message: `WebSocket check complete — ${findings.length} issue(s)` });
  return findings;
}
