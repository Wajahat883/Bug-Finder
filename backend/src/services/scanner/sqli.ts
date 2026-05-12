import { ScanContext, ScanFinding, ctxFetch, isInScope } from "./types";

const SQL_ERROR_PATTERNS = [
  "sql syntax",
  "mysql_fetch",
  "ora-01756",
  "unclosed quotation mark",
  "pg_query",
  "sqlite_query",
  "sqlstate",
  "division by zero",
  "syntax error in query",
  "unexpected end of sql",
  "invalid column name",
  "you have an error in your sql syntax",
  "quoted string not properly terminated",
  "unterminated string literal",
  "invalid input syntax for type",
  "column does not exist",
  "relation does not exist",
  "psql:",
  "warning: mysql",
  "function.mysql",
  "microsoft sql native client",
  "jdbc:",
  "hibernatetransaction",
];

// Error-based probes
const SQL_ERROR_PROBES = ["'", '"', "' OR '1'='1", "1; SELECT 1", "1 UNION SELECT NULL--"];

// Boolean-based pairs: [true_payload, false_payload]
const BOOLEAN_PAIRS: Array<[string, string]> = [
  ["1 AND 1=1", "1 AND 1=2"],
  ["1 OR 1=1", "1 OR 1=2"],
  ["' AND '1'='1", "' AND '1'='2"],
];

// Time-based blind payloads per DB (each should cause ~3s delay)
const TIME_BASED_PROBES = [
  "1; WAITFOR DELAY '0:0:3'--",         // MSSQL
  "1' AND SLEEP(3)--",                   // MySQL
  "1; SELECT pg_sleep(3)--",             // PostgreSQL
  "1 AND 1=1 AND SLEEP(3)",              // MySQL variant
  "1'; SELECT SLEEP(3)--",              // MySQL quoted
  "1 UNION SELECT SLEEP(3)--",          // MySQL union
];

const TEST_PARAMS = ["id", "user_id", "product_id", "search", "q", "query", "order", "sort", "page", "category"];
const TIME_THRESHOLD_MS = 2800; // 2.8s — fires below the 3s delay to account for network jitter

export async function runSqliCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "SQLMap/SQLi", message: "Probing for SQL injection (error-based, boolean-based, time-based)" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 5 : 10;
  const endpoints = discoveredEndpoints
    .filter(ep => isInScope(ctx, ep) && (ep.includes("/api") || ep.includes("?")))
    .slice(0, budget);
  if (!endpoints.includes(targetUrl) && isInScope(ctx, targetUrl)) endpoints.unshift(targetUrl);

  for (const endpoint of endpoints.slice(0, budget)) {
    const baseline = await ctxFetch(ctx, endpoint);
    if (!baseline) continue;
    const baseBody = await baseline.text().catch(() => "");
    const baseStatus = baseline.status;
    const baseLen = baseBody.length;

    for (const param of TEST_PARAMS.slice(0, profile === "quick" ? 3 : 6)) {
      // ── 1. Error-based detection ─────────────────────────────────────────
      for (const probe of SQL_ERROR_PROBES.slice(0, profile === "quick" ? 2 : SQL_ERROR_PROBES.length)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe)}`;
        const res = await ctxFetch(ctx, testUrl);
        if (!res) continue;

        const body = (await res.text().catch(() => "")).toLowerCase();
        const matchedPattern = SQL_ERROR_PATTERNS.find(p => body.includes(p));

        if (matchedPattern) {
          const key = `${endpoint}:${param}:error`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              title: `SQL Injection (Error-Based) in Parameter: ${param}`,
              category: "Injection",
              severity: "critical",
              endpoint,
              description: `Parameter "${param}" is vulnerable to error-based SQL injection. The server leaked a SQL error when supplied with a malformed payload, confirming unsanitized database queries.`,
              evidence: `GET ${testUrl}\nPayload: ${probe}\nSQL Error Pattern: "${matchedPattern}"\n\nResponse snippet:\n${body.slice(Math.max(0, body.indexOf(matchedPattern) - 50), body.indexOf(matchedPattern) + 200)}`,
              recommended_fix: "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
              cvss_score: 9.8,
              cwe_id: "CWE-89",
              scanner_name: "Bug-Finder/SQLi",
              scanner_family: "web",
              confidence: 0.95,
            });
            emit({ type: "log", message: `  [SQLi-Error] Pattern "${matchedPattern}" at ${endpoint} param=${param}` });
          }
          break;
        }

        // 500 error on quote injection
        if (probe === "'" && res.status >= 500) {
          const key = `${endpoint}:${param}:500`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              title: `Possible SQL Injection — Server Error on Quote: ${param}`,
              category: "Injection",
              severity: "high",
              endpoint,
              description: `Parameter "${param}" caused a 500 Internal Server Error when injected with a single quote, suggesting the input may reach a database query without sanitization.`,
              evidence: `GET ${testUrl}\nPayload: ${probe}\nBaseline status: ${baseStatus}\nWith payload status: ${res.status}`,
              recommended_fix: "Investigate the 500 error. Use parameterized queries to prevent SQL injection.",
              cvss_score: 7.5,
              cwe_id: "CWE-89",
              scanner_name: "Bug-Finder/SQLi",
              scanner_family: "web",
              confidence: 0.65,
            });
          }
        }
      }

      // ── 2. Boolean-based blind detection (3-pass consistency) ──────────────
      if (profile !== "quick" && !seen.has(`${endpoint}:${param}:error`) && !seen.has(`${endpoint}:${param}:500`)) {
        for (const [truePayload, falsePayload] of BOOLEAN_PAIRS) {
          const trueUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(truePayload)}`;
          const falseUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(falsePayload)}`;

          // 3-pass consistency: send each condition 3 times to eliminate CDN/A-B variance
          const trueLengths: number[] = [];
          const falseLengths: number[] = [];
          for (let pass = 0; pass < 3; pass++) {
            const [tRes, fRes] = await Promise.all([ctxFetch(ctx, trueUrl), ctxFetch(ctx, falseUrl)]);
            if (tRes) trueLengths.push((await tRes.text().catch(() => "")).length);
            if (fRes) falseLengths.push((await fRes.text().catch(() => "")).length);
          }

          if (trueLengths.length < 2 || falseLengths.length < 2) continue;

          // Check internal consistency of each set — high variance = CDN rotation, not SQLi
          const trueVariance = Math.max(...trueLengths) - Math.min(...trueLengths);
          const falseVariance = Math.max(...falseLengths) - Math.min(...falseLengths);
          if (trueVariance > 60 || falseVariance > 60) {
            emit({ type: "log", message: `  Boolean pair for ${param} has high variance (${trueVariance}/${falseVariance}b) — skipping (CDN/A-B noise)` });
            continue;
          }

          const trueAvg = trueLengths.reduce((a, b) => a + b, 0) / trueLengths.length;
          const falseAvg = falseLengths.reduce((a, b) => a + b, 0) / falseLengths.length;
          const lenDiff = Math.abs(trueAvg - falseAvg);
          const baselineDiff = Math.abs(trueAvg - baseLen);

          const trueMatchesBaseline = baselineDiff < 50;
          const falseDeviates = lenDiff > 100;

          if (trueMatchesBaseline && falseDeviates) {
            const key = `${endpoint}:${param}:boolean`;
            if (!seen.has(key)) {
              seen.add(key);
              findings.push({
                title: `SQL Injection (Boolean-Based Blind) in Parameter: ${param}`,
                category: "Injection",
                severity: "critical",
                endpoint,
                description: `Parameter "${param}" is vulnerable to boolean-based blind SQL injection. Across 3 independent request pairs, TRUE conditions consistently returned ~${Math.round(trueAvg)} bytes while FALSE conditions returned ~${Math.round(falseAvg)} bytes — confirming conditional query execution.`,
                evidence: `TRUE payload: GET ${trueUrl}\n3-pass lengths: ${trueLengths.join(", ")} (avg ${Math.round(trueAvg)}, variance ${trueVariance}b)\nBaseline: ${baseLen} bytes\n\nFALSE payload: GET ${falseUrl}\n3-pass lengths: ${falseLengths.join(", ")} (avg ${Math.round(falseAvg)}, variance ${falseVariance}b)\n\nAverage difference: ${Math.round(lenDiff)} bytes — consistent across all 3 passes, ruling out CDN/A-B variation.`,
                recommended_fix: "Use parameterized queries. This type of SQLi is confirmed even without visible errors — the application logic branches on query results.",
                cvss_score: 9.1,
                cwe_id: "CWE-89",
                scanner_name: "Bug-Finder/SQLi",
                scanner_family: "web",
                confidence: 0.88,
              });
              emit({ type: "log", message: `  [SQLi-Boolean] Blind SQLi at ${endpoint} param=${param} (avg ${Math.round(lenDiff)}b diff over 3 passes)` });
            }
          }
        }
      }

      // ── 3. Time-based blind detection ───────────────────────────────────
      if (profile === "deep" && !seen.has(`${endpoint}:${param}:error`) && !seen.has(`${endpoint}:${param}:boolean`)) {
        for (const probe of TIME_BASED_PROBES) {
          const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe)}`;

          const start = Date.now();
          const res = await ctxFetch(ctx, testUrl, { signal: AbortSignal.timeout(8000) });
          const elapsed = Date.now() - start;

          if (!res) continue;

          if (elapsed >= TIME_THRESHOLD_MS) {
            const key = `${endpoint}:${param}:timebased`;
            if (!seen.has(key)) {
              seen.add(key);
              findings.push({
                title: `SQL Injection (Time-Based Blind) in Parameter: ${param}`,
                category: "Injection",
                severity: "critical",
                endpoint,
                description: `Parameter "${param}" is vulnerable to time-based blind SQL injection. The server delayed its response by ${elapsed}ms when injected with a sleep payload, confirming the payload was executed by the database engine.`,
                evidence: `GET ${testUrl}\nPayload: ${probe}\nResponse time: ${elapsed}ms (threshold: ${TIME_THRESHOLD_MS}ms)\n\nA ${elapsed}ms delay strongly indicates the database executed the SLEEP/WAITFOR command inside the query.`,
                recommended_fix: "Use parameterized queries or prepared statements immediately. Time-based blind SQLi is fully exploitable for data extraction via binary search.",
                cvss_score: 9.8,
                cwe_id: "CWE-89",
                scanner_name: "Bug-Finder/SQLi",
                scanner_family: "web",
                confidence: 0.88,
              });
              emit({ type: "log", message: `  [SQLi-TimeBased] ${elapsed}ms delay at ${endpoint} param=${param}` });
              break;
            }
          }
        }
      }
    }
  }

  // ── POST/JSON body injection ───────────────────────────────────────────────
  // Tests the same params but sends them in a JSON POST body — covers REST APIs
  // that only accept application/json and ignore query strings
  if (profile !== "quick") {
    const jsonEndpoints = endpoints.slice(0, Math.min(3, budget));
    for (const endpoint of jsonEndpoints) {
      const baseline = await ctxFetch(ctx, endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      if (!baseline) continue;
      const baseBody = await baseline.text().catch(() => "");
      const baseLen = baseBody.length;

      for (const param of TEST_PARAMS.slice(0, 4)) {
        for (const probe of SQL_ERROR_PROBES.slice(0, 3)) {
          const jsonKey = `${endpoint}:${param}:json-error`;
          if (seen.has(jsonKey)) continue;

          const res = await ctxFetch(ctx, endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ [param]: probe }),
          });
          if (!res) continue;

          const body = (await res.text().catch(() => "")).toLowerCase();
          const matchedPattern = SQL_ERROR_PATTERNS.find(p => body.includes(p));

          if (matchedPattern) {
            seen.add(jsonKey);
            findings.push({
              title: `SQL Injection (Error-Based) in JSON Body Parameter: ${param}`,
              category: "Injection",
              severity: "critical",
              endpoint,
              description: `The JSON body parameter "${param}" is vulnerable to SQL injection. The server returned a SQL error when the parameter was sent with a malicious payload via POST application/json.`,
              evidence: `POST ${endpoint}\nContent-Type: application/json\nBody: ${JSON.stringify({ [param]: probe })}\n\nSQL Error Pattern: "${matchedPattern}"\nResponse snippet:\n${body.slice(Math.max(0, body.indexOf(matchedPattern) - 50), body.indexOf(matchedPattern) + 200)}`,
              recommended_fix: "Use parameterized queries for all database operations. JSON body parameters are equally injectable if concatenated into queries.",
              cvss_score: 9.8,
              cwe_id: "CWE-89",
              scanner_name: "Bug-Finder/SQLi",
              scanner_family: "web",
              confidence: 0.95,
            });
            emit({ type: "log", message: `  [SQLi-JSON-Error] Pattern "${matchedPattern}" via POST JSON at ${endpoint} field=${param}` });
            break;
          }

          // 500 on POST
          if (probe === "'" && res.status >= 500) {
            const key500 = `${endpoint}:${param}:json-500`;
            if (!seen.has(key500)) {
              seen.add(key500);
              findings.push({
                title: `Possible SQL Injection in JSON Body — Server Error: ${param}`,
                category: "Injection",
                severity: "high",
                endpoint,
                description: `JSON field "${param}" caused a 500 error when injected with a single quote via POST application/json.`,
                evidence: `POST ${endpoint}\nContent-Type: application/json\nBody: ${JSON.stringify({ [param]: probe })}\nBaseline: ${baseLen}b / HTTP ${baseline.status}\nWith payload: HTTP ${res.status}`,
                recommended_fix: "Use parameterized queries. Investigate the 500 error.",
                cvss_score: 7.5,
                cwe_id: "CWE-89",
                scanner_name: "Bug-Finder/SQLi",
                scanner_family: "web",
                confidence: 0.65,
              });
            }
          }
        }
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No SQL injection signals detected" });
  }

  emit({
    type: "engine_done",
    engine: "SQLMap/SQLi",
    message: `SQLi check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
