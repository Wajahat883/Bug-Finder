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
              scanner_name: "SQLi-Scanner",
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
              scanner_name: "SQLi-Scanner",
              scanner_family: "web",
              confidence: 0.65,
            });
          }
        }
      }

      // ── 2. Boolean-based blind detection ────────────────────────────────
      if (profile !== "quick" && !seen.has(`${endpoint}:${param}:error`) && !seen.has(`${endpoint}:${param}:500`)) {
        for (const [truePayload, falsePayload] of BOOLEAN_PAIRS) {
          const trueUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(truePayload)}`;
          const falseUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(falsePayload)}`;

          const [trueRes, falseRes] = await Promise.all([ctxFetch(ctx, trueUrl), ctxFetch(ctx, falseUrl)]);
          if (!trueRes || !falseRes) continue;

          const trueBody = await trueRes.text().catch(() => "");
          const falseBody = await falseRes.text().catch(() => "");

          const trueLen = trueBody.length;
          const falseLen = falseBody.length;

          // Significant body length difference between true/false condition = boolean-based blind SQLi
          const lenDiff = Math.abs(trueLen - falseLen);
          const baselineDiff = Math.abs(trueLen - baseLen);

          // True condition should match baseline, false condition should differ
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
                description: `Parameter "${param}" is vulnerable to boolean-based blind SQL injection. The response length changes significantly between TRUE and FALSE SQL conditions (${trueLen} vs ${falseLen} bytes), confirming conditional query execution.`,
                evidence: `TRUE payload: GET ${trueUrl}\nResponse length: ${trueLen} bytes (matches baseline ${baseLen})\n\nFALSE payload: GET ${falseUrl}\nResponse length: ${falseLen} bytes (${lenDiff} byte difference)\n\nThis length difference indicates the database evaluates the boolean condition.`,
                recommended_fix: "Use parameterized queries. This type of SQLi is confirmed even without visible errors — the application logic branches on query results.",
                cvss_score: 9.1,
                cwe_id: "CWE-89",
                scanner_name: "SQLi-Scanner",
                scanner_family: "web",
                confidence: 0.82,
              });
              emit({ type: "log", message: `  [SQLi-Boolean] Blind SQLi detected at ${endpoint} param=${param} (${lenDiff}b diff)` });
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
                scanner_name: "SQLi-Scanner",
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
