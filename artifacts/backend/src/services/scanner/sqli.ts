import { ScanContext, ScanFinding, safeFetch } from "./types";

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

const SQL_PROBES = ["'", '"', "' OR '1'='1", "1; SELECT 1", "1 UNION SELECT NULL--"];

const TEST_PARAMS = ["id", "user_id", "product_id", "search", "q", "query", "order", "sort", "page", "category"];

export async function runSqliCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "SQLMap/SQLi", message: "Probing for SQL injection signals" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 5 : 10;
  const endpoints = discoveredEndpoints.filter(ep => ep.includes("/api") || ep.includes("?")).slice(0, budget);
  if (!endpoints.includes(targetUrl)) endpoints.unshift(targetUrl);

  for (const endpoint of endpoints.slice(0, budget)) {
    // First get baseline response
    const baseline = await safeFetch(endpoint);
    if (!baseline) continue;
    const baseBody = await baseline.text().catch(() => "");
    const baseStatus = baseline.status;

    for (const param of TEST_PARAMS.slice(0, 4)) {
      for (const probe of SQL_PROBES.slice(0, 2)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe)}`;
        const res = await safeFetch(testUrl);
        if (!res) continue;

        const body = (await res.text().catch(() => "")).toLowerCase();

        // Check for SQL error patterns
        const matchedPattern = SQL_ERROR_PATTERNS.find(p => body.includes(p));
        if (matchedPattern) {
          const key = `${endpoint}:${param}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            title: `SQL Injection Signal in Parameter: ${param}`,
            category: "Injection",
            severity: "critical",
            endpoint,
            description: `The parameter "${param}" appears to be vulnerable to SQL injection. The server returned a SQL error message when supplied with a malformed input, indicating unsanitized database queries.`,
            evidence: `GET ${testUrl}\n\nPayload: ${probe}\nSQL Error Pattern Detected: "${matchedPattern}"\n\nResponse snippet:\n${body.slice(body.indexOf(matchedPattern) - 50, body.indexOf(matchedPattern) + 200)}`,
            recommended_fix: "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use an ORM that handles escaping automatically.",
            cvss_score: 9.8,
            cwe_id: "CWE-89",
            scanner_name: "SQLMap",
            scanner_family: "web",
            confidence: 0.9,
          });
          emit({ type: "log", message: `  [SQLi] SQL error at ${endpoint} param=${param}: "${matchedPattern}"` });
          break;
        }

        // Check for response anomalies (timing/length changes on quote injection)
        if (probe === "'" && res.status >= 500) {
          const key = `${endpoint}:${param}:500`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              title: `Possible SQL Injection — Server Error on Quote Injection: ${param}`,
              category: "Injection",
              severity: "high",
              endpoint,
              description: `Parameter "${param}" caused a 500 Internal Server Error when a single quote was injected, suggesting the input may be passed directly into a database query.`,
              evidence: `GET ${testUrl}\nPayload: ${probe}\nBaseline status: ${baseStatus}\nWith payload status: ${res.status}`,
              recommended_fix: "Investigate the server error. Use parameterized queries to prevent SQL injection.",
              cvss_score: 7.5,
              cwe_id: "CWE-89",
              scanner_name: "SQLMap",
              scanner_family: "web",
              confidence: 0.65,
            });
            emit({ type: "log", message: `  [SQLi?] 500 error on quote injection at ${endpoint} param=${param}` });
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
