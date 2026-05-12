import { ScanContext, ScanFinding, ctxFetch } from "./types";

// PII and sensitive data patterns
const SENSITIVE_PATTERNS = [
  { name: "Email Address", pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: "medium" as const, cwe: "CWE-359" },
  { name: "US Social Security Number", pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: "critical" as const, cwe: "CWE-359" },
  { name: "Credit Card Number (Visa/MC)", pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b/g, severity: "critical" as const, cwe: "CWE-359" },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical" as const, cwe: "CWE-312" },
  { name: "Private Key Block", pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical" as const, cwe: "CWE-312" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: "high" as const, cwe: "CWE-312" },
  { name: "Password Hash (bcrypt)", pattern: /\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}/g, severity: "high" as const, cwe: "CWE-312" },
  { name: "Internal IP Address", pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, severity: "medium" as const, cwe: "CWE-200" },
  { name: "Database Connection String", pattern: /(mongodb|postgresql|mysql|redis):\/\/[^\s"'<>]+/gi, severity: "critical" as const, cwe: "CWE-312" },
  { name: "GitHub Personal Access Token", pattern: /ghp_[A-Za-z0-9]{36}/g, severity: "critical" as const, cwe: "CWE-312" },
];

const ERROR_TRIGGER_PATHS = [
  "/<>\"'", "/undefined", "/null", "/%00", "/../../../etc/passwd",
  "/api/undefined", "/api/null", "/api/test?id=undefined",
];

export async function runDataExposureCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/DataExposure", message: "Scanning for sensitive data leakage and verbose error messages" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const seen = new Set<string>();

  // 1. Scan API responses for sensitive data patterns
  emit({ type: "log", message: "Scanning API responses for sensitive data..." });

  const scanEndpoints = [
    targetUrl,
    ...discoveredEndpoints.slice(0, budget),
    `${base}/api/users`, `${base}/api/profile`, `${base}/api/me`,
  ];

  for (const endpoint of scanEndpoints.slice(0, budget + 3)) {
    const r = await ctxFetch(ctx, endpoint, { redirect: "follow" });
    if (!r) continue;

    const body = await r.text().catch(() => "");
    if (!body || body.length < 20) continue;

    for (const pat of SENSITIVE_PATTERNS) {
      const matches = body.match(pat.pattern);
      if (matches && matches.length > 0 && !seen.has(`${endpoint}:${pat.name}`)) {
        seen.add(`${endpoint}:${pat.name}`);
        const sampleMatch = matches[0];
        // Redact sensitive parts before storing as evidence
        const redacted = sampleMatch.replace(/(?<=.{4}).(?=.{4})/g, "*");

        findings.push({
          title: `Sensitive Data Exposed in Response: ${pat.name}`,
          category: "Data Exposure",
          severity: pat.severity,
          endpoint,
          description: `The API response at ${endpoint} contains what appears to be ${pat.name}. Exposing sensitive data in API responses violates least-privilege principles and can lead to data breaches.`,
          evidence: `GET ${endpoint}\nHTTP ${r.status}\nPattern: ${pat.name}\nMatches found: ${matches.length}\nSample (redacted): ${redacted}\nNote: Full value redacted for security`,
          recommended_fix: `Remove ${pat.name} from API responses. Apply field-level filtering. Use data masking for sensitive fields. Audit all API responses for unintended data exposure.`,
          cvss_score: pat.severity === "critical" ? 9.1 : pat.severity === "high" ? 7.5 : 5.3,
          cwe_id: pat.cwe,
          scanner_name: "Bug-Finder/Data",
          scanner_family: "web",
          confidence: 0.88,
        });
        emit({ type: "log", message: `  [${pat.severity.toUpperCase()}] ${pat.name} found at ${endpoint}` });
      }
    }
  }

  // 2. Error message analysis — trigger errors and check for verbose output
  emit({ type: "log", message: "Testing for verbose error messages..." });

  for (const errPath of ERROR_TRIGGER_PATHS.slice(0, budget)) {
    const url = `${base}${errPath}`;
    const r = await ctxFetch(ctx, url, { redirect: "manual" });
    if (!r) continue;

    const body = await r.text().catch(() => "");
    if (!body) continue;

    const stackTracePatterns = [
      "at java.", "at com.", "at org.", "at net.", "NullPointerException",
      "StackTrace", "Traceback (most recent", "File \"", "line ", " in <module>",
      "System.Exception", "at System.", "Microsoft.AspNetCore",
      "Error: Cannot", "TypeError:", "ReferenceError:", "SyntaxError:",
      "mongoose", "sequelize", "prisma", "drizzle",
    ];

    const pathInfoPatterns = [
      "/var/www/", "/home/", "/usr/local/", "C:\\", "D:\\",
      "/app/", "/src/", "/opt/", "node_modules",
    ];

    const hasStackTrace = stackTracePatterns.some(p => body.includes(p));
    const hasPathInfo = pathInfoPatterns.some(p => body.includes(p));

    if ((r.status >= 400 || r.status >= 500) && hasStackTrace && !seen.has(`error:${url}`)) {
      seen.add(`error:${url}`);
      findings.push({
        title: "Verbose Stack Trace in Error Response",
        category: "Information Disclosure",
        severity: "medium",
        endpoint: url,
        description: `The application returns detailed stack traces in error responses. Stack traces reveal internal technology, file paths, class names, and line numbers that significantly aid attackers in targeted exploitation.`,
        evidence: `GET ${url}\nHTTP ${r.status}\nStack trace content detected in response:\n${body.slice(0, 500)}`,
        recommended_fix: "Configure error handling to return generic error messages in production. Log full stack traces server-side only. Set NODE_ENV=production / DEBUG=false. Never expose internal errors to clients.",
        cvss_score: 5.3,
        cwe_id: "CWE-209",
        scanner_name: "Bug-Finder/Data",
        scanner_family: "web",
        confidence: 0.9,
      });
      emit({ type: "log", message: `  Stack trace exposed at ${url}` });
    }

    if (hasPathInfo && !seen.has(`path:${url}`)) {
      seen.add(`path:${url}`);
      findings.push({
        title: "Server File Path Disclosed in Response",
        category: "Information Disclosure",
        severity: "low",
        endpoint: url,
        description: `The server discloses internal file system paths in its response. This reveals the server's directory structure and can help attackers identify file locations for path traversal attacks.`,
        evidence: `GET ${url}\nHTTP ${r.status}\nFile path detected in response:\n${body.slice(0, 300)}`,
        recommended_fix: "Configure error pages to never reveal internal paths. Use generic error messages in production. Set appropriate error reporting levels.",
        cvss_score: 3.7,
        cwe_id: "CWE-200",
        scanner_name: "Bug-Finder/Data",
        scanner_family: "web",
        confidence: 0.85,
      });
      emit({ type: "log", message: `  Path info disclosed at ${url}` });
    }
  }

  // 3. CSP analysis
  emit({ type: "log", message: "Analyzing Content Security Policy..." });
  const mainRes = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (mainRes) {
    const csp = mainRes.headers.get("content-security-policy") ?? mainRes.headers.get("content-security-policy-report-only");

    if (csp) {
      // Check for unsafe CSP directives
      const unsafeChecks = [
        { pattern: "unsafe-inline", title: "CSP Allows Unsafe Inline Scripts", severity: "high" as const, cvss: 6.1 },
        { pattern: "unsafe-eval", title: "CSP Allows Unsafe eval()", severity: "high" as const, cvss: 6.1 },
        { pattern: "'unsafe-hashes'", title: "CSP Uses Unsafe Hashes", severity: "medium" as const, cvss: 5.3 },
        { pattern: "*", title: "CSP Wildcard Source Directive", severity: "medium" as const, cvss: 5.3 },
        { pattern: "data:", title: "CSP Allows data: URIs", severity: "medium" as const, cvss: 5.3 },
      ];

      for (const check of unsafeChecks) {
        if (csp.includes(check.pattern) && !seen.has(`csp:${check.pattern}`)) {
          seen.add(`csp:${check.pattern}`);
          findings.push({
            title: check.title,
            category: "Content Security Policy",
            severity: check.severity,
            endpoint: targetUrl,
            description: `The Content Security Policy contains "${check.pattern}" which weakens XSS protection. Attackers may bypass the CSP and execute malicious scripts.`,
            evidence: `Content-Security-Policy: ${csp}\n\nProblematic directive: "${check.pattern}"`,
            recommended_fix: `Remove "${check.pattern}" from your CSP. Use nonces or hashes for legitimate inline scripts instead. Test your CSP at https://csp-evaluator.withgoogle.com/`,
            cvss_score: check.cvss,
            cwe_id: "CWE-693",
            scanner_name: "Bug-Finder/CSP",
            scanner_family: "web",
            confidence: 0.95,
          });
          emit({ type: "log", message: `  CSP issue: ${check.title}` });
        }
      }
    }

    // Check if CSP is report-only only
    if (!mainRes.headers.get("content-security-policy") && mainRes.headers.get("content-security-policy-report-only")) {
      findings.push({
        title: "CSP in Report-Only Mode — Not Enforced",
        category: "Content Security Policy",
        severity: "medium",
        endpoint: targetUrl,
        description: "The Content Security Policy is set in report-only mode (Content-Security-Policy-Report-Only). This means the policy is not enforced and XSS attacks will not be blocked.",
        evidence: `Content-Security-Policy-Report-Only: ${mainRes.headers.get("content-security-policy-report-only")}\nContent-Security-Policy: [NOT SET]`,
        recommended_fix: "Switch from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce the policy.",
        cvss_score: 5.4,
        cwe_id: "CWE-693",
        scanner_name: "Bug-Finder/CSP",
        scanner_family: "web",
        confidence: 0.98,
      });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No sensitive data exposure detected" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/DataExposure", message: `Data exposure check complete — ${findings.length} finding(s)` });
  return findings;
}
