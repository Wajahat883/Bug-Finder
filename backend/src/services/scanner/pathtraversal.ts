import { ScanContext, ScanFinding, ctxFetch } from "./types";

const TRAVERSAL_PROBES = [
  "../../../etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
];

const TRAVERSAL_PARAMS = ["file", "path", "filename", "page", "template", "include", "load", "view", "dir", "document"];

const SSRF_TARGET = "http://169.254.169.254/latest/meta-data/";
const SSRF_PARAMS = ["url", "endpoint", "target", "dest", "destination", "fetch", "proxy", "webhook", "callback", "site"];

export async function runPathTraversalCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Netsparker/Traversal", message: "Testing path traversal and SSRF vectors" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 5 : 8;
  const endpoints = discoveredEndpoints.slice(0, budget);

  // Path Traversal
  for (const endpoint of endpoints) {
    for (const param of TRAVERSAL_PARAMS.slice(0, 3)) {
      for (const probe of TRAVERSAL_PROBES.slice(0, 2)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${probe}`;
        const res = await ctxFetch(ctx, testUrl);
        if (!res) continue;

        const body = await res.text().catch(() => "");
        const bodyLower = body.toLowerCase();

        if (
          bodyLower.includes("root:x:0:0") ||
          bodyLower.includes("/bin/bash") ||
          bodyLower.includes("/bin/sh") ||
          (bodyLower.includes("root") && bodyLower.includes("nobody") && bodyLower.includes(":"))
        ) {
          const key = `${endpoint}:path_traversal`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              title: "Path Traversal — /etc/passwd Disclosure",
              category: "Path Traversal",
              severity: "critical",
              endpoint,
              description: `The parameter "${param}" is vulnerable to path traversal, allowing an attacker to read arbitrary files from the server filesystem. The /etc/passwd file was successfully read.`,
              evidence: `GET ${testUrl}\n\nPayload: ${probe}\nFile content leaked:\n${body.slice(0, 500)}`,
              recommended_fix: "Validate and sanitize all file paths. Use a whitelist of allowed paths. Never concatenate user input into file system paths.",
              cvss_score: 9.1,
              cwe_id: "CWE-22",
              scanner_name: "Netsparker",
              scanner_family: "web",
              confidence: 0.97,
            });
            emit({ type: "log", message: `  [CRITICAL] Path traversal at ${endpoint} param=${param}` });
          }
          break;
        }
      }
    }
  }

  // SSRF probes
  for (const endpoint of endpoints.slice(0, 3)) {
    for (const param of SSRF_PARAMS.slice(0, 3)) {
      const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(SSRF_TARGET)}`;
      const res = await ctxFetch(ctx, testUrl);
      if (!res) continue;

      const body = await res.text().catch(() => "");

      if (
        body.includes("ami-id") ||
        body.includes("instance-id") ||
        body.includes("iam/security-credentials") ||
        body.includes("169.254.169.254")
      ) {
        const key = `${endpoint}:ssrf`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push({
            title: "Server-Side Request Forgery (SSRF) — AWS Metadata",
            category: "SSRF",
            severity: "critical",
            endpoint,
            description: `The parameter "${param}" can be used to make the server send requests to the AWS EC2 metadata endpoint (169.254.169.254). This can expose IAM credentials and allow full AWS account compromise.`,
            evidence: `GET ${testUrl}\nMetadata endpoint response:\n${body.slice(0, 500)}`,
            recommended_fix: "Block server-side requests to 169.254.169.254 and private IP ranges. Validate and whitelist allowed URLs before making server-side HTTP requests.",
            cvss_score: 9.8,
            cwe_id: "CWE-918",
            scanner_name: "Netsparker",
            scanner_family: "web",
            confidence: 0.97,
          });
          emit({ type: "log", message: `  [CRITICAL] SSRF to AWS metadata at ${endpoint} param=${param}` });
        }
      } else {
        emit({ type: "log", message: `  ${endpoint} ${param} — SSRF probe returned ${res.status}` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No path traversal or SSRF vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Netsparker/Traversal",
    message: `Path traversal/SSRF check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
