import { ScanContext, ScanFinding, safeFetch } from "./types";

interface SensitivePathCheck {
  path: string;
  title: string;
  severity: ScanFinding["severity"];
  description: string;
  fix: string;
  cvss: number;
  cwe: string;
  detectFn?: (status: number, body: string, headers: Headers) => boolean;
}

const SENSITIVE_PATHS: SensitivePathCheck[] = [
  {
    path: "/.env",
    title: "Exposed .env File",
    severity: "critical",
    description: "A .env file is publicly accessible, potentially exposing API keys, database credentials, and other secrets.",
    fix: "Block access to .env files at the web server level and never serve them publicly.",
    cvss: 9.8,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && (body.includes("=") || body.includes("SECRET") || body.includes("PASSWORD") || body.includes("KEY")),
  },
  {
    path: "/.git/config",
    title: "Exposed .git Directory",
    severity: "critical",
    description: "The .git directory is publicly accessible. Attackers can reconstruct the entire source code.",
    fix: "Block web access to .git directories in your web server configuration.",
    cvss: 9.1,
    cwe: "CWE-538",
    detectFn: (status, body) => status === 200 && (body.includes("[core]") || body.includes("repositoryformatversion")),
  },
  {
    path: "/phpinfo.php",
    title: "PHP Info Page Exposed",
    severity: "high",
    description: "A phpinfo.php page is publicly accessible, disclosing PHP configuration, extensions, and server paths.",
    fix: "Remove phpinfo.php from production. Never expose PHP configuration publicly.",
    cvss: 7.5,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && body.toLowerCase().includes("php version"),
  },
  {
    path: "/admin",
    title: "Admin Panel Publicly Accessible",
    severity: "high",
    description: "The /admin path is accessible without apparent authentication.",
    fix: "Restrict admin interfaces to specific IP ranges or require strong multi-factor authentication.",
    cvss: 7.3,
    cwe: "CWE-284",
    detectFn: (status) => status === 200,
  },
  {
    path: "/backup.zip",
    title: "Backup Archive Exposed",
    severity: "critical",
    description: "A backup archive file is publicly downloadable, potentially exposing the entire application codebase.",
    fix: "Remove backup files from the web root and store them in a private, access-controlled location.",
    cvss: 9.8,
    cwe: "CWE-538",
    detectFn: (status, _body, headers) => status === 200 && (headers.get("content-type") ?? "").includes("zip"),
  },
  {
    path: "/robots.txt",
    title: "Sensitive Paths Disclosed in robots.txt",
    severity: "info",
    description: "The robots.txt file discloses paths that should not be crawled, potentially revealing sensitive areas.",
    fix: "Review robots.txt to ensure it does not expose sensitive internal paths.",
    cvss: 2.5,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && (body.includes("Disallow: /admin") || body.includes("Disallow: /api") || body.includes("Disallow: /internal")),
  },
  {
    path: "/.DS_Store",
    title: "macOS .DS_Store File Exposed",
    severity: "medium",
    description: "A .DS_Store file is publicly accessible, revealing directory structure and filenames.",
    fix: "Add .DS_Store to .gitignore and configure your web server to block access to these files.",
    cvss: 4.3,
    cwe: "CWE-538",
    detectFn: (status) => status === 200,
  },
  {
    path: "/server-status",
    title: "Apache Server Status Page Exposed",
    severity: "medium",
    description: "The Apache server-status page is publicly accessible, revealing server internals.",
    fix: "Restrict access to /server-status to localhost only.",
    cvss: 5.3,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && (body.includes("Apache") || body.includes("Server Status")),
  },
  {
    path: "/api/v1/users",
    title: "Unauthenticated API User Listing",
    severity: "high",
    description: "The /api/v1/users endpoint responds with data without requiring authentication.",
    fix: "Require authentication tokens on all API endpoints that expose user data.",
    cvss: 7.5,
    cwe: "CWE-306",
    detectFn: (status, body) => status === 200 && (body.includes("[") || body.includes("email") || body.includes("username")),
  },
  {
    path: "/.well-known/security.txt",
    title: "Security.txt Not Configured",
    severity: "info",
    description: "No security.txt file found. This file helps researchers report vulnerabilities.",
    fix: "Create a /.well-known/security.txt file with contact and vulnerability disclosure policy.",
    cvss: 0,
    cwe: "CWE-693",
    detectFn: (status) => status !== 200,
  },
  {
    path: "/swagger.json",
    title: "Swagger/OpenAPI Spec Publicly Exposed",
    severity: "medium",
    description: "The Swagger/OpenAPI specification is publicly accessible, revealing all API endpoints and parameters.",
    fix: "Require authentication to access API documentation in production.",
    cvss: 5.3,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && (body.includes('"swagger"') || body.includes('"openapi"')),
  },
  {
    path: "/api-docs",
    title: "API Documentation Publicly Exposed",
    severity: "medium",
    description: "Interactive API documentation is publicly accessible without authentication.",
    fix: "Restrict API documentation access in production environments.",
    cvss: 5.3,
    cwe: "CWE-200",
    detectFn: (status, body) => status === 200 && (body.includes("swagger") || body.includes("Swagger") || body.includes("API")),
  },
];

export async function runReconCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Nikto/Recon", message: "Probing for exposed files and sensitive paths" });

  const base = new URL(targetUrl);
  const budget = profile === "quick" ? 5 : profile === "standard" ? 9 : SENSITIVE_PATHS.length;
  const checks = SENSITIVE_PATHS.slice(0, budget);

  for (const check of checks) {
    const url = `${base.origin}${check.path}`;
    const res = await safeFetch(url, { redirect: "follow" });

    if (!res) {
      emit({ type: "log", message: `  ${check.path} — unreachable` });
      continue;
    }

    const body = await res.text().catch(() => "");
    const detected = check.detectFn
      ? check.detectFn(res.status, body, res.headers)
      : res.status === 200;

    if (detected) {
      findings.push({
        title: check.title,
        category: "Information Disclosure",
        severity: check.severity,
        endpoint: url,
        description: check.description,
        evidence: `GET ${url}\nHTTP ${res.status} ${res.statusText}\nContent-Type: ${res.headers.get("content-type") ?? "unknown"}\n\nBody preview:\n${body.slice(0, 300)}`,
        recommended_fix: check.fix,
        cvss_score: check.cvss,
        cwe_id: check.cwe,
        scanner_name: "Nikto",
        scanner_family: "web",
        confidence: 0.92,
      });
      emit({ type: "log", message: `  [FOUND] ${check.path} — ${check.title}` });
    } else {
      emit({ type: "log", message: `  ${check.path} — OK (${res.status})` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Nikto/Recon",
    message: `Recon complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
