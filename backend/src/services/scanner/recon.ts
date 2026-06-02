import { ScanContext, ScanFinding, safeFetch } from "./types";
import { checkSpaFallback } from "./spa-detector";

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
    description: "The /admin path is accessible without apparent authentication. The page did not redirect to a login screen.",
    fix: "Restrict admin interfaces to specific IP ranges or require strong multi-factor authentication.",
    cvss: 7.3,
    cwe: "CWE-284",
    // Must not redirect to a login page AND must contain admin-specific UI keywords.
    // A catch-all SPA returning 200 with "settings" somewhere is excluded by requiring
    // at least two of the admin-specific indicators.
    detectFn: (status, body, headers) => {
      if (status !== 200) return false;
      // If redirected to /login, /signin, or /auth — not a real open admin panel
      const finalUrl = headers.get("x-final-url") ?? "";
      if (finalUrl.includes("login") || finalUrl.includes("signin") || finalUrl.includes("auth")) return false;
      const lower = body.toLowerCase();
      const adminIndicators = ["dashboard", "manage users", "user list", "admin panel", "logout", "sign out", "welcome, admin", "administration"].filter(kw => lower.includes(kw));
      return adminIndicators.length >= 2;
    },
  },
  {
    path: "/backup.zip",
    title: "Backup Archive Exposed",
    severity: "critical",
    description: "A backup archive file is publicly downloadable, potentially exposing the entire application codebase.",
    fix: "Remove backup files from the web root and store them in a private, access-controlled location.",
    cvss: 9.8,
    cwe: "CWE-538",
    // ZIP magic bytes: PK\x03\x04 at start, or Content-Type includes zip
    detectFn: (status, body, headers) => status === 200 && (
      (headers.get("content-type") ?? "").includes("zip") ||
      body.startsWith("PK") ||
      body.charCodeAt(0) === 0x50 && body.charCodeAt(1) === 0x4B
    ),
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
    // DS_Store is a binary format — first 4 bytes are always 0x00000001 (Bud1 magic)
    detectFn: (status, body) => status === 200 && (body.includes("Bud1") || body.charCodeAt(0) === 0),
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
    description: "The /api/v1/users endpoint responds with structured user data without requiring authentication.",
    fix: "Require authentication tokens on all API endpoints that expose user data.",
    cvss: 7.5,
    cwe: "CWE-306",
    // Must be JSON and contain structured user fields — not just any page with the word "email"
    detectFn: (status, body, headers) => {
      if (status !== 200) return false;
      const ct = headers.get("content-type") ?? "";
      if (!ct.includes("json")) return false;
      try {
        const parsed = JSON.parse(body);
        const items = Array.isArray(parsed) ? parsed : (parsed?.items ?? parsed?.data ?? parsed?.users ?? []);
        if (!Array.isArray(items) || items.length === 0) return false;
        const first = items[0];
        return typeof first === "object" && first !== null && ("email" in first || "username" in first || "id" in first);
      } catch { return false; }
    },
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
    // Require structured Swagger UI or ReDoc markers — "API" alone is too broad
    detectFn: (status, body) => status === 200 && (
      body.includes("swagger-ui") || body.includes("SwaggerUIBundle") ||
      body.includes("redoc") || body.includes("\"swagger\"") || body.includes("\"openapi\"")
    ),
  },
  {
    path: "/.git/HEAD",
    title: "Git Repository HEAD Reference Exposed",
    severity: "critical",
    description: "The .git/HEAD file is publicly accessible. Combined with other .git/ files, the full source code can be reconstructed.",
    fix: "Block all access to .git/ directories at the web server configuration level.",
    cvss: 9.1,
    cwe: "CWE-538",
    detectFn: (status, body) => status === 200 && (body.startsWith("ref: refs/") || body.trim().match(/^[0-9a-f]{40}$/) !== null),
  },
  {
    path: "/backup.sql",
    title: "SQL Backup File Exposed",
    severity: "critical",
    description: "A SQL dump file is publicly accessible, potentially containing the entire database including user credentials.",
    fix: "Move backup files outside the web root. Use access controls and encryption for database backups.",
    cvss: 9.8,
    cwe: "CWE-538",
    detectFn: (status, body) => status === 200 && (
      body.includes("CREATE TABLE") || body.includes("INSERT INTO") || body.includes("-- MySQL dump") || body.includes("-- PostgreSQL")
    ),
  },
  {
    path: "/wp-login.php",
    title: "WordPress Login Page Exposed",
    severity: "medium",
    description: "The WordPress admin login page is publicly accessible and may be subject to brute-force attacks.",
    fix: "Restrict access to wp-login.php by IP. Enable CAPTCHA and account lockout.",
    cvss: 5.3,
    cwe: "CWE-307",
    detectFn: (status, body) => status === 200 && body.includes("user_login") && body.includes("user_pass"),
  },
];

export async function runReconCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Recon", message: "Probing for exposed files and sensitive paths" });

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

    // ── SPA fallback guard ────────────────────────────────────────────────────
    // If the target is a SPA (React/Vite/etc.) it serves its index.html shell
    // for every unknown route. Detecting /.env, /wp-login.php, /actuator, etc.
    // on a SPA is always a false positive — the app returned its frontend, not
    // the real resource. Suppress the finding and do not report it.
    const spaCheck = checkSpaFallback(res, body, ctx.spaSignature);
    if (spaCheck.isFallback) {
      emit({
        type: "log",
        message: `  ${check.path} — SUPPRESSED (${spaCheck.reason} | confidence ${spaCheck.confidence.toFixed(1)})`,
      });
      continue;
    }

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
        evidence: [
          `GET ${url}`,
          `HTTP ${res.status} ${res.statusText}`,
          `Content-Type: ${res.headers.get("content-type") ?? "unknown"}`,
          `Content-Length: ${res.headers.get("content-length") ?? body.length} bytes`,
          ``,
          `Body preview (first 400 bytes):`,
          body.slice(0, 400),
        ].join("\n"),
        recommended_fix: check.fix,
        cvss_score: check.cvss,
        cwe_id: check.cwe,
        scanner_name: "Bug-Finder/Recon",
        scanner_family: "web",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [FOUND] ${check.path} — ${check.title}` });
    } else {
      emit({ type: "log", message: `  ${check.path} — OK (${res.status})` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Recon",
    message: `Recon complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
