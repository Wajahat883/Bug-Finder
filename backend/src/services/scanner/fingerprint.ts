import { ScanContext, ScanFinding, safeFetch } from "./types";

interface TechSignature {
  name: string;
  category: string;
  check: (headers: Headers, body: string, url: string) => boolean;
  severity: ScanFinding["severity"];
  description: string;
  fix: string;
  cvss: number;
  cwe: string;
}

const TECH_SIGNATURES: TechSignature[] = [
  {
    name: "WordPress",
    category: "CMS",
    check: (_h, body) => body.includes("/wp-content/") || body.includes("/wp-includes/") || body.includes("wp-json"),
    severity: "medium",
    description: "WordPress CMS detected. WordPress sites are frequently targeted due to vulnerable plugins and themes. Ensure core, plugins, and themes are kept up to date.",
    fix: "Keep WordPress core, plugins, and themes updated. Use a security plugin (Wordfence). Disable XML-RPC if not needed. Change default login URL.",
    cvss: 5.3,
    cwe: "CWE-1035",
  },
  {
    name: "Drupal",
    category: "CMS",
    check: (_h, body) => body.includes("Drupal") || body.includes("/sites/default/") || body.includes("drupal.js"),
    severity: "medium",
    description: "Drupal CMS detected. Drupal has historically had critical remote code execution vulnerabilities (Drupalgeddon).",
    fix: "Keep Drupal core and modules updated. Apply security patches promptly. Disable PHP filter module.",
    cvss: 5.3,
    cwe: "CWE-1035",
  },
  {
    name: "Joomla",
    category: "CMS",
    check: (_h, body) => body.includes("/components/com_") || body.includes("Joomla"),
    severity: "medium",
    description: "Joomla CMS detected. Joomla extensions are frequently vulnerable to SQL injection and remote file inclusion.",
    fix: "Keep Joomla and extensions updated. Restrict admin panel access by IP. Enable two-factor authentication.",
    cvss: 5.3,
    cwe: "CWE-1035",
  },
  {
    name: "Laravel",
    category: "Framework",
    check: (h, body) => (h.get("set-cookie") ?? "").includes("laravel_session") || body.includes("laravel") || (h.get("x-powered-by") ?? "").includes("Laravel"),
    severity: "low",
    description: "Laravel PHP framework detected. Ensure APP_DEBUG is disabled in production and APP_KEY is properly set.",
    fix: "Set APP_DEBUG=false and APP_ENV=production. Ensure .env file is not web-accessible. Rotate APP_KEY periodically.",
    cvss: 3.7,
    cwe: "CWE-200",
  },
  {
    name: "Django",
    category: "Framework",
    check: (h, body) => (h.get("set-cookie") ?? "").includes("csrftoken") || (h.get("set-cookie") ?? "").includes("sessionid") && body.includes("Django") || body.includes("django"),
    severity: "low",
    description: "Django Python framework detected. Ensure DEBUG=False in production and SECRET_KEY is strong.",
    fix: "Set DEBUG=False in settings. Use environment variables for SECRET_KEY. Enable SecurityMiddleware.",
    cvss: 3.1,
    cwe: "CWE-200",
  },
  {
    name: "Ruby on Rails",
    category: "Framework",
    check: (h) => (h.get("set-cookie") ?? "").includes("_session_id") || (h.get("x-powered-by") ?? "").toLowerCase().includes("rails") || (h.get("server") ?? "").toLowerCase().includes("puma"),
    severity: "low",
    description: "Ruby on Rails framework detected. Ensure secret_key_base is strong and RAILS_ENV is set to production.",
    fix: "Set RAILS_ENV=production. Use strong secret_key_base. Keep Rails and gems updated.",
    cvss: 3.1,
    cwe: "CWE-200",
  },
  {
    name: "ASP.NET",
    category: "Framework",
    check: (h) => !!(h.get("x-aspnet-version") || h.get("x-aspnetmvc-version") || (h.get("x-powered-by") ?? "").includes("ASP.NET")),
    severity: "medium",
    description: "ASP.NET framework version disclosed. Version information helps attackers identify known vulnerabilities for the specific .NET version.",
    fix: "Remove X-AspNet-Version and X-Powered-By headers. Keep .NET framework updated. Use latest LTS version.",
    cvss: 5.3,
    cwe: "CWE-200",
  },
  {
    name: "PHP",
    category: "Language",
    check: (h) => !!(h.get("x-powered-by") ?? "").includes("PHP"),
    severity: "low",
    description: "PHP version disclosed via X-Powered-By header. Version disclosure aids attackers in targeting known PHP vulnerabilities.",
    fix: "Set expose_php = Off in php.ini. Remove X-Powered-By header.",
    cvss: 3.7,
    cwe: "CWE-200",
  },
  {
    name: "Express.js",
    category: "Framework",
    check: (h) => (h.get("x-powered-by") ?? "").toLowerCase().includes("express"),
    severity: "low",
    description: "Express.js Node.js framework detected via X-Powered-By header. Framework disclosure reduces attack effort.",
    fix: "Disable X-Powered-By: app.disable('x-powered-by') in Express.",
    cvss: 3.1,
    cwe: "CWE-200",
  },
  {
    name: "Shopify",
    category: "E-commerce",
    check: (_h, body) => body.includes("cdn.shopify.com") || body.includes("shopify"),
    severity: "info",
    description: "Shopify e-commerce platform detected. Ensure third-party apps and custom scripts are vetted for security.",
    fix: "Review installed Shopify apps for security. Use CSP to restrict script sources. Enable 2FA on Shopify admin.",
    cvss: 0,
    cwe: "CWE-200",
  },
  {
    name: "Nginx",
    category: "Web Server",
    check: (h) => (h.get("server") ?? "").toLowerCase().startsWith("nginx"),
    severity: "info",
    description: "Nginx web server detected. Ensure Nginx is kept updated and misconfiguration issues are addressed.",
    fix: "Keep Nginx updated. Disable server_tokens. Apply security hardening best practices.",
    cvss: 0,
    cwe: "CWE-200",
  },
  {
    name: "Apache",
    category: "Web Server",
    check: (h) => (h.get("server") ?? "").toLowerCase().startsWith("apache"),
    severity: "info",
    description: "Apache HTTP Server detected. Verify version is up-to-date and server tokens are minimized.",
    fix: "Set ServerTokens Prod and ServerSignature Off. Keep Apache updated.",
    cvss: 0,
    cwe: "CWE-200",
  },
];

export async function runFingerprintCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Wappalyzer/Fingerprint", message: "Fingerprinting technologies, frameworks, and CMS" });

  const res = await safeFetch(targetUrl, { redirect: "follow" });
  if (!res) {
    emit({ type: "log", message: "Target unreachable for fingerprinting" });
    emit({ type: "engine_done", engine: "Wappalyzer/Fingerprint", message: "Skipped (unreachable)" });
    return findings;
  }

  const body = await res.text().catch(() => "");
  const detected: string[] = [];

  for (const sig of TECH_SIGNATURES) {
    if (sig.check(res.headers, body, targetUrl)) {
      detected.push(sig.name);
      findings.push({
        title: `Technology Detected: ${sig.name} (${sig.category})`,
        category: "Technology Fingerprinting",
        severity: sig.severity,
        endpoint: targetUrl,
        description: sig.description,
        evidence: `Fingerprint matched for ${sig.name}\nURL: ${targetUrl}\nResponse headers:\n${[...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n")}`,
        recommended_fix: sig.fix,
        cvss_score: sig.cvss,
        cwe_id: sig.cwe,
        scanner_name: "Wappalyzer",
        scanner_family: "web",
        confidence: 0.88,
      });
      emit({ type: "log", message: `  Detected: ${sig.name} (${sig.category})` });
    }
  }

  // Check additional sensitive paths for version disclosure
  const versionPaths = ["/wp-login.php", "/administrator/", "/phpmyadmin/", "/manager/html"];
  for (const path of versionPaths) {
    const url = `${new URL(targetUrl).origin}${path}`;
    const r = await safeFetch(url, { redirect: "manual" });
    if (r && r.status === 200) {
      const name = path.includes("wp-login") ? "WordPress Login Page" : path.includes("administrator") ? "Joomla Admin" : path.includes("phpmyadmin") ? "phpMyAdmin" : "Tomcat Manager";
      findings.push({
        title: `Admin Interface Exposed: ${name}`,
        category: "Technology Fingerprinting",
        severity: "high",
        endpoint: url,
        description: `${name} is publicly accessible at ${url}. Admin interfaces should not be exposed to the internet.`,
        evidence: `GET ${url}\nHTTP ${r.status} — panel accessible`,
        recommended_fix: `Restrict access to ${path} to trusted IP addresses only. Consider moving admin interfaces to a separate internal network.`,
        cvss_score: 7.5,
        cwe_id: "CWE-284",
        scanner_name: "Wappalyzer",
        scanner_family: "web",
        confidence: 0.9,
      });
      emit({ type: "log", message: `  Admin panel found: ${url}` });
    }
  }

  if (detected.length === 0) {
    emit({ type: "log", message: "No specific technology signatures detected" });
  } else {
    emit({ type: "log", message: `Technologies identified: ${detected.join(", ")}` });
  }

  emit({ type: "engine_done", engine: "Wappalyzer/Fingerprint", message: `Fingerprinting complete — ${findings.length} finding(s)` });
  return findings;
}
