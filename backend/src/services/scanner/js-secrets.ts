import { ScanContext, ScanFinding, safeFetch } from "./types";

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: ScanFinding["severity"];
  cvss: number;
  cwe: string;
  fix: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Rotate the AWS access key immediately. Use IAM roles instead of embedded credentials." },
  { name: "AWS Secret Key", regex: /aws[_-]secret[_-]?(access[_-]?)?key['":\s=]+[A-Za-z0-9/+=]{40}/gi, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Rotate AWS credentials. Use environment variables or AWS Secrets Manager." },
  { name: "GitHub Personal Access Token", regex: /ghp_[a-zA-Z0-9]{36}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Revoke the token immediately in GitHub settings. Use fine-grained tokens with minimum permissions." },
  { name: "GitHub OAuth Token", regex: /gho_[a-zA-Z0-9]{36}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Revoke the OAuth token immediately." },
  { name: "Stripe Secret Key", regex: /sk_live_[a-zA-Z0-9]{24,}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Rotate the Stripe secret key immediately in your Stripe dashboard." },
  { name: "Stripe Publishable Key", regex: /pk_live_[a-zA-Z0-9]{24,}/g, severity: "medium", cvss: 5.3, cwe: "CWE-200", fix: "Publishable keys are less sensitive but should be treated as secrets." },
  { name: "Google API Key", regex: /AIza[0-9A-Za-z_-]{35}/g, severity: "high", cvss: 7.5, cwe: "CWE-798", fix: "Restrict the API key to specific APIs and domains in Google Cloud Console." },
  { name: "Private RSA Key", regex: /-----BEGIN RSA PRIVATE KEY-----/g, severity: "critical", cvss: 9.8, cwe: "CWE-321", fix: "Remove the private key from client-side code immediately. Regenerate the keypair." },
  { name: "Private Key", regex: /-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", cvss: 9.8, cwe: "CWE-321", fix: "Never embed private keys in client-side JavaScript." },
  { name: "JWT Secret", regex: /jwt[_-]?secret['":\s=]+['"][^'"]{8,}/gi, severity: "critical", cvss: 9.1, cwe: "CWE-798", fix: "Rotate the JWT secret. Store secrets in environment variables, not source code." },
  { name: "Database Connection String", regex: /(?:mongodb|postgres|mysql|mssql):\/\/[^:]+:[^@]+@[^\s'"]+/gi, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Remove database credentials from source code. Use environment variables." },
  { name: "Hardcoded Password", regex: /password['":\s=]+['"][^'"]{6,}/gi, severity: "high", cvss: 7.5, cwe: "CWE-259", fix: "Never hardcode passwords. Use environment variables or a secrets manager." },
  { name: "Slack Webhook URL", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: "medium", cvss: 5.3, cwe: "CWE-200", fix: "Regenerate the Slack webhook URL. Treat webhook URLs as secrets." },
  { name: "SendGrid API Key", regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: "high", cvss: 7.5, cwe: "CWE-798", fix: "Rotate your SendGrid API key immediately." },
  { name: "Twilio API Key", regex: /SK[a-zA-Z0-9]{32}/g, severity: "high", cvss: 7.5, cwe: "CWE-798", fix: "Rotate your Twilio API credentials." },
  { name: "Bearer Token", regex: /Authorization['":\s]+['"]Bearer [a-zA-Z0-9_-]{20,}/gi, severity: "high", cvss: 8.1, cwe: "CWE-200", fix: "Do not embed authorization tokens in JavaScript files." },
  // Enhanced patterns
  { name: "OpenAI API Key", regex: /sk-[a-zA-Z0-9]{48}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Revoke the OpenAI API key immediately in your OpenAI account settings." },
  { name: "Anthropic API Key", regex: /sk-ant-[a-zA-Z0-9\-]{90,}/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Revoke the Anthropic API key immediately." },
  { name: "MongoDB URI", regex: /mongodb(\+srv)?:\/\/[^\s"']+/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Remove the MongoDB URI from code. Use environment variables." },
  { name: "PostgreSQL URI", regex: /postgres(ql)?:\/\/[^\s"']+/g, severity: "critical", cvss: 9.8, cwe: "CWE-798", fix: "Remove the PostgreSQL URI from code. Use environment variables." },
  { name: "Private Key Block", regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", cvss: 9.8, cwe: "CWE-321", fix: "Never expose private keys in client code. Rotate the key immediately." },
  { name: "JWT Token", regex: /eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/g, severity: "high", cvss: 7.5, cwe: "CWE-200", fix: "Do not embed live JWT tokens in client-side code." },
  { name: "Twilio Account SID", regex: /AC[a-zA-Z0-9]{32}/g, severity: "high", cvss: 7.5, cwe: "CWE-798", fix: "Rotate your Twilio Account SID and auth token immediately." },
];

export async function runJsSecretScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/JS-Secrets", message: "Scanning JavaScript files for hardcoded secrets" });

  // Collect JS file URLs
  const jsUrls: string[] = [];

  // First parse the homepage for script tags
  const homeRes = await safeFetch(targetUrl);
  if (homeRes) {
    const html = await homeRes.text().catch(() => "");
    const scriptMatches = [...html.matchAll(/src=["']([^"']+\.js(?:\?[^"']*)?)['"]/g)];
    for (const m of scriptMatches) {
      try {
        const full = new URL(m[1], targetUrl).toString();
        if (!jsUrls.includes(full)) jsUrls.push(full);
      } catch { /* skip */ }
    }
  }

  // Add well-known JS bundle paths
  const base = new URL(targetUrl);
  const commonJs = ["/main.js", "/app.js", "/bundle.js", "/static/js/main.chunk.js", "/assets/index.js", "/js/app.js"];
  for (const p of commonJs) {
    const url = `${base.origin}${p}`;
    if (!jsUrls.includes(url)) jsUrls.push(url);
  }

  const budget = profile === "quick" ? 3 : profile === "standard" ? 8 : 15;
  emit({ type: "log", message: `Scanning ${Math.min(jsUrls.length, budget)} JS files for secrets` });

  for (const jsUrl of jsUrls.slice(0, budget)) {
    const res = await safeFetch(jsUrl);
    if (!res || res.status !== 200) continue;

    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("javascript") && !ct.includes("text") && !jsUrl.endsWith(".js")) continue;

    const code = await res.text().catch(() => "");
    if (code.length < 10) continue;

    emit({ type: "log", message: `  Scanning ${jsUrl.split("/").pop() ?? jsUrl} (${Math.round(code.length / 1024)}KB)` });

    for (const pattern of SECRET_PATTERNS) {
      const matches = [...code.matchAll(pattern.regex)];
      for (const match of matches.slice(0, 2)) {
        const key = `${jsUrl}:${pattern.name}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const offset = match.index ?? 0;
        const lineNumber = code.slice(0, offset).split("\n").length;
        const context = code.slice(Math.max(0, offset - 30), offset + Math.min(match[0].length + 30, 100));
        // Redact the actual secret value in evidence
        const redacted = match[0].replace(/[a-zA-Z0-9_/+=]{8,}$/, "****REDACTED****");

        findings.push({
          title: `Hardcoded Secret in JavaScript: ${pattern.name}`,
          category: "Secrets Exposure",
          severity: pattern.severity,
          endpoint: jsUrl,
          description: `A ${pattern.name} was found hardcoded in a client-side JavaScript file. Anyone who visits the site can extract this credential from their browser's developer tools.`,
          evidence: `File: ${jsUrl}\nLine: ${lineNumber}\nSecret Type: ${pattern.name}\nContext: ...${context.replace(match[0], redacted)}...`,
          recommended_fix: pattern.fix,
          cvss_score: pattern.cvss,
          cwe_id: pattern.cwe,
          scanner_name: "Bug-Finder/Secrets",
          scanner_family: "web",
          confidence: 0.88,
        });
        emit({ type: "log", message: `  [SECRET] ${pattern.name} in ${jsUrl.split("/").pop()}` });
      }
    }
  }

  // ── Exposed .env file check ──────────────────────────────────────────────────
  const envPaths = ["/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev"];
  const base2 = new URL(targetUrl);
  for (const envPath of envPaths) {
    const envUrl = `${base2.origin}${envPath}`;
    try {
      const envRes = await safeFetch(envUrl);
      if (envRes && envRes.status === 200) {
        const body = await envRes.text().catch(() => "");
        if (body.includes("=") && body.length > 10) {
          const key = `env-exposed:${envPath}`;
          if (!seen.has(key)) {
            seen.add(key);
            findings.push({
              title: `Exposed Environment File: ${envPath}`,
              category: "Secrets Exposure",
              severity: "critical",
              endpoint: envUrl,
              description: `The file ${envPath} is publicly accessible. Environment files often contain database credentials, API keys, and other sensitive configuration values that should never be exposed.`,
              evidence: `URL: ${envUrl}\nStatus: 200 OK\nContent preview: ${body.slice(0, 200).replace(/\n/g, " ").substring(0, 150)}...`,
              recommended_fix: "Block access to .env files via web server configuration. Add /.env to .gitignore and rotate any exposed credentials immediately.",
              cvss_score: 9.8,
              cwe_id: "CWE-538",
              scanner_name: "Bug-Finder/Secrets",
              scanner_family: "web",
              confidence: 0.99,
            });
            emit({ type: "log", message: `  [CRITICAL] Exposed .env file at ${envUrl}` });
          }
        }
      }
    } catch { /* skip */ }
  }

  // ── robots.txt path discovery ────────────────────────────────────────────────
  try {
    const robotsUrl = `${base2.origin}/robots.txt`;
    const robotsRes = await safeFetch(robotsUrl);
    if (robotsRes && robotsRes.status === 200) {
      const robotsBody = await robotsRes.text().catch(() => "");
      const disallowPaths = [...robotsBody.matchAll(/^Disallow:\s*(.+)$/gm)]
        .map(m => m[1]?.trim())
        .filter(Boolean)
        .filter(p => p !== "/" && p!.length > 1) as string[];
      if (disallowPaths.length > 0) {
        findings.push({
          title: "Hidden Paths Discovered via robots.txt",
          category: "Information Disclosure",
          severity: "info",
          endpoint: robotsUrl,
          description: `The robots.txt file reveals ${disallowPaths.length} disallowed path(s) that the site owner likely wants to keep private. Attackers can use this to discover admin panels, backup files, and sensitive endpoints.`,
          evidence: `Disallowed paths:\n${disallowPaths.slice(0, 20).join("\n")}`,
          recommended_fix: "Do not rely on robots.txt for security through obscurity. Protect sensitive paths with proper authentication and access controls.",
          cvss_score: 3.1,
          cwe_id: "CWE-200",
          scanner_name: "Bug-Finder/Secrets",
          scanner_family: "web",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [INFO] robots.txt reveals ${disallowPaths.length} hidden paths` });
      }
    }
  } catch { /* skip */ }

  emit({ type: "engine_done", engine: "Bug-Finder/JS-Secrets", message: `JS secret scan complete — ${findings.length} secret(s) found` });
  return findings;
}
