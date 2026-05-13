import { ScanContext, ScanFinding, safeFetch } from "./types";
import * as crypto from "crypto";

// Shannon entropy — high-entropy strings are more likely real secrets, not placeholders
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, n) => sum + (n / len) * Math.log2(n / len), 0);
}

// Validate an AWS access key via STS GetCallerIdentity (no billing impact, works with any valid key)
async function validateAwsKey(accessKeyId: string, secretKey?: string): Promise<"valid" | "invalid" | "unknown"> {
  if (!secretKey) return "unknown";
  try {
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const datetime = new Date().toISOString().replace(/[:-]/g, "").slice(0, 15) + "Z";
    const region = "us-east-1";
    const service = "sts";
    const host = "sts.amazonaws.com";
    const body = "Action=GetCallerIdentity&Version=2011-06-15";
    const payloadHash = crypto.createHash("sha256").update(body).digest("hex");
    const canonicalHeaders = `content-type:application/x-www-form-urlencoded\nhost:${host}\nx-amz-date:${datetime}\n`;
    const signedHeaders = "content-type;host;x-amz-date";
    const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
    const credentialScope = `${date}/${region}/${service}/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${datetime}\n${credentialScope}\n${crypto.createHash("sha256").update(canonicalRequest).digest("hex")}`;
    const hmac = (key: Buffer | string, data: string) => crypto.createHmac("sha256", key).update(data).digest();
    const signingKey = hmac(hmac(hmac(hmac(`AWS4${secretKey}`, date), region), service), "aws4_request");
    const signature = hmac(signingKey, stringToSign).toString("hex");
    const auth = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    const res = await fetch(`https://${host}/`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Amz-Date": datetime, "Authorization": auth },
      body,
      signal: AbortSignal.timeout(6000),
    });
    // 200 = valid; 403 with InvalidClientTokenId = invalid key; 403 with AccessDenied = valid key (no STS permission)
    if (res.status === 200) return "valid";
    const text = await res.text().catch(() => "");
    if (text.includes("InvalidClientTokenId")) return "invalid";
    if (text.includes("AccessDenied") || text.includes("AuthFailure")) return "valid";
    return "unknown";
  } catch { return "unknown"; }
}

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
  // Match password = "actualvalue" but exclude placeholder text (phrases with spaces, common placeholder words)
  { name: "Hardcoded Password", regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'" \t]{8,}['"]/gi, severity: "high", cvss: 7.5, cwe: "CWE-259", fix: "Never hardcode passwords. Use environment variables or a secrets manager." },
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

    // Placeholder strings that appear in credential patterns but are not real secrets
    const PLACEHOLDER_PHRASES = ["enter your", "your password", "must be", "please enter", "confirm your", "example", "placeholder", "replace with", "put your", "insert your", "change me", "changeme", "todo", "fixme", "xxxxxxxxx"];

    for (const pattern of SECRET_PATTERNS) {
      const matches = [...code.matchAll(pattern.regex)];
      for (const match of matches.slice(0, 2)) {
        const key = `${jsUrl}:${pattern.name}`;
        if (seen.has(key)) continue;

        // Skip obvious placeholder values
        const matchLower = match[0].toLowerCase();
        if (PLACEHOLDER_PHRASES.some(p => matchLower.includes(p))) continue;

        // Entropy gate: secret-looking strings should have high randomness.
        // Extract the credential portion (last token after = : or space).
        const credPart = match[0].split(/[=:\s"']+/).pop() ?? match[0];
        if (credPart.length >= 8) {
          const entropy = shannonEntropy(credPart);
          // Low entropy strings (<3.0) are likely template names or test fixtures
          if (entropy < 3.0 && !match[0].includes("-----BEGIN")) {
            emit({ type: "log", message: `  Skipping low-entropy match (${entropy.toFixed(1)}) for ${pattern.name}` });
            continue;
          }
        }

        seen.add(key);

        const offset = match.index ?? 0;
        const lineNumber = code.slice(0, offset).split("\n").length;
        const context = code.slice(Math.max(0, offset - 30), offset + Math.min(match[0].length + 30, 100));
        // Redact the actual secret value in evidence
        const redacted = match[0].replace(/[a-zA-Z0-9_/+=]{8,}$/, "****REDACTED****");

        // AWS key validation — attempt live STS call to confirm key is active
        let validationNote = "";
        let confidence = 0.88;
        if (pattern.name === "AWS Access Key") {
          const awsKeyId = match[0];
          // Try to find the secret key near the access key in the same file (within 500 chars)
          const nearby = code.slice(Math.max(0, offset - 250), offset + 250);
          const secretMatch = nearby.match(/[A-Za-z0-9/+=]{40}/);
          const awsSecretKey = secretMatch?.[0];
          const validationResult = await validateAwsKey(awsKeyId, awsSecretKey);
          if (validationResult === "valid") {
            validationNote = "\nLIVE VALIDATION: AWS STS confirmed this key is ACTIVE.";
            confidence = 0.99;
          } else if (validationResult === "invalid") {
            validationNote = "\nLIVE VALIDATION: AWS STS rejected this key — likely rotated or test data.";
            confidence = 0.30;
            if (confidence < 0.5) {
              emit({ type: "log", message: `  AWS key validation: invalid/rotated — skipping` });
              seen.delete(key); // allow re-check from another match
              continue;
            }
          } else {
            validationNote = "\nLIVE VALIDATION: Could not confirm (network/STS unavailable).";
          }
        }

        // Share with session store for use by downstream modules
        if (credPart.length > 12 && confidence >= 0.8) {
          ctx.sessionStore.discoveredCredentials.push({
            key: pattern.name,
            value: credPart.slice(0, 8) + "****", // partial — not fully stored
            source: jsUrl,
          });
        }

        findings.push({
          title: `Hardcoded Secret in JavaScript: ${pattern.name}`,
          category: "Secrets Exposure",
          severity: pattern.severity,
          endpoint: jsUrl,
          description: `A ${pattern.name} was found hardcoded in a client-side JavaScript file. Anyone who visits the site can extract this credential from their browser's developer tools.`,
          evidence: [
            `File: ${jsUrl}`,
            `Line: ${lineNumber}`,
            `Secret Type: ${pattern.name}`,
            `Entropy: ${shannonEntropy(credPart).toFixed(2)} bits/char`,
            `Context: ...${context.replace(match[0], redacted)}...`,
            validationNote,
          ].join("\n"),
          recommended_fix: pattern.fix,
          cvss_score: pattern.cvss,
          cwe_id: pattern.cwe,
          scanner_name: "Bug-Finder/Secrets",
          scanner_family: "web",
          confidence,
        });
        emit({ type: "log", message: `  [SECRET] ${pattern.name} in ${jsUrl.split("/").pop()} (entropy: ${shannonEntropy(credPart).toFixed(1)})` });
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
