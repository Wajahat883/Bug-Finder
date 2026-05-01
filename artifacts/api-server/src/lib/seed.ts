import { ObjectId } from "mongodb";
import { col } from "./db";
import { logger } from "./logger";

const TARGETS = [
  { url: "https://example.com", domain: "example.com", tags: ["web", "production"] },
  { url: "https://api.acme.io", domain: "api.acme.io", tags: ["api", "staging"] },
  { url: "https://shop.testcorp.dev", domain: "shop.testcorp.dev", tags: ["ecommerce", "production"] },
  { url: "https://auth.bugapp.io", domain: "auth.bugapp.io", tags: ["auth", "critical"] },
  { url: "https://admin.devsite.net", domain: "admin.devsite.net", tags: ["admin", "internal"] },
];

const FINDING_TEMPLATES = [
  { title: "Missing Content-Security-Policy Header", category: "Security Headers", severity: "high", cvss: 7.4, cwe: "CWE-693", scanner: "tls_check", fix: "Add Content-Security-Policy header to all HTTP responses to prevent XSS attacks." },
  { title: "SQL Injection Vulnerability", category: "Injection", severity: "critical", cvss: 9.8, cwe: "CWE-89", scanner: "sqli_scanner", fix: "Use parameterized queries or prepared statements to prevent SQL injection." },
  { title: "Cross-Site Scripting (XSS)", category: "XSS", severity: "high", cvss: 8.2, cwe: "CWE-79", scanner: "xss_validator", fix: "Encode all user-supplied output. Implement a strict Content Security Policy." },
  { title: "Insecure Direct Object Reference (IDOR)", category: "Access Control", severity: "critical", cvss: 9.1, cwe: "CWE-639", scanner: "idor_checker", fix: "Implement proper access controls and validate user authorization for each object." },
  { title: "Missing HSTS Header", category: "TLS/Transport", severity: "medium", cvss: 5.3, cwe: "CWE-319", scanner: "tls_check", fix: "Add Strict-Transport-Security header with max-age of at least 31536000 seconds." },
  { title: "Exposed robots.txt with Sensitive Paths", category: "Information Disclosure", severity: "info", cvss: 2.0, cwe: "CWE-200", scanner: "discovery", fix: "Review robots.txt contents. Avoid disclosing sensitive or admin paths." },
  { title: "Cookie Missing HttpOnly Flag", category: "Session Management", severity: "medium", cvss: 5.0, cwe: "CWE-1004", scanner: "cookie_checker", fix: "Set the HttpOnly flag on all session and authentication cookies." },
  { title: "Overly Permissive CORS Policy", category: "CORS", severity: "high", cvss: 7.5, cwe: "CWE-346", scanner: "cors_check", fix: "Restrict CORS to trusted origins only. Avoid using wildcard (*)." },
  { title: "Missing X-Frame-Options Header", category: "Security Headers", severity: "medium", cvss: 4.3, cwe: "CWE-1021", scanner: "tls_check", fix: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks." },
  { title: "Open Port Exposing Redis", category: "Network", severity: "high", cvss: 8.0, cwe: "CWE-284", scanner: "port_scanner", fix: "Restrict Redis port access to internal networks only. Enable Redis AUTH." },
  { title: "Reflected XSS in Search Parameter", category: "XSS", severity: "high", cvss: 7.8, cwe: "CWE-79", scanner: "xss_validator", fix: "Sanitize and encode the search parameter before reflecting it in the response." },
  { title: "Subdomain Takeover Risk", category: "DNS", severity: "critical", cvss: 9.0, cwe: "CWE-350", scanner: "dns_check", fix: "Remove dangling DNS records pointing to decommissioned services." },
  { title: "Sensitive Data in URL Parameters", category: "Information Disclosure", severity: "medium", cvss: 5.5, cwe: "CWE-598", scanner: "discovery", fix: "Move sensitive data from URL query strings to POST body or headers." },
  { title: "Missing Rate Limiting on Login Endpoint", category: "Authentication", severity: "medium", cvss: 5.9, cwe: "CWE-307", scanner: "auth_tester", fix: "Implement rate limiting on authentication endpoints to prevent brute-force attacks." },
  { title: "JWT with Weak Signing Secret", category: "Authentication", severity: "critical", cvss: 9.5, cwe: "CWE-330", scanner: "auth_tester", fix: "Use a strong, randomly-generated secret (256 bits) for JWT signing." },
];

const ENDPOINTS = ["/api/users", "/api/orders", "/api/products", "/search", "/login", "/admin", "/api/data", "/api/auth", "/api/reports"];
const VALIDATION_STATUSES = ["real", "real", "real", "false_positive", "informational", "pending"];
const SCAN_PROFILES = ["quick", "standard", "deep"] as const;
const SCAN_STATUSES = ["completed", "completed", "completed", "completed", "running", "failed", "queued"] as const;

function randomItem<T>(arr: readonly T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function daysAgo(n: number): Date {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d;
}

export async function seedData() {
  const scanJobsCol = col("scan_jobs");
  const findingsCol = col("findings");
  const targetsCol = col("targets");
  const activityCol = col("activity_events");
  const settingsCol = col("settings");
  const remediationsCol = col("remediations");

  const existingCount = await scanJobsCol.countDocuments();
  if (existingCount > 0) {
    logger.info("Database already seeded, skipping");
    return;
  }

  logger.info("Seeding demo data...");

  // Seed settings
  await settingsCol.insertOne({
    default_export_format: "json",
    notifications_enabled: true,
    ai_analysis_enabled: true,
    max_concurrent_scans: 5,
    webhook_url: "",
    api_key: `bbp_${Math.random().toString(36).substring(2, 18)}`,
    github_login: "Wajahat883",
    created_at: new Date(),
    updated_at: new Date(),
  });

  // Seed targets and scan jobs
  const targetIds: ObjectId[] = [];
  const jobIds: ObjectId[] = [];

  for (let t = 0; t < TARGETS.length; t++) {
    const targetData = TARGETS[t];
    const targInsert = await targetsCol.insertOne({
      url: targetData.url,
      domain: targetData.domain,
      last_scanned: daysAgo(randomInt(0, 14)),
      total_scans: randomInt(2, 12),
      total_findings: 0,
      critical_findings: 0,
      high_findings: 0,
      risk_score: 0,
      status: "active",
      tags: targetData.tags,
      created_at: daysAgo(randomInt(15, 90)),
    });
    targetIds.push(targInsert.insertedId);
  }

  // Create scan jobs (last 30 days)
  for (let i = 0; i < 18; i++) {
    const targetData = TARGETS[i % TARGETS.length];
    const profile = randomItem(SCAN_PROFILES);
    const status = randomItem(SCAN_STATUSES);
    const createdAt = daysAgo(randomInt(0, 29));
    const startedAt = new Date(createdAt.getTime() + 1000 * 60);
    const completedAt = status === "completed" ? new Date(startedAt.getTime() + 1000 * 60 * randomInt(2, 30)) : undefined;
    const progress = status === "completed" ? 100 : status === "running" ? randomInt(10, 90) : status === "queued" ? 0 : 100;

    const engines = ["tls_check", "header_scan", "cors_check", "cookie_checker", "port_scanner"];
    if (profile !== "quick") engines.push("sqli_scanner", "xss_validator");
    if (profile === "deep") engines.push("idor_checker", "auth_tester", "dns_check");

    const numFindings = status === "completed" ? randomInt(3, 15) : status === "running" ? randomInt(0, 5) : 0;
    let critCount = 0, highCount = 0, medCount = 0, lowCount = 0, infoCount = 0;

    const jobInsert = await scanJobsCol.insertOne({
      target_url: targetData.url,
      scan_profile: profile,
      status,
      progress,
      created_at: createdAt,
      started_at: startedAt,
      completed_at: completedAt,
      findings_count: numFindings,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      info_count: 0,
      risk_score: 0,
      ai_summary: status === "completed" ? generateAiSummary(targetData.domain) : null,
      validation_enabled: Math.random() > 0.5,
      fuzzing_enabled: Math.random() > 0.7,
      bug_bounty_mode: Math.random() > 0.8,
      authorization_acknowledged: true,
      scanner_engines: engines,
      error_message: status === "failed" ? "Scanner timeout after 300 seconds" : null,
    });

    jobIds.push(jobInsert.insertedId);

    // Create findings for completed/running jobs
    for (let f = 0; f < numFindings; f++) {
      const tmpl = randomItem(FINDING_TEMPLATES);
      const valStatus = randomItem(VALIDATION_STATUSES);
      const sev = tmpl.severity as "critical" | "high" | "medium" | "low" | "info";

      if (sev === "critical") critCount++;
      else if (sev === "high") highCount++;
      else if (sev === "medium") medCount++;
      else if (sev === "low") lowCount++;
      else infoCount++;

      const riskScore = Math.round(
        (sev === "critical" ? 10 : sev === "high" ? 9 : sev === "medium" ? 6 : sev === "low" ? 3 : 1) * 0.6 * 10
      );

      const findInsert = await findingsCol.insertOne({
        scan_job_id: jobInsert.insertedId,
        title: tmpl.title,
        category: tmpl.category,
        severity: sev,
        validation_status: valStatus,
        confidence: Math.random() * 0.4 + 0.6,
        endpoint: randomItem(ENDPOINTS),
        description: `${tmpl.title} was detected on ${targetData.domain}. This vulnerability may allow an attacker to compromise the security of the application.`,
        evidence: `HTTP/1.1 200 OK\nServer: nginx/1.18\n...\n[Finding evidence captured at ${new Date().toISOString()}]`,
        recommended_fix: tmpl.fix,
        cvss_score: tmpl.cvss,
        cwe_id: tmpl.cwe,
        risk_score: riskScore,
        scanner_name: tmpl.scanner,
        created_at: completedAt ? new Date(completedAt.getTime() - randomInt(0, 5) * 60000) : new Date(),
        target_url: targetData.url,
      });

      // Create remediation for critical/high findings
      if ((sev === "critical" || sev === "high") && Math.random() > 0.5) {
        const remStatus = randomItem(["pending", "in_progress", "resolved", "wont_fix"] as const);
        await remediationsCol.insertOne({
          finding_id: findInsert.insertedId,
          scan_job_id: jobInsert.insertedId,
          title: `Fix: ${tmpl.title}`,
          description: `Remediation task for ${tmpl.title} found on ${targetData.url}`,
          patch_snippet: generatePatchSnippet(tmpl.category),
          status: remStatus,
          created_at: new Date(),
          updated_at: new Date(),
        });
      }
    }

    // Update job with finding counts
    await scanJobsCol.updateOne(
      { _id: jobInsert.insertedId },
      {
        $set: {
          critical_count: critCount,
          high_count: highCount,
          medium_count: medCount,
          low_count: lowCount,
          info_count: infoCount,
          risk_score: Math.min(100, critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3),
        },
      }
    );

    // Update target totals
    const targetIdx = i % TARGETS.length;
    const targetId = targetIds[targetIdx];
    await targetsCol.updateOne(
      { _id: targetId },
      {
        $set: {
          total_findings: numFindings,
          critical_findings: critCount,
          high_findings: highCount,
          risk_score: Math.min(100, critCount * 25 + highCount * 15 + medCount * 8),
        },
      }
    );
  }

  // Seed activity events
  const activityTypes = ["scan_created", "scan_started", "finding_created", "scan_completed", "ai_summary_ready", "remediation_created"];
  const messages = [
    "New scan job created for example.com",
    "Scan started: Deep profile on api.acme.io",
    "Critical finding detected: SQL Injection on /api/users",
    "Scan completed: 12 findings identified on shop.testcorp.dev",
    "AI summary generated for scan #3",
    "High severity XSS finding on auth.bugapp.io",
    "Remediation task created for CVE-2024-1234",
    "Scan failed: Timeout on admin.devsite.net",
    "New target added: https://newsite.example.com",
    "IDOR vulnerability confirmed on api.acme.io",
  ];

  for (let i = 0; i < 20; i++) {
    await activityCol.insertOne({
      type: randomItem(activityTypes),
      message: randomItem(messages),
      timestamp: daysAgo(randomInt(0, 7)),
      scan_job_id: jobIds[i % jobIds.length],
      severity: randomItem(["critical", "high", "medium", "low", "info", null]),
    });
  }

  logger.info("Demo data seeded successfully");
}

function generateAiSummary(domain: string): string {
  const summaries = [
    `Security assessment of ${domain} identified several critical vulnerabilities requiring immediate attention. The most severe issues include SQL injection and IDOR vulnerabilities that could allow unauthorized data access. Recommend immediate remediation of critical and high severity findings before next deployment.`,
    `Assessment of ${domain} reveals a moderate attack surface with key concerns around missing security headers and cookie misconfiguration. The application lacks proper CSP and HSTS enforcement, increasing XSS and downgrade attack risks. Priority should be given to implementing security headers and reviewing authentication flows.`,
    `Comprehensive scan of ${domain} shows good baseline security posture with some improvements needed. No critical vulnerabilities detected. Medium-severity findings around CORS configuration and rate limiting should be addressed in the next sprint. Low and informational findings are documented for awareness.`,
  ];
  return summaries[Math.floor(Math.random() * summaries.length)];
}

function generatePatchSnippet(category: string): string {
  const patches: Record<string, string> = {
    "Security Headers": `// Add security headers middleware\napp.use((req, res, next) => {\n  res.setHeader('Content-Security-Policy', "default-src 'self'");\n  res.setHeader('X-Frame-Options', 'DENY');\n  res.setHeader('X-Content-Type-Options', 'nosniff');\n  next();\n});`,
    "Injection": `// Use parameterized queries\nconst result = await db.query(\n  'SELECT * FROM users WHERE id = $1',\n  [userId]\n);`,
    "XSS": `// Encode user input before rendering\nimport { escape } from 'html-escaper';\nconst safeValue = escape(userInput);`,
    "CORS": `// Restrict CORS origins\napp.use(cors({\n  origin: ['https://yourdomain.com'],\n  credentials: true\n}));`,
    "Session Management": `// Set secure cookie flags\nres.cookie('session', token, {\n  httpOnly: true,\n  secure: true,\n  sameSite: 'strict',\n  maxAge: 3600000\n});`,
  };
  return patches[category] ?? `// Implement fix for ${category}\n// Refer to OWASP guidelines for remediation steps`;
}
