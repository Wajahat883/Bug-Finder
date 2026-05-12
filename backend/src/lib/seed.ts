import bcrypt from "bcryptjs";
import { col, ObjectId } from "./db";
import { logger } from "./logger";

export async function seedData() {
  const adminEmail = process.env["ADMIN_EMAIL"];
  const adminPassword = process.env["ADMIN_PASSWORD"];

  if (adminEmail && adminPassword) {
    const adminExists = await col("users").findOne({ email: adminEmail });
    if (!adminExists) {
      logger.info("Creating default admin user from env vars...");
      const hashed = await bcrypt.hash(adminPassword, 10);
      await col("users").insertOne({
        _id: new ObjectId(),
        username: "waji_admin",
        email: adminEmail,
        password: hashed,
        role: "admin",
        first_name: "Waji",
        last_name: "Admin",
        created_at: new Date(),
        updated_at: new Date(),
      });
      logger.info({ email: adminEmail }, "Default admin user created");
    }
  }

  const settingsCol = col("settings");

  const existing = await settingsCol.findOne({});
  if (existing) {
    logger.info("Database already seeded, skipping");
    return;
  }

  logger.info("Seeding initial settings...");

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

  logger.info("Settings seeded successfully");

  // Seed demo data if no targets exist
  const targetCount = await col("targets").countDocuments();
  if (targetCount === 0) {
    logger.info("Seeding demo targets, findings, and remediations...");
    await seedDemoData();
  }
}

async function seedDemoData() {
  const now = new Date();
  const pastDate = (days: number) => new Date(now.getTime() - days * 86400000);

  const targets = [
    { url: "https://api.example.com", domain: "api.example.com", risk_score: 85, total_scans: 3, total_findings: 24, critical_findings: 4, high_findings: 8, status: "active", tags: ["production", "api"], tech_stack: ["node", "express", "postgresql", "nginx"], subdomains: ["v1.api.example.com", "internal.api.example.com"], risk_history: [{score: 85, date: now.toISOString()}, {score: 72, date: pastDate(7).toISOString()}, {score: 65, date: pastDate(14).toISOString()}], last_scanned: now, created_at: pastDate(30), updated_at: now },
    { url: "https://www.example.com", domain: "www.example.com", risk_score: 62, total_scans: 2, total_findings: 15, critical_findings: 2, high_findings: 5, status: "active", tags: ["production", "web"], tech_stack: ["react", "next.js", "node", "cloudflare"], subdomains: ["blog.example.com", "shop.example.com"], risk_history: [{score: 62, date: now.toISOString()}, {score: 55, date: pastDate(10).toISOString()}], last_scanned: pastDate(3), created_at: pastDate(20), updated_at: pastDate(3) },
    { url: "https://admin.example.com", domain: "admin.example.com", risk_score: 38, total_scans: 1, total_findings: 8, critical_findings: 0, high_findings: 3, status: "active", tags: ["internal", "admin"], tech_stack: ["python", "django", "postgresql", "apache"], subdomains: [], risk_history: [{score: 38, date: now.toISOString()}], last_scanned: pastDate(5), created_at: pastDate(15), updated_at: pastDate(5) },
    { url: "https://staging.example.com", domain: "staging.example.com", risk_score: 94, total_scans: 2, total_findings: 31, critical_findings: 8, high_findings: 12, status: "active", tags: ["staging", "test"], tech_stack: ["node", "express", "mongodb", "react"], subdomains: ["dev.staging.example.com"], risk_history: [{score: 94, date: now.toISOString()}, {score: 88, date: pastDate(3).toISOString()}], last_scanned: pastDate(1), created_at: pastDate(10), updated_at: pastDate(1) },
  ];

  const targetIds: ObjectId[] = [];
  for (const t of targets) {
    const id = new ObjectId();
    targetIds.push(id);
    await col("targets").insertOne({ _id: id, ...t });
  }

  const findings = [
    { title: "SQL Injection in User Lookup", severity: "critical", category: "Injection", endpoint: "/api/users?id=1", cvss_score: 9.8, cwe_id: "CWE-89", validation_status: "real", scanner_name: "sqli", description: "The id parameter in GET /api/users is directly interpolated into a SQL query without parameterization, allowing UNION-based extraction of the entire user database.", evidence: "GET /api/users?id=1' UNION SELECT email,password FROM users-- HTTP/1.1 returned all user credentials.", recommended_fix: "Use parameterized queries with pg.query('SELECT * FROM users WHERE id = $1', [id]).", created_at: pastDate(2), target_url: targets[0].url },
    { title: "Missing CSP Header", severity: "high", category: "Security Misconfiguration", endpoint: "/dashboard", cvss_score: 7.5, cwe_id: "CWE-693", validation_status: "real", scanner_name: "headers", description: "Content-Security-Policy header is missing, allowing inline script execution and making XSS attacks easier to exploit.", evidence: "Response headers do not include Content-Security-Policy.", recommended_fix: "Add CSP header: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'", created_at: pastDate(3), target_url: targets[0].url },
    { title: "CORS Wildcard Origin", severity: "medium", category: "CORS", endpoint: "/api/data", cvss_score: 5.3, cwe_id: "CWE-942", validation_status: "real", scanner_name: "cors", description: "Access-Control-Allow-Origin is set to '*', allowing any domain to make credentialed requests to the API.", evidence: "Response header: Access-Control-Allow-Origin: *", recommended_fix: "Whitelist specific origins instead of using wildcard.", created_at: pastDate(4), target_url: targets[0].url },
    { title: "Reflected XSS in Search", severity: "high", category: "Cross-Site Scripting", endpoint: "/search?q=<script>alert(1)</script>", cvss_score: 7.2, cwe_id: "CWE-79", validation_status: "real", scanner_name: "xss", description: "Search query parameter is reflected in the HTML response without output encoding, enabling script injection.", evidence: "The search term is echoed directly in the page: <div>Results for: <script>alert(1)</script></div>", recommended_fix: "HTML-encode all user input before rendering. Use DOMPurify for client-side sanitization.", created_at: pastDate(1), target_url: targets[1].url },
    { title: "JWT Weak Secret", severity: "high", category: "JWT Security", endpoint: "/api/auth/token", cvss_score: 7.5, cwe_id: "CWE-327", validation_status: "real", scanner_name: "jwt", description: "JWT tokens are signed with a weak secret that can be brute-forced in under 1 hour.", evidence: "JWT secret 'secret123' found in rockyou.txt wordlist.", recommended_fix: "Use a cryptographically strong random secret of at least 256 bits.", created_at: pastDate(2), target_url: targets[1].url },
    { title: "TLS 1.0 Enabled", severity: "medium", category: "TLS", endpoint: "https://api.example.com", cvss_score: 5.9, cwe_id: "CWE-326", validation_status: "real", scanner_name: "tls", description: "Server supports TLS 1.0 which is vulnerable to BEAST and POODLE attacks.", evidence: "nmap --script ssl-enum-ciphers shows TLSv1.0 accepted.", recommended_fix: "Disable TLS 1.0 and 1.1. Only allow TLS 1.2+.", created_at: pastDate(5), target_url: targets[0].url },
    { title: "Open Redirect in Login", severity: "medium", category: "Broken Access Control", endpoint: "/login?redirect=https://evil.com", cvss_score: 4.7, cwe_id: "CWE-601", validation_status: "real", scanner_name: "redirect", description: "The redirect parameter accepts arbitrary external URLs, enabling phishing attacks.", evidence: "POST /login with redirect=https://evil.com redirects after login.", recommended_fix: "Validate redirect URL against a whitelist of allowed domains.", created_at: pastDate(3), target_url: targets[2].url },
    { title: "Directory Listing Enabled", severity: "low", category: "Security Misconfiguration", endpoint: "/uploads/", cvss_score: 3.7, cwe_id: "CWE-548", validation_status: "real", scanner_name: "recon", description: "Directory listing is enabled on the uploads folder, exposing all uploaded files.", evidence: "GET /uploads/ returns an HTML listing of all files.", recommended_fix: "Disable directory listing in nginx: autoindex off;", created_at: pastDate(6), target_url: targets[2].url },
    { title: "X-Frame-Options Missing", severity: "low", category: "Header Injection", endpoint: "/", cvss_score: 3.1, cwe_id: "CWE-1021", validation_status: "real", scanner_name: "headers", description: "X-Frame-Options header is missing, making the site vulnerable to clickjacking.", evidence: "Response headers lack X-Frame-Options.", recommended_fix: "Add X-Frame-Options: DENY or SAMEORIGIN header.", created_at: pastDate(4), target_url: targets[1].url },
    { title: "Default Admin Credentials", severity: "critical", category: "Authentication", endpoint: "/admin/login", cvss_score: 9.0, cwe_id: "CWE-798", validation_status: "real", scanner_name: "auth", description: "Admin panel uses default credentials admin/admin that have not been changed.", evidence: "Successful login with admin:admin confirmed.", recommended_fix: "Change default credentials immediately. Implement account lockout after 5 failed attempts.", created_at: pastDate(1), target_url: targets[2].url },
    { title: "Unrestricted File Upload", severity: "critical", category: "File Upload", endpoint: "/api/upload", cvss_score: 8.8, cwe_id: "CWE-434", validation_status: "real", scanner_name: "file-upload", description: "File upload endpoint accepts any file type without validation, allowing upload of web shells.", evidence: "Successfully uploaded test.php to the uploads directory.", recommended_fix: "Validate file type, size, and content. Store files outside web root. Use virus scanning.", created_at: pastDate(2), target_url: targets[3].url },
    { title: "MongoDB Injection in Filter", severity: "critical", category: "Injection", endpoint: "/api/products?filter[$gt]=", cvss_score: 8.6, cwe_id: "CWE-943", validation_status: "real", scanner_name: "api-advanced", description: "MongoDB query operators are not sanitized, allowing NoSQL injection via query parameters.", evidence: "GET /api/products?filter[$gt]= returns all documents bypassing filters.", recommended_fix: "Sanitize user input before passing to MongoDB queries. Use mongo-sanitize or mongoose validation.", created_at: pastDate(3), target_url: targets[3].url },
  ];

  for (const f of findings) {
    await col("findings").insertOne({ _id: new ObjectId(), scan_job_id: new ObjectId(), ...f });
  }

  const remediations = [
    { finding_id: null, scan_job_id: null, title: "Fix: SQL Injection in User Lookup", description: "Replace raw SQL queries with parameterized queries using pg or Sequelize.", patch_snippet: "const result = await db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);", status: "in_progress", created_at: pastDate(1), updated_at: now },
    { finding_id: null, scan_job_id: null, title: "Fix: Missing CSP Header", description: "Add Content-Security-Policy header to all responses via Express middleware.", patch_snippet: "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"] } }));", status: "pending", created_at: pastDate(2), updated_at: pastDate(2) },
    { finding_id: null, scan_job_id: null, title: "Fix: Default Admin Credentials", description: "Change default admin password and implement MFA.", patch_snippet: "Force password change on next login. Enable TOTP-based 2FA.", status: "pending", created_at: pastDate(1), updated_at: pastDate(1) },
    { finding_id: null, scan_job_id: null, title: "Fix: CORS Configuration", description: "Replace wildcard CORS with specific origin whitelist.", patch_snippet: "app.use(cors({ origin: ['https://example.com', 'https://admin.example.com'], credentials: true }));", status: "completed", created_at: pastDate(5), updated_at: pastDate(3) },
  ];

  for (const r of remediations) {
    await col("remediations").insertOne({ _id: new ObjectId(), ...r });
  }

  const scanJobs = [
    { target_url: targets[0].url, scan_profile: "deep", status: "completed", progress: 100, risk_score: 85, findings_count: 24, critical_count: 4, high_count: 8, medium_count: 7, low_count: 3, info_count: 2, created_at: pastDate(1), started_at: pastDate(1), completed_at: pastDate(1) },
    { target_url: targets[1].url, scan_profile: "standard", status: "completed", progress: 100, risk_score: 62, findings_count: 15, critical_count: 2, high_count: 5, medium_count: 5, low_count: 2, info_count: 1, created_at: pastDate(5), started_at: pastDate(5), completed_at: pastDate(5) },
    { target_url: targets[2].url, scan_profile: "standard", status: "completed", progress: 100, risk_score: 38, findings_count: 8, critical_count: 0, high_count: 3, medium_count: 3, low_count: 1, info_count: 1, created_at: pastDate(8), started_at: pastDate(8), completed_at: pastDate(8) },
    { target_url: targets[3].url, scan_profile: "deep", status: "completed", progress: 100, risk_score: 94, findings_count: 31, critical_count: 8, high_count: 12, medium_count: 7, low_count: 3, info_count: 1, created_at: pastDate(2), started_at: pastDate(2), completed_at: pastDate(2) },
  ];

  for (const s of scanJobs) {
    await col("scan_jobs").insertOne({
      _id: new ObjectId(),
      ...s,
      validation_enabled: true, fuzzing_enabled: false, bug_bounty_mode: false,
      authorization_acknowledged: true, error_message: null, ai_summary: null,
    });
  }

  const activityEvents = [
    { type: "scan_completed", message: `Scan completed: 24 findings — Risk score 85/100`, severity: null, timestamp: pastDate(1), scan_job_id: null },
    { type: "finding_created", message: "CRITICAL finding: SQL Injection in User Lookup", severity: "critical", timestamp: pastDate(1), scan_job_id: null },
    { type: "finding_created", message: "HIGH finding: Missing CSP Header", severity: "high", timestamp: pastDate(2), scan_job_id: null },
    { type: "scan_started", message: "Scan started for api.example.com", severity: null, timestamp: pastDate(1.1), scan_job_id: null },
    { type: "scan_completed", message: "Scan completed: 15 findings — Risk score 62/100", severity: null, timestamp: pastDate(5), scan_job_id: null },
    { type: "finding_created", message: "HIGH finding: Reflected XSS in Search", severity: "high", timestamp: pastDate(5), scan_job_id: null },
    { type: "scan_completed", message: "Scan completed: 8 findings — Risk score 38/100", severity: null, timestamp: pastDate(8), scan_job_id: null },
    { type: "scan_completed", message: "Scan completed: 31 findings — Risk score 94/100", severity: "critical", timestamp: pastDate(2), scan_job_id: null },
    { type: "finding_created", message: "CRITICAL finding: Unrestricted File Upload", severity: "critical", timestamp: pastDate(2), scan_job_id: null },
    { type: "finding_created", message: "CRITICAL finding: MongoDB Injection in Filter", severity: "critical", timestamp: pastDate(3), scan_job_id: null },
  ];

  for (const e of activityEvents) {
    await col("activity_events").insertOne({ _id: new ObjectId(), ...e });
  }

  logger.info("Demo data seeded: 4 targets, 12 findings, 4 remediations, 4 scans, 10 activity events");
}
