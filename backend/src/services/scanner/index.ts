import { EventEmitter } from "events";
import { ObjectId } from "mongodb";
import { col } from "../../lib/db";
import { logger } from "../../lib/logger";
import { ScanFinding, ScanContext, ScannerEvent, createSessionStore } from "./types";
import { runCrawl } from "./crawl";
import { runTlsCheck } from "./tls";
import { runHeaderCheck } from "./headers";
import { runCookieCheck } from "./cookies";
import { runCorsCheck } from "./cors";
import { runReconCheck } from "./recon";
import { runPortScan } from "./ports";
import { runXssCheck } from "./xss";
import { runSqliCheck } from "./sqli";
import { runRedirectCheck } from "./redirect";
import { runAuthCheck } from "./auth";
import { runIdorCheck } from "./idor";
import { runPathTraversalCheck } from "./pathtraversal";
import { runDnsCheck } from "./dns";
import { runSubdomainEnum, runWaybackCrawl } from "./subdomains";
import { sendIntegrationAlerts } from "../alerts";
import { runJsSecretScan } from "./js-secrets";
import { runJwtCheck } from "./jwt";
import { runGraphQLCheck, runWebSocketCheck } from "./graphql";
import { runSstiCheck, runCrlfCheck, runPrototypePollutionCheck } from "./injection-advanced";
import { runFileUploadCheck, runDependencyConfusionCheck } from "./file-upload";
import { runCveLookup } from "./cve-lookup";
import { runRequestSmugglingCheck, runRateLimitCheck } from "./smuggling";
// New scanner modules
import { runInfrastructureCheck } from "./infrastructure";
import { runFingerprintCheck } from "./fingerprint";
import { runPassiveRecon } from "./passive-recon";
import { runCsrfCheck } from "./csrf";
import { runXxeCheck } from "./xxe";
import { runOAuthCheck } from "./oauth";
import { runAdvancedAuthCheck } from "./auth-advanced";
import { runGrpcCheck } from "./grpc";
import { runApiAdvancedCheck } from "./api-advanced";
import { runBusinessLogicCheck } from "./business-logic";
import { runCachePoisoningCheck } from "./cache-poisoning";
import { runCloudCheck } from "./cloud";
import { runDataExposureCheck } from "./data-exposure";
import { runZapScan } from "./zap";
import { runNucleiScan } from "./nuclei";
import { runPlaywrightScan } from "./playwright";
import { runOsintEnrichment } from "./osint";
import { runCustomRules } from "./custom-rules";
import { runDomBrowserScan } from "./dom-browser";
import { isSuppressed } from "./fp-learner";
import { fetchSpaSignature, isSpaFallback, annotateSpaFalsePositive } from "./spa-detector";
import { isPathAllowed, rateAwareFetch as _rateAwareFetch } from "./scope-manager";
import { findSourceLocation, indexRepo, formatSourceLocation } from "./source-mapper";
import { notifyAllChannels } from "../notifications";
import { runSsrfCheck } from "./ssrf";
import { runOpenApiDiscovery } from "./openapi";
import { runRawSmugglingCheck } from "./smuggling-raw";
import { loadCredentialsForTarget } from "../../lib/credential-vault";
import { inferCvss4FromFinding } from "../../lib/cvss4";
import { isSuppressionActive } from "../../routes/suppression";
import { triggerWebhooks } from "../../routes/webhooks";

export const scanEvents = new EventEmitter();
scanEvents.setMaxListeners(100);

// ── Concurrency limiter ────────────────────────────────────────────────────────
const MAX_CONCURRENT_SCANS = parseInt(process.env["MAX_CONCURRENT_SCANS"] ?? "5", 10);
let activeScanCount = 0;

// ── Stale job recovery on startup ─────────────────────────────────────────────
// If the process crashed mid-scan, jobs remain stuck in "running". Fix them on
// startup so the UI does not show perpetually running scans.
(async () => {
  try {
    const stale = await col("scan_jobs").updateMany(
      { status: "running" } as Record<string, unknown>,
      { $set: { status: "failed", error_message: "Process restarted — scan interrupted" } }
    );
    if (stale.modifiedCount > 0) {
      logger.warn({ count: stale.modifiedCount }, "Marked stale running scan jobs as failed on startup");
    }
  } catch { /* non-fatal — DB may not be ready yet */ }
})();

export interface ScanJobOptions {
  jobId: string;
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
  sessionCookie?: string;
  authToken?: string;
  customHeaders?: Record<string, string>;
  repoUrl?: string;
  githubToken?: string;
  openapiSpecUrl?: string;
  scopeHosts?: string[];
  targetId?: string;
}

// ─── Scanner Pipeline Definitions ────────────────────────────────────────────
// Quick  = ~15 modules (fast recon, no fuzzing)
// Standard = ~30 modules (full web app scan)
// Deep   = all 60 modules (bug bounty / pentest)

const PIPELINE_QUICK = [
  { name: "Crawl & Discover",        fn: (ctx: ScanContext) => { runCrawl(ctx); return Promise.resolve([] as ScanFinding[]); }, isDiscovery: true },
  { name: "TLS/HTTPS",               fn: (ctx: ScanContext) => runTlsCheck(ctx) },
  { name: "Security Headers",        fn: (ctx: ScanContext) => runHeaderCheck(ctx) },
  { name: "Cookie Security",         fn: (ctx: ScanContext) => runCookieCheck(ctx) },
  { name: "Recon & Sensitive Paths", fn: (ctx: ScanContext) => runReconCheck(ctx) },
  { name: "DNS Security",            fn: (ctx: ScanContext) => runDnsCheck(ctx) },
  { name: "JS Secrets",              fn: (ctx: ScanContext) => runJsSecretScan(ctx) },
  { name: "CVE Lookup",              fn: (ctx: ScanContext) => runCveLookup(ctx) },
  { name: "Technology Fingerprint",  fn: (ctx: ScanContext) => runFingerprintCheck(ctx) },
  { name: "Infrastructure (WAF/LB)", fn: (ctx: ScanContext) => runInfrastructureCheck(ctx) },
  { name: "Passive Recon",           fn: (ctx: ScanContext) => runPassiveRecon(ctx) },
  { name: "Data Exposure",           fn: (ctx: ScanContext) => runDataExposureCheck(ctx) },
  { name: "Cloud & Container",       fn: (ctx: ScanContext) => runCloudCheck(ctx) },
  { name: "CORS",                    fn: (ctx: ScanContext) => runCorsCheck(ctx) },
  { name: "Port Scanner",            fn: (ctx: ScanContext) => runPortScan(ctx) },
  { name: "DOM Browser Scan",        fn: (ctx: ScanContext) => runDomBrowserScan(ctx) },
  { name: "OSINT Enrichment",        fn: (ctx: ScanContext) => runOsintEnrichment(ctx) },
  { name: "Custom Scanner Rules",    fn: (ctx: ScanContext) => runCustomRules(ctx.targetUrl) },
];

const PIPELINE_STANDARD = [
  ...PIPELINE_QUICK.filter(p => p.name !== "OSINT Enrichment"),
  { name: "OpenAPI Discovery",        fn: (ctx: ScanContext) => { runOpenApiDiscovery(ctx); return Promise.resolve([] as ScanFinding[]); }, isDiscovery: true },
  { name: "XSS Probe",               fn: (ctx: ScanContext) => runXssCheck(ctx) },
  { name: "SQLi Probe",              fn: (ctx: ScanContext) => runSqliCheck(ctx) },
  { name: "Open Redirect",           fn: (ctx: ScanContext) => runRedirectCheck(ctx) },
  { name: "JWT Security",            fn: (ctx: ScanContext) => runJwtCheck(ctx) },
  { name: "Rate Limit",              fn: (ctx: ScanContext) => runRateLimitCheck(ctx) },
  { name: "GraphQL",                 fn: (ctx: ScanContext) => runGraphQLCheck(ctx) },
  { name: "WebSocket Security",      fn: (ctx: ScanContext) => runWebSocketCheck(ctx) },
  { name: "CSRF Protection",         fn: (ctx: ScanContext) => runCsrfCheck(ctx) },
  { name: "OAuth/SSO",               fn: (ctx: ScanContext) => runOAuthCheck(ctx) },
  { name: "API Version Abuse",       fn: (ctx: ScanContext) => runApiAdvancedCheck(ctx) },
  { name: "CRLF Injection",          fn: (ctx: ScanContext) => runCrlfCheck(ctx) },
  { name: "Prototype Pollution",     fn: (ctx: ScanContext) => runPrototypePollutionCheck(ctx) },
  { name: "Dep Confusion",           fn: (ctx: ScanContext) => runDependencyConfusionCheck(ctx) },
  { name: "gRPC Detection",          fn: (ctx: ScanContext) => runGrpcCheck(ctx) },
  { name: "Cache Poisoning",         fn: (ctx: ScanContext) => runCachePoisoningCheck(ctx) },
  { name: "SSRF",                    fn: (ctx: ScanContext) => runSsrfCheck(ctx) },
  { name: "OWASP ZAP Active Scan",   fn: (ctx: ScanContext) => runZapScan(ctx) },
  { name: "Nuclei Templates",        fn: (ctx: ScanContext) => runNucleiScan(ctx) },
  { name: "Playwright Browser",      fn: (ctx: ScanContext) => runPlaywrightScan(ctx) },
  { name: "OSINT Enrichment",        fn: (ctx: ScanContext) => runOsintEnrichment(ctx) },
];

const PIPELINE_DEEP = [
  ...PIPELINE_STANDARD,
  { name: "Auth/Session",            fn: (ctx: ScanContext) => runAuthCheck(ctx) },
  { name: "Advanced Auth & MFA",     fn: (ctx: ScanContext) => runAdvancedAuthCheck(ctx) },
  { name: "IDOR",                    fn: (ctx: ScanContext) => runIdorCheck(ctx) },
  { name: "Path Traversal/SSRF",     fn: (ctx: ScanContext) => runPathTraversalCheck(ctx) },
  { name: "Subdomain Enum",          fn: (ctx: ScanContext) => runSubdomainEnum(ctx) },
  { name: "Wayback Machine",         fn: (ctx: ScanContext) => runWaybackCrawl(ctx) },
  { name: "SSTI",                    fn: (ctx: ScanContext) => runSstiCheck(ctx) },
  { name: "XXE Injection",           fn: (ctx: ScanContext) => runXxeCheck(ctx) },
  { name: "File Upload",             fn: (ctx: ScanContext) => runFileUploadCheck(ctx) },
  { name: "Request Smuggling",       fn: (ctx: ScanContext) => runRequestSmugglingCheck(ctx) },
  { name: "Smuggling (Raw TCP)",     fn: (ctx: ScanContext) => runRawSmugglingCheck(ctx) },
  { name: "Business Logic",          fn: (ctx: ScanContext) => runBusinessLogicCheck(ctx) },
];

function getPipeline(profile: string, validationEnabled: boolean, fuzzingEnabled: boolean, bugBountyMode: boolean) {
  let pipeline = profile === "quick" ? PIPELINE_QUICK : profile === "standard" ? PIPELINE_STANDARD : PIPELINE_DEEP;

  if (validationEnabled && !pipeline.find(p => p.name === "XSS Probe")) {
    pipeline = [...pipeline, { name: "XSS Probe", fn: (ctx: ScanContext) => runXssCheck(ctx) }];
  }
  if (fuzzingEnabled && !pipeline.find(p => p.name === "SQLi Probe")) {
    pipeline = [...pipeline, { name: "SQLi Probe", fn: (ctx: ScanContext) => runSqliCheck(ctx) }];
  }
  if (bugBountyMode) {
    if (!pipeline.find(p => p.name === "IDOR")) pipeline = [...pipeline, { name: "IDOR", fn: (ctx: ScanContext) => runIdorCheck(ctx) }];
    if (!pipeline.find(p => p.name === "Auth/Session")) pipeline = [...pipeline, { name: "Auth/Session", fn: (ctx: ScanContext) => runAuthCheck(ctx) }];
    if (!pipeline.find(p => p.name === "Business Logic")) pipeline = [...pipeline, { name: "Business Logic", fn: (ctx: ScanContext) => runBusinessLogicCheck(ctx) }];
    if (!pipeline.find(p => p.name === "Subdomain Enum")) pipeline = [...pipeline, { name: "Subdomain Enum", fn: (ctx: ScanContext) => runSubdomainEnum(ctx) }];
  }

  return pipeline;
}

async function saveFinding(jobId: string, targetUrl: string, finding: ScanFinding, userId?: string) {
  const sev = finding.severity;
  // Deterministic risk score: CVSS * 10, clamped to severity band, never random.
  // This ensures the same finding always gets the same score across rescans.
  const cvssBase = Math.round(finding.cvss_score * 10);
  const riskScore = sev === "critical" ? Math.max(cvssBase, 90)
    : sev === "high" ? Math.min(Math.max(cvssBase, 70), 89)
    : sev === "medium" ? Math.min(Math.max(cvssBase, 40), 69)
    : sev === "low" ? Math.min(Math.max(cvssBase, 10), 39) : 5;

  // Truncated evidence for the main findings collection (UI display)
  const evidenceTruncated = typeof finding.evidence === "string" && finding.evidence.length > 800
    ? finding.evidence.slice(0, 800) + "\n\n[truncated — see raw_evidence collection for full details]"
    : finding.evidence;

  // ── Deduplication: check if this finding already exists for this target ─────
  // Key = title + normalized endpoint (strip query string for stability)
  let normalizedEndpoint = finding.endpoint;
  try { normalizedEndpoint = new URL(finding.endpoint).origin + new URL(finding.endpoint).pathname; } catch { /* use as-is */ }
  const dedupKey = `${finding.title}||${normalizedEndpoint}`;

  // Check suppression via FP learner patterns
  if (await isSuppressed(finding.title, finding.endpoint, finding.scanner_name, finding.description)) {
    logger.info({ title: finding.title }, "Finding suppressed by FP learner pattern — skipping");
    return 0;
  }

  // Check suppression rules — skip this finding entirely if a matching active rule exists
  if (await isSuppressionActive(dedupKey, targetUrl)) {
    logger.info({ dedupKey, targetUrl }, "Finding suppressed by rule — skipping");
    return 0;
  }

  const existing = await col("findings").findOne({
    dedup_key: dedupKey,
    target_url: targetUrl,
  } as Record<string, unknown>) as Record<string, unknown> | null;

  let insertResult: { insertedId: ObjectId };

  if (existing) {
    // Finding already exists — update last_seen, increment occurrence count,
    // and mark as regression if it was previously resolved.
    const wasResolved = existing["validation_status"] === "resolved";
    await col("findings").updateOne(
      { _id: existing["_id"] } as Record<string, unknown>,
      {
        $set: {
          last_seen_at: new Date(),
          scan_job_id: new ObjectId(jobId),  // point to most recent scan
          evidence: evidenceTruncated,
          confidence: finding.confidence,
          has_raw_evidence: (sev === "critical" || sev === "high") && finding.evidence.length > 200,
          ...(wasResolved ? { validation_status: "regression", regression_detected_at: new Date() } : {}),
          updated_at: new Date(),
        },
        $inc: { occurrence_count: 1 } as Record<string, unknown>,
      } as Record<string, unknown>
    );
    insertResult = { insertedId: existing["_id"] as ObjectId };

    if (wasResolved) {
      logger.warn({ title: finding.title, endpoint: finding.endpoint }, "Finding regression detected");
    }
    // Skip activity_event and remediation creation for duplicate findings
    return riskScore;
  }

  // Compute CVSS 4.0 score for every new finding
  const cvss4 = inferCvss4FromFinding({
    category: finding.category,
    cwe_id: finding.cwe_id,
    cvss_score: finding.cvss_score,
    severity: finding.severity,
    endpoint: finding.endpoint,
  });

  // New finding — insert with dedup_key and initial state fields
  insertResult = await col("findings").insertOne({
    scan_job_id: new ObjectId(jobId),
    user_id: userId ?? null,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    validation_status: "real",
    confidence: finding.confidence,
    endpoint: finding.endpoint,
    description: finding.description,
    evidence: evidenceTruncated,
    recommended_fix: finding.recommended_fix,
    cvss_score: finding.cvss_score,
    cvss4_score: cvss4.score,
    cvss4_severity: cvss4.severity,
    cvss4_vector: cvss4.vector,
    cwe_id: finding.cwe_id,
    risk_score: riskScore,
    raw_request: finding.raw_request ?? null,
    raw_response: finding.raw_response ?? null,
    reproduction_curl: finding.reproduction_curl ?? null,
    scanner_name: finding.scanner_name,
    scanner_family: finding.scanner_family,
    created_at: new Date(),
    last_seen_at: new Date(),
    occurrence_count: 1,
    target_url: targetUrl,
    dedup_key: dedupKey,
    has_raw_evidence: (sev === "critical" || sev === "high") && finding.evidence.length > 200,
    source_location: finding.source_location ?? null,
    cve_id: (finding as unknown as Record<string, unknown>)["cve_id"] as string ?? null,
  });

  // Non-blocking CVE/EPSS enrichment — triggered whenever finding has a cve_id
  const cveId = (finding as unknown as Record<string, unknown>)["cve_id"] as string | undefined;
  if (cveId) {
    import("../../routes/findings").then(({ enrichFindingWithCVEExport }) => {
      enrichFindingWithCVEExport(String(insertResult.insertedId), cveId).catch(() => {});
    }).catch(() => {});
  }

  // For critical/high findings, store the complete untruncated evidence in a
  // dedicated collection with a 30-day TTL so analysts can fully reproduce issues.
  if (sev === "critical" || sev === "high") {
    await col("raw_evidence").insertOne({
      finding_id: insertResult.insertedId,
      scan_job_id: new ObjectId(jobId),
      title: finding.title,
      endpoint: finding.endpoint,
      evidence_full: finding.evidence,        // complete, untruncated
      raw_request: finding.raw_request ?? null,
      raw_response: finding.raw_response ?? null,
      reproduction_curl: finding.reproduction_curl ?? null,
      scanner_name: finding.scanner_name,
      severity: finding.severity,
      created_at: new Date(),
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30-day TTL
    });
  }

  await col("activity_events").insertOne({
    type: "finding_created",
    message: `${finding.severity.toUpperCase()} finding: ${finding.title}`,
    timestamp: new Date(),
    scan_job_id: new ObjectId(jobId),
    severity: finding.severity,
  });

  // Integration alerts (Slack/Teams) — non-blocking
  if (["critical", "high"].includes(String(finding.severity ?? ""))) {
    sendIntegrationAlerts({ ...finding, _id: insertResult.insertedId } as Record<string, unknown>).catch(() => {});
  }

  // Auto-notify on critical/high findings
  try {
    const sev2 = String(finding.severity ?? "");
    if (["critical", "high"].includes(sev2) && userId) {
      const [prefs, user] = await Promise.all([
        col("notification_preferences").findOne({ user_id: userId }) as Promise<Record<string, unknown> | null>,
        col("users").findOne({ _id: new ObjectId(userId) }) as Promise<Record<string, unknown> | null>,
      ]);
      const shouldNotify = sev2 === "critical" ? ((prefs as Record<string, unknown> | null)?.["notify_critical"] !== false) : ((prefs as Record<string, unknown> | null)?.["notify_high"] === true);
      if (shouldNotify && (user as Record<string, unknown> | null)?.["email"]) {
        const { sendEmail } = await import("../../services/email");
        const { broadcastNewFinding } = await import("../../routes/stream");
        sendEmail({
          to: String((user as Record<string, unknown>)["email"]),
          subject: `[${sev2.toUpperCase()}] New finding: ${String(finding.title ?? "Security vulnerability detected")}`,
          html: `<div style="font-family:sans-serif;max-width:600px"><div style="background:#7c3aed;padding:20px;border-radius:8px 8px 0 0"><h2 style="color:white;margin:0">🚨 ${sev2.toUpperCase()} Finding Detected</h2></div><div style="padding:20px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px"><p><strong>Title:</strong> ${finding.title ?? ""}</p><p><strong>Endpoint:</strong> ${finding.endpoint ?? "N/A"}</p><p><strong>Category:</strong> ${finding.category ?? "N/A"}</p><a href="${process.env["APP_URL"] ?? "http://localhost:5000"}/findings" style="display:inline-block;background:#7c3aed;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;margin-top:10px">View Finding →</a></div></div>`,
        }).catch(() => {});
        broadcastNewFinding({ severity: sev2, title: finding.title });
      }
    }
  } catch { /* non-fatal */ }

  if (finding.severity === "critical" || finding.severity === "high") {
    await col("remediations").insertOne({
      finding_id: insertResult.insertedId,
      scan_job_id: new ObjectId(jobId),
      title: `Fix: ${finding.title}`,
      description: `Remediation task for ${finding.title}`,
      patch_snippet: finding.recommended_fix,
      status: "pending",
      created_at: new Date(),
      updated_at: new Date(),
    });
  }

  return riskScore;
}

export async function runScanPipeline(opts: ScanJobOptions): Promise<void> {
  const { jobId, targetUrl, profile, validationEnabled, fuzzingEnabled, bugBountyMode, sessionCookie, authToken, customHeaders, scopeHosts, targetId, openapiSpecUrl } = opts;

  const emit = (event: ScannerEvent) => {
    scanEvents.emit(`scan:${jobId}`, event);
  };

  // Build auth headers from session cookie / Bearer token / custom headers
  const authHeaders: Record<string, string> = { ...(customHeaders ?? {}) };
  if (sessionCookie) authHeaders["Cookie"] = sessionCookie;
  if (authToken) authHeaders["Authorization"] = authToken.startsWith("Bearer ") ? authToken : `Bearer ${authToken}`;

  // Load stored credentials from the vault (if a targetId was provided and no
  // explicit credential was passed in the request — vault fills the gap for
  // scheduled/automated scans where re-entering creds is not possible).
  if (targetId && !sessionCookie && !authToken) {
    try {
      const vaultCreds = await loadCredentialsForTarget(targetId);
      for (const cred of vaultCreds) {
        if (cred.type === "bearer") authHeaders["Authorization"] = `Bearer ${cred.value}`;
        else if (cred.type === "cookie") authHeaders["Cookie"] = cred.value;
        else if (cred.type === "apikey") authHeaders["X-Api-Key"] = cred.value;
        else if (cred.type === "basic") {
          const encoded = Buffer.from(`${cred.username ?? ""}:${cred.value}`).toString("base64");
          authHeaders["Authorization"] = `Basic ${encoded}`;
        }
      }
      if (vaultCreds.length > 0) {
        emit({ type: "log", message: `Credential vault: loaded ${vaultCreds.length} credential(s) for target` });
      }
    } catch { /* vault unavailable — proceed unauthenticated */ }
  }

  const discoveredEndpoints: string[] = [];
  const ctx: ScanContext = {
    targetUrl,
    profile: profile as "quick" | "standard" | "deep",
    validationEnabled,
    fuzzingEnabled,
    bugBountyMode,
    emit,
    discoveredEndpoints,
    discoveredForms: [],
    discoveredParams: [],
    sessionCookie,
    authToken,
    customHeaders,
    authHeaders,
    scopeHosts: scopeHosts ?? [],
    sessionStore: createSessionStore(),
    openapiSpecUrl,
    // Re-authentication: if login credentials were provided, re-run the login
    // flow when a module gets a 401 mid-scan (expired JWT / session rotation).
    reauthenticate: (authToken || sessionCookie)
      ? async (): Promise<boolean> => {
          // Try re-posting the login endpoint with whatever credentials we have
          const loginUrl = `${new URL(targetUrl).origin}/api/auth/login`;
          try {
            const body = authToken
              ? JSON.stringify({ token: authToken })
              : JSON.stringify({ cookie: sessionCookie });
            const res = await fetch(loginUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body,
              signal: AbortSignal.timeout(8000),
            });
            if (res.ok) {
              // Extract new token from response body
              const data = await res.json().catch(() => null) as Record<string, unknown> | null;
              const newToken = (data?.["token"] ?? data?.["access_token"] ?? data?.["accessToken"]) as string | undefined;
              if (newToken) {
                ctx.authHeaders["Authorization"] = `Bearer ${newToken}`;
                emit({ type: "log", message: "Session refreshed — re-authenticated successfully" });
                return true;
              }
              // Extract from Set-Cookie
              const setCookie = res.headers.get("set-cookie");
              if (setCookie) {
                ctx.authHeaders["Cookie"] = setCookie.split(";")[0] ?? "";
                emit({ type: "log", message: "Session refreshed via cookie" });
                return true;
              }
            }
          } catch { /* network error — cannot refresh */ }
          emit({ type: "log", message: "Session refresh failed — continuing with stale credentials" });
          return false;
        }
      : undefined,
  };

  // ── Auth pre-flight check ─────────────────────────────────────────────────────
  // If credentials were provided, verify they actually work before starting the scan.
  // A failed pre-flight means auth-dependent findings would be silent false negatives.
  if (Object.keys(ctx.authHeaders).length > 0) {
    const origin = new URL(targetUrl).origin;
    const authCheckUrls = [`${origin}/api/me`, `${origin}/api/auth/me`, `${origin}/api/user`, `${origin}/api/account`];
    let authVerified = false;
    for (const checkUrl of authCheckUrls) {
      try {
        const r = await fetch(checkUrl, { headers: ctx.authHeaders, signal: AbortSignal.timeout(5000) });
        if (r.status === 200) { authVerified = true; break; }
        if (r.status === 401 || r.status === 403) break;
      } catch { /* endpoint not found — try next */ }
    }
    if (!authVerified) {
      emit({ type: "log", message: "⚠ Auth pre-flight: could not verify credentials — protected-route findings may be incomplete" });
    } else {
      emit({ type: "log", message: "Auth pre-flight: credentials verified — authenticated scan active" });
    }
  }

  // ── SPA Baseline Fingerprint ──────────────────────────────────────────────────
  // Fetch the target root once to determine if it is a Single-Page Application.
  // All subsequent probe responses are compared against this signature so that
  // scanner modules can skip endpoints that simply return the SPA shell (index.html).
  emit({ type: "log", message: "Detecting SPA baseline…" });
  ctx.spaSignature = await fetchSpaSignature(targetUrl);
  if (ctx.spaSignature?.isSpa) {
    emit({ type: "log", message: `[SPA] Detected SPA shell (title: "${ctx.spaSignature.title}", ${ctx.spaSignature.bodyLength} bytes) — SPA fallback filtering enabled` });
  } else {
    emit({ type: "log", message: "[SPA] Target does not appear to be a SPA — fallback filtering disabled" });
  }

  // ── Concurrency gate ────────────────────────────────────────────────────────
  if (activeScanCount >= MAX_CONCURRENT_SCANS) {
    logger.warn({ jobId, activeScanCount, MAX_CONCURRENT_SCANS }, "Scan rejected — concurrency limit reached");
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      { $set: { status: "failed", error_message: `Server busy — max ${MAX_CONCURRENT_SCANS} concurrent scans. Try again shortly.` } }
    );
    emit({ type: "error", message: "Server busy — scan limit reached. Please try again shortly." });
    return;
  }
  activeScanCount++;

  const pipeline = getPipeline(profile, validationEnabled, fuzzingEnabled, bugBountyMode);
  const totalSteps = pipeline.length;

  // Resolve the owning user so findings inherit the same user_id
  const jobDoc = await col("scan_jobs").findOne({ _id: new ObjectId(jobId) } as Record<string, unknown>) as Record<string, unknown> | null;
  const jobUserId = jobDoc?.["user_id"] as string | undefined;

  try {
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      { $set: { status: "running", started_at: new Date(), progress: 0 } }
    );
    await col("activity_events").insertOne({
      type: "scan_started",
      message: `Scan started for ${targetUrl}`,
      timestamp: new Date(),
      scan_job_id: new ObjectId(jobId),
      severity: null,
    });

    emit({ type: "log", message: `Starting scan pipeline for ${targetUrl}` });
    emit({ type: "log", message: `Profile: ${profile} | ${totalSteps} scanner modules` });
    emit({ type: "progress", progress: 0 });

    let critCount = 0, highCount = 0, medCount = 0, lowCount = 0, infoCount = 0;
    let maxRiskScore = 0;
    let totalFindings = 0;

    // Listen for cancellation
    let cancelled = false;
    const cancelListener = () => { cancelled = true; };
    scanEvents.once(`cancel:${jobId}`, cancelListener);

    for (let i = 0; i < pipeline.length; i++) {
      if (cancelled) {
        emit({ type: "log", message: "Scan cancelled by user" });
        break;
      }
      const step = pipeline[i];
      const progress = Math.round(((i + 1) / totalSteps) * 95);

      emit({ type: "engine_start", engine: step.name, message: `[${i + 1}/${totalSteps}] Running: ${step.name}` });

      let findings: ScanFinding[] = [];
      try {
        findings = await step.fn(ctx);
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        emit({ type: "log", message: `  ${step.name} error: ${errMsg}` });
        logger.error({ err, step: step.name, jobId }, "Scanner step error");
      }

      // ── SPA Fallback Post-Processing ───────────────────────────────────────
      // For each finding, verify its endpoint is not just the SPA shell page.
      // Modules that already call isSpaFallback() inline skip the network re-check;
      // this is a safety net for modules that do not have inline checks.
      const filteredFindings: ScanFinding[] = [];
      for (const finding of findings) {
        // Only re-verify endpoints that look like real web URLs (skip DNS, port, etc.)
        if (ctx.spaSignature?.isSpa && finding.endpoint.startsWith("http")) {
          try {
            const verifyRes = await fetch(finding.endpoint, {
              headers: { ...ctx.authHeaders, Accept: "text/html,application/xhtml+xml" },
              signal: AbortSignal.timeout(6000),
            });
            const verifyBody = await verifyRes.text().catch(() => "");
            if (isSpaFallback(verifyRes, verifyBody, ctx.spaSignature)) {
              const annotation = annotateSpaFalsePositive(finding.evidence, finding.endpoint);
              filteredFindings.push({
                ...finding,
                evidence: annotation.evidence,
                confidence: annotation.confidence,
                validation_status: annotation.validation_status,
                fp_reason: annotation.fp_reason,
              });
              emit({ type: "log", message: `  [SPA-FP] ${finding.title} @ ${finding.endpoint} — marked as false positive (SPA fallback)` });
              continue; // skip normal push so it goes through as annotated finding
            }
          } catch { /* network error — keep finding as-is */ }
        }
        filteredFindings.push(finding);
      }

      for (const finding of filteredFindings) {
        const riskScore = await saveFinding(jobId, targetUrl, finding, jobUserId);
        // Only count findings that were actually persisted (saveFinding returns 0 for suppressed)
        if (riskScore > 0) totalFindings++;
        maxRiskScore = Math.max(maxRiskScore, riskScore);

        if (finding.severity === "critical") critCount++;
        else if (finding.severity === "high") highCount++;
        else if (finding.severity === "medium") medCount++;
        else if (finding.severity === "low") lowCount++;
        else infoCount++;

        emit({ type: "finding", finding });
      }

      await col("scan_jobs").updateOne(
        { _id: new ObjectId(jobId) } as Record<string, unknown>,
        {
          $set: {
            progress,
            findings_count: totalFindings,
            critical_count: critCount,
            high_count: highCount,
            medium_count: medCount,
            low_count: lowCount,
            info_count: infoCount,
          },
        }
      );

      emit({ type: "progress", progress });
    }

    // Always remove the cancel listener — prevents permanent leak on any exit path
    scanEvents.off(`cancel:${jobId}`, cancelListener);
    if (cancelled) {
      await col("scan_jobs").updateOne(
        { _id: new ObjectId(jobId) } as Record<string, unknown>,
        { $set: { status: "cancelled", completed_at: new Date() } }
      );
      emit({ type: "complete", progress: 100, message: "Scan cancelled" });
      activeScanCount = Math.max(0, activeScanCount - 1);
      return;
    }

    const riskScore = Math.min(100, critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3);
    const aiSummary = buildQuickSummary(targetUrl, totalFindings, critCount, highCount, medCount, lowCount, riskScore);

    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      {
        $set: {
          status: "completed",
          progress: 100,
          completed_at: new Date(),
          findings_count: totalFindings,
          critical_count: critCount,
          high_count: highCount,
          medium_count: medCount,
          low_count: lowCount,
          info_count: infoCount,
          risk_score: riskScore,
          ai_summary: aiSummary,
        },
      }
    );

    await col("activity_events").insertOne({
      type: "scan_completed",
      message: `Scan completed: ${totalFindings} findings — Risk score ${riskScore}/100`,
      timestamp: new Date(),
      scan_job_id: new ObjectId(jobId),
      severity: null,
    });

    emit({ type: "progress", progress: 100 });
    emit({
      type: "complete",
      progress: 100,
      message: `Scan complete — ${totalFindings} findings (${critCount} critical, ${highCount} high, ${medCount} medium, ${lowCount} low, ${infoCount} info)`,
    });

    logger.info({ jobId, totalFindings, riskScore }, "Scan pipeline completed");

    // Fire scan.completed webhook — non-blocking, errors are suppressed
    triggerWebhooks("scan.completed", {
      scan_id: jobId,
      target_url: targetUrl,
      findings_count: totalFindings,
      critical_count: critCount,
      high_count: highCount,
      medium_count: medCount,
      low_count: lowCount,
      risk_score: riskScore,
      completed_at: new Date().toISOString(),
    }).catch((err) => logger.warn({ err }, "Webhook delivery error"));

    // Update target document with scan results, tech stack, subdomains, risk history
    updateTargetAfterScan(jobId, targetUrl, riskScore, critCount, highCount, totalFindings, jobUserId).catch((err) =>
      logger.warn({ err }, "Target update after scan error")
    );

    // Differential engine — compare with previous completed scan on the same target
    runDifferentialAnalysis(jobId, targetUrl, jobUserId).catch((err) =>
      logger.warn({ err }, "Differential analysis error")
    );

    // Slack notification for critical/high findings
    if ((critCount > 0 || highCount > 0) && process.env["SLACK_WEBHOOK_URL"]) {
      sendSlackAlert(targetUrl, totalFindings, critCount, highCount, riskScore).catch(() => {});
    }

    // AI auto-triage: score findings with AI confidence
    runAiAutoTriage(jobId).catch((err) => logger.warn({ err }, "AI auto-triage error"));
    activeScanCount = Math.max(0, activeScanCount - 1);
  } catch (err) {
    // Always remove cancel listener and release concurrency slot on any fatal error
    scanEvents.off(`cancel:${jobId}`, () => {});
    activeScanCount = Math.max(0, activeScanCount - 1);
    logger.error({ err, jobId }, "Scan pipeline fatal error");
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      { $set: { status: "failed", error_message: err instanceof Error ? err.message : "Scan error" } }
    );
    emit({ type: "error", message: err instanceof Error ? err.message : "Scan failed" });
  }
}

// Differential engine: mark new / recurring / resolved findings vs the previous scan
async function runDifferentialAnalysis(jobId: string, targetUrl: string, userId?: string): Promise<void> {
  let domain: string;
  try { domain = new URL(targetUrl).hostname; } catch { return; }

  // Find previous completed scan on same target by same user
  const prevQuery: Record<string, unknown> = {
    target_url: { $regex: domain, $options: "i" },
    status: "completed",
    _id: { $ne: new ObjectId(jobId) },
  };
  if (userId) prevQuery["user_id"] = userId;

  const prevScan = (await col("scan_jobs")
    .find(prevQuery)
    .sort({ completed_at: -1 })
    .limit(1)
    .toArray())[0] as Record<string, unknown> | undefined;

  if (!prevScan) return; // First scan on this target — no diff possible

  const [currentFindings, prevFindings] = await Promise.all([
    col("findings").find({ scan_job_id: new ObjectId(jobId) } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    col("findings").find({ scan_job_id: prevScan["_id"] } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
  ]);

  const key = (f: Record<string, unknown>) => `${String(f["title"])}||${String(f["endpoint"])}`;
  const prevKeys = new Set(prevFindings.map(key));
  const currentKeys = new Set(currentFindings.map(key));

  let newCount = 0, recurringCount = 0, resolvedCount = 0;

  // Mark current findings as new or recurring
  for (const f of currentFindings) {
    const isRecurring = prevKeys.has(key(f));
    await col("findings").updateOne(
      { _id: f["_id"] } as Record<string, unknown>,
      { $set: { is_new: !isRecurring, is_recurring: isRecurring } }
    );
    if (isRecurring) recurringCount++; else newCount++;
  }

  // Mark previous findings that no longer appear as resolved
  for (const f of prevFindings) {
    if (!currentKeys.has(key(f))) {
      await col("findings").updateOne(
        { _id: f["_id"] } as Record<string, unknown>,
        { $set: { is_resolved: true } }
      );
      resolvedCount++;
    }
  }

  // Store diff stats on the scan job
  await col("scan_jobs").updateOne(
    { _id: new ObjectId(jobId) } as Record<string, unknown>,
    {
      $set: {
        diff_stats: {
          new: newCount,
          recurring: recurringCount,
          resolved: resolvedCount,
          compared_to_scan_id: String(prevScan["_id"]),
          compared_at: new Date(),
        },
      },
    }
  );

  logger.info({ jobId, newCount, recurringCount, resolvedCount }, "Differential analysis complete");
}

async function updateTargetAfterScan(
  jobId: string, targetUrl: string, riskScore: number,
  critCount: number, highCount: number, totalFindings: number,
  userId?: string
) {
  let domain: string;
  try { domain = new URL(targetUrl).hostname; } catch { return; }

  const findings = (await col("findings")
    .find({ scan_job_id: new ObjectId(jobId) } as Record<string, unknown>)
    .toArray()) as Array<Record<string, unknown>>;

  // Extract tech stack from fingerprint findings
  const techFindings = findings.filter((f) =>
    String(f["category"]).toLowerCase().includes("fingerprint") ||
    String(f["scanner_name"] ?? "").toLowerCase().includes("fingerprint") ||
    String(f["title"]).toLowerCase().includes("technology")
  );
  const techStack: string[] = [];
  for (const f of techFindings) {
    const desc = String(f["description"] ?? "") + " " + String(f["evidence"] ?? "");
    const matches = desc.match(/\b(nginx|apache|iis|node\.?js|express|react|angular|vue|django|rails|laravel|php|python|java|golang|wordpress|drupal|jquery|bootstrap|next\.?js|nuxt|varnish|cloudflare|aws|azure|gcp|kubernetes|docker)\b/gi);
    if (matches) techStack.push(...matches.map((m) => m.toLowerCase()));
  }
  const uniqueTech = [...new Set(techStack)];

  // Extract discovered subdomains from subdomain enum findings
  const subFindings = findings.filter((f) =>
    String(f["scanner_name"] ?? "").toLowerCase().includes("subdomain") ||
    String(f["category"]).toLowerCase().includes("subdomain")
  );
  const subdomains: string[] = [];
  for (const f of subFindings) {
    const ep = String(f["endpoint"] ?? "");
    try {
      const sub = new URL(ep.startsWith("http") ? ep : `https://${ep}`).hostname;
      if (sub !== domain && sub.endsWith(domain)) subdomains.push(sub);
    } catch { /* ignore */ }
  }

  const existing = (await col("targets").findOne({ domain, ...(userId ? { user_id: userId } : {}) } as Record<string, unknown>)) as Record<string, unknown> | null;

  const riskHistoryEntry = { score: riskScore, date: new Date().toISOString() };
  let riskHistory = (existing?.["risk_history"] as Array<{ score: number; date: string }>) ?? [];
  riskHistory = [...riskHistory, riskHistoryEntry].slice(-10); // keep last 10

  const existingTech = (existing?.["tech_stack"] as string[]) ?? [];
  const mergedTech = [...new Set([...existingTech, ...uniqueTech])];

  const existingSubs = (existing?.["subdomains"] as string[]) ?? [];
  const mergedSubs = [...new Set([...existingSubs, ...subdomains])];

  if (existing) {
    await col("targets").updateOne(
      { domain, ...(userId ? { user_id: userId } : {}) } as Record<string, unknown>,
      {
        $set: {
          last_scanned: new Date(),
          risk_score: riskScore,
          total_findings: totalFindings,
          critical_findings: critCount,
          high_findings: highCount,
          tech_stack: mergedTech,
          subdomains: mergedSubs,
          risk_history: riskHistory,
          updated_at: new Date(),
        },
        $inc: { total_scans: 1 },
      }
    );
  } else {
    await col("targets").insertOne({
      url: targetUrl,
      domain,
      user_id: userId ?? null,
      last_scanned: new Date(),
      risk_score: riskScore,
      total_findings: totalFindings,
      critical_findings: critCount,
      high_findings: highCount,
      total_scans: 1,
      status: "active",
      tags: [],
      tech_stack: mergedTech,
      subdomains: mergedSubs,
      risk_history: riskHistory,
      created_at: new Date(),
      updated_at: new Date(),
    });
  }
}

async function sendSlackAlert(targetUrl: string, total: number, crit: number, high: number, riskScore: number) {
  const webhook = process.env["SLACK_WEBHOOK_URL"];
  if (!webhook) return;
  await fetch(webhook, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      text: `:rotating_light: *Bug Finder Pro Alert* — Scan completed for \`${targetUrl}\``,
      attachments: [{
        color: crit > 0 ? "danger" : "warning",
        fields: [
          { title: "Risk Score", value: `${riskScore}/100`, short: true },
          { title: "Total Findings", value: String(total), short: true },
          { title: "Critical", value: String(crit), short: true },
          { title: "High", value: String(high), short: true },
        ],
      }],
    }),
  });
}

async function runAiAutoTriage(jobId: string) {
  const OpenAI = (await import("openai")).default;
  const openai = new OpenAI({
    apiKey: process.env["OPENCODE_API_KEY"] ?? "",
    baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
    timeout: 60000,
  });
  const model = process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free";

  const findings = await col("findings")
    .find({ scan_job_id: new ObjectId(jobId) } as Record<string, unknown>)
    .toArray() as Array<Record<string, unknown>>;

  for (const finding of findings) {
    try {
      const prompt = `You are a security triage expert. Given this vulnerability finding, respond with ONLY a JSON object with two fields: "suggested_severity" (one of: critical, high, medium, low, info) and "confidence_score" (0.0 to 1.0). No explanation.

Title: ${finding["title"]}
Category: ${finding["category"]}
Description: ${String(finding["description"] ?? "").slice(0, 200)}
Current Severity: ${finding["severity"]}
CVSS: ${finding["cvss_score"] ?? "N/A"}
CWE: ${finding["cwe_id"] ?? "N/A"}`;

      const completion = await openai.chat.completions.create({
        model,
        max_tokens: 100,
        messages: [{ role: "user", content: prompt }],
        stream: false,
      });

      const text = completion.choices[0]?.message?.content ?? "{}";
      const json = JSON.parse(text.trim()) as { suggested_severity?: string; confidence_score?: number };

      await col("findings").updateOne(
        { _id: finding["_id"] } as Record<string, unknown>,
        { $set: { ai_suggested_severity: json.suggested_severity, ai_confidence: json.confidence_score } }
      );
    } catch {
      // Non-fatal — skip individual finding on error
    }
  }
  logger.info({ jobId, count: findings.length }, "AI auto-triage complete");
}

function buildQuickSummary(
  targetUrl: string,
  total: number,
  crit: number,
  high: number,
  med: number,
  low: number,
  riskScore: number
): string {
  const severity = crit > 0 ? "CRITICAL" : high > 0 ? "HIGH" : med > 0 ? "MEDIUM" : "LOW";
  return `Security scan of ${targetUrl} completed. Found ${total} vulnerabilities: ${crit} critical, ${high} high, ${med} medium, ${low} low severity issues. Overall risk score: ${riskScore}/100 (${severity}). ${crit > 0 || high > 0 ? "Immediate remediation required for critical and high findings." : "Address medium findings at earliest opportunity."}`;
}
