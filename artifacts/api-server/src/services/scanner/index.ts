import { EventEmitter } from "events";
import { ObjectId } from "mongodb";
import { col } from "../../lib/db";
import { logger } from "../../lib/logger";
import { ScanFinding, ScanContext, ScannerEvent } from "./types";
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

export const scanEvents = new EventEmitter();
scanEvents.setMaxListeners(100);

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
}

// ─── Scanner Pipeline Definitions ────────────────────────────────────────────
// Quick  = ~15 modules (fast recon, no fuzzing)
// Standard = ~30 modules (full web app scan)
// Deep   = all 60 modules (bug bounty / pentest)

const PIPELINE_QUICK = [
  { name: "Crawl & Discover",        fn: (ctx: ScanContext) => { runCrawl(ctx); return Promise.resolve([]); }, isDiscovery: true },
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
];

const PIPELINE_STANDARD = [
  ...PIPELINE_QUICK,
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

async function saveFinding(jobId: string, targetUrl: string, finding: ScanFinding) {
  const sev = finding.severity;
  const riskScore = sev === "critical" ? 90 + Math.floor(Math.random() * 10)
    : sev === "high" ? 70 + Math.floor(Math.random() * 15)
    : sev === "medium" ? 40 + Math.floor(Math.random() * 20)
    : sev === "low" ? 15 + Math.floor(Math.random() * 15) : 5;

  const insertResult = await col("findings").insertOne({
    scan_job_id: new ObjectId(jobId),
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    validation_status: "real",
    confidence: finding.confidence,
    endpoint: finding.endpoint,
    description: finding.description,
    evidence: finding.evidence,
    recommended_fix: finding.recommended_fix,
    cvss_score: finding.cvss_score,
    cwe_id: finding.cwe_id,
    risk_score: riskScore,
    scanner_name: finding.scanner_name,
    scanner_family: finding.scanner_family,
    created_at: new Date(),
    target_url: targetUrl,
  });

  await col("activity_events").insertOne({
    type: "finding_created",
    message: `${finding.severity.toUpperCase()} finding: ${finding.title}`,
    timestamp: new Date(),
    scan_job_id: new ObjectId(jobId),
    severity: finding.severity,
  });

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
  const { jobId, targetUrl, profile, validationEnabled, fuzzingEnabled, bugBountyMode, sessionCookie, authToken, customHeaders } = opts;

  const emit = (event: ScannerEvent) => {
    scanEvents.emit(`scan:${jobId}`, event);
  };

  const discoveredEndpoints: string[] = [];
  const ctx: ScanContext = {
    targetUrl,
    profile: profile as "quick" | "standard" | "deep",
    validationEnabled,
    fuzzingEnabled,
    bugBountyMode,
    emit,
    discoveredEndpoints,
    sessionCookie,
    authToken,
    customHeaders,
  };

  const pipeline = getPipeline(profile, validationEnabled, fuzzingEnabled, bugBountyMode);
  const totalSteps = pipeline.length;

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

    for (let i = 0; i < pipeline.length; i++) {
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

      for (const finding of findings) {
        const riskScore = await saveFinding(jobId, targetUrl, finding);
        totalFindings++;
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
  } catch (err) {
    logger.error({ err, jobId }, "Scan pipeline fatal error");
    await col("scan_jobs").updateOne(
      { _id: new ObjectId(jobId) } as Record<string, unknown>,
      { $set: { status: "failed", error_message: err instanceof Error ? err.message : "Scan error" } }
    );
    emit({ type: "error", message: err instanceof Error ? err.message : "Scan failed" });
  }
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
