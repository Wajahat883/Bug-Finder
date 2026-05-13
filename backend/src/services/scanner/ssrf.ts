import { ScanContext, ScanFinding, ctxFetch, isInScope, curlReproducer } from "./types";
import { createOastClient } from "./oast";

// Common SSRF-triggering parameter names
const SSRF_PARAMS = [
  "url", "endpoint", "host", "fetch", "load", "callback", "redirect",
  "dest", "destination", "target", "uri", "path", "resource", "src",
  "source", "href", "link", "next", "data", "api", "proxy", "webhook",
];

// Cloud metadata endpoints — if the server fetches these, it's running in a cloud env
const CLOUD_METADATA_URLS = [
  "http://169.254.169.254/latest/meta-data/",           // AWS IMDSv1
  "http://169.254.169.254/latest/meta-data/iam/",       // AWS IAM roles
  "http://metadata.google.internal/computeMetadata/v1/", // GCP
  "http://169.254.169.254/metadata/instance",            // Azure
];

// Internal IP ranges to probe (non-routable)
const INTERNAL_PROBES = [
  "http://localhost/",
  "http://127.0.0.1/",
  "http://0.0.0.0/",
  "http://[::1]/",
];

export async function runSsrfCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/SSRF", message: "Probing for Server-Side Request Forgery (SSRF)" });

  const base = new URL(targetUrl);
  const budget = profile === "quick" ? 3 : profile === "standard" ? 8 : 15;

  // Set up OAST client for out-of-band confirmation
  const oast = await createOastClient();
  if (oast) {
    emit({ type: "log", message: `OAST client connected — OOB SSRF confirmation enabled (${oast.domain})` });
  } else {
    emit({ type: "log", message: "No INTERACTSH_URL set — using metadata URL reflection for SSRF detection" });
  }

  const endpoints = [
    targetUrl,
    ...discoveredEndpoints.filter(ep => isInScope(ctx, ep) && ep.includes("/api")).slice(0, budget - 1),
  ];

  for (const endpoint of endpoints.slice(0, budget)) {
    for (const param of SSRF_PARAMS.slice(0, profile === "quick" ? 5 : 12)) {
      const key = `${endpoint}:${param}`;
      if (seen.has(key)) continue;

      // ── Strategy 1: OOB callback — most reliable ──────────────────────────
      if (oast) {
        const tag = `ssrf-${param}-${Date.now()}`;
        const callbackUrl = oast.allocate(tag);
        const probeUrl = buildUrl(endpoint, param, callbackUrl);

        const res = await ctxFetch(ctx, probeUrl);
        if (res) {
          const hit = await oast.poll(tag, 4000);
          if (hit) {
            seen.add(key);
            findings.push({
              title: `SSRF Confirmed via OOB Callback: Parameter "${param}"`,
              category: "SSRF",
              severity: "critical",
              endpoint,
              description: `Parameter "${param}" triggered a server-side HTTP request to an attacker-controlled domain. The interactsh OOB server received a DNS/HTTP callback from the target, confirming the server fetches URLs supplied by the user. An attacker can use this to reach internal services, cloud metadata endpoints, or exfiltrate data.`,
              evidence: [
                `GET ${probeUrl}`,
                `Payload: ${param}=${callbackUrl}`,
                `HTTP ${res.status} from target`,
                `OOB callback received at: ${callbackUrl}`,
                `Interactsh domain: ${oast.domain}`,
                ``,
                `This is a confirmed SSRF — the server made an outbound HTTP/DNS request to our OOB server.`,
              ].join("\n"),
              recommended_fix: "Validate and whitelist allowed destinations. Block requests to 169.254.169.254, 127.0.0.0/8, and 10.0.0.0/8. Use an allowlist-based HTTP client wrapper. Disable unnecessary outbound fetch functionality.",
              cvss_score: 9.8,
              cwe_id: "CWE-918",
              scanner_name: "Bug-Finder/SSRF",
              scanner_family: "web",
              confidence: 0.97,
              reproduction_curl: curlReproducer("GET", probeUrl),
            });
            emit({ type: "log", message: `  [SSRF CONFIRMED OOB] ${endpoint} param=${param} — OOB callback received` });
            break;
          }
        }
      }

      // ── Strategy 2: Cloud metadata reflection ────────────────────────────
      // If the server fetches the URL and returns the metadata body, it's vulnerable
      for (const metaUrl of CLOUD_METADATA_URLS.slice(0, 2)) {
        const probeUrl = buildUrl(endpoint, param, metaUrl);
        const res = await ctxFetch(ctx, probeUrl);
        if (!res) continue;

        const body = await res.text().catch(() => "");
        const bodyLower = body.toLowerCase();

        // AWS metadata indicators
        const awsHit = bodyLower.includes("ami-id") || bodyLower.includes("instance-id") ||
          bodyLower.includes("iam") || body.includes("169.254.169.254");
        // GCP indicators
        const gcpHit = bodyLower.includes("computemetadata") || bodyLower.includes("instance/zone");
        // Azure indicators
        const azureHit = bodyLower.includes("compute") && bodyLower.includes("subscriptionid");

        if (awsHit || gcpHit || azureHit) {
          seen.add(key);
          const provider = awsHit ? "AWS" : gcpHit ? "GCP" : "Azure";
          findings.push({
            title: `SSRF Confirmed — ${provider} Cloud Metadata Exposed: Parameter "${param}"`,
            category: "SSRF",
            severity: "critical",
            endpoint,
            description: `Parameter "${param}" caused the server to fetch ${metaUrl} and return cloud instance metadata in the response. An attacker can use this to retrieve IAM credentials, instance identity, and potentially escalate to full cloud account compromise.`,
            evidence: [
              `GET ${probeUrl}`,
              `Payload: ${param}=${metaUrl}`,
              `HTTP ${res.status}`,
              ``,
              `Cloud metadata detected in response (${provider}):`,
              body.slice(0, 500),
            ].join("\n"),
            recommended_fix: "Block all requests to 169.254.169.254 and metadata hostnames at the application layer and firewall level. Enforce IMDSv2 on AWS (requires session tokens). Validate URL destinations against an allowlist.",
            cvss_score: 9.8,
            cwe_id: "CWE-918",
            scanner_name: "Bug-Finder/SSRF",
            scanner_family: "web",
            confidence: 0.95,
            reproduction_curl: curlReproducer("GET", probeUrl),
          });
          emit({ type: "log", message: `  [SSRF CRITICAL] ${provider} metadata reflected at ${endpoint} param=${param}` });
          break;
        }
      }

      if (seen.has(key)) break;

      // ── Strategy 3: Internal redirect detection ───────────────────────────
      // Check if the server redirects to internal IPs when we inject them
      for (const internalUrl of INTERNAL_PROBES.slice(0, 2)) {
        const probeUrl = buildUrl(endpoint, param, internalUrl);
        const res = await ctxFetch(ctx, probeUrl, { redirect: "manual" });
        if (!res) continue;

        const location = res.headers.get("location") ?? "";
        const body = await res.text().catch(() => "");
        const bodyLower = body.toLowerCase();

        // If the server blindly reflects the internal URL in a redirect or in the body
        const reflectedInBody = bodyLower.includes("localhost") ||
          bodyLower.includes("127.0.0.1") || bodyLower.includes("0.0.0.0");
        const reflectedInLocation = location.includes("127.") || location.includes("localhost");

        if (res.status === 200 && reflectedInBody && body.length > 100) {
          seen.add(key);
          findings.push({
            title: `Potential SSRF — Internal URL Reflected: Parameter "${param}"`,
            category: "SSRF",
            severity: "high",
            endpoint,
            description: `Parameter "${param}" returned a response containing internal IP addresses when injected with "${internalUrl}". This suggests the server may be fetching the URL and reflecting the response. Manual verification recommended.`,
            evidence: [
              `GET ${probeUrl}`,
              `Payload: ${param}=${internalUrl}`,
              `HTTP ${res.status}`,
              `Internal URL pattern found in response body`,
              `Response snippet: ${body.slice(0, 300)}`,
            ].join("\n"),
            recommended_fix: "Validate that URL parameters do not point to internal network addresses. Implement an allowlist of allowed external domains.",
            cvss_score: 7.5,
            cwe_id: "CWE-918",
            scanner_name: "Bug-Finder/SSRF",
            scanner_family: "web",
            confidence: 0.60,
          });
          emit({ type: "log", message: `  [SSRF?] Internal URL reflected at ${endpoint} param=${param}` });
          break;
        } else if (reflectedInLocation) {
          seen.add(key);
          findings.push({
            title: `SSRF Redirect to Internal Host: Parameter "${param}"`,
            category: "SSRF",
            severity: "high",
            endpoint,
            description: `Parameter "${param}" caused the server to issue a redirect to an internal IP address. This indicates the server processes user-supplied URLs and may be reachable to internal services.`,
            evidence: [
              `GET ${probeUrl}`,
              `Payload: ${param}=${internalUrl}`,
              `HTTP ${res.status}`,
              `Location: ${location}`,
            ].join("\n"),
            recommended_fix: "Block redirects to private IP ranges. Validate and restrict allowed URL destinations.",
            cvss_score: 7.5,
            cwe_id: "CWE-918",
            scanner_name: "Bug-Finder/SSRF",
            scanner_family: "web",
            confidence: 0.75,
          });
          emit({ type: "log", message: `  [SSRF redirect] ${endpoint} param=${param} → ${location}` });
          break;
        }
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No SSRF vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/SSRF",
    message: `SSRF check complete — ${findings.length} finding(s)`,
  });

  return findings;
}

function buildUrl(endpoint: string, param: string, value: string): string {
  return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(value)}`;
}
