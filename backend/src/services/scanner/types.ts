export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface ScanFinding {
  title: string;
  category: string;
  severity: Severity;
  endpoint: string;
  description: string;
  evidence: string;
  recommended_fix: string;
  cvss_score: number;
  cwe_id: string;
  scanner_name: string;
  scanner_family: string;
  confidence: number;
  source_location?: string;
  raw_request?: string;
  raw_response?: string;
  reproduction_curl?: string;
  validation_status?: string;
  fp_reason?: string;
}

export interface ScannerEvent {
  type: "log" | "engine_start" | "engine_done" | "finding" | "progress" | "complete" | "error";
  engine?: string;
  message?: string;
  progress?: number;
  finding?: ScanFinding;
}

export type EmitFn = (event: ScannerEvent) => void;

export interface DiscoveredForm {
  action: string;      // absolute URL
  method: "GET" | "POST";
  fields: string[];    // input/textarea/select name attributes
}

export interface DiscoveredParam {
  endpoint: string;    // absolute URL with method, e.g. "GET /api/users"
  name: string;        // parameter name
  location: "query" | "body" | "path" | "header";
}

export interface ScanContext {
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
  emit: EmitFn;
  discoveredEndpoints: string[];
  discoveredForms: DiscoveredForm[];
  discoveredParams: DiscoveredParam[];
  abortSignal?: AbortSignal;
  sessionCookie?: string;
  authToken?: string;
  customHeaders?: Record<string, string>;
  // Auth-aware fetch — pre-bound with session cookie / Bearer token / custom headers
  authHeaders: Record<string, string>;
  // Scope enforcement — empty array = unrestricted
  scopeHosts: string[];
  // Re-authentication callback — called when a probe returns 401 mid-scan.
  // Refreshes ctx.authHeaders in-place and returns true if successful.
  reauthenticate?: () => Promise<boolean>;
  // Cross-module session store — modules write discovered credentials/tokens here
  // so downstream modules can reuse them without re-discovering.
  sessionStore: SessionStore;
  // Optional OpenAPI/Swagger spec URL — when set, nuclei will scan each discovered path
  // with api/ templates in addition to the standard full-target scan.
  openapiSpecUrl?: string;
  // SPA baseline signature — fetched once at scan start by the orchestrator.
  // Scanner modules use this with isSpaFallback() from spa-detector.ts to skip
  // responses that are just the React/Vue/Angular index.html shell page.
  spaSignature?: import("./spa-detector").SpaSignature | null;
  // WAF/CDN presence — set by the infrastructure module after detection.
  // Downstream modules read this to reduce confidence on header-based findings.
  wafDetected: string[];
  cdnDetected: string[];
}

// Cross-module session store for sharing discovered tokens across scanner modules
export interface SessionStore {
  // Auth tokens discovered by auth/JWT scanners
  discoveredTokens: Array<{ token: string; type: "bearer" | "cookie" | "api-key"; endpoint: string }>;
  // Object IDs discovered by IDOR scanner for use in other modules
  discoveredObjectIds: Array<{ id: string; type: "uuid" | "objectid" | "integer"; endpoint: string }>;
  // API endpoints confirmed to return data (for chaining)
  confirmedDataEndpoints: string[];
  // Credentials found in JS secrets / passive recon
  discoveredCredentials: Array<{ key: string; value: string; source: string }>;
  // Generic key-value store for module coordination
  shared: Map<string, unknown>;
}

export function createSessionStore(): SessionStore {
  return {
    discoveredTokens: [],
    discoveredObjectIds: [],
    confirmedDataEndpoints: [],
    discoveredCredentials: [],
    shared: new Map(),
  };
}

// Build raw HTTP reproduction strings from a fetch Response for use in findings evidence.
// Call after reading the body; pass the body text since it can only be consumed once.
export function buildRawCapture(
  method: string,
  url: string,
  requestHeaders: Record<string, string>,
  requestBody: string | undefined,
  res: Response,
  responseBodySlice: string
): Pick<ScanFinding, "raw_request" | "raw_response" | "reproduction_curl"> {
  const parsedUrl = (() => { try { return new URL(url); } catch { return null; } })();
  const host = parsedUrl?.host ?? url;
  const pathAndQuery = parsedUrl ? `${parsedUrl.pathname}${parsedUrl.search}` : url;

  const reqHeaderLines = Object.entries({ Host: host, ...requestHeaders })
    .filter(([k]) => !["host"].includes(k.toLowerCase()))
    .map(([k, v]) => `${k}: ${v}`)
    .join("\r\n");

  const raw_request = [
    `${method.toUpperCase()} ${pathAndQuery} HTTP/1.1`,
    `Host: ${host}`,
    reqHeaderLines,
    "",
    requestBody ?? "",
  ].join("\r\n");

  const resHeaderLines: string[] = [];
  res.headers.forEach((v, k) => resHeaderLines.push(`${k}: ${v}`));

  const raw_response = [
    `HTTP/1.1 ${res.status} ${res.statusText}`,
    resHeaderLines.join("\r\n"),
    "",
    responseBodySlice.slice(0, 500),
  ].join("\r\n");

  const curlHeaders = Object.entries({ ...requestHeaders })
    .map(([k, v]) => `-H '${k}: ${v}'`)
    .join(" ");
  const curlBody = requestBody ? `-d '${requestBody.slice(0, 200).replace(/'/g, "'\\''")}' ` : "";
  const reproduction_curl = `curl -s -X ${method.toUpperCase()} '${url}' ${curlHeaders} ${curlBody}`.trim();

  return { raw_request, raw_response, reproduction_curl };
}

// Lightweight curl reproducer — use when the Response body has already been consumed.
// For full raw_request + raw_response capture use buildRawCapture() instead.
export function curlReproducer(
  method: string,
  url: string,
  headers?: Record<string, string>,
  body?: string
): string {
  const h = Object.entries(headers ?? {}).map(([k, v]) => `-H '${k}: ${v}'`).join(" ");
  const b = body ? `-d '${body.slice(0, 300).replace(/'/g, "'\\''")}' ` : "";
  return `curl -sv -X ${method.toUpperCase()} '${url}' ${h} ${b}`.replace(/\s+/g, " ").trim();
}

// Returns true if url is within the scan's defined scope
export function isInScope(ctx: ScanContext, url: string): boolean {
  if (!ctx.scopeHosts || ctx.scopeHosts.length === 0) return true;
  try {
    const host = new URL(url).hostname;
    return ctx.scopeHosts.some(h => host === h || host.endsWith(`.${h}`));
  } catch { return false; }
}

// Auth-aware safeFetch: merges session/token headers into every request.
// Automatically retries once with refreshed credentials when a 401 is received
// and a reauthenticate() callback is registered on the context.
export async function ctxFetch(
  ctx: ScanContext,
  url: string,
  options: RequestInit = {},
  timeoutMs = FETCH_TIMEOUT
): Promise<Response | null> {
  // Scope enforcement — never probe hosts outside the defined scope
  if (ctx.scopeHosts && ctx.scopeHosts.length > 0 && !isInScope(ctx, url)) {
    ctx.emit({ type: "log", message: `  [SCOPE] Skipping out-of-scope URL: ${url}` });
    return null;
  }

  const buildMerged = () => ({
    ...options,
    headers: { ...ctx.authHeaders, ...(options.headers as Record<string, string> ?? {}) },
  });

  let res = await safeFetch(url, buildMerged(), timeoutMs);

  // On 401, attempt re-authentication once and retry
  if (res?.status === 401 && ctx.reauthenticate) {
    const refreshed = await ctx.reauthenticate();
    if (refreshed) {
      res = await safeFetch(url, buildMerged(), timeoutMs);
    }
  }

  return res;
}

export const FETCH_TIMEOUT = 10000;

// Per-target throttle state — tracks last request time and adaptive delay.
// Capped at 500 hosts with LRU eviction to prevent unbounded memory growth during
// large scans or long-running server uptime.
const TARGET_THROTTLE_MAX = 500;
const targetThrottle = new Map<string, { lastMs: number; delayMs: number }>();

function throttleSet(host: string, val: { lastMs: number; delayMs: number }): void {
  if (targetThrottle.size >= TARGET_THROTTLE_MAX && !targetThrottle.has(host)) {
    // Evict the entry with the oldest lastMs (LRU)
    let oldestKey = "";
    let oldestMs = Infinity;
    for (const [k, v] of targetThrottle) {
      if (v.lastMs < oldestMs) { oldestMs = v.lastMs; oldestKey = k; }
    }
    if (oldestKey) targetThrottle.delete(oldestKey);
  }
  targetThrottle.set(host, val);
}

function getHostKey(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

// POINT 8: Throttle — enforces minimum gap between requests to the same host
// POINT 9: Rate adaptation — slows down when target responds with 429/503 or is slow
export async function safeFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = FETCH_TIMEOUT
): Promise<Response | null> {
  const host = getHostKey(url);
  const state = targetThrottle.get(host) ?? { lastMs: 0, delayMs: 150 };

  // Enforce minimum gap between requests to same host
  const elapsed = Date.now() - state.lastMs;
  if (elapsed < state.delayMs) {
    await new Promise(r => setTimeout(r, state.delayMs - elapsed));
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const userSignal = options.signal;
  if (userSignal) {
    userSignal.addEventListener("abort", () => controller.abort(), { once: true });
  }

  const t0 = Date.now();
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const latency = Date.now() - t0;

    // Rate adaptation: back off on 429 / 503 or slow responses
    if (res.status === 429 || res.status === 503) {
      const retryAfter = res.headers.get("retry-after");
      const backoff = retryAfter ? parseInt(retryAfter) * 1000 : Math.min(state.delayMs * 2, 5000);
      throttleSet(host, { lastMs: Date.now(), delayMs: backoff });
    } else if (latency > 3000) {
      // Slow target — increase delay proportionally
      const newDelay = Math.min(state.delayMs + 200, 3000);
      throttleSet(host, { lastMs: Date.now(), delayMs: newDelay });
    } else {
      // Fast response — gradually recover toward base delay
      const newDelay = Math.max(state.delayMs - 20, 150);
      throttleSet(host, { lastMs: Date.now(), delayMs: newDelay });
    }

    return res;
  } catch {
    throttleSet(host, { lastMs: Date.now(), delayMs: Math.min(state.delayMs + 100, 3000) });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function resetThrottle(host: string): void {
  targetThrottle.delete(host);
}

// WAF/block detection — returns true if the response looks like a WAF challenge or block page.
// Modules can call this after each probe and back off + warn when triggered.
export function isWafBlock(res: Response | null, body: string): boolean {
  if (!res) return false;
  if (res.status === 403 || res.status === 429 || res.status === 406 || res.status === 503) return true;
  const ct = res.headers.get("content-type") ?? "";
  const server = (res.headers.get("server") ?? "").toLowerCase();
  // CloudFlare challenge
  if (server.includes("cloudflare") && res.status === 403) return true;
  // Akamai / Imperva / Sucuri block pages contain these strings
  const bodyLower = body.slice(0, 500).toLowerCase();
  if (
    bodyLower.includes("access denied") ||
    bodyLower.includes("blocked by") ||
    bodyLower.includes("security check") ||
    bodyLower.includes("ddos protection") ||
    bodyLower.includes("ray id") ||            // Cloudflare
    bodyLower.includes("reference #")          // Akamai
  ) return true;
  return false;
}

// Adaptive WAF backoff — call when isWafBlock returns true.
// Doubles the host's throttle delay (up to 10s) and emits a warning.
export function handleWafBlock(ctx: ScanContext, url: string): void {
  const host = getHostKey(url);
  const state = targetThrottle.get(host) ?? { lastMs: 0, delayMs: 150 };
  const newDelay = Math.min(state.delayMs * 2, 10000);
  throttleSet(host, { lastMs: Date.now(), delayMs: newDelay });
  ctx.emit({ type: "log", message: `  [WAF] Block detected at ${host} — backing off to ${newDelay}ms between requests` });
}
