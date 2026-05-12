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
}

export interface ScannerEvent {
  type: "log" | "engine_start" | "engine_done" | "finding" | "progress" | "complete" | "error";
  engine?: string;
  message?: string;
  progress?: number;
  finding?: ScanFinding;
}

export type EmitFn = (event: ScannerEvent) => void;

export interface ScanContext {
  targetUrl: string;
  profile: "quick" | "standard" | "deep";
  validationEnabled: boolean;
  fuzzingEnabled: boolean;
  bugBountyMode: boolean;
  emit: EmitFn;
  discoveredEndpoints: string[];
  abortSignal?: AbortSignal;
  sessionCookie?: string;
  authToken?: string;
  customHeaders?: Record<string, string>;
}

export const FETCH_TIMEOUT = 10000;

// POINT 8 & 9: Per-target throttle state — tracks last request time and adaptive delay
const targetThrottle = new Map<string, { lastMs: number; delayMs: number }>();

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
      targetThrottle.set(host, { lastMs: Date.now(), delayMs: backoff });
    } else if (latency > 3000) {
      // Slow target — increase delay proportionally
      const newDelay = Math.min(state.delayMs + 200, 3000);
      targetThrottle.set(host, { lastMs: Date.now(), delayMs: newDelay });
    } else {
      // Fast response — gradually recover toward base delay
      const newDelay = Math.max(state.delayMs - 20, 150);
      targetThrottle.set(host, { lastMs: Date.now(), delayMs: newDelay });
    }

    return res;
  } catch {
    targetThrottle.set(host, { lastMs: Date.now(), delayMs: Math.min(state.delayMs + 100, 3000) });
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function resetThrottle(host: string): void {
  targetThrottle.delete(host);
}
