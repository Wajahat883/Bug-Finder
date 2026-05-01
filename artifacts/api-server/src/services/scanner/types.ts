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

export async function safeFetch(
  url: string,
  options: RequestInit = {},
  timeoutMs = FETCH_TIMEOUT
): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
