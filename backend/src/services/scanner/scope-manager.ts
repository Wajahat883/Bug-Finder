import { logger } from "../../lib/logger";

interface ScopeRules {
  includePaths: string[];
  excludePaths: string[];
  excludeDomains: string[];
  maxDepth: number;
  maxRequestsPerMinute: number;
  maxRequestsTotal: number;
}

interface RateTracker {
  timestamps: number[];
  backoffMs: number;
  consecutive429s: number;
}

const rateTrackers: Map<string, RateTracker> = new Map();

const DEFAULT_SCOPE: ScopeRules = {
  includePaths: ["/*"],
  excludePaths: [
    "/logout", "/signout", "/delete-account",
    "/admin/delete", "/api/admin/delete",
    "/cdn/", "/static/", "/assets/",
  ],
  excludeDomains: [],
  maxDepth: 50,
  maxRequestsPerMinute: 60,
  maxRequestsTotal: 5000,
};

let activeScope: ScopeRules = { ...DEFAULT_SCOPE };

export function updateScope(rules: Partial<ScopeRules>): void {
  activeScope = { ...activeScope, ...rules };
  logger.info({ scope: activeScope }, "Scan scope updated");
}

export function getScope(): ScopeRules {
  return { ...activeScope };
}

export function isPathAllowed(url: string): boolean {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname;

    for (const excl of activeScope.excludePaths) {
      if (path.startsWith(excl) || path.match(new RegExp(excl.replace(/\*/g, ".*")))) {
        logger.debug({ path, rule: excl }, "Path excluded by scope");
        return false;
      }
    }

    const depth = path.split("/").filter(Boolean).length;
    if (depth > activeScope.maxDepth) {
      logger.debug({ path, depth, max: activeScope.maxDepth }, "Max depth exceeded");
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export function isDomainAllowed(hostname: string): boolean {
  for (const excl of activeScope.excludeDomains) {
    if (hostname === excl || hostname.endsWith("." + excl)) {
      return false;
    }
  }
  return true;
}

export async function rateAwareFetch(
  targetKey: string,
  url: string,
  options: RequestInit = {},
  timeoutMs = 8000
): Promise<Response | null> {
  if (!rateTrackers.has(targetKey)) {
    rateTrackers.set(targetKey, { timestamps: [], backoffMs: 0, consecutive429s: 0 });
  }

  const tracker = rateTrackers.get(targetKey)!;

  const now = Date.now();
  tracker.timestamps = tracker.timestamps.filter(t => now - t < 60000);

  if (tracker.timestamps.length >= activeScope.maxRequestsPerMinute) {
    const oldest = tracker.timestamps[0];
    const waitMs = 60000 - (now - oldest) + 100;
    logger.warn({ targetKey, waitMs }, "Rate limit approaching — backing off");
    await new Promise(r => setTimeout(r, waitMs));
    tracker.timestamps = [];
    tracker.backoffMs = 0;
  }

  if (tracker.backoffMs > 0) {
    await new Promise(r => setTimeout(r, tracker.backoffMs));
    tracker.backoffMs = 0;
  }

  if (tracker.timestamps.length > activeScope.maxRequestsTotal) {
    logger.warn({ targetKey }, "Max total requests reached for target");
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const userSignal = options.signal;
  if (userSignal) {
    userSignal.addEventListener("abort", () => controller.abort(), { once: true });
  }

  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    tracker.timestamps.push(now);

    if (res.status === 429) {
      tracker.consecutive429s++;
      tracker.backoffMs = Math.min(60000, 1000 * Math.pow(2, tracker.consecutive429s));
      logger.warn({ targetKey, backoffMs: tracker.backoffMs, url }, "Received 429 — increasing backoff");
    } else {
      tracker.consecutive429s = Math.max(0, tracker.consecutive429s - 1);
      tracker.backoffMs = Math.max(0, tracker.backoffMs - 500);
    }

    if (res.status >= 500) {
      await new Promise(r => setTimeout(r, 500));
    }

    return res;
  } catch (err) {
    tracker.backoffMs = Math.min(10000, (tracker.backoffMs || 100) * 2);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function getRateStats(targetKey: string) {
  const tracker = rateTrackers.get(targetKey);
  if (!tracker) return { requestCount: 0, backoffMs: 0, throttled: false };
  return {
    requestCount: tracker.timestamps.length,
    backoffMs: tracker.backoffMs,
    throttled: tracker.backoffMs > 0,
    consecutive429s: tracker.consecutive429s,
  };
}
