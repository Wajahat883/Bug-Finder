import { logger } from "./logger";

// POINT 1: SSRF Protection — validate URLs against private/internal IP ranges
const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,       // AWS metadata / link-local
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // CGNAT
  /^0\./,
  /^::1$/,             // IPv6 loopback
  /^fc00:/i,           // IPv6 private
  /^fe80:/i,           // IPv6 link-local
];

const BLOCKED_HOSTNAMES = [
  "localhost",
  "metadata.google.internal",
  "metadata",
];

const ALLOWED_SCHEMES = ["http:", "https:"];

export interface SsrfCheckResult {
  allowed: boolean;
  reason?: string;
}

export function checkSsrf(targetUrl: string): SsrfCheckResult {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { allowed: false, reason: "Invalid URL format" };
  }

  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    return { allowed: false, reason: `Blocked scheme: ${parsed.protocol}` };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    return { allowed: false, reason: `Blocked hostname: ${hostname}` };
  }

  // Check if hostname is a raw IP
  const ipv4Pattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipv4Pattern.test(hostname)) {
    for (const range of PRIVATE_RANGES) {
      if (range.test(hostname)) {
        return { allowed: false, reason: `Blocked private IP range: ${hostname}` };
      }
    }
    // 0.0.0.0 and 255.255.255.255
    if (hostname === "0.0.0.0" || hostname === "255.255.255.255") {
      return { allowed: false, reason: `Blocked special IP: ${hostname}` };
    }
  }

  // Block IPv6 private ranges
  if (hostname.startsWith("[")) {
    const ipv6 = hostname.slice(1, -1);
    // Handle IPv6-mapped IPv4 addresses (e.g., [::ffff:169.254.169.254])
    if (ipv6.toLowerCase().startsWith("::ffff:")) {
      const ipv4 = ipv6.slice(7);
      for (const range of PRIVATE_RANGES) {
        if (range.test(ipv4)) {
          return { allowed: false, reason: `Blocked IPv6-mapped IPv4 private range: ${ipv4}` };
        }
      }
      if (ipv4 === "0.0.0.0" || ipv4 === "255.255.255.255") {
        return { allowed: false, reason: `Blocked special IP: ${ipv4}` };
      }
      return { allowed: true };
    }
    for (const range of PRIVATE_RANGES) {
      if (range.test(ipv6)) {
        return { allowed: false, reason: `Blocked private IPv6: ${ipv6}` };
      }
    }
  }

  return { allowed: true };
}

export function assertSsrfSafe(targetUrl: string): void {
  const result = checkSsrf(targetUrl);
  if (!result.allowed) {
    logger.warn({ targetUrl, reason: result.reason }, "SSRF blocked");
    throw new Error(`SSRF protection: ${result.reason}`);
  }
}
