/**
 * Domain Normalization Engine
 *
 * Provides canonical domain representations for consistent SPF/DMARC checks,
 * deduplication key construction, and scope matching across scanner modules.
 *
 * Key features:
 *   - www → root domain mapping (SPF lives on root, not www)
 *   - Case-insensitive DNS record parsing (RFC 1035)
 *   - Public suffix-aware root domain extraction
 *   - Endpoint normalization for stable dedup keys
 */

import { logger } from "../../lib/logger";

const PUBLIC_SUFFIX_CACHE = new Map<string, string | null>();

const COMMON_TWO_PART_TLDS = new Set([
  "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.il",
  "com.au", "net.au", "org.au", "com.br", "net.br", "org.br",
  "com.cn", "net.cn", "org.cn", "com.tw", "net.tw", "org.tw",
  "com.mx", "net.mx", "org.mx", "co.id", "or.id", "ac.id",
  "com.sg", "net.sg", "org.sg", "com.hk", "net.hk", "org.hk",
  "com.ar", "net.ar", "org.ar", "com.pl", "net.pl", "org.pl",
  "com.pt", "net.pt", "org.pt", "com.tr", "net.tr", "org.tr",
  "com.ua", "net.ua", "org.ua", "com.vn", "net.vn", "org.vn",
  "org.uk", "me.uk", "ac.uk", "gov.uk", "nhs.uk",
  "com.my", "net.my", "org.my", "edu.my", "gov.my",
]);

export interface DomainInfo {
  hostname: string;
  port: string;
  protocol: string;
  isIp: boolean;
  isLocalhost: boolean;
  rootDomain: string;
  apexDomain: string;
  hasWwwPrefix: boolean;
}

export function parseDomain(urlOrHost: string): DomainInfo | null {
  try {
    const parsed = new URL(
      urlOrHost.includes("://") ? urlOrHost : `https://${urlOrHost}`
    );
    const hostname = parsed.hostname.toLowerCase();
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
    const isLocalhost = hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";

    return {
      hostname,
      port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
      protocol: parsed.protocol.replace(":", ""),
      isIp,
      isLocalhost,
      rootDomain: getRootDomain(hostname),
      apexDomain: stripWww(hostname),
      hasWwwPrefix: hostname.startsWith("www."),
    };
  } catch {
    return null;
  }
}

function stripWww(hostname: string): string {
  return hostname.replace(/^www\./i, "");
}

function getRootDomain(hostname: string): string {
  const cached = PUBLIC_SUFFIX_CACHE.get(hostname);
  if (cached !== undefined) return cached ?? hostname;

  const parts = hostname.split(".");
  if (parts.length <= 2) {
    PUBLIC_SUFFIX_CACHE.set(hostname, hostname);
    return hostname;
  }

  const lastTwo = parts.slice(-2).join(".").toLowerCase();
  const lastThree = parts.slice(-3).join(".").toLowerCase();

  if (COMMON_TWO_PART_TLDS.has(lastTwo)) {
    const root = parts.slice(-3).join(".");
    PUBLIC_SUFFIX_CACHE.set(hostname, root);
    return root;
  }

  if (COMMON_TWO_PART_TLDS.has(lastThree)) {
    const root = parts.slice(-4).join(".");
    PUBLIC_SUFFIX_CACHE.set(hostname, root);
    return root;
  }

  const root = parts.slice(-2).join(".");
  PUBLIC_SUFFIX_CACHE.set(hostname, root);
  return root;
}

export function getRootRoot(hostname: string): string {
  const root = getRootDomain(stripWww(hostname));
  PUBLIC_SUFFIX_CACHE.set(hostname, root);
  return root;
}

export function normalizeEndpoint(endpoint: string): string {
  try {
    const url = new URL(endpoint);
    return url.origin.toLowerCase() + url.pathname;
  } catch {
    return endpoint.toLowerCase();
  }
}

export function buildDedupKey(title: string, endpoint: string): string {
  return `${title}||${normalizeEndpoint(endpoint)}`;
}

export function rfcHeaderGet(
  headers: Headers | Record<string, string>,
  name: string
): string | null {
  const key = name.toLowerCase();
  if (headers instanceof Headers) {
    for (const [k, v] of (headers as unknown as Iterable<[string, string]>)) {
      if (k.toLowerCase() === key) return v;
    }
    return null;
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === key) return v;
  }
  return null;
}

export function rfcHeaderContains(
  headers: Headers | Record<string, string>,
  name: string,
  substring: string
): boolean {
  const value = rfcHeaderGet(headers, name);
  if (!value) return false;
  return value.toLowerCase().includes(substring.toLowerCase());
}

export { getRootDomain, stripWww };
