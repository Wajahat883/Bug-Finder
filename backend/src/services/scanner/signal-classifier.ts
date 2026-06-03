/**
 * Signal Classification Engine
 *
 * Enterprise-grade finding classifier (Burp Suite / Nessus style).
 * Every finding is assigned exactly ONE signal type. This determines
 * its treatment in risk scoring, confidence calculation, and reporting.
 *
 *   VULNERABILITY   — Real security bugs with an exploit path (XSS, SQLi, SSRF, auth bypass)
 *   MISCONFIG       — Defense-in-depth gaps that require context to be risky (missing CSP, weak TLS)
 *   INFRASTRUCTURE  — Operational metadata, NOT a security issue (CDN, WAF, cache, server fingerprint)
 *   INFORMATIONAL   — Discovery data with zero risk (robots.txt, tech detection, subdomains)
 *
 * INFRASTRUCTURE signals are EXPLICITLY EXCLUDED from risk scoring.
 * CDN/WAF detection is NOT a vulnerability and must never affect severity or confidence.
 */

import type { ScanFinding } from "./types";

// ── Signal type enum ────────────────────────────────────────────────────────────

export type SignalType = "vulnerability" | "misconfig" | "infrastructure" | "informational";

export interface SignalClassification {
  type: SignalType;
  riskRelevant: boolean;
  label: string;
}

// ── Classification tables ────────────────────────────────────────────────────────

const VULN_CATEGORIES = new Set([
  "xss", "sql injection", "ssrf", "open redirect", "csrf",
  "authentication bypass", "authorization bypass", "business logic",
  "command injection", "server-side template injection",
  "ssti", "xxe", "path traversal", "idor",
  "request smuggling", "file upload", "insecure deserialization",
  "subdomain takeover",
]);

const VULN_SCANNER_FAMILIES = new Set([
  "injection", "auth", "session", "access-control", "business-logic",
]);

const MISCONFIG_CATEGORIES = new Set([
  "security headers", "cookie security", "cors", "tls/transport",
  "hsts", "email security", "dns",
]);

const INFRA_SCANNERS = new Set([
  "Bug-Finder/WAF", "Bug-Finder/Infra",
]);

const INFRA_TITLES = new Set([
  "waf/cdn detected", "load balancer detected",
  "tls/transport", // HSTS is misconfig, but TLS version/fingerprint is infra
]);

const INFO_SCANNERS = new Set([
  "Bug-Finder/Fingerprint", "Bug-Finder/OSINT",
]);

const INFO_TITLES_LOWER = new Set([
  "sensitive paths disclosed in robots.txt",
  "security.txt not configured",
  "technology detection",
  "subdomain enumeration",
]);

const CDN_SERVICES = new Set(["cloudflare", "fastly", "akamai", "varnish cache", "aws waf"]);

// ── Classification logic ────────────────────────────────────────────────────────

export function classifySignal(finding: ScanFinding): SignalClassification {
  const titleLower = finding.title.toLowerCase();
  const catLower = finding.category.toLowerCase();
  const scannerLower = finding.scanner_name.toLowerCase();
  const familyLower = finding.scanner_family.toLowerCase();

  // 1. Infrastructure signals — operational metadata, NOT security issues
  if (INFRA_SCANNERS.has(scannerLower) || INFRA_SCANNERS.has(finding.scanner_name)) {
    const infra = isCdnOnly(finding);
    return {
      type: "infrastructure",
      riskRelevant: false,
      label: infra ? "CDN detection — operational metadata" : "Infrastructure detection — operational metadata",
    };
  }

  // 2. Explicit CDN/WAF finding titles
  if (titleLower.startsWith("waf/cdn detected") || titleLower.includes("load balancer detected")) {
    return {
      type: "infrastructure",
      riskRelevant: false,
      label: "Infrastructure metadata — not a vulnerability",
    };
  }

  // 3. Informational signals — discovery data with zero risk
  if (INFO_SCANNERS.has(scannerLower) || INFO_TITLES_LOWER.has(titleLower)) {
    return {
      type: "informational",
      riskRelevant: false,
      label: "Informational — discovery data, no security risk",
    };
  }

  if (finding.severity === "info" && finding.cvss_score === 0) {
    return {
      type: "informational",
      riskRelevant: false,
      label: "Informational — zero CVSS score",
    };
  }

  // 4. Real vulnerability signals — exploit path exists
  if (VULN_CATEGORIES.has(catLower) || VULN_SCANNER_FAMILIES.has(familyLower)) {
    return {
      type: "vulnerability",
      riskRelevant: true,
      label: "Vulnerability — real security risk with exploit potential",
    };
  }

  // 5. Misconfiguration signals — may or may not have real risk
  if (MISCONFIG_CATEGORIES.has(catLower)) {
    return {
      type: "misconfig",
      riskRelevant: true,
      label: "Security misconfiguration — may require context to assess risk",
    };
  }

  // Default: treat as misconfig unless clearly informational
  if (finding.severity === "info") {
    return { type: "informational", riskRelevant: false, label: "Informational" };
  }

  return { type: "misconfig", riskRelevant: true, label: "Security misconfiguration" };
}

// ── Utility queries ──────────────────────────────────────────────────────────────

export function isVulnerabilitySignal(finding: ScanFinding): boolean {
  return classifySignal(finding).type === "vulnerability";
}

export function isInfrastructureSignal(finding: ScanFinding): boolean {
  return classifySignal(finding).type === "infrastructure";
}

export function isInformationalSignal(finding: ScanFinding): boolean {
  return classifySignal(finding).type === "informational";
}

export function isRiskRelevant(finding: ScanFinding): boolean {
  return classifySignal(finding).riskRelevant;
}

export function isCdnOnly(finding: ScanFinding): boolean {
  if (!finding.title.startsWith("WAF/CDN Detected:")) return false;
  const names = finding.title.replace("WAF/CDN Detected:", "").split(",").map(s => s.trim().toLowerCase());
  return names.every(n => CDN_SERVICES.has(n));
}
