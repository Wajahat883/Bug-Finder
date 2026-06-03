/**
 * False Positive Reduction Engine (Revised)
 *
 * CDN/WAF detection does NOT reduce confidence. Infrastructure signals are
 * classified separately and scored at zero risk — never mixed with real vulns.
 *
 * This engine ONLY handles:
 *   - SPA fallback suppression (endpoint returned index.html shell)
 *   - robots.txt → informational classification
 *   - Case-insensitive HTTP header parsing (RFC 7230)
 */

import { rfcHeaderContains, rfcHeaderGet } from "./normalize-engine";
import type { ScanFinding } from "./types";

const INFO_ONLY_TITLES = new Set([
  "Sensitive Paths Disclosed in robots.txt",
  "Security.txt Not Configured",
]);

export { rfcHeaderGet, rfcHeaderContains };

export function classifyRobotsTxtFinding(raw: ScanFinding): ScanFinding {
  return {
    ...raw,
    severity: "info",
    cvss_score: 0,
    description:
      raw.description +
      " NOTE: robots.txt is a public advisory file — its contents are NOT a security vulnerability. This finding is informational only.",
    confidence: 1.0,
  };
}

export function isRobotsTxtTitle(title: string): boolean {
  return INFO_ONLY_TITLES.has(title);
}

export function checkCaseInsensitiveHeader(
  headers: Headers,
  headerName: string
): string | null {
  return rfcHeaderGet(
    Object.fromEntries(
      Array.from((headers as unknown as Iterable<[string, string]>)).map(
        ([k, v]) => [k.toLowerCase(), v]
      )
    ),
    headerName
  );
}

export function headerHasDirectiveCi(
  headers: Headers,
  headerName: string,
  directive: string
): boolean {
  return rfcHeaderContains(
    Object.fromEntries(
      Array.from((headers as unknown as Iterable<[string, string]>)).map(
        ([k, v]) => [k.toLowerCase(), v]
      )
    ),
    headerName,
    directive
  );
}
