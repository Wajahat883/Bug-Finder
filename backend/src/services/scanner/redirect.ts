import { ScanContext, ScanFinding, ctxFetch } from "./types";

const REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnTo", "next", "url", "goto", "dest", "destination", "target", "ref", "referer", "callback", "continue"];
const EVIL_URL = "https://evil-test-8c7d.example.com";

export async function runRedirectCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Acunetix/Redirect", message: "Testing for open redirect vulnerabilities" });

  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const base = new URL(targetUrl);
  const authEndpoints = [
    `${base.origin}/login`,
    `${base.origin}/logout`,
    `${base.origin}/auth`,
    `${base.origin}/oauth/authorize`,
    `${base.origin}/api/auth`,
    ...discoveredEndpoints.filter(ep => ep.includes("login") || ep.includes("auth") || ep.includes("return") || ep.includes("callback")),
  ].slice(0, budget);

  for (const endpoint of authEndpoints) {
    for (const param of REDIRECT_PARAMS.slice(0, 6)) {
      const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(EVIL_URL)}`;

      const res = await ctxFetch(ctx, testUrl, { redirect: "manual" });
      if (!res) continue;

      const location = res.headers.get("location");
      const isRedirect = res.status >= 300 && res.status < 400;

      if (isRedirect && location && (location.includes("evil-test-8c7d.example.com") || location === EVIL_URL)) {
        const key = `${endpoint}:${param}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          title: `Open Redirect via Parameter: ${param}`,
          category: "Open Redirect",
          severity: "high",
          endpoint,
          description: `The "${param}" parameter controls the redirect destination without validation. An attacker can craft a link that redirects victims to a malicious site after performing an action on this domain.`,
          evidence: `GET ${testUrl}\n\nHTTP ${res.status} ${res.statusText}\nLocation: ${location}`,
          recommended_fix: "Validate redirect destinations against a whitelist of allowed URLs. Never use user-supplied input directly as a redirect destination.",
          cvss_score: 6.1,
          cwe_id: "CWE-601",
          scanner_name: "Acunetix",
          scanner_family: "web",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [Redirect] Open redirect via param=${param} at ${endpoint}` });
        break;
      } else if (isRedirect && location) {
        emit({ type: "log", message: `  Redirect to ${location.slice(0, 50)} — not an open redirect` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No open redirect vulnerabilities found" });
  }

  emit({
    type: "engine_done",
    engine: "Acunetix/Redirect",
    message: `Redirect check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
