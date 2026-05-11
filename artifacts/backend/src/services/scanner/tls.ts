import { ScanContext, ScanFinding, safeFetch } from "./types";

export async function runTlsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Nmap/TLS", message: "Checking TLS and HTTPS configuration" });

  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === "https:";

  if (!isHttps) {
    const httpsUrl = targetUrl.replace(/^http:/, "https:");
    const httpsRes = await safeFetch(httpsUrl, { redirect: "manual" });
    const httpRes = await safeFetch(targetUrl, { redirect: "manual" });

    if (!httpsRes) {
      findings.push({
        title: "HTTPS Not Available",
        category: "TLS/Transport",
        severity: "high",
        endpoint: targetUrl,
        description: "The target does not appear to support HTTPS. All traffic is transmitted in plaintext.",
        evidence: `HTTP URL: ${targetUrl} — HTTPS endpoint unreachable`,
        recommended_fix: "Enable TLS on the server and redirect all HTTP traffic to HTTPS.",
        cvss_score: 7.5,
        cwe_id: "CWE-319",
        scanner_name: "Nmap",
        scanner_family: "network",
        confidence: 0.92,
      });
      emit({ type: "log", message: "HTTPS not available on target" });
    }

    if (httpRes && httpRes.status === 200) {
      findings.push({
        title: "HTTP Not Redirected to HTTPS",
        category: "TLS/Transport",
        severity: "medium",
        endpoint: targetUrl,
        description: "The server accepts plaintext HTTP connections without redirecting to HTTPS.",
        evidence: `GET ${targetUrl} HTTP/1.1\nResponse: ${httpRes.status} ${httpRes.statusText}\nNo Location redirect header found`,
        recommended_fix: "Configure a 301 redirect from HTTP to HTTPS for all endpoints.",
        cvss_score: 5.3,
        cwe_id: "CWE-319",
        scanner_name: "Nmap",
        scanner_family: "network",
        confidence: 0.88,
      });
      emit({ type: "log", message: "HTTP not redirected to HTTPS" });
    }
  }

  // Check HSTS header
  const res = await safeFetch(targetUrl);
  if (res) {
    const hsts = res.headers.get("strict-transport-security");
    if (!hsts) {
      findings.push({
        title: "Missing HTTP Strict-Transport-Security (HSTS) Header",
        category: "TLS/Transport",
        severity: "medium",
        endpoint: targetUrl,
        description:
          "The server does not set the Strict-Transport-Security header, allowing downgrade attacks.",
        evidence: `GET ${targetUrl}\nResponse headers:\n${[...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n")}\n\nStrict-Transport-Security: [MISSING]`,
        recommended_fix:
          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        cvss_score: 5.3,
        cwe_id: "CWE-319",
        scanner_name: "Nmap",
        scanner_family: "network",
        confidence: 0.95,
      });
      emit({ type: "log", message: "Missing HSTS header" });
    } else {
      emit({ type: "log", message: `HSTS configured: ${hsts.slice(0, 60)}` });
      if (!hsts.includes("includeSubDomains")) {
        findings.push({
          title: "HSTS Missing includeSubDomains Directive",
          category: "TLS/Transport",
          severity: "low",
          endpoint: targetUrl,
          description: "The HSTS header does not include the 'includeSubDomains' directive.",
          evidence: `Strict-Transport-Security: ${hsts}`,
          recommended_fix: "Add 'includeSubDomains' to your HSTS header.",
          cvss_score: 3.1,
          cwe_id: "CWE-319",
          scanner_name: "Nmap",
          scanner_family: "network",
          confidence: 0.9,
        });
      }
    }
  }

  emit({
    type: "engine_done",
    engine: "Nmap/TLS",
    message: `TLS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
