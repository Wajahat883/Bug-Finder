import { ScanContext, ScanFinding, ctxFetch } from "./types";

const EVIL_ORIGINS = [
  "https://evil.com",
  "https://attacker.com",
  "null",
];

export async function runCorsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "OWASP ZAP/CORS", message: "Testing CORS policy" });

  const base = new URL(targetUrl);
  const apiEndpoints = discoveredEndpoints
    .filter(ep => ep.includes("/api") || ep.endsWith("/"))
    .slice(0, 4);

  if (!apiEndpoints.includes(targetUrl)) apiEndpoints.unshift(targetUrl);

  for (const endpoint of apiEndpoints) {
    for (const origin of EVIL_ORIGINS) {
      const res = await ctxFetch(ctx, endpoint, {
        method: "OPTIONS",
        headers: {
          "Origin": origin,
          "Access-Control-Request-Method": "GET",
          "Access-Control-Request-Headers": "Authorization",
        },
      });

      if (!res) continue;

      const acao = res.headers.get("access-control-allow-origin");
      const acac = res.headers.get("access-control-allow-credentials");

      if (acao === "*") {
        findings.push({
          title: "Overly Permissive CORS Policy — Wildcard Origin Allowed",
          category: "CORS Misconfiguration",
          severity: "high",
          endpoint,
          description:
            "The server sets Access-Control-Allow-Origin: * which allows any website to make cross-origin requests and read responses.",
          evidence: `OPTIONS ${endpoint}\nOrigin: ${origin}\n\nResponse:\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: ${acac ?? "[not set]"}`,
          recommended_fix:
            "Replace wildcard CORS with a strict allowlist: Access-Control-Allow-Origin: https://yourdomain.com",
          cvss_score: 7.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder",
          scanner_family: "web",
          confidence: 0.97,
        });
        emit({ type: "log", message: `CORS wildcard on ${endpoint}` });
        break;
      }

      if (acao && acao === origin && origin !== "null") {
        const severity = acac === "true" ? "critical" : "high";
        findings.push({
          title: `CORS Reflects Arbitrary Origin${acac === "true" ? " with Credentials" : ""}`,
          category: "CORS Misconfiguration",
          severity,
          endpoint,
          description: `The server reflects any supplied Origin header back in Access-Control-Allow-Origin${acac === "true" ? " and also sets Allow-Credentials: true, enabling cross-origin credential theft" : ""}.`,
          evidence: `OPTIONS ${endpoint}\nOrigin: ${origin}\n\nResponse:\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac ?? "[not set]"}`,
          recommended_fix:
            "Validate Origins against a static allowlist. Never reflect arbitrary origins. Do not combine ACAO: * with credentials.",
          cvss_score: severity === "critical" ? 9.1 : 7.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder",
          scanner_family: "web",
          confidence: 0.93,
        });
        emit({ type: "log", message: `CORS reflects arbitrary origin on ${endpoint}` });
        break;
      }

      if (acao === "null") {
        findings.push({
          title: "CORS Allows Null Origin",
          category: "CORS Misconfiguration",
          severity: "high",
          endpoint,
          description: "The server allows the null origin, which can be exploited by sandboxed iframes.",
          evidence: `Access-Control-Allow-Origin: null`,
          recommended_fix: "Remove null from the allowed origins list.",
          cvss_score: 6.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder",
          scanner_family: "web",
          confidence: 0.9,
        });
        emit({ type: "log", message: `CORS allows null origin on ${endpoint}` });
        break;
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "CORS policy appears well-configured" });
  }

  emit({
    type: "engine_done",
    engine: "OWASP ZAP/CORS",
    message: `CORS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
