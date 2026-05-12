import { ScanContext, ScanFinding, ctxFetch } from "./types";

// Test with a realistic attacker origin and null (sandboxed iframe exploit)
const EVIL_ORIGINS = [
  "https://evil.com",
  "https://attacker.com",
  "null",
];

export async function runCorsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/CORS", message: "Testing CORS policy (preflight + credentialed GET verification)" });

  const apiEndpoints = discoveredEndpoints
    .filter(ep => ep.includes("/api") || ep.endsWith("/"))
    .slice(0, 5);

  if (!apiEndpoints.includes(targetUrl)) apiEndpoints.unshift(targetUrl);

  for (const endpoint of apiEndpoints) {
    for (const origin of EVIL_ORIGINS) {
      if (seen.has(endpoint)) break;

      // ── Step 1: OPTIONS preflight ───────────────────────────────────────────
      const preflightRes = await ctxFetch(ctx, endpoint, {
        method: "OPTIONS",
        headers: {
          "Origin": origin,
          "Access-Control-Request-Method": "GET",
          "Access-Control-Request-Headers": "Authorization",
        },
      });

      if (!preflightRes) continue;

      const acao = preflightRes.headers.get("access-control-allow-origin");
      const acac = preflightRes.headers.get("access-control-allow-credentials");

      // ── Step 2: Verify with an actual GET request, not just preflight ───────
      // Preflight can pass CORS while the actual request is blocked server-side.
      // We send a GET with the Origin header to confirm the policy applies to
      // real requests, which is what an attacker's browser would send.
      const getRes = await ctxFetch(ctx, endpoint, {
        headers: { "Origin": origin },
        redirect: "follow",
      });
      const getAcao = getRes?.headers.get("access-control-allow-origin") ?? acao;
      const getAcac = getRes?.headers.get("access-control-allow-credentials") ?? acac;

      const preflight = `OPTIONS ${endpoint}\nOrigin: ${origin}\n\nPreflight Response:\nAccess-Control-Allow-Origin: ${acao ?? "[not set]"}\nAccess-Control-Allow-Credentials: ${acac ?? "[not set]"}\n\nGET Verification:\nAccess-Control-Allow-Origin: ${getAcao ?? "[not set]"}\nAccess-Control-Allow-Credentials: ${getAcac ?? "[not set]"}`;

      // ── Case 1: Wildcard + credentials — IMPOSSIBLE per spec but some servers
      //    misconfigure it; browsers reject it, but non-browser clients exploit it
      if ((acao === "*" || getAcao === "*") && (acac === "true" || getAcac === "true")) {
        seen.add(endpoint);
        findings.push({
          title: "Critical CORS Misconfiguration — Wildcard Origin with Credentials",
          category: "CORS Misconfiguration",
          severity: "critical",
          endpoint,
          description: "The server returns Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. While browsers reject this combination per the CORS spec, non-browser HTTP clients (scripts, curl, Axios without a browser) can exploit this to read credentialed responses from any origin. This exposes session tokens and authenticated data.",
          evidence: preflight,
          recommended_fix: "Never combine ACAO: * with ACAC: true. If credentials are needed, specify an explicit allowlisted origin: Access-Control-Allow-Origin: https://yourdomain.com",
          cvss_score: 9.1,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder/CORS",
          scanner_family: "web",
          confidence: 0.97,
        });
        emit({ type: "log", message: `  [CORS CRITICAL] wildcard + credentials on ${endpoint}` });
        break;
      }

      // ── Case 2: Wildcard origin (no credentials) ────────────────────────────
      if (acao === "*" || getAcao === "*") {
        seen.add(endpoint);
        findings.push({
          title: "Overly Permissive CORS — Wildcard Origin Allowed",
          category: "CORS Misconfiguration",
          severity: "high",
          endpoint,
          description: "The server sets Access-Control-Allow-Origin: * allowing any website to read responses. Public APIs intentionally use this, but if the endpoint returns any user-specific or sensitive data, the wildcard is exploitable by any malicious web page.",
          evidence: preflight,
          recommended_fix: "If the endpoint returns sensitive data, replace ACAO: * with an explicit allowlist: Access-Control-Allow-Origin: https://yourdomain.com",
          cvss_score: 7.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder/CORS",
          scanner_family: "web",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [CORS HIGH] wildcard origin on ${endpoint}` });
        break;
      }

      // ── Case 3: Reflected attacker origin + credentials — most exploitable ──
      const reflectsOrigin = (acao === origin || getAcao === origin) && origin !== "null";
      const allowsCredentials = acac === "true" || getAcac === "true";

      if (reflectsOrigin) {
        seen.add(endpoint);
        const severity = allowsCredentials ? "critical" : "high";
        findings.push({
          title: allowsCredentials
            ? "CORS Reflects Arbitrary Origin with Credentials — Session Hijack Risk"
            : "CORS Reflects Arbitrary Origin (No Credentials)",
          category: "CORS Misconfiguration",
          severity,
          endpoint,
          description: allowsCredentials
            ? `The server reflects any Origin header back in Access-Control-Allow-Origin AND sets Allow-Credentials: true. An attacker's website at "${origin}" can make authenticated cross-origin requests, read responses including session tokens, CSRF tokens, and private API data — even if the user is logged in on your domain.`
            : `The server reflects any Origin header back in Access-Control-Allow-Origin. While credentials are not allowed, an attacker can read public API responses from any web page, which may enable data exfiltration if the endpoint returns non-public information.`,
          evidence: [
            preflight,
            "",
            allowsCredentials
              ? `EXPLOIT: An attacker page at ${origin} can run:\n  fetch("${endpoint}", {credentials:"include"}).then(r=>r.json()).then(exfiltrate)`
              : `EXPLOIT: An attacker page at ${origin} can read response body via:\n  fetch("${endpoint}").then(r=>r.text()).then(exfiltrate)`,
          ].join("\n"),
          recommended_fix: "Validate the Origin header against a static allowlist. Never use req.headers.origin directly as the ACAO value. If credentials are needed, the allowlist must not accept arbitrary domains.",
          cvss_score: allowsCredentials ? 9.3 : 7.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder/CORS",
          scanner_family: "web",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [CORS ${severity.toUpperCase()}] reflected origin${allowsCredentials ? " + credentials" : ""} on ${endpoint}` });
        break;
      }

      // ── Case 4: Null origin allowed ──────────────────────────────────────────
      if (acao === "null" || getAcao === "null") {
        seen.add(endpoint);
        findings.push({
          title: "CORS Allows Null Origin — Sandboxed Iframe Exploit",
          category: "CORS Misconfiguration",
          severity: "high",
          endpoint,
          description: "The server allows the null origin. Browsers send Origin: null from sandboxed iframes (e.g. <iframe sandbox src=...>). An attacker can host a sandboxed iframe on any site and read responses from this endpoint cross-origin.",
          evidence: preflight,
          recommended_fix: "Remove null from the CORS origin allowlist. Treat null origin as untrusted.",
          cvss_score: 6.5,
          cwe_id: "CWE-346",
          scanner_name: "Bug-Finder/CORS",
          scanner_family: "web",
          confidence: 0.92,
        });
        emit({ type: "log", message: `  [CORS HIGH] null origin allowed on ${endpoint}` });
        break;
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "CORS policy appears well-configured" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/CORS",
    message: `CORS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
