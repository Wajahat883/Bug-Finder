import { ScanContext, ScanFinding, ctxFetch } from "./types";

const OAUTH_PATHS = [
  "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
  "/connect/authorize", "/sso/authorize", "/openid/authorize",
  "/login/oauth", "/api/oauth", "/.well-known/openid-configuration",
];

export async function runOAuthCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/OAuth", message: "Checking OAuth/SSO misconfiguration" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : OAUTH_PATHS.length;

  // Check OpenID Connect discovery document
  const oidcRes = await ctxFetch(ctx, `${base}/.well-known/openid-configuration`, {}, 8000);
  if (oidcRes && oidcRes.status === 200) {
    let config: Record<string, unknown> = {};
    try { config = await oidcRes.json() as Record<string, unknown>; } catch { /* skip */ }

    emit({ type: "log", message: `OpenID Connect configuration found at /.well-known/openid-configuration` });

    // Check for insecure response types
    const responseTypes = config.response_types_supported as string[] ?? [];
    if (responseTypes.includes("token")) {
      findings.push({
        title: "OAuth Implicit Flow Supported (Deprecated)",
        category: "OAuth/SSO",
        severity: "medium",
        endpoint: `${base}/.well-known/openid-configuration`,
        description: "The OAuth server supports the implicit flow (response_type=token), which is deprecated by OAuth 2.0 Security Best Current Practices. The implicit flow exposes access tokens in URLs and browser history.",
        evidence: `OpenID Configuration:\nresponse_types_supported: ${JSON.stringify(responseTypes)}`,
        recommended_fix: "Disable implicit flow. Use Authorization Code flow with PKCE instead. Update all clients to use the secure flow.",
        cvss_score: 6.1,
        cwe_id: "CWE-287",
        scanner_name: "Bug-Finder/OAuth",
        scanner_family: "auth",
        confidence: 0.92,
      });
    }

    // Check grant types
    const grantTypes = config.grant_types_supported as string[] ?? [];
    if (grantTypes.includes("password")) {
      findings.push({
        title: "OAuth Resource Owner Password Grant Enabled",
        category: "OAuth/SSO",
        severity: "medium",
        endpoint: `${base}/.well-known/openid-configuration`,
        description: "The OAuth Resource Owner Password Credentials (ROPC) grant is enabled. This grant requires clients to handle user credentials directly, negating many OAuth security benefits.",
        evidence: `grant_types_supported: ${JSON.stringify(grantTypes)}`,
        recommended_fix: "Disable the password grant. Use Authorization Code with PKCE. Only use ROPC for highly trusted legacy clients.",
        cvss_score: 5.9,
        cwe_id: "CWE-287",
        scanner_name: "Bug-Finder/OAuth",
        scanner_family: "auth",
        confidence: 0.9,
      });
    }

    // Check JWKS endpoint
    const jwksUri = config.jwks_uri as string;
    if (jwksUri) {
      const jwksRes = await ctxFetch(ctx, jwksUri, {}, 5000);
      if (jwksRes && jwksRes.status === 200) {
        let jwks: Record<string, unknown> = {};
        try { jwks = await jwksRes.json() as Record<string, unknown>; } catch { /* skip */ }
        const keys = jwks.keys as Array<Record<string, unknown>> ?? [];
        const weakKeys = keys.filter(k => k.kty === "RSA" && Number(k.n?.toString().length ?? 0) < 344);
        if (weakKeys.length > 0) {
          findings.push({
            title: "JWKS Contains Potentially Weak RSA Keys",
            category: "OAuth/SSO",
            severity: "high",
            endpoint: jwksUri,
            description: "The JWKS endpoint contains RSA keys that may be shorter than the recommended 2048 bits. Weak RSA keys can be factored, allowing token forgery.",
            evidence: `JWKS URI: ${jwksUri}\nKeys found: ${keys.length}\nPotentially weak keys: ${weakKeys.length}`,
            recommended_fix: "Use RSA keys of at least 2048 bits. Prefer EC keys (P-256) for better performance and security.",
            cvss_score: 7.5,
            cwe_id: "CWE-326",
            scanner_name: "Bug-Finder/OAuth",
            scanner_family: "auth",
            confidence: 0.7,
          });
        }
      }
    }
  }

  // Test OAuth authorize endpoint for open redirect
  for (const path of OAUTH_PATHS.slice(0, budget)) {
    const url = `${base}${path}`;
    const attackRedirect = "https://evil.com/callback";

    // Test with open redirect payload
    const testUrl = `${url}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(attackRedirect)}&state=x`;
    const r = await ctxFetch(ctx, testUrl, { redirect: "manual" });
    if (!r) continue;

    const location = r.headers.get("location") ?? "";

    // If it redirects to evil.com, that's an open redirect
    if (location.includes("evil.com")) {
      findings.push({
        title: "OAuth Open Redirect — Arbitrary redirect_uri Accepted",
        category: "OAuth/SSO",
        severity: "critical",
        endpoint: url,
        description: `The OAuth authorization endpoint accepted an arbitrary redirect_uri (https://evil.com/callback) without validation. An attacker can steal authorization codes by tricking users into authenticating and being redirected to the attacker's server.`,
        evidence: `GET ${testUrl}\nHTTP ${r.status}\nLocation: ${location}`,
        recommended_fix: "Strictly validate redirect_uri against a pre-registered whitelist. Never allow arbitrary URIs. Use exact string matching, not prefix matching.",
        cvss_score: 9.1,
        cwe_id: "CWE-601",
        scanner_name: "Bug-Finder/OAuth",
        scanner_family: "auth",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [OAuth] Open redirect at ${url} → ${location}` });
    } else if (r.status === 200 || r.status === 302 || r.status === 301) {
      emit({ type: "log", message: `  OAuth endpoint found at ${url} (${r.status})` });
    }

    // Test for missing state parameter enforcement
    const noStateUrl = `${url}?response_type=code&client_id=test&redirect_uri=${encodeURIComponent(base + "/callback")}`;
    const noStateR = await ctxFetch(ctx, noStateUrl, { redirect: "manual" });
    if (noStateR && (noStateR.status === 200 || noStateR.status === 302)) {
      const noStateLocation = noStateR.headers.get("location") ?? "";
      if (!noStateLocation.includes("state=") && noStateR.status === 302) {
        findings.push({
          title: "OAuth Missing State Parameter — CSRF Risk",
          category: "OAuth/SSO",
          severity: "medium",
          endpoint: url,
          description: "The OAuth authorization request succeeded without a state parameter. The state parameter is required to prevent CSRF attacks against the OAuth flow.",
          evidence: `GET ${noStateUrl}\nHTTP ${noStateR.status}\nLocation: ${noStateLocation}\nstate parameter: [NOT REQUIRED]`,
          recommended_fix: "Require and validate the state parameter in all OAuth authorization requests. Generate a cryptographically random state value per request.",
          cvss_score: 6.1,
          cwe_id: "CWE-352",
          scanner_name: "Bug-Finder/OAuth",
          scanner_family: "auth",
          confidence: 0.75,
        });
        emit({ type: "log", message: `  [OAuth] Missing state parameter enforcement at ${url}` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No OAuth/SSO endpoints or misconfigurations detected" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/OAuth", message: `OAuth check complete — ${findings.length} finding(s)` });
  return findings;
}
