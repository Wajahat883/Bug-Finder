import { ScanContext, ScanFinding, ctxFetch } from "./types";

const CACHE_BUSTER = () => `cp${Date.now()}`;

const UNKEYED_HEADERS = [
  { header: "X-Forwarded-Host", value: "evil.com", description: "X-Forwarded-Host override" },
  { header: "X-Host", value: "evil.com", description: "X-Host header injection" },
  { header: "X-Forwarded-Scheme", value: "nothttps", description: "X-Forwarded-Scheme manipulation" },
  { header: "X-Original-URL", value: "/admin", description: "X-Original-URL override" },
  { header: "X-Rewrite-URL", value: "/admin", description: "X-Rewrite-URL override" },
  { header: "X-Forwarded-Port", value: "8080", description: "X-Forwarded-Port manipulation" },
];

export async function runCachePoisoningCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Cache Poisoning Scanner", message: "Testing web cache poisoning via unkeyed headers" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 4 : UNKEYED_HEADERS.length;

  // First get a baseline response to compare against
  const cb = CACHE_BUSTER();
  const baselineUrl = `${targetUrl}${targetUrl.includes("?") ? "&" : "?"}cb=${cb}`;
  const baseline = await ctxFetch(ctx, baselineUrl, { redirect: "follow" });
  if (!baseline) {
    emit({ type: "engine_done", engine: "Cache Poisoning Scanner", message: "Skipped (unreachable)" });
    return findings;
  }
  const baselineBody = await baseline.text().catch(() => "");

  // Check if caching is in use
  const cacheHeaders = [
    baseline.headers.get("cache-control"),
    baseline.headers.get("cf-cache-status"),
    baseline.headers.get("x-cache"),
    baseline.headers.get("x-varnish"),
    baseline.headers.get("age"),
  ].filter(Boolean);

  const isCached = cacheHeaders.some(h => h && (h.includes("HIT") || h.includes("max-age") || h.includes("public")));

  if (!isCached) {
    emit({ type: "log", message: "No caching detected — limited cache poisoning risk" });
    // Still test for response reflection as a signal
  }

  // Test each unkeyed header for reflection in response body
  for (const test of UNKEYED_HEADERS.slice(0, budget)) {
    const cb2 = CACHE_BUSTER();
    const testUrl = `${targetUrl}${targetUrl.includes("?") ? "&" : "?"}cb=${cb2}`;

    const r = await ctxFetch(ctx, testUrl, {
      redirect: "follow",
      headers: {
        [test.header]: test.value,
      },
    });

    if (!r) continue;

    const body = await r.text().catch(() => "");

    // Check if the injected value is reflected in the response
    if (body.includes(test.value) && !baselineBody.includes(test.value)) {
      emit({ type: "log", message: `  [POISON?] ${test.header}: ${test.value} reflected in response` });
      findings.push({
        title: `Web Cache Poisoning Signal: ${test.description}`,
        category: "Cache Poisoning",
        severity: isCached ? "high" : "medium",
        endpoint: targetUrl,
        description: `The header "${test.header}: ${test.value}" was reflected in the response body. If this response is cached, an attacker could poison the cache and serve a malicious response to all users who subsequently request this URL.`,
        evidence: `GET ${testUrl}\n${test.header}: ${test.value}\nHTTP ${r.status}\n\nInjected value "${test.value}" found in response body.\nCaching active: ${isCached}\nCache-Control: ${baseline.headers.get("cache-control") ?? "not set"}\n\nReflection context: ...${body.slice(Math.max(0, body.indexOf(test.value) - 80), body.indexOf(test.value) + 80)}...`,
        recommended_fix: "Normalize or strip unkeyed headers before caching. Include all headers that influence the response in the cache key. Set Cache-Control: no-store for sensitive pages.",
        cvss_score: isCached ? 8.1 : 5.3,
        cwe_id: "CWE-444",
        scanner_name: "Cache Poisoning Scanner",
        scanner_family: "web",
        confidence: isCached ? 0.85 : 0.6,
      });
    } else {
      emit({ type: "log", message: `  ${test.header} — not reflected (${r.status})` });
    }

    // Check for X-Original-URL / X-Rewrite-URL path override
    if (test.header === "X-Original-URL" || test.header === "X-Rewrite-URL") {
      const overrideR = await ctxFetch(ctx, targetUrl, {
        headers: { [test.header]: "/admin" },
        redirect: "follow",
      });
      if (overrideR && overrideR.status === 200) {
        const overrideBody = await overrideR.text().catch(() => "");
        if (overrideBody.includes("admin") || overrideBody.length !== baselineBody.length) {
          findings.push({
            title: `URL Override via ${test.header} Header`,
            category: "Cache Poisoning",
            severity: "high",
            endpoint: targetUrl,
            description: `The server honored the ${test.header}: /admin header, potentially serving admin content to an unauthenticated request. This can also be used for cache poisoning to redirect users to attacker-controlled paths.`,
            evidence: `GET ${targetUrl}\n${test.header}: /admin\nHTTP ${overrideR.status}\nResponse appears to serve different content`,
            recommended_fix: `Strip ${test.header} header at the load balancer/reverse proxy layer. Never honor URL override headers from untrusted clients.`,
            cvss_score: 8.1,
            cwe_id: "CWE-444",
            scanner_name: "Cache Poisoning Scanner",
            scanner_family: "web",
            confidence: 0.8,
          });
          emit({ type: "log", message: `  URL override successful via ${test.header}` });
        }
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No cache poisoning vulnerabilities detected" });
  }

  emit({ type: "engine_done", engine: "Cache Poisoning Scanner", message: `Cache poisoning check complete — ${findings.length} finding(s)` });
  return findings;
}
