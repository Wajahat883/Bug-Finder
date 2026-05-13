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

  emit({ type: "engine_start", engine: "Bug-Finder/CachePoisoning", message: "Testing web cache poisoning via unkeyed headers" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 4 : UNKEYED_HEADERS.length;

  // First get a baseline response to compare against
  const cb = CACHE_BUSTER();
  const baselineUrl = `${targetUrl}${targetUrl.includes("?") ? "&" : "?"}cb=${cb}`;
  const baseline = await ctxFetch(ctx, baselineUrl, { redirect: "follow" });
  if (!baseline) {
    emit({ type: "engine_done", engine: "Bug-Finder/CachePoisoning", message: "Skipped (unreachable)" });
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

    // Step 1: Check if the injected value is reflected in the response
    if (body.includes(test.value) && !baselineBody.includes(test.value)) {
      emit({ type: "log", message: `  [POISON?] ${test.header}: ${test.value} reflected — verifying cache persistence` });

      // Step 2: Make a second CLEAN request (no injected header) to the same URL.
      // If the poisoned value still appears, the response was cached — confirmed poisoning.
      const cleanCb = CACHE_BUSTER();
      // Use the same cb2 URL so we hit the same cache entry, not a fresh one
      const cleanRes = await ctxFetch(ctx, testUrl);
      const cleanBody = cleanRes ? await cleanRes.text().catch(() => "") : "";
      const cacheConfirmed = isCached && cleanBody.includes(test.value);

      const severity = cacheConfirmed ? "high" : isCached ? "medium" : "low";
      const confidence = cacheConfirmed ? 0.92 : isCached ? 0.65 : 0.45;

      emit({ type: "log", message: cacheConfirmed
        ? `  [CONFIRMED CACHE POISON] ${test.header} poisoned cache at ${targetUrl}`
        : `  [REFLECTION ONLY] ${test.header} reflected but not cached (${testUrl})`
      });

      findings.push({
        title: cacheConfirmed
          ? `Web Cache Poisoning Confirmed: ${test.description}`
          : `Cache Poisoning Signal (Reflection Only): ${test.description}`,
        category: "Cache Poisoning",
        severity,
        endpoint: targetUrl,
        description: cacheConfirmed
          ? `CONFIRMED: The header "${test.header}: ${test.value}" was reflected in the response and the poisoned value persisted in a subsequent clean request, confirming the cache served the poisoned response to other users.`
          : `The header "${test.header}: ${test.value}" was reflected in the response body, but the value did not persist in a subsequent clean request. This indicates reflection without confirmed caching — lower risk but warrants investigation.`,
        evidence: [
          `Probe 1 (with injected header):`,
          `  GET ${testUrl}`,
          `  ${test.header}: ${test.value}`,
          `  HTTP ${r.status}`,
          `  Reflection context: ...${body.slice(Math.max(0, body.indexOf(test.value) - 80), body.indexOf(test.value) + 80)}...`,
          ``,
          `Probe 2 (clean request — no injected header):`,
          `  GET ${testUrl}`,
          `  HTTP ${cleanRes?.status ?? "N/A"}`,
          `  Injected value persisted: ${cacheConfirmed ? "YES (cache poisoned)" : "NO (not cached)"}`,
          ``,
          `Cache indicators: ${cacheHeaders.filter(Boolean).join(", ") || "none"}`,
          `Cache-Control: ${baseline.headers.get("cache-control") ?? "not set"}`,
        ].join("\n"),
        recommended_fix: "Normalize or strip unkeyed headers before caching. Include all headers that influence the response in the cache key. Set Cache-Control: no-store for sensitive pages. Use Vary header to key responses on relevant headers.",
        cvss_score: cacheConfirmed ? 8.1 : 5.3,
        cwe_id: "CWE-444",
        scanner_name: "Bug-Finder/Cache",
        scanner_family: "web",
        confidence,
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
            scanner_name: "Bug-Finder/Cache",
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

  emit({ type: "engine_done", engine: "Bug-Finder/CachePoisoning", message: `Cache poisoning check complete — ${findings.length} finding(s)` });
  return findings;
}
