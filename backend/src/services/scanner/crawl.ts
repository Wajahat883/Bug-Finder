import { ScanContext, ctxFetch } from "./types";

const COMMON_PATHS = [
  "/", "/login", "/register", "/api", "/api/v1", "/api/v2",
  "/admin", "/dashboard", "/users", "/api/users", "/api/auth",
  "/search", "/api/search", "/api/data", "/api/products",
  "/profile", "/api/profile", "/api/me", "/health", "/api/health",
  "/graphql", "/api/graphql", "/swagger", "/swagger.json", "/openapi.json",
  "/api/swagger", "/docs", "/api/docs",
];

// Regex patterns to extract API routes from JS bundles
const ROUTE_PATTERNS = [
  /["'`](\/api\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
  /path:\s*["'`](\/[a-zA-Z0-9/_:.-]{1,60})["'`]/g,
  /fetch\s*\(["'`](\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
  /axios\.[a-z]+\(["'`](\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
  /url:\s*["'`](\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
  /route\s*:\s*["'`](\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
  /href\s*:\s*["'`](\/[a-zA-Z0-9/_:.-]{2,60})["'`]/g,
];

function extractRoutesFromJs(js: string, base: URL): string[] {
  const routes = new Set<string>();
  for (const pattern of ROUTE_PATTERNS) {
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(js)) !== null) {
      const path = m[1];
      if (!path || path.length < 2) continue;
      try {
        const full = new URL(path, base).toString();
        // Only keep same-origin paths
        if (full.startsWith(base.origin)) routes.add(full);
      } catch { /* skip */ }
    }
  }
  return [...routes];
}

export async function runCrawl(ctx: ScanContext): Promise<void> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;

  emit({ type: "engine_start", engine: "Crawler", message: `Crawling ${targetUrl}` });

  discoveredEndpoints.push(targetUrl);

  let base: URL;
  try { base = new URL(targetUrl); } catch {
    emit({ type: "engine_done", engine: "Crawler", message: "Invalid target URL" });
    return;
  }

  // --- 1. Try Playwright service for SPA rendering ---
  const playwrightUrl = process.env["PLAYWRIGHT_URL"];
  let playwrightLinks: string[] = [];
  if (playwrightUrl) {
    try {
      const resp = await fetch(`${playwrightUrl}/crawl`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: targetUrl,
          authHeaders: ctx.authHeaders,
          waitForNetworkIdle: true,
        }),
        signal: AbortSignal.timeout(30000),
      });
      if (resp.ok) {
        const data = await resp.json() as { links?: string[]; apiCalls?: string[] };
        playwrightLinks = [...(data.links ?? []), ...(data.apiCalls ?? [])];
        emit({ type: "log", message: `Playwright: ${playwrightLinks.length} links/API calls discovered` });
      }
    } catch {
      emit({ type: "log", message: "Playwright service unavailable — using static crawl" });
    }
  }

  for (const link of playwrightLinks) {
    try {
      const resolved = new URL(link, base).toString();
      if (resolved.startsWith(base.origin) && !discoveredEndpoints.includes(resolved)) {
        discoveredEndpoints.push(resolved);
      }
    } catch { /* skip */ }
  }

  // --- 2. Fetch robots.txt and extract Disallow / Allow paths ---
  const robotsRes = await ctxFetch(ctx, `${base.origin}/robots.txt`, {}, 5000);
  if (robotsRes && robotsRes.status === 200) {
    const robotsTxt = await robotsRes.text().catch(() => "");
    const pathMatches = [...robotsTxt.matchAll(/^(?:Allow|Disallow):\s*(.+)$/gm)];
    for (const m of pathMatches) {
      const p = m[1].trim();
      if (p && p !== "/" && !p.includes("*") && p.startsWith("/")) {
        try {
          const full = `${base.origin}${p}`;
          if (!discoveredEndpoints.includes(full)) discoveredEndpoints.push(full);
        } catch { /* skip */ }
      }
    }
    emit({ type: "log", message: `robots.txt: ${pathMatches.length} paths found` });
  }

  // --- 3. Fetch sitemap.xml and extract URLs ---
  const sitemapRes = await ctxFetch(ctx, `${base.origin}/sitemap.xml`, {}, 5000);
  if (sitemapRes && sitemapRes.status === 200) {
    const sitemapXml = await sitemapRes.text().catch(() => "");
    const locMatches = [...sitemapXml.matchAll(/<loc>([^<]+)<\/loc>/g)];
    let sitemapAdded = 0;
    for (const m of locMatches.slice(0, 50)) {
      const url = m[1].trim();
      if (url.startsWith(base.origin) && !discoveredEndpoints.includes(url)) {
        discoveredEndpoints.push(url);
        sitemapAdded++;
      }
    }
    emit({ type: "log", message: `sitemap.xml: ${sitemapAdded} URLs added` });
  }

  // --- 4. Parse homepage HTML for links + script tags ---
  const homeRes = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  const jsUrls: string[] = [];
  if (homeRes) {
    const html = await homeRes.text().catch(() => "");

    // Extract links/forms from HTML
    const hrefMatches = [...html.matchAll(/href=["']([^"'#?]+)["']/g)];
    const srcMatches = [...html.matchAll(/src=["']([^"'#?]+)["']/g)];
    const actionMatches = [...html.matchAll(/action=["']([^"'#?]+)["']/g)];

    const allLinks = [...hrefMatches, ...srcMatches, ...actionMatches].map(m => m[1]).filter(Boolean);

    for (const link of allLinks) {
      try {
        const resolved = new URL(link, base).toString();
        if (resolved.startsWith(base.origin) && !discoveredEndpoints.includes(resolved)) {
          discoveredEndpoints.push(resolved);
        }
        // Collect JS files for bundle analysis
        if (resolved.endsWith(".js") || resolved.includes(".js?") || resolved.includes("/static/js/")) {
          if (!jsUrls.includes(resolved)) jsUrls.push(resolved);
        }
      } catch { /* skip */ }
    }
    emit({ type: "log", message: `HTML: ${allLinks.length} links found, ${jsUrls.length} JS bundles` });

    // --- 5. Parse JS bundles for embedded API routes ---
    const bundleBudget = profile === "quick" ? 2 : profile === "standard" ? 5 : 10;
    let routesFromBundles = 0;
    for (const jsUrl of jsUrls.slice(0, bundleBudget)) {
      const jsRes = await ctxFetch(ctx, jsUrl, {}, 8000);
      if (!jsRes || jsRes.status !== 200) continue;
      const jsContent = await jsRes.text().catch(() => "");
      const extracted = extractRoutesFromJs(jsContent, base);
      for (const route of extracted) {
        if (!discoveredEndpoints.includes(route)) {
          discoveredEndpoints.push(route);
          routesFromBundles++;
        }
      }
    }
    if (routesFromBundles > 0) {
      emit({ type: "log", message: `JS bundles: ${routesFromBundles} API routes extracted` });
    }
  } else {
    emit({ type: "log", message: "Could not fetch homepage (unreachable or requires auth)" });
  }

  // --- 6. Probe common paths ---
  const budget = profile === "quick" ? 5 : profile === "standard" ? 12 : 20;
  let probed = 0;
  for (const p of COMMON_PATHS.slice(0, budget)) {
    const full = `${base.origin}${p}`;
    if (!discoveredEndpoints.includes(full)) {
      const res = await ctxFetch(ctx, full, { method: "HEAD" }, 4000);
      if (res && res.status !== 404 && res.status !== 410) {
        discoveredEndpoints.push(full);
        probed++;
      }
    }
  }
  emit({ type: "log", message: `Common paths: ${probed} responding` });

  emit({
    type: "engine_done",
    engine: "Crawler",
    message: `Crawl complete — ${discoveredEndpoints.length} unique endpoints discovered`,
  });
}
