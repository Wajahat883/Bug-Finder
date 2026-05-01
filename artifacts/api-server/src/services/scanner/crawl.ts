import { ScanContext, safeFetch } from "./types";

const COMMON_PATHS = [
  "/", "/login", "/register", "/api", "/api/v1", "/api/v2",
  "/admin", "/dashboard", "/users", "/api/users", "/api/auth",
  "/search", "/api/search", "/api/data", "/api/products",
  "/profile", "/api/profile", "/api/me", "/health", "/api/health",
  "/graphql", "/api/graphql",
];

export async function runCrawl(ctx: ScanContext): Promise<void> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;

  emit({ type: "engine_start", engine: "Crawler", message: `Crawling ${targetUrl}` });

  discoveredEndpoints.push(targetUrl);

  const res = await safeFetch(targetUrl);
  if (res) {
    const html = await res.text().catch(() => "");
    const hrefMatches = [...html.matchAll(/href=["']([^"'#?]+)["']/g)];
    const srcMatches = [...html.matchAll(/src=["']([^"'#?]+)["']/g)];
    const actionMatches = [...html.matchAll(/action=["']([^"'#?]+)["']/g)];

    const base = new URL(targetUrl);
    const allLinks = [...hrefMatches, ...srcMatches, ...actionMatches]
      .map(m => m[1])
      .filter(Boolean);

    for (const link of allLinks) {
      try {
        const resolved = new URL(link, base).toString();
        if (resolved.startsWith(base.origin) && !discoveredEndpoints.includes(resolved)) {
          discoveredEndpoints.push(resolved);
        }
      } catch {
        // skip invalid URLs
      }
    }

    emit({ type: "log", message: `Crawled homepage, found ${allLinks.length} links` });
  } else {
    emit({ type: "log", message: "Could not fetch homepage (unreachable or timeout)" });
  }

  // Add common paths for standard/deep profiles
  const budget = profile === "quick" ? 5 : profile === "standard" ? 12 : 20;
  const base = new URL(targetUrl);
  for (const p of COMMON_PATHS.slice(0, budget)) {
    const full = `${base.origin}${p}`;
    if (!discoveredEndpoints.includes(full)) {
      discoveredEndpoints.push(full);
    }
  }

  emit({
    type: "engine_done",
    engine: "Crawler",
    message: `Discovered ${discoveredEndpoints.length} endpoints`,
  });
}
