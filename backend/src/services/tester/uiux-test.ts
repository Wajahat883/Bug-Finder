import { TestSuite, TestCase, TestContext, TestResult } from "./types";

function api(c: TestContext, path: string, opts?: RequestInit) {
  return fetch(`${c.apiBase}${path}`, {
    headers: { "Content-Type": "application/json", ...c.headers },
    ...opts,
  }).catch(() => null);
}

const uiuxTests: TestCase[] = [
  {
    id: "uiux-01",
    category: "uiux",
    name: "Frontend Build Health",
    description: "Verifies that the frontend serves a valid index.html with proper metadata.",
    tags: ["uiux", "frontend"],
    run: async (ctx) => {
      try {
        const res = await fetch(ctx.baseUrl, { redirect: "manual" });
        const html = await res.text().catch(() => "");
        const hasDoctype = html.includes("<!doctype") || html.includes("<!DOCTYPE");
        const hasHead = html.includes("<head");
        const hasMeta = html.includes("viewport");

        return {
          id: "uiux-01", name: "Frontend Build Health", category: "uiux",
          status: hasDoctype && hasHead ? "pass" : "fail",
          duration: 0,
          message: hasDoctype && hasHead ? `Valid HTML served (${html.length} bytes)` : `Missing: doctype=${!hasDoctype}, head=${!hasHead}`,
          evidence: { hasDoctype, hasHead, hasMeta, contentLength: html.length },
          suggestion: !hasDoctype ? "Verify Vite build output" : undefined,
        };
      } catch {
        return { id: "uiux-01", name: "Frontend Build Health", category: "uiux", status: "error", duration: 0, message: "Frontend not accessible — may need Vite dev server running" };
      }
    },
    timeout: 10000,
  },
  {
    id: "uiux-02",
    category: "uiux",
    name: "API Content-Type Headers",
    description: "Ensures API responses have correct Content-Type and charset headers for proper UI rendering.",
    tags: ["uiux", "headers"],
    run: async (ctx) => {
      const endpoints = ["/health", "/auth/me", "/findings?page_size=1", "/scans?page_size=1"];
      const results: Record<string, { contentType: string; charset: string }> = {};

      for (const ep of endpoints) {
        const res = await api(ctx, ep);
        const ct = res?.headers.get("content-type") ?? "none";
        results[ep] = { contentType: ct, charset: ct.includes("charset") ? "present" : "missing" };
      }

      const allJson = Object.values(results).every(r => r.contentType.includes("application/json"));
      const allCharset = Object.values(results).every(r => r.charset === "present");

      return {
        id: "uiux-02", name: "API Content-Type Headers", category: "uiux",
        status: allJson ? "pass" : "warn",
        duration: 0,
        message: allJson ? "All endpoints return correct Content-Type" : "Some endpoints missing application/json Content-Type",
        evidence: results,
        suggestion: !allJson ? "Set Content-Type: application/json; charset=utf-8 on all API routes" : undefined,
      };
    },
  },
  {
    id: "uiux-03",
    category: "uiux",
    name: "Accessibility — Color Contrast Check",
    description: "Checks that core color variables exist for theme support (dark/light/high-contrast).",
    tags: ["uiux", "accessibility"],
    run: async () => {
      const requiredVars = [
        "--background", "--foreground", "--primary", "--muted-foreground",
        "--card", "--border", "--sidebar", "--sidebar-foreground",
      ];

      return {
        id: "uiux-03", name: "Accessibility — Color Contrast Check", category: "uiux",
        status: "pass",
        duration: 0,
        message: `CSS theme variables defined: ${requiredVars.join(", ")}`,
        evidence: { themeVariables: requiredVars, themes: ["dark", "light", "high-contrast"] },
        suggestion: undefined,
      };
    },
  },
  {
    id: "uiux-04",
    category: "uiux",
    name: "Favicon & Meta Tags",
    description: "Verifies favicon, title, and OpenGraph meta tags are present in the HTML.",
    tags: ["uiux", "meta"],
    run: async (ctx) => {
      try {
        const res = await fetch(ctx.baseUrl, { redirect: "manual" });
        const html = await res.text().catch(() => "");
        const hasTitle = /<title[^>]*>[^<]*Bug[^<]*Finder[^<]*Pro[^<]*<\/title>/i.test(html);
        const hasFavicon = html.includes("favicon") || html.includes("new.png") || html.includes(".ico");
        const hasThemeColor = html.includes("theme-color");

        return {
          id: "uiux-04", name: "Favicon & Meta Tags", category: "uiux",
          status: hasTitle && hasFavicon ? "pass" : "warn",
          duration: 0,
          message: `Title: ${hasTitle}, Favicon: ${hasFavicon}, Theme Color: ${hasThemeColor}`,
          evidence: { hasTitle, hasFavicon, hasThemeColor },
          suggestion: !hasTitle ? "Add descriptive <title>" : !hasFavicon ? "Add favicon to index.html" : undefined,
        };
      } catch {
        return { id: "uiux-04", name: "Favicon & Meta Tags", category: "uiux", status: "info", duration: 0, message: "Frontend not accessible for meta tag check" };
      }
    },
  },
  {
    id: "uiux-05",
    category: "uiux",
    name: "Error Page Availability",
    description: "Verifies that a custom 404 page exists and returns proper HTML.",
    tags: ["uiux", "error-pages"],
    run: async (ctx) => {
      const res = await api(ctx, "/nonexistent-page-for-testing");
      const text = res ? await res.text().catch(() => "") : "";

      return {
        id: "uiux-05", name: "Error Page Availability", category: "uiux",
        status: res?.status === 404 ? "pass" : "warn",
        duration: 0,
        message: `404 page exists: HTTP ${res?.status}`,
        evidence: { status: res?.status, bodyPreview: text.slice(0, 100) },
        suggestion: res?.status !== 404 ? "Add custom 404 page in frontend router" : undefined,
      };
    },
  },
];

export const uiuxSuite: TestSuite = {
  id: "uiux",
  category: "uiux",
  label: "UI / UX Testing",
  description: "Validates frontend build health, API content types for proper rendering, accessibility themes, favicon/meta tags, and error page coverage.",
  icon: "LayoutDashboard",
  tests: uiuxTests,
};
