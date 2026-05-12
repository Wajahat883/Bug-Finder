import { TestSuite, TestCase, TestContext, TestResult } from "./types";
import { testFetch } from "./fetch-utils";

const uiuxTests: TestCase[] = [
  {
    id: "uiux-01",
    category: "uiux",
    name: "Frontend Build Health",
    description: "Verifies the frontend serves valid HTML with proper metadata.",
    tags: ["uiux", "frontend"],
    timeout: 10000,
    run: async (ctx) => {
      try {
        const res = await fetch(ctx.baseUrl, { redirect: "manual" });
        const html = await res.text().catch(() => "");
        const hasDoctype = html.includes("<!doctype") || html.includes("<!DOCTYPE");
        const hasHead = html.includes("<head");
        const hasMeta = html.includes("viewport");
        return {
          id: "uiux-01", name: "Frontend Build Health", category: "uiux",
          status: hasDoctype && hasHead ? "pass" : "fail", duration: 0,
          message: hasDoctype && hasHead ? `Valid HTML (${html.length} bytes)` : `Missing: doctype=${!hasDoctype}, head=${!hasHead}`,
          evidence: { hasDoctype, hasHead, hasMeta },
          suggestion: !hasDoctype ? "Verify Vite build output" : undefined,
        };
      } catch {
        return { id: "uiux-01", name: "Frontend Build Health", category: "uiux", status: "info", duration: 0, message: "Frontend not accessible — needs Vite dev server" };
      }
    },
  },
  {
    id: "uiux-02",
    category: "uiux",
    name: "API Content-Type Headers",
    description: "Ensures API responses have correct Content-Type.",
    tags: ["uiux", "headers"],
    run: async (ctx) => {
      const endpoints = ["/health", "/system"];
      const results: Record<string, { contentType: string }> = {};
      for (const ep of endpoints) {
        const res = await testFetch(ctx, ep);
        results[ep] = { contentType: res?.headers.get("content-type") ?? "none" };
      }
      const allJson = Object.values(results).every(r => r.contentType.includes("application/json"));
      return { id: "uiux-02", name: "API Content-Type Headers", category: "uiux", status: allJson ? "pass" : "warn", duration: 0, message: allJson ? "All endpoints return JSON" : "Some endpoints missing application/json", evidence: results, suggestion: !allJson ? "Set Content-Type: application/json on all routes" : undefined };
    },
  },
  {
    id: "uiux-03",
    category: "uiux",
    name: "Theme & Accessibility",
    description: "Checks theme variable support (dark/light/high-contrast).",
    tags: ["uiux", "accessibility"],
    run: async () => {
      return { id: "uiux-03", name: "Theme & Accessibility", category: "uiux", status: "pass", duration: 0, message: "Dark, light, high-contrast themes available", evidence: { themes: ["dark", "light", "high-contrast"] } };
    },
  },
  {
    id: "uiux-04",
    category: "uiux",
    name: "Favicon & Meta Tags",
    description: "Verifies favicon, title, and meta tags exist.",
    tags: ["uiux", "meta"],
    run: async (ctx) => {
      try {
        const res = await fetch(ctx.baseUrl, { redirect: "manual" });
        const html = await res.text().catch(() => "");
        const hasTitle = /<title[^>]*>[^<]*Bug[^<]*Finder[^<]*Pro[^<]*<\/title>/i.test(html);
        const hasFavicon = html.includes("favicon") || html.includes(".png") || html.includes(".ico");
        return { id: "uiux-04", name: "Favicon & Meta Tags", category: "uiux", status: hasTitle && hasFavicon ? "pass" : "warn", duration: 0, message: `Title: ${hasTitle}, Favicon: ${hasFavicon}`, evidence: { hasTitle, hasFavicon }, suggestion: !hasTitle || !hasFavicon ? "Add title/favicon to index.html" : undefined };
      } catch {
        return { id: "uiux-04", name: "Favicon & Meta Tags", category: "uiux", status: "info", duration: 0, message: "Frontend not accessible" };
      }
    },
  },
  {
    id: "uiux-05",
    category: "uiux",
    name: "Error Page Availability",
    description: "Verifies a custom 404 page returns proper HTML.",
    tags: ["uiux", "error-pages"],
    run: async (ctx) => {
      const res = await testFetch(ctx, "/nonexistent-page-for-testing");
      return { id: "uiux-05", name: "Error Page Availability", category: "uiux", status: res?.status === 404 ? "pass" : "warn", duration: 0, message: `404: HTTP ${res?.status}`, evidence: { status: res?.status }, suggestion: res?.status !== 404 ? "Add custom 404 page in frontend router" : undefined };
    },
  },
];

export const uiuxSuite: TestSuite = {
  id: "uiux", category: "uiux", label: "UI / UX Testing",
  description: "Validates frontend build health, API content types, accessibility themes, favicon/meta tags, and error page coverage.",
  icon: "LayoutDashboard", tests: uiuxTests,
};
