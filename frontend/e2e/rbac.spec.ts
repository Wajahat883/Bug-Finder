import { test, expect } from "@playwright/test";

test.describe("Admin Panel Access", () => {
  test("normal user cannot access admin panel directly", async ({ page }) => {
    await page.goto("/admin/panel");
    await page.waitForURL("**/admin", { timeout: 10000 });
    expect(page.url()).toContain("/admin");
  });

  test("normal user cannot access audit log directly", async ({ page }) => {
    await page.goto("/audit-log");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access integrations directly", async ({ page }) => {
    await page.goto("/integrations");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access admin users directly", async ({ page }) => {
    await page.goto("/admin/users");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access api keys directly", async ({ page }) => {
    await page.goto("/api-keys");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access testing dashboard directly", async ({ page }) => {
    await page.goto("/testing");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });
});

test.describe("Analytics Routes", () => {
  test("normal user cannot access executive dashboard directly", async ({ page }) => {
    await page.goto("/executive");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access compliance directly", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access SLA directly", async ({ page }) => {
    await page.goto("/sla");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access attack surface directly", async ({ page }) => {
    await page.goto("/attack-surface");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access engagements directly", async ({ page }) => {
    await page.goto("/engagements");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user can access OWASP page", async ({ page }) => {
    await page.goto("/owasp");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    expect(page.url()).toContain("/owasp");
  });

  test("normal user can access timeline", async ({ page }) => {
    await page.goto("/timeline");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    expect(page.url()).toContain("/timeline");
  });
});

test.describe("AI & Tools Routes", () => {
  test("normal user can access AI Triage", async ({ page }) => {
    await page.goto("/ai-triage");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    expect(page.url()).toContain("/ai-triage");
  });

  test("normal user cannot access CVSS calculator directly", async ({ page }) => {
    await page.goto("/cvss");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });

  test("normal user cannot access scan templates directly", async ({ page }) => {
    await page.goto("/scan-templates");
    await page.waitForURL("**/admin", { timeout: 10000 });
  });
});
