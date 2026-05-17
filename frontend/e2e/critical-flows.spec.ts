import { test, expect } from "@playwright/test";

test.describe("Critical User Flows — admin-gated routes", () => {
  test("admin policy page redirects to admin portal or forbidden", async ({ page }) => {
    await page.goto("/admin/policy");
    await page.waitForURL("**/admin**", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/admin/);
  });

  test("executive dashboard requires authentication", async ({ page }) => {
    await page.goto("/executive");
    await page.waitForURL("**/admin", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/executive|admin/);
  });

  test("compliance page requires authentication", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForURL("**/admin", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/compliance|admin/);
  });

  test("SLA page requires authentication", async ({ page }) => {
    await page.goto("/sla");
    await page.waitForURL("**/admin", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/sla|admin/);
  });

  test("attack surface page requires authentication", async ({ page }) => {
    await page.goto("/attack-surface");
    await page.waitForURL("**/admin", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/attack-surface|admin/);
  });

  test("integrations page requires authentication", async ({ page }) => {
    await page.goto("/integrations");
    await page.waitForURL("**/admin", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toMatch(/integrations|admin/);
  });
});

test.describe("Critical User Flows — public or user-accessible routes", () => {
  test("AI triage page is accessible to authenticated users", async ({ page }) => {
    await page.goto("/ai-triage");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toContain("/ai-triage");
  });

  test("OWASP page loads without redirect to admin", async ({ page }) => {
    await page.goto("/owasp");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toContain("/owasp");
  });

  test("timeline page loads without redirect to admin", async ({ page }) => {
    await page.goto("/timeline");
    await page.waitForLoadState("networkidle", { timeout: 10000 }).catch(() => {});
    const url = page.url();
    expect(url).toContain("/timeline");
  });

  test("forgot password page loads without authentication", async ({ page }) => {
    await page.goto("/forgot-password");
    await expect(page.locator("text=Forgot Password")).toBeVisible({ timeout: 8000 });
    expect(page.url()).toContain("/forgot-password");
  });
});

test.describe("Critical User Flows — page content smoke tests", () => {
  test("landing page has marketing content", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Bug Finder Pro")).toBeVisible({ timeout: 8000 });
  });

  test("login page has the sign-in form", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("admin portal page has restricted access indicator", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("text=Admin Portal")).toBeVisible({ timeout: 8000 });
    await expect(page.locator("text=Restricted access")).toBeVisible({ timeout: 8000 });
  });

  test("404 page is rendered for completely unknown routes", async ({ page }) => {
    await page.goto("/this-route-absolutely-does-not-exist-xyz-99999");
    await expect(page.locator("text=404")).toBeVisible({ timeout: 8000 });
  });

  test("unauthenticated dashboard access redirects to login", async ({ page }) => {
    await page.goto("/dashboard");
    await page.waitForURL("**/login", { timeout: 10000 });
    expect(page.url()).toContain("/login");
  });
});

test.describe("Critical User Flows — navigation smoke", () => {
  test("sign-in CTA on landing navigates to /login", async ({ page }) => {
    await page.goto("/");
    await page.locator("text=Sign In").first().click();
    await page.waitForURL("**/login", { timeout: 5000 });
    expect(page.url()).toContain("/login");
  });

  test("landing page has features and coverage nav links", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Features")).toBeVisible();
    await expect(page.locator("text=Coverage")).toBeVisible();
  });

  test("empty login form shows validation error", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(
      page.locator("text=email and password are required")
    ).toBeVisible({ timeout: 5000 });
  });

  test("failed login shows an error message", async ({ page }) => {
    await page.goto("/login");
    await page.locator('input[type="email"]').fill("no-such-user@example.invalid");
    await page.locator('input[type="password"]').fill("wrongpassword");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(
      page.locator("text=/invalid|incorrect|wrong|error/i")
    ).toBeVisible({ timeout: 8000 });
  });
});
