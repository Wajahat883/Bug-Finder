import { test, expect } from "@playwright/test";

test.describe("Authentication", () => {
  test("landing page loads and shows CTA", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Bug Finder Pro")).toBeVisible();
    await expect(page.locator("text=Start Free Scan")).toBeVisible();
    await expect(page.locator("text=Sign In")).toBeVisible();
  });

  test("login page loads", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("admin login page shows restricted warning", async ({ page }) => {
    await page.goto("/admin");
    await expect(page.locator("text=Admin Portal")).toBeVisible();
    await expect(page.locator("text=Restricted access")).toBeVisible();
    await expect(page.locator('input[type="email"]')).toBeVisible();
  });

  test("forgot password page loads", async ({ page }) => {
    await page.goto("/forgot-password");
    await expect(page.locator("text=Forgot Password")).toBeVisible();
    await expect(page.locator('input[type="email"]')).toBeVisible();
  });

  test("unauthenticated user redirected to login from dashboard", async ({ page }) => {
    await page.goto("/dashboard");
    await page.waitForURL("**/login", { timeout: 10000 });
    expect(page.url()).toContain("/login");
  });
});

test.describe("Navigation", () => {
  test("login page has correct title", async ({ page }) => {
    await page.goto("/login");
    const title = await page.title();
    expect(title.toLowerCase()).toContain("bug");
  });

  test("landing page navbar links are present", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("text=Features")).toBeVisible();
    await expect(page.locator("text=Coverage")).toBeVisible();
  });

  test("clicking Sign In goes to login", async ({ page }) => {
    await page.goto("/");
    await page.locator("text=Sign In").first().click();
    await page.waitForURL("**/login", { timeout: 5000 });
    expect(page.url()).toContain("/login");
  });
});

test.describe("404 & Error Pages", () => {
  test("unknown route shows 404", async ({ page }) => {
    await page.goto("/this-page-does-not-exist-12345");
    await expect(page.locator("text=404")).toBeVisible({ timeout: 5000 });
  });
});

test.describe("Form Validation", () => {
  test("empty login form shows validation", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.locator("text=email and password are required")).toBeVisible({ timeout: 5000 });
  });
});
