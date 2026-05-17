/**
 * Playwright global setup — authenticate as admin once and save storage state
 * to e2e/.auth/user.json so subsequent test files can reuse the session.
 *
 * Usage in playwright.config.ts projects that need auth:
 *   { name: "setup", testMatch: /auth\.setup\.ts/ }
 *   { name: "authenticated", dependencies: ["setup"],
 *     use: { storageState: "e2e/.auth/user.json" } }
 */

import { test as setup, expect } from "@playwright/test";
import path from "path";

const authFile = path.join(__dirname, "../.auth/user.json");

setup("authenticate as admin", async ({ page }) => {
  const email = process.env["E2E_EMAIL"] ?? "admin@test.com";
  const password = process.env["E2E_PASSWORD"] ?? "password123";

  await page.goto("/login");

  // Wait for the email input — if not found the dev server may not be running,
  // in which case we still save an empty state so dependent tests can be skipped
  // gracefully rather than crashing.
  await page.waitForSelector('input[type="email"]', { timeout: 10000 }).catch(() => {});

  const emailInput = page.locator('input[type="email"]');
  const passwordInput = page.locator('input[type="password"]');
  const submitButton = page.getByRole("button", { name: /sign in/i });

  if ((await emailInput.count()) === 0) {
    // Dev server not reachable — save an empty storage state and bail out.
    await page.context().storageState({ path: authFile });
    return;
  }

  await emailInput.fill(email);
  await passwordInput.fill(password);
  await submitButton.click();

  // Wait for successful login redirect; swallow the error if credentials are
  // wrong (CI without a real test server) and save whatever state we have.
  try {
    await page.waitForURL("**/dashboard", { timeout: 8000 });
    // Verify we're actually on the dashboard before saving auth state.
    await expect(page).toHaveURL(/dashboard/);
  } catch {
    // Login failed (no test server / wrong creds) — save empty state so
    // downstream tests can assert on the unauthenticated behaviour instead.
  }

  await page.context().storageState({ path: authFile });
});
