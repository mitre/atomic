// @ts-check
const { test, expect } = require("@playwright/test");
const { login } = require("../helpers/auth");
const { navigateToAtomic } = require("../helpers/navigation");

test.describe("Atomic plugin - page load", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("should load the Caldera UI successfully", async ({ page }) => {
    await expect(page).not.toHaveURL(/\/login/);
  });

  test("should display the Atomic navigation item", async ({ page }) => {
    const navItem = page.locator(
      'a:has-text("Atomic"), .nav-item:has-text("Atomic"), [data-test="nav-atomic"], button:has-text("Atomic")'
    ).first();
    await expect(navItem).toBeVisible({ timeout: 15_000 });
  });

  test("should navigate to the Atomic tab and display the heading", async ({ page }) => {
    await navigateToAtomic(page);
    await expect(page.locator("h2:has-text('Atomic')").first()).toBeVisible();
  });

  test("should display the plugin description text", async ({ page }) => {
    await navigateToAtomic(page);
    await expect(
      page.locator("p:has-text('Red Canary Atomic')").first()
    ).toBeVisible();
  });

  test("should display the abilities count card", async ({ page }) => {
    await navigateToAtomic(page);
    // The card shows the count of atomic abilities or "---" while loading
    const countCard = page.locator(".card, .is-flex .card").first();
    await expect(countCard).toBeVisible({ timeout: 15_000 });
  });
});
