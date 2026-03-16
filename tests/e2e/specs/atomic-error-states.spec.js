// @ts-check
const { test, expect } = require("@playwright/test");
const { login } = require("../helpers/auth");
const { navigateToAtomic } = require("../helpers/navigation");

test.describe("Atomic plugin - error states", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("should show placeholder count when abilities API fails", async ({ page }) => {
    // Intercept abilities API to simulate failure
    await page.route("**/api/v2/abilities", (route) => {
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ error: "Internal Server Error" }),
      });
    });

    await navigateToAtomic(page);

    // The count should show "---" since no abilities loaded
    const countText = page.locator(".is-size-1, h1.is-size-1").first();
    await expect(countText).toBeVisible({ timeout: 15_000 });
    const text = await countText.textContent();
    expect(text?.trim()).toBe("---");
  });

  test("page should remain functional when abilities API returns empty array", async ({ page }) => {
    await page.route("**/api/v2/abilities", (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await navigateToAtomic(page);

    // Count should show "---" for zero abilities
    const countText = page.locator(".is-size-1, h1.is-size-1").first();
    await expect(countText).toBeVisible({ timeout: 15_000 });
    const text = await countText.textContent();
    expect(text?.trim()).toBe("---");

    // Page heading should still be visible
    await expect(page.locator("h2:has-text('Atomic')").first()).toBeVisible();
  });

  test("page should remain functional when adversaries API fails", async ({ page }) => {
    await page.route("**/api/v2/adversaries", (route) => {
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ error: "Internal Server Error" }),
      });
    });

    await navigateToAtomic(page);

    // The page heading and description should still render
    await expect(page.locator("h2:has-text('Atomic')").first()).toBeVisible();
    await expect(page.locator("p:has-text('Red Canary Atomic')").first()).toBeVisible();
  });

  test("View Abilities button should still be present when no abilities loaded", async ({ page }) => {
    await page.route("**/api/v2/abilities", (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await navigateToAtomic(page);

    const viewBtn = page.locator(
      'a:has-text("View Abilities"), .button:has-text("View Abilities")'
    ).first();
    await expect(viewBtn).toBeVisible({ timeout: 15_000 });
  });

  test("page should handle slow API responses gracefully", async ({ page }) => {
    // Simulate slow response
    await page.route("**/api/v2/abilities", async (route) => {
      await new Promise((r) => setTimeout(r, 5_000));
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify([]),
      });
    });

    await navigateToAtomic(page);

    // While loading, the count should show "---"
    const countText = page.locator(".is-size-1, h1.is-size-1").first();
    await expect(countText).toBeVisible({ timeout: 15_000 });
    const initialText = await countText.textContent();
    expect(initialText?.trim()).toBe("---");

    // Heading should be visible during loading
    await expect(page.locator("h2:has-text('Atomic')").first()).toBeVisible();
  });

  test("page should not crash with malformed API response", async ({ page }) => {
    await page.route("**/api/v2/abilities", (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: "not valid json",
      });
    });

    await navigateToAtomic(page);

    // Page should still show the heading even if parsing fails
    await expect(page.locator("h2:has-text('Atomic')").first()).toBeVisible({ timeout: 15_000 });
  });
});
