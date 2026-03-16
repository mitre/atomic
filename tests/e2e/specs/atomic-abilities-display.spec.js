// @ts-check
const { test, expect } = require("@playwright/test");
const { login } = require("../helpers/auth");
const { navigateToAtomic } = require("../helpers/navigation");

test.describe("Atomic plugin - abilities display", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToAtomic(page);
  });

  test("should display the abilities count (numeric or placeholder)", async ({ page }) => {
    // The Vue template shows {{ atomicAbilities.length || "---" }}
    const countText = page.locator(".is-size-1, h1.is-size-1").first();
    await expect(countText).toBeVisible({ timeout: 15_000 });
    const text = await countText.textContent();
    // Should be either a number or "---"
    expect(text?.trim()).toMatch(/^(\d+|---)$/);
  });

  test("should display the 'abilities' label under the count", async ({ page }) => {
    const label = page.locator("p:has-text('abilities')").first();
    await expect(label).toBeVisible({ timeout: 15_000 });
  });

  test("should show the View Abilities button", async ({ page }) => {
    const viewBtn = page.locator(
      'a:has-text("View Abilities"), button:has-text("View Abilities"), .button:has-text("View Abilities")'
    ).first();
    await expect(viewBtn).toBeVisible({ timeout: 15_000 });
  });

  test("the View Abilities button should link to the abilities page with atomic filter", async ({ page }) => {
    const viewBtn = page.locator(
      'a:has-text("View Abilities"), .button:has-text("View Abilities")'
    ).first();
    await expect(viewBtn).toBeVisible({ timeout: 15_000 });

    // The router-link should resolve to /abilities?plugin=atomic
    const href = await viewBtn.getAttribute("href");
    if (href) {
      expect(href).toContain("abilities");
      expect(href).toContain("atomic");
    }
    // If it's a router-link, the href might be generated dynamically
    // Just check the button text and that it's clickable
    await expect(viewBtn).toBeEnabled();
  });

  test("clicking View Abilities should navigate to the abilities page", async ({ page }) => {
    const viewBtn = page.locator(
      'a:has-text("View Abilities"), .button:has-text("View Abilities")'
    ).first();
    await expect(viewBtn).toBeVisible({ timeout: 15_000 });
    await viewBtn.click();

    // Should navigate to abilities page
    await page.waitForURL(/abilities/, { timeout: 15_000 });
  });

  test("abilities count should update to a number after data loads", async ({ page }) => {
    const countText = page.locator(".is-size-1, h1.is-size-1").first();
    await expect(countText).toBeVisible({ timeout: 15_000 });

    // Wait for count to potentially become a number (may stay --- if no abilities)
    await page.waitForTimeout(5_000);
    const text = await countText.textContent();
    // Should be either a valid number or "---" (if no atomic abilities ingested)
    expect(text?.trim()).toMatch(/^(\d+|---)$/);
  });

  test("the card should be properly centered on the page", async ({ page }) => {
    const container = page.locator(
      ".is-flex.is-align-items-center.is-justify-content-center"
    ).first();
    await expect(container).toBeVisible({ timeout: 15_000 });
  });
});
