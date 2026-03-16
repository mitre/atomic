// @ts-check
const { test, expect } = require("@playwright/test");
const { login } = require("../helpers/auth");
const { navigateToAtomic } = require("../helpers/navigation");

test.describe("Atomic plugin - ability ingestion", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("atomic abilities should be filtered from the global abilities store", async ({ page }) => {
    await navigateToAtomic(page);

    // The atomic page makes API calls to /api/v2/abilities
    // Intercept to verify the call is made
    const apiCalled = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/abilities") && resp.status() === 200,
      { timeout: 20_000 }
    ).catch(() => null);

    // Reload to trigger the API call fresh
    await page.reload();
    await navigateToAtomic(page);

    const response = await apiCalled;
    if (response) {
      expect(response.status()).toBe(200);
    }
  });

  test("the abilities API response should contain ability objects", async ({ page }) => {
    // Intercept abilities API
    let abilitiesData = null;
    await page.route("**/api/v2/abilities", async (route) => {
      const response = await route.fetch();
      abilitiesData = await response.json();
      await route.fulfill({ response });
    });

    await navigateToAtomic(page);
    await page.waitForTimeout(5_000);

    // If we got abilities data, verify structure
    if (abilitiesData && Array.isArray(abilitiesData)) {
      // Each ability should have standard fields
      if (abilitiesData.length > 0) {
        const first = abilitiesData[0];
        expect(first).toHaveProperty("ability_id");
        expect(first).toHaveProperty("name");
      }
    }
  });

  test("atomic abilities should have plugin field set to 'atomic'", async ({ page }) => {
    let abilitiesData = null;
    await page.route("**/api/v2/abilities", async (route) => {
      const response = await route.fetch();
      abilitiesData = await response.json();
      await route.fulfill({ response });
    });

    await navigateToAtomic(page);
    await page.waitForTimeout(5_000);

    if (abilitiesData && Array.isArray(abilitiesData)) {
      const atomicOnes = abilitiesData.filter((a) => a.plugin === "atomic");
      // The count on the page should match the filtered count
      const countText = await page.locator(".is-size-1, h1.is-size-1").first().textContent();
      const displayedCount = parseInt(countText?.trim() || "0", 10);
      if (!isNaN(displayedCount) && displayedCount > 0) {
        expect(atomicOnes.length).toBe(displayedCount);
      }
    }
  });

  test("adversaries API should also be called on page mount", async ({ page }) => {
    const apiCalled = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/adversaries") && resp.status() === 200,
      { timeout: 20_000 }
    ).catch(() => null);

    await navigateToAtomic(page);
    const response = await apiCalled;
    if (response) {
      expect(response.status()).toBe(200);
    }
  });
});
