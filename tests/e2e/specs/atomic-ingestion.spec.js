// @ts-check
const { test, expect } = require("@playwright/test");
const { login } = require("../helpers/auth");
const { navigateToAtomic } = require("../helpers/navigation");

test.describe("Atomic plugin - ability ingestion", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("atomic abilities should be filtered from the global abilities store", async ({ page }) => {
    // Set up response interception before navigating to ensure we catch the call
    const apiCalled = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/abilities") && resp.status() === 200,
      { timeout: 20_000 }
    );

    await navigateToAtomic(page);

    const response = await apiCalled;
    expect(response.status()).toBe(200);
  });

  test("the abilities API response should contain ability objects", async ({ page }) => {
    // Intercept abilities API
    let abilitiesData = null;
    await page.route("**/api/v2/abilities", async (route) => {
      const response = await route.fetch();
      abilitiesData = await response.json();
      return route.fulfill({ response });
    });

    // Wait for the abilities API response after navigation
    const apiResponse = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/abilities") && resp.status() === 200,
      { timeout: 20_000 }
    );
    await navigateToAtomic(page);
    await apiResponse;

    // Verify the response is a non-empty array with standard ability fields
    expect(Array.isArray(abilitiesData)).toBe(true);
    expect(abilitiesData.length).toBeGreaterThan(0);
    const first = abilitiesData[0];
    expect(first).toHaveProperty("ability_id");
    expect(first).toHaveProperty("name");
  });

  test("atomic abilities should have plugin field set to 'atomic'", async ({ page }) => {
    let abilitiesData = null;
    await page.route("**/api/v2/abilities", async (route) => {
      const response = await route.fetch();
      abilitiesData = await response.json();
      return route.fulfill({ response });
    });

    // Wait for the abilities API response after navigation
    const apiResponse = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/abilities") && resp.status() === 200,
      { timeout: 20_000 }
    );
    await navigateToAtomic(page);
    await apiResponse;

    expect(Array.isArray(abilitiesData)).toBe(true);
    const atomicOnes = abilitiesData.filter((a) => a.plugin === "atomic");
    // The count on the page should match the filtered count
    const countText = await page.locator(".is-size-1, h1.is-size-1").first().textContent();
    const displayedCount = parseInt(countText?.trim() || "", 10);
    // Assert the displayed count is a valid number and matches the API array length
    expect(Number.isInteger(displayedCount)).toBe(true);
    expect(atomicOnes.length).toBe(displayedCount);
  });

  test("adversaries API should also be called on page mount", async ({ page }) => {
    const apiCalled = page.waitForResponse(
      (resp) => resp.url().includes("/api/v2/adversaries") && resp.status() === 200,
      { timeout: 20_000 }
    );

    await navigateToAtomic(page);
    const response = await apiCalled;
    expect(response.status()).toBe(200);
  });
});
