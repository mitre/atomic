/**
 * Shared authentication helper for Caldera UI tests.
 *
 * Caldera's default credentials are admin:admin.  Override via env vars
 * CALDERA_USER / CALDERA_PASS if the instance uses something else.
 */
const CALDERA_USER = process.env.CALDERA_USER || "admin";
const CALDERA_PASS = process.env.CALDERA_PASS || "admin";

/**
 * Log into Caldera through the login page.
 * After this resolves the page is authenticated and ready.
 */
async function login(page) {
  await page.goto("/");

  // If we are already past the login screen, nothing to do.
  if (page.url().includes("/login") || (await page.locator('input[name="username"], input#username').count()) > 0) {
    await page.locator('input[name="username"], input#username').first().fill(CALDERA_USER);
    await page.locator('input[name="password"], input#password').first().fill(CALDERA_PASS);
    await page.locator('button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign")').first().click();
    // Wait for navigation away from login
    await page.waitForURL((url) => !url.pathname.includes("/login"), { timeout: 15_000 });
  }
}

module.exports = { login, CALDERA_USER, CALDERA_PASS };
