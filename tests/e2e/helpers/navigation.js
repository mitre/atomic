/**
 * Navigation helpers for reaching plugin tabs inside Caldera / Magma.
 */

/**
 * Navigate to the Atomic plugin tab in the Magma Vue app.
 */
async function navigateToAtomic(page) {
  const navItem = page.locator(
    'a:has-text("Atomic"), .nav-item:has-text("Atomic"), [data-test="nav-atomic"], button:has-text("Atomic")'
  ).first();
  await navItem.waitFor({ state: "visible", timeout: 15_000 });
  await navItem.click();

  // Wait for the atomic page content
  await page.locator("h2:has-text('Atomic'), .content:has-text('Atomic')").first().waitFor({
    state: "visible",
    timeout: 15_000,
  });
}

module.exports = { navigateToAtomic };
