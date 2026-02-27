// @ts-check
const { test, expect } = require('@playwright/test');

const ADMIN = 'http://localhost:8766/admin';
const API = 'http://localhost:8766';
const PASSWORD = process.env.GLITCH_ADMIN_PASSWORD || 'admin';

test.setTimeout(60000);

async function login(page) {
  await page.goto(ADMIN + '/login');
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/admin');
}

async function goToBuiltinScanner(page) {
  await login(page);
  await page.goto(ADMIN + '#scanner');
  await page.waitForTimeout(1000);
  // Click the Built-in Scanner sub-tab
  const builtinTab = page.locator('.scanner-subtab-btn').filter({ hasText: /built.?in/i });
  if (await builtinTab.count() > 0) {
    await builtinTab.click();
  }
  await page.waitForTimeout(2000); // wait for results to render
}

// Ensure a completed scan exists. If no completed scan, start one and wait.
async function ensureScanCompleted(request) {
  const statusResp = await request.get(API + '/admin/api/scanner/builtin/status');
  const status = await statusResp.json();
  if (status.state === 'completed') return;
  if (status.state === 'running') {
    // Wait for completion
    for (let i = 0; i < 150; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const s = await (await request.get(API + '/admin/api/scanner/builtin/status')).json();
      if (s.state !== 'running') return;
    }
    return;
  }
  // Start a compliance scan
  await request.post(API + '/admin/api/scanner/builtin/run', {
    data: { profile: 'compliance', target: 'http://localhost:8765' },
  });
  for (let i = 0; i < 150; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const s = await (await request.get(API + '/admin/api/scanner/builtin/status')).json();
    if (s.state !== 'running') return;
  }
}

test.describe.serial('Scanner Results UI', () => {
  test.beforeAll(async ({ request }) => {
    test.setTimeout(360000);
    await ensureScanCompleted(request);
  });

  test('results section visible after completed scan', async ({ page }) => {
    await goToBuiltinScanner(page);
    await expect(page.locator('#builtin-results-section')).toBeVisible({ timeout: 10000 });
  });

  test('severity count cards render correctly', async ({ page }) => {
    await goToBuiltinScanner(page);
    const labels = await page.locator('#builtin-results-cards .card .label').allTextContents();
    expect(labels).toContain('Critical');
    expect(labels).toContain('High');
    expect(labels).toContain('Medium');
    expect(labels).toContain('Low');
    expect(labels).toContain('Info');
    expect(labels).toContain('Total');
  });

  test('severity filter badges all start active', async ({ page }) => {
    await goToBuiltinScanner(page);
    const filters = page.locator('.severity-filter');
    expect(await filters.count()).toBe(5);
    for (let i = 0; i < 5; i++) {
      expect(await filters.nth(i).evaluate(el => el.classList.contains('active'))).toBeTruthy();
    }
  });

  test('severity filter toggles independently without resetting others', async ({ page }) => {
    await goToBuiltinScanner(page);

    // Deactivate info
    const infoFilter = page.locator('.severity-filter[data-sev="info"]');
    await infoFilter.click();
    await page.waitForTimeout(300);
    expect(await infoFilter.evaluate(el => el.classList.contains('active'))).toBeFalsy();

    // Others stay active
    for (const sev of ['critical', 'high', 'medium', 'low']) {
      expect(await page.locator(`.severity-filter[data-sev="${sev}"]`).evaluate(el => el.classList.contains('active'))).toBeTruthy();
    }

    // Re-activate
    await infoFilter.click();
    await page.waitForTimeout(300);
    expect(await infoFilter.evaluate(el => el.classList.contains('active'))).toBeTruthy();
  });

  test('arrow icons render as Unicode triangle, not raw text', async ({ page }) => {
    await goToBuiltinScanner(page);
    const arrows = page.locator('.fg-arrow');
    expect(await arrows.count()).toBeGreaterThan(0);
    expect((await arrows.first().textContent()).trim()).toBe('\u25B6');
  });

  test('findings groups start collapsed', async ({ page }) => {
    await goToBuiltinScanner(page);
    const groups = page.locator('.findings-group');
    expect(await groups.count()).toBeGreaterThan(0);
    expect(await groups.first().evaluate(el => el.hasAttribute('open'))).toBeFalsy();
  });

  test('group toggle open/close works without auto-reopen', async ({ page }) => {
    await goToBuiltinScanner(page);
    const group = page.locator('.findings-group').first();
    const summary = group.locator('summary');

    // Open
    await summary.click();
    await page.waitForTimeout(300);
    expect(await group.evaluate(el => el.hasAttribute('open'))).toBeTruthy();

    // Close
    await summary.click();
    await page.waitForTimeout(500);
    expect(await group.evaluate(el => el.hasAttribute('open'))).toBeFalsy();

    // Stays closed
    await page.waitForTimeout(500);
    expect(await group.evaluate(el => el.hasAttribute('open'))).toBeFalsy();
  });

  test('search filter does not reset severity filters', async ({ page }) => {
    await goToBuiltinScanner(page);

    // Deactivate info first
    const infoFilter = page.locator('.severity-filter[data-sev="info"]');
    await infoFilter.click();
    await page.waitForTimeout(200);

    // Type in search
    await page.locator('#findings-search').fill('injection');
    await page.waitForTimeout(300);

    // Info should still be inactive
    expect(await infoFilter.evaluate(el => el.classList.contains('active'))).toBeFalsy();
    // Critical should still be active
    expect(await page.locator('.severity-filter[data-sev="critical"]').evaluate(el => el.classList.contains('active'))).toBeTruthy();
  });

  test('scan history has clickable rows', async ({ page }) => {
    await goToBuiltinScanner(page);
    const rows = page.locator('#builtin-history-body tr.history-clickable');
    expect(await rows.count()).toBeGreaterThan(0);
    expect(await rows.first().evaluate(el => getComputedStyle(el).cursor)).toBe('pointer');
  });

  test('clicking history row shows banner and close works', async ({ page }) => {
    await goToBuiltinScanner(page);
    const rows = page.locator('#builtin-history-body tr.history-clickable');
    await rows.first().click();
    await page.waitForTimeout(2000);

    await expect(page.locator('#builtin-results-section')).toBeVisible();
    const banner = page.locator('.history-viewing-banner');
    await expect(banner).toBeVisible();
    expect(await banner.textContent()).toContain('Viewing historical scan');

    // Close
    await banner.locator('button').click();
    await page.waitForTimeout(300);
    expect(await page.locator('#builtin-results-section').evaluate(el => el.style.display)).toBe('none');
  });

  test('no JavaScript errors during UI interactions', async ({ page }) => {
    const jsErrors = [];
    page.on('pageerror', e => jsErrors.push(e.message));

    await goToBuiltinScanner(page);

    // Toggle filter
    const filters = page.locator('.severity-filter');
    if (await filters.count() > 0) {
      await filters.first().click();
      await page.waitForTimeout(200);
      await filters.first().click();
      await page.waitForTimeout(200);
    }

    // Toggle group
    const groups = page.locator('.findings-group');
    if (await groups.count() > 0) {
      await groups.first().locator('summary').click();
      await page.waitForTimeout(200);
      await groups.first().locator('summary').click();
      await page.waitForTimeout(200);
    }

    // Click history
    const rows = page.locator('#builtin-history-body tr.history-clickable');
    if (await rows.count() > 0) {
      await rows.first().click();
      await page.waitForTimeout(2000);
    }

    const relevant = jsErrors.filter(e =>
      !e.includes('net::ERR') && !e.includes('Failed to fetch') && !e.includes('NetworkError')
    );
    expect(relevant).toEqual([]);
  });

  test('progress bar widths capped at 100%', async ({ page }) => {
    await goToBuiltinScanner(page);
    const bars = page.locator('#builtin-scores .prog-fill');
    const count = await bars.count();
    for (let i = 0; i < count; i++) {
      const width = await bars.nth(i).evaluate(el => parseFloat(el.style.width));
      expect(width).toBeLessThanOrEqual(100);
      expect(width).toBeGreaterThanOrEqual(0);
    }
  });
});
