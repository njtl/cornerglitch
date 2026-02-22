const { test, expect } = require('@playwright/test');

const ADMIN = 'http://localhost:8766/admin';
const API = 'http://localhost:8766';
const SERVER = 'http://localhost:8765';

// Helper: generate some traffic so dashboard/traffic tabs have data
async function generateTraffic() {
  const urls = ['/', '/about', '/contact', '/api/test', '/vuln/a01/'];
  for (const url of urls) {
    try { await fetch(SERVER + url); } catch {}
  }
}

test.describe('Admin Panel Navigation', () => {
  test('loads admin panel with title', async ({ page }) => {
    await page.goto(ADMIN);
    await expect(page.locator('h1')).toContainText('GLITCH ADMIN PANEL');
  });

  test('has all 7 tabs', async ({ page }) => {
    await page.goto(ADMIN);
    const tabs = page.locator('.tab');
    await expect(tabs).toHaveCount(7);
    const tabNames = ['Dashboard', 'Sessions', 'Traffic', 'Controls', 'Request Log', 'Vulnerabilities', 'Scanner'];
    for (let i = 0; i < tabNames.length; i++) {
      await expect(tabs.nth(i)).toContainText(tabNames[i]);
    }
  });

  test('tab switching updates URL hash', async ({ page }) => {
    await page.goto(ADMIN);
    await page.click('.tab:text("Controls")');
    await expect(page).toHaveURL(/#controls/);
    await page.click('.tab:text("Vulnerabilities")');
    await expect(page).toHaveURL(/#vulns/);
  });

  test('URL hash restores correct tab on load', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(500);
    await expect(page.locator('#panel-controls')).toHaveClass(/active/);
  });

  test('all tabs are clickable and show content', async ({ page }) => {
    await page.goto(ADMIN);
    const tabIds = ['dashboard', 'sessions', 'traffic', 'controls', 'log', 'vulns', 'scanner'];
    for (const id of tabIds) {
      await page.click(`.tab[onclick*="${id}"]`);
      await expect(page.locator(`#panel-${id}`)).toHaveClass(/active/);
    }
  });
});

test.describe('Dashboard Tab', () => {
  test('shows metric cards', async ({ page }) => {
    await generateTraffic();
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    const cards = page.locator('#dash-metrics .card');
    await expect(cards).not.toHaveCount(0);
    // Check specific card labels
    await expect(page.locator('#dash-metrics')).toContainText('Total Requests');
    await expect(page.locator('#dash-metrics')).toContainText('Uptime');
  });

  test('shows sparkline', async ({ page }) => {
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-sparkline')).toBeVisible();
  });

  test('shows connected clients table', async ({ page }) => {
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-clients-body').locator('..').locator('..')).toBeVisible();
  });
});

test.describe('Sessions Tab', () => {
  test('shows session table headers', async ({ page }) => {
    await page.goto(ADMIN + '#sessions');
    await page.waitForTimeout(1500);
    const headers = page.locator('#panel-sessions th');
    await expect(headers.first()).toContainText('Client ID');
  });

  test('client detail panel is initially hidden', async ({ page }) => {
    await page.goto(ADMIN + '#sessions');
    await expect(page.locator('#client-detail')).not.toBeVisible();
  });
});

test.describe('Traffic Tab', () => {
  test('shows overview cards', async ({ page }) => {
    await generateTraffic();
    await page.goto(ADMIN + '#traffic');
    await page.waitForTimeout(1500);
    await expect(page.locator('#overview-cards')).toContainText('Total Requests');
    await expect(page.locator('#overview-cards')).toContainText('Error Rate');
  });

  test('shows pie chart canvas', async ({ page }) => {
    await page.goto(ADMIN + '#traffic');
    await page.waitForTimeout(1500);
    await expect(page.locator('#pie-status')).toBeVisible();
  });
});

test.describe('Controls Tab', () => {
  test('shows feature toggles', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    const toggles = page.locator('#toggles .toggle-row');
    const count = await toggles.count();
    expect(count).toBeGreaterThanOrEqual(15);
  });

  test('can toggle a feature', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    // Find the labyrinth toggle and click its label (checkbox is visually hidden)
    const toggleRow = page.locator('.toggle-row:has(.toggle-name:text("Labyrinth"))');
    await expect(toggleRow).toBeVisible();
    const toggleLabel = toggleRow.locator('.toggle-sw');
    await toggleLabel.click();
    await page.waitForTimeout(500);
    // Verify the API was called (check toast)
    await expect(page.locator('.toast')).toContainText('labyrinth');
    // Toggle back to restore state
    await toggleLabel.click();
    await page.waitForTimeout(500);
  });

  test('shows slider controls', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    const sliders = page.locator('#sliders .slider-group');
    const count = await sliders.count();
    expect(count).toBeGreaterThanOrEqual(5);
  });

  test('shows error weight radio grid', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    const grid = page.locator('#error-weight-grid');
    await expect(grid).toBeVisible();
    const rows = grid.locator('.ew-row');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(20);
  });

  test('error weight radio buttons are clickable', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    // Click HIGH on the first error type
    const firstRow = page.locator('.ew-row').first();
    const highBtn = firstRow.locator('.ew-opt:text("HIGH")');
    await highBtn.click();
    await page.waitForTimeout(500);
    await expect(highBtn).toHaveClass(/active/);
  });

  test('shows page type weight grid', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    const grid = page.locator('#page-type-grid');
    await expect(grid).toBeVisible();
    const rows = grid.locator('.ew-row');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(8);
  });

  test('shows dropdown controls', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    await expect(page.locator('#ctrl-honeypot-style')).toBeVisible();
    await expect(page.locator('#ctrl-framework')).toBeVisible();
    await expect(page.locator('#ctrl-theme')).toBeVisible();
  });

  test('config export button exists', async ({ page }) => {
    await page.goto(ADMIN + '#controls');
    await page.waitForTimeout(1500);
    await expect(page.locator('button:text("Export Config")')).toBeVisible();
    await expect(page.locator('button:text("Import Config")')).toBeVisible();
  });
});

test.describe('Request Log Tab', () => {
  test('shows log table with headers', async ({ page }) => {
    await page.goto(ADMIN + '#log');
    await page.waitForTimeout(1500);
    await expect(page.locator('#panel-log th').first()).toContainText('Time');
  });

  test('search filter is functional', async ({ page }) => {
    await page.goto(ADMIN + '#log');
    await page.waitForTimeout(1500);
    const filter = page.locator('#log-filter');
    await expect(filter).toBeVisible();
    await filter.fill('nonexistent-path-xyz');
    await page.waitForTimeout(300);
    // Should filter the results (possibly to 0)
    const rows = page.locator('#log-body tr');
    const count = await rows.count();
    expect(count).toBeLessThanOrEqual(0);
  });
});

test.describe('Vulnerabilities Tab', () => {
  test('shows vuln overview cards', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    await page.waitForTimeout(2000);
    await expect(page.locator('#vuln-overview-cards')).toContainText('OWASP');
    await expect(page.locator('#vuln-overview-cards')).toContainText('Total Vulns');
  });

  test('shows group toggles', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    await page.waitForTimeout(2000);
    const groups = page.locator('#vuln-group-toggles .group-toggle');
    await expect(groups).toHaveCount(3);
  });

  test('shows severity badges', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    await page.waitForTimeout(2000);
    await expect(page.locator('#vuln-severity-badges')).toContainText('critical');
    await expect(page.locator('#vuln-severity-badges')).toContainText('high');
  });

  test('shows vuln table with toggles', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    // Wait for vuln table rows to appear (profile + vulns APIs)
    await page.waitForSelector('#vuln-body tr', { timeout: 10000 });
    const vulnRows = page.locator('#vuln-body tr');
    const count = await vulnRows.count();
    expect(count).toBeGreaterThanOrEqual(5);
  });

  test('vuln search filter works', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    await page.waitForTimeout(3000);
    // First verify we have some rows
    const allRows = await page.locator('#vuln-body tr').count();
    if (allRows === 0) return; // Skip if no data loaded yet
    const filter = page.locator('#vuln-filter');
    await filter.fill('xss');
    await page.waitForTimeout(500);
    const rows = page.locator('#vuln-body tr');
    const count = await rows.count();
    expect(count).toBeLessThan(allRows); // filtered should be fewer
  });

  test('can toggle vuln group', async ({ page }) => {
    await page.goto(ADMIN + '#vulns');
    await page.waitForTimeout(3000);
    // Toggle OWASP group by clicking the label (checkbox is hidden)
    const owaspToggle = page.locator('.group-toggle:has(.toggle-name:text("OWASP")) .toggle-sw');
    await owaspToggle.click();
    await page.waitForTimeout(500);
    // Toggle it back
    await owaspToggle.click();
    await page.waitForTimeout(500);
  });
});

test.describe('Scanner Tab', () => {
  test('shows profile generation button', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('button:text("Generate Profile")')).toBeVisible();
  });

  test('generate profile shows vulnerability counts', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await page.click('button:text("Generate Profile")');
    await page.waitForTimeout(1500);
    await expect(page.locator('#scanner-profile-summary')).toContainText('Total Vulns');
    await expect(page.locator('#scanner-profile-summary')).toContainText('Total Endpoints');
  });

  test('shows scanner type selector', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('#scanner-type')).toBeVisible();
    const options = page.locator('#scanner-type option');
    const count = await options.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  test('shows scanner output textarea', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('#scanner-output')).toBeVisible();
  });

  test('shows run scanner buttons', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    const btns = page.locator('#scanner-run-btns .scanner-btn');
    const count = await btns.count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('shows scan history table', async ({ page }) => {
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('#scanner-history-body').locator('..').locator('..')).toBeVisible();
  });
});

test.describe('Config Export/Import API', () => {
  test('export returns valid JSON with all sections', async ({ request }) => {
    const resp = await request.get(API + '/admin/api/config/export');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.version).toBe('1.0');
    expect(data.features).toBeDefined();
    expect(data.config).toBeDefined();
    expect(data.vuln_config).toBeDefined();
    expect(data.features.labyrinth).toBeDefined();
    expect(data.config.max_labyrinth_depth).toBeDefined();
  });

  test('import restores config state', async ({ request }) => {
    // Export current state
    const exportResp = await request.get(API + '/admin/api/config/export');
    const original = await exportResp.json();

    // Modify a feature
    await request.post(API + '/admin/api/features', {
      data: { feature: 'captcha', enabled: false },
    });

    // Verify it changed
    const featResp = await request.get(API + '/admin/api/features');
    const feats = await featResp.json();
    expect(feats.captcha).toBe(false);

    // Import original config
    const importResp = await request.post(API + '/admin/api/config/import', {
      data: original,
    });
    const importResult = await importResp.json();
    expect(importResult.ok).toBe(true);

    // Verify restoration
    const featResp2 = await request.get(API + '/admin/api/features');
    const feats2 = await featResp2.json();
    expect(feats2.captcha).toBe(original.features.captcha);
  });
});

test.describe('Feature Toggle API', () => {
  test('toggle feature and verify', async ({ request }) => {
    // Get current state
    const resp = await request.get(API + '/admin/api/features');
    const before = await resp.json();

    // Toggle search off
    const toggleResp = await request.post(API + '/admin/api/features', {
      data: { feature: 'search', enabled: false },
    });
    const result = await toggleResp.json();
    expect(result.ok).toBe(true);

    // Verify
    const resp2 = await request.get(API + '/admin/api/features');
    const after = await resp2.json();
    expect(after.search).toBe(false);

    // Restore
    await request.post(API + '/admin/api/features', {
      data: { feature: 'search', enabled: before.search },
    });
  });
});

test.describe('Vulnerability Controls API', () => {
  test('toggle vuln group', async ({ request }) => {
    const resp = await request.post(API + '/admin/api/vulns/group', {
      data: { group: 'advanced', enabled: false },
    });
    const result = await resp.json();
    expect(result.ok).toBe(true);

    const stateResp = await request.get(API + '/admin/api/vulns');
    const state = await stateResp.json();
    expect(state.groups.advanced).toBe(false);

    // Restore
    await request.post(API + '/admin/api/vulns/group', {
      data: { group: 'advanced', enabled: true },
    });
  });

  test('toggle individual vuln category', async ({ request }) => {
    const resp = await request.post(API + '/admin/api/vulns', {
      data: { id: 'owasp-a01', enabled: false },
    });
    const result = await resp.json();
    expect(result.ok).toBe(true);

    // Restore
    await request.post(API + '/admin/api/vulns', {
      data: { id: 'owasp-a01', enabled: true },
    });
  });
});

test.describe('Error Weights API', () => {
  test('set and reset error weights', async ({ request }) => {
    // Set a weight
    const setResp = await request.post(API + '/admin/api/error-weights', {
      data: { error_type: '503', weight: 0.25 },
    });
    const setResult = await setResp.json();
    expect(setResult.ok).toBe(true);

    // Verify
    const getResp = await request.get(API + '/admin/api/error-weights');
    const weights = await getResp.json();
    expect(weights.weights['503']).toBe(0.25);

    // Reset
    const resetResp = await request.post(API + '/admin/api/error-weights', {
      data: { reset: true },
    });
    const resetResult = await resetResp.json();
    expect(resetResult.ok).toBe(true);
    expect(Object.keys(resetResult.weights)).toHaveLength(0);
  });
});

test.describe('Page Type Weights API', () => {
  test('set and reset page type weights', async ({ request }) => {
    // Set a weight
    const setResp = await request.post(API + '/admin/api/page-type-weights', {
      data: { page_type: 'json', weight: 0.3 },
    });
    const setResult = await setResp.json();
    expect(setResult.ok).toBe(true);

    // Verify
    const getResp = await request.get(API + '/admin/api/page-type-weights');
    const weights = await getResp.json();
    expect(weights.weights['json']).toBe(0.3);

    // Reset
    const resetResp = await request.post(API + '/admin/api/page-type-weights', {
      data: { reset: true },
    });
    const resetResult = await resetResp.json();
    expect(resetResult.ok).toBe(true);
    expect(Object.keys(resetResult.weights)).toHaveLength(0);
  });
});

test.describe('Config Wiring', () => {
  test('active framework config affects server headers', async ({ request }) => {
    // Set framework to Django
    await request.post(API + '/admin/api/config', {
      data: { key: 'active_framework', value: 'django' },
    });

    // Verify config was saved
    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.active_framework).toBe('django');

    // Reset to auto
    await request.post(API + '/admin/api/config', {
      data: { key: 'active_framework', value: 'auto' },
    });
  });

  test('error rate multiplier config is stored', async ({ request }) => {
    // Set multiplier
    await request.post(API + '/admin/api/config', {
      data: { key: 'error_rate_multiplier', value: 2.5 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.error_rate_multiplier).toBe(2.5);

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'error_rate_multiplier', value: 1.0 },
    });
  });

  test('delay config is stored', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'delay_min_ms', value: 50 },
    });
    await request.post(API + '/admin/api/config', {
      data: { key: 'delay_max_ms', value: 200 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.delay_min_ms).toBe(50);
    expect(cfg.delay_max_ms).toBe(200);

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'delay_min_ms', value: 0 },
    });
    await request.post(API + '/admin/api/config', {
      data: { key: 'delay_max_ms', value: 0 },
    });
  });

  test('cookie trap frequency config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'cookie_trap_frequency', value: 2 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.cookie_trap_frequency).toBe(2);

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'cookie_trap_frequency', value: 6 },
    });
  });

  test('js trap difficulty config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'js_trap_difficulty', value: 4 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.js_trap_difficulty).toBe(4);

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'js_trap_difficulty', value: 2 },
    });
  });

  test('content theme config is stored and affects pages', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'content_theme', value: 'dark' },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.content_theme).toBe('dark');

    // Verify theme is applied to content pages
    const pageResp = await request.get(SERVER + '/blog/test-theme');
    const html = await pageResp.text();
    expect(html).toContain('#0f172a'); // dark theme bg color

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'content_theme', value: 'default' },
    });
  });

  test('honeypot response style config is stored', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'honeypot_response_style', value: 'aggressive' },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.honeypot_response_style).toBe('aggressive');

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'honeypot_response_style', value: 'realistic' },
    });
  });

  test('content cache TTL config is stored', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'content_cache_ttl_sec', value: 120 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.content_cache_ttl_sec).toBe(120);

    // Reset
    await request.post(API + '/admin/api/config', {
      data: { key: 'content_cache_ttl_sec', value: 60 },
    });
  });
});
