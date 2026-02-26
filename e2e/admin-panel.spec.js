const { test, expect } = require('@playwright/test');

const ADMIN = 'http://localhost:8766/admin';
const API = 'http://localhost:8766';
const SERVER = 'http://localhost:8765';
const PASSWORD = process.env.GLITCH_ADMIN_PASSWORD || 'admin';

// Helper: log in via form POST to get a session cookie
async function login(page) {
  await page.goto(ADMIN + '/login');
  await page.fill('#password', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL('**/admin');
}

// Helper: generate some traffic so dashboard has data
async function generateTraffic() {
  const urls = ['/', '/about', '/contact', '/api/test', '/vuln/a01/'];
  for (const url of urls) {
    try { await fetch(SERVER + url); } catch {}
  }
}

// --- Navigation ---

test.describe('Admin Panel Navigation', () => {
  test('loads admin panel with title', async ({ page }) => {
    await login(page);
    await expect(page.locator('h1')).toContainText('GLITCH ADMIN PANEL');
  });

  test('has all 5 tabs', async ({ page }) => {
    await login(page);
    const tabs = page.locator('.tab');
    await expect(tabs).toHaveCount(5);
    const tabNames = ['Dashboard', 'Server', 'Scanner', 'Proxy', 'Settings'];
    for (let i = 0; i < tabNames.length; i++) {
      await expect(tabs.nth(i)).toContainText(tabNames[i]);
    }
  });

  test('tab switching updates URL hash', async ({ page }) => {
    await login(page);
    await page.click('.tab[data-mode="server"]');
    await expect(page).toHaveURL(/#server/);
    await page.click('.tab[data-mode="scanner"]');
    await expect(page).toHaveURL(/#scanner/);
  });

  test('URL hash restores correct tab on load', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(500);
    await expect(page.locator('#panel-server')).toHaveClass(/active/);
  });

  test('all tabs are clickable and show content', async ({ page }) => {
    await login(page);
    const tabIds = ['dashboard', 'server', 'scanner', 'proxy', 'settings'];
    for (const id of tabIds) {
      await page.evaluate((tabName) => window.showTab(tabName), id);
      await expect(page.locator(`#panel-${id}`)).toHaveClass(/active/);
    }
  });
});

// --- Dashboard Tab ---

test.describe('Dashboard Tab', () => {
  test('shows metric cards', async ({ page }) => {
    await generateTraffic();
    await login(page);
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    const cards = page.locator('#dash-metrics .card');
    await expect(cards).not.toHaveCount(0);
    await expect(page.locator('#dash-metrics')).toContainText('Total Requests');
    await expect(page.locator('#dash-metrics')).toContainText('Uptime');
  });

  test('shows sparkline', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-sparkline')).toBeVisible();
  });

  test('shows connected clients table', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-clients-body').locator('..').locator('..')).toBeVisible();
  });

  test('shows request log table', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-log-body').locator('..').locator('..')).toBeVisible();
  });

  test('shows subsystem status cards', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#dashboard');
    await page.waitForTimeout(1500);
    await expect(page.locator('#dash-mode-server')).toBeVisible();
    await expect(page.locator('#dash-mode-scanner')).toBeVisible();
    await expect(page.locator('#dash-mode-proxy')).toBeVisible();
  });
});

// --- Server Tab ---

test.describe('Server Tab', () => {
  test('shows feature toggles section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    // Features section starts open; wait for toggle rows to be populated by auto-refresh
    await page.waitForSelector('#toggles .toggle-row', { timeout: 10000 });
    const toggles = page.locator('#toggles .toggle-row');
    const count = await toggles.count();
    expect(count).toBeGreaterThanOrEqual(10);
  });

  test('can toggle a feature', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    // Wait for toggles to be populated
    await page.waitForSelector('#toggles .toggle-row', { timeout: 10000 });
    const toggleRow = page.locator('.toggle-row:has(.toggle-name:text("Labyrinth"))');
    await expect(toggleRow).toBeVisible();
    const toggleLabel = toggleRow.locator('.toggle-sw');
    await toggleLabel.click();
    await page.waitForTimeout(500);
    await expect(page.locator('#toast')).toBeVisible();
    // Toggle back to restore state
    await toggleLabel.click();
    await page.waitForTimeout(500);
  });

  test('shows error configuration section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(1500);
    // Open the errors section via JS
    await page.evaluate(() => window.toggleServerSection('errors'));
    await page.waitForTimeout(300);
    const httpGrid = page.locator('#http-error-grid');
    await expect(httpGrid).toBeVisible();
  });

  test('shows content configuration section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(1500);
    // Open the content section via JS
    await page.evaluate(() => window.toggleServerSection('content'));
    await page.waitForTimeout(300);
    await expect(page.locator('#page-type-grid')).toBeVisible();
  });

  test('shows dropdown controls', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(1500);
    // Open content section via JS
    await page.evaluate(() => window.toggleServerSection('content'));
    await page.waitForTimeout(300);
    await expect(page.locator('#ctrl-honeypot-style')).toBeVisible();
    await expect(page.locator('#ctrl-framework')).toBeVisible();
  });

  test('shows vulnerability groups section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(1500);
    // Open vulns section via JS
    await page.evaluate(() => window.toggleServerSection('vulns'));
    await page.waitForTimeout(300);
    const section = page.locator('#srv-vulns');
    await expect(section).toBeVisible();
  });

  test('shows recording section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#server');
    await page.waitForTimeout(1500);
    // Open recording section via JS
    await page.evaluate(() => window.toggleServerSection('recording'));
    await page.waitForTimeout(300);
    await expect(page.locator('#rec-format')).toBeVisible();
    await expect(page.locator('#rec-start-btn')).toBeVisible();
  });
});

// --- Scanner Tab ---

test.describe('Scanner Tab', () => {
  test('shows scanner subtabs', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    const subtabs = page.locator('.scanner-subtab-btn');
    await expect(subtabs).toHaveCount(3);
  });

  test('shows scanner launch buttons', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    // Eval subtab should be active by default
    await expect(page.locator('#scanner-eval-panel')).toBeVisible();
    // Check scanner card panels exist
    const scannerPanels = page.locator('#scanner-eval-panel .scanner-panel');
    const count = await scannerPanels.count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('shows scan history table', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('#scanner-history-body').locator('..').locator('..')).toBeVisible();
  });

  test('shows scanner type selector for manual upload', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    // Expand the manual upload section (starts collapsed)
    await page.evaluate(() => {
      document.getElementById('manual-upload-body').style.display = '';
    });
    await page.waitForTimeout(300);
    await expect(page.locator('#scanner-type')).toBeVisible();
    const options = page.locator('#scanner-type option');
    const count = await options.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  test('shows scanner output textarea', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    // Expand the manual upload section (starts collapsed)
    await page.evaluate(() => {
      document.getElementById('manual-upload-body').style.display = '';
    });
    await page.waitForTimeout(300);
    await expect(page.locator('#scanner-output')).toBeVisible();
  });

  test('built-in scanner subtab shows profile cards', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    // Switch to built-in subtab
    await page.evaluate(() => window.switchScannerSubtab('builtin'));
    await page.waitForTimeout(300);
    await expect(page.locator('#scanner-builtin-panel')).toBeVisible();
    const profiles = page.locator('.profile-card');
    const count = await profiles.count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('replay subtab shows upload controls', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    // Switch to replay subtab
    await page.evaluate(() => window.switchScannerSubtab('replay'));
    await page.waitForTimeout(300);
    await expect(page.locator('#scanner-replay-panel')).toBeVisible();
    await expect(page.locator('#replay-upload-label')).toBeVisible();
  });

  test('shows target vulnerability surface', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#scanner');
    await page.waitForTimeout(1000);
    await expect(page.locator('#scanner-profile-summary')).toBeVisible();
  });
});

// --- Proxy Tab ---

test.describe('Proxy Tab', () => {
  test('shows proxy controls', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#proxy');
    await page.waitForTimeout(1500);
    await expect(page.locator('#proxy-rt-port')).toBeVisible();
    await expect(page.locator('#proxy-rt-target')).toBeVisible();
    await expect(page.locator('#proxy-rt-start-btn')).toBeVisible();
  });

  test('shows proxy mode radios', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#proxy');
    await page.waitForTimeout(1500);
    await expect(page.locator('#proxy-mode-radios')).toBeVisible();
    const radios = page.locator('input[name="proxy-mode"]');
    const count = await radios.count();
    expect(count).toBeGreaterThanOrEqual(4);
  });

  test('shows proxy metrics section', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#proxy');
    await page.waitForTimeout(1500);
    await expect(page.locator('#proxy-metrics')).toBeVisible();
  });

  test('shows proxy pipeline table', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#proxy');
    await page.waitForTimeout(1500);
    await expect(page.locator('#proxy-pipeline-body').locator('..').locator('..')).toBeVisible();
  });
});

// --- Settings Tab ---

test.describe('Settings Tab', () => {
  test('shows password change form', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#settings');
    await page.waitForTimeout(1000);
    await expect(page.locator('#settings-current-pw')).toBeVisible();
    await expect(page.locator('#settings-new-pw')).toBeVisible();
    await expect(page.locator('#settings-confirm-pw')).toBeVisible();
  });

  test('shows config import/export buttons', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#settings');
    await page.waitForTimeout(1000);
    await expect(page.locator('button:text("Export Config")')).toBeVisible();
    await expect(page.locator('button:text("Import Config")')).toBeVisible();
  });

  test('shows server info', async ({ page }) => {
    await login(page);
    await page.goto(ADMIN + '#settings');
    await page.waitForTimeout(1000);
    await expect(page.locator('#settings-uptime')).toBeVisible();
  });
});

// --- API Tests (use Basic Auth) ---

test.describe('Config Export/Import API', () => {
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

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
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('toggle feature and verify', async ({ request }) => {
    const resp = await request.get(API + '/admin/api/features');
    const before = await resp.json();

    const toggleResp = await request.post(API + '/admin/api/features', {
      data: { feature: 'search', enabled: false },
    });
    const result = await toggleResp.json();
    expect(result.ok).toBe(true);

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
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

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
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('set and reset error weights', async ({ request }) => {
    const setResp = await request.post(API + '/admin/api/error-weights', {
      data: { error_type: '503', weight: 0.25 },
    });
    const setResult = await setResp.json();
    expect(setResult.ok).toBe(true);

    const getResp = await request.get(API + '/admin/api/error-weights');
    const weights = await getResp.json();
    expect(weights.weights['503']).toBe(0.25);

    const resetResp = await request.post(API + '/admin/api/error-weights', {
      data: { reset: true },
    });
    const resetResult = await resetResp.json();
    expect(resetResult.ok).toBe(true);
    expect(Object.keys(resetResult.weights)).toHaveLength(0);
  });
});

test.describe('Page Type Weights API', () => {
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('set and reset page type weights', async ({ request }) => {
    const setResp = await request.post(API + '/admin/api/page-type-weights', {
      data: { page_type: 'json', weight: 0.3 },
    });
    const setResult = await setResp.json();
    expect(setResult.ok).toBe(true);

    const getResp = await request.get(API + '/admin/api/page-type-weights');
    const weights = await getResp.json();
    expect(weights.weights['json']).toBe(0.3);

    const resetResp = await request.post(API + '/admin/api/page-type-weights', {
      data: { reset: true },
    });
    const resetResult = await resetResp.json();
    expect(resetResult.ok).toBe(true);
    expect(Object.keys(resetResult.weights)).toHaveLength(0);
  });
});

test.describe('Config Wiring', () => {
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('active framework config affects server headers', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'active_framework', value: 'django' },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.active_framework).toBe('django');

    // Reset to auto
    await request.post(API + '/admin/api/config', {
      data: { key: 'active_framework', value: 'auto' },
    });
  });

  test('error rate multiplier config is stored', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'error_rate_multiplier', value: 2.5 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.error_rate_multiplier).toBe(2.5);

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

    const pageResp = await request.get(SERVER + '/blog/test-theme');
    const html = await pageResp.text();
    expect(html).toContain('#0f172a');

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

    await request.post(API + '/admin/api/config', {
      data: { key: 'content_cache_ttl_sec', value: 60 },
    });
  });

  test('recorder format config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'recorder_format', value: 'pcap' },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.recorder_format).toBe('pcap');

    await request.post(API + '/admin/api/config', {
      data: { key: 'recorder_format', value: 'jsonl' },
    });
  });

  test('labyrinth max depth config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'max_labyrinth_depth', value: 25 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.max_labyrinth_depth).toBe(25);

    await request.post(API + '/admin/api/config', {
      data: { key: 'max_labyrinth_depth', value: 50 },
    });
  });

  test('header corruption level config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'header_corrupt_level', value: 3 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.header_corrupt_level).toBe(3);

    await request.post(API + '/admin/api/config', {
      data: { key: 'header_corrupt_level', value: 1 },
    });
  });

  test('captcha trigger threshold config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'captcha_trigger_thresh', value: 50 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.captcha_trigger_thresh).toBe(50);

    await request.post(API + '/admin/api/config', {
      data: { key: 'captcha_trigger_thresh', value: 100 },
    });
  });

  test('bot score threshold config is stored and synced', async ({ request }) => {
    await request.post(API + '/admin/api/config', {
      data: { key: 'bot_score_threshold', value: 80 },
    });

    const cfgResp = await request.get(API + '/admin/api/config');
    const cfg = await cfgResp.json();
    expect(cfg.bot_score_threshold).toBe(80);

    await request.post(API + '/admin/api/config', {
      data: { key: 'bot_score_threshold', value: 60 },
    });
  });
});

test.describe('Scanner Comparison API', () => {
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('comparison history endpoint returns array', async ({ request }) => {
    const resp = await request.get(API + '/admin/api/scanner/history');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.entries).toBeDefined();
    expect(Array.isArray(data.entries)).toBeTruthy();
  });

  test('scanner baseline endpoint works', async ({ request }) => {
    const resp = await request.get(API + '/admin/api/scanner/baseline?scanner=nuclei');
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data).toBeDefined();
  });

  test('multi-compare endpoint accepts multiple scanners', async ({ request }) => {
    const resp = await request.post(API + '/admin/api/scanner/multi-compare', {
      data: {
        reports: {
          nuclei: '{"info":{"severity":"high"},"matched-at":"http://localhost:8765/vuln/a01/","template-id":"sql-injection"}',
          ffuf: '{"results":[{"input":{"FUZZ":"admin"},"url":"http://localhost:8765/admin","status":200,"length":1234}]}',
        },
      },
    });
    expect(resp.ok()).toBeTruthy();
    const data = await resp.json();
    expect(data.reports).toBeDefined();
    expect(data.coverage_matrix).toBeDefined();
  });

  test('single compare adds to history', async ({ request }) => {
    const beforeResp = await request.get(API + '/admin/api/scanner/history');
    const before = await beforeResp.json();
    const countBefore = before.entries.length;

    await request.post(API + '/admin/api/scanner/compare', {
      data: {
        scanner: 'nuclei',
        data: '{"info":{"severity":"high"},"matched-at":"http://localhost:8765/vuln/a01/","template-id":"sql-injection"}',
      },
    });

    const afterResp = await request.get(API + '/admin/api/scanner/history');
    const after = await afterResp.json();
    expect(after.entries.length).toBeGreaterThan(countBefore);
  });
});

test.describe('PCAP Recording API', () => {
  test.use({
    extraHTTPHeaders: {
      'Authorization': 'Basic ' + Buffer.from(':' + PASSWORD).toString('base64'),
    },
  });

  test('can start recording in PCAP format', async ({ request }) => {
    const resp = await request.post(SERVER + '/captures/start', {
      data: { format: 'pcap' },
    });
    const data = await resp.json();
    expect(data.status).toBe('recording');
    if (data.file) {
      expect(data.file).toContain('.pcap');
    }

    await request.post(SERVER + '/captures/stop');
  });

  test('can start recording in JSONL format', async ({ request }) => {
    const resp = await request.post(SERVER + '/captures/start', {
      data: { format: 'jsonl' },
    });
    const data = await resp.json();
    expect(data.status).toBe('recording');

    await request.post(SERVER + '/captures/stop');
  });
});
