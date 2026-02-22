const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30000,
  retries: 1,
  use: {
    baseURL: 'http://localhost:8766',
    headless: true,
  },
  webServer: {
    command: 'go build -o /tmp/glitch-e2e ./cmd/glitch && /tmp/glitch-e2e',
    port: 8766,
    reuseExistingServer: true,
    timeout: 15000,
  },
});
