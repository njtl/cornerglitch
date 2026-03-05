# QA Screenshots

Baseline snapshots of all admin panels. Due to the absence of a headless browser
in the CI/dev environment, HTML and JSON snapshots are captured instead of PNG
screenshots. The HTML file contains the full SPA (single-page application) and
can be opened in any browser to view all panels.

## Captured Snapshots

| File | Description |
|------|-------------|
| `01-login.html` | Login page HTML |
| `02-dashboard-overview.html` | Full admin SPA (all tabs/panels in one HTML file) |
| `03-server-features.json` | Feature toggles API response |
| `04-server-errors.json` | Config API response (error profiles, weights) |
| `05-server-mcp.json` | MCP stats API response |
| `06-server-vulns.json` | Vulnerability groups API response |
| `07-server-apichaos.json` | API chaos categories response |
| `08-metrics.json` | Metrics API response |
| `09-config-export.json` | Full config export |
| `10-nightmare.json` | Nightmare mode status |

## Why Not PNG Screenshots

The admin dashboard is a JavaScript-driven SPA. Rendering it to PNG requires a
headless browser (Chromium, Playwright, Puppeteer, etc.), which is not available
in this environment. The HTML file (`02-dashboard-overview.html`) contains the
complete SPA — opening it in a local browser shows all panels with full
interactivity.

## Capture Command

```bash
# Capture HTML/JSON snapshots (used in CI)
GLITCH_ADMIN_PASSWORD=admin bash tests/qa/run-qa.sh

# For PNG screenshots (requires headless browser)
# npx playwright screenshot http://localhost:8766/admin --output 02-dashboard-overview.png
```
