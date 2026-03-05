# QA Test Cases — Glitch Admin Dashboard

## Prerequisites

- Glitch server running on port 8765, dashboard on port 8766
- Admin password set via `GLITCH_ADMIN_PASSWORD` env var or `.env` file
- Browser or agent-browser available for UI testing

---

## TC-001: Admin Login

| Step | Action | Expected |
|------|--------|----------|
| 1 | Navigate to `http://localhost:8766/admin` | Redirected to login page |
| 2 | Enter wrong password | Error message shown |
| 3 | Enter correct password | Redirected to dashboard |
| 4 | Refresh page | Still authenticated (session cookie) |
| 5 | Wait 8+ hours | Session expires, redirected to login |

---

## TC-002: Dashboard Tab — Overview

| Step | Action | Expected |
|------|--------|----------|
| 1 | Click Dashboard tab | Shows overview with metrics cards |
| 2 | Check metrics | Uptime, total requests, error rate, unique clients visible |
| 3 | Check time series | Chart or data table present |
| 4 | Check quick actions | "Run Scanner" and "View Proxy" buttons visible |
| 5 | Wait for auto-refresh | Metrics update every 5 seconds |

---

## TC-003: Server Tab — Feature Toggles

| Step | Action | Expected |
|------|--------|----------|
| 1 | Click Server tab | Server status bar visible (RUNNING) |
| 2 | Expand Features section | All feature toggles visible |
| 3 | Toggle a feature off (e.g., labyrinth) | Toggle turns off, change persists |
| 4 | Toggle it back on | Toggle turns on |
| 5 | Verify all toggles present | honeypot, captcha, oauth, analytics, cdn, etc. |
| 6 | Check MCP toggle | MCP Honeypot toggle visible and functional |
| 7 | Check api_chaos, media_chaos, budget_traps | All three toggles visible |

---

## TC-004: Server Tab — Error Profiles

| Step | Action | Expected |
|------|--------|----------|
| 1 | Expand Errors section | Error type sliders visible |
| 2 | Adjust a slider | Weight changes, toast notification |
| 3 | Check "Use Custom Weights" toggle | Can switch between default and custom |
| 4 | Check reset button | Resets to default weights |

---

## TC-005: Server Tab — MCP Section

| Step | Action | Expected |
|------|--------|----------|
| 1 | Expand MCP Honeypot section | Stats cards visible (Sessions, Tool Calls, etc.) |
| 2 | Check stats | Shows tools registered, resources exposed, prompts registered |
| 3 | Check events table | Table with Time, Method, Tool/URI, Category, Session columns |
| 4 | Check per-tool breakdown | Shows tool call counts when MCP clients connect |
| 5 | Auto-refresh when section open | Stats update on dashboard refresh cycle |

---

## TC-006: Server Tab — Vulnerabilities

| Step | Action | Expected |
|------|--------|----------|
| 1 | Expand Vulnerabilities section | Vuln group toggles visible |
| 2 | Toggle a group off | Group disabled |
| 3 | Toggle all on/off | All groups toggle |
| 4 | Check filter | Can filter vulnerabilities by name |

---

## TC-007: Scanner Tab — Evaluate External

| Step | Action | Expected |
|------|--------|----------|
| 1 | Click Scanner tab | Shows Evaluate External sub-tab by default |
| 2 | Check scanner launch section | Scanner selection (nuclei, httpx, etc.) |
| 3 | Check history section | Previous scan results (if any) |
| 4 | Check results section | Findings table with severity/category |

---

## TC-008: Scanner Tab — Built-in Scanner

| Step | Action | Expected |
|------|--------|----------|
| 1 | Switch to Built-in Scanner sub-tab | Profile selection visible |
| 2 | Select a profile | Profile highlighted |
| 3 | Click Run | Scanner starts, progress shown |
| 4 | Wait for completion | Results displayed with findings |

---

## TC-009: Scanner Tab — MCP Scanner

| Step | Action | Expected |
|------|--------|----------|
| 1 | Switch to MCP Scanner sub-tab | Input field and Scan button visible |
| 2 | Enter target URL | URL accepted |
| 3 | Click Scan | Status shows "Scanning..." |
| 4 | Wait for completion | Risk score, findings table, server info shown |
| 5 | Check findings | Injection, credential, traversal findings listed |

---

## TC-010: Proxy Tab

| Step | Action | Expected |
|------|--------|----------|
| 1 | Click Proxy tab | Proxy status bar visible |
| 2 | Check proxy config | Target URL, port, mode settings visible |
| 3 | Start proxy | Proxy starts (or shows running status) |
| 4 | Check proxy modes | Transparent, WAF, Chaos modes available |

---

## TC-011: Settings Tab

| Step | Action | Expected |
|------|--------|----------|
| 1 | Click Settings tab | Settings sections visible |
| 2 | Check config export | Export button works, downloads JSON |
| 3 | Check config import | Import accepts JSON file |
| 4 | Check password change | Can change admin password |
| 5 | Check stats reset | Can reset metrics |

---

## TC-012: Nightmare Mode

| Step | Action | Expected |
|------|--------|----------|
| 1 | Check nightmare bar | Visible at top of dashboard |
| 2 | Activate server nightmare | Red pulsing bar, extreme settings applied |
| 3 | Verify settings changed | Error rates increased, chaos enabled |
| 4 | Deactivate nightmare | Settings restored to previous values |

---

## TC-013: Config Persistence

| Step | Action | Expected |
|------|--------|----------|
| 1 | Change a setting | Setting applied |
| 2 | Export config | JSON file with current settings |
| 3 | Restart server | Settings preserved (via state file or DB) |
| 4 | Import previous export | All settings restored |

---

## TC-014: MCP Endpoint (Functional)

| Step | Action | Expected |
|------|--------|----------|
| 1 | POST initialize to /mcp | Session ID returned, server info correct |
| 2 | POST tools/list | All tools listed (honeypot + legit) |
| 3 | POST tools/call (get_aws_credentials) | Fake AWS credentials returned |
| 4 | POST resources/list | All resources listed |
| 5 | POST resources/read (file:///app/.env) | Fake .env content returned |
| 6 | POST prompts/list | All prompts listed |
| 7 | DELETE session | Session closed |
| 8 | Disable MCP feature flag | /mcp returns 404 |
