# Admin Panel UI/UX Refactoring Plan

**Author:** Senior Product Management
**Date:** 2026-02-24
**Status:** Ready for Implementation
**Scope:** Full admin panel restructuring (`/admin` on dashboard port, default 8766)

---

## 1. Executive Summary

### What is wrong with the current UI organization

The admin panel (`admin_html.go`) currently presents 9 top-level tabs: Dashboard, Sessions, Traffic, Controls, Request Log, Vulnerabilities, Scanner, Proxy, and Replay. This flat structure has three critical usability failures:

1. **No conceptual grouping around operational modes.** The Glitch Web Server operates in three distinct modes -- Backend (the glitch server itself), Scanner/Client (tools that test the server), and Proxy (a reverse proxy that intercepts traffic). The current UI scatters controls for these modes across unrelated tabs. For example, "Controls" contains backend server toggles (labyrinth, honeypot, error injection) alongside spider config, content themes, and config import/export -- all lumped into one massive scrollable page. A user managing the proxy has no idea that "Controls" also affects backend behavior unless they scroll through 600+ lines of sliders and toggles.

2. **Nightmare mode is invisible as a unified concept.** Nightmare mode exists independently in three places -- scanner profiles (`scanner/config.go` NightmareConfig), proxy modes (`proxy/modes/modes.go` nightmare registry entry), and implicitly in the backend (max error rates + all traps active). But there is no unified nightmare indicator, no global toggle, and no way to see "the entire system is in nightmare mode" at a glance. A security researcher who wants maximum chaos has to manually configure three separate subsystems.

3. **Replay is orphaned.** PCAP replay (`/admin/api/replay/*`) is a client/scanner-mode tool -- it replays captured traffic against the server. But it sits as its own top-level tab with no connection to the Scanner tab. Similarly, the Scanner tab's "Evaluate External Scanners" sub-tab and the "Built-in Scanner" sub-tab were recently redesigned (see `docs/scanner_redesign.md`) but PCAP replay was not integrated.

### What the new organization should be

Replace the 9 flat tabs with 5 sections organized around operational intent:

```
+---------------------------------------------------------------+
| GLITCH ADMIN PANEL                                            |
| [Dashboard] [Server] [Scanner] [Proxy] [Settings]            |
+---------------------------------------------------------------+
```

- **Dashboard** -- at-a-glance health across all three modes, real-time metrics, nightmare mode indicator
- **Server** (Backend Mode) -- all controls for the glitch server: features, errors, content, labyrinth, vulnerabilities, spider, adaptive, fingerprinting
- **Scanner** (Client Mode) -- built-in scanner, external scanner evaluation, PCAP replay
- **Proxy** (Proxy Mode) -- proxy configuration, WAF, chaos injection, live traffic monitoring
- **Settings** -- admin password, config import/export, theme, global preferences

### Why this restructuring makes the product more usable

- **Mental model alignment.** Users think in terms of "what am I doing?" -- running the server, testing it, proxying traffic, or configuring global settings. The new structure maps directly to these mental models.
- **Nightmare mode surfaces as a first-class feature.** A persistent indicator in the header and per-mode toggles make nightmare state immediately visible.
- **Reduced cognitive load.** The current "Controls" tab has 21 feature toggles, 16 sliders, 30 error weight controls, 8 page type controls, 5 spider sliders, 4 content dropdowns, and import/export -- all on one page. Breaking this into Server sub-sections (Errors, Content, Labyrinth, Fingerprinting, etc.) makes each section scannable.
- **Feature discoverability.** PCAP replay moves from an orphaned tab into Scanner mode where it logically belongs. Vulnerability controls move from a separate tab into Server mode alongside the features that generate them.

---

## 2. Information Architecture

### Top-level navigation

```
Dashboard  |  Server  |  Scanner  |  Proxy  |  Settings
```

Each top-level tab contains sub-sections (rendered as collapsible sections or inner tabs). The top-level tabs use hash routing (`#dashboard`, `#server`, `#scanner`, `#proxy`, `#settings`) for deep linking.

### What goes in each section

#### Dashboard
- System health cards (uptime, total requests, error rate, active connections, unique clients)
- Mode status indicators (Server: running/nightmare, Scanner: idle/scanning, Proxy: mode name)
- Nightmare mode global indicator + toggle
- Throughput sparkline (last 60s)
- Connected clients summary (top 10)
- Recent requests (last 30)
- Quick action buttons (e.g., "Enable Nightmare", "Run Quick Scan", "View Proxy Traffic")

#### Server (Backend Mode)
- **Feature Toggles** -- the 21 on/off switches (labyrinth, error_inject, captcha, honeypot, vuln, etc.)
- **Error Configuration** -- error rate multiplier, HTTP error weights, TCP/network error weights
- **Content & Presentation** -- page type distribution, honeypot style, framework emulation, content theme, content cache TTL
- **Labyrinth** -- depth, link density, adaptive labyrinth paths
- **Adaptive Behavior** -- interval, aggressive RPS threshold, blocking config
- **Traps & Detection** -- captcha threshold, cookie traps, JS traps, bot detection threshold, random blocking
- **Vulnerabilities** -- vulnerability group toggles, category toggles, severity breakdown, endpoint table
- **Spider & Crawl Data** -- sitemap/robots/favicon/meta error rates
- **Sessions & Clients** -- active sessions table, client detail view, behavior overrides
- **Request Log** -- full request log with filtering
- **Traffic Analytics** -- status code distribution, response type distribution, top paths, top UAs

#### Scanner (Client Mode)
- **Evaluate External Scanners** (sub-tab) -- profile banner, launch external scanner, upload & grade, comparison report, multi-scanner comparison, evaluation history
- **Built-in Scanner** (sub-tab) -- profile selection, module selection, run controls, results, scan history
- **PCAP Replay** (sub-tab) -- upload/fetch capture files, file browser, metadata viewer, playback controls, playback status

#### Proxy (Proxy Mode)
- **Status** -- current mode, pipeline stats, connection info
- **Mode Selection** -- 5 mode radio cards (transparent, waf, chaos, gateway, nightmare)
- **WAF Configuration** -- block action, rate limit, detection stats
- **Chaos Configuration** -- latency/corrupt/drop/reset probability sliders
- **Pipeline Monitor** -- interceptor table, live traffic stats

#### Settings
- **Admin Password** -- change password (currently auto-generated, logged to stderr)
- **Configuration Import/Export** -- export/import JSON config
- **Recording Format** -- JSONL vs PCAP (currently in Controls tab)
- **Theme** -- dark theme is the only option now, but placeholder for future
- **About** -- server version, port info, uptime

### Feature migration table

| Current Location | Feature | New Location |
|---|---|---|
| Dashboard tab | Metric cards | Dashboard |
| Dashboard tab | Throughput sparkline | Dashboard |
| Dashboard tab | Connected clients | Dashboard |
| Dashboard tab | Recent requests | Dashboard |
| Sessions tab | Active client sessions | Server > Sessions & Clients |
| Sessions tab | Client detail + override | Server > Sessions & Clients |
| Traffic tab | Overview cards | Server > Traffic Analytics |
| Traffic tab | Sparkline | Server > Traffic Analytics |
| Traffic tab | Status code pie chart | Server > Traffic Analytics |
| Traffic tab | Response type bars | Server > Traffic Analytics |
| Traffic tab | Top paths | Server > Traffic Analytics |
| Traffic tab | Top user agents | Server > Traffic Analytics |
| Controls tab | Feature toggles (21) | Server > Feature Toggles |
| Controls tab | Behavior tuning sliders (11) | Server > Error Config / Labyrinth / Adaptive / Traps |
| Controls tab | HTTP error weights | Server > Error Configuration |
| Controls tab | TCP error weights | Server > Error Configuration |
| Controls tab | Page type distribution | Server > Content & Presentation |
| Controls tab | Response & content settings (4 dropdowns) | Server > Content & Presentation |
| Controls tab | Advanced tuning sliders (5) | Server > Traps / Adaptive / Labyrinth (split by domain) |
| Controls tab | Spider & crawl data | Server > Spider & Crawl Data |
| Controls tab | Config import/export | Settings |
| Request Log tab | Request log + filter | Server > Request Log |
| Vulnerabilities tab | Profile overview | Server > Vulnerabilities |
| Vulnerabilities tab | Group toggles | Server > Vulnerabilities |
| Vulnerabilities tab | Severity badges | Server > Vulnerabilities |
| Vulnerabilities tab | Endpoint table | Server > Vulnerabilities |
| Scanner tab > Evaluate External | All sections | Scanner > Evaluate External Scanners |
| Scanner tab > Built-in Scanner | All sections | Scanner > Built-in Scanner |
| Proxy tab | All sections | Proxy (unchanged structure) |
| Replay tab | All sections | Scanner > PCAP Replay |
| (new) | Nightmare mode indicator | Dashboard header bar |
| (new) | Admin password change | Settings |

---

## 3. Dashboard Design

### Metrics and status indicators for all 3 modes

```
+-----------------------------------------------------------------------+
| // GLITCH ADMIN PANEL          [NIGHTMARE MODE: OFF]     uptime: 2h3m |
+-----------------------------------------------------------------------+
|  [Dashboard]  [Server]  [Scanner]  [Proxy]  [Settings]                |
+-----------------------------------------------------------------------+
|                                                                       |
|  +-------------------+  +-------------------+  +-------------------+  |
|  | SERVER            |  | SCANNER           |  | PROXY             |  |
|  | Status: RUNNING   |  | Status: IDLE      |  | Mode: TRANSPARENT |  |
|  | Requests: 14,232  |  | Last scan: 3m ago |  | Forwarded: 0      |  |
|  | Error rate: 12.4% |  | Grade: B+         |  | Blocked: 0        |  |
|  | Clients: 7        |  | Findings: 42      |  | Chaos: OFF        |  |
|  +-------------------+  +-------------------+  +-------------------+  |
|                                                                       |
|  +-- THROUGHPUT (last 60s) ----------------------------------------+ |
|  | [sparkline bars]                                                 | |
|  +------------------------------------------------------------------+ |
|                                                                       |
|  +-- CONNECTED CLIENTS ----------+  +-- RECENT REQUESTS -----------+ |
|  | Client    Reqs  R/s  Mode     |  | Time   Client Path  Status   | |
|  | a3f2...   342   2.1  normal   |  | 14:32  a3f2  /api   200     | |
|  | b7c1...   128   0.8  aggress  |  | 14:32  b7c1  /vuln  500     | |
|  | ...                           |  | ...                          | |
|  +-------------------------------+  +------------------------------+ |
|                                                                       |
|  QUICK ACTIONS:                                                       |
|  [Enable Nightmare]  [Run Quick Scan]  [View Server Logs]             |
+-----------------------------------------------------------------------+
```

### Real-time data feeds

| Data Source | API Endpoint | Poll Interval | Displayed Where |
|---|---|---|---|
| Server metrics | `GET /api/metrics` | 3s | Dashboard server card |
| Time series | `GET /api/timeseries` | 5s | Sparkline |
| Client list | `GET /api/clients` | 5s | Connected clients table |
| Recent requests | `GET /api/recent` | 3s | Recent requests table |
| Scanner status | `GET /admin/api/scanner/builtin/status` | 3s (only if running) | Scanner card |
| Proxy status | `GET /admin/api/proxy/status` | 5s | Proxy card |

### Quick actions from the dashboard

| Action | Effect | API Call |
|---|---|---|
| Enable Nightmare | Activates nightmare across all modes (see Section 8) | Multiple POSTs |
| Run Quick Scan | Switches to Scanner tab, starts compliance scan | Navigate + POST `/admin/api/scanner/builtin/run` |
| View Server Logs | Switches to Server > Request Log | Navigate only |

### Nightmare mode indicator

A persistent bar in the page header, visible on all tabs:

- **Off state:** Small text: `NIGHTMARE: OFF` in muted gray
- **On state:** Full-width banner with red pulsing glow: `NIGHTMARE MODE ACTIVE` with per-mode status icons

This is detailed in Section 8.

---

## 4. Backend/Server Mode

### Sub-section organization

The Server tab uses collapsible sections (not inner tabs) since users often need to see multiple subsystem states simultaneously. Each section is a `.section` card with a clickable header that collapses/expands the body.

```
SERVER MODE
|
+-- Feature Toggles         [21 toggle switches in a grid]
+-- Error Configuration      [error multiplier + HTTP/TCP weight grids]
+-- Content & Presentation   [page types, theme, framework, honeypot style]
+-- Labyrinth                [depth, link density, adaptive paths]
+-- Adaptive Behavior        [interval, aggressive RPS, blocking]
+-- Traps & Detection        [captcha, cookie traps, JS traps, bot score]
+-- Vulnerabilities          [groups, categories, endpoints table]
+-- Spider & Crawl Data      [error rate sliders for sitemap/robots/etc]
+-- Sessions & Clients       [client table, detail view, overrides]
+-- Request Log              [filterable log table]
+-- Traffic Analytics        [pie chart, bars, top paths, top UAs]
```

### Feature Toggles section

Exactly the current toggle grid from the Controls tab. All 21 features:

```
labyrinth, error_inject, captcha, honeypot, vuln, analytics, cdn, oauth,
header_corrupt, cookie_traps, js_traps, bot_detection, random_blocking,
framework_emul, search, email, i18n, recorder, websocket, privacy,
health, spider
```

API: `GET/POST /admin/api/features`

### Error Configuration section

Combines:
- Error Rate Multiplier slider (from Controls > Behavior Tuning)
- HTTP Error Weights grid (from Controls > HTTP Error Weights)
- TCP/Network Error Weights grid (from Controls > TCP/Network Error Weights)
- "Reset All to Default" button

API: `GET/POST /admin/api/config` (error_rate_multiplier), `GET/POST /admin/api/error-weights`

### Content & Presentation section

Combines:
- Page Type Distribution grid (from Controls > Page Type Distribution)
- Honeypot Response Style dropdown
- Active Framework Emulation dropdown
- Content Theme dropdown
- Content Cache TTL slider

API: `GET/POST /admin/api/config`, `GET/POST /admin/api/page-type-weights`

### Labyrinth section

Groups:
- Max Labyrinth Depth slider (1-100)
- Labyrinth Link Density slider (1-20)
- Adaptive Labyrinth Paths slider (1-50)

API: `POST /admin/api/config` with keys `max_labyrinth_depth`, `labyrinth_link_density`, `adaptive_labyrinth_paths`

### Adaptive Behavior section

Groups:
- Adaptive Re-eval Interval slider (5-300s)
- Adaptive Aggressive RPS threshold slider (1-100)
- Blocking enabled toggle + chance slider + duration slider

API: `POST /admin/api/config`, `GET/POST /admin/api/blocking`

### Traps & Detection section

Groups:
- CAPTCHA Trigger Threshold slider
- Cookie Trap Frequency slider (0-20)
- JS Trap Difficulty slider (0-5)
- Bot Score Threshold slider (0-100)
- Random Block Chance slider (0-1)
- Block Duration slider (1-3600s)
- Header Corruption Level slider (0-4)
- Delay Min/Max sliders

API: `POST /admin/api/config`

### Vulnerabilities section

The entire current Vulnerabilities tab moves here:
- Vulnerability Profile Overview cards (total vulns, total endpoints, groups active)
- Group Toggles (9 groups: owasp, api_security, advanced, modern, infrastructure, iot_desktop, mobile_privacy, specialized, dashboard)
- Severity Breakdown badges
- Searchable endpoint table with per-category toggles

API: `GET /admin/api/scanner/profile`, `GET/POST /admin/api/vulns`, `POST /admin/api/vulns/group`

### Spider & Crawl Data section

The spider config sliders:
- Sitemap Error Rate (0-1)
- Sitemap Gzip Error Rate (0-1)
- Favicon Error Rate (0-1)
- Robots.txt Error Rate (0-1)
- Meta Files Error Rate (0-1)

API: `GET/POST /admin/api/spider`

### Sessions & Clients section

The entire current Sessions tab:
- Active Client Sessions table (client ID, requests, req/s, errors, paths, lab depth, mode, last seen, actions)
- Client Detail panel (cards + path breakdown + behavior override dropdown)

API: `GET /api/clients`, `GET /admin/api/client/{id}`, `POST /admin/api/override`

### Request Log section

The entire current Request Log tab:
- Filter text input
- Scrollable table (time, client, method, path, status, latency, type, mode, UA)

API: `GET /admin/api/log?limit=200`

### Traffic Analytics section

The entire current Traffic tab minus the top overview cards (those are on the Dashboard now):
- Status Code Distribution pie chart
- Response Type Distribution bars
- Top 10 Paths bar chart
- Top 10 User Agents bar chart

API: `GET /admin/api/overview`

### Nightmare mode for backend

When backend nightmare is activated, the following changes apply:

| Parameter | Normal Default | Nightmare Value |
|---|---|---|
| error_rate_multiplier | 1.0 | 5.0 |
| header_corrupt_level | 1 | 4 |
| block_chance | 0.02 | 0.15 |
| delay_min_ms | 0 | 500 |
| delay_max_ms | 0 | 10000 |
| max_labyrinth_depth | 50 | 100 |
| labyrinth_link_density | 8 | 20 |
| captcha_trigger_thresh | 100 | 10 |
| cookie_trap_frequency | 3 | 15 |
| js_trap_difficulty | 2 | 5 |
| bot_score_threshold | 60 | 20 |
| All features | (varies) | All ON |

API implementation: `POST /admin/api/nightmare/server` applies all nightmare values. `DELETE /admin/api/nightmare/server` restores previous config (snapshotted before activation).

### Status indicators

At the top of the Server tab, a status bar:

```
+-----------------------------------------------------------------------+
| SERVER STATUS: RUNNING     Error Rate: 12.4%    Clients: 7            |
| Features: 21/21 enabled   Nightmare: OFF                              |
+-----------------------------------------------------------------------+
```

---

## 5. Scanner/Client Mode

### Sub-tab navigation within Scanner

```
Scanner Tab
  |
  +-- [Evaluate External Scanners]  [Built-in Scanner]  [PCAP Replay]
```

Three inner sub-tabs (not collapsible sections, because these are distinct workflows).

### Built-in Scanner controls

Unchanged from `docs/scanner_redesign.md` Section 4. Key elements:

- **Profile selection:** 4 radio cards (compliance, aggressive, stealth, nightmare)
  - Compliance: 5 workers, 20 req/s, no evasion
  - Aggressive: 30 workers, 300 req/s, no evasion
  - Stealth: 3 workers, 10 req/s, advanced evasion
  - Nightmare: 50 workers, 500 req/s, nightmare evasion

- **Module selection:** 5 checkboxes (owasp, injection, fuzzing, protocol, auth)
- **Target input:** defaults to `http://localhost:8765`
- **Run/Stop controls** with progress bar
- **Results:** severity cards, coverage-by-category table, resilience score, findings table
- **History:** timestamped table of past runs

API endpoints:
- `POST /admin/api/scanner/builtin/run`
- `GET /admin/api/scanner/builtin/status`
- `POST /admin/api/scanner/builtin/stop`
- `GET /admin/api/scanner/builtin/results`
- `GET /admin/api/scanner/builtin/history`
- `GET /admin/api/scanner/builtin/modules`

### External scanner evaluation

Unchanged from `docs/scanner_redesign.md` Section 3. Key elements:

- Auto-loaded vulnerability profile banner
- Scanner cards (nuclei, nikto, nmap, ffuf, wapiti) with install status
- Upload & Grade textarea + file input
- Comparison Report (grade, detection rate, false pos/neg tables)
- Multi-Scanner Comparison
- Evaluation History with scanner filter

API endpoints:
- `GET /admin/api/scanner/profile`
- `POST /admin/api/scanner/run`
- `GET /admin/api/scanner/results`
- `POST /admin/api/scanner/stop`
- `POST /admin/api/scanner/compare`
- `POST /admin/api/scanner/multi-compare`
- `GET /admin/api/scanner/history`
- `GET /admin/api/scanner/baseline`

### PCAP Replay (moved from standalone Replay tab)

The entire current Replay tab moves here as a third sub-tab. This is a natural fit because PCAP replay is a client-side tool that sends traffic to the server -- it is conceptually a scanner/client activity.

Structure (unchanged from current replay tab):

- **Upload Capture** -- file upload + URL fetch + cleanup
- **Capture Files** -- file browser table with Load action
- **Capture Metadata** -- packet counts, time span, methods, top paths
- **Replay Target** -- target URL input
- **Playback Controls** -- timing mode, speed, filter, loop, play/stop
- **Playback Status** -- state badge, progress bar, stats cards

API endpoints (all unchanged):
- `GET /admin/api/replay/files`
- `GET /admin/api/replay/status`
- `POST /admin/api/replay/load`
- `POST /admin/api/replay/start`
- `POST /admin/api/replay/stop`
- `POST /admin/api/replay/upload`
- `POST /admin/api/replay/fetch-url`
- `GET /admin/api/replay/metadata`
- `POST /admin/api/replay/cleanup`

### Nightmare mode for scanner

When scanner nightmare is activated:
- Built-in scanner profile is forced to "nightmare" (50 workers, 500 req/s, nightmare evasion)
- All 5 modules are selected
- The "Run Glitch Scanner" button changes to red with warning text

No API change needed -- this is a UI-level preset that sets `profile: "nightmare"` in the run request.

### Status indicators

At the top of the Scanner tab:

```
+-----------------------------------------------------------------------+
| SCANNER STATUS                                                        |
| Built-in: IDLE    External: 0 running    Replay: STOPPED              |
| Last scan: compliance @ 14:32 (42 findings, 78% coverage)             |
+-----------------------------------------------------------------------+
```

---

## 6. Proxy Mode

### Structure (largely unchanged)

```
Proxy Tab
|
+-- Status Cards (mode badge, pipeline stats, connection counts)
+-- Mode Selection (5 radio cards)
+-- WAF Configuration (block action, rate limit, stats)
+-- Chaos Configuration (4 probability sliders)
+-- Connection Info (active conns, forwarded, blocked)
+-- Pipeline Monitor (interceptor table)
```

### Proxy configuration

Upstream target and listen address inputs (currently in the Proxy tab, unchanged).

API: `GET /admin/api/proxy/status`, `POST /admin/api/proxy/mode`

### WAF settings

Shown/hidden based on current mode. Visible when mode is `waf`, `gateway`, or `nightmare`.

- Block Action dropdown: block, log, challenge, reject, tarpit, redirect
- Rate Limit input: requests/second
- Detection stats cards: detections, rate limited

### Chaos controls

4 sliders, same as current:
- Latency Probability (0-1)
- Corruption Probability (0-1)
- Drop Probability (0-1)
- Reset Probability (0-1)

These are read-only when mode is `transparent` (all zeroed). They auto-populate from mode defaults when switching modes.

### Nightmare mode for proxy

When proxy nightmare is activated:

| Parameter | Nightmare Value |
|---|---|
| mode | nightmare |
| latency_prob | 0.6 |
| corrupt_prob | 0.3 |
| drop_prob | 0.15 |
| reset_prob | 0.1 |
| waf_enabled | true |
| waf_block_action | block |
| waf_rate_limit_rps | 20 |

These values come directly from `proxy/modes/modes.go` nightmare configuration.

API: `POST /admin/api/proxy/mode` with `{"mode":"nightmare"}`

### Live traffic monitoring

The Pipeline Stats table shows per-interceptor metrics. When nightmare mode is active, the table header gets a red glow to indicate elevated chaos.

### Status indicators

```
+-----------------------------------------------------------------------+
| PROXY STATUS                                                          |
| Mode: [NIGHTMARE] (red pulsing badge)                                 |
| Processed: 1,234    Blocked: 89    Modified: 456                      |
+-----------------------------------------------------------------------+
```

---

## 7. Settings

### Global settings

Settings is a simple tab containing items that do not belong in any mode-specific context.

```
Settings Tab
|
+-- Admin Authentication
|     Password: [*********]  [Change Password]
|     Current session expires: 2026-02-24 22:30
|
+-- Configuration Management
|     [Export Config]  [Import Config]
|     Status: "Config exported at 14:32"
|
+-- Traffic Recording
|     Format: [JSONL v] / [PCAP]
|     (affects recorder subsystem output format)
|
+-- Server Info
|     Server Port: 8765
|     Dashboard Port: 8766
|     Go Version: 1.24
|     Uptime: 2h 14m
```

### What does NOT belong in Settings

- Feature toggles (Server-specific)
- Proxy mode (Proxy-specific)
- Scanner profiles (Scanner-specific)
- Vulnerability config (Server-specific)
- Error weights (Server-specific)

---

## 8. Nightmare Mode

### Concept

Nightmare mode is a named extreme-chaos state that can be applied independently to each of the three operational modes. It represents "maximum unreliability, maximum chaos, everything turned up to 11."

### Global vs per-mode toggle

**Both.** The system supports:

1. **Per-mode toggles** -- each mode (Server, Scanner, Proxy) has its own nightmare on/off. These are independent.
2. **Global toggle** -- the header bar "NIGHTMARE MODE" button activates nightmare on ALL three modes simultaneously. Deactivating it restores the previous state for each mode.

### Implementation

A new `NightmareState` struct in `admin.go`:

```go
type NightmareState struct {
    mu              sync.RWMutex
    ServerActive    bool
    ScannerActive   bool
    ProxyActive     bool
    PreviousConfig  *AdminConfig    // snapshot before server nightmare
    PreviousFeatures map[string]bool // snapshot before server nightmare
}
```

New API endpoints:

| Method | Path | Body | Effect |
|---|---|---|---|
| `GET` | `/admin/api/nightmare` | -- | Returns `{server, scanner, proxy}` booleans |
| `POST` | `/admin/api/nightmare` | `{"mode":"all","enabled":true}` | Toggles all modes |
| `POST` | `/admin/api/nightmare` | `{"mode":"server","enabled":true}` | Toggles server nightmare |
| `POST` | `/admin/api/nightmare` | `{"mode":"scanner","enabled":true}` | Toggles scanner nightmare |
| `POST` | `/admin/api/nightmare` | `{"mode":"proxy","enabled":true}` | Toggles proxy nightmare |

### What changes in each mode when nightmare is activated

**Server nightmare:**
- All 21 feature flags set to `true`
- `error_rate_multiplier` -> 5.0
- `header_corrupt_level` -> 4 (chaos)
- `block_chance` -> 0.15
- `delay_min_ms` -> 500, `delay_max_ms` -> 10000
- `max_labyrinth_depth` -> 100
- `labyrinth_link_density` -> 20
- `captcha_trigger_thresh` -> 10
- `cookie_trap_frequency` -> 15
- `js_trap_difficulty` -> 5
- `bot_score_threshold` -> 20
- `adaptive_aggressive_rps` -> 2
- All vulnerability groups enabled

**Scanner nightmare:**
- Built-in scanner profile locked to "nightmare" (50 workers, 500 req/s, nightmare evasion mode)
- All 5 attack modules force-selected
- UI prevents changing profile/modules while nightmare is active (grayed out with tooltip)

**Proxy nightmare:**
- Proxy mode set to "nightmare"
- Chaos config: latency 0.6, corrupt 0.3, drop 0.15, reset 0.1
- WAF enabled with aggressive blocking (rate limit 20 rps)

### Visual treatment

**Global nightmare indicator (header bar):**

```
Normal state:
+-----------------------------------------------------------------------+
| // GLITCH ADMIN PANEL                              NIGHTMARE: OFF     |
+-----------------------------------------------------------------------+

Nightmare state (any mode):
+-----------------------------------------------------------------------+
| // GLITCH ADMIN PANEL      [!!!] NIGHTMARE ACTIVE: Server, Proxy      |
+-----------------------------------------------------------------------+
```

The nightmare banner uses:
- Background: `#1a0000` (very dark red)
- Border: `1px solid #ff000066`
- Text color: `#ff4444`
- Pulsing glow animation: `box-shadow: 0 0 20px #ff000033` with 2s pulse
- The specific active modes are listed (e.g., "Server, Proxy" means scanner is not in nightmare)

**Per-mode nightmare indicators:**

Each mode tab shows a small badge next to its name when nightmare is active for that mode:

```
[Server] [Scanner] [Proxy !!!]
```

The `!!!` badge uses `color: #ff4444; font-weight: bold`.

**Nightmare button styling:**

- Color scheme: Red/black gradient
- Text: Bold, uppercase
- Hover: Brighter red glow
- Active state: Pulsing border

```css
.nightmare-btn {
    background: linear-gradient(135deg, #1a0000, #330000);
    color: #ff4444;
    border: 1px solid #ff000044;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.nightmare-btn:hover {
    background: linear-gradient(135deg, #2a0000, #440000);
    box-shadow: 0 0 12px #ff000033;
}
.nightmare-btn.active {
    background: linear-gradient(135deg, #330000, #550000);
    border-color: #ff0000;
    animation: nightmare-pulse 2s infinite;
}
@keyframes nightmare-pulse {
    0%, 100% { box-shadow: 0 0 8px #ff000033; }
    50% { box-shadow: 0 0 20px #ff000066; }
}
```

---

## 9. CSS/Visual Design System

### Color scheme per mode

| Mode | Primary Color | Accent | Border | Badge BG |
|---|---|---|---|---|
| Dashboard | `#00ffcc` (cyan) | `#00ff88` (green) | `#00ff8833` | `#00ffcc22` |
| Server | `#00ff88` (green) | `#00ccaa` (teal) | `#00ff8833` | `#00ff8822` |
| Scanner | `#00ccff` (cyan-blue) | `#0088cc` (steel blue) | `#00ccff33` | `#00ccff22` |
| Proxy | `#ffaa00` (orange) | `#ff8800` (dark orange) | `#ffaa0033` | `#ffaa0022` |
| Settings | `#888888` (gray) | `#666666` | `#88888833` | `#88888822` |
| Nightmare | `#ff4444` (red) | `#ff0000` | `#ff000044` | `#ff444422` |

### How to visually distinguish which mode the user is in

1. **Tab highlight color** changes per mode (green for server, cyan-blue for scanner, orange for proxy)
2. **Section header (`h2`)** color matches the mode color
3. **Active tab** has a 2px bottom border in the mode color
4. **Page background** subtly shifts: Server gets a very faint green tint (`#0a0f0a`), Scanner gets blue tint (`#0a0a0f`), Proxy gets orange tint (`#0f0a0a`), Nightmare overlays a red tint on everything

### CSS for mode-aware tab styling

```css
/* Tab colors per mode */
.tab[data-mode="server"].active { color: #00ff88; border-color: #00ff8844; }
.tab[data-mode="scanner"].active { color: #00ccff; border-color: #00ccff44; }
.tab[data-mode="proxy"].active { color: #ffaa00; border-color: #ffaa0044; }
.tab[data-mode="settings"].active { color: #888; border-color: #88888844; }

/* Mode-specific section headers */
#panel-server h2 { color: #00ccaa; }
#panel-scanner h2 { color: #0099cc; }
#panel-proxy h2 { color: #cc8800; }
#panel-settings h2 { color: #888; }

/* Nightmare overlay */
body.nightmare-active {
    background: #0a0000;
}
body.nightmare-active .tabs {
    border-bottom-color: #ff000033;
}
```

### Card / section / grid layout patterns

The existing layout system is well-designed and should be preserved:

- `.grid` for metric cards (auto-fit, minmax 180px)
- `.section` for content groups (dark bg, border, rounded corners)
- `.tbl-scroll` for scrollable tables (max-height with overflow)
- `.toggle-grid` for feature toggle switches (auto-fit, minmax 220px)

New additions:

```css
/* Collapsible server subsections */
.server-section-header {
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 18px;
    background: #111;
    border: 1px solid #00ff8822;
    border-radius: 8px;
    margin-bottom: 4px;
    transition: all 0.2s;
}
.server-section-header:hover {
    background: #1a1a1a;
    border-color: #00ff8844;
}
.server-section-header .chevron {
    transition: transform 0.2s;
    color: #555;
}
.server-section-header.open .chevron {
    transform: rotate(90deg);
}
.server-section-body {
    display: none;
    padding: 18px;
    background: #111;
    border: 1px solid #00ff8822;
    border-top: none;
    border-radius: 0 0 8px 8px;
    margin-bottom: 18px;
}
.server-section-body.open {
    display: block;
}

/* Mode status cards on dashboard */
.mode-card {
    background: #111;
    border: 1px solid #00ff8833;
    border-radius: 8px;
    padding: 18px;
    min-height: 140px;
}
.mode-card.nightmare {
    border-color: #ff000044;
    background: #110000;
    box-shadow: 0 0 12px #ff000011;
}

/* Scanner sub-tab colors */
.scanner-subtab-btn.active[data-subtab="evaluate"] {
    color: #00ccff;
    border-color: #00ccff44;
}
.scanner-subtab-btn.active[data-subtab="builtin"] {
    color: #00ccaa;
    border-color: #00ccaa44;
}
.scanner-subtab-btn.active[data-subtab="replay"] {
    color: #aa88ff;
    border-color: #aa88ff44;
}
```

---

## 10. Implementation Plan

### Phase 1: Navigation restructure and Dashboard (Estimated: 2-3 days)

**Goal:** Replace 9 tabs with 5 tabs. Move content without changing functionality.

**Changes:**

1. `admin_html.go` -- Replace tab bar:
   - Remove: Sessions, Traffic, Controls, Request Log, Vulnerabilities, Replay tabs
   - Keep: Dashboard, Scanner, Proxy tabs
   - Add: Server, Settings tabs
   - Update `showTab()` JS function

2. `admin_html.go` -- Create Server tab panel:
   - Move Sessions HTML into Server > Sessions & Clients section
   - Move Traffic HTML into Server > Traffic Analytics section
   - Move Controls HTML into Server sub-sections (Feature Toggles, Error Config, Content, Labyrinth, Adaptive, Traps)
   - Move Request Log HTML into Server > Request Log section
   - Move Vulnerabilities HTML into Server > Vulnerabilities section
   - Wrap each sub-section in collapsible headers

3. `admin_html.go` -- Create Settings tab panel:
   - Move Config Import/Export from Controls
   - Move Recorder Format dropdown from Controls
   - Add placeholder for password change

4. `admin_html.go` -- Add mode status cards to Dashboard

5. `admin_html.go` -- Move Replay tab content into Scanner as third sub-tab

**JS changes:**
- Update `showTab()` for new tab names
- Add `toggleServerSection(name)` for collapsible sections
- Update `switchScannerSubtab()` to handle 3 sub-tabs (eval, builtin, replay)
- Update refresh functions to work with new panel IDs

**Risk areas:**
- Element ID references in JS must be updated carefully. The current JS uses many `getElementById` calls that reference elements by their panel location.
- The `refreshDashboard()`, `refreshSessions()`, `refreshTraffic()`, `refreshControls()`, `refreshLog()`, `refreshVulns()`, `refreshProxy()`, and `refreshReplay()` functions currently assume their elements are in specific panels. They need to work regardless of which section is collapsed.

**Files changed:**
- `internal/dashboard/admin_html.go` (HTML structure + JS)
- No backend changes needed

### Phase 2: Nightmare mode system (Estimated: 2-3 days)

**Goal:** Implement nightmare as a first-class cross-mode concept.

**Changes:**

1. `admin.go` -- Add `NightmareState` struct and global singleton
2. `admin_routes.go` -- Add nightmare API endpoints:
   - `GET /admin/api/nightmare`
   - `POST /admin/api/nightmare`
3. `admin_html.go` -- Add nightmare header indicator
4. `admin_html.go` -- Add nightmare toggle buttons in Dashboard and per-mode tabs
5. `admin_html.go` -- Add nightmare CSS (red theme, pulse animation)
6. `admin_html.go` -- JS: `toggleNightmare(mode, enabled)` function, status polling

**Risk areas:**
- Server nightmare must snapshot current config before applying nightmare values, and restore on deactivation. Race conditions with concurrent config changes.
- Proxy nightmare calls `SetMode("nightmare")` which is straightforward.
- Scanner nightmare is UI-only (forces profile selection).

**Files changed:**
- `internal/dashboard/admin.go` (NightmareState struct)
- `internal/dashboard/admin_routes.go` (nightmare API handlers)
- `internal/dashboard/admin_html.go` (UI + JS)

### Phase 3: Visual design system (Estimated: 1-2 days)

**Goal:** Apply per-mode color coding, nightmare visual treatment, and improved layout.

**Changes:**

1. `admin_html.go` CSS -- Add mode-specific colors for tab highlights, section headers, and borders
2. `admin_html.go` CSS -- Add nightmare visual treatment (red overlay, pulsing glow, dark red backgrounds)
3. `admin_html.go` CSS -- Add collapsible section styles for Server tab
4. `admin_html.go` CSS -- Add `.mode-card` styles for Dashboard
5. `admin_html.go` JS -- Add `data-mode` attributes to tabs for CSS targeting
6. `admin_html.go` JS -- Add `body.nightmare-active` class toggle

**Risk areas:**
- CSS specificity conflicts with existing styles. The current stylesheet is ~500 lines; changes must be additive, not breaking.
- Dark red nightmare tint must not make text unreadable. Test contrast ratios.

**Files changed:**
- `internal/dashboard/admin_html.go` (CSS + HTML attributes)

### Phase 4: Settings tab and admin password (Estimated: 1 day)

**Goal:** Implement Settings tab with password change and server info.

**Changes:**

1. `admin_routes.go` -- Add password change endpoint: `POST /admin/api/password`
2. `auth.go` -- Add `ChangePassword(old, new string) error` function
3. `admin_html.go` -- Settings tab HTML with password form, server info
4. `admin_html.go` -- JS for password change flow

**Risk areas:**
- Password change must validate old password first
- Must not break existing session auth

**Files changed:**
- `internal/dashboard/auth.go`
- `internal/dashboard/admin_routes.go`
- `internal/dashboard/admin_html.go`

### Phase 5: Polish and testing (Estimated: 1-2 days)

**Goal:** Fix edge cases, test all workflows, ensure no regressions.

- Test all API endpoints still work
- Test hash routing (`#server`, `#scanner`, etc.)
- Test nightmare mode activation/deactivation cycle
- Test config export/import still works
- Test scanner workflows (both sub-tabs)
- Test replay within Scanner tab
- Test all collapsible sections expand/collapse correctly
- Test mobile responsiveness

**Total estimated scope: 7-11 days**

---

## 11. Acceptance Criteria

### Navigation & Structure

**AC-1:** The admin panel has exactly 5 top-level tabs: Dashboard, Server, Scanner, Proxy, Settings. No other top-level tabs exist.

**AC-2:** Clicking each tab shows only that tab's content. URL hash updates to `#dashboard`, `#server`, `#scanner`, `#proxy`, or `#settings`. Loading a URL with a hash directly navigates to that tab.

**AC-3:** The Server tab contains collapsible sections for: Feature Toggles, Error Configuration, Content & Presentation, Labyrinth, Adaptive Behavior, Traps & Detection, Vulnerabilities, Spider & Crawl Data, Sessions & Clients, Request Log, and Traffic Analytics. Each section has a clickable header that expands/collapses its content.

**AC-4:** The Scanner tab contains exactly 3 sub-tabs: "Evaluate External Scanners", "Built-in Scanner", and "PCAP Replay". Clicking each sub-tab shows only its content and hides the others.

**AC-5:** The Settings tab contains: admin password change form, configuration import/export buttons, traffic recording format selector, and server info display.

### Dashboard

**AC-6:** The Dashboard displays 3 mode status cards (Server, Scanner, Proxy) showing current state, key metric, and mode-specific info (e.g., proxy mode name, scanner last run, server error rate).

**AC-7:** The Dashboard shows a throughput sparkline, connected clients table (top 10), and recent requests table (last 30), refreshed every 3-5 seconds.

**AC-8:** The Dashboard has quick action buttons: "Enable Nightmare", "Run Quick Scan", and "View Server Logs" that navigate to the appropriate section.

### Server Mode

**AC-9:** All 21 feature toggles from the original Controls tab appear in Server > Feature Toggles. Each toggle calls `POST /admin/api/features` and shows a toast confirmation.

**AC-10:** All 11 behavior tuning sliders from the original Controls tab appear in their domain-specific Server sub-sections (Error Config, Labyrinth, Adaptive, Traps). Each slider commits its value to `POST /admin/api/config` on change.

**AC-11:** The HTTP Error Weights and TCP Error Weights grids appear in Server > Error Configuration with the same OFF/LOW/MED/HIGH/MAX radio presets and "Reset All to Default" button.

**AC-12:** The Vulnerabilities section shows group toggles, severity badges, and the searchable endpoint table with per-category on/off switches. Data comes from `GET /admin/api/scanner/profile` and `GET /admin/api/vulns`.

**AC-13:** The Sessions & Clients section shows the client table. Clicking a client ID opens the detail panel with behavior override dropdown and apply/clear buttons.

**AC-14:** The Request Log section shows a filterable request log (200 entries) with the same columns as the original Request Log tab.

### Scanner Mode

**AC-15:** The PCAP Replay sub-tab within Scanner contains all functionality from the original Replay tab: upload, URL fetch, file browser, metadata viewer, playback controls (timing, speed, filter, loop), and playback status with progress bar.

**AC-16:** The Evaluate External Scanners and Built-in Scanner sub-tabs retain all functionality described in `docs/scanner_redesign.md` (profile auto-load, scanner cards, upload & grade, comparison report, multi-compare, history, profile selection, module selection, run/stop, results, history).

### Proxy Mode

**AC-17:** The Proxy tab retains all current functionality: mode selection (5 radio cards), WAF configuration (conditionally shown), chaos sliders, connection info cards, and pipeline stats table.

### Nightmare Mode

**AC-18:** A nightmare mode indicator is visible in the page header on all tabs. When any mode is in nightmare state, the indicator shows "NIGHTMARE ACTIVE" with the list of active modes (e.g., "Server, Proxy").

**AC-19:** `GET /admin/api/nightmare` returns `{"server": bool, "scanner": bool, "proxy": bool}` reflecting current nightmare state for each mode.

**AC-20:** `POST /admin/api/nightmare` with `{"mode":"all","enabled":true}` activates nightmare on all 3 modes. Server nightmare applies extreme config values (error_rate_multiplier=5.0, header_corrupt_level=4, etc.). Proxy nightmare sets mode to "nightmare". Scanner nightmare is flagged for UI enforcement.

**AC-21:** `POST /admin/api/nightmare` with `{"mode":"server","enabled":false}` deactivates server nightmare and restores the config snapshot taken before activation.

**AC-22:** When server nightmare is active, the Server tab's status bar shows a red "NIGHTMARE" badge. Feature toggles and sliders are still adjustable (nightmare sets values but does not lock them).

**AC-23:** When scanner nightmare is active, the Built-in Scanner profile selection is forced to "nightmare" and the profile cards for compliance/aggressive/stealth are visually disabled (grayed out with a tooltip: "Nightmare mode is active").

**AC-24:** When proxy nightmare is active, the Proxy tab shows the mode as "NIGHTMARE" with its characteristic red badge and the chaos sliders show the nightmare values.

### Visual Design

**AC-25:** Each top-level tab uses a distinct accent color: Server=green (#00ff88), Scanner=cyan-blue (#00ccff), Proxy=orange (#ffaa00), Settings=gray. The active tab border and section headers match the mode color.

**AC-26:** Nightmare mode applies a dark red visual overlay: body background shifts to #0a0000, the header bar gets a red pulsing glow, and active nightmare tabs show a "!!!" badge.

**AC-27:** The "Enable Nightmare" / "Disable Nightmare" button uses red/black gradient styling that is visually distinct from all other buttons in the UI. When active, the button pulses with a red glow animation.

### Settings

**AC-28:** The Settings > Admin Password section has a form with fields for current password, new password, and confirm new password. Submitting calls `POST /admin/api/password` and shows success/error feedback.

**AC-29:** The Settings > Configuration Management section has Export and Import buttons that call `GET /admin/api/config/export` and `POST /admin/api/config/import` respectively, with the same behavior as the current Controls tab.

### Regression Safety

**AC-30:** All existing API endpoints (`/admin/api/features`, `/admin/api/config`, `/admin/api/overview`, `/admin/api/log`, `/admin/api/blocking`, `/admin/api/override`, `/admin/api/scanner/*`, `/admin/api/proxy/*`, `/admin/api/replay/*`, `/admin/api/vulns`, `/admin/api/error-weights`, `/admin/api/page-type-weights`, `/admin/api/spider`, `/admin/api/config/export`, `/admin/api/config/import`, `/api/metrics`, `/api/clients`, `/api/timeseries`, `/api/recent`, `/api/behaviors`) continue to work without changes to their request/response format.

---

## Appendix A: ASCII Mockup -- Full Dashboard

```
+=========================================================================+
| // GLITCH ADMIN PANEL                    NIGHTMARE: OFF      up: 2h 14m |
+=========================================================================+
|  [Dashboard]   [Server]   [Scanner]   [Proxy]   [Settings]             |
+-------------------------------------------------------------------------+
|                                                                         |
|  +-----------------------+ +---------------------+ +------------------+ |
|  | SERVER       [green]  | | SCANNER    [cyan]   | | PROXY    [orange]| |
|  | Status: Running       | | Status: Idle        | | Mode: transparent| |
|  | Requests: 14,232      | | Last: 3m ago        | | Forwarded: 0     | |
|  | Error Rate: 12.4%     | | Grade: B+ (nuclei)  | | Blocked: 0       | |
|  | Clients: 7            | | Builtin: 42 findings| | WAF: OFF         | |
|  | Features: 21/21       | | Coverage: 78%       | | Chaos: OFF       | |
|  +-----------------------+ +---------------------+ +------------------+ |
|                                                                         |
|  +-- THROUGHPUT (last 60s) -------------------------------------------+ |
|  | ||||| ||||||||||||||||||  |||| ||||||||||||||||| ||||||| || |||||||  | |
|  +--------------------------------------------------------------------+ |
|                                                                         |
|  +-- CONNECTED CLIENTS --------+  +-- RECENT REQUESTS ---------------+ |
|  | Client    Reqs  R/s  Mode   |  | Time   Client  Path    Status    | |
|  | a3f2cd..  342   2.1  normal |  | 14:32  a3f2..  /api/u  200      | |
|  | b7c1e0..  128   0.8  aggr.  |  | 14:32  b7c1..  /vuln/  500      | |
|  | c4d9f1..   47   0.3  normal |  | 14:32  a3f2..  /login  302      | |
|  | ...                         |  | 14:31  c4d9..  /       200      | |
|  +-----------------------------+  +----------------------------------+ |
|                                                                         |
|  [Enable Nightmare]  [Run Quick Scan]  [View Server Logs]               |
+-------------------------------------------------------------------------+
```

## Appendix B: ASCII Mockup -- Server Tab (collapsed sections)

```
+=========================================================================+
| // GLITCH ADMIN PANEL                    NIGHTMARE: OFF      up: 2h 14m |
+=========================================================================+
|  [Dashboard]  [*Server*]  [Scanner]  [Proxy]  [Settings]               |
+-------------------------------------------------------------------------+
| SERVER STATUS: Running | Error Rate: 12.4% | Clients: 7 | Nightmare OFF|
+-------------------------------------------------------------------------+
|                                                                         |
|  [v] Feature Toggles                                    21/21 enabled   |
|  +--------------------------------------------------------------------+ |
|  | [on] Labyrinth        [on] Error Injection    [on] CAPTCHA         | |
|  | [on] Honeypot         [on] Vulnerabilities    [on] Analytics       | |
|  | [on] CDN Emulation    [on] OAuth              [on] Header Corrupt  | |
|  | [on] Cookie Traps     [on] JS Traps           [on] Bot Detection   | |
|  | [on] Random Blocking  [on] Framework Emul     [on] Search Engine   | |
|  | [on] Email/Webmail    [on] i18n               [on] Traffic Recorder| |
|  | [on] WebSocket        [on] Privacy/Consent    [on] Health          | |
|  | [on] Spider/Crawl                                                  | |
|  +--------------------------------------------------------------------+ |
|                                                                         |
|  [>] Error Configuration                                                |
|  [>] Content & Presentation                                             |
|  [>] Labyrinth                                                          |
|  [>] Adaptive Behavior                                                  |
|  [>] Traps & Detection                                                  |
|  [>] Vulnerabilities                                    229 vulns active|
|  [>] Spider & Crawl Data                                                |
|  [>] Sessions & Clients                                 7 connected     |
|  [>] Request Log                                        200 entries     |
|  [>] Traffic Analytics                                                  |
|                                                                         |
+-------------------------------------------------------------------------+
```

## Appendix C: ASCII Mockup -- Scanner Tab (3 sub-tabs)

```
+=========================================================================+
| // GLITCH ADMIN PANEL                    NIGHTMARE: OFF      up: 2h 14m |
+=========================================================================+
|  [Dashboard]  [Server]  [*Scanner*]  [Proxy]  [Settings]               |
+-------------------------------------------------------------------------+
| SCANNER STATUS: Built-in: IDLE | External: 0 running | Replay: STOPPED |
+-------------------------------------------------------------------------+
|                                                                         |
|  [Evaluate External Scanners]  [*Built-in Scanner*]  [PCAP Replay]     |
|                                                                         |
|  +-- GLITCH SCANNER ----------------------------------------------+    |
|  | The built-in scanner tests this server's defenses using 5      |    |
|  | attack modules and 4 scan profiles.                            |    |
|  | Target: [http://localhost:8765_______________]                  |    |
|  +----------------------------------------------------------------+    |
|                                                                         |
|  +-- SCAN PROFILE ------------------------------------------------+    |
|  | +---------------+ +---------------+ +----------+ +----------+  |    |
|  | | (*) COMPLIANCE| | ( ) AGGRESSIVE| | STEALTH  | | NIGHTMARE|  |    |
|  | | Workers: 5    | | Workers: 30   | | Workers:3| | Workers:50|  |    |
|  | | Rate: 20 r/s  | | Rate: 300 r/s | | Rate: 10 | | Rate: 500|  |    |
|  | | Evasion: none | | Evasion: none | | Evasion: | | Evasion: |  |    |
|  | |               | |               | | advanced | | nightmare|  |    |
|  | +---------------+ +---------------+ +----------+ +----------+  |    |
|  +----------------------------------------------------------------+    |
|                                                                         |
|  +-- ATTACK MODULES -----------------------------------------------+   |
|  | [x] owasp      OWASP Top 10 vulnerabilities       ~180 reqs    |   |
|  | [x] injection   SQLi, XSS, SSRF, SSTI, cmd-inj    ~320 reqs    |   |
|  | [x] fuzzing     Parameter/header/path fuzzing       ~250 reqs    |   |
|  | [x] protocol    Malformed HTTP, smuggling           ~90 reqs     |   |
|  | [x] auth        Brute force, token manipulation     ~60 reqs     |   |
|  | [Select All] [Deselect All]  5/5 modules (~900 reqs)            |   |
|  +------------------------------------------------------------------+  |
|                                                                         |
|  +-- RUN CONTROLS -------------------------------------------------+   |
|  | Profile: compliance | Modules: 5/5 | Target: localhost:8765     |   |
|  | [Run Glitch Scanner]                                             |   |
|  +------------------------------------------------------------------+  |
|                                                                         |
+-------------------------------------------------------------------------+
```

## Appendix D: ASCII Mockup -- Nightmare Mode Active

```
+=========================================================================+
| // GLITCH ADMIN PANEL    [!!! NIGHTMARE ACTIVE: Server, Scanner, Proxy] |
|                                     [Disable Nightmare]                 |
+=========================================================================+
|  [Dashboard]  [Server !!!]  [Scanner !!!]  [Proxy !!!]  [Settings]     |
+-------------------------------------------------------------------------+
|                                                                         |
|  +-----------------------+ +---------------------+ +------------------+ |
|  | SERVER       [RED]    | | SCANNER    [RED]    | | PROXY     [RED]  | |
|  | NIGHTMARE ACTIVE      | | NIGHTMARE ACTIVE    | | NIGHTMARE ACTIVE | |
|  | Error Rate: 47.2%     | | Profile: nightmare  | | Mode: NIGHTMARE  | |
|  | Clients: 7            | | Workers: 50         | | Latency: 60%     | |
|  | All features ON       | | Rate: 500 req/s     | | Corrupt: 30%     | |
|  | Error mult: 5.0x      | | All modules ON      | | Drop: 15%        | |
|  +-----------------------+ +---------------------+ +------------------+ |
|                                                                         |
|  ... (rest of dashboard content with red-tinted backgrounds) ...        |
|                                                                         |
+-------------------------------------------------------------------------+
```

## Appendix E: API Endpoint Summary

### Existing endpoints (unchanged)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/metrics` | Server metrics |
| `GET` | `/api/clients` | Client list |
| `GET` | `/api/timeseries` | Time series data |
| `GET` | `/api/recent` | Recent requests |
| `GET` | `/api/behaviors` | Adaptive behaviors |
| `GET/POST` | `/admin/api/features` | Feature toggles |
| `GET/POST` | `/admin/api/config` | Admin config |
| `GET` | `/admin/api/log` | Request log |
| `GET` | `/admin/api/client/{id}` | Client detail |
| `GET/POST` | `/admin/api/blocking` | Blocking config |
| `GET/POST` | `/admin/api/override` | Behavior overrides |
| `GET` | `/admin/api/scanner/profile` | Vulnerability profile |
| `POST` | `/admin/api/scanner/run` | Run external scanner |
| `POST` | `/admin/api/scanner/compare` | Compare scanner output |
| `GET` | `/admin/api/scanner/results` | Scanner results |
| `POST` | `/admin/api/scanner/stop` | Stop scanner |
| `GET` | `/admin/api/scanner/history` | Evaluation history |
| `POST` | `/admin/api/scanner/multi-compare` | Multi-scanner compare |
| `GET` | `/admin/api/scanner/baseline` | Scanner baseline |
| `POST` | `/admin/api/scanner/builtin/run` | Run built-in scanner |
| `GET` | `/admin/api/scanner/builtin/status` | Built-in scan status |
| `POST` | `/admin/api/scanner/builtin/stop` | Stop built-in scan |
| `GET` | `/admin/api/scanner/builtin/results` | Built-in scan results |
| `GET` | `/admin/api/scanner/builtin/history` | Built-in scan history |
| `GET` | `/admin/api/scanner/builtin/modules` | Module list |
| `GET` | `/admin/api/proxy/status` | Proxy status |
| `POST` | `/admin/api/proxy/mode` | Set proxy mode |
| `GET/POST` | `/admin/api/spider` | Spider config |
| `GET/POST` | `/admin/api/vulns` | Vuln categories |
| `POST` | `/admin/api/vulns/group` | Vuln group toggle |
| `GET/POST` | `/admin/api/error-weights` | Error weight control |
| `GET/POST` | `/admin/api/page-type-weights` | Page type weights |
| `GET` | `/admin/api/config/export` | Export config |
| `POST` | `/admin/api/config/import` | Import config |
| `GET` | `/admin/api/replay/files` | List capture files |
| `GET` | `/admin/api/replay/status` | Replay status |
| `POST` | `/admin/api/replay/load` | Load capture file |
| `POST` | `/admin/api/replay/start` | Start replay |
| `POST` | `/admin/api/replay/stop` | Stop replay |
| `POST` | `/admin/api/replay/upload` | Upload capture |
| `POST` | `/admin/api/replay/fetch-url` | Fetch capture URL |
| `GET` | `/admin/api/replay/metadata` | Capture metadata |
| `POST` | `/admin/api/replay/cleanup` | Cleanup captures |
| `GET` | `/admin/api/overview` | Traffic overview |

### New endpoints

| Method | Path | Request Body | Response | Purpose |
|---|---|---|---|---|
| `GET` | `/admin/api/nightmare` | -- | `{"server":bool,"scanner":bool,"proxy":bool}` | Get nightmare state |
| `POST` | `/admin/api/nightmare` | `{"mode":"all\|server\|scanner\|proxy","enabled":bool}` | `{"ok":true,"state":{...}}` | Toggle nightmare |
| `POST` | `/admin/api/password` | `{"current":"..","new":".."}` | `{"ok":true}` or `{"error":".."}` | Change admin password |
