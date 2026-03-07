# Dashboard Refactor Sprint — 2026-03-07

## Goal
Refactor the dashboard for better UX, faster data loading, universal sort/filter, and Grafana-inspired flexibility.

## Current State Analysis

### Complexity
- **5938 lines** in single `admin_html.go` (623 CSS, 3998 JS, rest HTML)
- **24 tables** — zero support sorting, zero support filtering (except audit log)
- **59 API routes** in `admin_routes.go`
- **348 getElementById** calls, **114 innerHTML** assignments — string-based DOM everywhere
- **15 fetch()** calls across refresh functions

### Data Loading (Current)
- Global `refresh()` every 3s, dispatches to active tab's refresh function
- Dashboard tab: `Promise.all` fetching 4 endpoints (metrics, timeseries, clients, recent) — good
- Server tab: Only refreshes open collapsible sections — good optimization
- Scanner/Proxy: Full refresh every 3s when active
- **No pagination** on most tables (audit log is the exception)
- **No delta/incremental updates** — full data re-fetch every cycle
- **No time range selection** — hardcoded windows

### Tables Inventory (24 total, 0 sortable)

| # | Table | Location | Columns | Rows (typical) | Sort? | Filter? |
|---|-------|----------|---------|-----------------|-------|---------|
| 1 | Connected clients | Dashboard | 6 | 10 (top) | No | No |
| 2 | Recent requests | Dashboard | 9 | 30 (last) | No | No |
| 3 | MCP endpoints | Server>MCP | 4 | ~20 | No | No |
| 4 | MCP events | Server>MCP | 5 | ~50 | No | No |
| 5 | Vulnerabilities | Server>Vulns | 6 | ~200 | No | No |
| 6 | Sessions/Clients | Server>Sessions | 9 | variable | No | No |
| 7 | Eval history | Scanner>Eval | 7 | variable | No | No |
| 8 | Scan results | Scanner>Eval | variable | variable | No | No |
| 9 | Builtin scan results | Scanner>Builtin | variable | variable | No | No |
| 10 | Builtin history | Scanner>Builtin | 5 | variable | No | No |
| 11 | Module selection | Scanner>Builtin | 3 | ~12 | No | No |
| 12 | Replay files | Scanner>Replay | 4 | variable | No | No |
| 13 | Proxy pipeline | Proxy | 4 | ~8 | No | No |
| 14 | Error weights | Server>Errors | 3+presets | ~20 | No | No |
| 15 | TCP error weights | Server>Errors | 3+presets | ~10 | No | No |
| 16 | Page type weights | Server>Content | 3+presets | ~8 | No | No |
| 17 | Feature toggles | Server>Features | 2 | ~21 | No | No |
| 18 | Vuln group toggles | Server>Vulns | 2 | ~9 | No | No |
| 19 | Status code dist | Dashboard | 2 | ~5 | No | No |
| 20 | Top paths | Dashboard | 2 | ~10 | No | No |
| 21 | Top user agents | Dashboard | 2 | ~10 | No | No |
| 22 | Audit log | Settings | 7 | paginated | No | Yes (4 filters) |
| 23 | MCP scanner results | Scanner>MCP | variable | variable | No | No |
| 24 | API chaos config | Server>API | variable | variable | No | No |

### UX Issues
1. **No column sorting** on any table — can't find highest error client, most recent scan, etc.
2. **No column filtering** — can't filter requests by status code, clients by mode, vulns by severity
3. **No search** on large tables (vulns has ~200 rows)
4. **No time range selector** — everything is "all time" or fixed window
5. **Tables rebuilt via innerHTML every 3s** — flickers, loses scroll position, kills selection
6. **No loading indicators** — data appears to be static until it suddenly changes
7. **No empty states** — blank tables with no "No data" message
8. **Inconsistent table styling** — some have inline styles, some use classes

---

## Sprint Tasks

### Phase 1: Universal Table System (Core Infrastructure)

**Task 1.1: Create reusable sortable/filterable table component**
Build a JS table component that provides:
- Click column header to sort (asc/desc/none, with arrow indicators)
- Per-column text filter inputs (shown/hidden via toggle)
- Search box for full-text search across all columns
- Pagination (configurable page size: 10/25/50/100)
- Stable updates (diff-based, preserves scroll position and selection)
- Empty state ("No data" message)
- Row count indicator ("Showing 1-25 of 142")
- Export button (copy as CSV)

This is a single JS class `GlitchTable` embedded in admin_html.go that replaces all innerHTML-based table rendering.

**Task 1.2: Migrate all data tables to GlitchTable**
Convert each of the 24 tables to use the new component. Priority order:
1. Recent requests (Dashboard) — most viewed, 9 columns
2. Connected clients (Dashboard) — needs sort by req/s, errors
3. Sessions/Clients (Server) — large, needs search
4. Vulnerabilities (Server) — ~200 rows, needs search + severity filter
5. Scan results tables (Scanner) — variable size
6. Audit log (Settings) — already has filters, add sorting
7. All remaining tables

### Phase 2: Smart Data Loading

**Task 2.1: Incremental table updates (diff-based rendering)**
Instead of replacing innerHTML every 3s:
- Track row keys (client ID, request timestamp, etc.)
- Only add/remove/update changed rows
- Preserve scroll position
- Add subtle highlight animation on changed values

**Task 2.2: Pagination on backend API endpoints**
Add `?limit=N&offset=M&sort=field&order=asc|desc` query params to:
- `GET /api/clients` — currently returns ALL clients
- `GET /api/recent` — currently returns last 200
- `GET /admin/api/log` — currently returns last 200
- `GET /admin/api/scanner/builtin/results` — can be large
- `GET /admin/api/scanner/history` — unbounded

**Task 2.3: Conditional refresh / ETag support**
- Add `ETag` or `Last-Modified` headers to API responses
- Frontend sends `If-None-Match` — skip re-render on 304
- Reduces CPU on both server and browser when data hasn't changed

**Task 2.4: Lazy section loading**
- Server tab sections already only refresh when open (good)
- Apply same pattern to Dashboard: don't fetch clients/recent if those sections are scrolled out of view
- Scanner sub-tabs: don't poll history endpoint unless history section is visible

### Phase 3: Grafana-Style Features

**Task 3.1: Time range selector**
Add a global time range selector (top bar):
- Presets: Last 5m, 15m, 1h, 6h, 24h, All
- Custom range picker
- Pass `from` and `to` timestamps to API endpoints
- Affects: sparklines, recent requests, clients, audit log, scan history

**Task 3.2: Dashboard metric cards — click to drill down**
- Clicking "Total Requests" navigates to Server > Request Log
- Clicking "Error Rate" navigates to Server > Error Config
- Clicking "Unique Clients" navigates to Server > Sessions
- Clicking status code cards (2xx/4xx/5xx) filters request log by status

**Task 3.3: Auto-refresh controls**
- Dropdown next to time range: Off, 1s, 3s, 5s, 10s, 30s
- Currently hardcoded to 3s with no way to change
- Pauses auto-refresh when browser tab is hidden (visibility API)

**Task 3.4: Column visibility toggles**
- Per-table gear icon to show/hide columns
- Persisted in localStorage
- Especially useful for wide tables (recent requests has 9 cols)

### Phase 4: Visual & UX Polish

**Task 4.1: Consistent table styling**
- Remove all inline styles from tables (currently many have `style="..."` on th/td)
- Unified `.glitch-table` CSS class with:
  - Striped rows
  - Hover highlight
  - Sticky header
  - Responsive horizontal scroll
  - Compact/comfortable density toggle

**Task 4.2: Loading states**
- Skeleton loader on initial data fetch
- Subtle pulse animation on refresh
- "Last updated: Xs ago" indicator per section

**Task 4.3: Empty states**
- "No clients connected" with icon
- "No scan results — run a scan" with action button
- "No vulnerabilities found" etc.

**Task 4.4: Responsive improvements**
- Tables scroll horizontally on narrow screens
- Cards stack vertically on mobile
- Collapsible sidebar for section navigation on Server tab

---

## Implementation Strategy

### File Changes
- `internal/dashboard/admin_html.go` — main changes (new JS table component, migrate tables, time range, auto-refresh)
- `internal/dashboard/admin_routes.go` — add pagination/sort/filter params to list endpoints
- `internal/dashboard/admin.go` — helper methods for sorted/filtered data access
- `internal/metrics/collector.go` — time-windowed queries if not already supported

### Testing
- `internal/dashboard/admin_test.go` — test pagination params, sort order, filter logic
- `tests/integration/` — test dashboard loads, tables render, API pagination works
- Manual: verify sort/filter on every table, check scroll preservation, test time ranges

### Risk Areas
- **innerHTML replacement breaks scroll** — the diff-based approach in Task 2.1 is critical
- **JS bundle size** — GlitchTable component adds JS; keep it lean (no frameworks)
- **API backward compatibility** — new query params must be optional (existing behavior = no params)
- **Mutex contention** — sorted queries on large datasets under RWMutex could slow other ops

---

## Sprint Rules
1. Every table must be sortable by every column
2. Every table with >10 rows must have search/filter
3. Every table with >25 rows must have pagination
4. No innerHTML-based full table rebuilds on refresh
5. No data fetch for invisible sections
6. All API list endpoints must support `sort`, `order`, `limit`, `offset` params
7. Time range selector must work across all time-series data
8. Auto-refresh rate must be user-configurable
9. Zero external JS dependencies (stdlib only philosophy extends to frontend)
10. All changes must pass existing tests + new pagination/sort tests
