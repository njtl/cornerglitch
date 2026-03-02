# PRD: Audit Log System

## Overview

Add a comprehensive audit log that records **every state change, action, and system event** across all Glitch components (server, scanner, proxy, settings, PCAP/recorder). The audit log captures who made the change, what changed (old value, new value), when, and from where. This provides full observability into configuration drift, operational actions, and system lifecycle events.

## Goals

1. **Complete coverage** — every configuration change, every action, every system event is logged
2. **Before/after values** — config changes record previous and new values for rollback auditing
3. **Multi-user ready** — actor field supports future multi-user auth (currently "admin" default)
4. **Queryable** — filterable by actor, event type, resource, time range
5. **Dashboard UI** — last 50 events with pagination and filtering in the Settings tab
6. **Minimal performance impact** — async writes, no blocking on the hot path
7. **PostgreSQL + in-memory** — persisted to DB when available, in-memory ring buffer always

## Non-Goals

- Real-time streaming/websocket push of audit events (future)
- Audit log export to external SIEM systems (future)
- Tamper-proof/signed audit entries (future)
- Undo/rollback from audit log (future)

## Architecture

### Storage Layer

New `internal/audit` package with:

```go
// Entry represents a single audit log event.
type Entry struct {
    ID        int64                  `json:"id"`
    Timestamp time.Time              `json:"timestamp"`
    Actor     string                 `json:"actor"`      // "admin", "system", future usernames
    Action    string                 `json:"action"`     // "config.change", "feature.toggle", etc.
    Resource  string                 `json:"resource"`   // "feature_flags.labyrinth", "admin_config.error_rate_multiplier"
    OldValue  interface{}            `json:"old_value,omitempty"`  // previous value (nil for actions)
    NewValue  interface{}            `json:"new_value,omitempty"`  // new value (nil for actions)
    Details   map[string]interface{} `json:"details,omitempty"`    // extra context
    ClientIP  string                 `json:"client_ip,omitempty"`
    Status    string                 `json:"status"`     // "success", "error", "denied"
}
```

### Dual Storage

1. **In-memory ring buffer** (always available, 1000 entries) — for the dashboard UI and non-DB deployments
2. **PostgreSQL table** `audit_log` (when DB available) — for persistent, queryable history

### Database Schema (migration 002)

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor       VARCHAR(100) NOT NULL DEFAULT 'system',
    action      VARCHAR(100) NOT NULL,
    resource    VARCHAR(200) NOT NULL,
    old_value   JSONB,
    new_value   JSONB,
    details     JSONB,
    client_ip   VARCHAR(45),
    status      VARCHAR(20) NOT NULL DEFAULT 'success',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_timestamp ON audit_log (timestamp DESC);
CREATE INDEX idx_audit_log_actor ON audit_log (actor, timestamp DESC);
CREATE INDEX idx_audit_log_action ON audit_log (action, timestamp DESC);
CREATE INDEX idx_audit_log_resource ON audit_log (resource, timestamp DESC);
```

## Event Taxonomy

### Action Types

| Action | Description | Resource Pattern |
|--------|-------------|-----------------|
| `feature.toggle` | Feature flag enabled/disabled | `feature_flags.{name}` |
| `config.change` | Numeric/string config changed | `admin_config.{key}` |
| `config.error_weight` | Error type weight changed | `error_weights.{type}` |
| `config.page_type_weight` | Page type weight changed | `page_type_weights.{type}` |
| `vuln.group_toggle` | Vuln group enabled/disabled | `vuln_config.groups.{name}` |
| `vuln.category_toggle` | Vuln category enabled/disabled | `vuln_config.categories.{id}` |
| `vuln.bulk_toggle` | All vulns toggled at once | `vuln_config.all` |
| `spider.config_change` | Spider config changed | `spider_config.{key}` |
| `proxy.mode_change` | Proxy mode changed | `proxy.mode` |
| `proxy.start` | Proxy runtime started | `proxy.runtime` |
| `proxy.stop` | Proxy runtime stopped | `proxy.runtime` |
| `proxy.restart` | Proxy runtime restarted | `proxy.runtime` |
| `proxy.mirror_refresh` | Mirror config re-snapshotted | `proxy.mirror` |
| `scanner.run` | External scanner launched | `scanner.external.{name}` |
| `scanner.stop` | External scanner stopped | `scanner.external` |
| `scanner.compare` | Scanner comparison run | `scanner.compare` |
| `scanner.builtin_run` | Built-in scanner started | `scanner.builtin` |
| `scanner.builtin_stop` | Built-in scanner stopped | `scanner.builtin` |
| `recorder.start` | Traffic recording started | `recorder` |
| `recorder.stop` | Traffic recording stopped | `recorder` |
| `recorder.format_change` | Recording format changed | `recorder.format` |
| `replay.load` | PCAP/JSONL file loaded | `replay.{filename}` |
| `replay.start` | Replay started | `replay` |
| `replay.stop` | Replay stopped | `replay` |
| `replay.upload` | Capture file uploaded | `replay.upload` |
| `replay.cleanup` | Capture files cleaned up | `replay.cleanup` |
| `nightmare.server_enable` | Server nightmare enabled | `nightmare.server` |
| `nightmare.server_disable` | Server nightmare disabled | `nightmare.server` |
| `nightmare.scanner_enable` | Scanner nightmare enabled | `nightmare.scanner` |
| `nightmare.scanner_disable` | Scanner nightmare disabled | `nightmare.scanner` |
| `nightmare.proxy_enable` | Proxy nightmare enabled | `nightmare.proxy` |
| `nightmare.proxy_disable` | Proxy nightmare disabled | `nightmare.proxy` |
| `nightmare.all_enable` | All nightmare enabled | `nightmare.all` |
| `nightmare.all_disable` | All nightmare disabled | `nightmare.all` |
| `client.override` | Client behavior overridden | `client.{client_id}` |
| `client.override_clear` | Client override cleared | `client.{client_id}` |
| `client.block` | Client blocked | `client.{client_id}` |
| `client.unblock` | Client unblocked | `client.{client_id}` |
| `blocking.config_change` | Blocking config changed | `blocking.{key}` |
| `config.export` | Config exported | `config.export` |
| `config.import` | Config imported | `config.import` |
| `config.save` | Config auto-saved | `config.autosave` |
| `config.load` | Config loaded from DB/file | `config.load` |
| `auth.login` | User logged in | `auth.session` |
| `auth.login_failed` | Login attempt failed | `auth.session` |
| `auth.logout` | User logged out | `auth.session` |
| `auth.password_change` | Password changed | `auth.password` |
| `system.start` | Server started | `system.lifecycle` |
| `system.stop` | Server stopped (graceful) | `system.lifecycle` |
| `system.crash` | Server crashed/fatal error | `system.lifecycle` |
| `system.db_connect` | Database connected | `system.storage` |
| `system.db_disconnect` | Database disconnected | `system.storage` |
| `system.migration` | DB migration applied | `system.storage` |

## API Endpoints

### GET /admin/api/audit

Query audit log entries with filtering and pagination.

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | int | 50 | Max entries to return (1-200) |
| `offset` | int | 0 | Pagination offset |
| `actor` | string | | Filter by actor |
| `action` | string | | Filter by action (prefix match, e.g. `config` matches `config.change`) |
| `resource` | string | | Filter by resource (prefix match) |
| `status` | string | | Filter by status |
| `from` | RFC3339 | | Start time |
| `to` | RFC3339 | | End time |

**Response:**
```json
{
    "entries": [...],
    "total": 342,
    "limit": 50,
    "offset": 0,
    "filters": {
        "actors": ["admin", "system"],
        "actions": ["config.change", "feature.toggle", ...],
        "statuses": ["success", "error"]
    }
}
```

## Dashboard UI

### Location
Bottom of the **Settings** tab, below existing settings cards.

### Layout
```
+------------------------------------------------------------------+
| Audit Log                                              [Refresh]  |
+------------------------------------------------------------------+
| Filters: [Actor ▼] [Action ▼] [Resource ____] [Status ▼]        |
+------------------------------------------------------------------+
| Time            | Actor  | Action           | Resource      | Δ   |
|-----------------|--------|------------------|---------------|-----|
| 10:24:26        | system | system.start     | system.life.. |     |
| 10:24:26        | system | config.load      | config.load   |     |
| 10:25:01        | admin  | feature.toggle   | feature_fl..  | ●→○ |
| 10:25:03        | admin  | config.change    | admin_conf..  | 1→3 |
| ...             |        |                  |               |     |
+------------------------------------------------------------------+
| Showing 1-50 of 342     [◄ Prev]  Page 1 of 7  [Next ►]         |
+------------------------------------------------------------------+
```

### UI Features
- Auto-refresh every 5 seconds (only when Settings tab is visible)
- Click a row to expand full details (old_value, new_value, client_ip, details JSON)
- Delta column (Δ) shows compact before→after for value changes
- Color-coded actions: green=success, red=error, yellow=denied
- Dropdowns populated from actual distinct values in the log
- Resource field supports text search (substring match)

## Integration Points

### 1. Audit Logger Singleton

```go
// internal/audit/audit.go
var logger *Logger  // global singleton

func Log(actor, action, resource string, oldVal, newVal interface{}, details map[string]interface{})
func LogAction(actor, action, resource string, details map[string]interface{})
func LogSystem(action, resource string, details map[string]interface{})
```

### 2. Where to Instrument

**Feature Flags** (`internal/dashboard/admin.go`):
- `FeatureFlags.Set()` — log old and new boolean value

**Admin Config** (`internal/dashboard/admin.go`):
- `AdminConfig.Set()` — log old and new numeric value
- `AdminConfig.SetString()` — log old and new string value
- `AdminConfig.SetErrorWeight()` — log old and new weight
- `AdminConfig.SetPageTypeWeight()` — log old and new weight

**Vuln Config** (`internal/dashboard/admin.go`):
- `VulnConfig.SetGroup()` — log old and new enabled state
- `VulnConfig.SetCategory()` — log old and new enabled state

**Spider Config** (`internal/spider/spider.go` via `dashboard.GetSpiderConfig()`):
- `SpiderConfig.Set()` — log old and new value

**Proxy** (`internal/dashboard/admin_routes.go`):
- Mode change endpoint — log old and new mode
- Runtime start/stop/restart — log action with port/target details
- Mirror refresh — log action

**Scanner** (`internal/dashboard/admin_routes.go`, `scanner_api.go`):
- Run/stop/compare endpoints — log action with scanner name, target, profile
- Built-in scanner run/stop — log action with modules, target

**Recorder** (`internal/dashboard/admin_routes.go`):
- Start/stop recording — log action with format, limits
- Replay load/start/stop — log action with filename, timing mode

**Nightmare Mode** (`internal/dashboard/admin_routes.go`):
- Enable/disable per subsystem — log old and new state

**Client Overrides** (`internal/dashboard/admin_routes.go`):
- Set/clear override — log client ID, old mode, new mode
- Block/unblock — log client ID

**Config Persistence** (`internal/dashboard/admin.go`):
- `TriggerAutoSave()` — log save event (debounced, log once per actual write)
- `LoadStateFile()` — log load source (DB or file)
- `ImportConfig()` — log import event

**Auth** (`internal/dashboard/auth.go`):
- Login success/failure — log actor, client IP
- Logout — log actor
- Password change — log actor (NOT the password)

**System Lifecycle** (`cmd/glitch/main.go`):
- Startup — log startup with ports, config source
- Shutdown — log graceful shutdown
- Fatal errors — log crash details

### 3. Actor Resolution

The audit logger needs to know "who" triggered the action. Strategy:
- **Admin API requests**: extract from authenticated session (currently always "admin")
- **System actions**: use "system" as actor (startup, auto-save, auto-load)
- **Future**: session carries user identity when multi-user auth is added

For API routes, pass the actor through a context value or direct parameter:
```go
// In admin route handlers:
actor := "admin"  // from session, expandable later
audit.Log(actor, "config.change", "admin_config.error_rate_multiplier", oldVal, newVal, nil)
```

For setter methods called from API handlers, add audit logging at the **call site** (admin_routes.go), not inside the setter itself. This keeps the setter methods clean and gives the route handler access to the actor identity and HTTP context.

## Performance

- **In-memory ring buffer**: lock-free reads via atomic snapshot, mutex-protected writes
- **DB writes**: async via buffered channel (capacity 1000), background goroutine drains to DB
- **No blocking**: `Log()` never blocks the caller; drops oldest if buffer full
- **Batch inserts**: DB writer batches up to 50 entries per INSERT for efficiency
- **Indexes**: 4 targeted indexes for common query patterns

## Testing

1. **Unit tests** (`internal/audit/audit_test.go`):
   - Ring buffer capacity and overflow
   - Entry creation with all field types
   - Query filtering (actor, action, resource, time range)
   - JSON serialization round-trip

2. **Integration tests** (`tests/atomic/audit_test.go`):
   - Feature toggle generates audit entry
   - Config change records old/new values
   - Vuln group toggle generates audit entry
   - Proxy mode change generates audit entry
   - Scanner action generates audit entry
   - Nightmare mode generates audit entry
   - Auth events (login/logout) generate entries
   - System lifecycle events logged
   - API endpoint returns filtered results
   - Pagination works correctly

3. **DB tests** (skip if PostgreSQL unavailable):
   - Entries persist to audit_log table
   - Queries with filters return correct results
   - Concurrent writes don't lose entries

## File Plan

| File | Purpose |
|------|---------|
| `internal/audit/audit.go` | Logger singleton, Entry struct, ring buffer, Log/Query functions |
| `internal/audit/audit_test.go` | Unit tests |
| `internal/storage/migrations/002_audit_log.sql` | DB migration |
| `internal/storage/audit_store.go` | DB read/write methods |
| `internal/dashboard/admin_routes.go` | Instrument all POST handlers with audit calls |
| `internal/dashboard/admin.go` | Instrument setter methods + auto-save/load |
| `internal/dashboard/auth.go` | Instrument login/logout/password change |
| `internal/dashboard/admin_html.go` | Audit log UI in Settings tab |
| `cmd/glitch/main.go` | System lifecycle audit events |
| `tests/atomic/audit_test.go` | Integration tests |

## Milestones

1. **Core**: `internal/audit/` package — Entry struct, ring buffer, Logger, Query API
2. **Storage**: DB migration + audit_store.go for PostgreSQL persistence
3. **Instrumentation**: Wire audit.Log() calls into all admin routes, setters, auth, lifecycle
4. **API**: GET /admin/api/audit endpoint with filtering/pagination
5. **UI**: Audit log table in Settings tab with filters and pagination
6. **Tests**: Unit + integration + DB tests
