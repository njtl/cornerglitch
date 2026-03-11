# CLAUDE.md — Glitch

## What is this project?

**Glitch — HTTP Chaos Testing Framework.** A 3-in-1 tool for testing every layer of the HTTP stack:

- **Glitch Server** (`glitch`) — Backend emulator. Unreliable, adaptive, vulnerable. Simulates broken web services with dozens of error types, hundreds of vulnerability endpoints across all OWASP Top 10 lists, infinite scraper labyrinths, client fingerprinting, and adaptive behavior.
- **Glitch Scanner** (`glitch-scanner`) — Client emulator. Aggressive, malformed, adversarial. Simulates scanners, scrapers, fuzzers, and malicious clients with configurable attack modules, crawling, evasion, and resilience testing.
- **Glitch Proxy** (`glitch-proxy`) — Middleware emulator. Corrupting, filtering, chaotic. Simulates proxies, WAFs, WAAPs, API gateways, and load balancers with traffic manipulation, chaos injection, and WAF rule simulation.

**Nightmare Mode**: All three configured for maximum adversarial behavior simultaneously. If your service survives nightmare mode, it can handle anything production throws at it.

**Target audience**: Anyone building a client (scanner, scraper, crawler), a proxy (WAF, WAAP, API gateway, load balancer, CDN), or a backend (web app, API, microservice) — Glitch tests any combination of these services against real-world chaos.

## Build & Run

```bash
# Quick start (recommended)
cp .env.example .env                         # configure password + database URL
make start                                   # build, start in background, show logs

# Lifecycle commands
make start                                   # build + start in background (logs: /tmp/glitch.log)
make stop                                    # graceful shutdown
make restart                                 # stop + start
make status                                  # check if running
make logs                                    # tail -f /tmp/glitch.log
make run                                     # build + run in foreground

# Server (backend emulator)
go build -o glitch ./cmd/glitch
./glitch                                    # ports 8765 + 8766 + 8767 (TLS), auto-loads .env
./glitch -port 9000 -dash-port 9001 -tls-port 9002  # custom ports
./glitch -tls-port 0                        # disable TLS listener
./glitch -cert cert.pem -key key.pem        # use custom TLS cert (env: GLITCH_TLS_CERT/KEY)
./glitch -config config.json                # load saved configuration
./glitch -nightmare                         # nightmare mode
GLITCH_ADMIN_PASSWORD=secret ./glitch       # set admin password (or -admin-password flag, or .env file)
GLITCH_DB_URL=postgres://glitch:glitch@localhost:5432/glitch?sslmode=disable ./glitch  # with PostgreSQL persistence

# Scanner (client emulator)
go build -o glitch-scanner ./cmd/glitch-scanner
glitch-scanner -target http://localhost:8765
glitch-scanner -target http://localhost:8765 -profile nightmare
glitch-scanner -target http://localhost:9001 -profile destroyer  # server destruction mode

# Proxy (middleware emulator)
go build -o glitch-proxy ./cmd/glitch-proxy
glitch-proxy -target http://localhost:8765 -mode chaos
glitch-proxy -target http://localhost:8765 --chaos-prob 0.3 --waf-action block

# Self-test (all three against each other)
glitch selftest --mode nightmare --duration 60s
glitch selftest --mode baseline              # also: scanner-stress, proxy-stress, server-stress, chaos

# Docker (includes PostgreSQL)
docker-compose up                            # runs server + dashboard + postgres

# Database management
make db-up                                   # start standalone PostgreSQL container
make db-down                                 # stop PostgreSQL container
make db-reset                                # drop and recreate database
make db-psql                                 # connect to PostgreSQL with psql
```

### Environment Configuration

The server auto-loads `.env` from the working directory on startup. No need to manually `source` it. Explicit env vars and CLI flags always take precedence.

**Required `.env` variables** (see `.env.example`):

| Variable | Purpose | Default |
|----------|---------|---------|
| `GLITCH_ADMIN_PASSWORD` | Dashboard login password | Auto-generated (printed to stderr) |
| `GLITCH_DB_URL` | PostgreSQL connection string | None (no persistence — data lost on restart) |
| `PASSWORD_RESET_FROM_ENV` | Set to `1` to force-reset password from `GLITCH_ADMIN_PASSWORD`, overwriting DB | `0` (disabled) |
| `GLITCH_HEALTH_SECRET` | Secret path segment for internal health endpoint | Auto-generated (printed to stderr) |
| `GLITCH_TLS_CERT` | Path to TLS certificate file for HTTPS listener | None (self-signed auto-generated) |
| `GLITCH_TLS_KEY` | Path to TLS private key file for HTTPS listener | None (self-signed auto-generated) |
| `SENTRY_DSN` | Sentry error tracking DSN | None (disabled) |

**Password persistence**: When a database is configured, password changes via the admin UI are saved to PostgreSQL. On restart, the DB password takes priority over the `.env` value. To recover from a forgotten password, set `PASSWORD_RESET_FROM_ENV=1` — this overwrites the DB password with `GLITCH_ADMIN_PASSWORD` on next startup. Remove the flag after resetting.

**Health endpoints**: The server has **no real (externally accessible) health endpoints**. All public health paths (`/health`, `/health/live`, `/status`, `/ping`, `/actuator`, etc.) are emulated and subject to error injection like any other endpoint. For internal health checking (CI, Docker, selftest), a secret path `/_internal/<secret>/healthz` bypasses all chaos. The secret is set via `GLITCH_HEALTH_SECRET` env var or auto-generated on startup (printed to stderr). Docker and selftest use this path for health checks.

**Warning**: Without `GLITCH_DB_URL`, the server runs in memory-only mode — all metrics, scan history, and client profiles are lost on restart. The server logs a warning when no DB URL is configured.

Two external dependencies: `github.com/lib/pq` (PostgreSQL driver) and `github.com/getsentry/sentry-go` (error tracking, optional). Otherwise stdlib only, go 1.24+.

## Project Layout

```
cmd/
  glitch/main.go                 Server binary + selftest subcommand
  glitch-scanner/main.go         Scanner binary
  glitch-proxy/main.go           Proxy binary

internal/
  # Server subsystems
  server/handler.go              Main request handler — dispatches to all subsystems
  errors/generator.go            Error types (HTTP + TCP + protocol) with weighted probability profiles
  pages/generator.go             Content generators (HTML, JSON, XML, CSV, SSE, etc.)
  content/engine.go              Deterministic page generation with JS API calls
  labyrinth/labyrinth.go         Infinite procedural page graph for trapping scrapers
  fingerprint/engine.go          Client ID via headers, UA classification, IP
  adaptive/engine.go             Behavior modes, re-evaluates per client periodically
  metrics/collector.go           Ring buffer, time series, per-client profiles
  dashboard/                     Admin panel + unified dashboard (5 tabs, nightmare mode, all controls)
  vuln/                          All vulnerability endpoints (all OWASP Top 10 lists)
  api/                           REST API emulation (users, products, CMS, forms, infra)
  honeypot/                      Honeypot lure paths and response generation
  botdetect/                     Bot detection scoring and classification
  captcha/                       CAPTCHA challenge system
  framework/                     Framework emulation (Rails, Django, Express, Spring, Laravel)
  headers/                       Header corruption engine
  cookies/                       Cookie trap system
  jstrap/                        JavaScript trap challenges
  health/                        Health endpoints + Spring Boot Actuator emulation
  search/, email/, oauth/, cdn/, i18n/, privacy/, websocket/, analytics/
  recorder/                      Traffic recording (JSONL/PCAP formats)
  replay/                        PCAP/JSONL replay (loader, player, timing modes)
  spider/                        Spider data generation for crawl discovery
  media/                         Procedural media generation (images, audio, video, streaming)
  mediachaos/                    Media chaos engine (corruption, delivery chaos, cache poisoning)
  budgettrap/                    Budget-draining traps (tarpit, breadcrumbs, pagination, expansion, streaming bait)
  tlschaos/                      TLS chaos engine (version downgrade, weak ciphers, cert rotation, ALPN lies)
  h3chaos/                       HTTP/3 QUIC chaos engine (Alt-Svc injection, fake QUIC UDP listener, malformed packets)
  mcp/                           MCP (Model Context Protocol) subsystem — honeypot server, agent fingerprinting, SSE transport, outbound scanner, admin tools
    mcp/server.go                MCP honeypot server (Streamable HTTP transport, JSON-RPC 2.0)
    mcp/fingerprint.go           Client fingerprinting (classify Claude, GPT, Cursor, Windsurf; behavioral signals)
    mcp/scanner.go               Outbound MCP scanner (tests external MCP servers for injection, rug pulls, exfiltration)
    mcp/admin_tools.go           Authenticated admin MCP endpoint (toggle features, get metrics, nightmare control)
  storage/                       PostgreSQL persistence with insert-only versioning and migrations

  # Scanner subsystems
  scanner/
    engine.go                    Scanner orchestrator
    config.go                    Configuration and profiles
    crawler.go                   Page/API discovery
    reporter.go                  Findings and coverage reports
    attacks/                     Attack modules (owasp, injection, fuzzing, protocol, auth, chaos, tls, slowhttp, breakage, h3)
    resilience/                  Error handling, timeouts, connections
    evasion/                     WAF bypass, encoding, fragmentation
    profiles/                    Scan profiles (aggressive, stealth, nightmare, compliance, destroyer, waf-buster)

  # Proxy subsystems
  proxy/                         Core proxy + interception pipeline
    proxy/mcp_interceptor.go     MCP traffic interception (tool injection, resource poisoning, result modification)
    chaos/                       Chaos modules (latency, corruption, connection, rewrite)
    waf/                         WAF modules (signatures, ratelimit, geoblock, botblock)
    modes/                       Mode implementations (transparent, waf, chaos, nightmare, mirror, killer)

  # Scanner evaluation (comparison tool)
  scaneval/                      Scanner profile comparison, coverage matrix

  # Self-test
  selftest/                      Pipeline orchestration, monitoring, reporting

Dockerfile                       Multi-stage build (non-root, healthcheck)
docker-compose.yml               Server + dashboard + PostgreSQL with volumes/env config
Makefile                         build, test, vet, clean, docker-build, run, cross, db-up/down/reset/psql
.github/workflows/               CI (lint/test/build) + Docker multi-arch push
deploy/k8s/                      Kubernetes manifests (deployment, service, configmap, ingress)
deploy/systemd/                  Systemd service files (glitch-server, glitch-proxy)

docs/                            PRDs, architecture plans, design docs
tests/
  acceptance/                    Acceptance tests
  integration/                   Integration tests
  regression/                    Regression tests for fixed bugs
  nightmare/                     Nightmare mode survival tests
```

## Key Conventions

- **Minimal external deps.** Only `github.com/lib/pq` (PostgreSQL driver) and `github.com/getsentry/sentry-go` (error tracking) are allowed. Everything else uses Go stdlib.
- **All logic is in `internal/`.** Nothing in `internal/` is meant to be imported by external code.
- **Error profiles are probability maps** (`map[ErrorType]float64`). Weights should sum to ~1.0. Includes HTTP errors, TCP-level errors, protocol-level glitches, HTTP/2 frame-level chaos (h2_goaway, h2_rst_stream, h2_settings_flood, h2_window_exhaust, h2_continuation_flood, h2_ping_flood), and scanner-destroying payloads. Protocol glitches are togglable via admin config (`protocol_glitch_enabled`, `protocol_glitch_level` 0-4).
- **TLS chaos engine** (`internal/tlschaos/`) provides 5 chaos levels: 0=clean TLS 1.3, 1=version downgrade, 2=weak ciphers, 3=cert chaos (rotation through expired/wrong-host/weak-key certs), 4=nightmare (all + ALPN lies). Controlled via `tls_chaos_enabled` and `tls_chaos_level` admin config. HTTPS listener on port 8767 auto-generates self-signed certs. HTTP/2 is auto-enabled by Go stdlib over TLS.
- **HSTS chaos** injects random Strict-Transport-Security headers (max-age 0 to 999999999, conflicting directives). Controlled via `hsts_chaos_enabled` admin config.
- **H3/QUIC chaos engine** (`internal/h3chaos/`) emulates HTTP/3 support to confuse clients. 4 severity levels: 1=subtle Alt-Svc headers, 2=aggressive conflicting Alt-Svc, 3=invalid QUIC endpoints (emoji ports, null bytes), 4=nightmare (all + fake UDP QUIC listener responding with malformed packets including Version Negotiation, Retry, Stateless Reset, and garbage). Controlled via `h3_chaos_enabled` and `h3_chaos_level` admin config. Nightmare mode sets level 4.
- **CVE-inspired header attacks** in `internal/headers/corruption.go` — CRLF injection (CVE-2019-9740), 65KB header overflow, null bytes in URI (CVE-2013-4547), duplicate Content-Length, unicode Transfer-Encoding bypass, and other real-world crash patterns sourced from open-source vulnerability reports.
- **Killer proxy mode** — sets ClientKiller probability to 100%, applying all client-killing attacks (H3 Alt-Svc confusion, header corruption, connection manipulation) on every proxied response.
- **Labyrinth pages are deterministic** — seeded from path via SHA-256 so the same URL always yields the same page.
- **Adaptive behavior** is per-client (keyed by fingerprint ID) and mode transitions happen in `adaptive/engine.go:evaluate()`.
- **Admin panel runs on a separate port** (default 8766), password-protected via `GLITCH_ADMIN_PASSWORD` env var (or `.env` file) or `-admin-password` flag (session cookies with 8-hour TTL). 5 tabs: Dashboard, Server (green), Scanner (cyan), Proxy (orange), Settings. Server tab uses collapsible sections. Scanner has 3 sub-tabs (Evaluate External, Built-in Scanner, PCAP Replay). External scanner sub-tab order: Launch, History, Results, Target Vulnerability Surface, Manual Upload.
- **Vulnerability groups** are map-based (`VulnGroups` slice): owasp, api_security, advanced, modern, infrastructure, iot_desktop, mobile_privacy, specialized, dashboard. Each group can be toggled via admin API; disabled groups return 404.
- **Nightmare mode** is per-subsystem (server/scanner/proxy) via `NightmareState` struct. Server nightmare snapshots all config + feature flags and applies extreme values. Proxy nightmare snapshots the previous proxy mode for restore. Global nightmare bar with pulsing red animation.
- **Selftest** has 6 modes: baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare. Crawl budget is capped at 30% of remaining time.
- **Vuln pages use "Acme Corp Portal" layout** — corporate-looking nav bar, sidebar, breadcrumbs, footer.
- **Content pages include JS API calls** — `fetch()` calls, `<link rel="prefetch">` hints, and hidden `<a>` tags so scanners discover API endpoints.
- **Config is fully serializable** — export/import via admin API, or load from file with `-config` flag. Settings auto-save to `.glitch-state.json` on every change and auto-load on startup (unless `-config` flag is used). With PostgreSQL enabled (`GLITCH_DB_URL` or `-db-url`), config is also persisted to the database and restored from DB on startup (falling back to state file if DB is unavailable).
- **PostgreSQL persistence** is optional — the server works without a database (file-only mode). When enabled, uses insert-only versioning (no UPDATE/DELETE on config data) with auto-incrementing version numbers. Views provide "current state" via `DISTINCT ON`. Schema is managed by embedded SQL migrations (`internal/storage/migrations/`). Tables: `config_versions` (versioned config snapshots), `scan_history` (append-only scan results), `metrics_snapshots` (periodic metrics), `client_profiles` (versioned per-client state), `request_log` (sampled request log), `schema_migrations` (migration tracking).
- **What survives restarts**: With PostgreSQL enabled, cumulative metrics counters (total_requests, total_errors, etc.) are saved every 30s via `StartMetricsSnapshotter` and restored on startup via `RestoreMetrics`. Client profiles are saved every 5 minutes and restored via `RestoreClientProfiles`. Config is saved on every change. Without PostgreSQL, only the `.glitch-state.json` file persists config — metrics and client profiles are lost. Session-specific data (ring buffer, time-series buckets, active connections) intentionally resets on restart.
- **Recorder is an operational flag** — `FeatureFlags.SetAll()` excludes `recorder` because traffic recording is an operational setting, not a chaos feature. Nightmare mode does not start/stop recording.
- **MCP subsystem** at `/mcp` implements Streamable HTTP transport (JSON-RPC 2.0 over POST, SSE via GET, session close via DELETE). Includes: (1) **Honeypot server** — fake tools (credential harvesters, data harvesters, budget drains), poisoned resources (fake .env, SSH keys, DB dumps, K8s secrets), trap prompts (injection via `<IMPORTANT>` blocks, rug pulls, cross-server exfiltration); (2) **Agent fingerprinting** — classifies MCP clients (Claude, GPT, Cursor, Windsurf) by clientInfo and behavioral signals (credential access, tool sequences, injection susceptibility), risk scoring 0-100; (3) **SSE transport** — event channels, `tools/listChanged` and `resources/listChanged` notifications, heartbeat keepalive, `Last-Event-ID` reconnection; (4) **Outbound scanner** (`internal/mcp/scanner.go`) — connects to external MCP servers, analyzes tool descriptions for injection patterns, detects credential harvesting, path traversal, rug pulls (hash-based tool description change detection), tests canary payloads for data exfiltration; supports custom headers for authentication and scan history persistence; (5) **Admin tools** at `/admin/mcp` — authenticated MCP endpoint with server management tools (toggle_feature, get_metrics, set_error_profile, nightmare_toggle, get_mcp_stats, list_sessions); (6) **Dashboard integration** — MCP section in Server tab (stats cards, events table, per-tool breakdown), MCP Scanner sub-tab in Scanner tab; (7) **Proxy interception** (`internal/proxy/mcp_interceptor.go`) — detects MCP traffic in transit, injects tools, poisons resources, modifies results, tracks sessions. Controlled via `mcp` feature flag. Session management via `Mcp-Session-Id` header. Individual MCP subsystems (honeypot, fingerprinting, trap prompts) are independently toggleable via admin config (`mcp_honeypot_enabled`, `mcp_fingerprint_enabled`, `mcp_trap_prompts_enabled`). Dashboard shows MCP endpoint visibility table and scanner history with custom header support.
- **Budget traps** are per-client escalating mechanisms that activate after a configurable request threshold. Traps include graduated tarpits (3 levels), fake vulnerability breadcrumbs (headers + HTML comments), infinite pagination, progressive content expansion (exponential link growth), streaming bait (slow chunked responses), and WebSocket honeypots (3-phase degradation). Controlled via `budget_traps` feature flag and `budget_trap_threshold` config.
- **No real external endpoints.** The server has zero externally accessible endpoints that bypass chaos. All public health paths (`/health`, `/ping`, `/status`, `/actuator`, etc.) are emulated and go through error injection. The only real health endpoint is `/_internal/<secret>/healthz`, hidden behind a secret path known only to Docker/CI/selftest. Set via `GLITCH_HEALTH_SECRET` env var or auto-generated. In handler dispatch, health paths are checked AFTER error injection but skip the honeypot (which would otherwise intercept them as scanner probes).
- **Systemd boot chain**: `docker.service` → `glitch-postgres.service` → `pg_isready` health gate → `glitch.service`. PostgreSQL runs in Docker; the glitch systemd service uses `Requires=glitch-postgres.service` and an `ExecStartPre` health gate to ensure DB is ready before starting. Application code also retries DB connection 5 times with backoff as a safety net.
- **DB connection retry**: `InitStorage()` retries up to 5 times with exponential backoff (2s, 4s, 6s, 8s, 10s) on startup. Returns a real error on final failure (not nil). This prevents data loss from startup race conditions with Docker PostgreSQL.
- **Every subsystem is controllable** — all feature toggles and config parameters are wired to their actual subsystems.
- **Avoid hard numbers in docs** — use qualitative language since counts change as the project evolves.
- **Keep docs in sync** — any change to the project (new feature, refactor, bug fix, config change) must update both `CLAUDE.md` and `readme.md` to reflect the current state. This applies to user requests too: if the user asks for a change, update both files as part of the work.

### Vuln Handler Routing Chain

In `vuln/owasp.go:ServeHTTP`, paths are routed in order with longer prefixes checked before shorter ones (api10 before api1, a10 before a01) to avoid prefix collisions.

### Admin Panel Architecture

- Data structures in `dashboard/admin.go`: FeatureFlags, AdminConfig, VulnConfig, ProxyConfig, NightmareState, ConfigExport (all thread-safe with sync.RWMutex)
- Auth in `dashboard/auth.go`: password validation, session cookies, ChangePassword()
- API routes in `dashboard/admin_routes.go`
- HTML/CSS/JS in `dashboard/admin_html.go`: single-page app with auto-refresh

## Branch & Merge Policy

**All non-trivial work MUST go through a Pull Request.** Direct pushes to `master` are only allowed for single-commit hotfixes. For any feature, refactor, or multi-file change:

1. Create a feature branch (e.g. `qa/atomic-tests`, `feature/new-subsystem`)
2. Commit often to the branch
3. When done, open a PR via `gh pr create`
4. CI must pass on the PR branch
5. Merge via PR (squash or merge commit)

### Test Maintenance Rules

- When any setting is **added** → corresponding atomic tests MUST be added
- When any setting is **changed** → corresponding tests MUST be updated
- When any setting is **removed** → corresponding tests MUST be removed
- Test suite must stay in sync with the codebase at all times
- PR reviews must verify test coverage for setting changes

## Pushing to Remote

**A green CI pipeline is a hard requirement for pushing to `master`.** Before pushing:

1. Run `go build ./...` and `go vet ./...` — must pass
2. Run `go test ./... -count=1 -timeout 600s` — must pass (unit, integration, regression)
3. Push to remote
4. Wait for CI pipeline to complete — **must be green**
5. If CI fails, fix the issue and push again before considering the work done

**Do NOT push and move on without confirming the pipeline is green.** A red pipeline means the push is broken and must be fixed immediately.

### CI vs Local Parity

Integration tests must not be flaky between local and CI. Common causes of local-vs-CI divergence:
- **Random chaos error types**: Tests against the chaos handler (e.g. `newTestHandler()`) may get slow error types (`slow_drip`, `slow_headers`, `delayed`) that cause timeouts. Fix: use the internal health path (`/_internal/<secret>/healthz`) for deterministic 200 responses, or add retries on subsystem paths like `/api/v1/users`. Never test response speed against `/` which routes through the error generator. Note: `/health` is subject to error injection — use `testInternalHealthPath` in test code for reliable health checks.
- **CI runners are slower**: Shared VMs have less CPU/memory. Use generous timeouts (30s+) for concurrent tests.
- **No running server in CI**: Acceptance tests that hit `localhost:8765` must skip gracefully when no server is running (`requireServer` pattern with `t.Skip`).

## Testing

```bash
go build ./...                   # compile all binaries
go vet ./...                     # static analysis
go test ./... -count=1 -timeout 600s  # all unit tests (timeout matching CI)
```

### Acceptance Tests (require running server)

```bash
./glitch &
go test ./tests/acceptance/ -count=1 -timeout 120s
go test ./tests/integration/ -count=1 -timeout 60s
```

### Regression Tests

```bash
go test ./tests/regression/ -count=1 -v   # regression suite
```

**Every bug fix MUST include a regression test** in `tests/regression/regression_test.go`:

- **Naming**: `TestRegression_<BugID>_<ShortDescription>` — BugID is task number or commit hash
- **Documentation**: Each test group starts with a comment block explaining:
  - What was broken (root cause)
  - How it was fixed
  - What the test verifies
- **JSON field conventions**: All Go structs serving JSON APIs use snake_case JSON tags. JS must reference snake_case property names to match. Add regression tests that marshal structs and verify field names are snake_case.
- **Structural conventions**: MatchedVuln has nested `{expected: VulnCategory, found: Finding}`. VulnCategory.Endpoints is an array (not singular). Finding uses `title` and `url` (not `name` and `endpoint`). scanner_crashed/scanner_timed_out/scanner_errors are top-level on ComparisonReport (not nested in scanner_health).

### PM Acceptance Testing

**This is the default quality gate.** After any implementation work, the PM agent runs acceptance tests against the live application and produces a structured pass/fail report. Work is not considered done until PM acceptance passes.

## Architecture Notes

### Server Request Flow
1. `server/handler.go:ServeHTTP` — fingerprints client, gets adaptive behavior
2. `handler.dispatch` — checks subsystem eligibility (honeypot, API, vuln, labyrinth), rolls error type, serves page
3. Every request is recorded in `metrics/collector.go` (ring buffer + per-client profile)
4. Adaptive engine re-evaluates client behavior periodically based on accumulated metrics
5. Dashboard reads from collector and adaptive engine via JSON APIs

### Scanner Evaluation Flow
1. External scanners are launched from admin panel (or CLI) against the server
2. Supported external scanners: nuclei, httpx, ffuf, nikto, nmap, wapiti — each with dedicated parsers and command-line configuration in `scaneval/runner.go`
3. Scanner results are auto-captured and parsed by `scaneval/` parsers
4. Results compared against `ExpectedProfile` (computed from enabled vulns/features)
5. False negatives are classified: "crawled_not_detected" (critical) vs "not_crawled" (crawling issue) by cross-referencing with server request logs via `metrics/collector.GetPathsInTimeWindow()`
6. Multi-scanner results displayed with per-scanner tabs and side-by-side comparison
7. Accuracy is a weighted score (0-100): detection contributes 70%, low false-positive rate contributes 30%
8. Built-in scanner tracks phases (crawling/generating/scanning/done) for UI progress feedback
9. ffuf uses a generated wordlist of hundreds of paths covering all vuln groups, APIs, honeypots, frameworks, and discovery paths

### Three-Way Architecture
```
Scanner → Proxy → Server
   ↓         ↓       ↓
   └─────────┴───────┘
         Dashboard
```

Each component can be replaced with a real service for testing. See `docs/PLAN.md` for the full architecture.

## Agent Team

See `~/.claude/agents/` for all available agents:

| Agent | Primary use in this project |
|-------|----------------------------|
| `team-lead` | Coordinate large feature implementations across multiple packages |
| `developer` | Implement new subsystems, vuln categories, API endpoints |
| `qa` | Code review, test coverage analysis, regression testing |
| `pm` | **Default quality gate** — acceptance testing after every implementation |
| `pentester` | Verify vuln endpoints are exploitable, scanner coverage testing |
| `sre` | Docker/K8s deployment, CI/CD pipelines, performance tuning |
| `consultant` | Go web server architecture decisions, stdlib patterns |
| `chaos-engineer` | Nightmare mode design, failure scenarios, survival criteria |
| `protocol-engineer` | TCP/HTTP protocol-level features, connection hijacking |
| `marketing` | README, project positioning, release announcements |

New agents can be created in `~/.claude/agents/<name>.md` — follow the existing format with YAML frontmatter + autonomous operation rules + responsibilities.

## Documentation

- `docs/real-world-findings.md` — Real-world scanner behavior findings from live deployment, documenting scanner weaknesses and budget-draining mechanisms
- `docs/server-destruction-findings.md` — Server destruction testing results against common HTTP servers

### Internal Progress Archive

A `progress/` folder may exist locally (excluded from git). It contains sprint logs, QA artifacts, research notes, PRDs, architecture plans, and development history. Check `progress/claude.md` for an index of its contents. This folder is not published.
