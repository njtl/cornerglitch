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
# Server (backend emulator)
go build -o glitch ./cmd/glitch
./glitch                                    # ports 8765 + 8766
./glitch -port 9000 -dash-port 9001         # custom ports
./glitch -config config.json                # load saved configuration
./glitch -nightmare                         # nightmare mode
GLITCH_ADMIN_PASSWORD=secret ./glitch       # set admin password (or -admin-password flag, or .env file)

# Scanner (client emulator)
go build -o glitch-scanner ./cmd/glitch-scanner
glitch-scanner -target http://localhost:8765
glitch-scanner -target http://localhost:8765 -profile nightmare

# Proxy (middleware emulator)
go build -o glitch-proxy ./cmd/glitch-proxy
glitch-proxy -target http://localhost:8765 -mode chaos
glitch-proxy -target http://localhost:8765 --chaos-prob 0.3 --waf-action block

# Self-test (all three against each other)
glitch selftest --mode nightmare --duration 60s
glitch selftest --mode baseline              # also: scanner-stress, proxy-stress, server-stress, chaos

# Docker
docker-compose up                            # runs server + dashboard
```

No external dependencies — stdlib only, go 1.24+.

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

  # Scanner subsystems
  scanner/
    engine.go                    Scanner orchestrator
    config.go                    Configuration and profiles
    crawler.go                   Page/API discovery
    reporter.go                  Findings and coverage reports
    attacks/                     Attack modules (owasp, injection, fuzzing, protocol, auth)
    resilience/                  Error handling, timeouts, connections
    evasion/                     WAF bypass, encoding, fragmentation
    profiles/                    Scan profiles (aggressive, stealth, nightmare, compliance)

  # Proxy subsystems
  proxy/                         Core proxy + interception pipeline
    chaos/                       Chaos modules (latency, corruption, connection, rewrite)
    waf/                         WAF modules (signatures, ratelimit, geoblock, botblock)
    modes/                       Mode implementations (transparent, waf, chaos, nightmare, mirror)

  # Scanner evaluation (comparison tool)
  scaneval/                      Scanner profile comparison, coverage matrix

  # Self-test
  selftest/                      Pipeline orchestration, monitoring, reporting

Dockerfile                       Multi-stage build (non-root, healthcheck)
docker-compose.yml               Server + dashboard with volumes/env config
Makefile                         build, test, vet, clean, docker-build, run, cross
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

- **Zero external deps.** Everything uses Go stdlib. Do not add third-party modules.
- **All logic is in `internal/`.** Nothing in `internal/` is meant to be imported by external code.
- **Error profiles are probability maps** (`map[ErrorType]float64`). Weights should sum to ~1.0. Includes HTTP errors, TCP-level errors, and protocol-level glitches (18 types: version mismatches, header corruption, encoding conflicts, connection tricks). Protocol glitches are togglable via admin config (`protocol_glitch_enabled`, `protocol_glitch_level` 0-4).
- **Labyrinth pages are deterministic** — seeded from path via SHA-256 so the same URL always yields the same page.
- **Adaptive behavior** is per-client (keyed by fingerprint ID) and mode transitions happen in `adaptive/engine.go:evaluate()`.
- **Admin panel runs on a separate port** (default 8766), password-protected via `GLITCH_ADMIN_PASSWORD` env var (or `.env` file) or `-admin-password` flag (session cookies with 8-hour TTL). 5 tabs: Dashboard, Server (green), Scanner (cyan), Proxy (orange), Settings. Server tab uses collapsible sections. Scanner has 3 sub-tabs (Evaluate External, Built-in Scanner, PCAP Replay). External scanner sub-tab order: Launch, History, Results, Target Vulnerability Surface, Manual Upload.
- **Vulnerability groups** are map-based (`VulnGroups` slice): owasp, api_security, advanced, modern, infrastructure, iot_desktop, mobile_privacy, specialized, dashboard. Each group can be toggled via admin API; disabled groups return 404.
- **Nightmare mode** is per-subsystem (server/scanner/proxy) via `NightmareState` struct. Server nightmare snapshots all config + feature flags and applies extreme values. Proxy nightmare snapshots the previous proxy mode for restore. Global nightmare bar with pulsing red animation.
- **Selftest** has 6 modes: baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare. Crawl budget is capped at 30% of remaining time.
- **Vuln pages use "Acme Corp Portal" layout** — corporate-looking nav bar, sidebar, breadcrumbs, footer.
- **Content pages include JS API calls** — `fetch()` calls, `<link rel="prefetch">` hints, and hidden `<a>` tags so scanners discover API endpoints.
- **Config is fully serializable** — export/import via admin API, or load from file with `-config` flag.
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

## Pushing to Remote

**A green CI pipeline is a hard requirement for pushing to `master`.** Before pushing:

1. Run `go build ./...` and `go vet ./...` — must pass
2. Run `go test ./... -count=1 -timeout 300s` — must pass (unit, integration, regression)
3. Push to remote
4. Wait for CI pipeline to complete — **must be green**
5. If CI fails, fix the issue and push again before considering the work done

**Do NOT push and move on without confirming the pipeline is green.** A red pipeline means the push is broken and must be fixed immediately.

### CI vs Local Parity

Integration tests must not be flaky between local and CI. Common causes of local-vs-CI divergence:
- **Random chaos error types**: Tests against the chaos handler (e.g. `newTestHandler()`) may get slow error types (`slow_drip`, `slow_headers`, `delayed`) that cause timeouts. Fix: use deterministic subsystem paths (e.g. `/health`, `/api/v1/users`) or add retries. Never test response speed against `/` which routes through the error generator.
- **CI runners are slower**: Shared VMs have less CPU/memory. Use generous timeouts (30s+) for concurrent tests.
- **No running server in CI**: Acceptance tests that hit `localhost:8765` must skip gracefully when no server is running (`requireServer` pattern with `t.Skip`).

## Testing

```bash
go build ./...                   # compile all binaries
go vet ./...                     # static analysis
go test ./... -count=1 -timeout 300s  # all unit tests (with timeout matching CI)
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

- `docs/PLAN.md` — Master architecture plan for the 3-way framework
- `docs/PRD-scanner.md` — Scanner component PRD
- `docs/PRD-proxy.md` — Proxy component PRD
- `docs/PRD-nightmare.md` — Nightmare mode PRD
- `docs/PRD-selftest.md` — Self-test pipeline PRD
- `docs/scanner_redesign.md` — Scanner subsystem redesign notes
- `docs/ui_refactoring_plan.md` — Admin panel UI refactoring plan
