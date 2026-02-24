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

# Scanner (client emulator)
go build -o glitch-scanner ./cmd/glitch-scanner
glitch-scanner -target http://localhost:8765
glitch-scanner -target http://localhost:8765 -profile nightmare

# Proxy (middleware emulator)
go build -o glitch-proxy ./cmd/glitch-proxy
glitch-proxy -target http://localhost:8765 -mode chaos

# Self-test (all three against each other)
glitch selftest --mode nightmare --duration 60s
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
  errors/generator.go            Error types (HTTP + TCP) with weighted probability profiles
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
    modes/                       Mode implementations (transparent, waf, chaos, nightmare)

  # Scanner evaluation (comparison tool)
  scaneval/                      Scanner profile comparison, coverage matrix

  # Self-test
  selftest/                      Pipeline orchestration, monitoring, reporting

docs/                            PRDs, architecture plan
tests/
  acceptance/                    Acceptance tests
  integration/                   Integration tests
  nightmare/                     Nightmare mode survival tests
```

## Key Conventions

- **Zero external deps.** Everything uses Go stdlib. Do not add third-party modules.
- **All logic is in `internal/`.** Nothing in `internal/` is meant to be imported by external code.
- **Error profiles are probability maps** (`map[ErrorType]float64`). Weights should sum to ~1.0.
- **Labyrinth pages are deterministic** — seeded from path via SHA-256 so the same URL always yields the same page.
- **Adaptive behavior** is per-client (keyed by fingerprint ID) and mode transitions happen in `adaptive/engine.go:evaluate()`.
- **Admin panel runs on a separate port** (default 8766) with 5 tabs: Dashboard, Server (green), Scanner (cyan), Proxy (orange), Settings. Server tab uses collapsible sections. Scanner has 3 sub-tabs (Evaluate External, Built-in Scanner, PCAP Replay).
- **Vuln pages use "Acme Corp Portal" layout** — corporate-looking nav bar, sidebar, breadcrumbs, footer.
- **Content pages include JS API calls** — `fetch()` calls, `<link rel="prefetch">` hints, and hidden `<a>` tags so scanners discover API endpoints.
- **Config is fully serializable** — export/import via admin API, or load from file with `-config` flag.
- **Every subsystem is controllable** — all feature toggles and config parameters are wired to their actual subsystems.
- **Avoid hard numbers in docs** — use qualitative language since counts change as the project evolves.

### Vuln Handler Routing Chain

In `vuln/owasp.go:ServeHTTP`, paths are routed in order with longer prefixes checked before shorter ones (api10 before api1, a10 before a01) to avoid prefix collisions.

### Admin Panel Architecture

- Data structures in `dashboard/admin.go`: FeatureFlags, AdminConfig, VulnConfig, ConfigExport (all thread-safe with sync.RWMutex)
- API routes in `dashboard/admin_routes.go`
- HTML/CSS/JS in `dashboard/admin_html.go`: single-page app with auto-refresh

## Testing

```bash
go build ./...                   # compile all binaries
go vet ./...                     # static analysis
go test ./... -count=1           # all unit tests
```

### Acceptance Tests (require running server)

```bash
./glitch &
go test ./tests/acceptance/ -count=1 -timeout 120s
go test ./tests/integration/ -count=1 -timeout 60s
```

### PM Acceptance Testing

**This is the default quality gate.** After any implementation work, the PM agent runs acceptance tests against the live application and produces a structured pass/fail report. Work is not considered done until PM acceptance passes.

## Architecture Notes

### Server Request Flow
1. `server/handler.go:ServeHTTP` — fingerprints client, gets adaptive behavior
2. `handler.dispatch` — checks subsystem eligibility (honeypot, API, vuln, labyrinth), rolls error type, serves page
3. Every request is recorded in `metrics/collector.go` (ring buffer + per-client profile)
4. Adaptive engine re-evaluates client behavior periodically based on accumulated metrics
5. Dashboard reads from collector and adaptive engine via JSON APIs

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
- `done_*.md` — Work session logs with PM feedback tracking
