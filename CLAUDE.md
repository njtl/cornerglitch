# CLAUDE.md — Glitch Web Server

## What is this project?

An intentionally unreliable, adaptive HTTP server written in Go. Designed as a "DVWA on steroids" — a comprehensive scanner testing target with 347+ vulnerability endpoints across all 18 OWASP Top 10 lists, 30 error types, 8 page formats, an infinite scraper labyrinth, client fingerprinting, and adaptive behavior. A full admin panel exposes all internal state with 21 feature toggles, 19+ config parameters, and real-time monitoring.

## Build & Run

```bash
go build -o glitch ./cmd/glitch    # build
./glitch                            # run (ports 8765 + 8766)
./glitch -port 9000 -dash-port 9001 # custom ports
./glitch -config config.json        # load saved configuration
```

No external dependencies — stdlib only, go 1.24+.

## Project Layout

```
cmd/glitch/main.go              Entry point, flag parsing, graceful shutdown, config loading
internal/
  server/handler.go              Main request handler — dispatches to all 30+ subsystems
  errors/generator.go            30 error types (22 HTTP + 8 TCP) with weighted probability profiles
  pages/generator.go             8 content generators (HTML, JSON, XML, CSV, SSE, etc.)
  content/engine.go              Deterministic page generation with JS API calls for scanner discovery
  labyrinth/labyrinth.go         Infinite procedural page graph for trapping scrapers
  fingerprint/engine.go          Client ID via headers, UA classification, IP
  adaptive/engine.go             8 behavior modes, re-evaluates per client every 30s
  metrics/collector.go           Ring buffer (10k records), time series, per-client profiles
  dashboard/
    server.go                    Dashboard HTTP server (port 8766)
    admin.go                     Admin data structures, singletons, config import/export
    admin_routes.go              Admin API endpoints (toggles, config, vulns, scanner, PCAP)
    admin_html.go                Admin panel HTML/CSS/JS (7 tabs, 21 toggles, full controls)
  vuln/
    owasp.go                     OWASP Web Top 10 (2021) + routing for all vuln categories
    api_security.go              OWASP API Security Top 10 (2023) — 50 endpoints
    modern.go                    LLM Top 10 (2025), CI/CD Top 10 (2022), Cloud-Native Top 10 (2022)
    mobile_privacy.go            Mobile Top 10 (2024), Privacy Top 10 (2021), Client-Side Top 10 (2024)
    infrastructure.go            Serverless Top 10 (2018), Docker Top 10 (2019), K8s Top 10 (2022)
    iot_desktop.go               IoT Top 10 (2018), Desktop App Top 10 (2021), Low-Code Top 10 (2022)
    specialized.go               Proactive Controls (2024), ML Security (2023), Data Security (2025), Web 2025
  api/                           REST API handlers (users, products, CMS, forms, infra)
  honeypot/                      Honeypot lure paths and response generation
  botdetect/                     Bot detection scoring and classification
  captcha/                       CAPTCHA challenge system
  framework/                     Framework emulation (Rails, Django, Express, Spring, Laravel)
  headers/                       Header corruption engine
  cookies/                       Cookie trap system
  jstrap/                        JavaScript trap challenges
  proxy/                         Reverse proxy with scoring-based interception
  scanner/                       Scanner profile, comparison, and coverage analysis
  recorder/                      Traffic recording (JSONL/PCAP formats)
  health/                        Health endpoints + Spring Boot Actuator emulation
  search/                        Search engine simulation
  email/                         Email/webmail simulation
  oauth/                         OAuth/SSO discovery and token endpoints
  cdn/                           CDN static asset emulation
  i18n/                          Internationalization (12 languages)
  privacy/                       Privacy policy and consent flows
  websocket/                     WebSocket endpoint
  analytics/                     Analytics and tracking simulation
tests/
  acceptance/acceptance_test.go  55+ acceptance tests (14 sections)
  integration/                   Integration tests
deploy/
  k8s/                           Kubernetes manifests (deployment, service, configmap, ingress)
.github/workflows/               CI (lint/test/build) + Docker multi-arch push
Dockerfile                       Multi-stage, non-root, healthcheck
docker-compose.yml               Local deployment with volumes
Makefile                         build, test, vet, clean, docker-build, k8s-deploy, run, cross
```

## Key Conventions

- **Zero external deps.** Everything uses Go stdlib. Do not add third-party modules.
- **All server logic is in `internal/`.** Nothing in `internal/` is meant to be imported by external code.
- **Error profiles are probability maps** (`map[ErrorType]float64`). Weights should sum to ~1.0.
- **Labyrinth pages are deterministic** — seeded from path via SHA-256 so the same URL always yields the same page.
- **Adaptive behavior** is per-client (keyed by fingerprint ID) and mode transitions happen in `adaptive/engine.go:evaluate()`.
- **Admin panel runs on a separate port** (default 8766) with 7 tabs: Dashboard, Sessions, Traffic, Controls, Request Log, Vulnerabilities, Scanner.
- **Vuln pages use "Acme Corp Portal" layout** — nav bar, sidebar, breadcrumbs, footer. They look like a real corporate web app, not demo pages.
- **Content pages include JS API calls** — `fetch()` calls, `<link rel="prefetch">` hints, and hidden `<a>` tags so scanners discover API endpoints.
- **Config is fully serializable** — export/import via `/admin/api/config/export` and `/admin/api/config/import`, or load from file with `-config` flag.
- **Every subsystem is controllable** — all 21 feature toggles and 19+ config parameters are wired to their actual subsystems, not just stored in config.

## Testing

```bash
go build ./cmd/glitch/           # compile check
go vet ./...                     # static analysis
go test ./... -count=1           # all unit tests (30 packages, 1500+ test functions)
```

### Acceptance Tests (require running server)

```bash
./glitch &                                          # start server first
go test ./tests/acceptance/ -count=1 -timeout 120s  # 55+ acceptance tests
go test ./tests/integration/ -count=1 -timeout 60s  # integration tests
```

### PM Acceptance Testing

**This is the default quality gate.** After any implementation work, the PM agent runs acceptance tests against the live application and produces a structured pass/fail report. Work is not considered done until PM acceptance passes.

The acceptance suite covers 14 sections: Dashboard metrics, Sessions, Feature toggles, Config parameters, Error/page weights, Vulnerability controls, Config import/export, PCAP recording, Bot detection, Scanner framework, Subsystem responses, Blocking/adaptive, Request log, Admin panel HTML, and OWASP categories.

## Architecture Notes

Request flow:
1. `server/handler.go:ServeHTTP` — fingerprints client, gets adaptive behavior
2. `handler.dispatch` — checks subsystem eligibility (honeypot, API, vuln, labyrinth), rolls error type, serves page
3. Every request is recorded in `metrics/collector.go` (ring buffer + per-client profile)
4. Adaptive engine re-evaluates client behavior every 30s based on accumulated metrics
5. Dashboard reads from collector and adaptive engine via JSON APIs

The adaptive engine classifies clients into: browser, search_bot, ai_scraper, script_bot, api_tester, load_tester, unknown — then assigns a behavior mode accordingly.

### Vuln Handler Routing Chain

In `vuln/owasp.go:ServeHTTP`, paths are routed in this order:
1. OWASP Web Top 10 A01-A10 (note: A10 must be checked before A01 to avoid prefix collision)
2. API Security Top 10 (same: api10 before api1)
3. Advanced categories (CORS, XXE, SSTI, JWT, etc.)
4. Modern categories (LLM, CI/CD, Cloud-Native)
5. Infrastructure (Serverless, Docker, K8s)
6. IoT/Desktop/Low-Code
7. Mobile/Privacy/Client-Side
8. Specialized (Proactive Controls, ML Security, Data Security, Web 2025)
9. Dashboard/Settings vulns

### Admin Panel Architecture

- Data structures in `dashboard/admin.go`: FeatureFlags, AdminConfig, VulnConfig, ConfigExport (all thread-safe with sync.RWMutex)
- API routes in `dashboard/admin_routes.go`: 30+ endpoints for toggles, config, vulns, scanner, PCAP, blocking, clients
- HTML/CSS/JS in `dashboard/admin_html.go`: single-page app with 7 tabs, auto-refresh, file upload/download

## Agent Team

See `~/.claude/agents/` for all available agents. Key agents for this project:

| Agent | Primary use in this project |
|-------|----------------------------|
| `team-lead` | Coordinate large feature implementations across multiple packages |
| `developer` | Implement new subsystems, vuln categories, API endpoints |
| `qa` | Code review, test coverage analysis, regression testing |
| `pm` | **Default quality gate** — acceptance testing after every implementation |
| `pentester` | Verify vuln endpoints are exploitable, scanner coverage testing |
| `sre` | Docker/K8s deployment, CI/CD pipelines, performance tuning |
| `consultant` | Go web server architecture decisions, stdlib patterns |
| `marketing` | README, project positioning, release announcements |

New agents can be created in `~/.claude/agents/<name>.md` when needed — follow the existing format with YAML frontmatter + autonomous operation rules + responsibilities.

## Project Stats

| Metric | Value |
|--------|-------|
| Vulnerability endpoints | ~347 |
| OWASP Top 10 lists | 18 |
| Error types | 30 (22 HTTP + 8 TCP) |
| Test functions | 1,506 |
| Packages with tests | 30 |
| Go source files | 98 |
| Lines of code | ~89,670 |
| External dependencies | 0 (stdlib only) |
