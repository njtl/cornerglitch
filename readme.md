# Glitch -- HTTP Chaos Testing Framework

**Break everything before production does.**

A 3-in-1 chaos testing framework that emulates every layer of the HTTP stack -- client, proxy, and server -- so you can find out what breaks before your users do. Go stdlib + PostgreSQL driver only.

---

## What is Glitch?

Every HTTP service lives in a chain: client, middleware, backend. Each layer assumes the others behave correctly. They don't. Glitch lets you replace any layer with a hostile, unreliable, or adversarial emulator so you can test what happens when things go wrong at every level.

If your service survives Glitch, it can handle production.

---

## Architecture

```
+-----------------+     +-----------------+     +-----------------+
| Glitch Scanner  |     |  Glitch Proxy   |     | Glitch Server   |
|    (Client)     |---->|  (Middleware)    |---->|   (Backend)     |
|                 |     |                 |     |                 |
| Attack payloads |     | Traffic manip   |     | Broken responses|
| Crawling        |     | WAF emulation   |     | Vuln endpoints  |
| Protocol abuse  |     | Latency inject  |     | Error injection |
| Fuzzing         |     | Connection drop |     | Adaptive behav. |
| Evasion         |     | Header rewrite  |     | Bot detection   |
+-----------------+     +-----------------+     +-----------------+
        |                       |                       |
+---------------------------------------------------------------+
|                   Unified Admin Dashboard                     |
|   Scanner progress | Proxy traffic | Server metrics | Config  |
+---------------------------------------------------------------+
```

---

## What are you testing?

| Your goal | Swap in | Keep yours |
|-----------|---------|------------|
| Test your scanner/DAST tool | | Glitch Server as the target |
| Test your backend resilience | Glitch Scanner as the attacker | |
| Test your proxy/WAF/gateway | Glitch Scanner + Glitch Server | Your proxy in the middle |
| Test your API gateway | Glitch Scanner + Glitch Server | Your gateway in the middle |
| Full self-test | Glitch Scanner | Glitch Proxy + Glitch Server |
| Nightmare survival test | All three Glitch components against each other | |

---

## Quick Start

### Glitch Server

```bash
# Recommended: configure .env first
cp .env.example .env                        # set admin password + database URL
make start                                  # build, start in background, show logs

# Lifecycle
make start                                  # build + start (logs: /tmp/glitch.log)
make stop                                   # graceful shutdown
make restart                                # stop + start
make status                                 # check if running
make logs                                   # tail server logs

# Direct usage (auto-loads .env)
go build -o glitch ./cmd/glitch
./glitch                                    # serves on :8765, dashboard on :8766
./glitch -port 9000 -dash-port 9001         # custom ports
./glitch -config config.json                # load saved configuration (overrides auto-saved state)
./glitch -nightmare                         # nightmare mode
```

> **Important**: Set `GLITCH_DB_URL` in your `.env` to enable PostgreSQL persistence. Without it, all metrics, scan history, and client data are lost on restart.

### Glitch Scanner

```bash
go build -o glitch-scanner ./cmd/glitch-scanner
./glitch-scanner -target http://localhost:8765
./glitch-scanner -target http://localhost:8765 -profile nightmare
./glitch-scanner -target http://localhost:8765 -profile destroyer   # server destruction testing
```

### Glitch Proxy

```bash
go build -o glitch-proxy ./cmd/glitch-proxy
./glitch-proxy -target http://localhost:8765 -mode chaos
./glitch-proxy -target http://localhost:8765 --chaos-prob 0.3 --waf-action block --rate-limit 100
```

### Docker

```bash
docker-compose up                           # runs server + dashboard + PostgreSQL
make docker-build                           # build image
make k8s-deploy                             # deploy to Kubernetes
make db-up                                  # start standalone PostgreSQL container
make db-down                                # stop PostgreSQL container
make db-reset                               # drop and recreate database
make db-psql                                # connect to PostgreSQL with psql
```

---

## Who is this for?

- **Scanner and DAST developers** -- benchmark detection accuracy against hundreds of realistic vulnerability endpoints covering all major OWASP Top 10 lists
- **Proxy, WAF, and API gateway developers** -- test traffic handling when both sides speak broken HTTP
- **Backend and API developers** -- stress-test your service against adversarial, malformed, and abusive client traffic
- **Security researchers** -- reproducible vulnerability surfaces for tool benchmarking and research
- **QA engineers** -- controlled failure injection at any layer of the HTTP stack
- **DevSecOps teams** -- validate pipeline security with scanner-proxy-server integration

---

## Key Features

### Glitch Server (backend emulator)

- Dozens of error types across three layers: HTTP errors, TCP-level errors (resets, drops, slow drip, partial bodies), and protocol-level glitches (version mismatches, header corruption, encoding conflicts, HTTP/2 frame chaos -- GOAWAY, RST_STREAM, SETTINGS flood, window exhaustion, CONTINUATION flood, PING flood)
- TLS chaos engine with 5 levels (clean, downgrade, weak cipher, cert chaos, nightmare) -- auto-generated self-signed certs, per-connection cert rotation, SNI-based mismatch, weak key certs, ALPN lies, per-client TLS config adaptation
- HSTS chaos -- random Strict-Transport-Security headers per client+path (lock, disable, short-lived, conflicting, missing, subdomain-only)
- H3/QUIC chaos engine with 4 levels -- injects Alt-Svc headers to trick clients into QUIC upgrades, fake UDP QUIC listener responding with malformed packets (Version Negotiation, Retry, Stateless Reset, garbage), emoji ports, null bytes, CRLF injection in Alt-Svc values
- CVE-inspired header attacks -- CRLF injection (CVE-2019-9740), 65KB header overflow, null bytes in URI (CVE-2013-4547), duplicate Content-Length, unicode Transfer-Encoding bypass, and other real-world crash patterns from open-source vulnerability reports
- HTTPS listener on port 8767 with HTTP/2 auto-enabled via ALPN, custom cert/key support
- Vulnerability emulation across all major OWASP Top 10 lists (Web, API, LLM, CI/CD, Cloud-Native, Mobile, Privacy, Client-Side, IoT, Serverless, and more) plus advanced categories -- realistic corporate-looking pages, not demo labels
- Infinite AI scraper labyrinth -- procedurally generated, deterministic page graph that traps crawlers
- Adaptive behavior engine -- fingerprints clients and adjusts hostility per-client in real time
- Bot detection with multi-signal scoring, JS traps, cookie traps, and CAPTCHA challenges
- Honeypot system with hundreds of known scanner paths and realistic lure responses
- Budget-draining traps -- graduated tarpits, fake vulnerability breadcrumbs, infinite pagination, progressive content expansion, streaming bait, and WebSocket honeypots that escalate based on per-client request volume
- MCP (Model Context Protocol) honeypot server -- fake tools (credential harvesters, data harvesters, budget drains), poisoned resources (fake .env, SSH keys, DB dumps, K8s secrets), and trap prompts with injection attacks, rug pulls, and cross-server exfiltration lures. Agent fingerprinting classifies MCP clients (Claude, GPT, Cursor, Windsurf) by behavioral signals. SSE transport with event notifications and heartbeat keepalive. Authenticated admin MCP endpoint at `/admin/mcp` for server management via AI agents (toggle features, get metrics, nightmare control). Individual subsystems (honeypot, fingerprinting, trap prompts) independently toggleable via admin config. Dashboard integration with stats cards, event log, per-tool breakdown, endpoint visibility table, and MCP scanner history
- Multiple content formats, visual themes, and framework emulation (Rails, Django, Express, Spring, Laravel, and more)
- REST API emulation (users, products, CMS, forms, infrastructure), GraphQL, Swagger/OpenAPI
- OAuth2/SSO flows, CDN emulation, search engine, email/webmail simulation, i18n, emulated health/actuator endpoints (all subject to error injection), WebSocket streams, analytics tracking, privacy/consent
- Traffic recording in JSONL and PCAP formats with replay support
- Spider data generation for crawler discovery
- Full admin panel with 5-tab layout (Dashboard, Server, Scanner, Proxy, Settings), three-column dashboard grouping by subsystem, clickable clients with detail/override, group-level preset buttons (All On/Off, Off/Low/Med/High/Max), per-mode nightmare toggles, feature flags, tunable parameters, and config import/export
- Settings auto-persist across restarts (saved to `.glitch-state.json` on every change, auto-loaded on startup)
- Optional PostgreSQL persistence (`GLITCH_DB_URL` or `-db-url`) with insert-only versioning -- all config changes, scan results, metrics snapshots, and client profiles are stored with full version history. Server degrades gracefully to file-only mode if the database is unavailable. Schema managed by embedded SQL migrations.
- Password-protected admin panel via `GLITCH_ADMIN_PASSWORD` env var (or `.env` file) or `-admin-password` flag

### Glitch Scanner (client emulator)

- Attack payloads matched to every vulnerability endpoint on the server
- Crawl engine with depth limiting, deduplication, and loop detection
- Resilience testing -- verifies graceful handling of every error type the server can throw
- Evasion modes for WAF bypass testing (encoding, header manipulation, fragmentation)
- Slow HTTP attack module -- slowloris, slow POST (RUDY), slow read, connection exhaustion, large headers, chunked abuse, multipart bombs, ReDoS payloads, compression bombs
- TLS attack module -- HSTS probing, TLS version probing (1.0-1.3), weak cipher enumeration, certificate analysis, ALPN probing, downgrade testing
- H3 attack module -- Alt-Svc confusion probes (emoji port, null byte, huge port, negative max-age, CRLF injection)
- CVE-inspired breakage attacks -- raw TCP payloads reproducing real-world crashes (CRLF injection, 65KB headers, null in URI, duplicate Content-Length, overlong UTF-8 Transfer-Encoding)
- Configurable profiles: compliance, aggressive, stealth, nightmare, destroyer, waf-buster
- Scanner evaluation: compare results against expected vulnerability surface, classify false negatives (crawled vs not-crawled), multi-scanner comparison with accuracy scoring
- Supported external scanners: nuclei, httpx, ffuf, nikto, nmap, wapiti -- launched and parsed automatically from the admin panel
- MCP scanner -- connects to external MCP servers and tests for security issues: injection patterns in tool descriptions, credential harvesting, path traversal in resources, rug pull detection (tool description changes), canary payload exfiltration testing. Risk scoring and structured JSON reports via dashboard. Supports custom headers for authentication and scan history persistence

### Glitch Proxy (middleware emulator)

- Interception pipeline for request and response manipulation
- Chaos injection: latency spikes, body corruption, connection resets, header rewriting
- WAF mode with signature-based blocking and rate limiting
- PCAP replay: load recorded traffic and replay through the proxy pipeline
- MCP traffic interception -- detects MCP JSON-RPC traffic in transit, injects honeypot tools, poisons resource content, modifies tool results, tracks sessions
- Configurable modes: transparent, WAF, chaos, gateway, nightmare, mirror (copies server settings), killer (100% client-killing attacks on every response -- H3 Alt-Svc confusion, header corruption, connection manipulation)

---

## Nightmare Mode

Run all three components at maximum adversarial settings simultaneously. The scanner floods with malformed requests and attack payloads. The proxy corrupts traffic in both directions. The server responds with broken HTTP, TCP resets, and infinite response bodies. A service passes nightmare testing if it does not crash, does not corrupt state, recovers to normal operation afterward, and maintains health check responses throughout. This is sustained, multi-vector adversarial testing -- not a single probe, but an ongoing assault from every direction at once.

Nightmare mode is per-subsystem -- you can activate it independently for server, scanner, and proxy from the admin panel. Server nightmare snapshots all current config and applies extreme values, restoring on deactivate.

---

## Health Endpoints

**The server has no real externally accessible health endpoints.** All public health-like paths (`/health`, `/health/live`, `/status`, `/ping`, `/actuator/health`, `/metrics`, `/debug/vars`, etc.) are emulated and subject to error injection like any other endpoint. They return realistic Spring Boot Actuator / Kubernetes health responses when no error is injected, but may return errors, timeouts, or corrupted responses at any time.

For internal health checking (Docker, CI, selftest), a secret path `/_internal/<secret>/healthz` bypasses all chaos and always returns `{"status":"ok"}`. The secret is configured via:

- `GLITCH_HEALTH_SECRET` environment variable (or `.env` file)
- Auto-generated on startup if not set (printed to stderr)

Docker Compose and the Dockerfile use this path for container health checks. The selftest pipeline generates its own secret per run.

---

## MCP (Model Context Protocol) Security Testing

Glitch includes a full MCP subsystem for testing AI agent security. The MCP honeypot server at `/mcp` implements Streamable HTTP transport (JSON-RPC 2.0 over POST, SSE via GET, session management via DELETE) and exposes fake tools, poisoned resources, and trap prompts designed to detect unsafe agent behaviors.

**Honeypot categories**: credential harvesters (fake AWS/GCP/Azure keys), data harvesters (system info, file listing), budget drains (large model calls), poisoned resources (fake `.env`, SSH keys, database dumps, Kubernetes secrets), and trap prompts (injection via `<IMPORTANT>` blocks, rug pulls, cross-server exfiltration lures).

**Agent fingerprinting**: MCP clients are classified by their `clientInfo` handshake (Claude, GPT, Cursor, Windsurf, custom, unknown) and monitored for behavioral signals -- credential access patterns, tool call sequences, resource read patterns, and injection susceptibility. Each session gets a risk score (0-100).

**MCP scanner**: An outbound scanner that connects to external MCP servers and tests their security posture -- analyzes tool descriptions for injection patterns, detects credential harvesting, checks for path traversal in resource URIs, performs rug pull detection (hashes tool descriptions and detects changes), and tests canary payloads for data exfiltration. Available from the Scanner tab in the dashboard.

**Admin MCP tools**: An authenticated MCP endpoint at `/admin/mcp` exposes server management tools (toggle features, get metrics, set error profiles, nightmare control, MCP stats, session listing) for authorized AI agents.

**Proxy MCP interception**: The proxy detects MCP traffic in transit and can inject additional tools, poison resource content, modify tool results, and track sessions -- testing how agents handle man-in-the-middle scenarios.

---

## Self-Test

Glitch can test itself. Run all three components against each other to validate the entire framework end-to-end, or use it as a demo of what full-stack chaos looks like.

```bash
glitch selftest                              # baseline mode
glitch selftest --mode scanner-stress        # high-throughput scanner test
glitch selftest --mode proxy-stress          # traffic through proxy under load
glitch selftest --mode server-stress         # maximum request rate
glitch selftest --mode chaos                 # all components with evasion
glitch selftest --mode nightmare             # maximum adversarial
```

---

## Configuration

The server auto-loads `.env` from the working directory on startup. No need to manually `source` it. CLI flags and explicit env vars always take precedence over `.env` values.

```bash
cp .env.example .env    # then edit with your values
```

| Variable | Required | Purpose | Default |
|----------|----------|---------|---------|
| `GLITCH_ADMIN_PASSWORD` | Recommended | Dashboard login password | Auto-generated (printed to stderr) |
| `GLITCH_DB_URL` | **Yes** for persistence | PostgreSQL connection string | None (memory-only mode) |
| `PASSWORD_RESET_FROM_ENV` | No | Set to `1` to force-reset password from env | `0` (disabled) |
| `GLITCH_TLS_CERT` | No | Path to TLS certificate file | Auto-generated self-signed |
| `GLITCH_TLS_KEY` | No | Path to TLS private key file | Auto-generated self-signed |

> **Password persistence**: Password changes via the admin UI are saved to the database. On restart, the DB password takes priority over the `.env` value. To recover from a forgotten password, set `PASSWORD_RESET_FROM_ENV=1` — this overwrites the DB password with `GLITCH_ADMIN_PASSWORD` on next startup. Remove the flag after resetting.

> **Warning**: Without `GLITCH_DB_URL`, the server runs in memory-only mode. All metrics, scan history, client profiles, and configuration are lost on restart. The server logs a warning when no database URL is configured.

## Deployment

### Local Development

```bash
# Quick start
cp .env.example .env                        # configure password + database
make db-up                                  # start PostgreSQL (Docker)
make start                                  # build + start in background

# Lifecycle
make start          # build + start in background (logs: /tmp/glitch.log)
make stop           # graceful shutdown (saves metrics to DB)
make restart        # stop + start
make status         # check if running
make logs           # tail -f /tmp/glitch.log
make run            # build + run in foreground
```

### Docker Compose

```bash
docker-compose up                            # server + dashboard + PostgreSQL
docker-compose up -d                         # detached mode
```

Includes PostgreSQL 16 with health checks, named volumes for data persistence, and automatic `GLITCH_DB_URL` wiring. The server waits for PostgreSQL to be healthy before starting. Set `GLITCH_ADMIN_PASSWORD` in your `.env` or environment. Container health checks use the secret internal health endpoint (`/_internal/<secret>/healthz`) — configure via `GLITCH_HEALTH_SECRET` env var or use the default.

### Kubernetes

```bash
# Edit the secret first — change the base64-encoded GLITCH_ADMIN_PASSWORD
vim deploy/k8s/postgres-secret.yaml

kubectl apply -f deploy/k8s/                 # full deployment
```

Includes: namespace, deployment, service, ingress, configmap, PostgreSQL StatefulSet with persistent volume claim, and secrets for database credentials and admin password.

### Systemd

```bash
# Install environment file
sudo mkdir -p /etc/glitch
sudo cp deploy/systemd/glitch.env /etc/glitch/glitch.env
sudo chmod 600 /etc/glitch/glitch.env
sudo vim /etc/glitch/glitch.env              # set GLITCH_ADMIN_PASSWORD

# Install and enable services
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now glitch-postgres glitch-server

# Optional: proxy
sudo systemctl enable --now glitch-proxy
```

The server service loads environment from `/etc/glitch/glitch.env` and depends on the PostgreSQL service. Configure `glitch.env` from the provided template before starting.

### Makefile Reference

```bash
# Build
make build          # build server binary
make cross          # cross-compile for Linux/Darwin (amd64/arm64)
make docker-build   # build Docker image

# Test
make test           # run all tests
make vet            # static analysis

# Run
make start          # build + start in background
make stop           # graceful shutdown
make restart        # stop + start
make status         # check if running
make logs           # tail server logs
make run            # build + run in foreground

# Database
make db-up          # start PostgreSQL container
make db-down        # stop PostgreSQL container
make db-reset       # drop and recreate database
make db-psql        # connect to PostgreSQL with psql

# Deploy
make docker-push    # push image to GHCR
make k8s-deploy     # deploy to Kubernetes
```

---

## Architecture Overview

The server, scanner, and proxy are separate binaries built from `cmd/`. All internal logic lives under `internal/` organized by subsystem. The server has dozens of subsystems including error generation, page rendering, vulnerability emulation, fingerprinting, adaptive behavior, bot detection, honeypot, API emulation, OAuth, CDN, search, email, WebSocket, traffic recording, API chaos engine, media chaos engine (procedural generation and corruption of images, audio, video, and streaming formats), and a full admin dashboard with live metrics. The proxy adds an interception pipeline with chaos, WAF, corruption, and replay modules. The scanner adds attack, evasion, resilience, and crawl modules with multi-scanner evaluation. See `docs/PLAN.md` for the full architecture plan and `docs/` for component-level PRDs.

### Server Destruction Testing

The destroyer profile (`-profile destroyer`) runs all attack modules at maximum concurrency (200 workers, no rate limit, 60s timeout) with no crawling -- direct assault. Docker Compose targets in `tests/targets/` provide 7 common HTTP servers (Express, Flask, Django, Go net/http, Nginx, Apache, Puma) for benchmarking server resilience. See [`docs/server-destruction-findings.md`](docs/server-destruction-findings.md) for detailed results.

### Real-World Scanner Behavior

Glitch has been tested against real-world scanners on a public internet host. Documented findings include crawlers tar-pitted for hours by slow-drip media downloads, `.env` scanners defeated by escalating bot detection, Nmap-style probes neutralized by keepalive abuse, and AI scrapers stuck in infinite sitemap polling loops. These observations inform the server's anti-scanner design and identify exploitable weaknesses in common scanner architectures (no download limits, no honeypot detection, no connection pool management, no content deduplication, no adaptive strategy). See [`docs/real-world-findings.md`](docs/real-world-findings.md) for detailed case studies and budget-draining mechanism ideas.

---

## Use Cases

### Benchmark your DAST scanner

Point your scanner at Glitch Server running with all vulnerability groups enabled. Glitch covers every major OWASP Top 10 list with realistic, corporate-looking vulnerability pages. After the scan, use the built-in scanner evaluation to see exactly which vulnerabilities your tool found, which it missed, and whether it even crawled the right paths. Compare multiple scanners side-by-side with accuracy scoring.

```bash
make start                                          # start Glitch Server
nuclei -u http://localhost:8765 -o results.json     # run your scanner
# Open dashboard at :8766 → Scanner tab → upload results for analysis
```

### Stress-test your backend

Use Glitch Scanner with the `destroyer` profile to throw raw TCP attacks, slow HTTP floods, malformed requests, and protocol abuse at your service. The `waf-buster` profile tests WAF bypass with encoding tricks, request smuggling, and header manipulation.

```bash
glitch-scanner -target http://your-service:8080 -profile destroyer    # max destruction
glitch-scanner -target http://your-service:8080 -profile waf-buster   # WAF bypass testing
```

### Validate your proxy/WAF/API gateway

Put your proxy between Glitch Scanner and Glitch Server. Both sides speak broken HTTP -- does your proxy handle it gracefully, or does it crash, leak data, or silently corrupt traffic?

```bash
./glitch &                                                    # hostile backend on :8765
glitch-scanner -target http://your-proxy:8080 -profile nightmare   # hostile client
```

### Test AI agent security

The MCP honeypot at `/mcp` exposes fake tools with prompt injection traps, poisoned resources (fake `.env` files, SSH keys, database dumps), and rug-pull detection. Point your AI coding agent at Glitch and see if it leaks credentials, follows injection instructions, or falls for fake tool descriptions.

### Run as a honeypot

Deploy Glitch on a public-facing server. The adaptive behavior engine fingerprints every visitor, the labyrinth traps crawlers in infinite procedural page graphs, and budget-draining traps escalate against persistent scanners. All traffic is recorded with full metrics visible in the dashboard.

### Get started with AI assistance

You don't need to configure anything manually. Clone the repo, open Claude Code (or any AI coding assistant), and tell it to set up and run Glitch. The `CLAUDE.md` and README contain everything an AI agent needs to build, configure, and start experimenting.

```bash
git clone https://github.com/njtl/cornerglitch.git
cd cornerglitch
claude   # "set up and run Glitch, then show me the dashboard"
```

---

## Real-World Findings

Glitch has been deployed as a live honeypot and tested against popular security tools. Key discoveries:

- **Null byte in headers crashes most scanners** -- a single `\x00` in a response header (`X-Chaos: before\x00after`) kills Go's HTTP parser (Gobuster, Feroxbuster), hangs Python's urllib (Commix), and causes Ruby's NilClass errors (WhatWeb)
- **HTTP 102 (Processing) aborts SQLMap** -- SQLMap has no handler for 1xx status codes and immediately gives up
- **Nuclei achieves 0% detection** under nightmare mode -- error injection and delays prevent template matchers from seeing expected patterns
- **ZAP runs out of memory** -- the infinite labyrinth generates unlimited URLs, each with API endpoints and media links, exhausting JVM heap
- **Nmap hangs indefinitely** -- service version detection (`-sV`) can't parse corrupted responses and never completes
- **Real crawlers hold connections for 2+ hours** downloading procedurally generated audio files
- **AI scrapers poll robots.txt for 23 hours straight** in infinite loops

See [`docs/real-world-findings.md`](docs/real-world-findings.md) for detailed case studies.

---

## Contributing

Glitch uses Go stdlib plus `github.com/lib/pq` (PostgreSQL driver). Build with `go build ./...`, run static analysis with `go vet ./...`, and test with `go test ./...`. Storage tests require a running PostgreSQL instance (skipped automatically if unavailable).

## License

MIT
