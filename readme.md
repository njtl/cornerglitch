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

- Dozens of error types across three layers: HTTP errors, TCP-level errors (resets, drops, slow drip, partial bodies), and protocol-level glitches (version mismatches, header corruption, encoding conflicts)
- Vulnerability emulation across all major OWASP Top 10 lists (Web, API, LLM, CI/CD, Cloud-Native, Mobile, Privacy, Client-Side, IoT, Serverless, and more) plus advanced categories -- realistic corporate-looking pages, not demo labels
- Infinite AI scraper labyrinth -- procedurally generated, deterministic page graph that traps crawlers
- Adaptive behavior engine -- fingerprints clients and adjusts hostility per-client in real time
- Bot detection with multi-signal scoring, JS traps, cookie traps, and CAPTCHA challenges
- Honeypot system with hundreds of known scanner paths and realistic lure responses
- Multiple content formats, visual themes, and framework emulation (Rails, Django, Express, Spring, Laravel, and more)
- REST API emulation (users, products, CMS, forms, infrastructure), GraphQL, Swagger/OpenAPI
- OAuth2/SSO flows, CDN emulation, search engine, email/webmail simulation, i18n, health/actuator endpoints, WebSocket streams, analytics tracking, privacy/consent
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
- Configurable profiles: compliance, aggressive, stealth, nightmare
- Scanner evaluation: compare results against expected vulnerability surface, classify false negatives (crawled vs not-crawled), multi-scanner comparison with accuracy scoring
- Supported external scanners: nuclei, httpx, ffuf, nikto, nmap, wapiti -- launched and parsed automatically from the admin panel

### Glitch Proxy (middleware emulator)

- Interception pipeline for request and response manipulation
- Chaos injection: latency spikes, body corruption, connection resets, header rewriting
- WAF mode with signature-based blocking and rate limiting
- PCAP replay: load recorded traffic and replay through the proxy pipeline
- Configurable modes: transparent, WAF, chaos, gateway, nightmare, mirror (copies server settings)

---

## Nightmare Mode

Run all three components at maximum adversarial settings simultaneously. The scanner floods with malformed requests and attack payloads. The proxy corrupts traffic in both directions. The server responds with broken HTTP, TCP resets, and infinite response bodies. A service passes nightmare testing if it does not crash, does not corrupt state, recovers to normal operation afterward, and maintains health check responses throughout. This is sustained, multi-vector adversarial testing -- not a single probe, but an ongoing assault from every direction at once.

Nightmare mode is per-subsystem -- you can activate it independently for server, scanner, and proxy from the admin panel. Server nightmare snapshots all current config and applies extreme values, restoring on deactivate.

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

Includes PostgreSQL 16 with health checks, named volumes for data persistence, and automatic `GLITCH_DB_URL` wiring. The server waits for PostgreSQL to be healthy before starting. Set `GLITCH_ADMIN_PASSWORD` in your `.env` or environment.

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

### Real-World Scanner Behavior

Glitch has been tested against real-world scanners on a public internet host. Documented findings include crawlers tar-pitted for hours by slow-drip media downloads, `.env` scanners defeated by escalating bot detection, Nmap-style probes neutralized by keepalive abuse, and AI scrapers stuck in infinite sitemap polling loops. These observations inform the server's anti-scanner design and identify exploitable weaknesses in common scanner architectures (no download limits, no honeypot detection, no connection pool management, no content deduplication, no adaptive strategy). See [`docs/real-world-findings.md`](docs/real-world-findings.md) for detailed case studies and budget-draining mechanism ideas.

---

## Contributing

Glitch uses Go stdlib plus `github.com/lib/pq` (PostgreSQL driver). Build with `go build ./...`, run static analysis with `go vet ./...`, and test with `go test ./...`. Storage tests require a running PostgreSQL instance (skipped automatically if unavailable).

## License

MIT
