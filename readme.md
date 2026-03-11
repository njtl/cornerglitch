# Cornerglitch

**HTTP chaos testing framework. Break everything before production does.**

Cornerglitch emulates every layer of the HTTP stack -- client, proxy, and server -- with hostile, unreliable, or adversarial behavior. Replace any component in your stack with a Cornerglitch equivalent and see what breaks.

```
Scanner (client)  ──>  Proxy (middleware)  ──>  Server (backend)
  Attack payloads        Traffic corruption       Broken responses
  Protocol abuse         WAF emulation            Vulnerability endpoints
  Slow HTTP floods       Latency injection        Adaptive bot detection
  WAF bypass             Connection drops          Infinite labyrinths
```

All three report to a unified admin dashboard. Mix and match with your own services.

---

## Quick Start

```bash
git clone https://github.com/njtl/cornerglitch.git
cd cornerglitch

cp .env.example .env          # set admin password + database URL
make start                    # build + start (dashboard at :8766)
```

```bash
# Scanner
go build -o glitch-scanner ./cmd/glitch-scanner
glitch-scanner -target http://localhost:8765
glitch-scanner -target http://localhost:8765 -profile destroyer   # server destruction

# Proxy
go build -o glitch-proxy ./cmd/glitch-proxy
glitch-proxy -target http://localhost:8765 -mode chaos

# Self-test (all three against each other)
glitch selftest --mode nightmare

# Docker (server + PostgreSQL)
docker-compose up
```

> Set `GLITCH_DB_URL` in `.env` for PostgreSQL persistence. Without it, all data is lost on restart.

---

## What Can You Test?

| Your goal | Use Cornerglitch as | Keep yours as |
|-----------|---------------------|---------------|
| Benchmark your DAST scanner | Server (target) | Scanner |
| Stress-test your backend | Scanner (attacker) | Server |
| Test your proxy / WAF / gateway | Scanner + Server (both sides) | Proxy in the middle |
| AI agent security | MCP honeypot server | Your agent |
| Full chaos self-test | All three against each other | -- |

---

## Server

The server emulates a broken, hostile, or deceptive backend. It serves on `:8765` with an admin dashboard on `:8766`.

**Error injection** -- Dozens of error types across HTTP, TCP, and protocol layers. HTTP errors, connection resets, slow drip, partial bodies, HTTP/2 frame chaos (GOAWAY, RST_STREAM, SETTINGS flood, CONTINUATION flood). Configurable probability profiles.

**Vulnerability endpoints** -- Realistic corporate-looking pages covering all major OWASP Top 10 lists (Web, API, LLM, CI/CD, Cloud-Native, Mobile, Privacy, Client-Side, IoT, Serverless). Not demo labels -- full page layouts with navigation, forms, and API responses.

**Anti-scanner systems** -- Infinite procedural labyrinth that traps crawlers in deterministic page graphs. Adaptive behavior engine that fingerprints clients and escalates hostility. Bot detection with JS traps, cookie traps, and CAPTCHA challenges. Budget-draining traps: graduated tarpits, fake vulnerability breadcrumbs, infinite pagination, streaming bait.

**Protocol chaos** -- TLS chaos engine (5 levels from clean to nightmare). HSTS chaos with random Strict-Transport-Security headers. H3/QUIC confusion with fake Alt-Svc and malformed UDP packets. CVE-inspired header attacks (CRLF injection, null bytes, 65KB overflow, duplicate Content-Length).

**MCP honeypot** -- Model Context Protocol server at `/mcp` with fake tools (credential harvesters, budget drains), poisoned resources (fake `.env`, SSH keys, K8s secrets), and trap prompts with injection attacks. Classifies AI agents (Claude, GPT, Cursor, Windsurf) by behavioral signals.

**Everything else** -- REST API emulation with GraphQL and Swagger, OAuth2/SSO flows, CDN emulation, search engine, email/webmail, WebSocket streams, framework emulation (Rails, Django, Express, Spring, Laravel), traffic recording (JSONL/PCAP), media chaos engine.

**Admin dashboard** -- 5-tab layout with live metrics, per-client profiles, feature toggles, config import/export. All settings persist to PostgreSQL or local state file.

## Scanner

The scanner emulates malicious, broken, or aggressive HTTP clients.

- Attack modules matched to every server vulnerability endpoint
- Crawl engine with depth limiting, deduplication, and loop detection
- Slow HTTP attacks (slowloris, RUDY, slow read, connection exhaustion)
- TLS probing (version enumeration, weak ciphers, cert analysis, ALPN, downgrade)
- Raw TCP breakage attacks reproducing real-world CVE crash patterns
- WAF bypass with encoding tricks, request smuggling, header manipulation
- 6 profiles: `compliance`, `aggressive`, `stealth`, `nightmare`, `destroyer`, `waf-buster`
- Scanner evaluation: compare external scanner results against expected vulnerability surface
- Supported external scanners: nuclei, httpx, ffuf, nikto, nmap, wapiti
- MCP scanner for testing external MCP servers (injection patterns, rug pulls, exfiltration)

## Proxy

The proxy emulates corrupting middleware, WAFs, or API gateways.

- Interception pipeline for request and response manipulation
- Chaos injection: latency, body corruption, connection resets, header rewriting
- WAF mode with signature-based blocking and rate limiting
- MCP traffic interception: inject tools, poison resources, modify results
- 7 modes: `transparent`, `waf`, `chaos`, `gateway`, `nightmare`, `mirror`, `killer`
- Killer mode: 100% client-killing attacks on every proxied response

---

## Nightmare Mode

All three components at maximum adversarial settings simultaneously. The scanner floods with attack payloads. The proxy corrupts traffic in both directions. The server responds with broken HTTP, TCP resets, and infinite response bodies.

A service passes nightmare testing if it does not crash, does not corrupt state, and recovers to normal operation afterward. Per-subsystem activation from the admin panel.

```bash
glitch selftest --mode nightmare    # automated nightmare test
```

---

## Real-World Findings

Cornerglitch has been deployed as a live honeypot and tested against popular security tools:

- **Gobuster** -- instant crash. A single null byte in a response header kills Go's HTTP parser. Scan aborts with zero results.
- **SQLMap** -- immediate abort. HTTP 102 (Processing) has no handler. Zero injection tests performed.
- **Nuclei** -- honeypot endpoints fool every template. False positives on fake `.env` files, credential pages, and debug endpoints.
- **WhatWeb** -- plugin crash cascade. Ruby's HTTP parser returns nil on null bytes.
- **Wapiti** -- trapped in the infinite labyrinth. Hundreds of fake URLs crawled before timeout. No loop detection.
- **ZAP** -- runs out of memory. The labyrinth generates unlimited URLs with API and media links.
- **Real crawlers** hold connections for 2+ hours downloading procedurally generated audio.
- **AI scrapers** poll robots.txt for 23 hours straight in infinite loops.

WAF testing results against ModSecurity, NAXSI, and commercial WAFs:

- **CRLF injection bypasses all tested WAFs** -- universal, zero detection
- **SQLi via JSON body bypasses ModSecurity at all paranoia levels** -- JSON bodies aren't inspected
- **200 concurrent connections disable ModSecurity** for 15 seconds -- from one machine
- **60KB nested JSON OOM-kills a commercial WAF** in 90 seconds -- 275MB to 1.72GB before kernel kill
- **Response-side null bytes force 502 on every response** -- the most underexplored WAF weakness

See [`docs/real-world-findings.md`](docs/real-world-findings.md) for detailed case studies.

---

## Configuration

The server auto-loads `.env` on startup. CLI flags and env vars take precedence.

```bash
cp .env.example .env
```

| Variable | Purpose | Default |
|----------|---------|---------|
| `GLITCH_ADMIN_PASSWORD` | Dashboard login password | Auto-generated |
| `GLITCH_DB_URL` | PostgreSQL connection string | None (memory-only) |
| `PASSWORD_RESET_FROM_ENV` | Set `1` to force-reset password from env | `0` |
| `GLITCH_HEALTH_SECRET` | Secret path for internal health endpoint | Auto-generated |
| `GLITCH_TLS_CERT` / `GLITCH_TLS_KEY` | Custom TLS certificate | Self-signed |
| `SENTRY_DSN` | Sentry error tracking | Disabled |

> **No real health endpoints.** All public paths (`/health`, `/ping`, `/actuator`) go through error injection. The real health check is at `/_internal/<secret>/healthz`, configured via `GLITCH_HEALTH_SECRET`.

---

## Deployment

<details>
<summary><b>Docker Compose</b></summary>

```bash
docker-compose up       # server + dashboard + PostgreSQL
```

Includes PostgreSQL 16 with health checks, named volumes, and automatic `GLITCH_DB_URL` wiring.
</details>

<details>
<summary><b>Kubernetes</b></summary>

```bash
vim deploy/k8s/postgres-secret.yaml    # set credentials
kubectl apply -f deploy/k8s/           # full deployment
```

Includes namespace, deployment, service, ingress, configmap, PostgreSQL StatefulSet with PVC.
</details>

<details>
<summary><b>Systemd</b></summary>

```bash
sudo cp deploy/systemd/glitch.env /etc/glitch/glitch.env
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl enable --now glitch-postgres glitch-server
```
</details>

<details>
<summary><b>Makefile reference</b></summary>

```bash
make build        # build server binary
make start        # build + start in background
make stop         # graceful shutdown
make restart      # stop + start
make status       # check if running
make logs         # tail server logs
make test         # run all tests
make vet          # static analysis
make db-up        # start PostgreSQL container
make db-down      # stop PostgreSQL container
make db-reset     # drop and recreate database
make cross        # cross-compile (Linux/Darwin, amd64/arm64)
make docker-build # build Docker image
make k8s-deploy   # deploy to Kubernetes
```
</details>

---

## Contributing

Go 1.24+. Two external dependencies: `github.com/lib/pq` (PostgreSQL) and `github.com/getsentry/sentry-go` (error tracking). Everything else is stdlib.

```bash
go build ./...
go vet ./...
go test ./... -count=1 -timeout 600s
```

## License

MIT
