**Glitch Web Server v2 -- an intentionally unreliable, adaptive web server written in Go.**

A high-performance chaos web server designed for security scanner benchmarking, load testing, monitoring validation, and scraper/bot research. It fingerprints clients, adapts its behavior per-client, generates infinite labyrinth pages for AI scrapers, emulates ~250 vulnerability endpoints across 8 OWASP Top 10 lists, and exposes a full real-time admin panel with scanner comparison tools. Zero external dependencies -- stdlib only, Go 1.24+.

---

## Features

### Error Simulation (30 error types)

Standard HTTP errors (500, 502, 503, 504, 404, 403, 429, 408) plus application-level and TCP-level glitches:

| Category | Error Type | Description |
|----------|-----------|-------------|
| **Application** | Slow drip | Sends response byte-by-byte |
| | Connection reset | Closes TCP mid-response |
| | Partial body | Truncated JSON with wrong Content-Length |
| | Wrong content-type | HTML body with `application/json` header |
| | Garbage body | Random bytes as response |
| | Empty body | 200 OK with zero bytes |
| | Huge headers | 50 bloated `X-Glitch-Padding-*` headers |
| | Redirect loops | Infinite 307 chains |
| | Double encoding | Claims gzip but isn't |
| | Flip-flop | Alternates 200/500 on consecutive requests |
| | Variable delays | 1s, 3s, 10s, or random up to 15s |
| **TCP-level** | Packet drop | Accepts connection, holds 30-60s, never responds |
| | TCP reset | Hijacks connection and sends RST via `SetLinger(0)` |
| | Stream corrupt | Valid HTTP start, then random garbage bytes mid-stream |
| | Session timeout | Responds at 1 byte/second |
| | Keepalive abuse | Sends `Connection: keep-alive timeout=999`, holds forever |
| | TLS half-close | Partial response, `CloseWrite()`, holds read open |
| | Slow headers | Sends headers byte-by-byte with 200-500ms gaps |
| | Accept-then-FIN | Hijacks connection and immediately closes |

Error profiles are probability maps (`map[ErrorType]float64`) with weights summing to ~1.0. Default profile: ~62% success, ~38% glitchy. Aggressive profile for bots: ~22% success.

### Page Types (8 formats) + 10 Visual Themes

Every successful response generates rich content on the fly:
- **HTML** -- full pages with nav, links, tables, meta tags
- **JSON** -- paginated API responses with nested data
- **XML** -- structured item collections
- **CSV** -- downloadable tabular data
- **Markdown** -- formatted documents with tables
- **SSE** -- server-sent event streams
- **Chunked** -- chunked transfer encoding
- **Plain text** -- system report style logs

Visual themes applied deterministically per path: SaaS, Ecommerce, Social, News, Docs, Corporate, Startup, Government, University, Banking -- each with distinctive branding, colors, and navigation styles.

### AI Scraper Labyrinth

An infinite, procedurally generated graph of interlinked pages designed to trap crawlers:
- **Deterministic per-path** -- same URL always produces same page (looks cacheable)
- **Exponential link graph** -- each page has 10-30 outgoing links
- **5 link generation strategies** -- deeper paths, siblings, cross-references, query params, hash-based unique paths
- **Rich metadata** -- breadcrumbs, pagination, OG tags, keywords, canonical URLs
- **Both HTML and JSON** -- responds based on `Accept` header
- **Virtually infinite** -- SHA-based path seeds ensure the graph never ends

### Client Fingerprinting

Identifies and tracks clients via:
- Header ordering and presence patterns
- User-Agent classification (browser, search bot, AI scraper, load tester, script bot, API tester)
- IP-based grouping
- TLS/Sec-* header analysis (sorted for deterministic IDs)
- Request rate and pattern analysis

### Adaptive Behavior Engine (8 modes)

The server changes how it treats each client based on observed patterns:

| Mode | Trigger | Behavior |
|------|---------|----------|
| **Normal** | Browsers, new clients | Default error rates (~35% glitchy) |
| **Cooperative** | Search bots | Halved error rates, some labyrinth |
| **Aggressive** | High-rate bots | 70% error rate, connection resets |
| **Labyrinth** | AI scrapers, path scanners | 60-95% labyrinth redirect, all page types |
| **Escalating** | Load testers | Gets progressively worse over time (10 levels) |
| **Intermittent** | Low-rate script bots | Random bursts of failure |
| **Mirror** | API testers (Postman, etc.) | Full page variety, standard errors |
| **Blocked** | Random or admin override | 403 with Retry-After header |

Behavior re-evaluates every 30 seconds per client (configurable). Manual overrides available via admin panel.

---

## Vulnerability Emulation (~250 endpoints)

A major subsystem that emulates realistic vulnerabilities across 8 OWASP Top 10 lists plus advanced categories. All responses are synthetic, deterministically seeded from request paths, and rendered inside a realistic "Acme Corp Portal" corporate layout. Designed for benchmarking security scanners.

### OWASP Web Application Top 10 (2021)

10 categories, 47+ endpoints under `/vuln/a01/` through `/vuln/a10/`:

| ID | Category | Example Endpoints |
|----|----------|-------------------|
| A01 | Broken Access Control | `/vuln/a01/users`, IDOR on user/order/document IDs |
| A02 | Cryptographic Failures | Plaintext passwords, weak hashing, exposed keys |
| A03 | Injection | SQL injection, command injection, LDAP injection |
| A04 | Insecure Design | Missing rate limits, enumerable IDs, verbose errors |
| A05 | Security Misconfiguration | Default credentials, directory listing, stack traces |
| A06 | Vulnerable Components | Outdated library versions, known CVEs |
| A07 | Auth Failures | Weak passwords, session fixation, no MFA |
| A08 | Data Integrity Failures | Unsigned updates, deserialization, CI/CD tampering |
| A09 | Logging Failures | Exposed access logs, missing audit trails |
| A10 | SSRF | Proxy endpoints fetching internal URLs |

### OWASP API Security Top 10 (2023)

10 categories, 30 endpoints under `/vuln/api-sec/`:

| ID | Category | What It Emulates |
|----|----------|------------------|
| API1 | Broken Object Level Authorization (BOLA) | Direct object reference on users/orders/docs |
| API2 | Broken Authentication | Weak login, token refresh without validation |
| API3 | Broken Object Property Level Authorization | Mass assignment, excessive data exposure |
| API4 | Unrestricted Resource Consumption | No rate limits, unbounded pagination |
| API5 | Broken Function Level Authorization | Admin endpoints accessible to regular users |
| API6 | Unrestricted Access to Sensitive Flows | Business logic bypass, coupon abuse |
| API7 | Server-Side Request Forgery | Internal URL fetch via API parameter |
| API8 | Security Misconfiguration | CORS wildcard, verbose errors, debug headers |
| API9 | Improper Inventory Management | Undocumented endpoints, shadow APIs |
| API10 | Unsafe Consumption of APIs | Trusting third-party API responses without validation |

### OWASP LLM Top 10 (2025)

10 categories under `/vuln/llm/`:

Prompt injection, sensitive information disclosure, supply chain vulnerabilities, data poisoning, improper output handling, excessive agency, model theft, vector/embedding weaknesses, misinformation, unbounded consumption.

### OWASP CI/CD Top 10 (2022)

10 categories under `/vuln/cicd/`:

Insufficient flow control, inadequate identity management, dependency chain abuse, poisoned pipeline execution, insufficient PBAC, credential hygiene failures, insecure system configuration, ungoverned third-party usage, artifact integrity violations, insufficient logging.

### OWASP Cloud-Native Top 10 (2022)

10 categories under `/vuln/cloud/`:

Insecure defaults (K8s), supply chain vulnerabilities, overly permissive IAM, no encryption in transit/at rest, insecure secrets management, broken authentication, no network segmentation, insecure workload configuration, drift detection failures, inadequate logging.

### OWASP Mobile Top 10 (2024)

10 categories under `/vuln/mobile/`:

Improper credential usage, inadequate supply chain security, insecure authentication, insufficient input validation, insecure communication, inadequate privacy controls, insufficient binary protections, security misconfiguration, insecure data storage, insufficient cryptography.

### OWASP Privacy Risks Top 10 (2021)

10 categories under `/vuln/privacy-risks/`:

Web tracking and fingerprinting, excessive data collection, inadequate breach response, insufficient data deletion, non-transparent policies, insufficient consent (dark patterns), unnecessary data collection, sharing without consent, outdated personal data, insufficient session expiry.

### OWASP Client-Side Top 10 (2024)

10 categories under `/vuln/client-side/`:

DOM XSS, prototype pollution, sensitive data exposure in client storage, CSP bypass, insecure postMessage, vulnerable dependencies, CORS misconfiguration, insecure client-side storage, clickjacking, open redirect.

### Advanced Vulnerability Categories

15 categories under `/vuln/cors/`, `/vuln/redirect/`, `/vuln/xxe/`, etc.:

CORS misconfiguration, open redirect, XXE injection, SSTI (server-side template injection), CRLF injection, host header injection, HTTP verb tampering, HTTP parameter pollution, file upload bypass, command injection, GraphQL introspection, JWT vulnerabilities (alg:none, weak secrets), race conditions, insecure deserialization, path normalization bypass.

### Dashboard/Settings Vulnerabilities

30+ endpoints under `/vuln/dashboard/` and `/vuln/settings/`:

| Category | Endpoints |
|----------|-----------|
| Unauthenticated admin | Dashboard home, analytics, system info |
| Debug information | Environment variables, routes, SQL queries, sessions, cache |
| PHPInfo emulation | Full phpinfo() page with server details |
| API key management | Key listing, creation, rotation without auth |
| User management | User listing, CSV export, invite without auth |
| Backup access | Database backup download, config backup |
| Settings exposure | General, security, database, email, storage, integrations |
| Insecure headers | Missing X-Frame-Options, X-Content-Type-Options; debug mode headers |

---

## Scanner Testing Framework

A built-in system for benchmarking security scanners against the vulnerability surface.

### Scanner Profile System

- Computes an expected vulnerability profile based on enabled features and config
- Catalogs all active vulnerability endpoints with severity, CWE, and OWASP mapping
- Tracks total vulnerabilities by severity (critical, high, medium, low, info)

### Scanner Runner

- Executes external security tools (Nuclei, Nikto, Nmap, ffuf, Wapiti) with configurable timeout
- Parses native output formats (JSONL, JSON, XML) into normalized findings
- Compares scanner results against expected profile: true positives, false negatives, false positives
- Grades scanners (A-F) based on detection rate and false positive rate

### Multi-Scanner Comparison

- Side-by-side comparison of multiple scanners against the same profile
- Coverage matrix showing which scanner found which vulnerability
- Consensus findings (found by all scanners) and unique finds per scanner
- Best/worst/average detection rates with recommendations

### Scanner History and Baselines

- Tracks scan results over time for trend analysis
- Baseline snapshots for regression detection
- All accessible via admin panel API

### Admin Panel API Endpoints

```
GET    /admin/api/scanner/profile        Expected vulnerability profile
POST   /admin/api/scanner/run            Start a scanner
GET    /admin/api/scanner/results        All scan results
POST   /admin/api/scanner/stop           Stop a running scanner
POST   /admin/api/scanner/compare        Compare scanner vs expected
POST   /admin/api/scanner/multi-compare  Multi-scanner comparison
GET    /admin/api/scanner/history        Historical results
GET    /admin/api/scanner/baseline       Baseline snapshot
```

---

## Admin Panel (port 8766/admin)

Full control center with 7 tabs:

| Tab | Purpose |
|-----|---------|
| **Dashboard** | Live metrics, request rates, error rates, active connections, uptime |
| **Sessions** | Client table with clickable detail view, per-client behavior overrides |
| **Traffic** | Sparkline charts, status code pie chart, top paths/UAs, response type distribution |
| **Controls** | 21 feature toggles, 19 tunable parameters (sliders), error/page type weight controls |
| **Request Log** | Searchable request log with filtering by status, path, client |
| **Vulnerabilities** | Group/category toggles, enable/disable individual vuln endpoints |
| **Scanner** | Single scanner run, multi-scanner comparison, history, baseline tracking |

### 21 Feature Toggles

Labyrinth, error injection, CAPTCHA, honeypot, vulnerability emulation, analytics, CDN emulation, OAuth/SSO, header corruption, cookie traps, JS traps, bot detection, random blocking, framework emulation, search, email, i18n, traffic recorder, WebSocket, privacy consent, health endpoints.

### 19 Tunable Parameters

Max labyrinth depth, error rate multiplier, CAPTCHA trigger threshold, block chance, block duration, bot score threshold, header corruption level, delay min/max, labyrinth link density, adaptive interval, honeypot response style, cookie trap frequency, JS trap difficulty, active framework, content theme, content cache TTL, adaptive aggressive RPS threshold, adaptive labyrinth paths trigger, recorder format.

### Config Import/Export

```
GET  /admin/api/config/export   Export all features, config, and vuln states as JSON
POST /admin/api/config/import   Import a previously exported config snapshot
```

Startup import via CLI flag: `./glitch -config config.json`

### Additional Admin API Endpoints

```
GET/POST  /admin/api/features       Toggle subsystems on/off
GET/POST  /admin/api/config         Tune numeric parameters
GET       /admin/api/overview       Traffic analytics (top paths, UAs, status codes)
GET       /admin/api/log            Request log with filtering
GET       /admin/api/client/{id}    Detailed client profile
GET/POST  /admin/api/blocking       Random blocking controls
GET/POST  /admin/api/override       Per-client behavior overrides
GET/POST  /admin/api/vulns          Individual vulnerability controls
POST      /admin/api/vulns/group    Toggle vulnerability groups
GET/POST  /admin/api/error-weights  Error type probability weights
GET/POST  /admin/api/page-type-weights  Page type probability weights
```

### Real-Time Dashboard (port 8766)

A live monitoring UI with:
- Global metrics (total requests, error rates, active connections, uptime)
- Per-second throughput chart
- Per-client table showing fingerprint, request rate, adaptive mode, and reasoning
- Recent request log with status codes and latency
- JSON APIs: `/api/metrics`, `/api/clients`, `/api/timeseries`, `/api/recent`, `/api/behaviors`

---

## Additional Subsystems

| Subsystem | Description |
|-----------|-------------|
| **Header Corruption Engine** | 5 corruption levels (none/subtle/moderate/aggressive/chaos). Duplicate headers, cache confusion, cookie bombs, oversized headers. Targets non-browser clients. |
| **Cookie Traps** | Session, fingerprint, and honeypot cookies. Trap cookies that expire immediately. Domain mismatch and SameSite cookies. Compliance scoring feeds bot detection. |
| **JavaScript Traps** | WebDriver, Playwright, Puppeteer, CDP detection. Invisible honeypot links. JS-rendered content, timing traps, canvas fingerprinting, challenge pages. |
| **Bot Detection** | Multi-signal scoring (0-100). UA classification, Sec-Fetch validation, Client Hints, header ordering anomalies, timing regularity, cookie/JS compliance. Identifies Firecrawl, Oxylabs, ScrapingBee, Bright Data, Crawl4AI. Classifications: human/suspicious/bot/crawler_service. |
| **Framework Emulation** | 12 web stack personalities (Apache, Nginx, IIS, Express, Django, Rails, etc.) varying per client+path. |
| **Fake API Surface** | REST endpoints for users, products, CMS, forms. GraphQL endpoint and Swagger/OpenAPI docs. |
| **OAuth/SSO** | Simulated OAuth2, SAML, and OpenID Connect flows. |
| **CDN Emulation** | Fake CDN headers (X-Cache, CF-Ray, etc.) and static asset serving. |
| **Analytics Tracking** | Beacon endpoints and tracking pixels. |
| **CAPTCHA System** | Math, text, and image challenges. |
| **Honeypot** | Scanner-bait paths (/wp-admin, /phpmyadmin, /.env, /actuator, etc.). |
| **Search Engine** | Simulated search with suggestions and results. |
| **Email/Webmail** | Fake inbox and compose endpoints. |
| **i18n** | Multi-language content in 12 languages. |
| **Health Endpoints** | /health, /health/live, /status, /debug. |
| **WebSocket** | Echo and chat WebSocket endpoints. |
| **Privacy/Consent** | Cookie consent banners, privacy policy generation, GDPR-style consent management. |
| **Reverse Proxy Mode** | Run glitch-proxy in front of a real server. Scoring-based interception with configurable threshold. Modes: block, challenge, labyrinth, glitch. |

### Traffic Recording

Capture HTTP traffic to disk in two formats:
- **JSONL** -- one JSON object per request with headers, body size, latency, client ID
- **PCAP** -- Wireshark-compatible pcap files with synthesized Ethernet/IP/TCP headers

File rotation at 50MB or 1 hour. Format selectable via admin config (`recorder_format`). Captures stored in `./captures/` directory.

---

## Quick Start

```bash
go build -o glitch ./cmd/glitch
./glitch
```

Options:
```
-port       Server port (default: 8765)
-dash-port  Dashboard port (default: 8766)
-config     Path to config JSON file to import on startup
```

### Reverse Proxy Mode
```bash
go build -o glitch-proxy ./cmd/glitch-proxy
./glitch-proxy -backend http://your-real-server:8080
```

---

## Deployment

### Docker

```bash
docker compose up
```

Environment variables:
- `GLITCH_PORT` -- server port mapping (default: 8765)
- `GLITCH_DASH_PORT` -- dashboard port mapping (default: 8766)
- `GLITCH_CONFIG` -- set to any value to load `/etc/glitch/config.json` on startup

Volumes: `./config.json` mounted read-only, `./captures/` for traffic recordings.

### Kubernetes

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
kubectl apply -f deploy/k8s/ingress.yaml
```

Includes separate proxy deployment (`deploy/k8s/proxy-deployment.yaml`).

### Systemd

Service files in `deploy/systemd/`:
- `glitch-server.service` -- main server
- `glitch-proxy.service` -- reverse proxy mode

### GitHub Actions CI/CD

Workflows in `.github/workflows/`:
- `ci.yml` -- lint (`go vet`), test (`go test ./...`), build, artifact upload
- `docker.yml` -- Docker image build and push

### Makefile

```
make build          Build the server binary (CGO_ENABLED=0, stripped)
make test           Run all tests
make vet            Static analysis
make clean          Remove build artifacts
make docker-build   Build Docker image
make docker-push    Push to GHCR
make k8s-deploy     Apply all Kubernetes manifests
make run            Build and run locally
make cross          Cross-compile for linux/darwin amd64/arm64
```

---

## Architecture

```
cmd/
  glitch/main.go                 Entry point, wiring, config import, graceful shutdown
  glitch-proxy/main.go           Reverse proxy CLI
  glitch-crawler/                Crawler utility

internal/
  server/handler.go              Request dispatcher — orchestrates 26+ subsystems
  errors/generator.go            30 error types with weighted probability profiles
  pages/generator.go             8 content format generators
  content/engine.go              Rich HTML content engine with themes and caching
  content/themes.go              10 visual themes (SaaS, news, banking, etc.)
  labyrinth/labyrinth.go         Infinite page graph with deterministic seeding
  fingerprint/engine.go          Client identification and classification
  adaptive/engine.go             8 behavior modes, blocking, overrides
  metrics/collector.go           Ring buffer (10k records), time series, per-client profiling
  dashboard/server.go            Live HTML dashboard + JSON API endpoints
  dashboard/admin.go             21 feature toggles, 19 tunable parameters
  dashboard/admin_routes.go      Admin API route registration (scanner, vulns, config)
  dashboard/admin_html.go        Self-contained admin panel HTML (7 tabs)
  headers/corruption.go          HTTP header corruption engine (5 levels)
  cookies/tracker.go             Cookie traps and compliance analysis
  jstrap/jstrap.go               JavaScript traps and automation detection
  botdetect/detector.go          Multi-signal bot detection scoring
  proxy/proxy.go                 Reverse proxy with interception
  api/router.go                  REST API surface (users, products, CMS, forms)
  honeypot/honeypot.go           Scanner-bait endpoints
  framework/emulator.go          12 web stack personality emulation
  captcha/engine.go              CAPTCHA challenge system
  vuln/owasp.go                  OWASP Web Top 10 (2021) — 10 categories, 47+ endpoints
  vuln/api_security.go           OWASP API Security Top 10 (2023) — 10 categories, 30 endpoints
  vuln/modern.go                 OWASP LLM Top 10 (2025), CI/CD Top 10, Cloud-Native Top 10
  vuln/mobile_privacy.go         OWASP Mobile Top 10, Privacy Top 10, Client-Side Top 10
  vuln/advanced.go               Advanced vulns: CORS, XXE, SSTI, JWT, race conditions, etc.
  vuln/dashboard.go              Dashboard/settings vulnerability emulations (30+ endpoints)
  scanner/profile.go             Expected vulnerability profile computation
  scanner/comparison.go          Multi-scanner comparison and coverage matrix
  scanner/runner.go              External scanner execution and result collection
  scanner/parsers.go             Nuclei, Nikto, Nmap, ffuf, Wapiti output parsers
  recorder/recorder.go           JSONL traffic capture with file rotation
  recorder/pcap.go               PCAP file writer (Wireshark-compatible)
  analytics/engine.go            Beacon and tracking pixel endpoints
  cdn/engine.go                  CDN header emulation
  oauth/handler.go               OAuth2, SAML, OpenID Connect flows
  privacy/consent.go             Cookie consent and GDPR-style privacy management
  websocket/handler.go           WebSocket echo and chat endpoints
  search/handler.go              Search engine with suggestions
  email/handler.go               Webmail inbox and compose
  health/handler.go              Health check and status endpoints
  i18n/handler.go                Multi-language content (12 languages)

deploy/
  k8s/                           Kubernetes manifests (namespace, configmap, deployment,
                                   service, ingress, proxy-deployment)
  systemd/                       Systemd service files

.github/workflows/
  ci.yml                         CI pipeline (lint, test, build)
  docker.yml                     Docker image build/push
```

---

## Testing

```bash
go test ./...                    # run all tests (1500+ across 25 packages)
go build ./...                   # compile check
go vet ./...                     # static analysis
```

Quick smoke test:
```bash
./glitch &
curl http://localhost:8765/                                  # random page
curl http://localhost:8765/articles/some-topic/deep-path     # triggers labyrinth
curl http://localhost:8765/vuln/                             # vulnerability index
curl http://localhost:8765/vuln/api-sec/                     # API security index
curl http://localhost:8765/vuln/llm/                         # LLM Top 10 index
curl http://localhost:8766/api/metrics                       # dashboard API
curl http://localhost:8766/admin                             # admin panel
curl http://localhost:8766/admin/api/scanner/profile         # scanner profile
```

---

## History

The project started as a 41-line Python prototype and was rewritten in Go for performance and expanded to include 30+ subsystems, ~250 vulnerability endpoints, and a comprehensive scanner benchmarking framework.
