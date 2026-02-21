**Glitch Web Server v2 — an intentionally unreliable, adaptive web server written in Go.**

A high-performance chaos web server designed for load testing, monitoring validation, and scraper/bot research. It fingerprints clients, adapts its behavior to them, generates infinite labyrinth pages for AI scrapers, and exposes a full real-time monitoring dashboard with comprehensive admin controls.

## Features

### Error Simulation (22 error types)
Standard HTTP errors (500, 502, 503, 504, 404, 403, 429, 408) plus exotic glitches:
- **Slow drip** — sends response byte-by-byte
- **Connection reset** — closes TCP mid-response
- **Partial body** — truncated JSON with wrong Content-Length
- **Wrong content-type** — HTML body with `application/json` header
- **Garbage body** — random bytes as response
- **Empty body** — 200 OK with zero bytes
- **Huge headers** — 50 bloated `X-Glitch-Padding-*` headers
- **Redirect loops** — infinite 307 chains
- **Double encoding** — claims gzip but isn't
- **Flip-flop** — alternates 200/500 on consecutive requests
- **Variable delays** — 1s, 3s, 10s, or random up to 15s

### Page Types (8 formats) + 10 Visual Themes
Every successful response generates rich content on the fly:
- **HTML** — full pages with nav, links, tables, meta tags
- **JSON** — paginated API responses with nested data
- **XML** — structured item collections
- **CSV** — downloadable tabular data
- **Markdown** — formatted documents with tables
- **SSE** — server-sent event streams
- **Chunked** — chunked transfer encoding
- **Plain text** — system report style logs

Visual themes applied deterministically per path: SaaS, Ecommerce, Social, News, Docs, Corporate, Startup, Government, University, Banking — each with distinctive branding, colors, and navigation styles.

### AI Scraper Labyrinth
An infinite, procedurally generated graph of interlinked pages designed to trap crawlers:
- **Deterministic per-path** — same URL always produces same page (looks cacheable)
- **Exponential link graph** — each page has 10-30 outgoing links
- **5 link generation strategies** — deeper paths, siblings, cross-references, query params, hash-based unique paths
- **Rich metadata** — breadcrumbs, pagination, OG tags, keywords, canonical URLs
- **Both HTML and JSON** — responds based on `Accept` header
- **Virtually infinite** — SHA-based path seeds ensure the graph never ends

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

Behavior re-evaluates every 30 seconds per client. Manual overrides available via admin panel.

### Header Corruption Engine
5 corruption levels (none/subtle/moderate/aggressive/chaos):
- Duplicate response headers
- Cache confusion (conflicting Cache-Control directives)
- Cookie bombs and domain mismatch cookies
- Oversized headers, wrong Content-Length hints
- Targets non-browser clients; browsers are spared

### Cookie Traps
Bot detection via cookie compliance analysis:
- Session, fingerprint, and honeypot cookies set per client
- Trap cookies that expire immediately (bots often replay them)
- Domain mismatch and SameSite cookies
- Cookie compliance scoring feeds into bot detection

### JavaScript Traps
Detect headless browsers and automation tools:
- WebDriver, Playwright, Puppeteer, CDP detection scripts
- Invisible honeypot links (bots follow them, humans don't)
- JS-rendered content (invisible to non-JS scrapers)
- Timing traps and canvas fingerprinting
- JS challenge pages with verification endpoint

### Bot Detection System
Multi-signal scoring framework (0-100 scale):
- User-Agent classification and version mismatch detection
- Sec-Fetch header validation, Client Hints analysis
- Header ordering anomaly scoring
- Request timing regularity detection
- Cookie and JS compliance tracking
- **API crawler product identification**: Firecrawl, Oxylabs, ScrapingBee, Bright Data, Crawl4AI
- Classifications: human / suspicious / bot / crawler_service

### Reverse Proxy Mode
Run glitch-proxy in front of a real web server:
- Scoring-based interception (configurable threshold)
- Modes: block, challenge, labyrinth, glitch
- Passes through legitimate traffic to backend

### Admin Panel (port 8766/admin)
Full control center with 4 tabs:
- **Sessions** — live client table with clickable detail view, per-client behavior overrides
- **Traffic** — sparkline charts, status code pie chart, top paths/UAs, response type distribution
- **Controls** — 21 feature toggles, 11 tunable parameters (sliders)
- **Request Log** — searchable request log with filtering

Admin API endpoints:
- `GET/POST /admin/api/features` — toggle subsystems on/off
- `GET/POST /admin/api/config` — tune numeric parameters
- `GET /admin/api/overview` — traffic analytics
- `GET /admin/api/log` — request log with filtering
- `GET /admin/api/client/{id}` — detailed client profile
- `GET/POST /admin/api/blocking` — random blocking controls
- `GET/POST /admin/api/override` — per-client behavior overrides

### Real-Time Dashboard (port 8766)
A live monitoring UI with:
- Global metrics (total requests, error rates, active connections, uptime)
- Per-second throughput chart
- Per-client table showing fingerprint, request rate, adaptive mode, and reasoning
- Recent request log with status codes and latency
- JSON APIs: `/api/metrics`, `/api/clients`, `/api/timeseries`, `/api/recent`, `/api/behaviors`

### Additional Subsystems
- **Framework Emulation** — 12 web stack personalities (Apache, Nginx, IIS, etc.) varying per client+path
- **Fake API Surface** — REST endpoints for users, products, CMS, forms; GraphQL and Swagger docs
- **OAuth/SSO** — simulated OAuth2, SAML, and OpenID Connect flows
- **CDN Emulation** — fake CDN headers and static asset serving
- **Analytics Tracking** — beacon endpoints, tracking pixels
- **CAPTCHA System** — math, text, and image challenges
- **Honeypot** — scanner-bait paths (/wp-admin, /phpmyadmin, etc.)
- **Vulnerability Emulation** — OWASP-style endpoints for security scanner testing
- **Search Engine** — simulated search with suggestions
- **Email/Webmail** — fake inbox and compose endpoints
- **i18n** — multi-language content (12 languages)
- **Health Endpoints** — /health, /status, /debug
- **WebSocket** — echo and chat WebSocket endpoints
- **Traffic Recorder** — capture and replay request sessions

## Quick Start

```bash
go build -o glitch ./cmd/glitch
./glitch
```

Options:
```
-port      Server port (default: 8765)
-dash-port Dashboard port (default: 8766)
```

### Reverse Proxy Mode
```bash
go build -o glitch-proxy ./cmd/glitch-proxy
./glitch-proxy -backend http://your-real-server:8080
```

### Docker
```bash
docker compose up
```

## Architecture

```
cmd/glitch/main.go              Entry point, wiring, graceful shutdown
cmd/glitch-proxy/main.go         Reverse proxy CLI
internal/
  server/handler.go              Request dispatcher, orchestrates 26+ subsystems
  errors/generator.go            22 error types with weighted probability profiles
  pages/generator.go             8 content format generators
  content/engine.go              Rich HTML content engine with themes and caching
  content/themes.go              10 visual themes (SaaS, news, banking, etc.)
  labyrinth/labyrinth.go         Infinite page graph with deterministic seeding
  fingerprint/engine.go          Client identification and classification
  adaptive/engine.go             8 behavior modes, blocking, overrides
  metrics/collector.go           Ring buffer (10k records), time series, per-client profiling
  dashboard/server.go            Live HTML dashboard + JSON API endpoints
  dashboard/admin.go             Admin panel with 21 toggles, 11 parameters
  headers/corruption.go          HTTP header corruption engine (5 levels)
  cookies/tracker.go             Cookie traps and compliance analysis
  jstrap/jstrap.go               JavaScript traps and automation detection
  botdetect/detector.go          Multi-signal bot detection scoring
  proxy/proxy.go                 Reverse proxy with interception
  api/router.go                  REST API surface (users, products, CMS, forms)
  honeypot/honeypot.go           Scanner-bait endpoints
  framework/emulator.go          12 web stack personality emulation
  captcha/engine.go              CAPTCHA challenge system
deploy/                          Docker, Kubernetes, and systemd configs
```

## Testing

```bash
go test ./...                    # run all tests (1000+)
go build ./...                   # compile check
go vet ./...                     # static analysis
```

## History

The project started as a 41-line Python prototype and was rewritten in Go for performance and expanded to include 26+ subsystems.
