**Glitch Web Server v2 — an intentionally unreliable, adaptive web server written in Go.**

A high-performance chaos web server designed for load testing, monitoring validation, and scraper/bot research. It fingerprints clients, adapts its behavior to them, generates infinite labyrinth pages for AI scrapers, and exposes a full real-time monitoring dashboard.

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

### Page Types (8 formats)
Every successful response generates rich content on the fly:
- **HTML** — full pages with nav, links, tables, meta tags
- **JSON** — paginated API responses with nested data
- **XML** — structured item collections
- **CSV** — downloadable tabular data
- **Markdown** — formatted documents with tables
- **SSE** — server-sent event streams
- **Chunked** — chunked transfer encoding
- **Plain text** — system report style logs

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
- TLS/Sec-* header analysis
- Request rate and pattern analysis

### Adaptive Behavior Engine
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

Behavior re-evaluates every 30 seconds per client.

### Real-Time Dashboard (port 8766)
A live monitoring UI with:
- Global metrics (total requests, error rates, active connections, uptime)
- Per-second throughput chart
- Per-client table showing fingerprint, request rate, adaptive mode, and reasoning
- Recent request log with status codes and latency
- All data also available as JSON APIs:
  - `GET /api/metrics` — global counters
  - `GET /api/clients` — all client profiles
  - `GET /api/timeseries` — per-second throughput (last 60s)
  - `GET /api/recent` — last 100 requests
  - `GET /api/behaviors` — current adaptive assignments

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

## Architecture

```
cmd/glitch/main.go          Entry point, wiring, graceful shutdown
internal/
  server/handler.go          Request dispatcher, orchestrates all subsystems
  errors/generator.go        22 error types with weighted probability profiles
  pages/generator.go         8 content format generators
  labyrinth/labyrinth.go     Infinite page graph with deterministic seeding
  fingerprint/engine.go      Client identification and classification
  adaptive/engine.go         Behavior decision engine (7 modes)
  metrics/collector.go       Ring buffer, time series, per-client profiling
  dashboard/server.go        Live HTML dashboard + JSON API endpoints
```

## History

The project started as a 41-line Python prototype and was rewritten in Go for performance and expanded to include 20+ subsystems.
