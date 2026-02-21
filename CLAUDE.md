# CLAUDE.md — Glitch Web Server

## What is this project?

An intentionally unreliable, adaptive HTTP server written in Go. It simulates a broken web service with 22 error types, 8 page formats, an infinite AI scraper labyrinth, client fingerprinting, and behavior that adapts to whoever is testing it. A real-time dashboard exposes all internal state.

## Build & Run

```bash
go build -o glitch ./cmd/glitch    # build
./glitch                            # run (ports 8765 + 8766)
./glitch -port 9000 -dash-port 9001 # custom ports
```

No external dependencies — stdlib only, go 1.24+.

## Project Layout

```
cmd/glitch/main.go              Entry point, flag parsing, graceful shutdown
internal/
  server/handler.go              Main request handler — dispatches to all subsystems
  errors/generator.go            22 error types with weighted probability profiles
  pages/generator.go             8 content generators (HTML, JSON, XML, CSV, SSE, etc.)
  labyrinth/labyrinth.go         Infinite procedural page graph for trapping scrapers
  fingerprint/engine.go          Client ID via headers, UA classification, IP
  adaptive/engine.go             7 behavior modes, re-evaluates per client every 30s
  metrics/collector.go           Ring buffer (10k records), time series, per-client profiles
  dashboard/server.go            Live HTML dashboard + JSON API endpoints
```

## Key Conventions

- **Zero external deps.** Everything uses Go stdlib. Do not add third-party modules.
- **All server logic is in `internal/`.** Nothing in `internal/` is meant to be imported by external code.
- **Error profiles are probability maps** (`map[ErrorType]float64`). Weights should sum to ~1.0.
- **Labyrinth pages are deterministic** — seeded from path via SHA-256 so the same URL always yields the same page.
- **Adaptive behavior** is per-client (keyed by fingerprint ID) and mode transitions happen in `adaptive/engine.go:evaluate()`.
- **Dashboard runs on a separate port** (default 8766) and has no auth — it's for internal observability.
- **No legacy code.** The original Python prototype has been removed; Go is the sole implementation.

## Testing

```bash
go build ./cmd/glitch/           # compile check
go vet ./...                     # static analysis
```

Quick smoke test:
```bash
./glitch &
curl http://localhost:8765/
curl http://localhost:8765/articles/some-topic/deep-path  # triggers labyrinth
curl http://localhost:8766/api/metrics                     # dashboard API
```

## Architecture Notes

Request flow:
1. `server/handler.go:ServeHTTP` — fingerprints client, gets adaptive behavior
2. `handler.dispatch` — checks labyrinth eligibility, rolls error type, serves page
3. Every request is recorded in `metrics/collector.go` (ring buffer + per-client profile)
4. Adaptive engine re-evaluates client behavior every 30s based on accumulated metrics
5. Dashboard reads from collector and adaptive engine via JSON APIs

The adaptive engine classifies clients into: browser, search_bot, ai_scraper, script_bot, api_tester, load_tester, unknown — then assigns a behavior mode accordingly.
