# Glitch -- HTTP Chaos Testing Framework

**Break everything before production does.**

A 3-in-1 chaos testing framework that emulates every layer of the HTTP stack -- client, proxy, and server -- so you can find out what breaks before your users do. Zero external dependencies. Go stdlib only.

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
go build -o glitch ./cmd/glitch
./glitch                             # serves on :8765, dashboard on :8766
```

### Glitch Proxy

```bash
go build -o glitch-proxy ./cmd/glitch-proxy
./glitch-proxy -backend http://your-server:8080
```

### Glitch Scanner

```bash
go build -o glitch-scanner ./cmd/glitch-scanner
./glitch-scanner -target http://localhost:8765
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

- Dozens of error types: HTTP errors, TCP resets, slow drip, connection drops, partial responses, garbage bytes, redirect loops, and more
- Vulnerability emulation across all major OWASP Top 10 lists (Web, API, LLM, CI/CD, Cloud-Native, Mobile, Privacy, Client-Side) plus advanced categories
- Infinite AI scraper labyrinth -- procedurally generated, deterministic page graph that traps crawlers
- Adaptive behavior engine -- fingerprints clients and adjusts hostility per-client in real time
- Bot detection with multi-signal scoring, JS traps, cookie traps, and CAPTCHA challenges
- Multiple content formats, visual themes, and framework emulation personalities
- Full admin panel with 5-tab mode-based layout (Dashboard, Server, Scanner, Proxy, Settings), per-mode nightmare toggles, feature flags, tunable parameters, and config import/export

### Glitch Scanner (client emulator)

- Attack payloads matched to every vulnerability endpoint on the server
- Crawl engine with depth limiting, deduplication, and loop detection
- Resilience testing -- verifies graceful handling of every error type the server can throw
- Evasion modes for WAF bypass testing
- Configurable profiles: compliance, aggressive, stealth, nightmare

### Glitch Proxy (middleware emulator)

- Interception pipeline for request and response manipulation
- Chaos injection: latency spikes, body corruption, connection resets, header rewriting
- WAF mode with signature-based blocking and rate limiting
- Configurable modes: transparent, WAF, chaos, gateway, nightmare

---

## Nightmare Mode

Run all three components at maximum adversarial settings simultaneously. The scanner floods with malformed requests and attack payloads. The proxy corrupts traffic in both directions. The server responds with broken HTTP, TCP resets, and infinite response bodies. A service passes nightmare testing if it does not crash, does not corrupt state, recovers to normal operation afterward, and maintains health check responses throughout. This is sustained, multi-vector adversarial testing -- not a single probe, but an ongoing assault from every direction at once.

---

## Self-Test

Glitch can test itself. Run all three components against each other to validate the entire framework end-to-end, or use it as a demo of what full-stack chaos looks like.

```bash
glitch selftest                       # baseline mode
glitch selftest --mode nightmare      # maximum adversarial
```

---

## Architecture Overview

The server, scanner, and proxy are separate binaries built from `cmd/`. All internal logic lives under `internal/` organized by subsystem. The server alone has dozens of subsystems including error generation, page rendering, vulnerability emulation, fingerprinting, adaptive behavior, bot detection, and a full admin dashboard with live metrics. The proxy adds an interception pipeline with chaos, WAF, and corruption modules. The scanner adds attack, evasion, resilience, and crawl modules. See `docs/PLAN.md` for the full architecture plan and `docs/` for component-level PRDs.

---

## Contributing

Glitch is Go stdlib only -- no external dependencies. Build with `go build ./...`, run static analysis with `go vet ./...`, and test with `go test ./...`.

## License

MIT
