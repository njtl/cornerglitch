# Glitch — HTTP Chaos Testing Framework

## Master Architecture Plan

### Vision

Glitch is a 3-in-1 HTTP chaos testing framework. It provides interchangeable emulators for every layer of the HTTP stack — **client**, **proxy**, and **server** — so developers can test any service against the worst the internet can throw at it.

The goal: **if your service survives Glitch in nightmare mode, it can handle anything in production.**

### The Problem

Every HTTP service operates in a chain: Client → Proxy/Middleware → Backend. Each layer makes assumptions about the others:

- **Clients** (scanners, scrapers, browsers) assume servers return valid HTTP responses
- **Proxies** (WAFs, API gateways, load balancers) assume both sides speak clean HTTP
- **Backends** (web apps, APIs, microservices) assume clients send well-formed requests

In reality, none of these assumptions hold. Responses get corrupted. Requests get malformed. Proxies modify traffic in unexpected ways. Connections drop, timeout, or hang. TCP resets happen mid-stream.

No existing tool tests all three perspectives. DVWA only tests backends. Scanner benchmarks only test scanners. WAF testing tools only test WAFs. **Glitch tests everything.**

### Product Identity

**Name**: Glitch
**Tagline**: Break everything before production does
**Full name**: Glitch — HTTP Chaos Testing Framework

**Components**:
| Component | Binary | Description |
|-----------|--------|-------------|
| Glitch Server | `glitch` | Backend emulator — unreliable, adaptive, vulnerable |
| Glitch Scanner | `glitch-scanner` | Client emulator — aggressive, malformed, adversarial |
| Glitch Proxy | `glitch-proxy` | Middleware emulator — corrupting, filtering, chaotic |

### Three-Way Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Glitch Scanner │     │  Glitch Proxy   │     │  Glitch Server  │
│    (Client)     │────▶│   (Middleware)   │────▶│   (Backend)     │
│                 │     │                 │     │                 │
│ Attack payloads │     │ Traffic manip   │     │ Broken responses│
│ Crawling        │     │ WAF rules       │     │ Vuln endpoints  │
│ Protocol abuse  │     │ Latency inject  │     │ Error injection │
│ Fuzzing         │     │ Connection drop │     │ Adaptive behavior│
│ Evasion         │     │ Header modify   │     │ Bot detection   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
       ↓                       ↓                       ↓
┌──────────────────────────────────────────────────────────────────┐
│                    Unified Dashboard (port 8766)                  │
│  Scanner Progress | Proxy Traffic | Server Metrics | Pipeline    │
└──────────────────────────────────────────────────────────────────┘
```

### Usage Patterns

Every combination is a valid test scenario:

```
Testing your scanner:      Your Scanner    →                    → Glitch Server
Testing your backend:      Glitch Scanner  →                    → Your Backend
Testing your proxy/WAF:    Glitch Scanner  → Your Proxy         → Glitch Server
Testing your API gateway:  Glitch Scanner  → Your Gateway       → Glitch Server
Full chaos (self-test):    Glitch Scanner  → Glitch Proxy       → Glitch Server
Scanner through proxy:     Your Scanner    → Glitch Proxy       → Glitch Server
Backend behind proxy:      Glitch Scanner  → Glitch Proxy       → Your Backend
```

### Target Audiences

| Audience | What they test | How Glitch helps |
|----------|---------------|------------------|
| **Scanner/DAST developers** | Scanner detection accuracy | Glitch Server provides hundreds of real vulnerability endpoints to scan |
| **Scraper developers** | Scraper resilience | Glitch Server returns broken HTML, infinite loops, adaptive anti-bot |
| **Proxy/WAF developers** | Traffic handling correctness | Glitch Scanner sends adversarial requests; Glitch Server returns adversarial responses |
| **WAAP developers** | API protection | Glitch Scanner attacks APIs; Glitch Server emulates vulnerable APIs |
| **API gateway developers** | Routing, transformation, error handling | Adversarial traffic from both sides |
| **Load balancer developers** | Connection management | TCP-level chaos from server, connection floods from scanner |
| **Backend/API developers** | Server resilience against malicious clients | Glitch Scanner sends everything: fuzzing, protocol abuse, injection |
| **Web server developers** | HTTP protocol edge cases | Glitch Scanner tests every protocol violation imaginable |
| **Security researchers** | Vulnerability research, tool benchmarking | All OWASP categories with realistic exploitable endpoints |
| **QA engineers** | Integration testing with failure scenarios | Controlled chaos injection at any layer |
| **DevSecOps teams** | Pipeline security validation | Full scanning + proxy + server in CI/CD |

### Interim/Proxy Product Types (that Glitch Proxy emulates)

- HTTP/HTTPS proxies (forward, reverse, transparent)
- Web Application Firewalls (WAFs)
- Web Application & API Protection (WAAP)
- API gateways (Kong, Envoy, Apigee patterns)
- Load balancers (L4/L7)
- CDN edge nodes
- Service meshes (sidecar proxies)
- Rate limiters
- DDoS mitigation proxies
- Bot management platforms
- Content delivery middleware

### Client Product Types (that Glitch Scanner emulates)

- DAST scanners (Nuclei, ZAP, Burp, Acunetix, Invicti patterns)
- Web scrapers (Scrapy, Firecrawl, Playwright patterns)
- API testing tools (Postman, Insomnia patterns)
- Fuzzers (ffuf, wfuzz patterns)
- Crawlers (Googlebot, Bingbot patterns)
- Load testing tools (k6, Locust, wrk patterns)
- Security researchers (manual pentest patterns)
- Monitoring/uptime checkers
- Browser automation (Selenium, Puppeteer patterns)

### Backend Product Types (that Glitch Server emulates)

- Web applications (PHP, Rails, Django, Express, Spring patterns)
- REST APIs
- GraphQL APIs
- gRPC services (HTTP/2)
- WebSocket servers
- Server-Sent Events endpoints
- Static file servers / CDN origins
- Authentication/OAuth providers
- Email/SMTP gateways (over HTTP)
- Search engines
- CMS platforms

---

## Component 1: Glitch Server (existing, enhance)

The current glitch web server. Already has 30+ subsystems, vulnerability endpoints, error injection, adaptive behavior, admin panel.

### Enhancements needed:
1. **Nightmare mode flag** (`-nightmare`) — all error rates maximized, all chaos features enabled
2. **Scanner-aware mode** — detect when Glitch Scanner is the client, provide expected-results metadata via side channel
3. **Pipeline integration** — report metrics to unified dashboard when running in self-test mode
4. **API for expected results** — `/admin/api/expected-vulns` returns what a perfect scanner should find

## Component 2: Glitch Scanner (new, build from glitch-crawler)

A full-featured configurable HTTP client/scanner that mirrors every server capability from the attack side.

### Architecture

```
internal/scanner/
  engine.go              Main orchestrator — coordinates modules, manages workers
  config.go              Scanner configuration and profiles
  crawler.go             Page discovery, link extraction, sitemap parsing
  reporter.go            Findings collection, coverage metrics, JSON/HTML reports

  attacks/
    owasp.go             OWASP Top 10 attack payloads for all 18 lists
    injection.go         SQLi, XSS, SSRF, SSTI, command injection payloads
    auth.go              Authentication testing (brute force, token manipulation)
    fuzzing.go           Parameter, header, path, method fuzzing
    protocol.go          HTTP protocol abuse (malformed requests, method override)

  resilience/
    errors.go            Handle broken responses (corruption, truncation, garbage)
    timeouts.go          Timeout management, slow response handling
    connections.go       Connection pooling, retry logic, circuit breaking

  evasion/
    encoding.go          URL encoding, unicode, null bytes, double encoding
    headers.go           Header manipulation for WAF bypass
    fragmentation.go     Request splitting, chunked encoding abuse

  profiles/
    aggressive.go        Maximum attack surface, no stealth
    stealth.go           Evasion techniques, rate limiting, fingerprint spoofing
    nightmare.go         Everything at once — designed to crash targets
    compliance.go        Standards-compliant scanning for baseline testing

cmd/glitch-scanner/
  main.go                CLI entry point with all flags
```

### Scanner Capabilities (mirroring server features)

| Server Feature | Scanner Counterpart |
|---------------|---------------------|
| 30 error types | 30 error tolerance tests — verify scanner handles each gracefully |
| Infinite labyrinth | Crawl depth limiting, URL dedup, loop detection |
| Adaptive behavior | Adaptive crawling — adjust strategy based on server responses |
| Bot detection | Evasion techniques — fingerprint spoofing, rate adaptation |
| CAPTCHA challenges | CAPTCHA detection and reporting |
| 347+ vuln endpoints | 347+ attack payloads matching each endpoint's vulnerability type |
| Header corruption | Corrupted header parsing and tolerance |
| Cookie traps | Cookie handling, trap detection |
| JS traps | JavaScript analysis, trap identification |
| Framework emulation | Technology fingerprinting |
| TCP errors (resets, timeouts) | TCP error handling, connection recovery |

### Scanner Settings (all exposed in admin UI)

- Target URL and port
- Concurrency level (workers)
- Rate limiting (requests/sec)
- Crawl depth
- Request timeout
- User agent / fingerprint profile
- Attack modules (enable/disable individually)
- Evasion mode (none/basic/advanced/nightmare)
- Authentication credentials
- Custom headers
- Proxy configuration (for testing through Glitch Proxy)
- Report format (JSON/HTML/SARIF)
- Scope restrictions (include/exclude paths)

## Component 3: Glitch Proxy (existing, major enhancement)

Enhance from basic reverse proxy into a full middleware chaos emulator.

### Architecture

```
internal/proxy/
  proxy.go               Core reverse proxy (existing, enhance)
  interceptor.go         Request/response interception pipeline
  rules.go               WAF-like filtering rules engine

  chaos/
    latency.go           Latency injection (fixed, random, progressive, spike)
    corruption.go        Request/response corruption (headers, body, status)
    connection.go        Connection manipulation (drop, reset, half-close, slow)
    rewrite.go           URL rewriting, header injection, body modification

  waf/
    signatures.go        Attack signature detection (SQLi, XSS patterns)
    ratelimit.go         Rate limiting with multiple strategies
    geoblock.go          Geographic blocking simulation
    botblock.go          Bot detection and blocking

  modes/
    transparent.go       Pass-through with monitoring only
    waf.go               WAF behavior (block attacks)
    chaos.go             Random corruption and failures
    nightmare.go         Maximum adversarial — corrupt everything both ways

cmd/glitch-proxy/
  main.go                CLI entry point (existing, enhance)
```

### Proxy Settings (all exposed in admin UI)

- Backend target URL
- Listen address/port
- Interception mode (transparent/waf/chaos/nightmare)
- Latency injection (min/max/distribution)
- Corruption probability
- Connection drop rate
- Request modification rules
- Response modification rules
- Rate limiting thresholds
- WAF signature sets (enable/disable)
- Logging verbosity
- Traffic recording

## Nightmare Mode

A special operational mode where each component is configured for maximum adversarial behavior simultaneously. The goal: crash, hang, or corrupt the other components.

### Nightmare Scanner (attacks)
- All attack modules enabled simultaneously
- Maximum concurrency (100+ workers)
- Malformed HTTP requests (broken headers, invalid methods, oversized)
- Connection flooding (open thousands of connections)
- Slowloris attacks (hold connections open)
- Chunked encoding abuse
- Pipeline request smuggling
- Oversized headers (>64KB)
- Null bytes in every parameter
- Binary data in text fields
- Recursive/circular requests

### Nightmare Proxy (corrupts)
- Random latency spikes (0-30 seconds)
- Response body corruption (flip random bytes)
- Header injection (add conflicting headers)
- Status code randomization
- Content-Length mismatch
- Chunked encoding errors
- Connection reset mid-response
- TLS downgrade simulation
- Request duplication
- Response caching with wrong content

### Nightmare Server (breaks)
- All error types at maximum weight
- TCP resets on 50% of connections
- Infinite response bodies
- Deliberately invalid HTTP (malformed status lines, broken chunked)
- Memory-filling responses
- Connection hold (accept but never respond)
- Partial response then hang

### Survival Criteria

A service passes nightmare testing if it:
1. Does not crash or OOM
2. Recovers to normal operation after nightmare stops
3. Does not corrupt persistent state
4. Logs errors appropriately
5. Maintains health check responses throughout

---

## Self-Test Pipeline

Run all three Glitch components against each other with monitoring.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Scanner    │────▶│    Proxy     │────▶│   Server    │
│  :0 (auto)   │     │  :8080      │     │  :8765      │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                    ┌──────┴──────┐
                    │  Dashboard  │
                    │   :8766     │
                    │             │
                    │ ┌─────────┐ │
                    │ │Scanner  │ │  requests sent, findings, errors
                    │ │Metrics  │ │
                    │ ├─────────┤ │
                    │ │Proxy    │ │  requests modified, blocked, passed
                    │ │Metrics  │ │
                    │ ├─────────┤ │
                    │ │Server   │ │  requests received, errors injected
                    │ │Metrics  │ │
                    │ ├─────────┤ │
                    │ │Pipeline │ │  end-to-end latency, success rate
                    │ │Health   │ │
                    │ └─────────┘ │
                    └─────────────┘
```

### Self-Test Modes

| Mode | Scanner | Proxy | Server | Purpose |
|------|---------|-------|--------|---------|
| Baseline | compliance | transparent | normal | Verify basic functionality |
| Scanner stress | aggressive | transparent | normal | Test scanner against full server |
| Proxy stress | compliance | chaos | normal | Test proxy chaos handling |
| Server stress | compliance | transparent | aggressive | Test scanner error handling |
| Full chaos | aggressive | chaos | aggressive | Mutual stress test |
| Nightmare | nightmare | nightmare | nightmare | Maximum adversarial — survival test |

### CLI for self-test

```bash
# Run self-test with all three components
glitch selftest                           # baseline mode
glitch selftest --mode nightmare          # nightmare mode
glitch selftest --mode chaos              # full chaos
glitch selftest --duration 60s            # run for 60 seconds
glitch selftest --report report.json      # save report
```

---

## Implementation Phases

### Phase 1: Foundation
- [x] Master plan document (this file)
- [x] PRDs for each component (scanner, proxy, nightmare, selftest, audit-log)
- [x] New agent definitions (chaos-engineer, protocol-engineer)
- [x] Updated README (high-level, no hard numbers)
- [x] Updated CLAUDE.md files
- [x] Project renaming/branding where needed

### Phase 2: Scanner Core
- [x] Refactor glitch-crawler → glitch-scanner with new architecture
- [x] Scanner engine with module system
- [x] Attack modules for all OWASP lists (owasp, injection, fuzzing, protocol, auth, chaos)
- [x] Crawl engine with depth limiting and dedup
- [x] Resilience modules (error handling, timeout management)
- [x] JSON/HTML reporting
- [x] Scanner admin UI tab in dashboard (3 sub-tabs: Evaluate External, Built-in, PCAP Replay)

### Phase 3: Proxy Enhancement
- [x] Refactor glitch-proxy with interceptor pipeline
- [x] Chaos modules (latency, corruption, connection manipulation)
- [x] WAF mode with basic signature detection
- [x] Proxy admin UI tab in dashboard
- [ ] Traffic recording integration (proxy does not use internal/recorder)

### Phase 4: Nightmare Mode
- [x] Nightmare profiles for all three components (NightmareState for server/scanner/proxy)
- [ ] Survival criteria checking (only basic error rate check, no crash/OOM/state detection)
- [ ] Nightmare-specific monitoring and alerting (no monitor.go, no thresholds)
- [ ] Recovery detection (no post-nightmare health check)

### Phase 5: Self-Test Pipeline
- [x] `glitch selftest` command (6 modes: baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare)
- [x] Internal orchestration (start all three, connect, monitor)
- [ ] Unified dashboard with pipeline view (no selftest tab/display)
- [x] Self-test reporting

### Phase 6: Testing & Polish
- [x] Scanner unit tests
- [x] Proxy enhancement tests
- [ ] Self-test integration tests (no selftest test files)
- [ ] PM acceptance testing for all new features (partial — per-feature only)
- [ ] Documentation finalization (ongoing)

---

## Naming Convention Changes

### Current → New

| Current | New | Reason |
|---------|-----|--------|
| `glitch-crawler` | `glitch-scanner` | It's a scanner, not just a crawler |
| "Glitch Web Server" | "Glitch" | It's more than a web server now |
| README title | "Glitch — HTTP Chaos Testing Framework" | Describes the full product |
| `internal/scanner/` (comparison tool) | `internal/scaneval/` | Avoid collision with new scanner package |

### Binary Names
- `glitch` — Backend/server mode (default, unchanged)
- `glitch-scanner` — Scanner/client mode
- `glitch-proxy` — Proxy/middleware mode
- `glitch selftest` — Self-test pipeline (subcommand of main binary)

---

## File Structure (target state)

```
cmd/
  glitch/main.go                 Server binary + selftest subcommand
  glitch-scanner/main.go         Scanner binary (refactored from glitch-crawler)
  glitch-proxy/main.go           Proxy binary (enhanced)

internal/
  # Server subsystems (existing)
  server/handler.go
  errors/generator.go
  pages/generator.go
  content/engine.go
  labyrinth/labyrinth.go
  fingerprint/engine.go
  adaptive/engine.go
  metrics/collector.go
  dashboard/                     Admin panel + unified dashboard
  vuln/                          All vulnerability endpoints
  api/                           REST API emulation
  honeypot/                      Honeypot system
  botdetect/                     Bot detection
  captcha/                       CAPTCHA system
  framework/                     Framework emulation
  headers/                       Header corruption
  cookies/                       Cookie traps
  jstrap/                        JS traps
  health/                        Health endpoints + actuator
  search/                        Search engine sim
  email/                         Email sim
  oauth/                         OAuth/SSO
  cdn/                           CDN emulation
  i18n/                          Internationalization
  privacy/                       Privacy/consent
  websocket/                     WebSocket
  analytics/                     Analytics sim
  recorder/                      Traffic recording

  # Scanner subsystems (new)
  scanner/
    engine.go                    Scanner orchestrator
    config.go                    Configuration and profiles
    crawler.go                   Page/API discovery
    reporter.go                  Findings and coverage reports
    attacks/                     Attack modules (owasp, injection, fuzzing, protocol, auth)
    resilience/                  Error handling, timeouts, connections
    evasion/                     WAF bypass, encoding, fragmentation
    profiles/                    Scan profiles (aggressive, stealth, nightmare, compliance)

  # Proxy subsystems (new/enhanced)
  proxy/
    proxy.go                     Core proxy (existing, enhance)
    interceptor.go               Interception pipeline
    rules.go                     Rule engine
    chaos/                       Chaos modules (latency, corruption, connection, rewrite)
    waf/                         WAF modules (signatures, ratelimit, geoblock, botblock)
    modes/                       Mode implementations (transparent, waf, chaos, nightmare)

  # Scanner evaluation (renamed from internal/scanner)
  scaneval/                      Scanner profile comparison tool (existing, renamed)

  # Self-test
  selftest/
    pipeline.go                  Orchestrates scanner → proxy → server
    monitor.go                   Collects metrics from all three
    report.go                    Self-test report generation

docs/
  PLAN.md                        This file
  PRD-scanner.md                 Scanner PRD
  PRD-proxy.md                   Proxy PRD
  PRD-nightmare.md               Nightmare mode PRD
  PRD-selftest.md                Self-test pipeline PRD

tests/
  acceptance/                    Acceptance tests (existing + new)
  integration/                   Integration tests (existing + new)
  nightmare/                     Nightmare mode survival tests
```
