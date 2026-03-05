# Sprint Plan — 2026-03-06 Protocol Chaos & Server Destruction

## Status: NOT STARTED

## MANDATORY RULE: Plan Audit at Session Start

**Before ANY work begins, the agent MUST:**

1. Read this file in full
2. Count all items marked with unchecked status
3. Print the count: `"PLAN AUDIT: X items remaining out of Y total"`
4. **Refuse to close the sprint until that count is ZERO**
5. After completing each item, mark it and re-count
6. If context runs out, the continuation session MUST re-audit before resuming

**The sprint is NOT done until every single item is done.**

---

## Sprint Goals

Three major features, implemented and validated:

1. **HTTP/2 + TLS Chaos** — Add HTTPS listener to Glitch server, implement HTTP/2 frame-level chaos, TLS handshake chaos, certificate manipulation. Add corresponding capabilities to the built-in scanner.
2. **TLS/Domain Chaos** — Version downgrade, weak ciphers, cert chaos (expired/wrong-host/self-signed), ALPN lies, SNI routing chaos, HSTS manipulation. Scanner-side TLS testing.
3. **Server Destroyer Research & Implementation** — Run the built-in scanner in nightmare mode against real web servers (Docker containers: Express, Flask, nginx, Apache, Go net/http). Document which attacks crash which servers. Implement missing attack types (slowloris, compression bombs, ReDoS, multipart bombs). Validate server destruction is stable and reproducible.

---

## Sprint Rules

1. **All implementations MUST include tests** — unit tests for new code, integration tests for end-to-end
2. **No external deps** — stdlib only (exception: `github.com/lib/pq` already allowed)
3. **HTTP/3 is OUT OF SCOPE** — requires `quic-go` external dep, defer to future sprint
4. **Docker targets only** — never test against external services. All targets are localhost containers we control.
5. **Document everything** — every finding, crash, test result goes into docs
6. **CI must stay green** — every commit must pass `go build ./... && go vet ./... && go test ./... -count=1 -timeout 600s`
7. **Use feature branches** — PR workflow for all changes
8. **Track work in sprint file** — update items as completed
9. **Final PM acceptance gate** — sprint not done until PM validates
10. **Telegram notification** after sprint completion

---

## Phase 1 — HTTP/2 & TLS Infrastructure (Server)

### 1.1 Add TLS listener to Glitch server
- [ ] **1.1.1** Add `-cert` and `-key` CLI flags to `cmd/glitch/main.go`
- [ ] **1.1.2** Add `-tls-port` flag (default 8767) for HTTPS listener
- [ ] **1.1.3** Implement `ListenAndServeTLS()` alongside existing HTTP listener (both run concurrently)
- [ ] **1.1.4** Auto-generate self-signed cert on startup if no cert/key provided (using `crypto/x509` + `crypto/ecdsa`)
- [ ] **1.1.5** Log TLS listener address and cert info on startup
- [ ] **1.1.6** Add `GLITCH_TLS_CERT` and `GLITCH_TLS_KEY` env vars (loaded from .env)
- [ ] **1.1.7** HTTP/2 auto-enabled by Go stdlib over TLS — verify with `curl -v --http2 https://localhost:8767/`
- [ ] **1.1.8** Update `.env.example` with TLS variables

### 1.2 TLS chaos engine (`internal/tls/`)
- [ ] **1.2.1** Create `internal/tls/chaos.go` — TLS config builder with chaos levels 0-4
- [ ] **1.2.2** Level 0: clean TLS 1.3, strong ciphers, valid cert
- [ ] **1.2.3** Level 1: TLS version downgrade (force TLS 1.2, allow TLS 1.0/1.1)
- [ ] **1.2.4** Level 2: Weak cipher suites (RC4, 3DES, export-grade where Go allows)
- [ ] **1.2.5** Level 3: Certificate chaos — per-request cert selection via `GetCertificate` callback:
  - Expired cert (NotAfter in the past)
  - Wrong hostname cert (CN=evil.example.com)
  - Self-signed cert with untrusted CA
  - Cert with weak key (RSA-1024)
- [ ] **1.2.6** Level 4: All of above + ALPN lies (advertise h2 but serve h1), renegotiation abuse, random TLS alerts, session ticket rejection
- [ ] **1.2.7** `GetConfigForClient` callback — adapt TLS config per-client based on fingerprint (JA3-style ClientHello classification)
- [ ] **1.2.8** Wire TLS chaos config to admin API: `tls_chaos_level` (0-4), `tls_chaos_enabled` feature flag
- [ ] **1.2.9** Unit tests for each TLS chaos level

### 1.3 HTTP/2 chaos in error generator
- [ ] **1.3.1** Add new error types to `internal/errors/generator.go`:
  - `h2_goaway` — send GOAWAY frame (close connection with error code)
  - `h2_rst_stream` — reset individual stream
  - `h2_settings_flood` — rapid SETTINGS frames
  - `h2_window_exhaust` — zero-size WINDOW_UPDATE (flow control stall)
  - `h2_continuation_flood` — many small CONTINUATION frames
  - `h2_ping_flood` — rapid PING frames
- [ ] **1.3.2** Implement HTTP/2 frame writing using raw `net.Conn` via hijacking (Go's `http2` internal package doesn't expose frame-level API, so write raw frames)
- [ ] **1.3.3** Add H2 error types to `IsProtocolGlitch`, error profiles, `errTypeToStatus`
- [ ] **1.3.4** Gate H2 errors behind `protocol_glitch_enabled` + connection must be HTTP/2
- [ ] **1.3.5** Unit tests for H2 error types
- [ ] **1.3.6** Update CLAUDE.md with new error types

---

## Phase 2 — TLS & Domain Chaos Features

### 2.1 Domain-level chaos
- [ ] **2.1.1** HSTS chaos in response headers: random `max-age` (0 to disable, 999999999 to lock), `includeSubDomains`, `preload` — toggled by `hsts_chaos_enabled` feature flag
- [ ] **2.1.2** SNI-based cert selection — serve wrong cert when SNI doesn't match, serve different TLS versions per SNI hostname
- [ ] **2.1.3** HTTP→HTTPS redirect chaos — random redirects between protocols, redirect loops, 301 vs 302 vs 307 vs 308 mixing
- [ ] **2.1.4** Wire all domain chaos to admin API feature flags

### 2.2 Scanner-side TLS capabilities
- [ ] **2.2.1** Create `internal/scanner/attacks/tls.go` — TLS testing attack module
- [ ] **2.2.2** TLS version probing: test target for TLS 1.0, 1.1, 1.2, 1.3 support
- [ ] **2.2.3** Cipher suite enumeration: test which cipher suites target accepts
- [ ] **2.2.4** Certificate validation: check expiry, hostname match, issuer, key strength
- [ ] **2.2.5** ALPN probing: test h2, http/1.1, h2c support
- [ ] **2.2.6** Downgrade testing: try forcing lower TLS versions
- [ ] **2.2.7** Add TLS findings to scanner reporter
- [ ] **2.2.8** Unit tests for TLS attack module

---

## Phase 3 — Server Destroyer Scanner Enhancements

### 3.1 New attack types for server destruction
- [ ] **3.1.1** Slowloris attack: open connections, send partial headers slowly (1 byte/s), keep connections alive indefinitely — `internal/scanner/attacks/slowhttp.go`
- [ ] **3.1.2** Slow POST (R-U-Dead-Yet): send POST with large Content-Length, drip body 1 byte/s
- [ ] **3.1.3** Slow READ: read response body 1 byte/s, keeping server connection open
- [ ] **3.1.4** Compression bomb requests: gzip-encode request body with high compression ratio (accept `Content-Encoding: gzip` in requests)
- [ ] **3.1.5** Multipart form bomb: send multipart/form-data with thousands of parts, huge boundaries, nested multiparts
- [ ] **3.1.6** ReDoS payloads: regex patterns that cause catastrophic backtracking (e.g., `(a+)+$` with many `a`s)
- [ ] **3.1.7** Hash collision payloads: many POST parameters with hash-colliding keys (HashDoS)
- [ ] **3.1.8** Large header attack: send requests with headers totaling 64KB+ to exhaust server header buffers
- [ ] **3.1.9** Connection exhaustion: open many connections rapidly without closing them
- [ ] **3.1.10** Chunked request abuse: send chunked-encoded requests with invalid chunk sizes, infinite chunks, trailer bombs
- [ ] **3.1.11** Wire all new attacks to scanner's nightmare profile
- [ ] **3.1.12** Unit tests for each new attack type

### 3.2 Scanner configuration for server destruction mode
- [ ] **3.2.1** Add `destroyer` scan profile to `internal/scanner/config.go` — max aggression, all attack modules, no rate limit, no evasion (pure throughput)
- [ ] **3.2.2** Add `-profile destroyer` to CLI
- [ ] **3.2.3** Add slow HTTP configuration: `slow_http_enabled`, `slow_http_connections` (number of simultaneous slow connections)

---

## Phase 4 — Server Destruction Research

### 4.1 Set up Docker test targets
- [ ] **4.1.1** Create `tests/targets/` directory with Dockerfiles
- [ ] **4.1.2** Express.js (Node.js) — minimal HTTP server, default config
- [ ] **4.1.3** Flask (Python) — minimal WSGI server, default config
- [ ] **4.1.4** Django (Python) — minimal project, runserver
- [ ] **4.1.5** Go net/http — minimal stdlib server, default config
- [ ] **4.1.6** nginx — default config, serving static files
- [ ] **4.1.7** Apache httpd — default config, mod_cgi enabled
- [ ] **4.1.8** Ruby Rack/Puma — minimal Rack app
- [ ] **4.1.9** Each target exposes on a unique port (9001-9008), health endpoint at /health

### 4.2 Run scanner against each target
- [ ] **4.2.1** Run `glitch-scanner -target <target> -profile destroyer` against each Docker target
- [ ] **4.2.2** Monitor each target: CPU, memory, response time, error count, crash/OOM/hang detection
- [ ] **4.2.3** For each target, record: which attacks caused crashes, hangs, OOM, 5xx floods
- [ ] **4.2.4** Run at least 3 times per target for reproducibility
- [ ] **4.2.5** Document all findings in `docs/server-destruction-findings.md`

### 4.3 Run scanner through proxy (triple chaos)
- [ ] **4.3.1** Start Glitch Proxy in nightmare mode between scanner and each target
- [ ] **4.3.2** Record additional chaos from proxy layer (corruption, drops, resets)
- [ ] **4.3.3** Document which attacks are amplified by proxy chaos

### 4.4 Run scanner against Glitch server itself
- [ ] **4.4.1** `glitch-scanner -target http://localhost:8765 -profile destroyer` — scanner vs Glitch nightmare
- [ ] **4.4.2** Monitor Glitch server stability (it should survive — this validates robustness)
- [ ] **4.4.3** Document any Glitch server weaknesses found

---

## Phase 5 — Integration & Documentation

### 5.1 Integration testing
- [ ] **5.1.1** Integration test: scanner connects to Glitch server over HTTPS (HTTP/2)
- [ ] **5.1.2** Integration test: TLS chaos level 4 causes scanner resilience mechanisms to activate
- [ ] **5.1.3** Integration test: slow HTTP attacks against Docker target cause measurable degradation
- [ ] **5.1.4** All existing tests still pass (`go test ./... -count=1 -timeout 600s`)

### 5.2 Documentation
- [ ] **5.2.1** Update CLAUDE.md with TLS/HTTP/2 features, new error types, new scanner modules
- [ ] **5.2.2** Update readme.md with TLS listener docs, scanner destroyer profile
- [ ] **5.2.3** Create `docs/server-destruction-findings.md` with all research results
- [ ] **5.2.4** Create `docs/PRD-tls-chaos.md` with TLS chaos feature spec

### 5.3 Sprint completion
- [ ] **5.3.1** `go build ./... && go vet ./...` clean
- [ ] **5.3.2** `go test ./... -count=1 -timeout 600s` all pass
- [ ] **5.3.3** Create PR, CI green, merge
- [ ] **5.3.4** PM acceptance testing
- [ ] **5.3.5** Verify all plan items are completed — full audit
- [ ] **5.3.6** Send Telegram notification
- [ ] **5.3.7** Write `done_2026-03-06.md`

---

## Item Count

| Phase | Items | Done |
|-------|-------|------|
| 1. HTTP/2 & TLS Infrastructure | 23 | 0 |
| 2. TLS & Domain Chaos | 12 | 0 |
| 3. Scanner Destroyer Enhancements | 15 | 0 |
| 4. Server Destruction Research | 13 | 0 |
| 5. Integration & Documentation | 11 | 0 |
| **TOTAL** | **74** | **0** |

---

## Research Findings (Pre-Sprint)

### HTTP/2 Architecture Decision
- Go stdlib auto-enables HTTP/2 over TLS via ALPN negotiation
- HTTP/2 frame-level chaos requires raw TCP writing (hijack after TLS handshake)
- Go's `http2` internal package doesn't expose frame APIs publicly
- Solution: write raw HTTP/2 frames using known binary format (9-byte frame header + payload)
- HTTP/3 deferred (requires `quic-go` external dep)

### TLS Architecture Decision
- Nginx currently terminates TLS at someportal.online (Let's Encrypt)
- Glitch server adds its OWN TLS listener on a separate port (8767)
- Both clean (nginx) and chaos (Glitch direct) TLS available simultaneously
- TLS chaos uses `GetConfigForClient` callback for per-connection config
- Self-signed cert auto-generated on startup if none provided

### Scanner-vs-Server Research
- Built-in scanner already has 80+ attack types, 1000+ requests per scan
- Missing server-killing attacks: slowloris, compression bombs, ReDoS, HashDoS, multipart bombs
- Test targets: Docker containers (Express, Flask, Django, Go, nginx, Apache, Ruby)
- Glitch server itself should SURVIVE scanner nightmare (validates robustness)
- Triple chaos: Scanner nightmare → Proxy nightmare → Target

### Server Vulnerability Predictions
Based on known weaknesses:

| Server | Expected Weakness | Attack Type |
|--------|------------------|-------------|
| Express.js | No request size limits, JSON parsing bombs | Large headers, JSON depth, ReDoS |
| Flask | Single-threaded, synchronous | Slowloris, slow POST, connection exhaustion |
| Django runserver | Development server, not production-grade | Any sustained load, slowloris |
| nginx | Robust, but configurable limits | Large headers exceeding `large_client_header_buffers` |
| Apache | mod_cgi overhead, keep-alive abuse | Slowloris (classic), request smuggling |
| Go net/http | Robust, but `ReadAll` patterns | Compression bombs, infinite chunked |
| Ruby Puma | Thread pool limited | Connection exhaustion, slow POST |

---

## Key Metrics for Success

1. **HTTP/2 chaos**: At least 4 new H2-specific error types firing over TLS connections
2. **TLS chaos**: At least 4 TLS chaos levels working (downgrade, weak cipher, bad cert, ALPN lie)
3. **Scanner TLS**: Scanner can detect TLS version, cipher suite, cert validity of targets
4. **Server destruction**: At least 4 of 7 Docker targets crashed/hung/OOMed by scanner
5. **Glitch resilience**: Glitch server survives scanner destroyer mode (0 crashes)
6. **CI green**: All tests pass throughout sprint
7. **Documented**: All findings in docs/ with reproducibility data
