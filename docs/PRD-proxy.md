# PRD: Glitch Proxy (Enhanced)

## Overview

Glitch Proxy is an HTTP middleware chaos emulator. It sits between client and server, simulating the behavior of proxies, WAFs, WAAPs, API gateways, load balancers, CDN edge nodes, and other intermediary services — including their failure modes.

## Problem Statement

Proxy/WAF/gateway developers need to test how their products handle adversarial traffic from both directions. Backend developers need to test how their servers behave behind misbehaving proxies. Scanner developers need to test how their tools handle modified responses. No existing tool provides a configurable, adversarial HTTP proxy that can simulate the full range of intermediary behaviors.

## Product Types Emulated

| Type | Key Behaviors |
|------|--------------|
| Forward proxy | Client-side proxy, may modify requests |
| Reverse proxy | Server-side proxy, may cache/modify responses |
| WAF | Blocks attack payloads, may false-positive on legitimate traffic |
| WAAP | API-aware WAF with schema validation |
| API gateway | Authentication, rate limiting, routing, transformation |
| Load balancer (L7) | Request distribution, health checking, sticky sessions |
| CDN edge | Caching, geographic routing, DDoS mitigation |
| Service mesh sidecar | mTLS, observability injection, circuit breaking |
| Rate limiter | Token bucket, sliding window, concurrent request limits |
| DDoS mitigation | SYN cookies, JavaScript challenges, fingerprinting |
| Bot management | Bot detection, CAPTCHA injection, behavioral analysis |

## User Stories

1. As a **backend developer**, I want to test my server behind a proxy that randomly corrupts responses, to verify my error pages still work.
2. As a **WAF developer**, I want to compare my WAF's behavior against Glitch Proxy's WAF mode to benchmark false positive rates.
3. As a **scanner developer**, I want to run my scanner through a chaotic proxy to test how it handles modified responses.
4. As a **API gateway developer**, I want to simulate API gateway behaviors (rate limiting, auth, transformation) to test client compatibility.
5. As a **QA engineer**, I want to inject latency and errors between my frontend and backend to test timeout handling.

## Functional Requirements

### FR-1: Interception Pipeline

Requests and responses pass through a configurable pipeline of interceptors. Each interceptor can:
- Inspect the request/response
- Modify headers, body, status
- Block the request (return error response)
- Delay the request/response
- Drop the connection
- Log/record traffic

Pipeline order is configurable. Interceptors can be individually enabled/disabled.

### FR-2: Chaos Modules

| Module | Effects |
|--------|---------|
| **Latency injection** | Fixed delay, random (uniform/normal), progressive increase, periodic spikes |
| **Response corruption** | Flip random bytes in body, truncate response, inject garbage, wrong Content-Type |
| **Header manipulation** | Add/remove/modify headers, duplicate headers, conflicting values |
| **Status code override** | Replace status codes randomly or by rule |
| **Connection chaos** | Drop connection mid-transfer, RST after headers, half-close, slow drain |
| **Body rewriting** | Inject content into HTML, modify JSON responses, add tracking pixels |
| **Content-Length mismatch** | Advertise wrong size, cause client buffer issues |
| **Chunked encoding errors** | Invalid chunk sizes, premature termination, missing trailers |
| **Cache poisoning sim** | Return cached responses for wrong URLs |
| **Request duplication** | Forward request multiple times to backend |

### FR-3: WAF Mode

Basic WAF signature detection:
- SQL injection patterns (UNION, OR 1=1, etc.)
- XSS patterns (script tags, event handlers)
- Path traversal patterns (../, etc.)
- Command injection patterns (|, ;, backtick)
- Configurable block action (403, drop connection, return custom page, redirect to CAPTCHA)
- False positive simulation (block N% of legitimate requests)

### FR-4: Rate Limiting

Multiple strategies:
- Token bucket (requests per second)
- Sliding window (requests per time window)
- Concurrent request limit
- Per-IP / per-path / per-method limits
- Configurable response on limit (429, 503, queue, slow)

### FR-5: Proxy Modes

| Mode | Behavior |
|------|----------|
| `transparent` | Pass-through with monitoring only — no modifications |
| `waf` | WAF behavior — detect and block attack patterns |
| `chaos` | Random failures, latency, corruption — configurable probability |
| `gateway` | API gateway behavior — auth, rate limiting, transformation |
| `nightmare` | Maximum adversarial — corrupt everything in both directions |

### FR-6: Admin UI Integration

New "Proxy" tab in admin dashboard:
- Backend target configuration
- Mode selection
- Chaos module enable/disable and configuration
- Real-time traffic view (requests passing through)
- Metrics: total proxied, blocked, modified, errored
- Latency histogram
- WAF detection log

### FR-7: CLI Interface

```bash
glitch-proxy -target http://backend:8080                           # transparent
glitch-proxy -target http://backend:8080 -mode waf                # WAF mode
glitch-proxy -target http://backend:8080 -mode chaos -corrupt 0.1 # 10% corruption
glitch-proxy -target http://backend:8080 -mode nightmare          # full chaos
glitch-proxy -target http://backend:8080 -mode gateway -ratelimit 100/s
glitch-proxy -target http://backend:8080 -latency 50-200ms        # add 50-200ms latency
glitch-proxy -target http://backend:8080 -listen :9090             # custom listen port
```

### FR-8: Traffic Recording

Record all traffic passing through the proxy:
- Request/response pairs with timestamps
- Modifications made by interceptors
- Block decisions and reasons
- Latency measurements (client→proxy, proxy→backend, total)

## Non-Functional Requirements

- **NFR-1**: Zero external dependencies (Go stdlib only)
- **NFR-2**: < 5ms added latency in transparent mode
- **NFR-3**: Handle 1000+ concurrent connections
- **NFR-4**: Graceful handling of backend failures
- **NFR-5**: No goroutine leaks under any mode

## Acceptance Criteria

1. Transparent mode adds < 5ms latency and does not modify traffic
2. WAF mode detects and blocks basic SQLi, XSS, path traversal payloads
3. Chaos mode corrupts responses at configured probability rate
4. Nightmare mode degrades both request and response traffic adversarially
5. Rate limiting correctly enforces configured limits
6. Admin UI shows real-time proxy metrics and traffic
7. Traffic recording captures all proxied requests with modifications
8. Proxy handles backend timeouts and connection failures gracefully
9. Proxy works correctly in the self-test pipeline (scanner → proxy → server)
10. All CLI flags match documented interface

## Dependencies

- Dashboard must support new Proxy tab
- Self-test pipeline must orchestrate proxy startup/shutdown

## Out of Scope (v1)

- TLS termination (proxy runs HTTP only, TLS termination via external tool)
- HTTP/2 proxying (HTTP/1.1 only in v1)
- WebSocket proxying (passthrough only)
- Sticky sessions / session affinity
