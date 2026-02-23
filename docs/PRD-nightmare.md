# PRD: Nightmare Mode

## Overview

Nightmare Mode is a special operational configuration where Glitch components are tuned for maximum adversarial behavior. The goal is to crash, hang, corrupt, or exhaust the target service. If a service survives nightmare mode, it can handle anything production throws at it.

## Problem Statement

Resilience testing is typically gentle — tools send a few bad requests and check for crashes. Real-world attacks are sustained, multi-vector, and escalating. HTTP services need to prove they can survive sustained adversarial traffic at every protocol layer simultaneously. No existing tool provides this level of coordinated chaos.

## User Stories

1. As a **backend developer**, I want to prove my server doesn't crash or OOM under sustained adversarial traffic from a nightmare scanner.
2. As a **proxy developer**, I want to prove my proxy handles corrupted traffic from both client and server sides simultaneously.
3. As a **scanner developer**, I want to prove my scanner handles every possible server misbehavior without crashing.
4. As a **SRE**, I want to run nightmare mode in staging before production deployments to validate resilience.
5. As a **security auditor**, I want a reproducible adversarial test that proves service hardening.

## Nightmare Profiles

### Nightmare Scanner

Attack intensity: everything enabled, maximum volume.

| Attack Vector | Parameters |
|--------------|------------|
| Connection flooding | 100+ concurrent connections, rapid open/close |
| Slowloris | Hold connections open with slow headers (1 byte/2sec) |
| Oversized requests | Headers > 64KB, URLs > 8KB, body > 100MB |
| Malformed HTTP | Invalid methods, broken headers, null bytes everywhere |
| Request smuggling | CL.TE, TE.CL, TE.TE desync payloads |
| Chunked abuse | Invalid chunk sizes, zero-length chunks, interleaved data |
| All OWASP payloads | Every attack from all 18 lists simultaneously |
| Recursive requests | Requests that trigger server-to-server requests |
| Binary injection | Binary data in text parameters, headers, cookies |
| Encoding madness | Mixed URL encoding, overlong UTF-8, BOM injection |
| Method confusion | PATCH on GET endpoints, OPTIONS everywhere, custom methods |
| Header bombs | Thousands of headers per request, duplicate headers |

### Nightmare Proxy

Corruption intensity: everything modified, both directions.

| Corruption Vector | Parameters |
|------------------|------------|
| Latency spikes | Random 0-30 second delays |
| Response corruption | Flip 1-5% of response bytes randomly |
| Header injection | Add conflicting Content-Type, Content-Length headers |
| Status code randomization | Replace 200 with random 4xx/5xx |
| Connection resets | RST 20% of connections mid-transfer |
| Body truncation | Cut responses at random point |
| Request duplication | Forward 10% of requests twice |
| Cache confusion | Return wrong cached responses |
| Encoding mismatch | Declare gzip but send plain, declare UTF-8 but send latin1 |
| Chunked errors | Invalid chunk framing in both directions |

### Nightmare Server

Response chaos: maximum errors, minimum cooperation.

| Error Vector | Parameters |
|-------------|------------|
| All error types maxed | All 30 error types weighted equally |
| TCP resets | 50% of connections |
| Infinite responses | Never-ending chunked streams |
| Malformed HTTP | Invalid status lines, broken headers |
| Slow responses | 1 byte/second for all responses |
| Connection holding | Accept but never respond (30+ seconds) |
| Content-Length lies | Advertise 100 bytes, send 1MB (or vice versa) |
| Adaptive escalation | Get progressively worse the more requests a client sends |
| Cookie bombs | Set cookies that exceed browser limits |
| Redirect loops | Chain of 301/302 redirects back to self |

## Survival Criteria

A service **passes** nightmare testing if it meets ALL of the following:

### Mandatory (must pass)

| # | Criterion | How to verify |
|---|-----------|---------------|
| 1 | **No crash**: Process stays alive throughout | Process monitoring, exit code check |
| 2 | **No OOM**: Memory usage stays below 2x baseline | RSS monitoring every 1 second |
| 3 | **No goroutine leak**: Count returns to baseline within 30s of nightmare stop | runtime.NumGoroutine() check |
| 4 | **Recovery**: Service returns to normal operation within 10s of nightmare stop | Health check polling |
| 5 | **Health check**: /health/live responds throughout (may be slow) | Periodic GET with 30s timeout |
| 6 | **No data corruption**: Persistent state (if any) is not corrupted | State checksum before/after |

### Recommended (should pass)

| # | Criterion | How to verify |
|---|-----------|---------------|
| 7 | **Logging**: All errors are logged without log flooding | Log line count stays reasonable |
| 8 | **Graceful degradation**: Returns 503 rather than corrupted responses | Response validation |
| 9 | **Connection cleanup**: All connections closed within 60s of nightmare stop | netstat/ss check |
| 10 | **Resource release**: File descriptors return to baseline | /proc/self/fd count |

## Implementation

### Nightmare CLI Flags

```bash
# Server nightmare mode
glitch -nightmare                              # enable nightmare server
glitch -nightmare -nightmare-intensity 0.8     # 80% of max chaos

# Scanner nightmare mode
glitch-scanner -profile nightmare -target http://...

# Proxy nightmare mode
glitch-proxy -mode nightmare -target http://...

# Self-test nightmare
glitch selftest --mode nightmare --duration 60s --report nightmare-report.json
```

### Nightmare Configuration (admin API)

```json
POST /admin/api/nightmare
{
  "enabled": true,
  "intensity": 1.0,
  "components": ["server", "scanner", "proxy"],
  "duration_seconds": 60,
  "survival_checks": true
}
```

### Monitoring During Nightmare

The dashboard shows a special "Nightmare" panel when active:
- Timer: elapsed / remaining
- Memory usage graph (real-time)
- Goroutine count graph
- Request success/failure rate
- Connection count
- Error rate by type
- Survival criteria status (green/red indicators)

## Acceptance Criteria

1. Nightmare mode can be enabled via CLI flag and admin API
2. Nightmare scanner generates all specified attack vectors
3. Nightmare proxy corrupts traffic as specified
4. Nightmare server enables all error types at maximum weight
5. Survival criteria are automatically checked and reported
6. Service under test recovers within specified timeframes
7. Nightmare dashboard panel shows real-time metrics
8. Self-test in nightmare mode produces a pass/fail report
9. Glitch Server survives its own nightmare scanner (eating your own dogfood)
10. Nightmare intensity is configurable (0.0-1.0 scale)

## Risks

- Nightmare mode may trigger OS-level protections (TCP backlog, file descriptor limits)
- Container environments may OOM-kill nightmare processes
- Network equipment between components may interfere (firewalls, rate limiters)

## Mitigation

- Document required OS tuning (sysctl settings, ulimits)
- Provide Dockerfile with appropriate limits pre-configured
- Support local-only mode (all components on localhost) to avoid network interference
