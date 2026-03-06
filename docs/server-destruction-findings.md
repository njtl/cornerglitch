# Server Destruction Research Findings

## Overview

Destroyer profile scanner testing against 7 common HTTP server frameworks, plus the Glitch server itself. All targets ran with default configurations (no hardening, no reverse proxy, no rate limiting).

## Test Configuration

- **Scanner profile**: `destroyer` (200 concurrent workers, no rate limit, 60s timeout)
- **Attack modules**: All enabled (OWASP, injection, fuzzing, protocol, auth, slowhttp, tls)
- **Rounds**: 3 consecutive destroyer scans per target
- **Infrastructure**: Docker containers on single host

## Target Servers

| Target | Framework | Port | Base Image |
|--------|-----------|------|------------|
| Express | Node.js Express 4 | 9001 | node:20-alpine |
| Flask | Python Flask (dev server) | 9002 | python:3.12-alpine |
| Django | Python Django (dev server) | 9003 | python:3.12-alpine |
| Go HTTP | Go net/http | 9004 | golang:1.22-alpine |
| Nginx | Nginx 1.25 | 9005 | nginx:alpine |
| Apache | Apache httpd 2.4 | 9006 | httpd:alpine |
| Puma | Ruby Puma (Rack) | 9007 | ruby:3.3-alpine |

## Results Summary

**All 7 targets survived all 3 rounds with 0 restarts and stable memory.**

| Target | HTTP Errors | EOF/Connection Errors | Notable Behavior |
|--------|-------------|----------------------|------------------|
| Express | 0 | 6 EOFs | Cleanest survival; event loop handled concurrency well |
| Flask | 0 | 0 | Surprisingly resilient for a dev server |
| Django | 0 | 2 EOFs | Minor connection drops under load |
| Go HTTP | 0 | 0 | Rock solid; goroutine-per-request handles load naturally |
| Nginx | 0 | 0 | As expected from a production server |
| Apache | 36 HTTP 501s | 0 | Most 501 responses; mod_cgi/handler limitations |
| Puma | 99 HTTP 501s | 0 | Most errors overall; Ruby thread pool saturation likely |

### Key Observations

1. **No server crashed or required restart** — default configs are more resilient than expected against HTTP-level attacks
2. **Puma was most affected** with 99 HTTP 501 errors, suggesting thread pool pressure from concurrent slow requests
3. **Apache showed moderate weakness** with 36 HTTP 501s, likely from handler/module limitations under high concurrency
4. **Express had minor EOF errors** (6 total) — Node's event loop occasionally dropped connections under 200 concurrent workers
5. **Go, Nginx, Flask showed zero errors** — Go's goroutine model and Nginx's event-driven architecture handled load cleanly

## Glitch Server Self-Test

Scanner run against the Glitch server itself (already running on port 8765):

- **Result**: Survived with 66 total errors (mix of intentional chaos responses and connection errors)
- **Post-scan health**: HTTP 403 — adaptive blocking engaged against the scanner's fingerprint
- **Behavior**: The adaptive engine correctly identified the destroyer-profile scanner as hostile and began blocking

## Analysis

### Why Everything Survived

Current scanner attacks are **well-formed HTTP requests** that servers parse and reject/handle normally:
- Slow HTTP attacks (slowloris, RUDY) are mitigated by default timeouts in most frameworks
- Large headers are rejected at the parsing layer before reaching application code
- Compression bombs require the server to actually decompress (most don't by default)
- Connection exhaustion hits OS-level limits but doesn't crash the process

### What Would Actually Kill Servers

True server destruction requires attacks that bypass HTTP parsing:
- **Raw TCP socket exhaustion**: SYN floods, half-open connections at the TCP level
- **Malformed protocol data**: Invalid HTTP framing that confuses parsers
- **Resource amplification**: Requests that trigger disproportionate server-side computation (e.g., ReDoS against actual regex-heavy routes, not just sending ReDoS patterns)
- **Memory exhaustion**: Requests designed to grow server-side state (sessions, caches, connection pools)
- **File descriptor exhaustion**: Keep-alive connections held open without sending data

### Limitations

- All targets used **default configurations** — production hardening would make them even more resilient
- Docker's resource isolation provides some protection (cgroups, memory limits)
- Single-host testing means network latency is near-zero, reducing effectiveness of timing-based attacks
- Scanner attacks go through Go's `net/http` client which enforces valid HTTP, limiting protocol-level chaos

## Future Improvements

1. **Raw socket attack module**: Bypass Go's HTTP client for malformed protocol testing
2. **Connection-level attacks**: TCP-level exhaustion, half-open floods
3. **Application-layer targeting**: Attacks tuned to specific framework weaknesses (e.g., Django ORM queries, Express middleware chains)
4. **Longer duration tests**: Sustained load over minutes/hours to find slow memory leaks
5. **Resource monitoring**: Track CPU, memory, file descriptors, and connection counts during scans
