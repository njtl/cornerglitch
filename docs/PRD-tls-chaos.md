# PRD: TLS & HTTP/2 Chaos

## Overview

TLS and HTTP/2 chaos features for the Glitch server and scanner, enabling protocol-level testing beyond HTTP/1.1.

## Server-Side Features

### TLS Chaos Engine (`internal/tlschaos/`)

Five chaos levels controlled via admin dashboard:

| Level | Name | Behavior |
|-------|------|----------|
| 0 | Clean | Valid TLS 1.3, strong ciphers, valid self-signed cert |
| 1 | Downgrade | Allow TLS 1.0/1.1, force max TLS 1.2 |
| 2 | Weak Cipher | 3DES, CBC-mode, RSA key exchange |
| 3 | Cert Chaos | Rotate through valid, expired, wrong-host, weak-key certs per connection |
| 4 | Nightmare | All of above + ALPN lies (advertise h2 but serve spdy/3.1), per-client config adaptation |

Key implementation details:
- Auto-generates self-signed ECDSA P-256 certs on startup
- `GetCertificate` callback for per-connection cert selection (levels 3+)
- `GetConfigForClient` callback for per-client TLS config adaptation (level 4)
- SNI-based cert mismatch: wrong-host cert when SNI doesn't match hostname
- Weak-key cert uses P-224 curve (rejected by modern TLS stacks — intentional chaos)

### HTTPS Listener

- Port 8767 (configurable via `-tls-port`, `0` to disable)
- HTTP/2 auto-enabled by Go stdlib over TLS via ALPN
- Custom cert/key via `-cert`/`-key` flags or `GLITCH_TLS_CERT`/`GLITCH_TLS_KEY` env vars
- Self-signed cert auto-generated if none provided

### HTTP/2 Frame-Level Chaos

Six new error types in `internal/errors/generator.go`:

| Error Type | Mechanism | Effect |
|-----------|-----------|--------|
| `h2_goaway` | `panic(http.ErrAbortHandler)` | Triggers GOAWAY frame, tears down connection |
| `h2_rst_stream` | Partial write + abort | RST_STREAM on the active stream |
| `h2_settings_flood` | 100 headers + 50 flushed chunks | Maximizes SETTINGS frame overhead |
| `h2_window_exhaust` | 512KB response in 64KB chunks | Pressures flow control window |
| `h2_continuation_flood` | 500 headers (50KB total) | Forces CONTINUATION frame generation |
| `h2_ping_flood` | 200 flushed SSE events | Maximizes ping/ack control frame overhead |

### HSTS Chaos

Injects random `Strict-Transport-Security` headers per client+path:
- Lock: `max-age=999999999; includeSubDomains; preload`
- Disable: `max-age=0`
- Short-lived: `max-age=60; includeSubDomains`
- Conflicting: multiple HSTS headers with different values
- Controlled via `hsts_chaos_enabled` admin config

## Scanner-Side Features

### TLS Attack Module (`internal/scanner/attacks/tls.go`)

HTTP-level probes:
- HSTS header presence across content types
- TLS upgrade header testing (TLS 1.0-1.3)
- HTTP→HTTPS redirect behavior
- X-Forwarded-Proto spoofing
- Mixed-case scheme in Host header

Active TLS probing:
- TLS version probing (1.0, 1.1, 1.2, 1.3)
- Weak cipher suite enumeration (3DES, RC4, CBC)
- Certificate analysis (expiry, hostname match, self-signed, key type/size)
- ALPN protocol probing (h2, http/1.1, h2c, spdy/3.1)
- TLS downgrade testing

### Slow HTTP Attack Module (`internal/scanner/attacks/slowhttp.go`)

Server-destruction attack types:
- **Slowloris**: Partial headers with keep-alive
- **Slow POST (RUDY)**: Large Content-Length, tiny body
- **Slow READ**: Identity encoding, slow response consumption
- **Connection Exhaustion**: Aggressive keep-alive settings
- **Large Headers**: 32KB-64KB header payloads
- **Chunked Abuse**: Invalid sizes, infinite chunks, trailer bombs
- **Multipart Bombs**: 1000 parts, nested multipart, long filenames
- **ReDoS Payloads**: Catastrophic backtracking patterns via URL params, POST body, headers
- **Compression Bombs**: Gzip-compressed 10MB of zeros, double compression

### Destroyer Profile

New scan profile (`-profile destroyer`) for server destruction testing:
- 200 concurrent workers, no rate limiting
- 60s timeout, 8MB max body read
- All attack modules enabled
- No crawling (direct attack)
- Keep-alive with extreme timeout settings

## Admin Dashboard Integration

- TLS Chaos Level slider (0-4) in Protocol section
- TLS Chaos Enabled toggle
- HSTS Chaos Enabled toggle
- Config export/import includes TLS settings

## Architecture Decisions

1. **No HTTP/3**: Requires `quic-go` external dep — deferred to future sprint
2. **H2 frame chaos via handler-level mechanisms**: Go's HTTP/2 doesn't expose frame APIs; using handler panics, large headers, and flushed chunks to affect framing
3. **`http.ErrAbortHandler` for GOAWAY/RST_STREAM**: Bypasses server's panic recovery, signals Go's HTTP server to abort the connection
4. **Self-signed certs**: Auto-generated on startup; real certs optional via flags/env
