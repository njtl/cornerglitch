# Scanner Attack Module Security Assessment

**Date**: 2026-03-05
**Scope**: Slow HTTP module, TLS module, H2 frame chaos, destroyer profile effectiveness
**Context**: All 7 target servers (Express, Flask, Django, Go, Nginx, Apache, Puma) survived 3 rounds of destroyer-profile scanning with zero crashes.

---

## Executive Summary

The scanner's attack modules generate well-formed HTTP requests routed through Go's `net/http` client. This is the fundamental limiting factor: `net/http` enforces valid HTTP framing, completes requests atomically, and manages connection lifecycle automatically. The attacks that would actually degrade or crash servers -- partial writes, half-open connections, malformed framing, raw TCP manipulation -- are precisely the ones that `net/http` prevents. The current modules are effective at *detecting vulnerabilities* but ineffective at *exploiting them for denial of service*.

---

## Per-Category Effectiveness Ratings

### 1. Slowloris (Partial Headers)
**Rating: INEFFECTIVE**

The module generates requests with many `X-Slowloris-N` headers, but Go's `net/http` client sends the entire request (headers + body) as a complete, well-formed HTTP message. Real Slowloris works by opening a TCP socket and trickling header bytes one at a time, never completing the request. The client completes every request instantly -- the server sees a normal request with unusual headers, parses it in microseconds, and responds.

**What would work**: Raw TCP socket that sends `GET / HTTP/1.1\r\nHost: target\r\n` then sends one additional header line every 10-15 seconds, keeping the connection open without completing the request. Thousands of these connections exhaust the server's connection pool.

### 2. Slow POST / RUDY
**Rating: INEFFECTIVE**

The module sets `Content-Length: 1048576` but provides a tiny body string. Go's `net/http` client sends whatever body is in the `strings.Reader` immediately. It does not drip-feed bytes. The `Content-Length` header mismatch means the server either rejects the request or reads the small body and moves on. There is no slow delivery happening.

**What would work**: Raw TCP socket that sends headers with large `Content-Length`, then writes 1 byte of body every 5 seconds. The server's request handler blocks on `io.ReadFull` waiting for the declared body size, tying up a goroutine/thread.

### 3. Slow Read
**Rating: LOW**

The module requests content with `Accept-Encoding: identity` and `Connection: keep-alive`, hoping the server holds the connection while the client reads slowly. However, Go's `net/http` client reads the full response body via `io.ReadAll` (as seen in `executeRequest`), consuming it as fast as the server can send it. The server's write buffer empties immediately.

**What would work**: Raw TCP socket that reads 1 byte at a time with long pauses. If the server's write buffer fills up, the write syscall blocks, tying up the handler goroutine. Combined with TCP window size manipulation (advertising a tiny receive window), this can hold server resources indefinitely.

### 4. Connection Exhaustion
**Rating: LOW**

The `Keep-Alive: timeout=900, max=99999` headers are suggestions from the client. Servers set their own keep-alive policies. Go's `net/http.Transport` pools and reuses connections automatically -- it does not hold thousands of idle connections open. The 10 parallel connection requests share the same connection pool.

**What would work**: Open thousands of raw TCP connections, complete the TLS handshake, send a partial HTTP request on each (but never complete it). Each connection consumes a file descriptor and a goroutine/thread on the server. With 10,000+ connections, this hits `ulimit -n` on most default configurations.

### 5. Large Headers
**Rating: MEDIUM**

This is the most realistic attack category. Servers enforce header size limits: Go defaults to 1MB (generous), Nginx defaults to 8KB, Apache to 8KB. The 64KB header requests will trigger 431 (Request Header Fields Too Large) or connection closes on most servers. While not a crash vector, it does force the server to allocate and parse large buffers before rejecting.

**Limitation**: The allocation is transient. The server rejects, frees memory, and continues. To cause real damage, these need to be sent at extreme concurrency (thousands/sec) to pressure the allocator.

### 6. Chunked Abuse
**Rating: LOW**

The chunked encoding attacks are creative (negative sizes, hex overflow, missing terminator) but are sent as the request body via `strings.Reader`. Go's `net/http` client does NOT send these as actual chunked transfer-encoding -- it sends the raw string as the body with whatever `Content-Length` matches the string length. The `Transfer-Encoding: chunked` header is set, but the client may override it or the body is already fully buffered.

Even if the chunked framing reaches the server, well-implemented HTTP parsers (Go's `net/http`, Nginx, Apache) reject malformed chunks at the parsing layer without allocating unbounded memory.

**What would work**: Raw TCP socket sending actual chunked frames with huge declared sizes, or the "chunk extension" variant with megabytes of extension data after the chunk size.

### 7. Multipart Bomb
**Rating: MEDIUM**

The 1000-part multipart body and nested multipart variants are genuinely expensive to parse. Servers that use `multipart.Reader` allocate per-part structures and parse each boundary. However, most frameworks limit `multipart.MaxMemory` (Go defaults to 32MB) and will reject or truncate. The 50-file variant with 1KB filenames is interesting because some frameworks log or process filenames in O(n) operations.

**Improvement potential**: The multipart bomb would be more effective with parts containing file upload fields that trigger disk writes (temp files). Frameworks like Django and Rails write multipart files to `/tmp` by default.

### 8. ReDoS Payloads
**Rating: LOW (against targets without vulnerable regexes)**

The ReDoS patterns are textbook correct (`(a+)+$` with non-matching suffix), but they only work if the server passes user input to a vulnerable regular expression. The Glitch server itself may have such patterns in its adaptive engine or framework emulation, but generic servers (Nginx, Apache static) don't run regex on arbitrary input. Against applications with WAF rules or input validation using backtracking regex engines, these would be HIGH.

**Key issue**: The scanner sends ReDoS strings but has no way to know which server paths feed into regex evaluation. Blind ReDoS is a numbers game.

### 9. Compression Bombs
**Rating: INEFFECTIVE**

The module sends gzip-compressed request bodies (10MB of zeros compressed to ~10KB). This requires the server to:
1. Respect `Content-Encoding: gzip` on **requests** (not responses)
2. Decompress the body before processing

Most HTTP servers do NOT decompress request bodies. Go's `net/http` does not. Nginx does not. Apache does not. Only application-level middleware that explicitly handles `Content-Encoding` on requests would be affected (rare). The double-gzip variant has the same issue.

**Contrast with response bombs**: The server's gzip_bomb error type (sending compressed responses) is far more effective because clients/scanners routinely decompress response bodies.

### 10. TLS Module (HTTP-level probes)
**Rating: LOW for DoS, MEDIUM for reconnaissance**

The HSTS checks, upgrade headers, and redirect probes are reconnaissance -- they detect misconfigurations but don't cause harm. The active TLS probing (version enumeration, cipher probing, cert analysis) is solid for auditing. No DoS potential.

### 11. TLS Module (Active Probing)
**Rating: HIGH for reconnaissance, INEFFECTIVE for DoS**

Version probing, weak cipher enumeration, ALPN testing, and downgrade detection are well-implemented using raw `tls.Dial`. The certificate analysis (expiry, self-signed, key type, chain depth) is thorough. However, none of these probe aggressively enough to cause TLS-level denial of service.

### 12. H2 Frame Chaos (Server-Side)
**Rating: HIGH for scanner disruption, N/A for scanner attack module**

The 6 H2 error types in `generator.go` are server-side responses, not scanner attacks. They are designed to crash/confuse scanners connecting to the Glitch server:
- `h2_goaway`: Panics with `http.ErrAbortHandler` to send GOAWAY frame -- kills the scanner's connection
- `h2_rst_stream`: Partial write + panic to send RST_STREAM -- corrupts the scanner's stream state
- `h2_continuation_flood`: 500 headers forcing CONTINUATION frames -- stresses scanner's HPACK decoder
- `h2_window_exhaust`: 512KB response exceeding default 64KB window -- pressures scanner's flow control
- `h2_settings_flood`: 100 headers + 50 flushed chunks -- control frame overhead
- `h2_ping_flood`: 200 rapid flushed SSE events -- forces ping/ack overhead

These are effective at **defending** (disrupting scanners) but the scanner has no equivalent **offensive** H2 attacks.

---

## Missing Attack Vectors

### Critical Gaps

1. **Raw TCP Socket Module**
   The single biggest gap. Every slow HTTP attack (Slowloris, RUDY, Slow Read) is neutered by `net/http`. A raw socket module using `net.Dial` + manual HTTP framing would enable:
   - True byte-at-a-time header dripping
   - Partial request body delivery
   - Half-open connections (SYN sent, no ACK)
   - Connection holding without data
   - Malformed HTTP framing (line splitting, header injection)

2. **HTTP/2 Client-Side Attacks**
   The server has H2 chaos but the scanner has zero H2 offensive capability:
   - CONTINUATION flood (send request with thousands of CONTINUATION frames)
   - SETTINGS flood (rapid SETTINGS frames forcing ACK processing)
   - RST_STREAM flood (open and immediately reset streams)
   - PRIORITY flood (circular priority dependencies causing CPU spin)
   - WINDOW_UPDATE manipulation (advertise zero window, then never increase)
   - Stream ID exhaustion (open max streams simultaneously)
   - HPACK bomb (craft headers that expand to huge size in HPACK decoding)

3. **TCP Window Manipulation**
   Advertise a TCP receive window of 1 byte, forcing the server to buffer entire responses in kernel memory. Combined with many connections, this exhausts server memory without the application layer being aware.

4. **TLS Renegotiation Attack**
   Repeatedly trigger TLS renegotiation on the same connection. Each renegotiation is ~10x more CPU-expensive for the server than the client (asymmetric cost). With 100 connections each renegotiating repeatedly, a single client can saturate server CPU.

5. **Hash Collision DoS (HashDoS)**
   Send requests with thousands of POST parameters or query parameters whose keys hash-collide in the server's hash table implementation. This turns O(1) lookups into O(n), causing quadratic parsing time. Effective against PHP, Python (pre-randomized hashing), Java, and Ruby.

### Moderate Gaps

6. **WebSocket Abuse**
   No WebSocket attack module. Missing: connection exhaustion via WS upgrade, frame fragmentation, large frame size, ping/pong flood, close frame abuse.

7. **HTTP Request Smuggling**
   The chunked abuse module hints at this but doesn't implement actual CL/TE or TE/CL desync attacks. Proper request smuggling requires a proxy in front of the target (which Glitch Proxy provides) and precise control over raw bytes.

8. **DNS Rebinding / SSRF Amplification**
   No attacks that exploit server-side request following. If the target follows redirects or fetches URLs from request parameters, the scanner could redirect it to internal services.

9. **Cache Poisoning**
   No attacks targeting caching layers (vary header manipulation, host header poisoning for cache keys, response splitting via header injection).

10. **Algorithmic Complexity**
    Beyond ReDoS, missing: XML entity expansion in request bodies (not just as a response bomb), JSON parsing depth attacks against streaming parsers, YAML deserialization attacks.

---

## Recommendations

### Tier 1: Maximum Impact (Raw Socket Module)

Build a `RawSocketModule` in `internal/scanner/attacks/rawsocket.go` that bypasses `net/http`:

```
net.Dial("tcp", target) -> manual HTTP framing -> byte-by-byte control
```

This single addition would transform Slowloris, RUDY, Slow Read, and chunked abuse from ineffective to highly effective. Implementation approach:
- Use `net.Dial` for TCP, `tls.Dial` for HTTPS
- Implement a minimal HTTP/1.1 request writer that can pause between bytes
- Parameterize delay between bytes, total connection count, and request completion percentage
- For Slowloris: send headers 1 line per N seconds, never send final `\r\n\r\n`
- For RUDY: send body 1 byte per N seconds
- For Slow Read: read response 1 byte per N seconds (set TCP receive buffer to minimum)

### Tier 2: High Impact (H2 Offensive)

Build an `H2AttackModule` using `golang.org/x/net/http2` (or raw framing):
- CONTINUATION flood
- SETTINGS flood
- Rapid stream open/reset
- Zero-window advertisement

Note: This would require adding `golang.org/x/net/http2` as a dependency, or implementing raw H2 frame writing over a TLS connection (stdlib only, more work).

### Tier 3: Medium Impact (Targeted Improvements)

- **Compression bombs**: Remove or re-categorize. They don't work against servers. Keep only as a response-direction test (which is already in the server's error generator).
- **Connection exhaustion**: Rewrite to use raw TCP. Open N connections, complete TLS handshake, send partial request, hold.
- **ReDoS**: Add framework-specific paths known to use regex (Django URL routing, Rails route constraints, Express path-to-regexp).
- **Multipart bomb**: Add variants that trigger temp file creation (include actual binary content in file parts, not just "data").

### Tier 4: Nice to Have

- HashDoS payload generator (language-specific hash collision strings)
- WebSocket attack module
- HTTP request smuggling (CL/TE desync) module
- Duration-based testing mode (sustain attacks for minutes, not just fire-and-forget)

---

## Key Insight: Asymmetry Problem

The fundamental issue is that the scanner uses the same HTTP client for attacks and reconnaissance. A well-behaved HTTP client is the wrong tool for denial-of-service testing. The scanner needs two execution paths:

1. **`net/http` path** (current) -- for reconnaissance, vulnerability detection, and application-layer testing
2. **Raw socket path** (missing) -- for protocol-level attacks, slow HTTP, connection exhaustion, and framing violations

Without the raw socket path, the destroyer profile is just a very fast vulnerability scanner, not a server destruction tool. The 200 concurrent workers simply send 200 well-formed requests per second, which any modern server handles trivially.

---

## Effectiveness Summary Table

| Attack Category | Current Rating | With Raw Sockets | Primary Limitation |
|----------------|---------------|-------------------|-------------------|
| Slowloris | Ineffective | High | `net/http` completes requests atomically |
| Slow POST (RUDY) | Ineffective | High | Body sent instantly via `strings.Reader` |
| Slow Read | Low | High | `io.ReadAll` consumes response immediately |
| Connection Exhaustion | Low | High | Connection pooling limits open connections |
| Large Headers | Medium | Medium | Already works at HTTP level |
| Chunked Abuse | Low | Medium | Malformed chunks rejected at parse layer |
| Multipart Bomb | Medium | Medium | Already works at HTTP level |
| ReDoS | Low* | Low* | Depends on target having vulnerable regex |
| Compression Bombs | Ineffective | Ineffective | Servers don't decompress request bodies |
| TLS Reconnaissance | High | High | Already uses raw TLS connections |
| TLS DoS | N/A | Medium | Renegotiation attacks need raw TLS |
| H2 Offensive | N/A | High | No H2 attack module exists |
| HTTP Smuggling | N/A | High | Requires raw byte control |
| HashDoS | N/A | Medium | Needs language-specific collision strings |

*ReDoS effectiveness depends entirely on target application, not scanner implementation.
