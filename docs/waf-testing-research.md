# WAF/WAAP Testing Research — Glitch vs Real WAFs

## Executive Summary

This document catalogs open-source and free WAF solutions deployable locally via Docker, their known weaknesses, and how Glitch's three components (scanner, server, proxy) can be weaponized against them. The goal: deploy real WAFs, then systematically break, bypass, exhaust, and confuse them.

---

## Part 1: Top WAFs to Test (Ranked by Deployability + Attack Surface)

### 1. ModSecurity + OWASP CRS (via NGINX)

**Type**: Reverse proxy WAF (nginx module)
**Why #1**: The most widely deployed open-source WAF. Largest documented attack surface. Extensive CVE history. OWASP CRS is the gold standard ruleset — if Glitch can bypass CRS, it can bypass most rule-based WAFs.

**Docker Deployment**:
```yaml
# docker-compose.yml
version: '3'
services:
  modsecurity:
    image: owasp/modsecurity-crs:nginx-alpine
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - BACKEND=http://glitch-server:8765
      - PARANOIA=1                    # 1-4, higher = stricter
      - ANOMALY_INBOUND=5             # block threshold
      - ANOMALY_OUTBOUND=4
      - MODSEC_RULE_ENGINE=on
      - MODSEC_AUDIT_LOG=/var/log/modsecurity/audit.log
    volumes:
      - ./modsec-logs:/var/log/modsecurity
    networks:
      - waf-net

  glitch-server:
    build: .
    environment:
      - GLITCH_ADMIN_PASSWORD=testing
    networks:
      - waf-net

networks:
  waf-net:
```

**Verify Running**: `curl -I http://localhost:8080/` should return 200. Test blocking: `curl "http://localhost:8080/?id=1%20OR%201=1"` should return 403.

**Config Location**: Rules in `/etc/modsecurity.d/owasp-crs/`, main config at `/etc/modsecurity.d/modsecurity.conf`. Override via `MODSEC_*` env vars or mount custom rules.

**Known Weaknesses & CVEs**:
- **CVE-2024-1019** (CRITICAL): URL path bypass — ModSecurity 3.0.0–3.0.11 decodes percent-encoded chars before splitting URL path from query string, hiding payloads from path-inspecting rules
- **CVE-2022-48279**: Multipart request parsing bypass in ModSecurity < 2.9.6 and 3.x < 3.0.8
- **CVE-2023-24021**: Null byte handling in file uploads allows WAF bypass (< 2.9.7)
- **Nested JSON DoS**: Deeply nested JSON objects (tens of thousands deep) exhaust CPU (< 3.0.5)
- **PARANOIA level tradeoff**: Level 1 misses many attacks; level 4 generates massive false positives
- **Content-Type confusion**: Sending payloads via PUT or non-standard content types bypasses basic filters
- **Chunked Transfer-Encoding**: Fragmented payloads across chunks evade pattern matching

**Attack Surface**:
| Area | Description |
|------|-------------|
| Rule bypass | URL encoding, double encoding, unicode, case mixing |
| Parser confusion | Multipart boundaries, content-type switching, null bytes |
| Resource exhaustion | Nested JSON bombs, regex backtracking (ReDoS), large header floods |
| Protocol tricks | HTTP/2 smuggling, chunked extensions, CL/TE conflicts |
| Audit log flooding | High-volume requests fill disk via audit logging |

---

### 2. Coraza WAF (with Caddy)

**Type**: Embeddable Go WAF library (reverse proxy via Caddy)
**Why #2**: Written in Go (like Glitch), ModSecurity SecLang compatible, actively maintained by OWASP. Being Go-native means we can study its parser internals and find Go-specific bugs. Has recent CVEs.

**Docker Deployment**:
```yaml
# docker-compose.yml
version: '3'
services:
  coraza-waf:
    image: ghcr.io/coreruleset/coraza-crs-docker:latest
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - BACKEND=http://glitch-server:8765
      - PARANOIA=1
      - ANOMALY_INBOUND=5
      - PORT=8080
      - CADDY_EXTRA_CONFIG=""
    networks:
      - waf-net

  glitch-server:
    build: .
    environment:
      - GLITCH_ADMIN_PASSWORD=testing
    networks:
      - waf-net

networks:
  waf-net:
```

**Verify Running**: `curl http://localhost:8080/` returns proxied content. Test: `curl "http://localhost:8080/?attack=<script>alert(1)</script>"` returns 403.

**Config Location**: Caddyfile at `/etc/caddy/Caddyfile`, CRS rules loaded automatically. Custom rules via volume mount.

**Known Weaknesses & CVEs**:
- **CVE-2025-29914** (CRITICAL): URI parser bypass — URLs starting with `//` are misinterpreted by Go's `url.Parse()`. `//<host>/uploads/foo.php` causes `REQUEST_FILENAME` to be set to `/uploads/foo.php` instead of the full path, bypassing path-based rules
- **CRS charset bypass** (CVE-2026-21876, CVSS 9.3): Rule 922110 flaw allows UTF-7-encoded XSS payloads to bypass charset validation across ModSecurity and Coraza
- **Go `url.Parse` quirks**: Coraza inherits all Go stdlib URL parsing edge cases
- **SecLang compatibility gaps**: Not 100% compatible with all ModSecurity directives — some edge-case rules silently fail

**Attack Surface**:
| Area | Description |
|------|-------------|
| URI parsing | Double-slash prefix, Go url.Parse edge cases, path traversal variants |
| Charset attacks | UTF-7, UTF-16, Shift_JIS encoded payloads |
| Rule compatibility | SecLang features that silently don't work in Coraza |
| Go runtime | Goroutine exhaustion, memory pressure via concurrent connections |

---

### 3. SafeLine WAF

**Type**: Self-hosted reverse proxy WAF (nginx-based, semantic analysis engine)
**Why #3**: Highest GitHub stars among open-source WAFs, claims 99.45% detection rate. Uses semantic analysis rather than pure regex — a fundamentally different detection approach to test against. Has a web management UI.

**Docker Deployment**:
```bash
# One-line install (creates /data/safeline/)
bash -c "$(curl -fsSLk https://waf.chaitin.com/release/latest/manager.sh)" -- --en

# Or manual docker-compose (requires 5GB+ disk):
mkdir -p /data/safeline && cd /data/safeline
curl -fsSLk https://waf.chaitin.com/release/latest/compose.yaml -o compose.yaml
docker compose up -d
```

**Verify Running**: Web UI at `https://localhost:9443`. Configure upstream to point at Glitch server. Test: send SQLi payload — should see block in dashboard.

**Config Location**: `/data/safeline/` contains all config. Web UI for rule management. Custom rules via the management interface.

**Known Weaknesses**:
- **Semantic analysis blind spots**: ML/semantic engines can be confused by valid-looking but malicious payloads
- **Novel attack patterns**: Semantic engines trained on known patterns may miss zero-day constructs
- **Resource consumption**: Semantic analysis is CPU-intensive — potential for exhaustion under high load
- **Chinese-origin documentation**: Some configuration nuances poorly documented in English

**Attack Surface**:
| Area | Description |
|------|-------------|
| Semantic confusion | Payloads that look semantically valid but contain embedded attacks |
| Encoding evasion | Multi-layer encoding that defeats semantic parsing |
| Resource exhaustion | CPU-bound semantic analysis under high request volume |
| Management UI | Potential for admin interface attacks if exposed |

---

### 4. BunkerWeb

**Type**: Full-stack WAF (nginx-based, integrated ModSecurity + CRS + extras)
**Why #4**: "Secure by default" philosophy with dozens of built-in security features. Docker-native with web UI. Includes anti-bot, rate limiting, geo-blocking, and ModSecurity — multiple defense layers to attack.

**Docker Deployment**:
```yaml
# docker-compose.yml
version: '3'
services:
  bunkerweb:
    image: bunkerity/bunkerweb:latest
    ports:
      - "80:8080"
      - "443:8443"
    environment:
      - SERVER_NAME=waf.local
      - USE_REVERSE_PROXY=yes
      - REVERSE_PROXY_URL=/
      - REVERSE_PROXY_HOST=http://glitch-server:8765
      - USE_MODSECURITY=yes
      - USE_BAD_BEHAVIOR=yes
      - USE_LIMIT_REQ=yes
      - LIMIT_REQ_RATE=30r/s
      - USE_ANTIBOT=cookie          # cookie, javascript, captcha, recaptcha
      - USE_DNSBL=yes
      - USE_COUNTRY=yes
      - BLACKLIST_COUNTRY=
      - AUTO_LETS_ENCRYPT=no
    networks:
      - waf-net

  glitch-server:
    build: .
    environment:
      - GLITCH_ADMIN_PASSWORD=testing
    networks:
      - waf-net

networks:
  waf-net:
```

**Verify Running**: `curl -H "Host: waf.local" http://localhost/` — should return proxied content or antibot challenge. Check logs: `docker logs bunkerweb`.

**Config Location**: All via environment variables. Custom configs mountable at `/etc/bunkerweb/configs/`. Web UI available via separate `bunkerweb-ui` container.

**Known Weaknesses**:
- **Cookie-based antibot**: Trivially bypassable by accepting cookies
- **ModSecurity backend**: Inherits all ModSecurity weaknesses
- **Rate limiting**: Simple rate limits bypassable with distributed requests or slow attacks
- **Configuration complexity**: Many features, potential for misconfiguration leaving gaps

**Attack Surface**:
| Area | Description |
|------|-------------|
| Antibot bypass | Cookie/JS challenge solving, header spoofing |
| Rate limit evasion | Slowloris (below rate threshold), distributed sources |
| ModSecurity bypass | All CRS bypass techniques apply |
| Feature interaction | Bugs where multiple security layers conflict |

---

### 5. open-appsec (ML-based WAF)

**Type**: Machine learning WAF (nginx integration)
**Why #5**: Fundamentally different approach — no signatures, uses ML to model "normal" behavior. If Glitch can confuse an ML model, that's a novel finding. Apache 2.0 licensed.

**Docker Deployment**:
```yaml
# docker-compose.yml
version: '3'
services:
  open-appsec:
    image: ghcr.io/openappsec/nginx-attachment:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./appsec-config:/etc/cp/conf
      - ./nginx.conf:/etc/nginx/nginx.conf
    environment:
      - LEARNING_MODE=prevent         # detect, prevent
    networks:
      - waf-net

  glitch-server:
    build: .
    environment:
      - GLITCH_ADMIN_PASSWORD=testing
    networks:
      - waf-net

networks:
  waf-net:
```

**Verify Running**: Access via `http://localhost/` — should proxy to backend. Send known attack payloads and check detection logs.

**Config Location**: `/etc/cp/conf/` for policy files. Requires initial configuration via CLI or management portal.

**Known Weaknesses**:
- **Training period**: ML model needs to learn "normal" — during training, attacks pass through
- **Adversarial ML**: Carefully crafted inputs can fool ML classifiers
- **Novel protocols**: ML trained on HTTP/1.1 patterns may not handle HTTP/2 binary framing well
- **False positive pressure**: Aggressive ML models block legitimate unusual traffic
- **Model poisoning**: If attacker can influence training data, model can be corrupted

**Attack Surface**:
| Area | Description |
|------|-------------|
| Adversarial inputs | Payloads designed to sit at decision boundary of ML classifier |
| Training pollution | Sending "normal-looking" malicious requests during learning phase |
| Protocol confusion | HTTP/2, WebSocket, non-standard content types |
| Resource exhaustion | ML inference is CPU-intensive — flood with complex requests |

---

### Honorable Mentions (Lower Priority)

| WAF | Type | Notes |
|-----|------|-------|
| **NAXSI** | Nginx module | Archived/forked at `wargio/naxsi`. DROP-by-default model. Known null-byte bypass (Synacktiv). Docker: `docker pull notdodo/nginx-naxsi` |
| **lua-resty-waf** | OpenResty/Lua | Unmaintained since ~2020. Docker: `kusumoto/docker-openresty`. Historical interest only |
| **Shadow Daemon** | Application-level (PHP/Perl/Python) | Connector-based, not a reverse proxy. Good for app-layer testing |
| **Wallarm GoTestWAF** | Testing tool (not a WAF) | `docker pull wallarm/gotestwaf` — useful for benchmarking Glitch server as a "WAF" |

---

## Part 2: Attack Taxonomy

### Category 1: Rule Bypass Techniques

| Technique | Description | Effective Against |
|-----------|-------------|-------------------|
| **URL encoding** | `%27` for `'`, `%3C` for `<` | Basic WAFs, paranoia level 1 |
| **Double URL encoding** | `%2527` for `%27` | WAFs that decode once before inspection |
| **Unicode normalization** | `\u0027` for `'`, fullwidth chars `＜script＞` | CRS < PL3, Coraza |
| **HTML entity encoding** | `&#x27;` `&#39;` for `'` | WAFs inspecting raw without decode |
| **Case manipulation** | `SeLeCt`, `<ScRiPt>` | Signature-based without case folding |
| **Null byte injection** | `%00` in payload to truncate string matching | NAXSI < 1.1a, ModSecurity < 2.9.7 |
| **Comment insertion** | `SEL/**/ECT`, `<scr<!-- -->ipt>` | Regex-based signature matching |
| **Concatenation** | `CONCAT(0x73656c656374)` for SQL keywords | SQL signature matching |
| **Alternative syntax** | `EXEC('sel'+'ect')`, template literals | Keyword-based filters |
| **Content-Type switching** | Send SQLi via `application/json` or `text/xml` instead of form data | WAFs only inspecting form bodies |
| **HTTP method switching** | Use PUT/PATCH instead of POST/GET | WAFs filtering only GET/POST |
| **Parameter pollution** | `?id=1&id=OR+1=1` — first or last wins depending on backend | WAFs checking first param only |
| **Charset encoding** | UTF-7 (`+ADw-script+AD4-`), Shift_JIS payloads | CRS rule 922110 (CVE-2026-21876) |

### Category 2: HTTP Request Smuggling

| Technique | Description | Effective Against |
|-----------|-------------|-------------------|
| **CL.TE desync** | `Content-Length` vs `Transfer-Encoding: chunked` disagreement | Reverse proxy + backend pairs |
| **TE.CL desync** | Backend uses TE, frontend uses CL | Load balancer WAFs |
| **TE.TE obfuscation** | `Transfer-Encoding: chunked` with variations (`Transfer-Encoding : chunked`, `Transfer-Encoding: xchunked`) | WAFs with strict header parsing |
| **Chunked extension abuse** | Malformed chunk extensions (bare semicolons) cause parser disagreement | CDN/proxy WAFs (2024 research) |
| **HTTP/2 smuggling** | H2 binary framing → H1 backend conversion creates injection points | H2-terminating reverse proxies |
| **H2 header injection** | HTTP/2 allows header values with `\r\n` that get injected into H1 downstream | H2→H1 translation layers |
| **Double Content-Length** | Two CL headers with different values | WAFs that read first, backends that read last |

### Category 3: Resource Exhaustion

| Technique | Description | Effective Against |
|-----------|-------------|-------------------|
| **Slowloris** | Open many connections, send partial headers slowly (1 header/sec) | Thread-per-connection servers (Apache) |
| **Slow POST** | Declare large Content-Length, send body at 1 byte/sec | WAFs that buffer entire body before inspection |
| **Slow read** | Read response very slowly, keeping connection open | Connection-pool-limited WAFs |
| **Connection flood** | Open max connections without sending requests | All WAFs with connection limits |
| **Large header flood** | Send requests with many/huge headers near limits | WAFs that parse all headers before deciding |
| **Nested JSON bomb** | `{"a":{"a":{"a":...}}}` thousands deep | ModSecurity < 3.0.5 (confirmed DoS) |
| **XML bomb (Billion Laughs)** | Entity expansion exhausts memory | WAFs parsing XML bodies |
| **Regex backtracking (ReDoS)** | Payloads designed to cause catastrophic backtracking in WAF regex rules | Regex-heavy WAF rulesets |
| **Gzip bomb** | Compressed payload that expands to gigabytes | WAFs that decompress before inspection |
| **WebSocket upgrade flood** | Many WebSocket upgrade requests exhaust different resource pool | WAFs not handling WS separately |

### Category 4: Parser Confusion

| Technique | Description | Effective Against |
|-----------|-------------|-------------------|
| **Malformed multipart** | Invalid boundaries, missing CRLF, nested multipart | ModSecurity (CVE-2022-48279), NAXSI |
| **Ambiguous Content-Type** | `Content-Type: text/plain; application/json` | WAFs picking first vs last type |
| **URL path confusion** | `//host/path`, `/./path`, `/%2e%2e/path` | Coraza (CVE-2025-29914) |
| **Header injection** | CRLF in header values, null bytes in URI | ModSecurity (via header corruption) |
| **HTTP version manipulation** | `HTTP/0.9`, `HTTP/3.0`, malformed version strings | Strict version parsers |
| **Non-standard line endings** | `\n` instead of `\r\n`, bare `\r` | WAFs with strict CRLF parsing |
| **Overlong UTF-8** | `%C0%AF` for `/` (overlong encoding) | Byte-level pattern matchers |
| **Chunked body tricks** | Zero-length chunks mid-body, trailing headers after last chunk | Streaming WAF inspectors |

### Category 5: WAF-Specific Exploits

| Target | Technique | Reference |
|--------|-----------|-----------|
| **ModSecurity** | Path-based payload hiding via percent-decode before path split | CVE-2024-1019 |
| **ModSecurity** | Multipart parsing bypass | CVE-2022-48279 |
| **ModSecurity** | Null byte in file upload | CVE-2023-24021 |
| **ModSecurity** | Deeply nested JSON DoS | Pre-3.0.5 |
| **Coraza** | `//` prefix URI parsing confusion | CVE-2025-29914 |
| **Coraza/CRS** | UTF-7 charset bypass on rule 922110 | CVE-2026-21876 |
| **NAXSI** | Null byte injection bypasses string pattern rules | Synacktiv audit, fixed in 1.1a |
| **NAXSI** | Content-Type manipulation bypasses body parsing | Synacktiv audit |
| **CRS** | WAFFLED parsing discrepancies — 1207 bypasses across 5 WAFs via content-type mutations | 2025 research paper |
| **All WAFs** | HTTP Request Smuggling via CL/TE conflicts | Ongoing class of vulnerabilities |

---

## Part 3: Glitch Feature Mapping

### Scanner Modules vs WAF Attack Surface

| Glitch Scanner Module | WAF Attack Category | Specific Techniques |
|----------------------|--------------------|--------------------|
| `owasp` | Rule bypass | SQLi, XSS, XXE, path traversal with encoding variants |
| `injection` | Rule bypass | SQL, NoSQL, LDAP, command injection payloads |
| `fuzzing` | Parser confusion | Malformed inputs, boundary testing, edge cases |
| `protocol` | Smuggling, parser confusion | HTTP version tricks, header manipulation, protocol-level attacks |
| `auth` | Rule bypass | Authentication bypass, session attacks |
| `chaos` | Resource exhaustion | Random chaos payloads, bomb types |
| `slowhttp` | Resource exhaustion | Slowloris, slow POST, slow read |
| `breakage` | Resource exhaustion + parser confusion | Raw TCP attacks, partial connections, malformed HTTP |
| `tls` | Protocol attacks | TLS version probing, cipher manipulation |
| `h3` | Parser confusion | HTTP/3 Alt-Svc confusion, QUIC probing |

### Scanner Evasion Module vs WAF Detection

| Evasion Feature | Purpose Against WAFs |
|----------------|---------------------|
| `URLEncode` | Basic rule bypass |
| `DoubleURLEncode` | Bypass single-decode WAFs |
| `UnicodeEncode` | Bypass ASCII-only pattern matching |
| `HTMLEntityEncode` | Bypass raw-content inspection |
| `Base64Encode` | Bypass plaintext signature matching |
| `HexEncode` | Bypass string-based rules |
| Header manipulation | Bypass bot detection, fingerprinting |
| Nightmare mode encoding | All encodings combined + layered |

### Server Features as WAF Stress Test Targets

When Glitch **server** sits behind the WAF, its chaos features stress-test the WAF's response handling:

| Server Feature | WAF Stress Vector |
|---------------|-------------------|
| `gzip_bomb` | WAF response decompression handling |
| `xml_bomb` | WAF XML response parsing |
| `json_depth_bomb` | WAF JSON response depth limits |
| `infinite_chunked` | WAF response streaming limits |
| `slow_drip` / `slow_headers` | WAF response timeout handling |
| `header_corrupt` | WAF response header parsing (null bytes, CRLF) |
| `connection_reset` / `tcp_fin` | WAF connection error handling |
| TLS chaos | WAF TLS termination resilience |
| H3 chaos (Alt-Svc injection) | WAF HTTP/3 upgrade confusion |
| Content pages with JS API calls | WAF URL discovery from response content |

### Proxy Modes for WAF-in-the-Middle Testing

Glitch proxy between scanner and real WAF, or between WAF and backend:

| Proxy Mode | WAF Testing Use |
|-----------|-----------------|
| `chaos` | Inject latency/corruption between WAF and backend |
| `waf` | Simulate a second WAF layer (double-WAF confusion) |
| `nightmare` | Maximum corruption between WAF and backend |
| `killer` | Apply all client-killing attacks to WAF responses |
| `mirror` | Record traffic for replay analysis |
| MCP interceptor | Test WAF handling of MCP protocol traffic |

---

## Part 4: Test Architecture

### Architecture A: Scanner → WAF → Glitch Server
```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ Glitch       │────▶│  Target     │────▶│ Glitch       │
│ Scanner      │     │  WAF        │     │ Server       │
│ (attacker)   │◀────│  (defense)  │◀────│ (backend)    │
└──────────────┘     └─────────────┘     └──────────────┘
                      Port 8080           Port 8765
```
**Goal**: Bypass WAF rules, exhaust WAF resources, smuggle requests through to backend.

### Architecture B: Scanner → WAF → Real App (Replace Glitch Server)
```
┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ Glitch       │────▶│  Target     │────▶│ Real App     │
│ Scanner      │     │  WAF        │     │ (httpbin,    │
│ (attacker)   │◀────│  (defense)  │◀────│  nginx, etc) │
└──────────────┘     └─────────────┘     └──────────────┘
```
**Goal**: Confirm WAF bypasses reach a real backend (not just chaos backend).

### Architecture C: Scanner → Glitch Proxy → WAF → Backend
```
┌──────────┐   ┌──────────┐   ┌──────┐   ┌─────────┐
│ Glitch   │──▶│ Glitch   │──▶│ WAF  │──▶│ Backend │
│ Scanner  │   │ Proxy    │   │      │   │         │
│          │◀──│ (chaos)  │◀──│      │◀──│         │
└──────────┘   └──────────┘   └──────┘   └─────────┘
```
**Goal**: Test if WAF handles corrupted/chaotic inbound traffic (malformed headers, protocol tricks injected by proxy before WAF).

---

## Part 5: Sprint Plan

### Sprint Goal
Deploy the top 3 WAFs locally, create a WAF attack module for Glitch scanner, and produce a scored comparison report of WAF resilience.

### Phase 1: Infrastructure (Day 1)
**Goal**: All WAFs running, verified blocking, Glitch server as backend.

| # | Task | Success Criteria |
|---|------|-----------------|
| 1 | Install Docker if not present | `docker compose version` works |
| 2 | Deploy ModSecurity + CRS | SQLi payload returns 403 via port 8080 |
| 3 | Deploy Coraza + Caddy | XSS payload returns 403 via port 8081 |
| 4 | Deploy SafeLine | Management UI accessible, upstream configured |
| 5 | Deploy Glitch server as backend for all WAFs | All WAFs proxy to Glitch on port 8765 |
| 6 | Baseline test — confirm each WAF blocks OWASP Top 10 basics | All 3 WAFs block basic SQLi/XSS/path traversal |

### Phase 2: WAF Attack Module (Days 2-3)
**Goal**: New `waf` attack module in Glitch scanner with WAF-specific bypasses.

| # | Task | Success Criteria |
|---|------|-----------------|
| 1 | Create `internal/scanner/attacks/waf.go` — WAF bypass module | Module registered, generates requests |
| 2 | Implement encoding bypass payloads (double encode, unicode, charset) | Variants generated for each base payload |
| 3 | Implement smuggling payloads (CL/TE, chunked extensions) | Raw TCP smuggling requests generated |
| 4 | Implement parser confusion payloads (multipart, content-type switching) | Multipart boundary tricks, type confusion |
| 5 | Implement WAF-specific CVE payloads (CVE-2024-1019, CVE-2025-29914) | CVE-targeted requests for each WAF |
| 6 | Add `waf-buster` scanner profile optimized for WAF testing | Profile selects waf + slowhttp + breakage modules, nightmare encoding |
| 7 | Integrate with evasion encoder — all payloads x all encodings | Multiplicative payload generation |

### Phase 3: Attack Campaigns (Days 4-5)
**Goal**: Run full attack campaigns, measure bypass rates.

| # | Task | Success Criteria |
|---|------|-----------------|
| 1 | Run `waf-buster` profile against ModSecurity PL1-PL4 | Bypass count per paranoia level documented |
| 2 | Run `waf-buster` profile against Coraza | CVE-2025-29914 URI bypass confirmed |
| 3 | Run `waf-buster` profile against SafeLine | Semantic analysis bypass attempts documented |
| 4 | Run `slowhttp` module against each WAF | Connection exhaustion success/failure per WAF |
| 5 | Run `breakage` module against each WAF | Raw TCP attack results per WAF |
| 6 | Test Architecture C (Glitch proxy → WAF → backend) | WAF behavior under corrupted inbound traffic |
| 7 | Test Glitch server chaos features behind WAF | WAF response handling under server chaos |

### Phase 4: Reporting & Hardening (Day 6)
**Goal**: Scored comparison report, scanner improvements based on findings.

| # | Task | Success Criteria |
|---|------|-----------------|
| 1 | Score each WAF: bypass rate, exhaustion resistance, parser robustness | Comparison matrix with scores 0-100 |
| 2 | Document novel bypasses found | Each bypass reproducible with curl command |
| 3 | Update Glitch scanner based on findings | New evasion techniques from successful bypasses |
| 4 | Create `waf-results.md` with full comparison | Published in docs/ |
| 5 | PR with all changes | Green CI, PM acceptance |

### Success Criteria
- At least 3 WAFs deployed and tested
- WAF attack module with 50+ unique bypass payloads
- Bypass rate measured per WAF (target: find at least 1 bypass per WAF)
- Resource exhaustion tested (slowloris, slow POST, connection flood)
- Scored comparison report published
- All findings reproducible

---

## Part 6: Tools & References

### WAF Testing Tools (Complementary)
- **GoTestWAF** (`wallarm/gotestwaf`) — benchmark WAF detection rates, useful for comparison
- **WAFFLED** (`sa-akhavani/waffled`) — automated parsing discrepancy fuzzer
- **Awesome-WAF** (`0xInfection/Awesome-WAF`) — comprehensive WAF bypass knowledge base
- **WAF-Bypass** (`nemesida-waf/waf-bypass`) — WAF bypass payload collection
- **WhatWaf** (`Ekultek/WhatWaf`) — WAF detection and bypass suggestion

### Key Research Papers
- **WAFFLED (2025)**: 1207 bypasses across 5 major WAFs via parsing discrepancies in multipart/form-data, JSON, XML content types
- **Synacktiv NAXSI Audit**: Null byte and content-type parsing vulnerabilities
- **HTTP Desync Attacks**: CL/TE smuggling variants (Imperva, PortSwigger research)

### Sources
- [OWASP ModSecurity CRS Docker](https://github.com/coreruleset/modsecurity-crs-docker)
- [Coraza WAF GitHub](https://github.com/corazawaf/coraza)
- [Coraza CRS Docker](https://github.com/coreruleset/coraza-crs-docker)
- [SafeLine WAF GitHub](https://github.com/chaitin/SafeLine)
- [BunkerWeb GitHub](https://github.com/bunkerity/bunkerweb)
- [open-appsec GitHub](https://github.com/openappsec/openappsec)
- [CVE-2024-1019 — ModSecurity URL bypass](https://github.com/advisories/GHSA-w56r-g989-xqw3)
- [CVE-2025-29914 — Coraza URI parser bypass](https://www.miggo.io/vulnerability-database/cve/CVE-2025-29914)
- [WAFFLED Research Paper](https://arxiv.org/html/2503.10846v1)
- [Synacktiv NAXSI Bypass](https://www.synacktiv.com/en/publications/bypassing-naxsi-filtering-engine)
- [Awesome-WAF — Bypass Knowledge Base](https://github.com/0xInfection/Awesome-WAF)
- [WAF Bypass Techniques 2025](https://medium.com/infosecmatrix/web-application-firewall-waf-bypass-techniques-that-work-in-2025-b11861b2767b)
- [Advanced WAF Bypass Techniques](https://hetmehta.com/posts/Bypassing-Modern-WAF/)
- [GoTestWAF](https://github.com/wallarm/gotestwaf)
- [BunkerWeb Quickstart](https://docs.bunkerweb.io/latest/quickstart-guide/)
- [open-appsec Docker Deployment](https://www.openappsec.io/post/open-appsec-waf-docker-compose-deployment-new-capabilities)
- [ModSecurity CVE List](https://owasp.org/www-project-modsecurity/tab_cves)
- [Slowloris Attack — Cloudflare](https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/)
- [Top 5 Open Source WAFs 2025](https://dev.to/sharon_42e16b8da44dabde6d/top-5-open-source-wafs-to-secure-your-web-apps-in-2025-2d2c)
