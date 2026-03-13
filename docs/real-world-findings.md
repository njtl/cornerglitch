# Real-World Scanner Behavior Findings

Observations from running Glitch Server on a public internet host. These document actual scanner and crawler behavior when encountering Glitch's chaos mechanisms, and highlight weaknesses that can be exploited to waste scanner budgets.

---

## Finding 1: Media Tar Pit — Crawlers Follow Every Media Link Until Stuck

**Observed client**: `client_b8d38b937` — 446 requests over 4 hours

A crawler discovered the server, hit API endpoints and media links within seconds, and immediately began fetching every media format it could find: `.ico`, `.bmp`, `.mp3`, `.tiff`, `.wav`, `.ogg`, `.flac`, `.webm`, `.avi`, `.svg`, `.webp`, `.png`, `.jpg`, `.gif`, `.zip`, playlists (`.m3u8`), DASH manifests (`.mpd`), and raw streams (`.mp4`, `.mp3`).

The crawler made no attempt to prioritize — it fetched every format variant of every asset it found. After exhausting the initial batch, it followed links to new assets and repeated the process.

**Kill mechanism**: The media chaos engine served two slow-drip audio files. The first took **59 minutes** to complete. The second took **2 hours 17 minutes**. The crawler held both connections open for the entire duration, waiting for the download to finish. It never came back after the second one completed.

**Scanner weakness**: No timeout on individual resource downloads. No prioritization between content types. A crawler that treats a 200-status 2-hour audio stream as a valid resource to fully download is trivially exploitable.

**Budget cost**: 4 hours of wall time, 446 requests — the vast majority spent downloading procedurally generated garbage media that looked like real assets.

---

## Finding 2: .env Scanner Defeated by Escalating Punishment

**Observed client**: `client_eccac00f8` — 246 requests in 10 minutes, then gone

A dedicated `.env` file scanner hit the server with a wordlist of paths: `/.env`, `/config.ini`, `/backend/.env`, `/system/.env`, `/.env.backup`, `/.env.production`, `/.git/config`, `/sendgrid.env`, and hundreds of `/<directory>/.env` variations.

Glitch classified it as `script_bot` immediately (first request) and escalated to `intermittent` mode by request 15. From there, the scanner's experience degraded rapidly:

| Response type | Count | % of requests |
|---|---|---|
| Blocked (403) | 60 | 24% |
| Captcha (403) | 34 | 14% |
| Honeypot (200 with fake data) | 34 | 14% |
| Labyrinth (200 with fake page) | 31 | 13% |
| Actual OK | 10 | 4% |
| Connection kills (tcp_reset, packet_drop, etc.) | 22 | 9% |
| Delays (>10s) | 18 | 7% |

The scanner's last request was a `packet_drop` that held the connection for **42 seconds** before the server killed it. The scanner never returned.

**Scanner weakness**: No differentiation between real and honeypot responses. The scanner received `200 OK` with realistic `.env` file contents from honeypot paths and likely reported them as findings. It also had no strategy for dealing with escalating block rates — it kept trying the same pattern even as over half its requests were being blocked.

**Budget cost**: 10 minutes of scanner time, 246 requests, with the majority producing either blocks, fake data, or connection timeouts. The scanner likely produced a report full of false positives from honeypot responses.

---

## Finding 3: Nmap-Style Scanner Trapped in Labyrinth + Keepalive Abuse

**Observed client**: `client_9e3532c5f` — 171 requests in under 2 minutes

A fast scanner (likely Nmap or similar) blasted 171 requests in ~107 seconds, probing paths like `/login.php`, `/rest/applinks/1.0/manifest`, `/health`, `/owa/`, `/Account/Login`, `/cgi-mod/header_logo.cgi`, `/NmapUpperCheck1772582399`.

**Kill mechanism**: 48 of 171 requests (28%) were routed to the labyrinth, returning realistic-looking pages with internal links that lead deeper into an infinite page graph. The scanner's final requests hit `keepalive_abuse` responses that held connections open for **79-85 seconds each** — the server accepted the connection, started responding, then held it in a keep-alive loop. With 4 concurrent connections stuck in keepalive abuse, the scanner's connection pool was exhausted.

**Scanner weakness**: No connection timeout at the transport level. The scanner waited over a minute per request on keepalive abuse without killing the connection. It also couldn't distinguish labyrinth pages (deterministic but fake) from real content — it treated every 200 response as valid.

**Budget cost**: Despite being a fast scanner, it was effectively neutralized in under 2 minutes by tying up its connection pool.

---

## Finding 4: AI Scrapers Stuck in robots.txt/Sitemap Loop

**Observed clients**: `client_161f62656` and `client_b38d4b6c3` — AI scrapers detected over 23 hours

Two AI scrapers (classified as `ai_scraper` by user-agent) followed a predictable pattern: fetch `/robots.txt`, fetch `/sitemap_index.xml`, occasionally follow a sub-sitemap (`/sitemap-1.xml`, `/sitemap-2.xml`, `/sitemap-3.xml`), then come back hours later and do it again.

They hit the server at approximately 3-hour intervals: 23:02, 02:53, 05:27, 06:55, 08:38, 09:28, 11:39, 14:34, 17:35 — over 23 hours of periodic polling. One was pushed into `labyrinth` mode by the adaptive engine, but kept coming back to re-fetch the same robots.txt and sitemaps.

**Scanner weakness**: No awareness of repeated identical content. The sitemaps are deterministic — same URLs every time — but the scrapers re-fetched them on a polling schedule. They also never progressed beyond the discovery phase to actually crawl the URLs listed in the sitemaps, suggesting they were feeding URLs to a separate pipeline.

**Budget cost**: Minimal per-visit, but sustained over 23+ hours. The sitemaps contain URLs pointing into the labyrinth, so any downstream pipeline that follows those URLs would enter the infinite page graph.

---

## Finding 5: Slow Crawlers Burned by Per-Request Delays

**Observed client**: `client_2797e9448` — 117 requests over ~1 hour 45 minutes

A methodical crawler (probing `.php` pages — `acesso.php`, `desktop.php`, `contact.html`, `entrar.php`) was slowed by a combination of:
- `delayed` responses (11 requests with artificial delays)
- `slow_headers` (5 requests — server sends headers one byte at a time)
- `slow_drip` (4 requests — response body sent one byte at a time)
- `captcha` challenges (7 blocks)
- `session_timeout` (38-second hangs)
- `keepalive_abuse` (1m51s connection hold)

The crawler ended up averaging about 1 request per minute over its session — a throughput reduction of 10-100x compared to its initial burst rate.

**Scanner weakness**: No adaptive timeout strategy. The scanner used the same timeout for every request, allowing slow responses to consume disproportionate wall time. It also didn't distinguish between "server is slow" (retry later) and "server is deliberately slowing me down" (skip and move on).

**Budget cost**: 1h45m for 117 requests against a server that can serve hundreds of requests per second. The scanner's effective throughput was reduced to essentially manual browsing speed.

---

## Exploitable Scanner Budget Weaknesses

Based on these findings, scanners consistently fail at:

### 1. No Download Size/Time Limits
Scanners download entire media files regardless of size or duration. A 200 response with `Content-Type: audio/flac` that drip-feeds bytes for hours will be held open until completion or OS-level timeout.

**Exploit potential**: Serve increasingly large media assets linked from normal pages. A single HTML page with 20 `<link rel="prefetch">` hints to media endpoints can tie up 20 connections in parallel tar pits.

### 2. No Honeypot Detection
Scanners treat all `200 OK` responses as valid findings. When a honeypot serves a fake `.env` file with realistic-looking `DB_PASSWORD=...` content, scanners report it as a real credential exposure.

**Exploit potential**: Serve realistic but subtly wrong sensitive data. The scanner's report becomes filled with false positives, eroding trust in real findings. Defenders can embed canary tokens in honeypot responses to detect when scanner results are acted upon.

### 3. No Connection Pool Management
Scanners allow individual connections to be held open indefinitely by keepalive abuse, slow-drip, and session timeout responses. A server holding 4-8 connections can exhaust a scanner's entire connection pool.

**Exploit potential**: Serve keepalive abuse on every Nth response. The scanner's parallelism degrades over time as more connections get trapped, eventually serializing to single-request throughput.

### 4. No Content Deduplication
Scrapers re-fetch identical content on polling schedules without checking if it changed. Labyrinth pages generate realistic-looking but deterministic content that looks unique per-URL but is actually seeded from the path hash.

**Exploit potential**: Sitemaps can reference thousands of labyrinth URLs. Each URL produces a unique-looking page with links to more labyrinth pages. A scraper following these links will crawl indefinitely without ever reaching real content.

### 5. No Adaptive Strategy
Scanners don't adjust their behavior when block rates increase. A scanner getting 50%+ 403 responses should recognize it's being actively blocked and either change approach or abort. Instead, they continue with the same wordlist at the same rate.

**Exploit potential**: Escalate punishment gradually. Start with delays, then mix in captchas, then blocks, then connection kills. The scanner wastes its entire budget before recognizing it's been neutralized.

### 6. No Distinction Between Content Types
Scanners treat HTML pages, API responses, media files, and labyrinth pages identically. They follow every link, download every resource, and parse every response regardless of whether it's relevant to their scanning objective.

**Exploit potential**: Embed media links, API discovery hints, and labyrinth links in every HTML response. Each real page becomes a branching point into dozens of budget-wasting side channels.

---

## Future Budget-Draining Mechanisms (Ideas)

These are ideas for new features specifically designed to maximize scanner budget waste, based on the weaknesses observed in real-world scanner behavior:

### Graduated Tar Pit
Instead of random chaos, apply a deliberate escalation curve per-client:
1. First 10 requests: fast, normal 200 responses (build scanner confidence)
2. Requests 11-50: mix in 20% delays (1-5s) and labyrinth redirects
3. Requests 51-100: 40% slow responses (10-30s), media links appear in every page
4. Requests 100+: majority keepalive abuse, session timeouts, and media tar pits

The scanner's initial requests succeed, so it commits to the full scan. By the time the punishment ramps up, it's already invested too much budget to abort.

### Infinite API Pagination
Serve API endpoints with paginated responses that never end. `/api/v1/users?page=1` returns 20 users with a `next_page` link. Each page returns more users. Page 1000 still has a next page. Scanners that crawl APIs by following pagination links will fetch thousands of pages of procedurally generated user data.

### Fake Vulnerability Breadcrumbs
Serve responses that look like they're "almost" vulnerable — partial stack traces, debug headers with framework versions, commented-out code with SQL queries. Scanners spend extra time and requests trying to confirm and exploit vulnerabilities that don't actually exist.

### Progressive Content Expansion
Each page a scanner visits links to slightly more pages than the previous one. First page: 5 links. Those 5 pages each have 7 links. Those 35 pages each have 10 links. The exponential growth burns through crawl budgets at an increasing rate.

### WebSocket Trap
Serve pages with WebSocket upgrade endpoints. Scanners that support WebSocket will connect and receive an endless stream of realistic-looking real-time data (fake stock tickers, chat messages, notifications). Each WebSocket connection is a persistent resource drain.

### Streaming Response Bait
Serve `Transfer-Encoding: chunked` responses that stream realistic HTML at 1 byte/second. The response looks like it's loading — the scanner sees partial HTML and waits for it to complete. It never does.

---

## Controlled Testing: Scanner Tool Evaluation (2026-03-05)

The following findings are from a controlled test session where popular security scanning tools were run against the Glitch server in full nightmare mode. Unlike the findings above (which are from organic internet traffic), these represent deliberate, reproducible tests.

### Test Environment
- **Server**: Glitch in nightmare mode, all features maxed, all vuln groups enabled
- **Key settings**: error_rate_multiplier=5, delay_min_ms=500, delay_max_ms=10000, protocol_glitch_level=4, header_corrupt_level=4, all feature flags ON

### CT-1: Nuclei Detection Blindness (nuclei v3.7.0)
6,327 templates loaded. After 2 minutes: only 1,080 of 14,522 requests completed (7%), **zero vulnerabilities detected** despite hundreds of real vuln endpoints. Rate dropped to ~8 rps. The nightmare delays and error injection prevent template matchers from ever seeing the expected response patterns.

### CT-2: Nikto Framework Identity Crisis (nikto v2.1.5)
Hit 150s max time. Detected ASP.NET, Rails, Django, Next.js, Laravel, Spring Boot, IIS, and Varnish simultaneously — all from Glitch's framework emulation injecting contradictory headers. Reported every cookie trap as a real vulnerability. Server banner changed between requests (cloudflare vs WSGIServer).

### CT-3: SQLMap Complete Denial (sqlmap v1.10.2)
Received HTTP 102 (Processing) status code and **immediately aborted** — zero injection tests performed. Tried two different endpoints, same result both times. The chaos error generator returns unusual status codes that sqlmap cannot handle.

### CT-4: Wapiti Crawl Starvation (wapiti v3.2.10)
Found only 1 URL in the entire scan. Reported all 6 cookie traps as real vulnerabilities. Completed in 28 seconds because there was nothing to scan — the crawler couldn't discover any pages beyond the root.

### CT-5: ZAP Timeout + False Positive Flood (ZAP v2.17.0)
Killed by 5-minute timeout. Produced 15 alerts — all false positives from chaos headers and cookie traps. Couldn't complete spider phase. The combination of delays, errors, and contradictory headers overwhelmed ZAP's passive scanner.

### CT-6: Nmap Fingerprint Evasion (nmap v7.94SVN)
Identified port 8765 as `ultraseek-http?` (wrong). Generated 2 unrecognized service fingerprints. HTTP NSE scripts produced no output. Took 103 seconds for 2 ports. Framework emulation changes the server fingerprint on every request.

### CT-7: WhatWeb Misidentification (whatweb v0.5.5)
Detected Drupal CMS (from X-Drupal-Cache header) and Cloudflare server (from Server header) — both completely wrong. Reported fake emails, fake cache headers, and fake authentication methods as real findings.

### CT-8: ffuf Throughput Collapse (ffuf v2.1.0)
Effective throughput reduced to ~1 req/sec (normally hundreds). Error rate 47-64%. Average response time 2-9 seconds per URL. A high-speed fuzzer reduced to manual browsing speed.

### CT-9: wget Crawler Trapping (wget v1.21.4)
Only 20 files (140KB) in 2 minutes. In concurrent test, timed out on first request and gave up entirely. The labyrinth consumed crawl depth while delays killed throughput.

### CT-10: Server Stability Under Scanner Bombardment
Throughout all tests: **zero crashes, zero panics, zero memory leaks**. Memory: 23-54MB. CPU: 0.3-2%. Health endpoint returned 200 continuously. The Go stdlib HTTP server handles adversarial traffic without issues.

---

## Controlled Testing: Scanner Crash Sprint (2026-03-05, Sprint 2)

Extended testing with 16 tools, longer timeouts, and new tools. **Sprint goal: crash the scanners reproducibly.**

### CT-11: ZAP OOM Crash (ZAP v2.17.0)
With 512MB memory limit: internal proxy **crashed** during full active scan. 6 passive scan rules auto-disabled (10+ alerts each from framework emulation). HTTPConnectionPool error: proxy port died. With unlimited memory: grew to **1.4 GB** in 21 minutes, "unhealthy" status, zero output files. **Root cause (validated)**: Full nightmare feature set combined — labyrinth generates infinite URLs, each page has API endpoints, honeypot paths, media URLs, and vuln pages with form data. Every discovered URL stored in JVM heap. At 512MB limit: reached 502MB/512MB (98.13%) within ~60 seconds, container status "unhealthy". At 128MB limit: OOMKilled=true. Labyrinth alone only reaches 27MB stable — needs the full feature set to exhaust memory.

### CT-12: Feroxbuster Complete Denial (feroxbuster v2.13.1)
**5 out of 5 connection attempts failed.** "Could not connect to any target provided." **Root cause (validated)**: `header_corrupt=true` (level 4) alone is sufficient. Feroxbuster sends a canary request to verify connectivity. The hijacked response with null bytes (`corruption.go:328`), mixed HTTP versions, and 1xx informational responses causes Rust's `hyper` HTTP parser to reject the response. Feroxbuster treats canary failure as "target unreachable" and aborts. `error_inject` alone does NOT kill feroxbuster.

### CT-13: Commix Infinite Hang (commix v4.2.dev10)
Stuck at "Testing connection to the target URL" for **12+ minutes**. 0% CPU — not processing, just waiting. **Root cause (validated)**: `header_corrupt=true` (level 4) alone is sufficient. The hijacked response with null bytes (`corruption.go:328`) causes Python's urllib HTTP parser to enter a state it never exits (no timeout on response parsing). `error_inject` alone does NOT cause the hang — commix works fine and even finds a "vulnerability" (file-based command injection via path-based content generation).

### CT-14: Arjun Silent Hang (arjun v2.2.7)
**Zero output** after 5 minutes. No errors, no findings, no progress. Silent hang. **Root cause (validated, revised)**: Glitch's **deterministic content generation** from path seeds — NO features needed. Arjun's parameter detection compares responses with/without test parameters to detect reflection. Glitch generates identical pages regardless of URL parameters (content seeded from path via SHA-256). Arjun cannot establish a baseline. With `--stable` mode, enters infinite retry loop. It IS making requests (~996 in 15s) but never produces output. Nightmare delays compound this by making each comparison request take 500-10000ms instead of <10ms.

### CT-15: Gobuster Transport Error (gobuster v3.8.2)
Go's `net/http` MIME parser breaks on `X-Chaos: before\x00after` — null byte in header value (`internal/headers/corruption.go:328`). Error: "malformed MIME header line." With `--force`: only 3 paths found. Without: immediate abort on wildcard detection timeout.

### CT-16: WhatWeb Plugin Crashes (whatweb v0.5.5, aggression 4)
**Root cause (validated)**: `header_corrupt=true` (level 4) alone is sufficient. At aggression 4, actual error count is **151 plugin errors** (not 17 as initially reported): 95x `force_encoding for nil:NilClass` (null bytes cause Ruby's HTTP parser to return nil, plugins call `.force_encoding` on nil), 44x `incorrect header check` (corrupted Content-Encoding headers cause Zlib decompression failures), 11x `no implicit conversion of nil into String` (nil body passed to String operations). `framework_emul` alone causes 0 errors; `error_inject` alone causes WhatWeb to hang but no plugin errors.

### CT-17: Nmap Complete HTTP Script Stall (nmap v7.94SVN)
**Zero output** in 5 minutes with 9 HTTP scripts. Not even port state reported. **Root cause (validated)**: `header_corrupt=true` combined with `-sV` (service version detection). Nmap's service detection sends probes expecting parseable HTTP headers/banners. The hijacked connection with null bytes and mixed HTTP versions causes nmap's service detection engine to hang indefinitely. Key detail: without `-sV`, nmap NSE scripts complete in <2 seconds even with `header_corrupt` on — the stall is specifically in service version detection, not script execution.

### CT-18: Extended nuclei (nuclei v3.7.0, 10 min)
10 minutes, 0 findings. Template matching completely defeated. No crashes, no memory issues — just total ineffectiveness.

### CT-19: Extended wapiti (wapiti v3.2.10, 10 min, folder scope)
838 URLs found (much better with broader scope). **88 ReadErrors** from connection resets — ~10% of requests. Cookie traps still reported as real vulnerabilities.

### CT-20: httpx Technology Confusion (httpx, ProjectDiscovery)
Every path reports a **different technology stack**: .git=Akamai+ASP.NET, .env=Cloudflare+PHP, admin=Flask+Python+AWS, api/v1/users=RoR+Varnish, cgi-bin=Next.js+React+Webpack. Framework emulation is deterministic per-path — httpx consistently gets the wrong stack but handles chaos gracefully.

---

## Controlled Testing: Scanner Destroyer Bombs (2026-03-05, Sprint 3)

Testing 5 new scanner-destroying error types: gzip bomb, XML billion laughs, JSON depth bomb, infinite chunked, and chunk overflow. These target scanner response parsing and memory management.

### Test Environment
- **Server**: Glitch with custom error weights: gzip_bomb=15%, xml_bomb=15%, json_depth_bomb=15%, infinite_chunked=10%, chunk_overflow=10%, none=35%
- **Protocol glitch level**: 4, error_rate_multiplier=5, all features enabled

### CT-21: Python Scanner — JSON RecursionError Crash
**Tool**: Custom Python scanner using `urllib.request` + `json.loads` + `xml.etree.ElementTree`
**Result**: `RecursionError on 600,006 bytes` — Python's JSON parser hit stack overflow parsing 100,000 nested `{"a":` objects. Memory grew from 20MB to 78MB (3.75x). 6 `IncompleteRead` errors from chunk_overflow responses crashing Python's HTTP chunked transfer parser.

### CT-22: Python Scanner — Gzip Bomb Memory Expansion
**Tool**: Same Python scanner with `gzip.decompress`
**Result**: 10,224 bytes of gzip data decompressed to **10,485,760 bytes** (10MB) in memory — a 1024:1 compression ratio. Two gzip bombs hit during the test, each consuming 10MB of scanner memory. Scanner memory grew 57MB total (20KB -> 78MB).

### CT-23: Go Scanner — Infinite Chunked Connection Hang
**Tool**: Go scanner using `net/http` + `io.ReadAll`
**Result**: **Complete hang** — the Go HTTP client's `io.ReadAll` waited for the chunked transfer to end, but `infinite_chunked` sends small chunks every 2 seconds for 5 minutes without terminating. The 15-second client timeout was ineffective because the server kept sending data (keeping the connection alive). Scanner was killed by external timeout after 120 seconds with zero output. This is a denial-of-service against any Go client that reads response bodies without size limits.

### CT-24: curl — Chunk Overflow Protocol Violation
**Tool**: `curl --compressed` with `--max-time 10`
**Result**: Bash's `read` command received null bytes from `X-Data` header corruption, causing shell warnings. JSON depth bombs detected (600,006 bytes). The chunk_overflow response (`FFFFFFFFFFFFFFFF` chunk size) caused curl to abort the transfer — visible as `size=0` in results. Two out of 500 requests were curl-crashing chunk overflows.

### CT-25: WhatWeb — Multiple Ruby Plugin Crashes
**Tool**: WhatWeb v0.5.5, aggression level 3, 20 paths
**Result**: Multiple crash events:
- `"end of file reached"` — connection reset from chunk_overflow killing response mid-transfer
- `"Can't convert to UTF-8 undefined method 'force_encoding' for nil:NilClass"` — Ruby NilClass exception from malformed gzip/bomb response body
- `"wrong header line format"` — Ruby-on-Rails plugin crash from null bytes in headers
- `"Plugin Django failed"` — Django detection plugin crash from contradictory response format
WhatWeb survived (non-fatal plugin errors) but produced corrupted results.

### CT-26: Nikto — Bomb Resistance (Partial)
**Tool**: Nikto v2.1.5
**Result**: Nikto completed without crashing. It doesn't auto-decompress gzip, doesn't parse XML/JSON response bodies, and uses Perl's HTTP library which handles chunked encoding gracefully. However, it reported all framework emulation artifacts as real findings (45 items, all false positives). Nikto is resistant to bomb payloads but vulnerable to false positive flooding.

### Bomb Effectiveness Summary

| Bomb Type | Python (urllib) | Go (net/http) | Ruby (WhatWeb) | curl | Nikto (Perl) |
|-----------|----------------|---------------|----------------|------|--------------|
| **gzip_bomb** | 10MB memory spike | Not tested (hung first) | Plugin crash (NilClass) | Handled (--compressed) | Immune (no decompress) |
| **xml_bomb** | Would crash ET parser | Would crash xml.Unmarshal | Not observed | N/A (no parse) | Immune (no parse) |
| **json_depth_bomb** | **RecursionError crash** | Would crash json.Unmarshal | Not observed | Detected, no crash | Immune (no parse) |
| **infinite_chunked** | Timeout after 10s | **Complete hang (DoS)** | EOF error | Timeout (--max-time) | Handled |
| **chunk_overflow** | IncompleteRead crash | Transport error | EOF crash | Transfer abort | Handled |

### Key Findings
1. **JSON depth bomb is the most effective single payload** — crashes Python's json.loads with an unrecoverable RecursionError. Any scanner written in Python that parses JSON responses is vulnerable.
2. **Infinite chunked is the most effective DoS** — Go's net/http client hangs indefinitely because the server keeps sending data, defeating client-side timeouts. Any scanner using io.ReadAll on chunked responses is vulnerable.
3. **Gzip bomb causes memory spikes** — 10KB payload expands to 10MB. Multiple bombs in a scan session cause cumulative memory growth that can trigger OOM in memory-constrained environments (Docker, CI).
4. **Chunk overflow crashes transport layers** — the `FFFFFFFFFFFFFFFF` chunk size is rejected by HTTP parsers, causing IncompleteRead (Python), transport errors (Go), and EOF (Ruby).
5. **Scanners that don't parse response bodies (Nikto) are immune** — but they miss all content-based vulnerabilities, making them ineffective as security scanners.

---

## QA-Validated Root Cause Analysis (2026-03-05)

All scanner crash findings were independently validated with feature isolation testing. Each finding was reproduced with minimal feature configurations to identify the true root cause.

### The Nuclear Weapon: `header_corrupt` (corruption.go:328)

A single null byte in `X-Chaos: before\x00after`, written via HTTP hijacking to bypass Go's built-in header validation, crashes or hangs **5 out of 7** scanners tested:

| Scanner | Language | Effect | Mechanism |
|---------|----------|--------|-----------|
| Gobuster | Go | Transport error on every request | `net/http` stdlib rejects null bytes in MIME headers |
| Feroxbuster | Rust | 100% connection failure, scan aborts | `hyper` HTTP parser rejects corrupted response |
| Commix | Python | Infinite hang at connection test, 0% CPU | `urllib` parser enters unrecoverable state |
| WhatWeb | Ruby | 151 plugin errors (aggression 4) | nil reference from corrupted headers/body |
| Nmap | C | Infinite stall with `-sV` flag | Service detection can't parse response |

### Other Root Causes

| Scanner | Root Cause | Minimal Config |
|---------|-----------|----------------|
| Arjun | Deterministic content generation (SHA-256 path seeding) | **No features needed** — hangs with all features OFF |
| ZAP | Full nightmare feature set overwhelming JVM heap | All features combined (labyrinth alone = 27MB stable) |

---

## Finding 6: Cloudflare Browser Rendering Has No Defense Against Adversarial Pages

**Test target**: Cloudflare Browser Rendering API (`/crawl` and `/content` endpoints) pointed at Glitch server with browser chaos engine at level 4 (nightmare).

**Test period**: 2026-03-12 23:56 to 2026-03-13 14:33 (multiple crawl sessions across ~15 hours)

### Results Summary

| Metric | Value |
|--------|-------|
| Initial page renders | 85 |
| Total requests generated | 7,345 |
| **Amplification ratio** | **86x per page** |
| Unique URLs crawled | 5,529 |
| Labyrinth pages followed | 3,838 |
| Max labyrinth depth | 19 levels |
| JS-discovered API endpoints | 22 |
| Heartbeat requests (idle stall) | 973 |
| Budget trap hits (breadcrumbs) | 972 |
| Tarpit connections held | 208 |
| Iframe-injected paths followed | 53 |
| ServiceWorker registrations | 2 |
| Unique headless Chrome instances | 415 |

### Attack Vector Effectiveness

**1. Infinite labyrinth — fully effective.** CF Chrome crawled 3,838 labyrinth pages across 19 depth levels with no loop detection or depth limit. The labyrinth generates deterministic, realistic-looking content (articles, documentation, tutorials) with internal links at every level. CF followed them all.

Depth distribution:
- Levels 1–5: 1,990 pages (initial exploration)
- Levels 6–10: 911 pages (deep crawl)
- Levels 11–15: 768 pages (still going)
- Levels 16–19: 169 pages (only stopped because the crawl session ended)

**2. Network idle stall — fully effective.** The chaos payload fires a `fetch("/api/v{1,2,3}/heartbeat")` every 200–450ms, preventing Puppeteer's `networkidle2` from ever resolving. CF Chrome made 973 heartbeat requests across sessions, never reaching idle state. This forces the crawler to rely on hard timeouts rather than page-load completion detection.

**3. JS fetch() execution — fully effective.** CF Chrome executed all embedded JavaScript, including `fetch()` calls to API endpoints that existed only in JS (not in HTML links). Discovered and hit 22 distinct API routes:
- `/api/v1/users/me`, `/api/auth/status`, `/api/csrf-token`
- `/api/v1/analytics`, `/api/v2/events`, `/api/comments`
- `/api/newsletter/status`, `/api/search/suggest`, `/api/autocomplete`
- `/api/v1/notifications`, `/api/v1/products/recommendations`

This means any trap endpoint reachable via JS will be hit by CF Browser Rendering.

**4. Hidden iframe amplification — fully effective.** The chaos engine injects 2–6 hidden iframes (1x1px, positioned off-screen) loading unique paths. Each iframe loads a page that also receives chaos injection, creating recursive amplification. CF Chrome loaded all iframes and crawled 53 unique iframe-generated paths. This is more reliable than ServiceWorker for amplification because it requires no registration or scope negotiation.

**5. Budget traps — fully effective.** Fake vulnerability breadcrumbs (hints in HTML comments and headers pointing to "sensitive" paths) generated 972 follow-up requests. Tarpits (slow-drip responses that hold connections open) caught the crawler 208 times. CF Chrome has no mechanism to detect or avoid these traps.

**6. ServiceWorker poisoning — partially effective.** The SW endpoint at `/_bc/sw.js` was fetched twice, confirming CF Chrome can register ServiceWorkers via real URLs. Once active, the SW intercepts all fetch events and injects additional requests per navigation. However, registration only succeeded in 2 of the 415 Chrome instances — the others likely had SW blocked or timed out during registration. Blob URL-based SW registration (the original approach) was blocked entirely by headless Chrome.

**7. Media asset exhaustion — effective.** CF Chrome fetched every media format variant it found: `.jpg`, `.webp`, `.gif`, `.svg`, `.ico`, `.bmp`, `.tiff`, `.wav`, `.mp3`, `.ogg`, `.flac`, `.mp4`, `.webm`, `.avi`, `.ts`, DASH manifests (`.mpd`), and HLS playlists. No format filtering or size limits observed.

### What CF Browser Rendering Does NOT Do

- **No crawl depth limit** — followed links 19 levels deep into procedurally generated content
- **No per-page request budget** — a single page generated up to 75 requests in one second
- **No idle detection hardening** — `networkidle2` was trivially defeated by periodic fetch()
- **No trap/honeypot detection** — followed breadcrumbs, sat in tarpits, crawled labyrinth endlessly
- **No deduplication of generated content** — every labyrinth page looks unique (seeded from URL via SHA-256), so content-based dedup doesn't help
- **No JS execution sandboxing** — ServiceWorker registration, IndexedDB writes, and fetch() calls all execute without restriction
- **No iframe recursion limit** — hidden iframes are loaded and their content is crawled

### Practical Impact

An adversarial website can use these techniques to:
1. **Exhaust crawl budgets** — a single page can trigger thousands of requests via labyrinth links + JS execution + iframe amplification
2. **Hold connections indefinitely** — tarpits and network idle stalls keep Chrome instances busy
3. **Generate arbitrary server load** — the 86x amplification means 100 crawl requests become 8,600 requests hitting the target
4. **Waste compute resources** — CSS rendering bombs, WASM CPU loops, and memory pressure (IndexedDB/Blob leaks) consume Chrome's CPU and RAM
5. **Pollute crawl data** — procedurally generated content looks realistic but is meaningless, degrading any downstream analysis

### Comparison with Traditional Scanner Findings

| Behavior | Traditional scanners (Finding 1–5) | CF Browser Rendering |
|----------|-------------------------------------|---------------------|
| Follows infinite links | Yes (Finding 3: labyrinth trap) | Yes — 19 levels deep, 3,838 pages |
| Executes JavaScript | No (HTTP-only) | Yes — full V8 execution |
| Falls for budget traps | Partially (Finding 1: media tar pit) | Fully — breadcrumbs, tarpits, iframes |
| Detects honeypots | No | No |
| Download size limits | No (Finding 1: 2h17m audio) | No — fetched every media format |
| Adaptive timeout | No (Finding 5) | No — network idle stall defeated |
| **Attack surface** | **HTTP parser + response handling** | **HTTP + JS + SW + CSS + media + iframes** |

CF Browser Rendering's JS execution capability dramatically expands the attack surface compared to traditional HTTP-only scanners. Every attack that works against scanners also works against CF Chrome, plus an entire category of browser-specific attacks (ServiceWorker, iframe amplification, CSS bombs, network idle stall) that HTTP scanners are immune to.
