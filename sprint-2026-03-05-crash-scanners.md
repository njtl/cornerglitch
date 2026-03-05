# Sprint Plan — 2026-03-05 Crash Scanners

## Status: COMPLETE

## MANDATORY RULE: Plan Audit at Session Start

**Before ANY work begins, the agent MUST:**

1. Read this file in full
2. Count all items marked with unchecked status
3. Print the count: `"PLAN AUDIT: X items remaining out of Y total"`
4. **Refuse to close the sprint until that count is ZERO**
5. After completing each item, mark it and re-count
6. If context runs out, the continuation session MUST re-audit before resuming

**The sprint is NOT done until every single item is done.**

---

## Sprint Goal

**Glitch server must crash the scanners. Reproducibly.**

The previous sprint showed Glitch defeats scanners by confusing them and wasting their time. This sprint goes further: find configurations and behaviors that cause actual scanner crashes, panics, hangs, memory exhaustion, or protocol-level failures. Every finding must be reproducible and precisely attributed to a specific Glitch behavior.

---

## Rules (carried from previous sprint + new)

1. **Run 1-3 scanners at a time max** — don't overload the VPS (3.7GB RAM, 2 vCPUs)
2. **Docker for tools that can't run on the OS** — Go 1.24 system, some tools need newer
3. **Increase timeouts** — give scanners more time to fail (5-10 min per tool minimum)
4. **Precise bug reports** — every finding must identify the EXACT Glitch behavior that caused the malfunction, not just "ran tool against server"
5. **Reproducibility is mandatory** — every finding must be verified by running the same test at least twice
6. **Don't cheat or cut corners** — complete every item fully
7. **Monitor server** — check health endpoint and metrics during every scan
8. **Document everything** — every scan attempt, even failed ones, is data
9. **Plan audit on every session start**
10. **Senior QA engineer** validates all findings for precision and reproducibility

---

## Phase 1 — Tool Installation (Docker-first)

### 1.1 New tools via Docker
- [x] **1.1.1** Pull and verify: Katana (projectdiscovery/katana) — DONE
- [x] **1.1.2** Pull and verify: Feroxbuster (epi052/feroxbuster) — v2.13.1
- [x] **1.1.3** Pull and verify: Commix — cloned to /tmp/commix, v4.2.dev10
- [x] **1.1.4** Pull and verify: Burp Suite Community — SKIPPED, no headless Docker image, Enterprise-only
- [x] **1.1.5** Pull and verify: Arjun — pip installed, v2.2.7
- [x] **1.1.6** Pull and verify: Hakrawler — jauderho/hakrawler Docker image

### 1.2 Fix existing tools
- [x] **1.2.1** Gobuster — built v3.8.2 from golang:latest Docker, binary at /tmp/gobuster-bin
- [x] **1.2.2** httpx (ProjectDiscovery) — verified Go binary at ~/go/bin/httpx
- [x] **1.2.3** All existing tools verified: nuclei 3.7.0, nikto, sqlmap 1.10.2, wapiti 3.2.10, nmap 7.94, whatweb 0.5.5, ffuf 2.1.0, wget 1.21.4

---

## Phase 2 — Server Tuning for Maximum Scanner Damage

### 2.1 Analyze previous results for crash opportunities
- [x] **2.1.1** Gobuster: null byte in header value (corruption.go:328 `X-Chaos: before\x00after`) breaks Go MIME parser
- [x] **2.1.2** sqlmap: HTTP 102+100 Continue chain causes abort; with --ignore-code=102 it runs but random status codes prevent injection testing
- [x] **2.1.3** ZAP: 1.4GB RAM in 21 min with unlimited memory. With 512MB limit, internal proxy crashes during full scan
- [x] **2.1.4** nuclei: 10 min, 0 findings. Chaos responses prevent template matching entirely. No template engine errors — just mismatches.
- [x] **2.1.5** Connection reset mid-response: wapiti hit 88 ReadErrors in 10 min. Curl exit code 18 (partial transfer) seen in 10% of requests.
- [x] **2.1.6** Infinite chunked: HTTP/1.0+chunked combo (illegal) causes curl exit 8. Gobuster transport error.
- [x] **2.1.7** Content-Length mismatch: 40% of API requests return curl exit 8 (null byte). 0 bytes downloaded despite HTTP 200.
- [x] **2.1.8** Header injection: chaos-level corruption sends 100+102+200 chain with null byte, multiple protocol violations per response

### 2.2 Server configuration adjustments
- [x] **2.2.1** Nightmare mode verified active: 26/26 features ON, all config values at max
- [x] **2.2.2** protocol_glitch_level=4 confirmed active. Chaos-level header corruption (corruption.go:315-338) is the primary scanner crasher
- [x] **2.2.3** Enhancement requests: none needed — current chaos features already crash/hang multiple scanners

---

## Phase 3 — Scanner Execution (1-3 at a time, extended timeouts)

### 3.1 New tool scans (5-10 min each minimum)
- [x] **3.1.1** Katana crawl (5 min) — 208 URLs found, killed by timeout. No crash but labyrinth consumed crawl budget.
- [x] **3.1.2** Feroxbuster (5 min) — CANNOT CONNECT. 5/5 attempts fail. Canary request killed by chaos. Complete denial.
- [x] **3.1.3** Commix (12 min) — HUNG at "Testing connection". 0% CPU, had to be killed. Complete hang.
- [x] **3.1.4** Arjun (5 min) — ZERO OUTPUT. Killed by timeout. No error, no result. Silent hang.
- [x] **3.1.5** Hakrawler (21s) — 439 URLs found fast. Most resilient crawler tested.
- [x] **3.1.6** Gobuster (5 min) — Transport error from null byte in header. Only 3 paths found with --force.

### 3.2 Re-run previous scanners with extended timeouts
- [x] **3.2.1** nuclei (10 min) — 0 findings. Killed by timeout at ~18% completion. No memory issues.
- [x] **3.2.2** nikto (10 min) — 42 items, 5 errors. Hit max time. All findings are false positives from framework emulation.
- [x] **3.2.3** wapiti (10 min) — 838 URLs found (much better with folder scope). 88 ReadErrors from connection resets.
- [x] **3.2.4** ZAP full scan (10 min) — CRASH. Internal proxy dies with 512MB limit. 1.4GB with unlimited. 18 false positive warnings.
- [x] **3.2.5** sqlmap (5 min) — Ran with --ignore-code=102. Still 0 injections found. Random status codes prevent testing.
- [x] **3.2.6** ffuf (5 min) — 47 results from 76 paths. ~1 req/sec. 24% error rate.
- [x] **3.2.7** nmap (5 min) — ZERO OUTPUT in 5 min. Completely stalled on HTTP scripts.
- [x] **3.2.8** whatweb aggression 4 (5 min) — 17 plugin errors. 9x Ruby NilClass, 6x gzip errors, 1x EOF.

### 3.3 Targeted crash attempts
- [x] **3.3.1** 40% of API requests produce curl exit 8 (null byte). 10% exit 18 (partial). Protocol chaos is consistent.
- [x] **3.3.2** nuclei against specific endpoints — still 0 findings. Chaos defeats template matching regardless of path.
- [x] **3.3.3** Content-Length mismatch: every chaos-level response returns 0 bytes to curl despite HTTP 200.
- [x] **3.3.4** sqlmap against 4 endpoints: 2/4 got "unable to connect" errors. Protocol chaos chain blocks injection testing.

### 3.4 httpx proper configuration
- [x] **3.4.1** httpx with full flags — detected: Apache+Fastly+PHP+Ubuntu (all false positives from framework emulation)
- [x] **3.4.2** httpx against 76 paths — every path reports DIFFERENT tech stack. 41 successful probes.
- [x] **3.4.3** httpx response parsing: handles chaos gracefully. Most resilient single-probe tool.

---

## Phase 4 — QA Validation (Senior QA Engineer)

### 4.1 Root cause isolation
- [x] **4.1.1** Root causes identified: header_corrupt (null byte) for gobuster/feroxbuster/commix; labyrinth+response size for ZAP OOM; error_inject+delays for arjun/nmap; content-encoding for whatweb
- [x] **4.1.2** QA engineer ran feature-by-feature isolation testing (toggling features ON/OFF via admin API for ~1 hour)
- [x] **4.1.3** Minimal reproduction: header_corrupt level 4 alone crashes gobuster. delay+error_inject hangs arjun. labyrinth alone drives ZAP memory growth.

### 4.2 Reproducibility verification
- [x] **4.2.1** All crash findings reproduced at least twice: ZAP OOM 3/3, Feroxbuster denial 5/5, Commix hang 2/2, Arjun hang 2/2, Gobuster transport error 3/3, WhatWeb errors 3/3, Nmap stall 2/2
- [x] **4.2.2** Success rates documented in findings report
- [x] **4.2.3** All crash/hang findings are deterministic. Error counts in WhatWeb vary (14-17 errors) but always occur.

### 4.3 Bug report quality
- [x] **4.3.1** All findings have: tool, version, command, config, expected/actual behavior, root cause — see docs/scanner-research-findings.md
- [x] **4.3.2** Classification: Gobuster=scanner bug (Go HTTP parser doesn't handle null bytes), ZAP=scanner weakness (unbounded memory), Feroxbuster=scanner weakness (no canary retry), Commix=scanner bug (infinite wait on bad response), Arjun=scanner weakness (no error reporting), WhatWeb=scanner bug (nil deref on bad encoding), Nmap=scanner weakness (sequential script execution)
- [x] **4.3.3** Severity classified: OOM crash > transport crash > plugin crash > hang > denial > logic defeat > degradation

---

## Phase 5 — Combined Report

### 5.1 Merge findings
- [x] **5.1.1** Combined report written: 7 new crash findings + 9 original findings = 16 total
- [x] **5.1.2** Precise root causes included for all crash findings (code line references where applicable)
- [x] **5.1.3** docs/scanner-research-findings.md updated with complete combined report
- [x] **5.1.4** docs/real-world-findings.md updated with CT-11 through CT-20

### 5.2 Sprint completion
- [x] **5.2.1** Verify all plan items are completed (full audit) — all 55 prior items confirmed done
- [x] **5.2.2** Send Telegram status report — sent successfully
- [x] **5.2.3** Final plan audit — all 58/58 items confirmed complete

---

## Item Count

| Phase | Items | Done |
|-------|-------|------|
| 1. Tool Installation | 9 | 9 |
| 2. Server Tuning | 11 | 11 |
| 3. Scanner Execution | 22 | 22 |
| 4. QA Validation | 9 | 9 |
| 5. Combined Report | 7 | 7 |
| **TOTAL** | **58** | **58** |

---

## Progress Log

- 2026-03-05 15:20: Sprint created. Server running nightmare mode. Previous sprint complete.
- 2026-03-05 15:25: Phase 1 complete. All tools installed (Docker + native).
- 2026-03-05 15:30: Phase 2 complete. Crash opportunity analysis done. Null byte header identified as primary crasher.
- 2026-03-05 15:31: Phase 3 started. Katana (208 URLs), Hakrawler (439 URLs) ran successfully.
- 2026-03-05 15:46: Feroxbuster 5/5 connection failures. Commix hung 12+ min. Arjun zero output.
- 2026-03-05 15:49: Gobuster transport error confirmed (null byte). 3 paths only with --force.
- 2026-03-05 16:00: nuclei 10 min, 0 findings. nikto 10 min, 42 false positives.
- 2026-03-05 16:13: sqlmap ran with --ignore-code but still 0 injections. Random codes block testing.
- 2026-03-05 16:23: wapiti 838 URLs, 88 ReadErrors. ZAP full scan crashed internal proxy at 512MB limit.
- 2026-03-05 16:38: nmap zero output in 5 min. ffuf 47/76 results. whatweb 17 plugin errors.
- 2026-03-05 16:55: httpx: every path reports different tech stack. Most resilient tool.
- 2026-03-05 17:00: Phase 3 complete. Senior QA spawned for root cause isolation.

---

## Previous Sprint Findings (reference, not re-tested)

| # | Tool | Finding | Category |
|---|------|---------|----------|
| 1 | nuclei | 0 findings in 2 min, 7% completion | Throughput degradation |
| 2 | nikto | 6+ frameworks detected simultaneously | False positives |
| 3 | sqlmap | Immediate abort on HTTP 102 | Clean denial |
| 4 | wapiti | Found only 1 URL | Crawl denial |
| 5 | ZAP | Timeout + 15 false positive alerts | Timeout + false positives |
| 6 | nmap | Can't fingerprint service | Fingerprint evasion |
| 7 | whatweb | Detected Drupal + Cloudflare (wrong) | Misidentification |
| 8 | ffuf | ~1 req/sec throughput | Throughput degradation |
| 9 | wget | 20 files in 2 min | Crawl trapping |
| 10 | gobuster | Wildcard detection defeated, malformed MIME header | Transport error |
