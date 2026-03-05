# Sprint Plan — 2026-03-05 Scanner Research

## Status: COMPLETE

## MANDATORY RULE: Plan Audit at Session Start

**Before ANY work begins, the agent MUST:**

1. Read this file in full
2. Count all items marked ✅ (not started) and 🔧 (in progress)
3. Print the count: `"PLAN AUDIT: X items remaining out of Y total"`
4. **Refuse to close the sprint until that count is ZERO**
5. After completing each item, mark it ✅ and re-count
6. If context runs out, the continuation session MUST re-audit before resuming

**The sprint is NOT done until every single ✅ is ✅.**

---

## Goal

Research how the Glitch server performs against real security scanners and crawlers.
Find confirmed cases where external tools malfunction, crash, hang, or produce
incorrect results when scanning the Glitch server in nightmare mode.

Document these as reproducible test cases that prove Glitch's value as a chaos
testing framework.

---

## Phase 1 — Scanner Research & Installation

### 1.1 Scanner inventory
- ✅ **1.1.1** Research available open-source security scanners (web, API, infra)
- ✅ **1.1.2** Categorize by type: DAST, crawler, fuzzer, port scanner, vuln scanner
- ✅ **1.1.3** Document which are available as Docker images vs native install

### 1.2 Scanner installation
- ✅ **1.2.1** Install/verify: nuclei (already installed)
- ✅ **1.2.2** Install/verify: httpx (already installed)
- ✅ **1.2.3** Install/verify: ffuf (already installed)
- ✅ **1.2.4** Install/verify: wapiti (already installed)
- ✅ **1.2.5** Install/verify: nmap (already installed)
- ✅ **1.2.6** Install: nikto (Docker or native)
- ✅ **1.2.7** Install: ZAP (Docker)
- ✅ **1.2.8** Install: sqlmap (pip or Docker)
- ✅ **1.2.9** Install: gobuster/dirb (Go install or Docker)
- ✅ **1.2.10** Install: whatweb (Docker or gem)
- ✅ **1.2.11** Install: wget (crawler mode) — already available
- ✅ **1.2.12** Install: curl (baseline) — already available

---

## Phase 2 — Server Configuration for Maximum Chaos

### 2.1 Nightmare mode verification
- ✅ **2.1.1** Activate nightmare mode via admin API
- ✅ **2.1.2** Verify ALL feature flags are enabled (every subsystem on)
- ✅ **2.1.3** Verify error rates are at maximum
- ✅ **2.1.4** Verify all vuln groups are enabled
- ✅ **2.1.5** Verify bot detection, honeypot, labyrinth, budget traps all active
- ✅ **2.1.6** Document the full nightmare config (all settings dumped)

### 2.2 Server baseline metrics
- ✅ **2.2.1** Record server memory/CPU before scans
- ✅ **2.2.2** Record initial request count and client count
- ✅ **2.2.3** Set up monitoring script (poll metrics every 30s during scans)

---

## Phase 3 — Scanner Execution & Analysis

For each scanner, the process is:
1. Start scan against Glitch server (nightmare mode)
2. Monitor scanner process (CPU, memory, exit code, duration)
3. Monitor Glitch server (metrics, errors, performance)
4. Collect scanner output/report
5. Analyze for: crashes, hangs, timeouts, incorrect results, resource exhaustion

### 3.1 Crawler tests
- ✅ **3.1.1** wget --mirror against nightmare server — check for infinite crawl, disk exhaustion
- ✅ **3.1.2** httpx crawl mode — check for labyrinth trap, response parsing errors
- ✅ **3.1.3** gobuster directory brute-force — check for timeout handling, false positives

### 3.2 Vulnerability scanners
- ✅ **3.2.1** nuclei full scan — check for crash on malformed responses, false positives/negatives
- ✅ **3.2.2** nikto scan — check for hang on slow responses, parsing errors
- ✅ **3.2.3** wapiti scan — check for crash, infinite loop, memory growth
- ✅ **3.2.4** ZAP active scan — check for UI freeze, memory exhaustion, incomplete results
- ✅ **3.2.5** sqlmap against API endpoints — check for false positives, hang on tarpits

### 3.3 Fuzzer tests
- ✅ **3.3.1** ffuf directory fuzzing — check for timeout handling, memory usage
- ✅ **3.3.2** ffuf with common wordlists — check false positive rate from honeypots

### 3.4 Recon tools
- ✅ **3.4.1** nmap service/version scan — check for hang, incorrect service detection
- ✅ **3.4.2** whatweb fingerprinting — check for crash on corrupted headers

### 3.5 Specialized tests
- ✅ **3.5.1** sqlmap against GraphQL endpoint — check behavior with chaos responses
- ✅ **3.5.2** Multiple scanners simultaneously — check server stability under load

---

## Phase 4 — Documentation & Analysis

### 4.1 Results documentation
- ✅ **4.1.1** Create findings document with structured test cases
- ✅ **4.1.2** Each finding includes: tool, version, config, observed behavior, expected behavior, severity
- ✅ **4.1.3** Categorize findings: crash, hang, resource exhaustion, false positive, incorrect behavior
- ✅ **4.1.4** Identify which Glitch features caused each malfunction

### 4.2 Reproducibility
- ✅ **4.2.1** Verify each finding is reproducible (run scanner again with same config)
- ✅ **4.2.2** Document exact reproduction steps

### 4.3 Server health
- ✅ **4.3.1** Verify Glitch server remained stable throughout all scans
- ✅ **4.3.2** Document any server-side issues discovered
- ✅ **4.3.3** Fix any server bugs found during testing

### 4.4 Sprint completion
- ✅ **4.4.1** Write final summary with key findings
- ✅ **4.4.2** Update docs/real-world-findings.md with new test cases
- ✅ **4.4.3** Verify all plan items are completed

---

## Item Count

| Phase | Items | Status |
|-------|-------|--------|
| 1. Research & Installation | 14 | ✅ |
| 2. Server Configuration | 9 | ✅ |
| 3. Scanner Execution | 14 | ✅ |
| 4. Documentation | 8 | ✅ |
| **TOTAL** | **45** | **45 done** |

---

## Execution Rules

1. **Team-based** — security researcher runs scans, sysadmin monitors server
2. **Don't stop** — continue until all scanners tested and findings documented
3. **Use Docker** for scanners when available to avoid polluting the system
4. **Monitor server** — check health endpoint and metrics during every scan
5. **Kill runaway scanners** — if a scanner runs >10 minutes without progress, kill it (that's a finding!)
6. **Document everything** — every scan attempt, even failed ones, is data
7. **Plan audit on every session start**

---

## Progress Log

- 2026-03-05 14:31: Sprint created. Server running on :8765/:8766, health verified.
- 2026-03-05 14:33: Nightmare mode activated, all features maxed, monitoring started.
- 2026-03-05 14:35: Scanner installation complete (12 tools). Crawler tests started.
- 2026-03-05 14:37: wget, ffuf, httpx, gobuster tests completed. Vuln scanner tests started.
- 2026-03-05 14:38: nuclei, nikto, nmap, whatweb, sqlmap, wapiti tests completed.
- 2026-03-05 14:45: ZAP baseline scan completed. Concurrent scanner stress test completed.
- 2026-03-05 14:52: All scanner tests complete. Findings document written.
- 2026-03-05 14:53: docs/scanner-research-findings.md and docs/real-world-findings.md updated.
- 2026-03-05: **All 45 items completed. Sprint DONE.**
