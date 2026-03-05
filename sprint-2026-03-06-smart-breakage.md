# Sprint: Smart Breakage Scanner

**Goal**: Iteratively improve the built-in scanner to find real bugs, crashes, and disruptions in target web servers through malformed/chaotic HTTP requests (not performance testing).

## Findings — Confirmed Server Destruction

### Critical: Complete Service Denial

| # | Finding | Target | Attack | Impact |
|---|---------|--------|--------|--------|
| 1 | **Connection pool exhaustion** | Apache | 500 partial-header connections | Complete unavailability — server stops responding to ALL requests |
| 2 | **Chunked transfer resource exhaustion** | Flask | 200 incomplete chunked transfers | Complete unavailability — server stops responding to ALL requests |

### High: Server Instability

| # | Finding | Target | Attack | Impact |
|---|---------|--------|--------|--------|
| 3 | **HTTP 500 from bare CR** | Puma | `\r` line endings (no `\n`) | Internal Server Error on every malformed request |
| 4 | **HTTP 500 from empty request** | Puma | `\r\n\r\n` only | Internal Server Error |
| 5 | **HTTP 500 from chunk overflow** | Puma | `FFFFFFFFFFFFFFFF` hex chunk size | Internal Server Error |
| 6 | **HTTP 500 from CVE-2013-2028 pattern** | Puma | Oversized hex chunk + data | Internal Server Error |
| 7 | **75% error rate under flood** | Puma | 500 concurrent malformed requests | 375/500 requests return 500 (stability issue) |

### Medium: Protocol Violations

| # | Finding | Target | Attack | Impact |
|---|---------|--------|--------|--------|
| 8 | Non-HTTP response | Flask | HTTP/2 preface, HTTP/9.9, no space, null in version | Raw HTML without HTTP status line |
| 9 | Non-HTTP response | Django | HTTP/2 preface, HTTP/9.9, no space, null in version | Raw HTML without HTTP status line |
| 10 | HTTP/0.9 fallback | Nginx, Apache | `GET /\r\n` (no version) | Raw HTML without HTTP status line |

### Robustness (No Findings)

| Target | Result |
|--------|--------|
| Express (Node.js) | All attacks rejected correctly — zero findings |
| Go net/http | All attacks rejected correctly — zero findings |

## Architecture

### Raw TCP Attack Module (`internal/scanner/attacks/breakage.go`)
- Implements `scanner.RawTCPModule` interface — bypasses Go's `net/http` client entirely
- **~60 single-shot attacks** organized by category:
  - Request-line malformation (13 attacks)
  - Header malformation (14 attacks)
  - Chunked encoding abuse (7 attacks)
  - Content-Length abuse (7 attacks)
  - Request smuggling (5 attacks)
  - CVE-inspired (3 attacks)
  - Connection tricks (5 attacks)
  - Body/encoding confusion (6 attacks)
- **10 sequence attacks** that stress server state management:
  - Partial header flood (escalating: 100→250→500 connections)
  - Pipeline confusion (mixed valid/malformed)
  - Post-error connection reuse
  - Rapid TCP RST flood (200 connect/close cycles)
  - Massive connection hold (escalating: 500→1000→2000)
  - Chunked hang flood (200 incomplete transfers)
  - CL-mismatch hang (100 connections claiming 10MB body)
  - 500-triggering flood (500 concurrent malformed requests)
  - Combined assault (partial + malformed + chunked simultaneously)
  - Header bomb escalation (100→500→1K→5K→10K→50K headers)

### Scanner Engine Integration
- `RawTCPModule` interface in `internal/scanner/module.go`
- Engine calls `RunRawTCP()` after HTTP-based attack phases
- Module registered in `internal/scanner/attacks/registry.go`
- Health probing after each attack to detect crashes/hangs

## Implementation Log

### Phase 1: Raw TCP Module ✅
- Created `breakage.go` with `BreakageModule` implementing `RawTCPModule`
- All attacks use `net.Dial` raw TCP — no `net/http` sanitization
- Health probe after every attack detects crashes

### Phase 2: CVE-Inspired Attacks ✅
- Apache Range bomb (CVE-2011-3192) — modern Apache rejects with 400
- Nginx chunk overflow (CVE-2013-2028) — triggers Puma 500
- Node.js CL parsing (CVE-2018-7159) — modern Express rejects with 400

### Phase 3: Scanner Engine Integration ✅
- Added `RawTCPModule` interface to scanner
- Wired into engine's scan flow (runs after HTTP attacks)
- Registered in module registry

### Phase 4: Validation & Iteration ✅
- Ran against all 7 Docker targets
- Achieved functional destruction of 3/7 targets
- Iterated with escalating connection counts
- Added sequence attacks for multi-step exploitation

### Phase 5: Sprint Completion ✅
- All unit tests pass (45 packages)
- Crash tests confirm findings are reproducible
- Integration test verifies scanner module works end-to-end
