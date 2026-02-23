# PRD: Glitch Scanner

## Overview

Glitch Scanner is a configurable HTTP client/scanner emulator that mirrors every Glitch Server capability from the attack side. It serves two purposes: (1) test backends, proxies, and WAFs by sending adversarial traffic, and (2) act as the reference scanner for Glitch Server's scanner evaluation framework.

## Problem Statement

Backend developers, proxy developers, and WAF developers lack a tool that generates realistic, configurable, adversarial HTTP traffic at every protocol layer. Existing tools (nuclei, ZAP, ffuf) are real scanners optimized for finding vulns — they don't focus on breaking the services they scan. Glitch Scanner focuses on both: finding vulns AND stress-testing the target.

## User Stories

1. As a **WAF developer**, I want to test my WAF against hundreds of attack payloads organized by OWASP category, so I can measure detection coverage.
2. As a **backend developer**, I want to send malformed HTTP requests at my server to verify it doesn't crash on protocol violations.
3. As a **proxy developer**, I want to generate high-volume mixed traffic (normal + malicious) to test how my proxy handles it.
4. As a **QA engineer**, I want to run the scanner in compliance mode to establish a baseline, then in nightmare mode to test resilience.
5. As a **DevSecOps engineer**, I want to include Glitch Scanner in my CI/CD pipeline to continuously test my application's security.

## Functional Requirements

### FR-1: Scan Engine

- Worker pool with configurable concurrency (1-1000 workers)
- Rate limiting (requests/sec, configurable)
- Graceful shutdown on SIGINT/SIGTERM
- Context-aware cancellation
- Progress reporting (requests completed, findings, errors)

### FR-2: Attack Modules

Each module can be individually enabled/disabled. Modules organized by OWASP list:

| Module | Payloads | Description |
|--------|----------|-------------|
| OWASP Web A01-A10 | Broken access control, crypto, injection, SSRF, etc. |
| OWASP API 1-10 | BOLA, broken auth, mass assignment, SSRF |
| OWASP LLM 1-10 | Prompt injection, model manipulation |
| OWASP CI/CD 1-10 | Pipeline poisoning, credential leaks |
| OWASP Cloud 1-10 | K8s misconfig, IAM abuse |
| OWASP Mobile 1-10 | Credential storage, insecure crypto |
| OWASP IoT 1-10 | Default passwords, insecure interfaces |
| ... | All 18 OWASP lists |
| Fuzzing | Parameter, header, path, method fuzzing |
| Protocol abuse | Malformed HTTP, request smuggling, header injection |
| Authentication | Brute force, token manipulation, session fixation |
| Injection | SQLi, XSS, SSRF, SSTI, command injection |

### FR-3: Crawl Engine

- Breadth-first crawling with configurable depth
- Link extraction from HTML, JavaScript, CSS
- API endpoint discovery from JS fetch() calls, prefetch links
- robots.txt and sitemap.xml parsing
- URL deduplication and normalization
- Loop detection (labyrinth awareness)
- Form discovery and submission
- Cookie/session management

### FR-4: Scan Profiles

| Profile | Behavior |
|---------|----------|
| `compliance` | Standards-compliant, polite, rate-limited — baseline testing |
| `aggressive` | All modules enabled, high concurrency, no stealth |
| `stealth` | Evasion techniques, fingerprint spoofing, human-like timing |
| `nightmare` | Maximum adversarial — protocol abuse, connection flooding, designed to crash targets |
| `custom` | User-defined module selection and parameters |

### FR-5: Resilience Testing

The scanner must handle all Glitch Server error types gracefully:
- TCP resets mid-response
- Infinitely slow responses (byte-by-byte)
- Corrupted HTTP headers
- Invalid content-length
- Connection drops
- Infinite response bodies
- Invalid status codes
- Binary data in text responses

### FR-6: Evasion Techniques

For testing WAFs and bot detection:
- URL encoding variants (double, unicode, overlong UTF-8)
- Header case manipulation
- Request splitting / desync
- Chunked encoding payload hiding
- Comment injection in payloads
- Null byte injection
- User-agent rotation
- TLS fingerprint variation
- Request timing randomization

### FR-7: Reporting

Output formats:
- **JSON**: Machine-readable, full detail
- **HTML**: Human-readable with charts
- **SARIF**: For integration with code analysis tools

Report contents:
- Findings organized by OWASP category
- Coverage metrics (endpoints tested vs total)
- Resilience metrics (errors handled vs errors encountered)
- Timing data (per-request, per-category, overall)
- Comparison against expected results (when testing against Glitch Server)

### FR-8: Admin UI Integration

New "Scanner" tab in the admin dashboard:
- Start/stop scan controls
- Target URL configuration
- Profile selection
- Module enable/disable toggles
- Real-time progress (requests, findings, errors)
- Coverage heatmap
- Findings table

### FR-9: CLI Interface

```bash
glitch-scanner -target http://localhost:8765           # basic scan
glitch-scanner -target http://localhost:8765 -profile aggressive
glitch-scanner -target http://localhost:8765 -profile nightmare
glitch-scanner -target http://localhost:8765 -modules owasp-web,fuzzing
glitch-scanner -target http://localhost:8765 -concurrency 50 -rate 200
glitch-scanner -target http://localhost:8765 -proxy http://localhost:8080
glitch-scanner -target http://localhost:8765 -output report.json
glitch-scanner -target http://localhost:8765 -evasion advanced
```

## Non-Functional Requirements

- **NFR-1**: Zero external dependencies (Go stdlib only)
- **NFR-2**: Memory usage < 500MB even in nightmare mode
- **NFR-3**: Graceful handling of all server error types (no panics)
- **NFR-4**: Scan of full Glitch Server completes in < 60 seconds (aggressive profile)
- **NFR-5**: All attack modules have unit tests

## Acceptance Criteria

1. Scanner discovers all Glitch Server vulnerability endpoints via crawling
2. Scanner generates correct attack payloads for each OWASP category
3. Scanner handles all 30 Glitch Server error types without crashing
4. Scanner in nightmare mode generates protocol-level abuse traffic
5. Scanner produces accurate coverage report comparing findings vs expected vulns
6. Scanner works through Glitch Proxy without errors in compliance mode
7. All scan profiles produce expected behavior
8. Admin UI scanner tab shows real-time progress
9. CLI flags match documented interface
10. JSON/HTML reports contain all specified fields

## Dependencies

- Glitch Server must expose `/admin/api/expected-vulns` for coverage comparison
- Glitch Proxy must be runnable as intermediary for proxy-through testing
- Dashboard must support new Scanner tab

## Out of Scope (v1)

- Authenticated scanning (future: support for login sequences)
- HTTP/2-specific attacks (future)
- gRPC scanning (future)
- Distributed scanning across multiple machines
