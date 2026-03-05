# Vulnerability Scanner Test Results — Nightmare Mode

**Date**: 2026-03-05
**Target**: http://localhost:8765 (Glitch server in nightmare mode)

## Summary

Nightmare mode effectively defeated or severely degraded all vulnerability scanners tested. Key findings:

1. **Nuclei** — Complete defeat. 0 findings after 10+ minutes. Chaos responses (random status codes, timeouts, protocol glitches) prevented template matching. Used 800MB RAM processing templates against nonsensical responses.
2. **Nikto** — Nearly complete defeat. 1 finding (missing X-Frame-Options) out of 180s scan. Hit max execution time due to slow responses/tarpits.
3. **Wapiti** — Partial results. Found 14 cookie/header issues but 0 actual vulnerabilities (no XSS, SQLi, SSRF, etc. detected). Only crawled 1 URL due to chaos.
4. **ZAP** — Moderate results. Found 13 warnings (CSP, clickjacking, cookies, CORS) but 0 FAILs. Only crawled 3 URLs (/, /robots.txt, /sitemap.xml). Baseline scan mode.
5. **sqlmap** — Complete defeat. Both `/api/v1/users?id=1` and `/vuln/a03/sqli?id=1` returned chaos responses (blank pages, HTTP 102). Could not even begin injection testing.

## Detailed Results

### Nuclei v3.7.0
- **Duration**: 10+ min (killed)
- **Memory**: ~800MB
- **Findings**: 0
- **Behavior**: Loaded all templates, ran them against target, but chaos mode responses prevented any template from matching. Every probe got a random error/status/timeout.
- **Verdict**: Nightmare mode completely neutralizes template-based scanning.

### Nikto 2.1.5
- **Duration**: 198s (hit 180s max time)
- **Findings**: 1
  - Missing X-Frame-Options header
- **Server identified as**: cloudflare (framework emulation worked)
- **Errors**: 4 errors reported
- **Verdict**: Tarpits and slow responses consumed all scan time. Nikto barely completed any checks.

### Wapiti 3.2.10
- **Duration**: ~60s
- **URLs crawled**: 1
- **Findings**: 14 (all header/cookie issues)
  - CSP not set: 1
  - Clickjacking (X-Frame-Options): 1
  - HttpOnly flag missing: 5 cookies
  - Secure flag missing: 5 cookies
  - Unencrypted channels: 1
  - Information disclosure (full path): 1
- **Modules run**: upload, sql, exec, file, ssrf, xss, redirect, permanentxss
- **Vuln modules found**: 0 actual vulnerabilities
- **Verdict**: Crawler defeated (only found 1 URL). Attack modules ran but chaos responses prevented detection.

### OWASP ZAP 2.17.0 (Docker, baseline scan)
- **Duration**: ~120s
- **URLs crawled**: 3 (/, /robots.txt, /sitemap.xml)
- **FAILs**: 0
- **Warnings**: 13
  - Medium: CSP not set (2), Missing anti-clickjacking (2), Weak auth method (1)
  - Low: Cookie HttpOnly (5), Cookie SameSite (5), COEP missing (3), COOP missing (3), CORP missing (3), Permissions-Policy (2), X-Powered-By leak (1), X-Content-Type-Options (2)
  - Info: Suspicious comments (1), Cache (1), Session management (2), Storable content (4)
- **Passed checks**: 54
- **Verdict**: Found header/cookie issues (passive checks work). But crawler barely explored — active scanning would likely be defeated like others.

### sqlmap 1.10.2
- **Run 1**: `/api/v1/users?id=1` — Got blank page content, could not parse forms
- **Run 2**: `/vuln/a03/sqli?id=1` — Got HTTP 102 (Processing), could not retrieve page content
- **Duration**: <5s each (immediate failure)
- **Findings**: 0
- **Verdict**: Chaos status codes and empty responses prevent sqlmap from establishing a baseline, making injection testing impossible.

## Chaos Mechanisms Observed

| Mechanism | Effect on Scanners |
|-----------|-------------------|
| Random HTTP status codes | Template matching fails (nuclei), baseline comparison fails (sqlmap) |
| Tarpits / slow responses | Timeout exhaustion (nikto hit 180s limit) |
| Empty response bodies | Form parsing fails (sqlmap), content analysis fails |
| Protocol glitches (HTTP 102) | Immediate abort in sqlmap |
| Framework emulation (cloudflare) | Nikto misidentified server |
| Cookie traps (6+ cookies per request) | Generated cookie warnings in ZAP/wapiti |
| Header chaos (Vary, WWW-Authenticate, X-Redirect-Hint) | Confused ZAP passive analysis |
| Chaos mode active warning header | Detectable signal (Warning: 299) |

## ffuf Directory Fuzzing Results

Ran against 130 Glitch-specific paths:
- **200 OK**: 68 paths responded (most are honeypots/emulated endpoints)
- **404**: 10 paths (vuln/api1, vuln/api2, vuln/api7, vuln/api9, vuln/api4, vuln/a07/xss, vuln/a03/sqli, media/image)
- **418 I'm a teapot**: api/v1/users (chaos response)
- **500**: api-docs (chaos response)
- **Errors**: 50/130 requests had connection errors (timeouts, resets)
- **Average response time**: 4-9 seconds (tarpit effect)

## nmap Service Scan Results

- Port 8765: open, service unrecognized ("ultraseek-http?")
- All non-HTTP probes returned 400 Bad Request
- Could not fingerprint service version
- HTTP scripts found no additional info (chaos blocked enum/headers scripts)

## whatweb Fingerprinting Results

- **Server**: cloudflare (emulated)
- **Cookies**: 10 cookies set per request (traps, fingerprinting, session)
- **Headers**: Extensive chaos headers (X-Chaos-Drip, Warning: 299, dual WWW-Authenticate, X-Redirect-Hint honeypot lure)
- **CSP**: Present but restrictive
- **Vary**: 9 fields (Accept, Accept-Encoding, Accept-Language, User-Agent, Cookie, X-Forwarded-For, X-Requested-With, Origin, Referer)

## Key Takeaways

1. **Nightmare mode is highly effective** at defeating automated scanners
2. **Passive checks still work** — header/cookie analysis finds issues (but these are intentional honeypot features)
3. **Active scanning is completely blocked** — no scanner found real vulnerabilities despite the server having hundreds of vuln endpoints
4. **Crawling is the bottleneck** — most scanners only reached 1-3 pages due to chaos
5. **Memory impact**: nuclei consumed 800MB trying to process chaos responses
6. **Possible scanner improvement**: Retry logic with timeout backoff, chaos detection (Warning: 299 header), and baseline-free detection modes
