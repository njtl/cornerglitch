# Implementation Plan — Glitch Web Server Enhancements

## Overview

Three major new subsystems + comprehensive test suite for the glitch web server.

---

## 1. Realistic API Endpoints with Swagger (`internal/api/endpoints.go`)

**Goal:** Make the server expose convincing REST API endpoints that look like a real production service.

### Features:
- **4 full API definitions** — User Management, E-Commerce, Infrastructure Monitoring, Content Management
- Each API has 6-10 CRUD endpoints with proper HTTP methods (GET/POST/PUT/DELETE)
- Realistic response bodies: pagination, metadata, UUIDs, timestamps, nested objects
- Proper headers: `X-Request-Id`, `X-RateLimit-*`, `X-API-Version`, `Cache-Control`
- **Working Swagger/OpenAPI 2.0 spec** at `/api/swagger.json`, `/openapi.json`, `/v1/swagger.json`, `/v2/swagger.json`
- **Swagger UI** at `/swagger-ui`, `/api-docs`, `/docs/api` — loads the real Swagger UI from CDN and points at the JSON spec, fully interactive with "Try it out"
- **GraphQL endpoint** at `/graphql` and `/api/graphql` — returns introspection schema + mock query results
- ~33% of API paths randomly expose swagger (deterministic per-path via SHA-256 seed)
- Path detection: `/api/`, `/v1/`, `/v2/`, `/v3/`, `/rest/`, `/graphql`, `/rpc/`

### API Definitions:
| API | Base Path | Endpoints |
|-----|-----------|-----------|
| User Management API v1.4.2 | `/api/v1` | users CRUD, sessions, auth/login, auth/refresh, roles |
| E-Commerce API v2.8.1 | `/api/v2` | products, orders, cart, payments/charge, categories |
| Infrastructure Monitoring API v3.1.0 | `/api/v1` | hosts, host metrics, alerts, incidents, services, dashboards |
| Content Management API v1.2.0 | `/api/v3` | content CRUD, media/upload, webhooks |

---

## 2. Honeypot System for Fuzzers/Scanners (`internal/honeypot/honeypot.go`)

**Goal:** Detect and engage security scanners, fuzzers, and penetration testing tools by responding to the paths they probe.

### Features:
- **700+ known scanner paths** organized by category:
  - Admin panels: `/admin`, `/wp-admin`, `/administrator`, `/manager`, `/cpanel`, `/phpmyadmin`
  - Config/env files: `/.env`, `/config.json`, `/wp-config.php`, `/.git/config`, `/server.xml`
  - Backup files: `/backup.sql`, `/dump.sql`, `/database.bak`, `/site.tar.gz`
  - Debug/dev endpoints: `/debug`, `/trace`, `/phpinfo.php`, `/server-status`, `/elmah.axd`
  - Version/info: `/.svn/entries`, `/.hg/`, `/composer.json`, `/package.json`, `/Gemfile`
  - API discovery: `/.well-known/`, `/robots.txt`, `/sitemap.xml`, `/crossdomain.xml`
  - Known CVE paths: `/cgi-bin/`, `/shell`, `/cmd`, `/eval`, `/solr/`, `/actuator/`
  - Login/auth pages: `/login`, `/signin`, `/sso`, `/oauth`, `/register`

- **Scanner detection** via User-Agent matching:
  - Nikto, Nmap, sqlmap, Burp Suite, OWASP ZAP, DirBuster, Gobuster, ffuf, wfuzz
  - Nessus, Qualys, Acunetix, Nuclei, WPScan, w3af, arachni, skipfish
  - Detection confidence scoring

- **Realistic honeypot responses by category:**
  - Admin panels → fake login forms with CSRF tokens
  - Config files → fake credentials, DB connection strings, API keys (all honeypot markers)
  - Backup files → fake SQL dumps with realistic table structures
  - Debug endpoints → fake phpinfo(), server-status, stack traces
  - robots.txt → lists more honeypot paths to lure deeper scanning
  - Login pages → full HTML login forms

- **Behavior tracking:** records scanner tool, paths hit, timestamps for adaptive engine integration

---

## 3. Framework Emulation Engine (`internal/framework/emulator.go`)

**Goal:** Randomly impersonate different web frameworks and languages in responses, making the server appear as different technology stacks to different clients or requests.

### Emulated Frameworks (12+):
| Framework | Language | Key Signatures |
|-----------|----------|----------------|
| Express.js | Node.js | `X-Powered-By: Express`, ETag style, error format |
| Django | Python | `X-Frame-Options: DENY`, CSRF cookies, admin URLs |
| Ruby on Rails | Ruby | `X-Request-Id`, `X-Runtime`, CSRF meta tags |
| Spring Boot | Java | `X-Application-Context`, Whitelabel error pages |
| Laravel | PHP | `X-Powered-By: PHP/8.x`, `laravel_session` cookie |
| Flask | Python | `X-Powered-By: Werkzeug`, debug error pages |
| ASP.NET | C# | `X-Powered-By: ASP.NET`, `X-AspNet-Version`, ViewState |
| Gin (Go) | Go | Minimal headers, Go-style error JSON |
| FastAPI | Python | Validation error format, OpenAPI auto-gen headers |
| Next.js | Node.js | `X-Powered-By: Next.js`, `__NEXT_DATA__` script blocks |
| WordPress | PHP | `X-Powered-By: PHP`, `wp-content` paths, meta generator |
| Nginx | - | `Server: nginx/1.x`, default error pages |

### How It Works:
- Deterministic per-client: same client always sees same framework (via fingerprint hash)
- Headers, cookies, error pages, server header all match the emulated stack
- Framework-specific response wrappers modify the output of other generators
- Some frameworks add characteristic HTML patterns (Rails CSRF, Django admin, Next.js data)

---

## 4. Handler Integration (`internal/server/handler.go`)

### Updated Request Flow:
1. Fingerprint client → get adaptive behavior (existing)
2. **NEW:** Check if honeypot path → serve honeypot response
3. **NEW:** Check if API path → serve API/Swagger response
4. Check labyrinth eligibility → serve labyrinth (existing)
5. Roll error injection (existing)
6. **NEW:** Apply framework emulation headers/wrappers to all responses
7. Serve page (existing)
8. Record metrics (existing)

### New Handler Fields:
```go
type Handler struct {
    // existing...
    apiEndpoints *api.Endpoints
    honeypot     *honeypot.Honeypot
    framework    *framework.Emulator
}
```

---

## 5. Test System

### Unit Tests (`*_test.go` alongside each package):

| Package | Test File | What's Tested |
|---------|-----------|---------------|
| `api` | `endpoints_test.go` | API path detection, endpoint matching, swagger spec generation, response format |
| `honeypot` | `honeypot_test.go` | Path matching, scanner UA detection, response category, credential format |
| `framework` | `emulator_test.go` | Framework selection determinism, header injection, cookie format |
| `errors` | `generator_test.go` | Error profile weights sum to ~1.0, Pick distribution, Apply responses |
| `fingerprint` | `engine_test.go` | Client identification stability, classification accuracy |
| `adaptive` | `engine_test.go` | Behavior mode selection, escalation, per-class handling |
| `labyrinth` | `labyrinth_test.go` | Path detection, deterministic page content, link generation |
| `pages` | `generator_test.go` | Page type generation, content-type headers, response body format |
| `metrics` | `collector_test.go` | Ring buffer, client profiles, time series, concurrent safety |

### Integration Tests (`tests/integration/`):

- `server_integration_test.go` — Full HTTP request/response tests against a running handler:
  - API endpoints return valid JSON with correct structure
  - Swagger spec is valid OpenAPI
  - Honeypot paths return appropriate lure content
  - Framework headers are consistent per client
  - Error injection produces correct status codes
  - Labyrinth pages contain links
  - Adaptive behavior changes over time

### E2E Tests (`tests/e2e/`):

- `e2e_test.go` — Full server lifecycle:
  - Start server on random ports
  - Simulate browser, bot, scanner, and API tester traffic patterns
  - Verify adaptive behavior transitions
  - Verify dashboard API reflects real metrics
  - Verify graceful shutdown
  - Concurrent client stress test

---

## 6. Updated Project Layout

```
internal/
  api/endpoints.go           REST API simulation + Swagger/OpenAPI
  honeypot/honeypot.go       Scanner/fuzzer honeypot with 700+ paths
  framework/emulator.go      Random framework fingerprint emulation
  server/handler.go          Updated to dispatch to new subsystems
  errors/generator.go        (unchanged)
  pages/generator.go         (unchanged)
  labyrinth/labyrinth.go     (unchanged)
  fingerprint/engine.go      (unchanged)
  adaptive/engine.go         (unchanged)
  metrics/collector.go       (unchanged)
  dashboard/server.go        (unchanged)
tests/
  integration/server_integration_test.go
  e2e/e2e_test.go
```

---

## Build & Verify

```bash
go build ./cmd/glitch/           # compile check
go vet ./...                     # static analysis
go test ./...                    # all tests
go test ./internal/api/          # unit tests only
go test ./tests/integration/     # integration only
go test ./tests/e2e/             # e2e only
```
