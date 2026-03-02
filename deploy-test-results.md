# Deployment Test Results

**Date:** 2026-03-02 00:55:05 UTC
**Branch:** feature/docker-deployment-tests
**Commit:** 189991a

## Test Matrix

Each deployment method is tested with 15 endpoint/API tests covering:
health, admin auth, config API, metrics, features, vulns, API endpoints,
feature toggle round-trip, config update round-trip, honeypot, robots.txt,
labyrinth, and config export.

Tests 3 (main page) and 14 (labyrinth) use retries because the chaos
server injects random errors on these paths by design.

### bare

| # | Test | Status |
|---|------|--------|
| 1 | Health endpoint | **Pass** |
| 2 | Health/live endpoint | **Pass** |
| 3 | Main page returns HTML | **Pass** (with retry) |
| 4 | Admin requires auth | **Pass** (302) |
| 5 | Admin API config | **Pass** |
| 6 | Metrics endpoint | **Pass** |
| 7 | Feature flags | **Pass** |
| 8 | Vuln endpoints | **Pass** |
| 9 | API endpoints | **Pass** |
| 10 | Feature toggle round-trip | **Pass** |
| 11 | Config update round-trip | **Pass** |
| 12 | Honeypot endpoints | **Pass** (200) |
| 13 | robots.txt | **Pass** |
| 14 | Labyrinth pages | **Pass** (with retry) |
| 15 | Config export | **Pass** |

**Result: 15/15 passed**

### makefile

| # | Test | Status |
|---|------|--------|
| 1 | Health endpoint | **Pass** |
| 2 | Health/live endpoint | **Pass** |
| 3 | Main page returns HTML | **Pass** (with retry) |
| 4 | Admin requires auth | **Pass** (302) |
| 5 | Admin API config | **Pass** |
| 6 | Metrics endpoint | **Pass** |
| 7 | Feature flags | **Pass** |
| 8 | Vuln endpoints | **Pass** |
| 9 | API endpoints | **Pass** |
| 10 | Feature toggle round-trip | **Pass** |
| 11 | Config update round-trip | **Pass** |
| 12 | Honeypot endpoints | **Pass** (200) |
| 13 | robots.txt | **Pass** |
| 14 | Labyrinth pages | **Pass** (with retry) |
| 15 | Config export | **Pass** |

**Result: 15/15 passed**

### docker

| # | Test | Status |
|---|------|--------|
| 1 | Health endpoint | **Pass** |
| 2 | Health/live endpoint | **Pass** |
| 3 | Main page returns HTML | **Pass** (with retry) |
| 4 | Admin requires auth | **Pass** (302) |
| 5 | Admin API config | **Pass** |
| 6 | Metrics endpoint | **Pass** |
| 7 | Feature flags | **Pass** |
| 8 | Vuln endpoints | **Pass** |
| 9 | API endpoints | **Pass** |
| 10 | Feature toggle round-trip | **Pass** |
| 11 | Config update round-trip | **Pass** |
| 12 | Honeypot endpoints | **Pass** (200) |
| 13 | robots.txt | **Pass** |
| 14 | Labyrinth pages | **Pass** (with retry) |
| 15 | Config export | **Pass** |

**Result: 15/15 passed**

### compose

| # | Test | Status |
|---|------|--------|
| 1 | Health endpoint | **Pass** |
| 2 | Health/live endpoint | **Pass** |
| 3 | Main page returns HTML | **Pass** (with retry) |
| 4 | Admin requires auth | **Pass** (302) |
| 5 | Admin API config | **Pass** |
| 6 | Metrics endpoint | **Pass** |
| 7 | Feature flags | **Pass** |
| 8 | Vuln endpoints | **Pass** |
| 9 | API endpoints | **Pass** |
| 10 | Feature toggle round-trip | **Pass** |
| 11 | Config update round-trip | **Pass** |
| 12 | Honeypot endpoints | **Pass** (200) |
| 13 | robots.txt | **Pass** |
| 14 | Labyrinth pages | **Pass** (with retry) |
| 15 | Config export | **Pass** |

**Result: 15/15 passed**

## Summary

- **Passed:** 4
- **Failed:** 0

## Notes

- Docker and Docker Compose tests require Docker daemon access
- Main page and labyrinth tests use retry logic due to intentional chaos error injection
- All tests use env-only configuration (GLITCH_ADMIN_PASSWORD via .env file)
