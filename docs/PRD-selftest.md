# PRD: Self-Test Pipeline

## Overview

The Self-Test Pipeline runs all three Glitch components (Scanner, Proxy, Server) against each other in a single orchestrated session. It validates the entire framework's functionality, measures component interactions, and provides a comprehensive health report.

## Problem Statement

Testing a 3-component system requires orchestrating all three parts simultaneously, routing traffic through them in the correct order, and collecting metrics from each. Manual setup is error-prone. An automated self-test proves the framework works end-to-end and serves as a continuous integration validation.

## User Stories

1. As a **developer**, I want to run `glitch selftest` to verify all three components work together after making changes.
2. As a **CI pipeline**, I want an automated test that validates the full Glitch framework in one command.
3. As a **user**, I want to see how the three components interact in a dashboard, to understand what Glitch does.
4. As a **contributor**, I want a self-test report that shows what's working and what's broken across all components.

## Self-Test Modes

| Mode | Scanner Profile | Proxy Mode | Server Config | Duration | Purpose |
|------|----------------|------------|---------------|----------|---------|
| `baseline` | compliance | transparent | normal (low error rate) | 30s | Basic functionality verification |
| `scanner-stress` | aggressive | transparent | normal | 60s | Test scanner against full server |
| `proxy-stress` | compliance | chaos | normal | 60s | Test scanner handling of proxy chaos |
| `server-stress` | compliance | transparent | aggressive | 60s | Test scanner resilience to server errors |
| `chaos` | aggressive | chaos | aggressive | 60s | Full mutual stress test |
| `nightmare` | nightmare | nightmare | nightmare | 60s | Maximum adversarial survival test |

## Functional Requirements

### FR-1: Orchestration

```bash
glitch selftest [--mode MODE] [--duration DURATION] [--report FILE]
```

The selftest command:
1. Starts Glitch Server on an auto-selected port
2. Starts Glitch Proxy on an auto-selected port, targeting the server
3. Starts Glitch Scanner targeting the proxy
4. Runs for the specified duration
5. Collects metrics from all three components
6. Shuts down all components gracefully
7. Produces a report

All ports are auto-selected (binding to :0) to avoid conflicts. Components communicate via localhost.

### FR-2: Monitoring

During self-test, the dashboard (port 8766 or auto-selected) shows a unified view:

**Scanner Panel:**
- Requests sent / in-flight / completed
- Findings by category
- Error rate
- Coverage percentage

**Proxy Panel:**
- Requests proxied / blocked / modified / errored
- Added latency distribution
- Corruption actions taken
- Connection statistics

**Server Panel:**
- Requests received / served / errored
- Error types generated
- Client fingerprints seen
- Adaptive behavior triggered

**Pipeline Panel:**
- End-to-end success rate (scanner request → server response)
- End-to-end latency (scanner send → scanner receive)
- Data integrity (response matches expected format)
- Component health status (up/down/degraded)

### FR-3: Reporting

Self-test report (JSON):

```json
{
  "mode": "chaos",
  "duration_seconds": 60,
  "started_at": "...",
  "completed_at": "...",
  "scanner": {
    "requests_sent": 1500,
    "findings": 42,
    "errors": 15,
    "coverage_pct": 87.5
  },
  "proxy": {
    "requests_proxied": 1500,
    "requests_blocked": 30,
    "requests_modified": 150,
    "avg_added_latency_ms": 45
  },
  "server": {
    "requests_received": 1470,
    "errors_injected": 220,
    "error_type_distribution": {...}
  },
  "pipeline": {
    "e2e_success_rate": 0.85,
    "e2e_avg_latency_ms": 120,
    "data_integrity_pct": 99.2
  },
  "survival": {
    "no_crash": true,
    "no_oom": true,
    "recovery_seconds": 3.2,
    "goroutine_leak": false
  },
  "verdict": "PASS"
}
```

### FR-4: CI Integration

The selftest command exits with:
- Exit code 0: all survival criteria passed
- Exit code 1: one or more survival criteria failed
- Exit code 2: components failed to start

This enables simple CI integration:
```yaml
- name: Self-test
  run: |
    go build -o glitch ./cmd/glitch
    go build -o glitch-scanner ./cmd/glitch-scanner
    go build -o glitch-proxy ./cmd/glitch-proxy
    ./glitch selftest --mode baseline --duration 30s --report selftest.json
```

### FR-5: Comparison Across Runs

Store self-test results history (in `selftest-results/` directory) to track:
- Coverage changes across commits
- Performance regressions
- New failures introduced

## Non-Functional Requirements

- **NFR-1**: Selftest completes within 2x specified duration (overhead for startup/shutdown)
- **NFR-2**: All three components must clean up fully (no orphan processes)
- **NFR-3**: Works on Linux and macOS
- **NFR-4**: Zero external dependencies

## Acceptance Criteria

1. `glitch selftest` starts all three components and runs to completion
2. All six modes produce valid reports
3. Baseline mode passes with 100% component survival
4. Nightmare mode produces meaningful adversarial load
5. Dashboard shows unified pipeline view during self-test
6. Report contains all specified fields
7. CI exit codes are correct (0 for pass, 1 for fail, 2 for startup error)
8. Components shut down cleanly with no orphan processes
9. Self-test works on a clean build (no pre-existing state required)
10. Results are reproducible (same mode produces similar metrics)

## Dependencies

- Glitch Scanner must be fully functional
- Glitch Proxy must support all specified modes
- Dashboard must support the unified pipeline view
- Server must expose metrics API for monitoring

## Risks

- Port conflicts on CI machines → mitigated by auto-port selection
- Timing sensitivity in tests → mitigated by using duration-based runs, not request-count
- Resource constraints in containers → mitigated by configurable concurrency limits
