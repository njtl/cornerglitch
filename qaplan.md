================================================================================
REQUIREMENT: Comprehensive Atomic Test Suite for Server, Scanner & Proxy
================================================================================
From: Product Manager
To: QA/Dev Team (Test Manager, Test Analyst, SDET, Test Architect, Developers)
Priority: HIGH
Type: Testing Architecture & Infrastructure
--------------------------------------------------------------------------------

╔══════════════════════════════════════════════════════════════════════════════╗
║                        IMPORTANT: READ FIRST                               ║
║                                                                            ║
║  This document is NOT a closed or final specification.                     ║
║                                                                            ║
║  Everything described below — setting groups, values, examples, scopes,    ║
║  verification approaches — are REFERENCES and EXAMPLES that communicate    ║
║  the intent, depth, and philosophy of what is expected.                    ║
║                                                                            ║
║  The real work starts with the team. You must:                             ║
║                                                                            ║
║  • Deep-dive into the actual codebase to discover every setting, every     ║
║    value, every behavior, every edge case — not just what's listed here    ║
║  • Analyze the product holistically to understand what truly needs         ║
║    coverage — there will be settings, modes, interactions, and behaviors   ║
║    that this document does not mention because they can only be found      ║
║    through thorough code and product analysis                              ║
║  • Build the real test design from the ground up based on what you find,   ║
║    not just from what's written here                                       ║
║  • Continuously expand scope as you discover more — this is an open-ended  ║
║    initiative, not a checkbox exercise                                     ║
║                                                                            ║
║  If this document says "test all settings in group X" and you find 50      ║
║  settings not mentioned here — test all 50. If you find hidden behaviors,  ║
║  undocumented flags, or implicit dependencies — cover them.                ║
║                                                                            ║
║  The team owns the final test design. This document sets direction.        ║
╚══════════════════════════════════════════════════════════════════════════════╝

--------------------------------------------------------------------------------

1. OBJECTIVE
--------------------------------------------------------------------------------
Build a comprehensive, atomic test suite that validates every individual setting,
every variant of every setting, and key combinations across all three system
scopes: Server, Scanner, and Proxy.

The test suite must be:
- Deterministic (100/100 pass rate expected, zero flakiness)
- Explicit in verification (no implicit or assumed assertions)
- Efficient in execution (thousands of tests, selectively runnable)
- Self-validating (checks both response AND internal system state)

>>> CRITICAL: This effort is NOT limited to writing tests. <

If the current architecture, codebase, or infrastructure makes any setting
difficult to test, slow to apply, hard to observe, or flaky to verify — the
team MUST fix the underlying project code, not work around it in tests.

This is a testing AND engineering initiative.

--------------------------------------------------------------------------------

2. ARCHITECTURE-FIRST MANDATE
--------------------------------------------------------------------------------
THE TEAM IS AUTHORIZED AND REQUIRED TO MODIFY THE APPLICATION ITSELF.

During the course of building this test suite, the team will inevitably
encounter friction: settings that don't apply cleanly, state that leaks
between tests, behaviors that are hard to observe, startup times that make
large suites impractical, etc.

The mandate is clear:

  DO NOT write fragile tests around architectural weaknesses.
  FIX the weaknesses, THEN write clean tests.

  Examples of changes the team must make on the fly:

  ┌─────────────────────────────────────────────────────────────────────┐
  │ TESTABILITY                                                         │
  │ - Add APIs or hooks to apply/reset individual settings atomically   │
  │ - Expose internal state for verification (stats, counters, flags)   │
  │ - Make every setting observable from outside (response + internals) │
  │ - If a setting has no visible effect, that's a bug — fix or remove  │
  ├─────────────────────────────────────────────────────────────────────┤
  │ PERFORMANCE                                                         │
  │ - Reduce app startup/restart time if it blocks fast test cycles     │
  │ - Support hot-reload of settings without full restart where possible│
  │ - Optimize test infrastructure for parallel execution               │
  ├─────────────────────────────────────────────────────────────────────┤
  │ SETTINGS APPLICATION                                                │
  │ - Ensure every setting can be applied and reverted programmatically │
  │ - Eliminate side effects between settings (or document & test them) │
  │ - Guarantee clean state reset between test runs                     │
  ├─────────────────────────────────────────────────────────────────────┤
  │ OBSERVABILITY                                                       │
  │ - Ensure DB/dashboard/stats reflect every setting change            │
  │ - Add missing metrics or state endpoints if verification requires it│
  │ - Logging must be sufficient to diagnose test failures              │
  ├─────────────────────────────────────────────────────────────────────┤
  │ ANY OTHER WEAKNESS                                                  │
  │ - If the team discovers ANY architectural issue that blocks clean,  │
  │   reliable, fast testing — they must fix it immediately             │
  │ - This includes refactoring, dependency cleanup, config management, │
  │   data isolation, or anything else that stands in the way           │
  └─────────────────────────────────────────────────────────────────────┘

  Process:
  1. Encounter a blocker or weakness during test development
  2. Log it, assess impact, propose fix
  3. Developer implements the fix in the application
  4. SDET writes/updates the test against the improved code
  5. Verify and move on

  This is a continuous loop. Do not batch fixes for later. Fix on the fly.

--------------------------------------------------------------------------------

3. CORE TESTING PRINCIPLE
--------------------------------------------------------------------------------
For every setting:

  1. Start from a known baseline (clean state, nothing active)
  2. Toggle ONLY the single setting under test to a specific value
  3. Assert explicitly that:
     a. The system response reflects the change
     b. The internal system state (DB, dashboard, stats) reflects the change
  4. Toggle it back / off
  5. Assert explicitly that the system returns to baseline
  6. Repeat for every possible value of that setting

This is the "atomic isolation" approach. No test should depend on another test's
state. Every test must prove causality: this setting → this observable effect.

Dual-Layer Verification (apply everywhere):
- Layer 1: External — validate the HTTP response, behavior, or output
- Layer 2: Internal — validate DB records, dashboard metrics, internal stats
  Example: If error ratio is set to 20%, send 10 requests → assert ~2 errors
  in the response stream AND confirm the error count in the DB/dashboard.

  >>> These are EXAMPLES of the approach. The team must apply this thinking
  >>> to every setting they discover in the codebase, including ones not
  >>> mentioned anywhere in this document.

--------------------------------------------------------------------------------

4. SCOPE: SERVER
--------------------------------------------------------------------------------
Build full atomic test coverage for ALL setting groups listed below.
For each group: test every setting, for every possible value, in isolation.

  Setting Groups (known — expect more from code analysis):
  ┌─────────────────────────────┐
  │ TRAFFIC RECORDING           │
  │ FEATURE TOGGLES             │
  │ ERROR CONFIGURATION         │
  │ CONTENT & PRESENTATION      │
  │ LABYRINTH                   │
  │ ADAPTIVE BEHAVIOR           │
  │ TRAPS & DETECTION           │
  │ SPIDER & CRAWL DATA         │
  │ VULNERABILITIES             │
  │ SESSIONS & CLIENTS          │
  └─────────────────────────────┘

  >>> This list is a STARTING POINT. The team must audit the full codebase
  >>> and product to identify ALL setting groups, ALL individual settings
  >>> within each group, and ALL possible values. If you find groups,
  >>> settings, or behaviors not listed here — they are in scope.

  Additional — CHAOS MODE:
  - Must be tested in full isolation as its own group
  - Validate all chaos behaviors independently

  Combination Tests:
  - All settings ON
  - All settings OFF
  - Common/realistic feature combinations (define matrix with Test Analyst)
  - Known conflict pairs or dependency chains
  - NOT full combinatorial explosion — focus on high-value combinations

  >>> If any server setting is hard to test or has no visible effect,
  >>> that is a product/code defect. Fix the application first.

--------------------------------------------------------------------------------

5. SCOPE: SCANNER
--------------------------------------------------------------------------------
Apply the identical atomic testing approach to all built-in scanner settings.

Requirements:
  - For every scanner setting, prove it influences real scanner behavior
  - Same isolation principle: one setting changed, everything else baseline
  - Same dual-layer verification: scanner output + internal state

  Additionally, cover ALL external scanner integrations:
  - Running / triggering scans
  - Reading scan data / results
  - Loading / importing scan data
  - Comparing scan results (diff, delta)
  - Any other scanner workflow or lifecycle event

  >>> The above are EXAMPLES of scanner workflows I'm aware of. The team
  >>> must map the complete scanner surface — every setting, every flow,
  >>> every integration — through code and product analysis. Expect to
  >>> find significantly more than what is listed here.

  The depth and rigor must match the Server scope. Detail every setting and
  every value — do not treat this as secondary.

  >>> If scanner behavior is not observable or settings don't apply
  >>> cleanly, refactor the scanner code to support it.

--------------------------------------------------------------------------------

6. SCOPE: PROXY
--------------------------------------------------------------------------------
The Proxy scope is the largest. It includes everything from the Server scope
(since proxy mirrors server behavior) PLUS all proxy-specific modes.

  Setup Note: Environment setup for proxy testing is non-trivial but achievable.
  Document setup procedures and automate where possible.

  Mirroring Mode:
  - Repeat all Server-scope tests through the proxy in mirror mode
  - Validate that mirrored behavior is identical to direct server behavior

  Additional Proxy Modes (known — expect more from code analysis):
  ┌──────────────┬───────────────────────────────────────────┐
  │ TRANSPARENT   │ Pass-through, no modification              │
  │ WAF           │ Web Application Firewall filtering         │
  │ CHAOS         │ Random latency, corruption, drops          │
  │ GATEWAY       │ API gateway with rate limiting             │
  │ NIGHTMARE     │ Maximum chaos, all glitches active         │
  └──────────────┴───────────────────────────────────────────┘

  For each mode:
  - Test mode ON vs OFF (prove the mode activates/deactivates cleanly)
  - Test all mode-specific settings and their values
  - Dual-layer verification on every assertion
  - Cross-mode transitions (switching between modes cleanly)

  >>> These modes are what I know about. The team must discover and cover
  >>> ALL proxy modes, sub-modes, and per-mode settings from the codebase.

  >>> Proxy likely needs the most architectural work to become fully
  >>> testable. Budget for it. The team must make it happen.

--------------------------------------------------------------------------------

7. EXPECTED SCALE
--------------------------------------------------------------------------------
  - Estimated: thousands to tens of thousands of individual test cases
  - Tests must be efficient and tagged/grouped for selective execution
  - Not all tests run on every commit — define execution tiers:
      • Tier 1 (Smoke): Core settings, runs on every build
      • Tier 2 (Regression): Full atomic suite, runs on release candidates
      • Tier 3 (Comprehensive): Combinations + cross-scope, runs on demand

  >>> The actual number of tests will be determined by the team's analysis,
  >>> not by this document. If analysis reveals 30,000 test cases are needed,
  >>> then 30,000 test cases must be written.

--------------------------------------------------------------------------------

8. TEAM & EXECUTION APPROACH
--------------------------------------------------------------------------------
  Spin up the full test team:

  Role               │ Responsibility
  ────────────────────┼──────────────────────────────────────────────────
  Test Architect      │ Design overall suite structure, isolation strategy,
                      │ framework selection. IDENTIFY and DRIVE architectural
                      │ changes needed in the application for testability.
  Test Manager        │ Plan, track, report. Own the master test plan and
                      │ execution schedule. Coordinate with dev.
  Test Analyst        │ DEEP ANALYSIS of codebase and product. Map every
                      │ setting group → settings → values. Discover what
                      │ this document doesn't cover. Define the combination
                      │ matrix. Write complete test specs.
  SDET                │ Implement all automated tests. Build fixtures,
                      │ helpers, and the dual-layer verification framework.
  Developers          │ Fix ALL issues found — both test failures AND
                      │ architectural/code changes needed for testability.
                      │ Available continuously for fixes and re-runs.

  Workflow:
  1. Test Analyst performs full codebase & product analysis
     → produces COMPLETE setting inventory (not limited to this doc)
  2. Test Architect designs framework and identifies required app changes
  3. Developers implement architectural changes for testability
  4. SDET implements tests scope by scope (Server → Scanner → Proxy)
  5. Tests run → failures triaged:
     - Test bug? → SDET fixes
     - App bug? → Developer fixes
     - Architecture blocker? → Developer refactors, SDET retests
     - New setting/behavior discovered? → Add to inventory, write tests
  6. Iterate until 100% pass on all scopes
  7. Test Manager produces final test plan + test report

  >>> The dev-fix-retest loop is continuous and non-negotiable.
  >>> Architectural improvements are PART OF this initiative, not separate.
  >>> Discovery of new test targets is ONGOING throughout the initiative.

  DO NOT STOP until every setting, every value, every scope is covered
  and passing.

--------------------------------------------------------------------------------

9. MAINTENANCE & CI RULES
--------------------------------------------------------------------------------
  Add to claude.md (or equivalent project rules):

  - When any setting is ADDED    → corresponding atomic tests MUST be added
  - When any setting is CHANGED  → corresponding tests MUST be updated
  - When any setting is REMOVED  → corresponding tests MUST be removed
  - Test suite must stay in sync with the codebase at all times
  - PR/MR reviews must verify test coverage for setting changes

  Follow best practices:
  - Descriptive test names indicating setting, value, and expected outcome
  - Shared fixtures for baseline state setup and teardown
  - Parallel-safe (no shared mutable state between tests)
  - Clear failure messages showing expected vs actual + system state snapshot
  - Tagging system for selective execution (by scope, group, tier)

--------------------------------------------------------------------------------

10. DELIVERABLES
--------------------------------------------------------------------------------
  ☐ Codebase & Product Analysis Report
      - Complete inventory of ALL settings, values, and behaviors
        discovered through code analysis (not just what this doc lists)
      - Gaps, undocumented features, and implicit behaviors identified
      - This is the FOUNDATION — everything else builds on it

  ☐ Comprehensive Test Plan
      - All scopes, all setting groups, all values mapped
      - Combination matrix defined
      - Execution tiers defined
      - Timeline and milestones

  ☐ Automated Test Suite
      - All atomic tests implemented and passing
      - Combination tests implemented and passing
      - Tagged and organized for selective runs

  ☐ Application Changes Log
      - Every architectural/code change made to support testability
      - Rationale, scope of change, and verification status

  ☐ Test Report
      - Full results: pass/fail per setting, per value, per scope
      - Coverage summary (settings covered / total settings)
      - Issues found and resolution status

  ☐ Individual Team Member Reports
      - Each role provides a summary of work done, decisions made,
        issues encountered, and recommendations

================================================================================
REMINDER: This document defines the APPROACH and EXPECTATIONS.
The team defines the ACTUAL SCOPE through deep analysis of the codebase
and product. Everything here is a reference. The real coverage will be
larger than what is written. Own it.
================================================================================
END OF REQUIREMENT
================================================================================