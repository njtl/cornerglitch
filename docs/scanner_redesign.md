# Scanner Tab Redesign -- Specification Document

**Author:** Technical Product Management
**Date:** 2026-02-23
**Status:** Ready for Implementation
**Scope:** Admin panel Scanner tab (`/admin` on dashboard port)

---

## 1. Problem Statement

The current Scanner tab conflates two fundamentally different features into a single undifferentiated UI:

**Feature A -- "Scanner Evaluation"**: Users run external security scanners (nuclei, nikto, nmap, ffuf, wapiti) against the Glitch Server, then paste or auto-collect the output. The system compares what the scanner found against what the server actually exposes, grades the scanner (A-F), and tracks performance over time. The audience is someone evaluating scanner quality.

**Feature B -- "Built-in Scanner" (glitch-scanner)**: The project ships its own scanner binary with 5 attack modules (OWASP, Injection, Fuzzing, Protocol, Auth), 4 scan profiles (compliance, aggressive, stealth, nightmare), and a full crawl engine. Users run it from the admin panel to test the Glitch Server itself, acting as a reference scanner. The audience is someone testing the server's defenses.

### Current UX failures

1. The "Run Scanner" buttons (nuclei, nikto, nmap, ffuf, wapiti) sit in the same visual block as the profile generator and the comparison upload. Users cannot distinguish between "run an external tool on the host" and "run the built-in glitch-scanner."
2. "Generate Profile" shows raw numbers (229 vulns, 844 endpoints) with no explanation of what to do next. It is a prerequisite for comparison but appears to be a standalone action.
3. There is no way to run the built-in glitch-scanner from the admin panel at all -- the "Run Scanner" buttons only trigger external tools.
4. The workflow from "generate profile" to "run scan" to "compare results" to "view history" requires the user to discover each step by trial and error.

---

## 2. Information Architecture

The Scanner tab will be split into two visually distinct sub-tabs (inner tabs within the Scanner panel), each with its own workflow, its own results area, and its own history.

```
Scanner Tab
  |
  +-- Sub-tab: "Evaluate External Scanners"
  |     |-- Server Vulnerability Profile (auto-loaded, always visible)
  |     |-- Run External Scanner (nuclei, nikto, etc.)
  |     |-- Upload Scanner Output (paste/file)
  |     |-- Comparison Report (grade, true positives, false negatives, etc.)
  |     |-- Multi-Scanner Comparison
  |     |-- Evaluation History
  |
  +-- Sub-tab: "Built-in Scanner (glitch-scanner)"
        |-- Profile Selection (compliance, aggressive, stealth, nightmare)
        |-- Module Selection (OWASP, Injection, Fuzzing, Protocol, Auth)
        |-- Target Configuration
        |-- Run Controls (start, stop, progress)
        |-- Scan Results (findings table, coverage, resilience)
        |-- Scan History
```

### Naming conventions

| Old label | New label | Rationale |
|-----------|-----------|-----------|
| "Scanner" (tab) | "Scanner" (tab, unchanged) | Umbrella term still works |
| "Generate Profile" | Removed as a button; profile loads automatically | Profile is a prerequisite, not a user action |
| "Run Scanner" (nuclei etc.) | "Launch External Scanner" | Clarifies these are host-installed tools, not the built-in scanner |
| N/A | "Run Glitch Scanner" | New: triggers the built-in scanner |
| "Upload & Compare" | "Upload & Grade" | Emphasizes the grading/evaluation output |
| "Scanner Results" (section) | "Comparison Report" (in evaluate tab) / "Scan Results" (in built-in tab) | Different contexts, different names |

---

## 3. UI Layout -- Sub-tab A: "Evaluate External Scanners"

### 3.1 Header & Context Banner

A persistent banner at the top of this sub-tab that contextualizes the entire workflow. It auto-loads the vulnerability profile on tab activation (no "Generate Profile" button needed).

```
+-----------------------------------------------------------------------+
|  EVALUATE EXTERNAL SCANNERS                                           |
|                                                                       |
|  Your server currently exposes [229] vulnerabilities across [844]     |
|  endpoints. Run an external scanner and see how many it can find.     |
|                                                                       |
|  [critical: 47]  [high: 82]  [medium: 63]  [low: 24]  [info: 13]   |
|                                                                       |
|  Workflow: 1. Run or paste scanner output  -->  2. Grade the scanner  |
|            --> 3. Compare across scanners  --> 4. Track over time     |
+-----------------------------------------------------------------------+
```

**Data source:** `GET /admin/api/scanner/profile` -- called automatically when the sub-tab becomes active. The profile data is cached in JS and refreshed every 60 seconds or when features/config change.

### 3.2 Section: "Run External Scanner"

Purpose: Launch a security scanner that is installed on the host machine. The scanner runs against the Glitch Server and its output is automatically collected and compared.

```
+-----------------------------------------------------------------------+
|  LAUNCH EXTERNAL SCANNER                                              |
|                                                                       |
|  These buttons launch real security tools installed on this host.     |
|  Output is automatically collected and graded against the server's    |
|  vulnerability profile.                                               |
|                                                                       |
|  +------------------+ +------------------+ +------------------+       |
|  | nuclei           | | nikto            | | nmap             |       |
|  | Template-based   | | Web server vuln  | | Network/port     |       |
|  | vuln scanner     | | scanner          | | scanner w/ NSE   |       |
|  | [Installed: v3.x]| | [Not installed]  | | [Installed: 7.x] |       |
|  | [Launch]         | | [Install guide]  | | [Launch]         |       |
|  +------------------+ +------------------+ +------------------+       |
|  +------------------+ +------------------+                            |
|  | ffuf             | | wapiti           |                            |
|  | Web fuzzer for   | | Web application  |                            |
|  | endpoint discov. | | vuln scanner     |                            |
|  | [Not installed]  | | [Not installed]  |                            |
|  | [Install guide]  | | [Install guide]  |                            |
|  +------------------+ +------------------+                            |
|                                                                       |
|  Running: nuclei  [===========>       ] 67%  (2m 14s)  [Stop]        |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- Each scanner is a card showing name, one-line description, installed status, and version.
- If not installed, the button says "Install guide" (links to tool docs) instead of a non-functional "Launch" button. The current UI shows buttons for all tools regardless of installation status.
- Running scanners show a progress indicator inline below the cards. Only one external scanner can run at a time per tool (existing backend constraint).
- The "Launch" button is labeled clearly as "Launch" (not just the scanner name) to distinguish it from a link.

**Data sources:**
- `GET /admin/api/scanner/profile` returns `available_scanners[]` with `installed`, `path`, `version` fields.
- `POST /admin/api/scanner/run` with `{scanner, target}` to start.
- `GET /admin/api/scanner/results` polled at 1.5s intervals while running.
- `POST /admin/api/scanner/stop` to abort.

### 3.3 Section: "Upload Scanner Output"

Purpose: Users who run scanners externally (not via the admin panel) can paste or upload the raw output for comparison.

```
+-----------------------------------------------------------------------+
|  UPLOAD SCANNER OUTPUT                                                |
|                                                                       |
|  Ran a scanner outside this panel? Paste the output below to grade   |
|  it against the server's vulnerability profile.                       |
|                                                                       |
|  Scanner: [nuclei  v]  Format: auto-detected from output             |
|                                                                       |
|  +---------------------------------------------------------------+   |
|  | Paste raw scanner output here (JSONL, XML, or text)...        |   |
|  |                                                                |   |
|  |                                                                |   |
|  +---------------------------------------------------------------+   |
|                                                                       |
|  [Upload & Grade]                   Or: [Choose File...]              |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- The scanner type dropdown remains (nuclei, nikto, nmap, ffuf, wapiti, generic) because the parser needs to know the format.
- Added file upload as an alternative to pasting (many scanner outputs are large).
- The button says "Upload & Grade" not "Upload & Compare" to emphasize the grading action.
- "Format: auto-detected from output" tells users they don't need to worry about format details.

**Data source:** `POST /admin/api/scanner/compare` with `{scanner, data}`.

### 3.4 Section: "Comparison Report"

Purpose: Show the grading results after a scan completes or output is uploaded.

```
+-----------------------------------------------------------------------+
|  COMPARISON REPORT                                                    |
|                                                                       |
|  +----------+  +----------------+  +------------------+               |
|  | GRADE    |  | DETECTION RATE |  | FALSE POSITIVE   |               |
|  |   B+     |  |    67.2%       |  | RATE: 4.1%       |               |
|  |          |  |  154 / 229     |  |  7 false alarms   |               |
|  +----------+  +----------------+  +------------------+               |
|                                                                       |
|  +------------------+  +------------------+  +------------------+     |
|  | TRUE POSITIVES   |  | FALSE NEGATIVES  |  | ACCURACY         |     |
|  |    154           |  |    75            |  |   91.3%          |     |
|  +------------------+  +------------------+  +------------------+     |
|                                                                       |
|  Scanner Health:  [Crashed: No]  [Timed Out: No]  [Errors: 2]        |
|                                                                       |
|  TRUE POSITIVES (154)                      [Expand/Collapse]          |
|  +-------------------------------------------------------------------+|
|  | Vulnerability          | Severity | CWE      | Scanner Finding    ||
|  |------------------------+----------+----------+--------------------||
|  | SQL Injection (search) | critical | CWE-89   | sqli-error-based   ||
|  | XSS Reflected          | high     | CWE-79   | xss-reflected      ||
|  | ...                    |          |          |                     ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  FALSE NEGATIVES (75) -- Vulns the scanner missed   [Expand/Collapse]|
|  +-------------------------------------------------------------------+|
|  | Vulnerability          | Severity | CWE      | Endpoints          ||
|  |------------------------+----------+----------+--------------------||
|  | SSRF via redirect      | high     | CWE-918  | /vuln/a10/fetch    ||
|  | ...                    |          |          |                     ||
|  +-------------------------------------------------------------------+|
|                                                                       |
|  FALSE POSITIVES (7) -- Scanner reported but not real                 |
|  +-------------------------------------------------------------------+|
|  | Finding                | Severity | URL                            ||
|  +-------------------------------------------------------------------+|
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- The grade letter is displayed large and prominently (existing behavior, preserved).
- Detection rate shows both percentage and fraction ("154 / 229") so users understand the denominator.
- True positives, false negatives, and false positives are collapsible tables. Currently they are rendered in a flat block that gets unreadable with many entries.
- False negatives are explicitly labeled "Vulns the scanner missed" to make the meaning clear without security jargon.
- False positives are labeled "Scanner reported but not real."

**Data source:** The `ComparisonReport` struct from `scaneval/profile.go` lines 73-94. Rendered from either `POST /admin/api/scanner/compare` response or from completed `ScanRun.Comparison` in poll results.

### 3.5 Section: "Multi-Scanner Comparison"

Purpose: Compare results across multiple scanners side by side.

```
+-----------------------------------------------------------------------+
|  MULTI-SCANNER COMPARISON                                             |
|                                                                       |
|  Compare how different scanners perform against the same server       |
|  profile. Upload output from multiple scanners to see which finds     |
|  what.                                                                |
|                                                                       |
|  Add Scanner Results:                                                 |
|  Scanner: [nuclei v]  [Paste output or choose file]  [Add to compare]|
|                                                                       |
|  Scanners loaded: nuclei, nikto, nmap   [Run Comparison]              |
|                                                                       |
|  RESULTS:                                                             |
|  +---------+------------+----------+-----------+-----------+          |
|  | Scanner | Grade      | Detected | FP Rate   | Unique    |          |
|  |---------+------------+----------+-----------+-----------+          |
|  | nuclei  | B+ (67.2%) | 154/229  | 4.1%      | 23        |          |
|  | nikto   | C  (41.0%) |  94/229  | 12.3%     | 8         |          |
|  | nmap    | D  (18.3%) |  42/229  | 1.2%      | 5         |          |
|  +---------+------------+----------+-----------+-----------+          |
|                                                                       |
|  Coverage Matrix (which vulns each scanner found):                    |
|  +----------------------------+--------+-------+------+               |
|  | Vulnerability              | nuclei | nikto | nmap |               |
|  +----------------------------+--------+-------+------+               |
|  | SQL Injection              |   X    |   X   |      |               |
|  | XSS Reflected              |   X    |   X   |      |               |
|  | Open Redirect              |   X    |       |      |               |
|  | Missing HSTS               |   X    |   X   |   X  |               |
|  +----------------------------+--------+-------+------+               |
|                                                                       |
|  Consensus: 31 vulns found by ALL scanners                            |
|  Recommendation: "Low consensus: only 22% overlap. Each scanner       |
|  finds different issues; use all for comprehensive coverage."         |
+-----------------------------------------------------------------------+
```

**Data source:** `POST /admin/api/scanner/multi-compare` with `{reports: {scanner_name: raw_output}}`.

### 3.6 Section: "Evaluation History"

Purpose: Track scanner grades over time to see if scanners improve or regress.

```
+-----------------------------------------------------------------------+
|  EVALUATION HISTORY                                                   |
|                                                                       |
|  Filter: [All scanners v]                                             |
|                                                                       |
|  +--------------------------------------------------------------------+
|  | Timestamp           | Scanner | Grade | Detection | FP Rate | Vulns|
|  |---------------------+---------+-------+-----------+---------+------|
|  | 2026-02-23 14:32:01 | nuclei  | B+    | 67.2%     | 4.1%    |154/ |
|  |                     |         |       |           |         |229  |
|  | 2026-02-23 14:28:15 | nikto   | C     | 41.0%     | 12.3%   | 94/ |
|  |                     |         |       |           |         |229  |
|  | 2026-02-23 13:55:42 | nuclei  | B     | 62.0%     | 5.2%    |142/ |
|  |                     |         |       |           |         |229  |
|  +--------------------------------------------------------------------+
|                                                                       |
|  Baseline (best result per scanner):                                  |
|  nuclei: B+ (67.2%)  |  nikto: C (41.0%)  |  nmap: D (18.3%)        |
+-----------------------------------------------------------------------+
```

**Data sources:**
- `GET /admin/api/scanner/history` (all entries or filtered by `?scanner=nuclei`)
- `GET /admin/api/scanner/baseline?scanner=nuclei` (best historical result)

---

## 4. UI Layout -- Sub-tab B: "Built-in Scanner (glitch-scanner)"

### 4.1 Header & Context Banner

```
+-----------------------------------------------------------------------+
|  GLITCH SCANNER                                                       |
|                                                                       |
|  The built-in security scanner tests this server's defenses using     |
|  5 attack modules and 4 scan profiles. It generates adversarial       |
|  HTTP traffic designed to find vulnerabilities AND stress-test the     |
|  server.                                                              |
|                                                                       |
|  Target: http://localhost:8765   [Change]                             |
+-----------------------------------------------------------------------+
```

### 4.2 Section: "Scan Profile"

Purpose: Select a scan profile that determines concurrency, rate limiting, evasion, and module configuration.

```
+-----------------------------------------------------------------------+
|  SCAN PROFILE                                                         |
|                                                                       |
|  Select a profile to control scan intensity and behavior.             |
|                                                                       |
|  +-------------------+ +-------------------+                          |
|  | (*) COMPLIANCE    | | ( ) AGGRESSIVE    |                          |
|  | Polite, standards | | Full coverage,    |                          |
|  | compliant. Low    | | high concurrency  |                          |
|  | concurrency, no   | | (50 workers), all |                          |
|  | evasion. Safe for | | modules, no       |                          |
|  | production.       | | stealth. For      |                          |
|  |                   | | maximum speed.    |                          |
|  | Workers: 2        | | Workers: 50       |                          |
|  | Rate: 10 req/s    | | Rate: 500 req/s   |                          |
|  | Evasion: none     | | Evasion: none     |                          |
|  +-------------------+ +-------------------+                          |
|  +-------------------+ +-------------------+                          |
|  | ( ) STEALTH       | | ( ) NIGHTMARE     |                          |
|  | Low-and-slow with | | Maximum intensity |                          |
|  | browser spoofing  | | with protocol     |                          |
|  | and advanced      | | abuse. 100 workers|                          |
|  | evasion. Single   | | no rate limit.    |                          |
|  | threaded, random  | | WARNING: May crash|                          |
|  | delays.           | | the target.       |                          |
|  |                   | |                   |                          |
|  | Workers: 1        | | Workers: 100      |                          |
|  | Rate: 2 req/s     | | Rate: unlimited   |                          |
|  | Evasion: advanced | | Evasion: nightmare|                          |
|  +-------------------+ +-------------------+                          |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- Radio-button cards (one selected at a time) with full descriptions visible, not hidden behind tooltips.
- Each card shows the three most important parameters: workers, rate, evasion mode.
- Nightmare has a visible warning styled in red/orange.

### 4.3 Section: "Attack Modules"

Purpose: Select which attack modules to enable for the scan.

```
+-----------------------------------------------------------------------+
|  ATTACK MODULES                                                       |
|                                                                       |
|  Choose which modules to run. Each module generates targeted HTTP     |
|  requests testing different vulnerability categories.                 |
|                                                                       |
|  [x] owasp         OWASP Top 10 web vulnerabilities   (~180 reqs)    |
|  [x] injection      SQLi, XSS, SSRF, SSTI, cmd-inj   (~320 reqs)    |
|  [x] fuzzing        Parameter, header, path fuzzing    (~250 reqs)    |
|  [x] protocol       Malformed HTTP, smuggling, bombs   (~90 reqs)    |
|  [x] auth           Brute force, token manipulation    (~60 reqs)    |
|                                                                       |
|  Total: ~900 requests estimated                                       |
|                                                                       |
|  [Select All] [Deselect All]                                          |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- Checkboxes, not toggles, because this is a selection list (not on/off states).
- Request count estimates help users understand scan duration.
- "Select All" / "Deselect All" convenience buttons.

**Data source:** The module list comes from the `attacks.ListModules()` registry. In the current implementation, the admin panel would need a new API endpoint (`GET /admin/api/scanner/modules`) or the module list could be embedded in the profile endpoint response. For the initial implementation, the 5 modules can be hardcoded in the HTML since they are stable.

### 4.4 Section: "Run Controls"

Purpose: Start and monitor the built-in scanner.

```
+-----------------------------------------------------------------------+
|  RUN SCANNER                                                          |
|                                                                       |
|  Profile: aggressive  |  Modules: 5/5  |  Target: localhost:8765     |
|                                                                       |
|  [Run Glitch Scanner]                                                 |
|                                                                       |
|  --- (while running) ---                                              |
|                                                                       |
|  Status: RUNNING  [===========================>          ] 73%        |
|  Requests: 657 / 900  |  Findings: 42  |  Errors: 3  |  2m 34s      |
|                                                                       |
|  [Stop Scan]                                                          |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- The "Run Glitch Scanner" button is visually distinct (larger, different color -- cyan/teal rather than the green used for external scanner launch buttons) so users can clearly see this is a different action than launching nuclei.
- Summary line above the button confirms what will happen: profile, module count, target.
- Progress shows requests completed, findings count, error count, and elapsed time.

**Backend requirement:** This requires a new API endpoint to run the built-in glitch-scanner. Currently, only external scanners are supported by `scaneval.Runner`. The new endpoint would be `POST /admin/api/scanner/builtin/run` with `{profile, modules[], target}`. Implementation options:
1. Shell out to the `glitch-scanner` binary (if built).
2. Import the scanner engine directly (the `internal/scanner` package) and run it in-process.

Option 2 is preferred since everything is in the same Go module. The API would create a `scanner.Engine`, register selected modules, and run it in a goroutine with context cancellation.

New API endpoints needed:
- `POST /admin/api/scanner/builtin/run` -- start built-in scan
- `GET /admin/api/scanner/builtin/status` -- poll progress
- `POST /admin/api/scanner/builtin/stop` -- cancel running scan
- `GET /admin/api/scanner/builtin/results` -- get completed scan results

### 4.5 Section: "Scan Results"

Purpose: Display findings from the built-in scanner after a scan completes.

```
+-----------------------------------------------------------------------+
|  SCAN RESULTS                                                         |
|                                                                       |
|  Profile: aggressive  |  Duration: 47s  |  Requests: 900             |
|                                                                       |
|  +------------+  +-----------+  +-----------+  +-----------+          |
|  | FINDINGS   |  | CRITICAL  |  | HIGH      |  | MEDIUM    |          |
|  |    42      |  |    8      |  |    17     |  |    12     |          |
|  +------------+  +-----------+  +-----------+  +-----------+          |
|                                                                       |
|  +-----------+  +-----------+  +-----------+                          |
|  | LOW       |  | INFO      |  | ERRORS    |                          |
|  |    3      |  |    2      |  |    3      |                          |
|  +-----------+  +-----------+  +-----------+                          |
|                                                                       |
|  COVERAGE BY CATEGORY                                                 |
|  +----------------------------------+---------+----------+----------+ |
|  | Category                         | Tested  | Detected | Coverage | |
|  |----------------------------------+---------+----------+----------| |
|  | OWASP A01 - Broken Access        |   24    |    18    |  75.0%   | |
|  | OWASP A03 - Injection            |   48    |    42    |  87.5%   | |
|  | OWASP A07 - Auth Failures        |   16    |    12    |  75.0%   | |
|  | Protocol Abuse                   |   30    |    22    |  73.3%   | |
|  +----------------------------------+---------+----------+----------+ |
|                                                                       |
|  OVERALL COVERAGE: 78.4%   |   RESILIENCE: 96.7%                     |
|                                                                       |
|  FINDINGS TABLE                                     [Filter: ____]   |
|  +------------------------------------------------------------------+|
|  | Severity | Category      | URL               | Description        ||
|  |----------+---------------+-------------------+--------------------||
|  | CRITICAL | sqli          | /vuln/a03/search  | SQL error in resp  ||
|  | HIGH     | xss           | /vuln/a03/comment | Reflected XSS      ||
|  | ...      |               |                   |                    ||
|  +------------------------------------------------------------------+|
|                                                                       |
|  [Export JSON]  [Export HTML]                                          |
+-----------------------------------------------------------------------+
```

**Key design decisions:**
- Coverage by category table shows tested/detected/percentage per OWASP category, matching the built-in scanner's `Report.Coverage` map.
- Resilience metric is prominently displayed (this is unique to the built-in scanner -- it measures how well the scanner handled the server's intentional errors).
- Findings table is filterable by severity or keyword.
- Export buttons produce the same JSON/HTML reports as the CLI tool.

**Data source:** The `scanner.Report` struct with `Summary`, `Coverage`, `Findings`, `Errors` fields.

### 4.6 Section: "Scan History"

Purpose: Track built-in scanner runs over time.

```
+-----------------------------------------------------------------------+
|  SCAN HISTORY                                                         |
|                                                                       |
|  +--------------------------------------------------------------------+
|  | Timestamp           | Profile    | Findings | Coverage | Resil.   |
|  |---------------------+------------+----------+----------+----------|
|  | 2026-02-23 14:32:01 | aggressive |    42    |  78.4%   |  96.7%  |
|  | 2026-02-23 14:15:33 | stealth    |    28    |  52.1%   |  99.2%  |
|  | 2026-02-23 13:50:10 | compliance |    12    |  24.3%   | 100.0%  |
|  +--------------------------------------------------------------------+
+-----------------------------------------------------------------------+
```

---

## 5. Workflow Descriptions

### 5.1 Workflow: "Grade an external scanner"

**Goal:** Determine how effective an external security scanner is at finding the vulnerabilities this server exposes.

| Step | User action | System response |
|------|-------------|-----------------|
| 1 | Click "Evaluate External Scanners" sub-tab | Profile auto-loads. Banner shows "229 vulnerabilities across 844 endpoints" |
| 2a | Click "Launch" on an installed scanner card | Scanner starts. Progress bar appears. Output auto-collected on completion |
| 2b | (Alternative) Paste raw scanner output into the Upload section | Text appears in textarea |
| 3 | (If 2b) Select scanner type from dropdown, click "Upload & Grade" | System parses output, matches against profile |
| 4 | View Comparison Report | Grade card (e.g., "B+"), detection rate, true/false positive breakdown |
| 5 | (Optional) Repeat steps 2-4 with different scanners | Each result added to history |
| 6 | (Optional) Load results into Multi-Scanner Comparison | Side-by-side table, coverage matrix, consensus analysis |
| 7 | Review Evaluation History | Trend of grades over time, baseline per scanner |

### 5.2 Workflow: "Test server defenses with the built-in scanner"

**Goal:** Run the built-in glitch-scanner against the server to test how well it handles adversarial traffic and measure vulnerability coverage.

| Step | User action | System response |
|------|-------------|-----------------|
| 1 | Click "Built-in Scanner" sub-tab | Profile selection cards displayed |
| 2 | Select a scan profile (e.g., "aggressive") | Card highlights, parameters shown |
| 3 | (Optional) Toggle attack modules on/off | Request estimate updates |
| 4 | (Optional) Change target URL | Target field updates |
| 5 | Click "Run Glitch Scanner" | Scan starts. Progress bar with requests/findings/errors/elapsed |
| 6 | Wait for completion (or click "Stop Scan") | Results section populates |
| 7 | Review findings, coverage by category, resilience score | Tables and metrics displayed |
| 8 | (Optional) Export results as JSON or HTML | File download |
| 9 | (Optional) Compare across profiles by running compliance, then aggressive, then nightmare | History table shows all runs |

### 5.3 Workflow: "Multi-scanner comparison"

**Goal:** Compare how multiple external scanners perform against the same server configuration.

| Step | User action | System response |
|------|-------------|-----------------|
| 1 | Navigate to Multi-Scanner Comparison section | Empty comparison panel |
| 2 | Select scanner from dropdown, paste output, click "Add to compare" | Scanner added to loaded list |
| 3 | Repeat step 2 for each scanner | "Scanners loaded: nuclei, nikto, nmap" |
| 4 | Click "Run Comparison" | System parses all outputs, builds coverage matrix |
| 5 | Review comparison table (grade, detection, FP rate, unique finds per scanner) | Table and matrix displayed |
| 6 | Review coverage matrix (which vulns each scanner found) | Checkmark grid |
| 7 | Read recommendation | "Low consensus: only 22% overlap. Use all scanners for comprehensive coverage." |

---

## 6. Section Descriptions (Copy)

These are the exact text strings to display in the UI for each section. They are written to be understood by a user who has never seen the admin panel before.

### Sub-tab A: "Evaluate External Scanners"

**Tab label:** `Evaluate External Scanners`

**Banner text:**
> Your server currently exposes **{total_vulns}** vulnerabilities across **{total_endpoints}** endpoints. Run an external security scanner and see how many it can find. The system will grade the scanner from A to F based on detection rate, false positive rate, and accuracy.

**"Launch External Scanner" section header description:**
> Launch a security scanner installed on this host. The scanner will run against the Glitch Server and its output will be automatically collected and compared against the known vulnerability profile. Only scanners detected on this machine are launchable.

**"Upload Scanner Output" section header description:**
> Already ran a scanner outside this panel? Select the scanner type, paste the raw output (JSONL, XML, or text), and click "Upload & Grade" to see how it performed.

**"Comparison Report" section header description:**
> This report compares what the scanner found against what the server actually exposes. True positives are real vulnerabilities the scanner correctly identified. False negatives are vulnerabilities the scanner missed. False positives are things the scanner flagged that are not real vulnerabilities.

**"Multi-Scanner Comparison" section header description:**
> Compare multiple scanners side by side. Add output from each scanner, then run the comparison to see a coverage matrix showing which vulnerabilities each scanner found, which were found by all scanners (consensus), and which were uniquely found by only one scanner.

**"Evaluation History" section header description:**
> Every time you grade a scanner, the result is recorded here. Use this to track whether scanner updates improve detection, or to establish a baseline for each tool.

### Sub-tab B: "Built-in Scanner (glitch-scanner)"

**Tab label:** `Built-in Scanner`

**Banner text:**
> The Glitch Scanner is this project's own security testing tool. It sends adversarial HTTP traffic using 5 attack modules to test the server's defenses. Unlike external scanners (evaluated in the other tab), this scanner is designed specifically for the Glitch Server and measures both vulnerability coverage and server resilience.

**"Scan Profile" section header description:**
> Each profile controls how aggressively the scanner operates. Compliance mode is gentle and production-safe. Aggressive mode maximizes coverage. Stealth mode tests whether the server's bot detection can catch a careful scanner. Nightmare mode is designed to crash the target.

**"Attack Modules" section header description:**
> Each module generates HTTP requests targeting a specific category of vulnerabilities. Disable modules you do not want to test. The request count estimate helps predict scan duration.

**"Run Scanner" section header description:**
> Review the configuration summary, then click "Run Glitch Scanner" to start. The scan runs in the background -- you can navigate to other tabs and return to check progress.

**"Scan Results" section header description:**
> Results show every vulnerability found, organized by severity and OWASP category. Coverage measures what percentage of known endpoints were tested. Resilience measures how well the scanner handled the server's intentional errors (connection resets, corrupt headers, infinite responses, etc.).

---

## 7. HTML Structure

### 7.1 Sub-tab Navigation (replaces current Scanner panel content)

```html
<!-- Scanner tab inner navigation -->
<div id="panel-scanner" class="panel">
  <div class="scanner-subtabs">
    <button class="scanner-subtab active" onclick="showScannerSubtab('evaluate')">
      Evaluate External Scanners
    </button>
    <button class="scanner-subtab" onclick="showScannerSubtab('builtin')">
      Built-in Scanner
    </button>
  </div>

  <!-- Sub-tab A: Evaluate External Scanners -->
  <div id="scanner-sub-evaluate" class="scanner-subpanel active">
    <!-- content below -->
  </div>

  <!-- Sub-tab B: Built-in Scanner -->
  <div id="scanner-sub-builtin" class="scanner-subpanel" style="display:none">
    <!-- content below -->
  </div>
</div>
```

### 7.2 Sub-tab A: Evaluate External Scanners

```html
<div id="scanner-sub-evaluate" class="scanner-subpanel active">

  <!-- Context Banner -->
  <div class="section" id="eval-profile-banner">
    <div style="display:flex; justify-content:space-between; align-items:center">
      <h2>// Evaluate External Scanners</h2>
      <button class="scanner-btn" onclick="refreshEvalProfile()" style="font-size:0.75em; padding:4px 12px">
        Refresh Profile
      </button>
    </div>
    <p class="section-desc" id="eval-banner-text">
      Loading vulnerability profile...
    </p>
    <div class="grid" id="eval-profile-cards">
      <!-- Populated by JS: total vulns, total endpoints, severity breakdown -->
    </div>
    <div id="eval-severity-badges" style="margin-top:8px">
      <!-- Populated by JS: severity count badges -->
    </div>
    <div class="workflow-hint">
      Workflow: 1. Run or paste scanner output &rarr; 2. Grade the scanner
      &rarr; 3. Compare across scanners &rarr; 4. Track over time
    </div>
  </div>

  <!-- Launch External Scanner -->
  <div class="section">
    <h2>// Launch External Scanner</h2>
    <p class="section-desc">
      Launch a security scanner installed on this host. Output is automatically
      collected and graded against the server's vulnerability profile.
    </p>
    <div class="grid" id="external-scanner-cards">
      <!-- Populated by JS: one card per scanner from available_scanners -->
      <!--
        Each card structure:
        <div class="card scanner-tool-card">
          <div class="label">{name}</div>
          <div style="color:#888; font-size:0.78em; margin:4px 0">{description}</div>
          <div class="scanner-install-status">
            <span class="v-ok">Installed v{version}</span>
            OR
            <span class="v-warn">Not installed</span>
          </div>
          <button class="scanner-btn" onclick="launchExternal('{name}')">Launch</button>
          OR
          <a href="{install_url}" target="_blank" class="scanner-btn" style="...">Install Guide</a>
        </div>
      -->
    </div>
    <div id="external-scanner-progress" style="margin-top:12px">
      <!-- Running scanner status bar -->
    </div>
  </div>

  <!-- Upload Scanner Output -->
  <div class="section">
    <h2>// Upload Scanner Output</h2>
    <p class="section-desc">
      Already ran a scanner externally? Select the scanner type, paste the raw
      output, and click "Upload &amp; Grade" to see how it performed.
    </p>
    <div class="scanner-panel">
      <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap">
        <label style="color:#888; font-size:0.82em">Scanner:</label>
        <select id="eval-scanner-type" class="scanner-select">
          <option value="nuclei">Nuclei</option>
          <option value="nikto">Nikto</option>
          <option value="nmap">Nmap</option>
          <option value="ffuf">ffuf</option>
          <option value="wapiti">Wapiti</option>
          <option value="generic">Generic / Other</option>
        </select>
      </div>
      <textarea id="eval-scanner-output" class="scanner-textarea"
        placeholder="Paste raw scanner output here (JSONL, XML, or text)..."></textarea>
      <div style="display:flex; gap:12px; align-items:center">
        <button class="scanner-btn" onclick="uploadAndGrade()">Upload &amp; Grade</button>
        <label class="scanner-btn" style="cursor:pointer">
          Choose File...
          <input type="file" style="display:none" onchange="loadFileToTextarea(this, 'eval-scanner-output')">
        </label>
      </div>
    </div>
  </div>

  <!-- Comparison Report -->
  <div class="section">
    <h2>// Comparison Report</h2>
    <p class="section-desc">
      Grade breakdown comparing scanner findings against known server vulnerabilities.
    </p>
    <div id="eval-comparison-report">
      <div style="color:#555">
        No comparison data yet. Launch a scanner or upload results above.
      </div>
    </div>
  </div>

  <!-- Multi-Scanner Comparison -->
  <div class="section">
    <h2>// Multi-Scanner Comparison</h2>
    <p class="section-desc">
      Compare multiple scanners side by side. Add output from each scanner,
      then run the comparison to see a coverage matrix.
    </p>
    <div class="scanner-panel">
      <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:8px">
        <label style="color:#888; font-size:0.82em">Scanner:</label>
        <select id="multi-scanner-type" class="scanner-select">
          <option value="nuclei">Nuclei</option>
          <option value="nikto">Nikto</option>
          <option value="nmap">Nmap</option>
          <option value="ffuf">ffuf</option>
          <option value="wapiti">Wapiti</option>
          <option value="generic">Generic</option>
        </select>
        <textarea id="multi-scanner-output" class="scanner-textarea"
          style="min-height:60px"
          placeholder="Paste output for this scanner..."></textarea>
        <button class="scanner-btn" onclick="addToMultiCompare()">Add to Compare</button>
      </div>
      <div id="multi-compare-loaded" style="color:#888; font-size:0.82em; margin:8px 0">
        No scanners loaded yet.
      </div>
      <button class="scanner-btn" onclick="runMultiCompare()" id="btn-run-multi" disabled>
        Run Comparison
      </button>
    </div>
    <div id="multi-compare-results" style="margin-top:12px">
      <!-- Populated by JS: comparison table, coverage matrix, recommendation -->
    </div>
  </div>

  <!-- Evaluation History -->
  <div class="section">
    <h2>// Evaluation History</h2>
    <p class="section-desc">
      Every scanner grading is recorded here. Track improvements over time
      and establish baselines per scanner.
    </p>
    <div style="margin-bottom:8px">
      <label style="color:#888; font-size:0.82em">Filter:</label>
      <select id="eval-history-filter" class="scanner-select" onchange="filterEvalHistory()">
        <option value="">All scanners</option>
        <option value="nuclei">Nuclei</option>
        <option value="nikto">Nikto</option>
        <option value="nmap">Nmap</option>
        <option value="ffuf">ffuf</option>
        <option value="wapiti">Wapiti</option>
      </select>
    </div>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Scanner</th>
            <th>Grade</th>
            <th>Detection</th>
            <th>FP Rate</th>
            <th>Vulns</th>
          </tr>
        </thead>
        <tbody id="eval-history-body"></tbody>
      </table>
    </div>
    <div id="eval-baseline-summary" style="margin-top:8px; color:#888; font-size:0.82em">
      <!-- Populated by JS: baseline per scanner -->
    </div>
  </div>
</div>
```

### 7.3 Sub-tab B: Built-in Scanner

```html
<div id="scanner-sub-builtin" class="scanner-subpanel" style="display:none">

  <!-- Context Banner -->
  <div class="section">
    <h2>// Glitch Scanner</h2>
    <p class="section-desc">
      The built-in security scanner tests this server's defenses using 5 attack
      modules and 4 scan profiles. It generates adversarial HTTP traffic designed
      to find vulnerabilities AND stress-test the server.
    </p>
    <div style="margin-top:8px">
      <label style="color:#888; font-size:0.82em">Target:</label>
      <input type="text" id="builtin-target" class="scanner-select"
        value="http://localhost:8765"
        style="width:300px; margin-left:8px">
    </div>
  </div>

  <!-- Scan Profile Selection -->
  <div class="section">
    <h2>// Scan Profile</h2>
    <p class="section-desc">
      Each profile controls how aggressively the scanner operates. Select one.
    </p>
    <div class="grid" id="builtin-profile-cards">
      <!-- Four profile radio cards -->
      <label class="card" style="cursor:pointer; border-color:#00ff8844">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span class="label">COMPLIANCE</span>
          <input type="radio" name="builtin-profile" value="compliance"
            style="accent-color:#00ff88">
        </div>
        <div style="color:#888; font-size:0.78em; margin:6px 0">
          Polite, standards-compliant. Low concurrency, no evasion.
          Safe for production environments.
        </div>
        <div style="font-size:0.75em; color:#555">
          Workers: 2 &nbsp;|&nbsp; Rate: 10 req/s &nbsp;|&nbsp; Evasion: none
        </div>
      </label>

      <label class="card" style="cursor:pointer; border-color:#00ff8844">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span class="label">AGGRESSIVE</span>
          <input type="radio" name="builtin-profile" value="aggressive"
            checked style="accent-color:#00ff88">
        </div>
        <div style="color:#888; font-size:0.78em; margin:6px 0">
          Full coverage, high concurrency (50 workers), all modules enabled.
          Prioritizes speed and thoroughness over stealth.
        </div>
        <div style="font-size:0.75em; color:#555">
          Workers: 50 &nbsp;|&nbsp; Rate: 500 req/s &nbsp;|&nbsp; Evasion: none
        </div>
      </label>

      <label class="card" style="cursor:pointer; border-color:#00ff8844">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span class="label">STEALTH</span>
          <input type="radio" name="builtin-profile" value="stealth"
            style="accent-color:#00ff88">
        </div>
        <div style="color:#888; font-size:0.78em; margin:6px 0">
          Low-and-slow with browser fingerprint spoofing and advanced evasion.
          Tests whether bot detection can catch a careful scanner.
        </div>
        <div style="font-size:0.75em; color:#555">
          Workers: 1 &nbsp;|&nbsp; Rate: 2 req/s &nbsp;|&nbsp; Evasion: advanced
        </div>
      </label>

      <label class="card" style="cursor:pointer; border-color:#00ff8844">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span class="label" style="color:#ff4444">NIGHTMARE</span>
          <input type="radio" name="builtin-profile" value="nightmare"
            style="accent-color:#ff4444">
        </div>
        <div style="color:#ff8844; font-size:0.78em; margin:6px 0">
          Maximum intensity with protocol abuse. 100 workers, no rate limit.
          WARNING: Designed to crash the target server.
        </div>
        <div style="font-size:0.75em; color:#555">
          Workers: 100 &nbsp;|&nbsp; Rate: unlimited &nbsp;|&nbsp; Evasion: nightmare
        </div>
      </label>
    </div>
  </div>

  <!-- Attack Module Selection -->
  <div class="section">
    <h2>// Attack Modules</h2>
    <p class="section-desc">
      Each module generates HTTP requests targeting a specific vulnerability
      category. Disable modules you do not want to test.
    </p>
    <div id="builtin-module-list">
      <div class="toggle-row">
        <div>
          <div class="toggle-name">owasp</div>
          <div style="color:#555; font-size:0.72em; margin-top:2px">
            OWASP Top 10 web vulnerabilities (~180 requests)
          </div>
        </div>
        <input type="checkbox" class="builtin-module-cb" value="owasp" checked
          style="accent-color:#00ff88">
      </div>
      <div class="toggle-row">
        <div>
          <div class="toggle-name">injection</div>
          <div style="color:#555; font-size:0.72em; margin-top:2px">
            SQLi, XSS, SSRF, SSTI, command injection (~320 requests)
          </div>
        </div>
        <input type="checkbox" class="builtin-module-cb" value="injection" checked
          style="accent-color:#00ff88">
      </div>
      <div class="toggle-row">
        <div>
          <div class="toggle-name">fuzzing</div>
          <div style="color:#555; font-size:0.72em; margin-top:2px">
            Parameter, header, path, method fuzzing (~250 requests)
          </div>
        </div>
        <input type="checkbox" class="builtin-module-cb" value="fuzzing" checked
          style="accent-color:#00ff88">
      </div>
      <div class="toggle-row">
        <div>
          <div class="toggle-name">protocol</div>
          <div style="color:#555; font-size:0.72em; margin-top:2px">
            Malformed HTTP, request smuggling, header bombs (~90 requests)
          </div>
        </div>
        <input type="checkbox" class="builtin-module-cb" value="protocol" checked
          style="accent-color:#00ff88">
      </div>
      <div class="toggle-row">
        <div>
          <div class="toggle-name">auth</div>
          <div style="color:#555; font-size:0.72em; margin-top:2px">
            Brute force, token manipulation, session fixation (~60 requests)
          </div>
        </div>
        <input type="checkbox" class="builtin-module-cb" value="auth" checked
          style="accent-color:#00ff88">
      </div>
    </div>
    <div style="margin-top:8px; display:flex; gap:8px; align-items:center">
      <button class="scanner-btn" style="font-size:0.75em; padding:4px 12px"
        onclick="document.querySelectorAll('.builtin-module-cb').forEach(c=>c.checked=true); updateModuleCount()">
        Select All
      </button>
      <button class="scanner-btn" style="font-size:0.75em; padding:4px 12px"
        onclick="document.querySelectorAll('.builtin-module-cb').forEach(c=>c.checked=false); updateModuleCount()">
        Deselect All
      </button>
      <span id="builtin-module-count" style="color:#888; font-size:0.82em">
        5/5 modules selected (~900 requests)
      </span>
    </div>
  </div>

  <!-- Run Controls -->
  <div class="section">
    <h2>// Run Scanner</h2>
    <div id="builtin-run-summary" style="color:#888; font-size:0.82em; margin-bottom:8px">
      Profile: <span id="builtin-summary-profile">aggressive</span> &nbsp;|&nbsp;
      Modules: <span id="builtin-summary-modules">5/5</span> &nbsp;|&nbsp;
      Target: <span id="builtin-summary-target">localhost:8765</span>
    </div>
    <button class="scanner-btn" id="btn-run-builtin"
      onclick="runBuiltinScanner()"
      style="background:#00aacc; padding:10px 28px; font-size:0.95em">
      Run Glitch Scanner
    </button>
    <div id="builtin-run-progress" style="margin-top:12px; display:none">
      <!-- Populated by JS during scan:
        Status, progress bar, requests/findings/errors/elapsed, Stop button
      -->
    </div>
  </div>

  <!-- Scan Results -->
  <div class="section">
    <h2>// Scan Results</h2>
    <p class="section-desc">
      Findings organized by severity and OWASP category. Coverage measures
      endpoints tested. Resilience measures how the scanner handled intentional
      server errors.
    </p>
    <div id="builtin-results">
      <div style="color:#555">
        No scan results yet. Select a profile and click "Run Glitch Scanner."
      </div>
    </div>
    <div id="builtin-export-btns" style="margin-top:12px; display:none">
      <button class="scanner-btn" onclick="exportBuiltinResults('json')">Export JSON</button>
      <button class="scanner-btn" onclick="exportBuiltinResults('html')">Export HTML</button>
    </div>
  </div>

  <!-- Scan History -->
  <div class="section">
    <h2>// Scan History</h2>
    <p class="section-desc">
      History of built-in scanner runs. Compare results across profiles and
      configurations.
    </p>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Profile</th>
            <th>Modules</th>
            <th>Findings</th>
            <th>Coverage</th>
            <th>Resilience</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody id="builtin-history-body"></tbody>
      </table>
    </div>
  </div>
</div>
```

### 7.4 JavaScript Functions (Key Signatures)

The following JS functions need to be implemented or refactored. This is not exhaustive JS but documents the key function signatures and their responsibilities.

```javascript
// Sub-tab switching
function showScannerSubtab(name) {
  // Hide all .scanner-subpanel, show #scanner-sub-{name}
  // Update .scanner-subtab active state
  // If 'evaluate': call refreshEvalProfile() if not already loaded
  // If 'builtin': update run summary from current selections
}

// === Evaluate External Scanners ===

async function refreshEvalProfile() {
  // GET /admin/api/scanner/profile
  // Populate #eval-profile-cards with total_vulns, total_endpoints cards
  // Populate #eval-severity-badges with severity counts
  // Update banner text with dynamic numbers
  // Populate #external-scanner-cards with available_scanners
  // Each card shows: name, description, installed/version, Launch or Install Guide
}

async function launchExternal(scannerName) {
  // POST /admin/api/scanner/run {scanner, target}
  // Start polling with pollExternalStatus()
  // Show progress in #external-scanner-progress
}

async function pollExternalStatus() {
  // GET /admin/api/scanner/results
  // Update progress bar and running status
  // On completion: render comparison report from ScanRun.Comparison
}

async function uploadAndGrade() {
  // Read scanner type from #eval-scanner-type
  // Read output from #eval-scanner-output
  // POST /admin/api/scanner/compare {scanner, data}
  // Render comparison report in #eval-comparison-report
}

function renderEvalComparison(report) {
  // Render grade card, detection rate, FP rate, accuracy
  // Render true positives table (collapsible)
  // Render false negatives table (collapsible, labeled "Vulns scanner missed")
  // Render false positives table (collapsible, labeled "Scanner reported but not real")
  // Render scanner health status
}

async function addToMultiCompare() {
  // Read scanner type from #multi-scanner-type
  // Read output from #multi-scanner-output
  // Store in JS map: multiCompareData[scannerName] = rawOutput
  // Update #multi-compare-loaded with list of loaded scanners
  // Enable #btn-run-multi when >= 2 scanners loaded
}

async function runMultiCompare() {
  // POST /admin/api/scanner/multi-compare {reports: multiCompareData}
  // Render comparison table, coverage matrix, recommendation in #multi-compare-results
}

async function filterEvalHistory() {
  // GET /admin/api/scanner/history?scanner={filter}
  // Populate #eval-history-body
}

// === Built-in Scanner ===

function updateModuleCount() {
  // Count checked .builtin-module-cb checkboxes
  // Update #builtin-module-count text
  // Update #builtin-summary-modules
}

async function runBuiltinScanner() {
  // Read profile from input[name=builtin-profile]:checked
  // Read modules from .builtin-module-cb:checked
  // Read target from #builtin-target
  // POST /admin/api/scanner/builtin/run {profile, modules, target}
  // Show #builtin-run-progress, start polling pollBuiltinStatus()
}

async function pollBuiltinStatus() {
  // GET /admin/api/scanner/builtin/status
  // Update progress bar: requests completed/total, findings, errors, elapsed
  // On completion: call renderBuiltinResults()
}

async function stopBuiltinScanner() {
  // POST /admin/api/scanner/builtin/stop
}

function renderBuiltinResults(report) {
  // Render summary cards: total findings, by severity
  // Render coverage-by-category table
  // Render overall coverage and resilience metrics
  // Render findings table (filterable)
  // Show export buttons
  // Add row to #builtin-history-body
}

async function exportBuiltinResults(format) {
  // GET /admin/api/scanner/builtin/results?format={json|html}
  // Trigger file download
}
```

---

## 8. CSS Additions

The following CSS classes need to be added to the existing stylesheet in `admin_html.go`. These supplement the existing `.scanner-btn`, `.scanner-panel`, `.scanner-select`, `.scanner-textarea` classes.

```css
/* Scanner sub-tab navigation */
.scanner-subtabs {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  border-bottom: 1px solid #00ff8833;
  padding-bottom: 6px;
}
.scanner-subtab {
  padding: 8px 20px;
  background: #0d0d0d;
  border: 1px solid #00ff8822;
  border-bottom: none;
  border-radius: 6px 6px 0 0;
  color: #666;
  cursor: pointer;
  font-family: inherit;
  font-size: 0.82em;
  transition: all 0.2s;
}
.scanner-subtab:hover { color: #00ff88; background: #1a1a1a; }
.scanner-subtab.active {
  color: #00ffcc;
  background: #1a1a1a;
  border-color: #00ff8844;
}
.scanner-subpanel { display: none; }
.scanner-subpanel.active { display: block; }

/* Section description text */
.section-desc {
  color: #888;
  font-size: 0.82em;
  margin: 4px 0 12px 0;
  line-height: 1.5;
}

/* Workflow hint bar */
.workflow-hint {
  color: #555;
  font-size: 0.78em;
  background: #0d0d0d;
  border: 1px solid #222;
  border-radius: 4px;
  padding: 8px 12px;
  margin-top: 12px;
}

/* Scanner tool card (for external scanner grid) */
.scanner-tool-card {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  min-height: 140px;
}
.scanner-install-status { margin: 6px 0; font-size: 0.78em; }

/* Collapsible table sections */
.collapsible-header {
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  color: #00ccaa;
  font-size: 0.85em;
}
.collapsible-header:hover { color: #00ffcc; }
.collapsible-body { display: none; }
.collapsible-body.open { display: block; }

/* Built-in scanner run button (distinct from external Launch) */
#btn-run-builtin {
  background: #00aacc;
  color: #000;
  font-weight: bold;
  font-size: 0.95em;
  padding: 10px 28px;
}
#btn-run-builtin:hover { background: #00ccee; }
#btn-run-builtin:disabled { background: #333; color: #666; }

/* Severity badges */
.sev-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 0.75em;
  font-weight: bold;
  margin-right: 6px;
}
.sev-badge.critical { background: #ff444433; color: #ff4444; }
.sev-badge.high     { background: #ff884433; color: #ff8844; }
.sev-badge.medium   { background: #ffaa0033; color: #ffaa00; }
.sev-badge.low      { background: #44aaff33; color: #44aaff; }
.sev-badge.info     { background: #88888833; color: #888888; }
```

---

## 9. New API Endpoints Required

The existing API endpoints for external scanner evaluation remain unchanged. The following new endpoints are needed for the built-in scanner integration.

| Method | Path | Request Body | Response | Purpose |
|--------|------|-------------|----------|---------|
| `POST` | `/admin/api/scanner/builtin/run` | `{profile, modules[], target}` | `{status, run_id}` | Start built-in scanner |
| `GET` | `/admin/api/scanner/builtin/status` | -- | `{running, completed, total_requests, findings, errors, elapsed_ms, progress_pct}` | Poll scan progress |
| `POST` | `/admin/api/scanner/builtin/stop` | -- | `{ok, stopped}` | Stop running scan |
| `GET` | `/admin/api/scanner/builtin/results` | `?format=json\|html` | Full `scanner.Report` or HTML report | Get completed results |
| `GET` | `/admin/api/scanner/builtin/history` | -- | `{entries[]}` | Get scan run history |

### Backend implementation notes

The built-in scanner API handler should:
1. Create a `scanner.Config` from the selected profile using `profiles.Get(profileName)`.
2. Override `Config.Target` with the provided target URL.
3. Override `Config.EnabledModules` with the selected module list.
4. Create a `scanner.Engine` with the config.
5. Register filtered attack modules via `attacks.FilterModules(moduleNames)`.
6. Run the engine in a goroutine with a cancellable context.
7. Store progress in an atomic struct accessible by the status endpoint.
8. On completion, store the `scanner.Report` for the results endpoint.

This mirrors exactly what `cmd/glitch-scanner/main.go` does (lines 134-173) but exposes it via HTTP.

---

## 10. Acceptance Criteria

The following are testable criteria for PM sign-off. Each criterion is independently verifiable.

### Information Architecture

**AC-1:** The Scanner tab contains exactly two sub-tabs labeled "Evaluate External Scanners" and "Built-in Scanner". Clicking each sub-tab shows only its content and hides the other.

**AC-2:** The "Evaluate External Scanners" sub-tab contains exactly these sections in order: Context Banner (with auto-loaded profile), Launch External Scanner, Upload Scanner Output, Comparison Report, Multi-Scanner Comparison, Evaluation History.

**AC-3:** The "Built-in Scanner" sub-tab contains exactly these sections in order: Context Banner (with target field), Scan Profile, Attack Modules, Run Controls, Scan Results, Scan History.

### Profile & Context

**AC-4:** When the "Evaluate External Scanners" sub-tab is activated, the vulnerability profile loads automatically without requiring the user to click a button. The banner displays the total vulnerability count and total endpoint count (e.g., "229 vulnerabilities across 844 endpoints").

**AC-5:** The banner displays severity breakdown badges (critical, high, medium, low, info) with counts that match the output of `GET /admin/api/scanner/profile`.

### External Scanner Evaluation

**AC-6:** Each external scanner (nuclei, nikto, nmap, ffuf, wapiti) is displayed as a separate card showing: name, one-line description, installed status (with version if installed), and either a "Launch" button (if installed) or an "Install Guide" link (if not installed). Uninstalled scanners do not have a functional "Launch" button.

**AC-7:** Clicking "Launch" on an installed scanner card starts the scanner and displays a progress indicator. The progress indicator shows scanner name, running status, elapsed time, and a "Stop" button.

**AC-8:** The "Upload & Grade" flow accepts pasted text, parses it with the selected scanner parser, and displays a Comparison Report with grade (A-F), detection rate (percentage and fraction), false positive rate, accuracy, and expandable tables for true positives, false negatives, and false positives.

**AC-9:** The Multi-Scanner Comparison section allows adding output from 2+ scanners, running a comparison, and displaying: a summary table (scanner, grade, detection, FP rate, unique finds), a coverage matrix (vuln x scanner checkmark grid), consensus count, and a text recommendation.

**AC-10:** The Evaluation History table shows timestamp, scanner name, grade, detection rate, FP rate, and vuln count for every comparison recorded in the session. The filter dropdown restricts the table to a single scanner.

### Built-in Scanner

**AC-11:** The Scan Profile section displays all four profiles (compliance, aggressive, stealth, nightmare) as radio-button cards. Each card shows: profile name, description, workers count, rate limit, and evasion mode. Only one profile can be selected at a time.

**AC-12:** The Attack Modules section displays all 5 modules (owasp, injection, fuzzing, protocol, auth) as checkboxes with name, description, and approximate request count. "Select All" and "Deselect All" buttons work correctly. A module count summary updates dynamically.

**AC-13:** Clicking "Run Glitch Scanner" starts a scan using the selected profile, modules, and target. A progress indicator shows requests completed/total, findings count, errors count, and elapsed time. A "Stop Scan" button cancels the running scan.

**AC-14:** After a built-in scan completes, the Scan Results section displays: summary cards (total findings by severity), coverage-by-category table (category, tested, detected, coverage percentage), overall coverage percentage, overall resilience percentage, and a filterable findings table.

**AC-15:** The Scan History table for the built-in scanner shows timestamp, profile, module count, findings, coverage percentage, resilience percentage, and duration for each completed scan.

### Visual Separation

**AC-16:** The "Run Glitch Scanner" button is visually distinct from the external "Launch" buttons (different color: cyan/teal vs. green) so a user can tell at a glance they are different actions.

**AC-17:** No button in Sub-tab A triggers the built-in scanner, and no button in Sub-tab B triggers an external scanner. The two features are fully separated.

### Usability

**AC-18:** Every section has a descriptive paragraph (2-3 sentences) explaining what it does, visible without scrolling past the section header. A new user should understand the purpose of each section without reading external documentation.

**AC-19:** The false negatives table is labeled "Vulnerabilities the scanner missed" (not just "False Negatives") and the false positives table is labeled "Scanner reported but not real" (not just "False Positives").

**AC-20:** The workflow hint in the Evaluate banner reads: "Workflow: 1. Run or paste scanner output -> 2. Grade the scanner -> 3. Compare across scanners -> 4. Track over time."

---

## 11. Migration Notes

### What changes from the current UI

| Current element | What happens |
|----------------|--------------|
| "Generate Profile" button | Removed. Profile auto-loads on sub-tab activation |
| "Select Scanner" dropdown + "Upload & Compare" | Moved to Sub-tab A, "Upload Scanner Output" section |
| "Run Scanner" buttons (nuclei, nikto, nmap, ffuf, wapiti) | Moved to Sub-tab A, "Launch External Scanner" section, redesigned as cards |
| "Comparison Report" section | Stays in Sub-tab A with improved layout (collapsible tables, clearer labels) |
| "Scan History" table | Stays in Sub-tab A as "Evaluation History" with filter dropdown added |

### What is new

| New element | Location |
|-------------|----------|
| Sub-tab navigation | Top of Scanner panel |
| Auto-loading profile banner | Sub-tab A, top |
| Scanner install status cards | Sub-tab A, Launch section |
| Multi-Scanner Comparison | Sub-tab A, new section |
| File upload for scanner output | Sub-tab A, Upload section |
| Entire Sub-tab B | Built-in scanner (profile select, module select, run, results, history) |
| Built-in scanner API endpoints | 5 new API routes under `/admin/api/scanner/builtin/` |

### What is removed

| Removed element | Reason |
|-----------------|--------|
| "Generate Profile" standalone button | Replaced by auto-load. Reducing unnecessary user actions. |
| Ambiguous "Run Scanner" buttons that look like built-in scanner buttons | Replaced by clearly labeled "Launch" buttons on scanner cards with install status |

---

## 12. Out of Scope

The following items are explicitly excluded from this redesign:

1. **Authenticated scanning** -- The built-in scanner does not support login sequences. Future work.
2. **Real-time WebSocket progress** -- Polling at 1.5s intervals is sufficient. WebSocket upgrade is future work.
3. **Persistent history across server restarts** -- History is in-memory (ring buffer). Persistence is a separate feature.
4. **Custom scan profiles** -- The four built-in profiles are fixed. A "custom" profile builder is future work.
5. **CI/CD integration** -- The built-in scanner admin UI is interactive-only. CLI integration exists separately via `cmd/glitch-scanner`.
6. **SARIF report format** -- JSON and HTML exports only for now.
7. **Distributed scanning** -- Single-instance only.
