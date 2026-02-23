package scanner

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

// Report is the final output of a scan run.
type Report struct {
	Target        string                   `json:"target"`
	Profile       string                   `json:"profile"`
	StartedAt     string                   `json:"started_at"`
	CompletedAt   string                   `json:"completed_at"`
	DurationMs    int64                    `json:"duration_ms"`
	TotalRequests int                      `json:"total_requests"`
	Findings      []Finding                `json:"findings"`
	Coverage      map[string]*CoverageInfo `json:"coverage"`
	Resilience    *ResilienceInfo          `json:"resilience"`
	Errors        []string                 `json:"errors"`
	Summary       *ScanSummary             `json:"summary"`
}

// CoverageInfo tracks how many tests in a category were run and how
// many produced detectable findings.
type CoverageInfo struct {
	Category    string  `json:"category"`
	Tested      int     `json:"tested"`
	Detected    int     `json:"detected"`
	CoveragePct float64 `json:"coverage_pct"`
}

// ResilienceInfo summarises how the target handled error conditions
// (timeouts, connection resets, malformed input, etc.).
type ResilienceInfo struct {
	ErrorsEncountered int            `json:"errors_encountered"`
	ErrorsHandled     int            `json:"errors_handled"`
	ErrorTypes        map[string]int `json:"error_types"`
	ResiliencePct     float64        `json:"resilience_pct"`
}

// ScanSummary provides a top-level severity breakdown and overall metrics.
type ScanSummary struct {
	TotalFindings     int     `json:"total_findings"`
	Critical          int     `json:"critical"`
	High              int     `json:"high"`
	Medium            int     `json:"medium"`
	Low               int     `json:"low"`
	Info              int     `json:"info"`
	OverallCoverage   float64 `json:"overall_coverage_pct"`
	OverallResilience float64 `json:"overall_resilience_pct"`
}

// ---------------------------------------------------------------------------
// Reporter
// ---------------------------------------------------------------------------

// Reporter collects results and findings during a scan and can build a
// complete Report when the scan is finished.
type Reporter struct {
	mu       sync.Mutex
	findings []Finding
	results  []ScanResult
	errors   []string
}

// NewReporter creates an empty Reporter.
func NewReporter() *Reporter {
	return &Reporter{
		findings: make([]Finding, 0, 64),
		results:  make([]ScanResult, 0, 256),
		errors:   make([]string, 0),
	}
}

// AddResult records a scan result and runs automatic finding detection.
func (r *Reporter) AddResult(result ScanResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.results = append(r.results, result)

	// Auto-detect findings from response characteristics.
	for _, f := range detectFindings(result) {
		r.findings = append(r.findings, f)
	}
}

// FindingCount returns the current number of findings (thread-safe).
func (r *Reporter) FindingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.findings)
}

// AddFinding adds an explicitly-constructed finding.
func (r *Reporter) AddFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
}

// AddError records a non-fatal error that occurred during scanning.
func (r *Reporter) AddError(err string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, err)
}

// BuildReport constructs the final Report from all collected data.
func (r *Reporter) BuildReport(config *Config, startedAt, completedAt time.Time) *Report {
	r.mu.Lock()
	defer r.mu.Unlock()

	report := &Report{
		Target:        config.Target,
		Profile:       config.Profile,
		StartedAt:     startedAt.UTC().Format(time.RFC3339),
		CompletedAt:   completedAt.UTC().Format(time.RFC3339),
		DurationMs:    completedAt.Sub(startedAt).Milliseconds(),
		TotalRequests: len(r.results),
		Findings:      make([]Finding, len(r.findings)),
		Errors:        make([]string, len(r.errors)),
	}

	copy(report.Findings, r.findings)
	copy(report.Errors, r.errors)

	report.Coverage = r.buildCoverage()
	report.Resilience = r.buildResilience()
	report.Summary = r.buildSummary(report)

	return report
}

// ---------------------------------------------------------------------------
// Report output
// ---------------------------------------------------------------------------

// WriteJSON writes the report as indented JSON to w.
func (r *Reporter) WriteJSON(w io.Writer, report *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteHTML writes a self-contained HTML report to w.
func (r *Reporter) WriteHTML(w io.Writer, report *Report) error {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n")
	b.WriteString("<title>Glitch Scanner Report</title>\n")
	b.WriteString("<style>\n")
	b.WriteString("body{font-family:system-ui,-apple-system,sans-serif;margin:2em;background:#0d1117;color:#c9d1d9;}\n")
	b.WriteString("h1{color:#58a6ff;} h2{color:#79c0ff;margin-top:2em;}\n")
	b.WriteString("table{border-collapse:collapse;width:100%;margin-top:1em;}\n")
	b.WriteString("th,td{border:1px solid #30363d;padding:8px 12px;text-align:left;}\n")
	b.WriteString("th{background:#161b22;}\n")
	b.WriteString("tr:nth-child(even){background:#161b22;}\n")
	b.WriteString(".critical{color:#f85149;font-weight:bold;}\n")
	b.WriteString(".high{color:#f0883e;font-weight:bold;}\n")
	b.WriteString(".medium{color:#d29922;}\n")
	b.WriteString(".low{color:#58a6ff;}\n")
	b.WriteString(".info{color:#8b949e;}\n")
	b.WriteString(".summary-box{display:inline-block;padding:12px 24px;margin:6px;border-radius:6px;background:#161b22;border:1px solid #30363d;}\n")
	b.WriteString(".summary-box .num{font-size:2em;font-weight:bold;}\n")
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<h1>Glitch Scanner Report</h1>\n")
	b.WriteString(fmt.Sprintf("<p><strong>Target:</strong> %s</p>\n", html.EscapeString(report.Target)))
	b.WriteString(fmt.Sprintf("<p><strong>Profile:</strong> %s</p>\n", html.EscapeString(report.Profile)))
	b.WriteString(fmt.Sprintf("<p><strong>Started:</strong> %s</p>\n", html.EscapeString(report.StartedAt)))
	b.WriteString(fmt.Sprintf("<p><strong>Completed:</strong> %s</p>\n", html.EscapeString(report.CompletedAt)))
	b.WriteString(fmt.Sprintf("<p><strong>Duration:</strong> %d ms</p>\n", report.DurationMs))
	b.WriteString(fmt.Sprintf("<p><strong>Total Requests:</strong> %d</p>\n", report.TotalRequests))

	// Summary boxes.
	if s := report.Summary; s != nil {
		b.WriteString("<h2>Summary</h2>\n<div>\n")
		writeSummaryBox(&b, "Total", s.TotalFindings, "")
		writeSummaryBox(&b, "Critical", s.Critical, "critical")
		writeSummaryBox(&b, "High", s.High, "high")
		writeSummaryBox(&b, "Medium", s.Medium, "medium")
		writeSummaryBox(&b, "Low", s.Low, "low")
		writeSummaryBox(&b, "Info", s.Info, "info")
		b.WriteString(fmt.Sprintf("<div class=\"summary-box\"><div class=\"num\">%.1f%%</div><div>Coverage</div></div>\n", s.OverallCoverage))
		b.WriteString(fmt.Sprintf("<div class=\"summary-box\"><div class=\"num\">%.1f%%</div><div>Resilience</div></div>\n", s.OverallResilience))
		b.WriteString("</div>\n")
	}

	// Findings table.
	if len(report.Findings) > 0 {
		b.WriteString("<h2>Findings</h2>\n")
		b.WriteString("<table>\n<tr><th>Severity</th><th>Category</th><th>URL</th><th>Method</th><th>Status</th><th>Description</th><th>Evidence</th></tr>\n")
		for _, f := range report.Findings {
			sevClass := strings.ToLower(f.Severity)
			b.WriteString(fmt.Sprintf("<tr><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>\n",
				html.EscapeString(sevClass),
				html.EscapeString(f.Severity),
				html.EscapeString(f.Category),
				html.EscapeString(f.URL),
				html.EscapeString(f.Method),
				f.StatusCode,
				html.EscapeString(f.Description),
				html.EscapeString(truncateStr(f.Evidence, 200)),
			))
		}
		b.WriteString("</table>\n")
	}

	// Coverage table.
	if len(report.Coverage) > 0 {
		b.WriteString("<h2>Coverage</h2>\n")
		b.WriteString("<table>\n<tr><th>Category</th><th>Tested</th><th>Detected</th><th>Coverage %</th></tr>\n")
		for _, ci := range report.Coverage {
			b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%.1f%%</td></tr>\n",
				html.EscapeString(ci.Category), ci.Tested, ci.Detected, ci.CoveragePct))
		}
		b.WriteString("</table>\n")
	}

	// Resilience.
	if ri := report.Resilience; ri != nil {
		b.WriteString("<h2>Resilience</h2>\n")
		b.WriteString(fmt.Sprintf("<p>Errors encountered: %d, handled gracefully: %d (%.1f%%)</p>\n",
			ri.ErrorsEncountered, ri.ErrorsHandled, ri.ResiliencePct))
		if len(ri.ErrorTypes) > 0 {
			b.WriteString("<table>\n<tr><th>Error Type</th><th>Count</th></tr>\n")
			for et, cnt := range ri.ErrorTypes {
				b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>\n",
					html.EscapeString(et), cnt))
			}
			b.WriteString("</table>\n")
		}
	}

	// Errors.
	if len(report.Errors) > 0 {
		b.WriteString("<h2>Errors</h2>\n<ul>\n")
		for _, e := range report.Errors {
			b.WriteString(fmt.Sprintf("<li>%s</li>\n", html.EscapeString(e)))
		}
		b.WriteString("</ul>\n")
	}

	b.WriteString("</body>\n</html>\n")

	_, err := io.WriteString(w, b.String())
	return err
}

func writeSummaryBox(b *strings.Builder, label string, count int, class string) {
	if class != "" {
		b.WriteString(fmt.Sprintf("<div class=\"summary-box\"><div class=\"num %s\">%d</div><div>%s</div></div>\n",
			class, count, label))
	} else {
		b.WriteString(fmt.Sprintf("<div class=\"summary-box\"><div class=\"num\">%d</div><div>%s</div></div>\n",
			count, label))
	}
}

// ---------------------------------------------------------------------------
// Automatic finding detection
// ---------------------------------------------------------------------------

// Compiled patterns for finding detection.
var (
	reSQLError = regexp.MustCompile(`(?i)(` +
		`sql syntax|mysql_fetch|ORA-\d{5}|` +
		`pg_query|sqlite3?\.|` +
		`unterminated quoted string|` +
		`microsoft sql native client|` +
		`ODBC SQL Server Driver|` +
		`SQL Server.*Driver|` +
		`Warning.*\Wmysqli?_|` +
		`valid MySQL result|` +
		`PostgreSQL.*ERROR|` +
		`driver\..*Sql|` +
		`quoted string not properly terminated` +
		`)`)

	reXSSReflect = regexp.MustCompile(`(?i)(<script[^>]*>|javascript:|on\w+\s*=)`)

	reInfoDisclosure = regexp.MustCompile(`(?i)(` +
		`/etc/passwd|/etc/shadow|` +
		`C:\\Windows|` +
		`(?:^|\D)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?:\D|$)|` +
		`root:x:0:0|` +
		`/home/\w+/|` +
		`/var/www/|` +
		`/usr/local/|` +
		`X-Powered-By|` +
		`SERVER_SOFTWARE` +
		`)`)

	reStackTrace = regexp.MustCompile(`(?i)(` +
		`(?:at\s+[\w.$]+\([\w.]+:\d+\))|` +
		`goroutine \d+|` +
		`Traceback \(most recent call|` +
		`File ".*", line \d+|` +
		`Exception in thread|` +
		`panic:|` +
		`stack trace:|` +
		`at Object\.<anonymous>` +
		`)`)
)

// detectFindings analyses a single ScanResult and returns any
// automatically-detected findings.
func detectFindings(result ScanResult) []Finding {
	var findings []Finding

	body := result.BodySnippet
	reqURL := result.Request.Path
	method := result.Request.Method

	// Construct the full URL for the finding if we only have a path.
	findingURL := reqURL
	if result.Request.Category == "" && reqURL == "" {
		findingURL = "(unknown)"
	}

	// 1. SQL injection indicators.
	if reSQLError.MatchString(body) {
		findings = append(findings, Finding{
			Category:    "sql-injection",
			Severity:    "high",
			URL:         findingURL,
			Method:      method,
			StatusCode:  result.StatusCode,
			Evidence:    extractMatch(reSQLError, body),
			Description: "SQL error message detected in response body, possible SQL injection",
		})
	}

	// 2. XSS — reflected content.
	if result.Request.Category == "xss" && result.StatusCode == 200 && reXSSReflect.MatchString(body) {
		findings = append(findings, Finding{
			Category:    "xss",
			Severity:    "high",
			URL:         findingURL,
			Method:      method,
			StatusCode:  result.StatusCode,
			Evidence:    extractMatch(reXSSReflect, body),
			Description: "Potentially reflected XSS payload found in response body",
		})
	}

	// 3. Information disclosure — internal paths / IPs.
	if reInfoDisclosure.MatchString(body) {
		findings = append(findings, Finding{
			Category:    "info-disclosure",
			Severity:    "medium",
			URL:         findingURL,
			Method:      method,
			StatusCode:  result.StatusCode,
			Evidence:    extractMatch(reInfoDisclosure, body),
			Description: "Internal path or private IP address leaked in response",
		})
	}

	// 4. Stack trace / debug info in error responses.
	if result.StatusCode >= 400 && reStackTrace.MatchString(body) {
		findings = append(findings, Finding{
			Category:    "info-disclosure",
			Severity:    "medium",
			URL:         findingURL,
			Method:      method,
			StatusCode:  result.StatusCode,
			Evidence:    extractMatch(reStackTrace, body),
			Description: "Stack trace or debug information in error response",
		})
	}

	// 5. Status 200 on known vulnerability endpoint.
	if result.StatusCode == 200 && isVulnPath(reqURL) {
		findings = append(findings, Finding{
			Category:    result.Request.Category,
			Severity:    severityForCategory(result.Request.Category),
			URL:         findingURL,
			Method:      method,
			StatusCode:  result.StatusCode,
			Evidence:    fmt.Sprintf("HTTP 200 on %s", reqURL),
			Description: fmt.Sprintf("Successful response on vulnerability endpoint: %s", result.Request.Description),
		})
	}

	// 6. Open redirect indicators.
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		location := result.Headers["Location"]
		if location == "" {
			location = result.Headers["location"]
		}
		if location != "" && (strings.HasPrefix(location, "http://evil") || strings.HasPrefix(location, "//evil")) {
			findings = append(findings, Finding{
				Category:    "open-redirect",
				Severity:    "medium",
				URL:         findingURL,
				Method:      method,
				StatusCode:  result.StatusCode,
				Evidence:    "Location: " + location,
				Description: "Open redirect detected — server redirected to attacker-controlled domain",
			})
		}
	}

	// 7. Sensitive headers leaked.
	for _, hdr := range []string{"X-Powered-By", "Server"} {
		if val, ok := result.Headers[hdr]; ok && val != "" {
			findings = append(findings, Finding{
				Category:    "info-disclosure",
				Severity:    "low",
				URL:         findingURL,
				Method:      method,
				StatusCode:  result.StatusCode,
				Evidence:    hdr + ": " + val,
				Description: fmt.Sprintf("Server technology disclosed via %s header", hdr),
			})
		}
	}

	return findings
}

// ---------------------------------------------------------------------------
// Report-building helpers
// ---------------------------------------------------------------------------

// buildCoverage computes per-category coverage from collected results.
func (r *Reporter) buildCoverage() map[string]*CoverageInfo {
	coverage := make(map[string]*CoverageInfo)

	for _, res := range r.results {
		cat := res.Request.Category
		if cat == "" {
			cat = "general"
		}
		ci, ok := coverage[cat]
		if !ok {
			ci = &CoverageInfo{Category: cat}
			coverage[cat] = ci
		}
		ci.Tested++
	}

	// Count detections per category.
	for _, f := range r.findings {
		cat := f.Category
		if cat == "" {
			cat = "general"
		}
		if ci, ok := coverage[cat]; ok {
			ci.Detected++
		} else {
			coverage[cat] = &CoverageInfo{
				Category: cat,
				Tested:   0,
				Detected: 1,
			}
		}
	}

	for _, ci := range coverage {
		if ci.Tested > 0 {
			ci.CoveragePct = float64(ci.Detected) / float64(ci.Tested) * 100
		}
	}

	return coverage
}

// buildResilience analyses error patterns in scan results.
func (r *Reporter) buildResilience() *ResilienceInfo {
	ri := &ResilienceInfo{
		ErrorTypes: make(map[string]int),
	}

	for _, res := range r.results {
		if res.Error != "" {
			ri.ErrorsEncountered++
			// Classify the error.
			errType := classifyError(res.Error)
			ri.ErrorTypes[errType]++
		} else if res.StatusCode >= 500 {
			ri.ErrorsEncountered++
			ri.ErrorTypes[fmt.Sprintf("http_%d", res.StatusCode)]++
			// A 500 with a useful error page is "handled".
			if res.BodySize > 100 {
				ri.ErrorsHandled++
			}
		} else if res.StatusCode >= 400 && res.StatusCode < 500 {
			// 4xx errors are properly handled by definition.
			ri.ErrorsHandled++
		}
	}

	if ri.ErrorsEncountered > 0 {
		ri.ResiliencePct = float64(ri.ErrorsHandled) / float64(ri.ErrorsEncountered) * 100
	} else {
		ri.ResiliencePct = 100.0
	}

	return ri
}

// buildSummary computes the final summary from findings, coverage, and resilience.
func (r *Reporter) buildSummary(report *Report) *ScanSummary {
	s := &ScanSummary{
		TotalFindings: len(report.Findings),
	}

	for _, f := range report.Findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}

	// Overall coverage = average of per-category coverage.
	if len(report.Coverage) > 0 {
		total := 0.0
		for _, ci := range report.Coverage {
			total += ci.CoveragePct
		}
		s.OverallCoverage = total / float64(len(report.Coverage))
	}

	if report.Resilience != nil {
		s.OverallResilience = report.Resilience.ResiliencePct
	}

	return s
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// extractMatch returns the first match of re in s, truncated to 256 chars.
func extractMatch(re *regexp.Regexp, s string) string {
	m := re.FindString(s)
	return truncateStr(m, 256)
}

// truncateStr shortens s to at most max bytes.
func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// isVulnPath returns true if the path looks like a vulnerability test endpoint.
func isVulnPath(path string) bool {
	return strings.Contains(path, "/vuln/") || strings.HasPrefix(path, "vuln/")
}

// severityForCategory returns a default severity for a vulnerability category.
func severityForCategory(category string) string {
	switch strings.ToLower(category) {
	case "sql-injection", "sqli", "rce", "command-injection", "deserialization", "xxe":
		return "critical"
	case "xss", "ssti", "ssrf", "path-traversal", "lfi":
		return "high"
	case "open-redirect", "cors", "csrf", "idor", "info-disclosure":
		return "medium"
	case "missing-header", "cookie", "verbose-error":
		return "low"
	default:
		return "info"
	}
}

// classifyError categorises a transport-level error string.
func classifyError(errStr string) string {
	lower := strings.ToLower(errStr)
	switch {
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline"):
		return "timeout"
	case strings.Contains(lower, "connection refused"):
		return "connection_refused"
	case strings.Contains(lower, "connection reset"):
		return "connection_reset"
	case strings.Contains(lower, "eof"):
		return "eof"
	case strings.Contains(lower, "tls") || strings.Contains(lower, "certificate"):
		return "tls_error"
	case strings.Contains(lower, "dns") || strings.Contains(lower, "no such host"):
		return "dns_error"
	default:
		return "other"
	}
}
