package scaneval

import (
	"math"
	"strings"
	"time"
)

// VulnCategory represents one type of vulnerability the server exposes.
type VulnCategory struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Endpoints   []string `json:"endpoints"`
	Description string   `json:"description"`
	CWE         string   `json:"cwe"`
	OWASP       string   `json:"owasp"`
	Detectable  bool     `json:"detectable"`
}

// ExpectedProfile is a snapshot of what the server currently exposes.
type ExpectedProfile struct {
	Timestamp     time.Time              `json:"timestamp"`
	ServerPort    int                    `json:"server_port"`
	DashboardPort int                    `json:"dashboard_port"`
	Features      map[string]bool        `json:"features"`
	Config        map[string]interface{} `json:"config"`

	Vulnerabilities []VulnCategory `json:"vulnerabilities"`

	TotalVulns     int            `json:"total_vulns"`
	BySeverity     map[string]int `json:"by_severity"`
	TotalEndpoints int            `json:"total_endpoints"`

	ExpectedErrorRate     float64 `json:"expected_error_rate"`
	ExpectedLabyrinthRate float64 `json:"expected_labyrinth_rate"`
	ExpectedCaptchaRate   float64 `json:"expected_captcha_rate"`
	ExpectedBlockRate     float64 `json:"expected_block_rate"`

	TotalEndpointCount int            `json:"total_endpoint_count"`
	EndpointsByType    map[string]int `json:"endpoints_by_type"`
}

// ScanResult represents parsed output from one scanner tool.
type ScanResult struct {
	Scanner      string        `json:"scanner"`
	StartedAt    time.Time     `json:"started_at"`
	CompletedAt  time.Time     `json:"completed_at"`
	Duration     time.Duration `json:"duration_ms"`
	ExitCode     int           `json:"exit_code"`
	RawOutput    string        `json:"raw_output"`
	Findings     []Finding     `json:"findings"`
	Errors       []string      `json:"errors"`
	Crashed      bool          `json:"crashed"`
	TimedOut     bool          `json:"timed_out"`
	RequestCount int           `json:"request_count"`
}

// Finding is a single finding from a scanner.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Description string `json:"description"`
	CWE         string `json:"cwe"`
	Reference   string `json:"reference"`
	Evidence    string `json:"evidence"`
	Matched     bool   `json:"matched"`
}

// ComparisonReport compares expected vs actual scanner results.
type ComparisonReport struct {
	Scanner  string    `json:"scanner"`
	Timestamp time.Time `json:"timestamp"`
	Duration time.Duration `json:"duration_ms"`

	ExpectedVulns int `json:"expected_vulns"`
	FoundVulns    int `json:"found_vulns"`

	TruePositives  []MatchedVuln  `json:"true_positives"`
	FalseNegatives []VulnCategory `json:"false_negatives"`
	FalsePositives []Finding      `json:"false_positives"`

	DetectionRate     float64 `json:"detection_rate"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	Accuracy          float64 `json:"accuracy"`

	ScannerCrashed  bool     `json:"scanner_crashed"`
	ScannerTimedOut bool     `json:"scanner_timed_out"`
	ScannerErrors   []string `json:"scanner_errors"`

	ClassifiedFN []ClassifiedFalseNegative `json:"classified_false_negatives,omitempty"`

	Grade string `json:"grade"`
}

// MatchedVuln pairs an expected vulnerability with the scanner finding that detected it.
type MatchedVuln struct {
	Expected VulnCategory `json:"expected"`
	Found    Finding      `json:"found"`
}

// ClassifiedFalseNegative distinguishes between false negatives that were
// crawled but not detected (critical) vs not crawled at all (less critical).
type ClassifiedFalseNegative struct {
	Vuln            VulnCategory `json:"vuln"`
	Classification  string       `json:"classification"` // "not_crawled" or "crawled_not_detected"
	EndpointsHit    []string     `json:"endpoints_hit"`
	EndpointsMissed []string     `json:"endpoints_missed"`
}

// ClassifyFalseNegatives cross-references false negatives from a comparison
// report with server request logs (accessedPaths) to determine whether each
// missed vulnerability was actually crawled but not detected (critical) or
// not crawled at all (less critical, a crawling issue rather than detection).
func ClassifyFalseNegatives(report *ComparisonReport, accessedPaths map[string]int) {
	report.ClassifiedFN = nil
	for _, fn := range report.FalseNegatives {
		cfn := ClassifiedFalseNegative{Vuln: fn}
		for _, ep := range fn.Endpoints {
			if _, hit := accessedPaths[ep]; hit {
				cfn.EndpointsHit = append(cfn.EndpointsHit, ep)
			} else {
				cfn.EndpointsMissed = append(cfn.EndpointsMissed, ep)
			}
		}
		if len(cfn.EndpointsHit) > 0 {
			cfn.Classification = "crawled_not_detected"
		} else {
			cfn.Classification = "not_crawled"
		}
		report.ClassifiedFN = append(report.ClassifiedFN, cfn)
	}
}

// ComputeProfile examines enabled features and config to build a complete
// expected vulnerability profile. It takes feature flags and config as plain
// maps so it has no dependency on other internal packages.
func ComputeProfile(features map[string]bool, config map[string]interface{}, serverPort, dashPort int) *ExpectedProfile {
	p := &ExpectedProfile{
		Timestamp:     time.Now(),
		ServerPort:    serverPort,
		DashboardPort: dashPort,
		Features:      features,
		Config:        config,
		BySeverity:    make(map[string]int),
		EndpointsByType: make(map[string]int),
	}

	// Build vulnerability catalog based on enabled features
	if featureEnabled(features, "vuln") {
		p.Vulnerabilities = append(p.Vulnerabilities, owaspVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, advancedVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, dashboardVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, apiSecurityVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, modernVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, infrastructureVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, iotDesktopVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, mobilePrivacyVulns()...)
		p.Vulnerabilities = append(p.Vulnerabilities, specializedVulns()...)
	}

	if featureEnabled(features, "honeypot") {
		p.Vulnerabilities = append(p.Vulnerabilities, honeypotVulns()...)
	}

	if featureEnabled(features, "header_corrupt") {
		p.Vulnerabilities = append(p.Vulnerabilities, headerCorruptionVulns()...)
	}

	if featureEnabled(features, "cookie_traps") {
		p.Vulnerabilities = append(p.Vulnerabilities, cookieTrapVulns()...)
	}

	// Missing security headers are always present (the server intentionally omits them)
	p.Vulnerabilities = append(p.Vulnerabilities, missingHeaderVulns()...)

	// Server information disclosure is always present
	p.Vulnerabilities = append(p.Vulnerabilities, serverInfoVulns()...)

	// Compute summary statistics
	endpointSet := make(map[string]bool)
	for i := range p.Vulnerabilities {
		v := &p.Vulnerabilities[i]
		p.BySeverity[v.Severity]++
		for _, ep := range v.Endpoints {
			endpointSet[ep] = true
		}
	}
	p.TotalVulns = len(p.Vulnerabilities)
	p.TotalEndpoints = len(endpointSet)

	// Count endpoints by type
	for _, v := range p.Vulnerabilities {
		category := categorizeFinding(v.ID)
		p.EndpointsByType[category] += len(v.Endpoints)
	}

	// Compute total endpoint count (vuln endpoints + honeypot + dashboard API + misc)
	p.TotalEndpointCount = p.TotalEndpoints
	if featureEnabled(features, "honeypot") {
		p.EndpointsByType["honeypot"] += honeypotEndpointCount()
		p.TotalEndpointCount += honeypotEndpointCount()
	}
	// Dashboard API endpoints always exist on the dashboard port
	dashEP := 6 // /, /api/metrics, /api/clients, /api/timeseries, /api/recent, /api/behaviors
	p.EndpointsByType["api"] += dashEP
	p.TotalEndpointCount += dashEP

	// Compute expected behavioral rates from config
	p.ExpectedErrorRate = computeErrorRate(features, config)
	p.ExpectedLabyrinthRate = computeLabyrinthRate(features, config)
	p.ExpectedCaptchaRate = computeCaptchaRate(features, config)
	p.ExpectedBlockRate = computeBlockRate(features, config)

	return p
}

// CompareResults matches scanner findings against expected vulnerabilities
// and produces a graded comparison report.
func CompareResults(profile *ExpectedProfile, result *ScanResult) *ComparisonReport {
	report := &ComparisonReport{
		Scanner:         result.Scanner,
		Timestamp:       time.Now(),
		Duration:        result.Duration,
		ScannerCrashed:  result.Crashed,
		ScannerTimedOut: result.TimedOut,
		ScannerErrors:   result.Errors,
	}

	// Only consider detectable vulns for matching
	detectable := make([]VulnCategory, 0)
	for _, v := range profile.Vulnerabilities {
		if v.Detectable {
			detectable = append(detectable, v)
		}
	}
	report.ExpectedVulns = len(detectable)
	report.FoundVulns = len(result.Findings)

	// Track which findings have been matched to avoid double-counting
	matchedFindings := make([]bool, len(result.Findings))
	matchedVulns := make([]bool, len(detectable))

	// Phase 1: exact CWE matching
	for vi, vuln := range detectable {
		if matchedVulns[vi] || vuln.CWE == "" {
			continue
		}
		for fi, finding := range result.Findings {
			if matchedFindings[fi] {
				continue
			}
			if finding.CWE != "" && normalizeCWE(finding.CWE) == normalizeCWE(vuln.CWE) {
				if urlOverlap(vuln.Endpoints, finding.URL) || keywordMatch(vuln, finding) {
					report.TruePositives = append(report.TruePositives, MatchedVuln{
						Expected: vuln,
						Found:    finding,
					})
					matchedVulns[vi] = true
					matchedFindings[fi] = true
					break
				}
			}
		}
	}

	// Phase 2: URL matching
	for vi, vuln := range detectable {
		if matchedVulns[vi] {
			continue
		}
		for fi, finding := range result.Findings {
			if matchedFindings[fi] {
				continue
			}
			if urlOverlap(vuln.Endpoints, finding.URL) {
				report.TruePositives = append(report.TruePositives, MatchedVuln{
					Expected: vuln,
					Found:    finding,
				})
				matchedVulns[vi] = true
				matchedFindings[fi] = true
				break
			}
		}
	}

	// Phase 3: keyword matching (broad)
	for vi, vuln := range detectable {
		if matchedVulns[vi] {
			continue
		}
		for fi, finding := range result.Findings {
			if matchedFindings[fi] {
				continue
			}
			if keywordMatch(vuln, finding) {
				report.TruePositives = append(report.TruePositives, MatchedVuln{
					Expected: vuln,
					Found:    finding,
				})
				matchedVulns[vi] = true
				matchedFindings[fi] = true
				break
			}
		}
	}

	// Collect false negatives (expected but not found)
	for vi, vuln := range detectable {
		if !matchedVulns[vi] {
			report.FalseNegatives = append(report.FalseNegatives, vuln)
		}
	}

	// Collect false positives (found but not expected)
	for fi, finding := range result.Findings {
		if !matchedFindings[fi] {
			report.FalsePositives = append(report.FalsePositives, finding)
		}
	}

	// Compute rates
	tp := float64(len(report.TruePositives))
	fn := float64(len(report.FalseNegatives))
	fp := float64(len(report.FalsePositives))

	if tp+fn > 0 {
		report.DetectionRate = tp / (tp + fn)
	}

	if tp+fp > 0 {
		report.FalsePositiveRate = fp / (tp + fp)
	}

	// Accuracy is a weighted score: detection contributes 70%, low FP contributes 30%
	if report.ExpectedVulns > 0 || report.FoundVulns > 0 {
		detectionScore := report.DetectionRate * 70.0
		fpPenalty := 30.0
		if tp+fp > 0 {
			fpPenalty = (1.0 - report.FalsePositiveRate) * 30.0
		}
		report.Accuracy = math.Min(100.0, detectionScore+fpPenalty)
	}

	// Assign grade
	report.Grade = computeGrade(report.DetectionRate)

	return report
}

// ---------------------------------------------------------------------------
// OWASP Top 10 vulnerability definitions
// ---------------------------------------------------------------------------

func owaspVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "owasp-a01",
			Name:        "A01:2021 Broken Access Control",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/a01/", "/vuln/a01/idor", "/vuln/a01/privilege-escalation", "/admin/users"},
			Description: "IDOR, privilege escalation, missing access controls on admin endpoints",
			CWE:         "CWE-284",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a02",
			Name:        "A02:2021 Cryptographic Failures",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/a02/", "/vuln/a02/weak-hash", "/vuln/a02/plaintext", "/vuln/a02/weak-cipher"},
			Description: "Weak hashing (MD5/SHA1), plaintext credentials, weak ciphers exposed",
			CWE:         "CWE-327",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a03",
			Name:        "A03:2021 Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/a03/", "/vuln/a03/sqli", "/vuln/a03/xss", "/vuln/a03/ldap"},
			Description: "SQL injection, XSS, LDAP injection with reflected user input",
			CWE:         "CWE-79",
			OWASP:       "A03:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a04",
			Name:        "A04:2021 Insecure Design",
			Severity:    "high",
			Endpoints:   []string{"/vuln/a04/", "/vuln/a04/enum", "/vuln/a04/predictable"},
			Description: "User enumeration, predictable resource locations, insecure design patterns",
			CWE:         "CWE-209",
			OWASP:       "A04:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a05",
			Name:        "A05:2021 Security Misconfiguration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/a05/", "/vuln/a05/default-creds", "/vuln/a05/verbose-errors", "/vuln/a05/directory-listing"},
			Description: "Default credentials, verbose error messages, directory listing enabled",
			CWE:         "CWE-16",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a06",
			Name:        "A06:2021 Vulnerable and Outdated Components",
			Severity:    "high",
			Endpoints:   []string{"/vuln/a06/", "/vuln/a06/outdated", "/vuln/a06/cve"},
			Description: "Outdated software versions with known CVEs exposed in headers and responses",
			CWE:         "CWE-1104",
			OWASP:       "A06:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a07",
			Name:        "A07:2021 Identification and Authentication Failures",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/a07/", "/vuln/a07/weak-password", "/vuln/a07/session-fixation", "/vuln/a07/brute-force"},
			Description: "Weak passwords, session fixation, brute force endpoints without rate limiting",
			CWE:         "CWE-287",
			OWASP:       "A07:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a08",
			Name:        "A08:2021 Software and Data Integrity Failures",
			Severity:    "high",
			Endpoints:   []string{"/vuln/a08/", "/vuln/a08/unsigned", "/vuln/a08/cicd"},
			Description: "Unsigned updates, insecure deserialization, CI/CD pipeline exposure",
			CWE:         "CWE-502",
			OWASP:       "A08:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a09",
			Name:        "A09:2021 Security Logging and Monitoring Failures",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/a09/", "/logs/access.log"},
			Description: "Access logs exposed, insufficient logging, log injection possible",
			CWE:         "CWE-778",
			OWASP:       "A09:2021",
			Detectable:  true,
		},
		{
			ID:          "owasp-a10",
			Name:        "A10:2021 Server-Side Request Forgery (SSRF)",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/a10/", "/vuln/a10/fetch", "/proxy"},
			Description: "SSRF via fetch endpoint and open proxy with no validation",
			CWE:         "CWE-918",
			OWASP:       "A10:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Advanced vulnerability definitions
// ---------------------------------------------------------------------------

func advancedVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "cors-misconfig",
			Name:        "CORS Misconfiguration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cors/reflect", "/vuln/cors/wildcard", "/vuln/cors/null"},
			Description: "Origin reflection, wildcard with credentials, null origin accepted",
			CWE:         "CWE-942",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "xxe-injection",
			Name:        "XXE Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/xxe/parse", "/vuln/xxe/blind", "/vuln/xxe/oob"},
			Description: "XML external entity processing with file disclosure and SSRF",
			CWE:         "CWE-611",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "ssti",
			Name:        "Server-Side Template Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/ssti/render", "/vuln/ssti/eval"},
			Description: "Template injection allowing code execution via template expressions",
			CWE:         "CWE-1336",
			OWASP:       "A03:2021",
			Detectable:  true,
		},
		{
			ID:          "crlf-injection",
			Name:        "CRLF Injection",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/crlf/set", "/vuln/crlf/header"},
			Description: "HTTP header injection via CRLF characters in parameters",
			CWE:         "CWE-113",
			OWASP:       "A03:2021",
			Detectable:  true,
		},
		{
			ID:          "host-header-injection",
			Name:        "Host Header Injection",
			Severity:    "high",
			Endpoints:   []string{"/vuln/host/reset", "/vuln/host/cache", "/vuln/host/redirect"},
			Description: "Host header poisoning for password reset, cache, and redirect attacks",
			CWE:         "CWE-644",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "verb-tamper",
			Name:        "HTTP Verb Tampering",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/verb/admin", "/vuln/verb/delete", "/vuln/verb/debug"},
			Description: "Access control bypass via non-standard HTTP methods",
			CWE:         "CWE-650",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "hpp",
			Name:        "HTTP Parameter Pollution",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/hpp/transfer", "/vuln/hpp/search", "/vuln/hpp/login"},
			Description: "Duplicate parameter handling allows logic bypass",
			CWE:         "CWE-235",
			OWASP:       "A03:2021",
			Detectable:  true,
		},
		{
			ID:          "file-upload",
			Name:        "Insecure File Upload",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/upload/form", "/vuln/upload/api", "/vuln/upload/avatar"},
			Description: "Unrestricted file type upload allowing executable content",
			CWE:         "CWE-434",
			OWASP:       "A04:2021",
			Detectable:  true,
		},
		{
			ID:          "cmd-injection",
			Name:        "Command Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cmd/ping", "/vuln/cmd/dns", "/vuln/cmd/exec"},
			Description: "OS command injection via unsanitized user input",
			CWE:         "CWE-78",
			OWASP:       "A03:2021",
			Detectable:  true,
		},
		{
			ID:          "graphql-vuln",
			Name:        "GraphQL Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/graphql/introspection", "/vuln/graphql/batch", "/vuln/graphql/depth"},
			Description: "Introspection enabled, batch query abuse, deep query DoS",
			CWE:         "CWE-200",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "jwt-vuln",
			Name:        "JWT Vulnerabilities",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/jwt/none", "/vuln/jwt/weak-key", "/vuln/jwt/kid-injection"},
			Description: "None algorithm accepted, weak signing keys, kid parameter injection",
			CWE:         "CWE-347",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "race-condition",
			Name:        "Race Conditions",
			Severity:    "high",
			Endpoints:   []string{"/vuln/race/coupon", "/vuln/race/transfer", "/vuln/race/register"},
			Description: "TOCTOU bugs, double-spend exploits, race in state transitions",
			CWE:         "CWE-362",
			OWASP:       "A04:2021",
			Detectable:  true,
		},
		{
			ID:          "deserialization",
			Name:        "Insecure Deserialization",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/deserialize/java", "/vuln/deserialize/python", "/vuln/deserialize/php"},
			Description: "Deserialization of untrusted data with gadget chain exposure",
			CWE:         "CWE-502",
			OWASP:       "A08:2021",
			Detectable:  true,
		},
		{
			ID:          "path-traversal",
			Name:        "Path Traversal",
			Severity:    "high",
			Endpoints:   []string{"/vuln/path/traverse", "/vuln/path/normalize", "/vuln/path/bypass"},
			Description: "Directory traversal and path normalization bypass",
			CWE:         "CWE-22",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "open-redirect",
			Name:        "Open Redirect",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/redirect"},
			Description: "Unvalidated URL redirect via url, next, and return_to parameters",
			CWE:         "CWE-601",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Dashboard/settings vulnerability definitions
// ---------------------------------------------------------------------------

func dashboardVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "dashboard-unauth",
			Name:        "Unauthenticated Admin Dashboard",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/dashboard/", "/vuln/dashboard/analytics", "/vuln/dashboard/system"},
			Description: "Full admin dashboard access without any authentication",
			CWE:         "CWE-306",
			OWASP:       "A07:2021",
			Detectable:  true,
		},
		{
			ID:          "debug-info",
			Name:        "Debug Information Disclosure",
			Severity:    "high",
			Endpoints:   []string{"/vuln/dashboard/debug", "/vuln/dashboard/debug/env", "/vuln/dashboard/debug/routes", "/vuln/dashboard/debug/sql", "/vuln/dashboard/debug/sessions", "/vuln/dashboard/debug/cache"},
			Description: "Debug panel exposes environment variables, routes, SQL queries, sessions, and cache",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "phpinfo-exposure",
			Name:        "PHPInfo Exposure",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/dashboard/phpinfo"},
			Description: "PHPInfo page exposes full server configuration details",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "server-status",
			Name:        "Server Status Page",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/dashboard/server-status"},
			Description: "Apache mod_status style information leak exposing active connections",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "api-keys-exposed",
			Name:        "API Key Management Exposed",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/dashboard/api-keys", "/vuln/dashboard/api-keys/create", "/vuln/dashboard/api-keys/rotate"},
			Description: "API keys displayed in plaintext with no authentication required",
			CWE:         "CWE-312",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "user-data-exposed",
			Name:        "User Data Exposure",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/dashboard/users", "/vuln/dashboard/users/export", "/vuln/dashboard/users/invite", "/vuln/dashboard/export/users"},
			Description: "Admin user list with password hashes and PII export without authentication",
			CWE:         "CWE-359",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "backup-download",
			Name:        "Unauthenticated Backup Download",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/dashboard/backup/download", "/vuln/dashboard/backup/config"},
			Description: "Database backup files downloadable without authentication",
			CWE:         "CWE-552",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "insecure-settings",
			Name:        "Insecure Settings Panel",
			Severity:    "high",
			Endpoints:   []string{"/vuln/settings/", "/vuln/settings/general", "/vuln/settings/security", "/vuln/settings/update", "/vuln/settings/import", "/vuln/settings/webhook"},
			Description: "Configuration panel accessible without authentication, allows modification",
			CWE:         "CWE-306",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "database-creds",
			Name:        "Database Credentials Exposed",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/settings/database", "/vuln/settings/storage"},
			Description: "Database connection strings with credentials in plaintext",
			CWE:         "CWE-312",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "email-creds",
			Name:        "Email Credentials Exposed",
			Severity:    "high",
			Endpoints:   []string{"/vuln/settings/email"},
			Description: "SMTP credentials and email configuration in plaintext",
			CWE:         "CWE-312",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "integration-keys",
			Name:        "Integration API Keys Exposed",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/settings/integrations"},
			Description: "Third-party API keys (Stripe, AWS, SendGrid) exposed without auth",
			CWE:         "CWE-312",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
		{
			ID:          "audit-log",
			Name:        "Audit Log Exposed",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/settings/audit", "/vuln/settings/audit/export", "/vuln/settings/changelog"},
			Description: "Security audit events and changelog visible without authentication",
			CWE:         "CWE-200",
			OWASP:       "A01:2021",
			Detectable:  true,
		},
		{
			ID:          "feature-flags-secrets",
			Name:        "Feature Flags with Secrets",
			Severity:    "high",
			Endpoints:   []string{"/vuln/settings/flags", "/vuln/settings/flags/update"},
			Description: "Internal feature flags with secret values exposed and modifiable",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "service-credentials",
			Name:        "Service Credentials Exposed",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/settings/credentials", "/vuln/settings/certificates", "/vuln/settings/tokens"},
			Description: "Cloud provider access keys, SSL private keys, and admin API tokens exposed",
			CWE:         "CWE-798",
			OWASP:       "A02:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// OWASP API Security Top 10 (2023)
// ---------------------------------------------------------------------------

func apiSecurityVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "apisec-1",
			Name:        "API1 - Broken Object Level Authorization",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/api-sec/api1", "/vuln/api-sec/api1/user-id-enum", "/vuln/api-sec/api1/idor", "/vuln/api-sec/api1/object-traversal"},
			Description: "API endpoints allow accessing objects belonging to other users by manipulating IDs",
			CWE:         "CWE-639",
			OWASP:       "API1:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-2",
			Name:        "API2 - Broken Authentication",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/api-sec/api2", "/vuln/api-sec/api2/weak-token", "/vuln/api-sec/api2/no-rate-limit", "/vuln/api-sec/api2/credential-stuffing"},
			Description: "Authentication mechanisms are weak or improperly implemented allowing unauthorized access",
			CWE:         "CWE-287",
			OWASP:       "API2:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-3",
			Name:        "API3 - Broken Object Property Level Authorization",
			Severity:    "high",
			Endpoints:   []string{"/vuln/api-sec/api3", "/vuln/api-sec/api3/mass-assignment", "/vuln/api-sec/api3/excessive-data", "/vuln/api-sec/api3/property-tampering"},
			Description: "API exposes or allows modification of object properties that should be restricted",
			CWE:         "CWE-915",
			OWASP:       "API3:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-4",
			Name:        "API4 - Unrestricted Resource Consumption",
			Severity:    "high",
			Endpoints:   []string{"/vuln/api-sec/api4", "/vuln/api-sec/api4/no-rate-limit", "/vuln/api-sec/api4/large-payload", "/vuln/api-sec/api4/batch-abuse"},
			Description: "API does not limit resource consumption allowing denial of service",
			CWE:         "CWE-770",
			OWASP:       "API4:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-5",
			Name:        "API5 - Broken Function Level Authorization",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/api-sec/api5", "/vuln/api-sec/api5/admin-endpoint", "/vuln/api-sec/api5/privilege-escalation", "/vuln/api-sec/api5/method-tampering"},
			Description: "Administrative functions accessible to regular users through API endpoints",
			CWE:         "CWE-285",
			OWASP:       "API5:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-6",
			Name:        "API6 - Unrestricted Access to Sensitive Business Flows",
			Severity:    "high",
			Endpoints:   []string{"/vuln/api-sec/api6", "/vuln/api-sec/api6/purchase-abuse", "/vuln/api-sec/api6/referral-abuse", "/vuln/api-sec/api6/comment-spam"},
			Description: "Business-critical flows lack protections against automated abuse",
			CWE:         "CWE-799",
			OWASP:       "API6:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-7",
			Name:        "API7 - Server Side Request Forgery",
			Severity:    "high",
			Endpoints:   []string{"/vuln/api-sec/api7", "/vuln/api-sec/api7/ssrf-fetch", "/vuln/api-sec/api7/ssrf-redirect", "/vuln/api-sec/api7/ssrf-internal"},
			Description: "API accepts user-supplied URLs and fetches them server-side without validation",
			CWE:         "CWE-918",
			OWASP:       "API7:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-8",
			Name:        "API8 - Security Misconfiguration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/api-sec/api8", "/vuln/api-sec/api8/cors-wildcard", "/vuln/api-sec/api8/verbose-errors", "/vuln/api-sec/api8/missing-headers"},
			Description: "API is misconfigured with permissive CORS, verbose errors, or missing security headers",
			CWE:         "CWE-16",
			OWASP:       "API8:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-9",
			Name:        "API9 - Improper Inventory Management",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/api-sec/api9", "/vuln/api-sec/api9/old-version", "/vuln/api-sec/api9/shadow-api", "/vuln/api-sec/api9/undocumented"},
			Description: "Deprecated or undocumented API versions remain accessible and unmonitored",
			CWE:         "CWE-1059",
			OWASP:       "API9:2023",
			Detectable:  true,
		},
		{
			ID:          "apisec-10",
			Name:        "API10 - Unsafe Consumption of APIs",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/api-sec/api10", "/vuln/api-sec/api10/unvalidated-redirect", "/vuln/api-sec/api10/third-party-trust", "/vuln/api-sec/api10/data-injection"},
			Description: "API blindly trusts data from third-party APIs without validation or sanitization",
			CWE:         "CWE-20",
			OWASP:       "API10:2023",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Modern OWASP: LLM Top 10, CI/CD Top 10, Cloud-Native Top 10
// ---------------------------------------------------------------------------

func modernVulns() []VulnCategory {
	return []VulnCategory{
		// --- LLM Top 10 ---
		{
			ID:          "llm-01",
			Name:        "LLM01 - Prompt Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/llm/prompt-injection", "/vuln/llm/prompt-injection/direct", "/vuln/llm/prompt-injection/indirect", "/vuln/llm/prompt-injection/jailbreak"},
			Description: "LLM accepts crafted prompts that override system instructions or inject malicious context",
			CWE:         "CWE-77",
			OWASP:       "LLM01:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-02",
			Name:        "LLM02 - Sensitive Information Disclosure",
			Severity:    "high",
			Endpoints:   []string{"/vuln/llm/sensitive-disclosure", "/vuln/llm/sensitive-disclosure/training-data", "/vuln/llm/sensitive-disclosure/pii-leak", "/vuln/llm/sensitive-disclosure/system-prompt"},
			Description: "LLM reveals sensitive training data, PII, or system prompts in responses",
			CWE:         "CWE-200",
			OWASP:       "LLM02:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-03",
			Name:        "LLM03 - Supply Chain Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/llm/supply-chain", "/vuln/llm/supply-chain/poisoned-model", "/vuln/llm/supply-chain/malicious-plugin", "/vuln/llm/supply-chain/tainted-dataset"},
			Description: "LLM supply chain compromised through poisoned models, plugins, or training data",
			CWE:         "CWE-1357",
			OWASP:       "LLM03:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-04",
			Name:        "LLM04 - Data and Model Poisoning",
			Severity:    "high",
			Endpoints:   []string{"/vuln/llm/data-poisoning", "/vuln/llm/data-poisoning/training-manipulation", "/vuln/llm/data-poisoning/feedback-loop", "/vuln/llm/data-poisoning/backdoor"},
			Description: "Training data or model weights manipulated to produce biased or malicious outputs",
			CWE:         "CWE-1039",
			OWASP:       "LLM04:2025",
			Detectable:  false,
		},
		{
			ID:          "llm-05",
			Name:        "LLM05 - Improper Output Handling",
			Severity:    "high",
			Endpoints:   []string{"/vuln/llm/output-handling", "/vuln/llm/output-handling/xss-via-llm", "/vuln/llm/output-handling/code-exec", "/vuln/llm/output-handling/unescaped-render"},
			Description: "LLM output is rendered or executed without sanitization leading to injection attacks",
			CWE:         "CWE-79",
			OWASP:       "LLM05:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-06",
			Name:        "LLM06 - Excessive Agency",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/llm/excessive-agency", "/vuln/llm/excessive-agency/unrestricted-tools", "/vuln/llm/excessive-agency/auto-execute", "/vuln/llm/excessive-agency/over-permissioned"},
			Description: "LLM granted excessive permissions to perform actions without human approval",
			CWE:         "CWE-250",
			OWASP:       "LLM06:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-07",
			Name:        "LLM07 - System Prompt Leakage",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/llm/system-prompt-leak", "/vuln/llm/system-prompt-leak/extraction", "/vuln/llm/system-prompt-leak/side-channel", "/vuln/llm/system-prompt-leak/meta-prompt"},
			Description: "System prompts containing sensitive business logic or secrets can be extracted",
			CWE:         "CWE-200",
			OWASP:       "LLM07:2025",
			Detectable:  true,
		},
		{
			ID:          "llm-08",
			Name:        "LLM08 - Vector and Embedding Weaknesses",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/llm/vector-weakness", "/vuln/llm/vector-weakness/embedding-injection", "/vuln/llm/vector-weakness/rag-poisoning", "/vuln/llm/vector-weakness/similarity-abuse"},
			Description: "Vector databases and embeddings manipulated to inject malicious context into RAG",
			CWE:         "CWE-20",
			OWASP:       "LLM08:2025",
			Detectable:  false,
		},
		{
			ID:          "llm-09",
			Name:        "LLM09 - Misinformation",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/llm/misinformation", "/vuln/llm/misinformation/hallucination", "/vuln/llm/misinformation/fabricated-ref", "/vuln/llm/misinformation/confident-wrong"},
			Description: "LLM generates plausible but factually incorrect information with high confidence",
			CWE:         "CWE-1007",
			OWASP:       "LLM09:2025",
			Detectable:  false,
		},
		{
			ID:          "llm-10",
			Name:        "LLM10 - Unbounded Consumption",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/llm/unbounded-consumption", "/vuln/llm/unbounded-consumption/token-flood", "/vuln/llm/unbounded-consumption/recursive-prompt", "/vuln/llm/unbounded-consumption/resource-exhaust"},
			Description: "LLM endpoints lack limits on token usage, recursion depth, or request frequency",
			CWE:         "CWE-770",
			OWASP:       "LLM10:2025",
			Detectable:  true,
		},
		// --- CI/CD Top 10 ---
		{
			ID:          "cicd-01",
			Name:        "CICD-SEC-1 - Insufficient Flow Control Mechanisms",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cicd/insufficient-flow-control", "/vuln/cicd/insufficient-flow-control/no-approval", "/vuln/cicd/insufficient-flow-control/bypass-review", "/vuln/cicd/insufficient-flow-control/auto-merge"},
			Description: "CI/CD pipelines lack proper approval gates allowing unauthorized code to reach production",
			CWE:         "CWE-284",
			OWASP:       "CICD-SEC-1",
			Detectable:  true,
		},
		{
			ID:          "cicd-02",
			Name:        "CICD-SEC-2 - Inadequate Identity and Access Management",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cicd/iam-weakness", "/vuln/cicd/iam-weakness/shared-credentials", "/vuln/cicd/iam-weakness/excessive-perms", "/vuln/cicd/iam-weakness/no-mfa"},
			Description: "CI/CD identities use shared credentials, excessive permissions, or lack MFA",
			CWE:         "CWE-269",
			OWASP:       "CICD-SEC-2",
			Detectable:  true,
		},
		{
			ID:          "cicd-03",
			Name:        "CICD-SEC-3 - Dependency Chain Abuse",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cicd/dependency-chain", "/vuln/cicd/dependency-chain/typosquatting", "/vuln/cicd/dependency-chain/dependency-confusion", "/vuln/cicd/dependency-chain/compromised-package"},
			Description: "Build process pulls malicious dependencies through confusion, typosquatting, or compromise",
			CWE:         "CWE-1357",
			OWASP:       "CICD-SEC-3",
			Detectable:  true,
		},
		{
			ID:          "cicd-04",
			Name:        "CICD-SEC-4 - Poisoned Pipeline Execution",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cicd/poisoned-pipeline", "/vuln/cicd/poisoned-pipeline/malicious-pr", "/vuln/cicd/poisoned-pipeline/config-injection", "/vuln/cicd/poisoned-pipeline/script-tampering"},
			Description: "Attackers inject malicious code into CI/CD pipeline definitions via pull requests",
			CWE:         "CWE-94",
			OWASP:       "CICD-SEC-4",
			Detectable:  true,
		},
		{
			ID:          "cicd-05",
			Name:        "CICD-SEC-5 - Insufficient PBAC",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cicd/insufficient-pbac", "/vuln/cicd/insufficient-pbac/shared-runners", "/vuln/cicd/insufficient-pbac/no-sandbox", "/vuln/cicd/insufficient-pbac/cross-project"},
			Description: "Pipeline-based access controls are insufficient allowing cross-project access",
			CWE:         "CWE-284",
			OWASP:       "CICD-SEC-5",
			Detectable:  true,
		},
		{
			ID:          "cicd-06",
			Name:        "CICD-SEC-6 - Insufficient Credential Hygiene",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cicd/credential-hygiene", "/vuln/cicd/credential-hygiene/hardcoded-secrets", "/vuln/cicd/credential-hygiene/unrotated-tokens", "/vuln/cicd/credential-hygiene/logs-exposure"},
			Description: "Credentials hardcoded in pipeline configs, unrotated, or exposed in build logs",
			CWE:         "CWE-798",
			OWASP:       "CICD-SEC-6",
			Detectable:  true,
		},
		{
			ID:          "cicd-07",
			Name:        "CICD-SEC-7 - Insecure System Configuration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/cicd/insecure-config", "/vuln/cicd/insecure-config/debug-enabled", "/vuln/cicd/insecure-config/default-creds", "/vuln/cicd/insecure-config/open-registration"},
			Description: "CI/CD systems run with debug mode, default credentials, or open registration",
			CWE:         "CWE-16",
			OWASP:       "CICD-SEC-7",
			Detectable:  true,
		},
		{
			ID:          "cicd-08",
			Name:        "CICD-SEC-8 - Ungoverned Usage of Third-Party Services",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/cicd/third-party-services", "/vuln/cicd/third-party-services/unvetted-actions", "/vuln/cicd/third-party-services/oauth-overscope", "/vuln/cicd/third-party-services/marketplace-risk"},
			Description: "Third-party CI/CD integrations and marketplace actions used without vetting",
			CWE:         "CWE-829",
			OWASP:       "CICD-SEC-8",
			Detectable:  true,
		},
		{
			ID:          "cicd-09",
			Name:        "CICD-SEC-9 - Improper Artifact Integrity Validation",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cicd/artifact-integrity", "/vuln/cicd/artifact-integrity/unsigned-artifacts", "/vuln/cicd/artifact-integrity/no-checksum", "/vuln/cicd/artifact-integrity/registry-tampering"},
			Description: "Build artifacts deployed without signature verification or integrity checks",
			CWE:         "CWE-354",
			OWASP:       "CICD-SEC-9",
			Detectable:  true,
		},
		{
			ID:          "cicd-10",
			Name:        "CICD-SEC-10 - Insufficient Logging and Visibility",
			Severity:    "low",
			Endpoints:   []string{"/vuln/cicd/insufficient-logging", "/vuln/cicd/insufficient-logging/no-audit-trail", "/vuln/cicd/insufficient-logging/blind-spots", "/vuln/cicd/insufficient-logging/no-alerting"},
			Description: "CI/CD activities lack adequate logging, audit trails, and alerting mechanisms",
			CWE:         "CWE-778",
			OWASP:       "CICD-SEC-10",
			Detectable:  true,
		},
		// --- Cloud-Native Top 10 ---
		{
			ID:          "cloud-01",
			Name:        "CNS-01 - Insecure Cloud/Container/Orchestration Defaults",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cloud/insecure-defaults", "/vuln/cloud/insecure-defaults/public-storage", "/vuln/cloud/insecure-defaults/permissive-network", "/vuln/cloud/insecure-defaults/no-encryption"},
			Description: "Cloud services deployed with insecure default configurations such as public buckets",
			CWE:         "CWE-1188",
			OWASP:       "CNS-01",
			Detectable:  true,
		},
		{
			ID:          "cloud-02",
			Name:        "CNS-02 - Insecure Secrets Management",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cloud/insecure-secrets", "/vuln/cloud/insecure-secrets/env-vars", "/vuln/cloud/insecure-secrets/unencrypted-storage", "/vuln/cloud/insecure-secrets/hardcoded-keys"},
			Description: "Secrets stored in environment variables, unencrypted, or hardcoded in container images",
			CWE:         "CWE-798",
			OWASP:       "CNS-02",
			Detectable:  true,
		},
		{
			ID:          "cloud-03",
			Name:        "CNS-03 - Overly Permissive Network Policies",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cloud/permissive-network", "/vuln/cloud/permissive-network/open-ingress", "/vuln/cloud/permissive-network/no-segmentation", "/vuln/cloud/permissive-network/flat-network"},
			Description: "Cloud network policies allow unrestricted ingress/egress with no segmentation",
			CWE:         "CWE-284",
			OWASP:       "CNS-03",
			Detectable:  true,
		},
		{
			ID:          "cloud-04",
			Name:        "CNS-04 - Using Components with Known Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cloud/known-vulns", "/vuln/cloud/known-vulns/outdated-base-image", "/vuln/cloud/known-vulns/unpatched-runtime", "/vuln/cloud/known-vulns/eol-component"},
			Description: "Cloud workloads use container images or runtimes with known CVEs",
			CWE:         "CWE-1035",
			OWASP:       "CNS-04",
			Detectable:  true,
		},
		{
			ID:          "cloud-05",
			Name:        "CNS-05 - Inadequate Identity and Access Management",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cloud/iam-weakness", "/vuln/cloud/iam-weakness/over-privileged-role", "/vuln/cloud/iam-weakness/no-least-privilege", "/vuln/cloud/iam-weakness/stale-credentials"},
			Description: "Cloud IAM roles are over-privileged, stale, or not following least privilege principle",
			CWE:         "CWE-269",
			OWASP:       "CNS-05",
			Detectable:  true,
		},
		{
			ID:          "cloud-06",
			Name:        "CNS-06 - Lack of Cloud Security Architecture",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/cloud/no-sec-architecture", "/vuln/cloud/no-sec-architecture/no-waf", "/vuln/cloud/no-sec-architecture/no-ddos-protection", "/vuln/cloud/no-sec-architecture/single-region"},
			Description: "Cloud deployment lacks WAF, DDoS protection, or multi-region resilience",
			CWE:         "CWE-693",
			OWASP:       "CNS-06",
			Detectable:  true,
		},
		{
			ID:          "cloud-07",
			Name:        "CNS-07 - Insufficient Data Protection",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cloud/data-protection", "/vuln/cloud/data-protection/no-encryption-at-rest", "/vuln/cloud/data-protection/no-encryption-transit", "/vuln/cloud/data-protection/weak-kms"},
			Description: "Data stored or transmitted in cloud without encryption or with weak key management",
			CWE:         "CWE-311",
			OWASP:       "CNS-07",
			Detectable:  true,
		},
		{
			ID:          "cloud-08",
			Name:        "CNS-08 - Insecure Workload Configuration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/cloud/workload-config", "/vuln/cloud/workload-config/privileged-container", "/vuln/cloud/workload-config/root-user", "/vuln/cloud/workload-config/no-resource-limits"},
			Description: "Workloads run as root, privileged, or without resource limits",
			CWE:         "CWE-250",
			OWASP:       "CNS-08",
			Detectable:  true,
		},
		{
			ID:          "cloud-09",
			Name:        "CNS-09 - Insufficient Logging and Monitoring",
			Severity:    "low",
			Endpoints:   []string{"/vuln/cloud/logging-monitoring", "/vuln/cloud/logging-monitoring/no-cloudtrail", "/vuln/cloud/logging-monitoring/no-alerting", "/vuln/cloud/logging-monitoring/log-gaps"},
			Description: "Cloud environments lack comprehensive logging, monitoring, and alerting",
			CWE:         "CWE-778",
			OWASP:       "CNS-09",
			Detectable:  true,
		},
		{
			ID:          "cloud-10",
			Name:        "CNS-10 - Insecure API Server Configuration",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/cloud/api-server", "/vuln/cloud/api-server/anonymous-auth", "/vuln/cloud/api-server/exposed-dashboard", "/vuln/cloud/api-server/no-tls"},
			Description: "Cloud API servers exposed with anonymous auth, no TLS, or public dashboards",
			CWE:         "CWE-16",
			OWASP:       "CNS-10",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Infrastructure: Serverless Top 10, Docker Top 10, K8s Top 10
// ---------------------------------------------------------------------------

func infrastructureVulns() []VulnCategory {
	return []VulnCategory{
		// --- Serverless Top 10 ---
		{
			ID:          "sls-01",
			Name:        "SLS-01 - Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/serverless/injection", "/vuln/serverless/injection/event-injection", "/vuln/serverless/injection/sql-via-trigger", "/vuln/serverless/injection/command-injection"},
			Description: "Serverless functions vulnerable to injection via event data from queues, storage, or APIs",
			CWE:         "CWE-94",
			OWASP:       "SLS-01",
			Detectable:  true,
		},
		{
			ID:          "sls-02",
			Name:        "SLS-02 - Broken Authentication",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/serverless/broken-auth", "/vuln/serverless/broken-auth/missing-auth", "/vuln/serverless/broken-auth/weak-token", "/vuln/serverless/broken-auth/shared-api-key"},
			Description: "Serverless functions lack authentication or use shared/weak credentials",
			CWE:         "CWE-287",
			OWASP:       "SLS-02",
			Detectable:  true,
		},
		{
			ID:          "sls-03",
			Name:        "SLS-03 - Insecure Serverless Deployment Configuration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/serverless/deployment-config", "/vuln/serverless/deployment-config/public-function", "/vuln/serverless/deployment-config/over-permissioned", "/vuln/serverless/deployment-config/no-vpc"},
			Description: "Functions deployed with public access, excessive IAM permissions, or no VPC isolation",
			CWE:         "CWE-16",
			OWASP:       "SLS-03",
			Detectable:  true,
		},
		{
			ID:          "sls-04",
			Name:        "SLS-04 - Over-Privileged Function Permissions",
			Severity:    "high",
			Endpoints:   []string{"/vuln/serverless/over-privileged", "/vuln/serverless/over-privileged/admin-role", "/vuln/serverless/over-privileged/wildcard-policy", "/vuln/serverless/over-privileged/cross-account"},
			Description: "Serverless functions granted wildcard IAM policies or cross-account admin access",
			CWE:         "CWE-250",
			OWASP:       "SLS-04",
			Detectable:  true,
		},
		{
			ID:          "sls-05",
			Name:        "SLS-05 - Inadequate Function Monitoring and Logging",
			Severity:    "low",
			Endpoints:   []string{"/vuln/serverless/monitoring", "/vuln/serverless/monitoring/no-tracing", "/vuln/serverless/monitoring/missing-logs", "/vuln/serverless/monitoring/no-alerting"},
			Description: "Serverless functions lack distributed tracing, logging, and anomaly alerting",
			CWE:         "CWE-778",
			OWASP:       "SLS-05",
			Detectable:  true,
		},
		{
			ID:          "sls-06",
			Name:        "SLS-06 - Insecure Third-Party Dependencies",
			Severity:    "high",
			Endpoints:   []string{"/vuln/serverless/third-party-deps", "/vuln/serverless/third-party-deps/vulnerable-layer", "/vuln/serverless/third-party-deps/unvetted-package", "/vuln/serverless/third-party-deps/outdated-runtime"},
			Description: "Lambda layers or function packages include vulnerable or unvetted third-party code",
			CWE:         "CWE-1035",
			OWASP:       "SLS-06",
			Detectable:  true,
		},
		{
			ID:          "sls-07",
			Name:        "SLS-07 - Insecure Application Secrets Storage",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/serverless/secrets-storage", "/vuln/serverless/secrets-storage/env-var-secrets", "/vuln/serverless/secrets-storage/hardcoded-key", "/vuln/serverless/secrets-storage/unencrypted-config"},
			Description: "Secrets stored in plaintext environment variables or hardcoded in function code",
			CWE:         "CWE-798",
			OWASP:       "SLS-07",
			Detectable:  true,
		},
		{
			ID:          "sls-08",
			Name:        "SLS-08 - Denial of Service and Financial Resource Exhaustion",
			Severity:    "high",
			Endpoints:   []string{"/vuln/serverless/dos-financial", "/vuln/serverless/dos-financial/infinite-loop", "/vuln/serverless/dos-financial/no-concurrency-limit", "/vuln/serverless/dos-financial/recursive-trigger"},
			Description: "Functions vulnerable to infinite loops, recursive triggers, or unbounded concurrency",
			CWE:         "CWE-400",
			OWASP:       "SLS-08",
			Detectable:  true,
		},
		{
			ID:          "sls-09",
			Name:        "SLS-09 - Serverless Function Execution Flow Manipulation",
			Severity:    "high",
			Endpoints:   []string{"/vuln/serverless/flow-manipulation", "/vuln/serverless/flow-manipulation/state-tampering", "/vuln/serverless/flow-manipulation/order-bypass", "/vuln/serverless/flow-manipulation/race-condition"},
			Description: "Attackers manipulate serverless execution flow through state tampering or race conditions",
			CWE:         "CWE-362",
			OWASP:       "SLS-09",
			Detectable:  true,
		},
		{
			ID:          "sls-10",
			Name:        "SLS-10 - Improper Exception Handling and Verbose Error Messages",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/serverless/error-handling", "/vuln/serverless/error-handling/stack-trace-leak", "/vuln/serverless/error-handling/verbose-error", "/vuln/serverless/error-handling/unhandled-exception"},
			Description: "Serverless functions leak stack traces, internal paths, or sensitive data in errors",
			CWE:         "CWE-209",
			OWASP:       "SLS-10",
			Detectable:  true,
		},
		// --- Docker Top 10 ---
		{
			ID:          "docker-01",
			Name:        "Docker-01 - Host Network Exposure",
			Severity:    "high",
			Endpoints:   []string{"/vuln/docker/host-network", "/vuln/docker/host-network/host-mode", "/vuln/docker/host-network/port-binding", "/vuln/docker/host-network/bridge-escape"},
			Description: "Containers run with host network mode exposing host services and enabling escapes",
			CWE:         "CWE-668",
			OWASP:       "Docker-01",
			Detectable:  true,
		},
		{
			ID:          "docker-02",
			Name:        "Docker-02 - Image Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/docker/image-vuln", "/vuln/docker/image-vuln/outdated-base", "/vuln/docker/image-vuln/known-cve", "/vuln/docker/image-vuln/no-scan"},
			Description: "Container images use outdated base images with known CVEs and no scanning policy",
			CWE:         "CWE-1035",
			OWASP:       "Docker-02",
			Detectable:  true,
		},
		{
			ID:          "docker-03",
			Name:        "Docker-03 - Privileged Container",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/docker/privileged", "/vuln/docker/privileged/full-privileges", "/vuln/docker/privileged/cap-add-all", "/vuln/docker/privileged/device-mount"},
			Description: "Containers run in privileged mode with full host capabilities enabling breakout",
			CWE:         "CWE-250",
			OWASP:       "Docker-03",
			Detectable:  true,
		},
		{
			ID:          "docker-04",
			Name:        "Docker-04 - Sensitive Data in Image",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/docker/sensitive-data", "/vuln/docker/sensitive-data/secrets-in-layer", "/vuln/docker/sensitive-data/hardcoded-creds", "/vuln/docker/sensitive-data/exposed-env"},
			Description: "Docker images contain hardcoded secrets, credentials, or sensitive data in layers",
			CWE:         "CWE-798",
			OWASP:       "Docker-04",
			Detectable:  true,
		},
		{
			ID:          "docker-05",
			Name:        "Docker-05 - Insecure Registry",
			Severity:    "high",
			Endpoints:   []string{"/vuln/docker/insecure-registry", "/vuln/docker/insecure-registry/no-tls", "/vuln/docker/insecure-registry/anonymous-push", "/vuln/docker/insecure-registry/no-signing"},
			Description: "Container registry allows anonymous push, lacks TLS, or has no image signing",
			CWE:         "CWE-311",
			OWASP:       "Docker-05",
			Detectable:  true,
		},
		{
			ID:          "docker-06",
			Name:        "Docker-06 - Unprotected Docker Socket",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/docker/socket-exposure", "/vuln/docker/socket-exposure/mounted-sock", "/vuln/docker/socket-exposure/tcp-exposed", "/vuln/docker/socket-exposure/no-auth"},
			Description: "Docker socket mounted into containers or exposed via TCP without authentication",
			CWE:         "CWE-668",
			OWASP:       "Docker-06",
			Detectable:  true,
		},
		{
			ID:          "docker-07",
			Name:        "Docker-07 - Writable Root Filesystem",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/docker/writable-root", "/vuln/docker/writable-root/no-readonly", "/vuln/docker/writable-root/world-writable", "/vuln/docker/writable-root/tmpfs-abuse"},
			Description: "Containers run with writable root filesystem allowing persistent modifications",
			CWE:         "CWE-732",
			OWASP:       "Docker-07",
			Detectable:  true,
		},
		{
			ID:          "docker-08",
			Name:        "Docker-08 - Missing Resource Limits",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/docker/no-limits", "/vuln/docker/no-limits/no-cpu-limit", "/vuln/docker/no-limits/no-memory-limit", "/vuln/docker/no-limits/no-pids-limit"},
			Description: "Containers run without CPU, memory, or PID limits enabling resource exhaustion",
			CWE:         "CWE-770",
			OWASP:       "Docker-08",
			Detectable:  true,
		},
		{
			ID:          "docker-09",
			Name:        "Docker-09 - Running as Root",
			Severity:    "high",
			Endpoints:   []string{"/vuln/docker/root-user", "/vuln/docker/root-user/no-user-directive", "/vuln/docker/root-user/uid-zero", "/vuln/docker/root-user/setuid-binaries"},
			Description: "Containers run as root user increasing impact of container escapes",
			CWE:         "CWE-250",
			OWASP:       "Docker-09",
			Detectable:  true,
		},
		{
			ID:          "docker-10",
			Name:        "Docker-10 - Insufficient Logging and Monitoring",
			Severity:    "low",
			Endpoints:   []string{"/vuln/docker/logging", "/vuln/docker/logging/no-log-driver", "/vuln/docker/logging/missing-audit", "/vuln/docker/logging/no-runtime-detection"},
			Description: "Container runtime events not logged, no audit trail, no runtime anomaly detection",
			CWE:         "CWE-778",
			OWASP:       "Docker-10",
			Detectable:  true,
		},
		// --- Kubernetes Top 10 ---
		{
			ID:          "k8s-01",
			Name:        "K8S-01 - Insecure Workload Configurations",
			Severity:    "high",
			Endpoints:   []string{"/vuln/k8s/insecure-workload", "/vuln/k8s/insecure-workload/privileged-pod", "/vuln/k8s/insecure-workload/host-pid", "/vuln/k8s/insecure-workload/no-security-context"},
			Description: "Kubernetes pods run privileged, with host PID namespace, or no security context",
			CWE:         "CWE-250",
			OWASP:       "K8S-01",
			Detectable:  true,
		},
		{
			ID:          "k8s-02",
			Name:        "K8S-02 - Overly Permissive RBAC",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/k8s/overly-permissive-rbac", "/vuln/k8s/overly-permissive-rbac/cluster-admin", "/vuln/k8s/overly-permissive-rbac/wildcard-verbs", "/vuln/k8s/overly-permissive-rbac/default-sa"},
			Description: "RBAC roles with cluster-admin, wildcard verbs, or default service accounts abused",
			CWE:         "CWE-269",
			OWASP:       "K8S-02",
			Detectable:  true,
		},
		{
			ID:          "k8s-03",
			Name:        "K8S-03 - Supply Chain Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/k8s/supply-chain", "/vuln/k8s/supply-chain/untrusted-image", "/vuln/k8s/supply-chain/no-image-policy", "/vuln/k8s/supply-chain/compromised-helm"},
			Description: "Clusters pull untrusted images, lack admission policies, or use compromised Helm charts",
			CWE:         "CWE-1357",
			OWASP:       "K8S-03",
			Detectable:  true,
		},
		{
			ID:          "k8s-04",
			Name:        "K8S-04 - Network Policy Enforcement",
			Severity:    "high",
			Endpoints:   []string{"/vuln/k8s/network-policy", "/vuln/k8s/network-policy/no-network-policy", "/vuln/k8s/network-policy/allow-all-ingress", "/vuln/k8s/network-policy/no-egress-control"},
			Description: "Kubernetes cluster has no network policies or permits all ingress/egress traffic",
			CWE:         "CWE-284",
			OWASP:       "K8S-04",
			Detectable:  true,
		},
		{
			ID:          "k8s-05",
			Name:        "K8S-05 - Secrets Management",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/k8s/secrets-mgmt", "/vuln/k8s/secrets-mgmt/base64-secrets", "/vuln/k8s/secrets-mgmt/etcd-unencrypted", "/vuln/k8s/secrets-mgmt/mounted-secrets"},
			Description: "Kubernetes secrets stored as base64 in etcd, unencrypted, or over-mounted to pods",
			CWE:         "CWE-311",
			OWASP:       "K8S-05",
			Detectable:  true,
		},
		{
			ID:          "k8s-06",
			Name:        "K8S-06 - Exposed Dashboard / API Server",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/k8s/exposed-dashboard", "/vuln/k8s/exposed-dashboard/public-dashboard", "/vuln/k8s/exposed-dashboard/anonymous-api", "/vuln/k8s/exposed-dashboard/no-tls"},
			Description: "Kubernetes dashboard or API server publicly accessible without authentication",
			CWE:         "CWE-668",
			OWASP:       "K8S-06",
			Detectable:  true,
		},
		{
			ID:          "k8s-07",
			Name:        "K8S-07 - Missing Pod Security Standards",
			Severity:    "high",
			Endpoints:   []string{"/vuln/k8s/pod-security", "/vuln/k8s/pod-security/no-pss", "/vuln/k8s/pod-security/unrestricted-ns", "/vuln/k8s/pod-security/no-admission-controller"},
			Description: "Cluster lacks Pod Security Standards enforcement or admission controllers",
			CWE:         "CWE-693",
			OWASP:       "K8S-07",
			Detectable:  true,
		},
		{
			ID:          "k8s-08",
			Name:        "K8S-08 - Resource Exhaustion",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/k8s/resource-exhaustion", "/vuln/k8s/resource-exhaustion/no-limits", "/vuln/k8s/resource-exhaustion/no-quotas", "/vuln/k8s/resource-exhaustion/fork-bomb"},
			Description: "Pods deployed without resource limits or quotas enabling cluster-wide DoS",
			CWE:         "CWE-770",
			OWASP:       "K8S-08",
			Detectable:  true,
		},
		{
			ID:          "k8s-09",
			Name:        "K8S-09 - Insufficient Audit Logging",
			Severity:    "low",
			Endpoints:   []string{"/vuln/k8s/audit-logging", "/vuln/k8s/audit-logging/no-audit-policy", "/vuln/k8s/audit-logging/missing-events", "/vuln/k8s/audit-logging/no-siem"},
			Description: "Kubernetes audit logging disabled, incomplete, or not forwarded to SIEM",
			CWE:         "CWE-778",
			OWASP:       "K8S-09",
			Detectable:  true,
		},
		{
			ID:          "k8s-10",
			Name:        "K8S-10 - Vulnerable Components",
			Severity:    "high",
			Endpoints:   []string{"/vuln/k8s/vulnerable-components", "/vuln/k8s/vulnerable-components/outdated-kubelet", "/vuln/k8s/vulnerable-components/old-etcd", "/vuln/k8s/vulnerable-components/unpatched-cni"},
			Description: "Cluster runs outdated kubelet, etcd, or CNI plugins with known vulnerabilities",
			CWE:         "CWE-1035",
			OWASP:       "K8S-10",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// IoT Top 10, Desktop Top 10, Low-Code/No-Code Top 10
// ---------------------------------------------------------------------------

func iotDesktopVulns() []VulnCategory {
	return []VulnCategory{
		// --- IoT Top 10 ---
		{
			ID:          "iot-01",
			Name:        "IoT-01 - Weak, Guessable, or Hardcoded Passwords",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/iot/weak-passwords", "/vuln/iot/weak-passwords/default-creds", "/vuln/iot/weak-passwords/hardcoded", "/vuln/iot/weak-passwords/no-change-mechanism"},
			Description: "IoT devices ship with default, hardcoded, or easily guessable credentials",
			CWE:         "CWE-798",
			OWASP:       "IoT-01",
			Detectable:  true,
		},
		{
			ID:          "iot-02",
			Name:        "IoT-02 - Insecure Network Services",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/insecure-network", "/vuln/iot/insecure-network/open-ports", "/vuln/iot/insecure-network/telnet", "/vuln/iot/insecure-network/unencrypted-protocol"},
			Description: "IoT devices expose unnecessary network services like Telnet or unencrypted protocols",
			CWE:         "CWE-668",
			OWASP:       "IoT-02",
			Detectable:  true,
		},
		{
			ID:          "iot-03",
			Name:        "IoT-03 - Insecure Ecosystem Interfaces",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/insecure-interfaces", "/vuln/iot/insecure-interfaces/web-ui", "/vuln/iot/insecure-interfaces/cloud-api", "/vuln/iot/insecure-interfaces/mobile-app"},
			Description: "IoT web interfaces, cloud APIs, and companion apps lack proper authentication",
			CWE:         "CWE-306",
			OWASP:       "IoT-03",
			Detectable:  true,
		},
		{
			ID:          "iot-04",
			Name:        "IoT-04 - Lack of Secure Update Mechanism",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/iot/insecure-update", "/vuln/iot/insecure-update/no-ota", "/vuln/iot/insecure-update/unsigned-firmware", "/vuln/iot/insecure-update/no-rollback"},
			Description: "IoT firmware updates are unsigned, delivered over HTTP, or have no update mechanism",
			CWE:         "CWE-494",
			OWASP:       "IoT-04",
			Detectable:  true,
		},
		{
			ID:          "iot-05",
			Name:        "IoT-05 - Use of Insecure or Outdated Components",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/outdated-components", "/vuln/iot/outdated-components/old-kernel", "/vuln/iot/outdated-components/deprecated-lib", "/vuln/iot/outdated-components/eol-os"},
			Description: "IoT devices run end-of-life OS, deprecated libraries, or unpatched kernels",
			CWE:         "CWE-1035",
			OWASP:       "IoT-05",
			Detectable:  true,
		},
		{
			ID:          "iot-06",
			Name:        "IoT-06 - Insufficient Privacy Protection",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/privacy", "/vuln/iot/privacy/data-collection", "/vuln/iot/privacy/no-consent", "/vuln/iot/privacy/unencrypted-storage"},
			Description: "IoT devices collect personal data without consent or store it unencrypted",
			CWE:         "CWE-359",
			OWASP:       "IoT-06",
			Detectable:  true,
		},
		{
			ID:          "iot-07",
			Name:        "IoT-07 - Insecure Data Transfer and Storage",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/data-transfer", "/vuln/iot/data-transfer/plaintext-comms", "/vuln/iot/data-transfer/no-tls", "/vuln/iot/data-transfer/unencrypted-db"},
			Description: "IoT device data transmitted in plaintext or stored without encryption",
			CWE:         "CWE-319",
			OWASP:       "IoT-07",
			Detectable:  true,
		},
		{
			ID:          "iot-08",
			Name:        "IoT-08 - Lack of Device Management",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/iot/device-mgmt", "/vuln/iot/device-mgmt/no-inventory", "/vuln/iot/device-mgmt/no-decommission", "/vuln/iot/device-mgmt/orphaned-devices"},
			Description: "No device inventory, decommissioning process, or management of orphaned devices",
			CWE:         "CWE-1059",
			OWASP:       "IoT-08",
			Detectable:  false,
		},
		{
			ID:          "iot-09",
			Name:        "IoT-09 - Insecure Default Settings",
			Severity:    "high",
			Endpoints:   []string{"/vuln/iot/insecure-defaults", "/vuln/iot/insecure-defaults/open-debug", "/vuln/iot/insecure-defaults/permissive-firewall", "/vuln/iot/insecure-defaults/enabled-upnp"},
			Description: "IoT devices ship with debug ports open, UPnP enabled, or permissive firewall rules",
			CWE:         "CWE-1188",
			OWASP:       "IoT-09",
			Detectable:  true,
		},
		{
			ID:          "iot-10",
			Name:        "IoT-10 - Lack of Physical Hardening",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/iot/physical-hardening", "/vuln/iot/physical-hardening/exposed-jtag", "/vuln/iot/physical-hardening/uart-console", "/vuln/iot/physical-hardening/removable-storage"},
			Description: "IoT devices have exposed JTAG, UART, or removable storage enabling physical attacks",
			CWE:         "CWE-1263",
			OWASP:       "IoT-10",
			Detectable:  false,
		},
		// --- Desktop App Top 10 ---
		{
			ID:          "da-01",
			Name:        "DA-01 - Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/desktop/injection", "/vuln/desktop/injection/command-injection", "/vuln/desktop/injection/dll-injection", "/vuln/desktop/injection/sql-injection"},
			Description: "Desktop application vulnerable to command injection, DLL injection, or SQL injection",
			CWE:         "CWE-77",
			OWASP:       "DA-01",
			Detectable:  true,
		},
		{
			ID:          "da-02",
			Name:        "DA-02 - Broken Authentication and Session Management",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/broken-auth", "/vuln/desktop/broken-auth/stored-plaintext", "/vuln/desktop/broken-auth/no-lockout", "/vuln/desktop/broken-auth/weak-session"},
			Description: "Desktop app stores credentials in plaintext, lacks lockout, or has weak sessions",
			CWE:         "CWE-287",
			OWASP:       "DA-02",
			Detectable:  true,
		},
		{
			ID:          "da-03",
			Name:        "DA-03 - Insecure Data Storage",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/insecure-storage", "/vuln/desktop/insecure-storage/plaintext-config", "/vuln/desktop/insecure-storage/world-readable", "/vuln/desktop/insecure-storage/temp-files"},
			Description: "Sensitive data stored in plaintext config files, world-readable dirs, or temp files",
			CWE:         "CWE-922",
			OWASP:       "DA-03",
			Detectable:  true,
		},
		{
			ID:          "da-04",
			Name:        "DA-04 - Insufficient Cryptography",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/weak-crypto", "/vuln/desktop/weak-crypto/md5-hash", "/vuln/desktop/weak-crypto/ecb-mode", "/vuln/desktop/weak-crypto/hardcoded-key"},
			Description: "Desktop app uses weak crypto algorithms (MD5, ECB) or hardcoded encryption keys",
			CWE:         "CWE-327",
			OWASP:       "DA-04",
			Detectable:  true,
		},
		{
			ID:          "da-05",
			Name:        "DA-05 - Insecure Communication",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/insecure-comms", "/vuln/desktop/insecure-comms/no-tls", "/vuln/desktop/insecure-comms/cert-pinning-bypass", "/vuln/desktop/insecure-comms/http-fallback"},
			Description: "Desktop app communicates over HTTP, allows TLS downgrade, or lacks cert pinning",
			CWE:         "CWE-319",
			OWASP:       "DA-05",
			Detectable:  true,
		},
		{
			ID:          "da-06",
			Name:        "DA-06 - Improper Authorization",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/improper-authz", "/vuln/desktop/improper-authz/privilege-escalation", "/vuln/desktop/improper-authz/bypass-uac", "/vuln/desktop/improper-authz/insecure-ipc"},
			Description: "Desktop app allows privilege escalation, UAC bypass, or insecure IPC mechanisms",
			CWE:         "CWE-285",
			OWASP:       "DA-06",
			Detectable:  true,
		},
		{
			ID:          "da-07",
			Name:        "DA-07 - Poor Code Quality",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/desktop/code-quality", "/vuln/desktop/code-quality/buffer-overflow", "/vuln/desktop/code-quality/use-after-free", "/vuln/desktop/code-quality/race-condition"},
			Description: "Desktop app has buffer overflows, use-after-free, or race condition vulnerabilities",
			CWE:         "CWE-119",
			OWASP:       "DA-07",
			Detectable:  true,
		},
		{
			ID:          "da-08",
			Name:        "DA-08 - Code Tampering",
			Severity:    "high",
			Endpoints:   []string{"/vuln/desktop/code-tampering", "/vuln/desktop/code-tampering/no-signing", "/vuln/desktop/code-tampering/no-integrity-check", "/vuln/desktop/code-tampering/dll-sideloading"},
			Description: "Desktop app binaries unsigned, no integrity verification, or vulnerable to DLL sideloading",
			CWE:         "CWE-494",
			OWASP:       "DA-08",
			Detectable:  true,
		},
		{
			ID:          "da-09",
			Name:        "DA-09 - Reverse Engineering",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/desktop/reverse-engineering", "/vuln/desktop/reverse-engineering/no-obfuscation", "/vuln/desktop/reverse-engineering/debug-symbols", "/vuln/desktop/reverse-engineering/readable-strings"},
			Description: "Desktop app ships with debug symbols, no obfuscation, or readable embedded strings",
			CWE:         "CWE-693",
			OWASP:       "DA-09",
			Detectable:  true,
		},
		{
			ID:          "da-10",
			Name:        "DA-10 - Extraneous Functionality",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/desktop/extraneous", "/vuln/desktop/extraneous/hidden-backdoor", "/vuln/desktop/extraneous/debug-menu", "/vuln/desktop/extraneous/test-credentials"},
			Description: "Desktop app contains hidden backdoors, debug menus, or test credentials in production",
			CWE:         "CWE-489",
			OWASP:       "DA-10",
			Detectable:  true,
		},
		// --- Low-Code/No-Code Top 10 ---
		{
			ID:          "lc-01",
			Name:        "LC-01 - Account Impersonation",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/lowcode/account-impersonation", "/vuln/lowcode/account-impersonation/shared-connection", "/vuln/lowcode/account-impersonation/service-account-abuse", "/vuln/lowcode/account-impersonation/identity-spoofing"},
			Description: "Low-code platform allows user impersonation through shared connections or service accounts",
			CWE:         "CWE-287",
			OWASP:       "LC-01",
			Detectable:  true,
		},
		{
			ID:          "lc-02",
			Name:        "LC-02 - Authorization Misuse",
			Severity:    "high",
			Endpoints:   []string{"/vuln/lowcode/authz-misuse", "/vuln/lowcode/authz-misuse/over-permissioned-flow", "/vuln/lowcode/authz-misuse/privilege-escalation", "/vuln/lowcode/authz-misuse/bypass-approval"},
			Description: "Low-code automations run with excessive permissions or bypass approval workflows",
			CWE:         "CWE-269",
			OWASP:       "LC-02",
			Detectable:  true,
		},
		{
			ID:          "lc-03",
			Name:        "LC-03 - Data Leakage",
			Severity:    "high",
			Endpoints:   []string{"/vuln/lowcode/data-leakage", "/vuln/lowcode/data-leakage/uncontrolled-sharing", "/vuln/lowcode/data-leakage/log-exposure", "/vuln/lowcode/data-leakage/external-connector"},
			Description: "Low-code apps leak data through uncontrolled sharing, logs, or external connectors",
			CWE:         "CWE-200",
			OWASP:       "LC-03",
			Detectable:  true,
		},
		{
			ID:          "lc-04",
			Name:        "LC-04 - Authentication and Secure Communication Failures",
			Severity:    "high",
			Endpoints:   []string{"/vuln/lowcode/auth-failures", "/vuln/lowcode/auth-failures/no-mfa", "/vuln/lowcode/auth-failures/http-webhook", "/vuln/lowcode/auth-failures/weak-oauth"},
			Description: "Low-code platform lacks MFA, uses HTTP webhooks, or has weak OAuth implementation",
			CWE:         "CWE-287",
			OWASP:       "LC-04",
			Detectable:  true,
		},
		{
			ID:          "lc-05",
			Name:        "LC-05 - Security Misconfiguration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/lowcode/misconfig", "/vuln/lowcode/misconfig/default-settings", "/vuln/lowcode/misconfig/open-api", "/vuln/lowcode/misconfig/anonymous-access"},
			Description: "Low-code platform deployed with default settings, open APIs, or anonymous access",
			CWE:         "CWE-16",
			OWASP:       "LC-05",
			Detectable:  true,
		},
		{
			ID:          "lc-06",
			Name:        "LC-06 - Injection Handling Failures",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/lowcode/injection", "/vuln/lowcode/injection/formula-injection", "/vuln/lowcode/injection/expression-injection", "/vuln/lowcode/injection/sql-in-connector"},
			Description: "Low-code platform vulnerable to formula injection, expression injection, or SQL via connectors",
			CWE:         "CWE-94",
			OWASP:       "LC-06",
			Detectable:  true,
		},
		{
			ID:          "lc-07",
			Name:        "LC-07 - Vulnerable and Untrusted Components",
			Severity:    "high",
			Endpoints:   []string{"/vuln/lowcode/vulnerable-components", "/vuln/lowcode/vulnerable-components/marketplace-risk", "/vuln/lowcode/vulnerable-components/unvetted-connector", "/vuln/lowcode/vulnerable-components/outdated-plugin"},
			Description: "Low-code apps use unvetted marketplace components, connectors, or outdated plugins",
			CWE:         "CWE-1035",
			OWASP:       "LC-07",
			Detectable:  true,
		},
		{
			ID:          "lc-08",
			Name:        "LC-08 - Data and Secret Handling Failures",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/lowcode/secret-handling", "/vuln/lowcode/secret-handling/plaintext-secrets", "/vuln/lowcode/secret-handling/embedded-creds", "/vuln/lowcode/secret-handling/shared-vault"},
			Description: "Low-code platform stores secrets in plaintext, embeds credentials in flows, or shares vaults",
			CWE:         "CWE-798",
			OWASP:       "LC-08",
			Detectable:  true,
		},
		{
			ID:          "lc-09",
			Name:        "LC-09 - Asset Management Failures",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/lowcode/asset-mgmt", "/vuln/lowcode/asset-mgmt/shadow-apps", "/vuln/lowcode/asset-mgmt/orphaned-flows", "/vuln/lowcode/asset-mgmt/no-inventory"},
			Description: "Shadow apps, orphaned flows, and untracked automations proliferate without governance",
			CWE:         "CWE-1059",
			OWASP:       "LC-09",
			Detectable:  true,
		},
		{
			ID:          "lc-10",
			Name:        "LC-10 - Security Logging and Monitoring Failures",
			Severity:    "low",
			Endpoints:   []string{"/vuln/lowcode/logging", "/vuln/lowcode/logging/no-audit", "/vuln/lowcode/logging/missing-flow-logs", "/vuln/lowcode/logging/no-alerting"},
			Description: "Low-code platform lacks audit logging for automations, flow execution, and data access",
			CWE:         "CWE-778",
			OWASP:       "LC-10",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Mobile Top 10, Privacy Risks Top 10, Client-Side Top 10
// ---------------------------------------------------------------------------

func mobilePrivacyVulns() []VulnCategory {
	return []VulnCategory{
		// --- Mobile Top 10 ---
		{
			ID:          "m-01",
			Name:        "M01 - Improper Credential Usage",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/mobile/improper-credential", "/vuln/mobile/improper-credential/hardcoded-api-key", "/vuln/mobile/improper-credential/plaintext-password", "/vuln/mobile/improper-credential/shared-secret"},
			Description: "Mobile app hardcodes API keys, stores passwords in plaintext, or uses shared secrets",
			CWE:         "CWE-798",
			OWASP:       "M01:2024",
			Detectable:  true,
		},
		{
			ID:          "m-02",
			Name:        "M02 - Inadequate Supply Chain Security",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/supply-chain", "/vuln/mobile/supply-chain/malicious-sdk", "/vuln/mobile/supply-chain/compromised-lib", "/vuln/mobile/supply-chain/untrusted-repo"},
			Description: "Mobile app includes malicious SDKs, compromised libraries, or pulls from untrusted repos",
			CWE:         "CWE-1357",
			OWASP:       "M02:2024",
			Detectable:  true,
		},
		{
			ID:          "m-03",
			Name:        "M03 - Insecure Authentication/Authorization",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/mobile/insecure-auth", "/vuln/mobile/insecure-auth/biometric-bypass", "/vuln/mobile/insecure-auth/client-side-auth", "/vuln/mobile/insecure-auth/missing-server-check"},
			Description: "Mobile app relies on client-side auth, allows biometric bypass, or lacks server-side checks",
			CWE:         "CWE-287",
			OWASP:       "M03:2024",
			Detectable:  true,
		},
		{
			ID:          "m-04",
			Name:        "M04 - Insufficient Input/Output Validation",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/input-validation", "/vuln/mobile/input-validation/sqli", "/vuln/mobile/input-validation/xss", "/vuln/mobile/input-validation/path-traversal"},
			Description: "Mobile app lacks input validation enabling SQL injection, XSS, or path traversal",
			CWE:         "CWE-20",
			OWASP:       "M04:2024",
			Detectable:  true,
		},
		{
			ID:          "m-05",
			Name:        "M05 - Insecure Communication",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/insecure-comms", "/vuln/mobile/insecure-comms/no-tls", "/vuln/mobile/insecure-comms/cert-pinning-absent", "/vuln/mobile/insecure-comms/cleartext-traffic"},
			Description: "Mobile app communicates over cleartext, lacks TLS, or does not implement cert pinning",
			CWE:         "CWE-319",
			OWASP:       "M05:2024",
			Detectable:  true,
		},
		{
			ID:          "m-06",
			Name:        "M06 - Inadequate Privacy Controls",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/privacy-controls", "/vuln/mobile/privacy-controls/excessive-permissions", "/vuln/mobile/privacy-controls/tracking-without-consent", "/vuln/mobile/privacy-controls/pii-in-logs"},
			Description: "Mobile app requests excessive permissions, tracks users without consent, or logs PII",
			CWE:         "CWE-359",
			OWASP:       "M06:2024",
			Detectable:  true,
		},
		{
			ID:          "m-07",
			Name:        "M07 - Insufficient Binary Protections",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/mobile/binary-protections", "/vuln/mobile/binary-protections/no-obfuscation", "/vuln/mobile/binary-protections/debuggable", "/vuln/mobile/binary-protections/no-root-detection"},
			Description: "Mobile app binary lacks obfuscation, is debuggable, or has no root/jailbreak detection",
			CWE:         "CWE-693",
			OWASP:       "M07:2024",
			Detectable:  true,
		},
		{
			ID:          "m-08",
			Name:        "M08 - Security Misconfiguration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/mobile/misconfig", "/vuln/mobile/misconfig/backup-enabled", "/vuln/mobile/misconfig/debug-flag", "/vuln/mobile/misconfig/exported-components"},
			Description: "Mobile app deployed with backup enabled, debug flags, or exported components",
			CWE:         "CWE-16",
			OWASP:       "M08:2024",
			Detectable:  true,
		},
		{
			ID:          "m-09",
			Name:        "M09 - Insecure Data Storage",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/insecure-storage", "/vuln/mobile/insecure-storage/sqlite-plaintext", "/vuln/mobile/insecure-storage/shared-prefs", "/vuln/mobile/insecure-storage/external-storage"},
			Description: "Mobile app stores sensitive data in plaintext SQLite, SharedPreferences, or external storage",
			CWE:         "CWE-922",
			OWASP:       "M09:2024",
			Detectable:  true,
		},
		{
			ID:          "m-10",
			Name:        "M10 - Insufficient Cryptography",
			Severity:    "high",
			Endpoints:   []string{"/vuln/mobile/weak-crypto", "/vuln/mobile/weak-crypto/deprecated-algorithm", "/vuln/mobile/weak-crypto/insecure-random", "/vuln/mobile/weak-crypto/weak-key-length"},
			Description: "Mobile app uses deprecated crypto algorithms, insecure PRNG, or insufficient key length",
			CWE:         "CWE-327",
			OWASP:       "M10:2024",
			Detectable:  true,
		},
		// --- Privacy Risks Top 10 ---
		{
			ID:          "p-01",
			Name:        "P01 - Web Application Fingerprinting and Tracking",
			Severity:    "high",
			Endpoints:   []string{"/vuln/privacy-risks/web-tracking", "/vuln/privacy-risks/web-tracking/browser-fingerprint", "/vuln/privacy-risks/web-tracking/cross-site-tracking", "/vuln/privacy-risks/web-tracking/evercookies"},
			Description: "Application employs browser fingerprinting, cross-site tracking, or persistent cookies",
			CWE:         "CWE-359",
			OWASP:       "P01:2021",
			Detectable:  true,
		},
		{
			ID:          "p-02",
			Name:        "P02 - Excessive Data Collection",
			Severity:    "high",
			Endpoints:   []string{"/vuln/privacy-risks/data-collection", "/vuln/privacy-risks/data-collection/unnecessary-fields", "/vuln/privacy-risks/data-collection/hidden-telemetry", "/vuln/privacy-risks/data-collection/third-party-analytics"},
			Description: "Application collects unnecessary personal data, hidden telemetry, or excessive analytics",
			CWE:         "CWE-359",
			OWASP:       "P02:2021",
			Detectable:  true,
		},
		{
			ID:          "p-03",
			Name:        "P03 - Insufficient Data Breach Response",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/privacy-risks/breach-response", "/vuln/privacy-risks/breach-response/no-notification", "/vuln/privacy-risks/breach-response/no-incident-plan", "/vuln/privacy-risks/breach-response/delayed-disclosure"},
			Description: "Organization lacks data breach notification, incident response plan, or timely disclosure",
			CWE:         "CWE-778",
			OWASP:       "P03:2021",
			Detectable:  false,
		},
		{
			ID:          "p-04",
			Name:        "P04 - Insufficient Consent and Choice",
			Severity:    "high",
			Endpoints:   []string{"/vuln/privacy-risks/consent", "/vuln/privacy-risks/consent/pre-checked-boxes", "/vuln/privacy-risks/consent/no-opt-out", "/vuln/privacy-risks/consent/dark-patterns"},
			Description: "Application uses dark patterns, pre-checked consent boxes, or lacks opt-out mechanisms",
			CWE:         "CWE-359",
			OWASP:       "P04:2021",
			Detectable:  true,
		},
		{
			ID:          "p-05",
			Name:        "P05 - Non-Compliant Data Retention",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/privacy-risks/data-retention", "/vuln/privacy-risks/data-retention/no-expiration", "/vuln/privacy-risks/data-retention/unlimited-storage", "/vuln/privacy-risks/data-retention/no-deletion"},
			Description: "Data retained indefinitely without expiration, deletion mechanism, or retention policy",
			CWE:         "CWE-404",
			OWASP:       "P05:2021",
			Detectable:  true,
		},
		{
			ID:          "p-06",
			Name:        "P06 - Insufficient Data Anonymization",
			Severity:    "high",
			Endpoints:   []string{"/vuln/privacy-risks/anonymization", "/vuln/privacy-risks/anonymization/reversible-hash", "/vuln/privacy-risks/anonymization/insufficient-masking", "/vuln/privacy-risks/anonymization/re-identification"},
			Description: "Personal data anonymization is insufficient allowing re-identification attacks",
			CWE:         "CWE-200",
			OWASP:       "P06:2021",
			Detectable:  true,
		},
		{
			ID:          "p-07",
			Name:        "P07 - Insufficient Data Subject Rights",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/privacy-risks/subject-rights", "/vuln/privacy-risks/subject-rights/no-export", "/vuln/privacy-risks/subject-rights/no-deletion-request", "/vuln/privacy-risks/subject-rights/no-access-request"},
			Description: "Application lacks data export, deletion request, or access request capabilities",
			CWE:         "CWE-359",
			OWASP:       "P07:2021",
			Detectable:  true,
		},
		{
			ID:          "p-08",
			Name:        "P08 - Insecure Data Transfer",
			Severity:    "high",
			Endpoints:   []string{"/vuln/privacy-risks/insecure-transfer", "/vuln/privacy-risks/insecure-transfer/no-encryption", "/vuln/privacy-risks/insecure-transfer/cross-border", "/vuln/privacy-risks/insecure-transfer/third-party-sharing"},
			Description: "Personal data transferred unencrypted, cross-border without safeguards, or to third parties",
			CWE:         "CWE-319",
			OWASP:       "P08:2021",
			Detectable:  true,
		},
		{
			ID:          "p-09",
			Name:        "P09 - Inability to Process Data Requests",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/privacy-risks/data-requests", "/vuln/privacy-risks/data-requests/no-automation", "/vuln/privacy-risks/data-requests/slow-response", "/vuln/privacy-risks/data-requests/incomplete-data"},
			Description: "Organization cannot efficiently process data subject requests within regulatory deadlines",
			CWE:         "CWE-693",
			OWASP:       "P09:2021",
			Detectable:  false,
		},
		{
			ID:          "p-10",
			Name:        "P10 - Insufficient Data Processing Agreements",
			Severity:    "low",
			Endpoints:   []string{"/vuln/privacy-risks/processing-agreements", "/vuln/privacy-risks/processing-agreements/no-dpa", "/vuln/privacy-risks/processing-agreements/vague-terms", "/vuln/privacy-risks/processing-agreements/no-audit-rights"},
			Description: "Data processing agreements missing, vague, or lacking audit rights for data subjects",
			CWE:         "CWE-693",
			OWASP:       "P10:2021",
			Detectable:  false,
		},
		// --- Client-Side Top 10 ---
		{
			ID:          "c-01",
			Name:        "CS-01 - DOM-Based XSS",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/client-side/dom-xss", "/vuln/client-side/dom-xss/innerhtml-sink", "/vuln/client-side/dom-xss/eval-injection", "/vuln/client-side/dom-xss/document-write"},
			Description: "Client-side JavaScript vulnerable to DOM-based XSS via innerHTML, eval, or document.write",
			CWE:         "CWE-79",
			OWASP:       "CS-01",
			Detectable:  true,
		},
		{
			ID:          "c-02",
			Name:        "CS-02 - Prototype Pollution",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/prototype-pollution", "/vuln/client-side/prototype-pollution/merge-gadget", "/vuln/client-side/prototype-pollution/json-parse", "/vuln/client-side/prototype-pollution/query-string"},
			Description: "JavaScript object prototype polluted through deep merge, JSON parsing, or query parameters",
			CWE:         "CWE-1321",
			OWASP:       "CS-02",
			Detectable:  true,
		},
		{
			ID:          "c-03",
			Name:        "CS-03 - Sensitive Data Exposure in Client Storage",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/client-storage", "/vuln/client-side/client-storage/localstorage-secrets", "/vuln/client-side/client-storage/sessionstorage-tokens", "/vuln/client-side/client-storage/indexeddb-pii"},
			Description: "Secrets, tokens, or PII stored in localStorage, sessionStorage, or IndexedDB",
			CWE:         "CWE-922",
			OWASP:       "CS-03",
			Detectable:  true,
		},
		{
			ID:          "c-04",
			Name:        "CS-04 - JavaScript Dependency Vulnerabilities",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/js-deps", "/vuln/client-side/js-deps/outdated-jquery", "/vuln/client-side/js-deps/vulnerable-lodash", "/vuln/client-side/js-deps/malicious-package"},
			Description: "Client-side includes outdated jQuery, vulnerable lodash, or malicious npm packages",
			CWE:         "CWE-1035",
			OWASP:       "CS-04",
			Detectable:  true,
		},
		{
			ID:          "c-05",
			Name:        "CS-05 - Insufficient Content Security Policy",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/client-side/csp", "/vuln/client-side/csp/unsafe-inline", "/vuln/client-side/csp/unsafe-eval", "/vuln/client-side/csp/wildcard-source"},
			Description: "CSP allows unsafe-inline, unsafe-eval, or wildcard sources enabling injection attacks",
			CWE:         "CWE-693",
			OWASP:       "CS-05",
			Detectable:  true,
		},
		{
			ID:          "c-06",
			Name:        "CS-06 - Insecure PostMessage Communication",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/postmessage", "/vuln/client-side/postmessage/no-origin-check", "/vuln/client-side/postmessage/wildcard-target", "/vuln/client-side/postmessage/sensitive-data"},
			Description: "PostMessage used without origin validation, with wildcard targets, or sending sensitive data",
			CWE:         "CWE-346",
			OWASP:       "CS-06",
			Detectable:  true,
		},
		{
			ID:          "c-07",
			Name:        "CS-07 - Client-Side Path Traversal",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/client-side/path-traversal", "/vuln/client-side/path-traversal/fetch-manipulation", "/vuln/client-side/path-traversal/dynamic-import", "/vuln/client-side/path-traversal/asset-loading"},
			Description: "Client-side code allows path traversal in fetch URLs, dynamic imports, or asset loading",
			CWE:         "CWE-22",
			OWASP:       "CS-07",
			Detectable:  true,
		},
		{
			ID:          "c-08",
			Name:        "CS-08 - Clickjacking",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/client-side/clickjacking", "/vuln/client-side/clickjacking/no-x-frame", "/vuln/client-side/clickjacking/csp-frame-ancestors", "/vuln/client-side/clickjacking/ui-redress"},
			Description: "Application lacks X-Frame-Options or frame-ancestors CSP allowing clickjacking attacks",
			CWE:         "CWE-1021",
			OWASP:       "CS-08",
			Detectable:  true,
		},
		{
			ID:          "c-09",
			Name:        "CS-09 - Client-Side Request Forgery",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/csrf", "/vuln/client-side/csrf/no-csrf-token", "/vuln/client-side/csrf/get-side-effects", "/vuln/client-side/csrf/cors-misconfiguration"},
			Description: "Application lacks CSRF tokens, uses GET for state changes, or has CORS misconfigurations",
			CWE:         "CWE-352",
			OWASP:       "CS-09",
			Detectable:  true,
		},
		{
			ID:          "c-10",
			Name:        "CS-10 - WebSocket Security Issues",
			Severity:    "high",
			Endpoints:   []string{"/vuln/client-side/websocket", "/vuln/client-side/websocket/no-auth", "/vuln/client-side/websocket/no-origin-check", "/vuln/client-side/websocket/cross-site-hijacking"},
			Description: "WebSocket connections lack authentication, origin checking, or allow cross-site hijacking",
			CWE:         "CWE-346",
			OWASP:       "CS-10",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Specialized: Proactive Controls, ML Security, Data Security, Web 2025
// ---------------------------------------------------------------------------

func specializedVulns() []VulnCategory {
	return []VulnCategory{
		// --- Proactive Controls ---
		{
			ID:          "pc-01",
			Name:        "PC-01 - No Security Requirements Defined",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/proactive/no-security-reqs", "/vuln/proactive/no-security-reqs/missing-threat-model", "/vuln/proactive/no-security-reqs/no-abuse-cases", "/vuln/proactive/no-security-reqs/no-risk-assessment"},
			Description: "Application developed without security requirements, threat models, or abuse cases",
			CWE:         "CWE-1059",
			OWASP:       "C01:2024",
			Detectable:  false,
		},
		{
			ID:          "pc-02",
			Name:        "PC-02 - No Input Validation Framework",
			Severity:    "high",
			Endpoints:   []string{"/vuln/proactive/no-validation", "/vuln/proactive/no-validation/no-allowlist", "/vuln/proactive/no-validation/client-only", "/vuln/proactive/no-validation/no-schema"},
			Description: "Application lacks server-side input validation framework, schema validation, or allowlists",
			CWE:         "CWE-20",
			OWASP:       "C02:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-03",
			Name:        "PC-03 - No Output Encoding",
			Severity:    "high",
			Endpoints:   []string{"/vuln/proactive/no-encoding", "/vuln/proactive/no-encoding/no-html-encode", "/vuln/proactive/no-encoding/no-url-encode", "/vuln/proactive/no-encoding/no-js-encode"},
			Description: "Application lacks context-sensitive output encoding for HTML, URL, and JavaScript",
			CWE:         "CWE-116",
			OWASP:       "C03:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-04",
			Name:        "PC-04 - No Access Control Architecture",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/proactive/no-access-control", "/vuln/proactive/no-access-control/no-rbac", "/vuln/proactive/no-access-control/no-deny-default", "/vuln/proactive/no-access-control/no-centralized-authz"},
			Description: "Application lacks centralized access control, RBAC, or deny-by-default policy",
			CWE:         "CWE-284",
			OWASP:       "C04:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-05",
			Name:        "PC-05 - No Secure Configuration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/proactive/no-secure-config", "/vuln/proactive/no-secure-config/no-hardening", "/vuln/proactive/no-secure-config/default-settings", "/vuln/proactive/no-secure-config/no-patching"},
			Description: "No secure configuration baseline, hardening guide, or patching process in place",
			CWE:         "CWE-16",
			OWASP:       "C05:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-06",
			Name:        "PC-06 - No Cryptography Strategy",
			Severity:    "high",
			Endpoints:   []string{"/vuln/proactive/no-crypto", "/vuln/proactive/no-crypto/no-key-mgmt", "/vuln/proactive/no-crypto/custom-crypto", "/vuln/proactive/no-crypto/no-rotation"},
			Description: "No cryptography strategy: custom crypto, no key management, or no rotation policy",
			CWE:         "CWE-327",
			OWASP:       "C06:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-07",
			Name:        "PC-07 - No Error and Logging Strategy",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/proactive/no-logging", "/vuln/proactive/no-logging/no-centralized-log", "/vuln/proactive/no-logging/no-alerting", "/vuln/proactive/no-logging/verbose-errors"},
			Description: "No centralized logging, alerting strategy, or error handling that leaks information",
			CWE:         "CWE-778",
			OWASP:       "C07:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-08",
			Name:        "PC-08 - No Data Protection Controls",
			Severity:    "high",
			Endpoints:   []string{"/vuln/proactive/no-data-protection", "/vuln/proactive/no-data-protection/no-classification", "/vuln/proactive/no-data-protection/no-encryption-at-rest", "/vuln/proactive/no-data-protection/no-pii-handling"},
			Description: "No data classification, encryption at rest, or PII handling procedures defined",
			CWE:         "CWE-311",
			OWASP:       "C08:2024",
			Detectable:  true,
		},
		{
			ID:          "pc-09",
			Name:        "PC-09 - No Security Testing Integration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/proactive/no-sec-testing", "/vuln/proactive/no-sec-testing/no-sast", "/vuln/proactive/no-sec-testing/no-dast", "/vuln/proactive/no-sec-testing/no-pentest"},
			Description: "No SAST, DAST, or penetration testing integrated into development lifecycle",
			CWE:         "CWE-1053",
			OWASP:       "C09:2024",
			Detectable:  false,
		},
		{
			ID:          "pc-10",
			Name:        "PC-10 - No Secure Development Lifecycle",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/proactive/no-sdlc", "/vuln/proactive/no-sdlc/no-training", "/vuln/proactive/no-sdlc/no-code-review", "/vuln/proactive/no-sdlc/no-dependency-check"},
			Description: "No secure development lifecycle with training, code review, or dependency checking",
			CWE:         "CWE-1059",
			OWASP:       "C10:2024",
			Detectable:  false,
		},
		// --- ML Security Top 10 ---
		{
			ID:          "ml-01",
			Name:        "ML-01 - Input Manipulation Attack",
			Severity:    "high",
			Endpoints:   []string{"/vuln/ml-sec/input-manipulation", "/vuln/ml-sec/input-manipulation/adversarial-sample", "/vuln/ml-sec/input-manipulation/evasion-attack", "/vuln/ml-sec/input-manipulation/feature-squeezing"},
			Description: "ML model vulnerable to adversarial samples, evasion attacks, or feature manipulation",
			CWE:         "CWE-20",
			OWASP:       "ML01:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-02",
			Name:        "ML-02 - Data Poisoning Attack",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/ml-sec/data-poisoning", "/vuln/ml-sec/data-poisoning/training-manipulation", "/vuln/ml-sec/data-poisoning/label-flipping", "/vuln/ml-sec/data-poisoning/backdoor-injection"},
			Description: "ML training data poisoned through manipulation, label flipping, or backdoor injection",
			CWE:         "CWE-20",
			OWASP:       "ML02:2023",
			Detectable:  false,
		},
		{
			ID:          "ml-03",
			Name:        "ML-03 - Model Inversion Attack",
			Severity:    "high",
			Endpoints:   []string{"/vuln/ml-sec/model-inversion", "/vuln/ml-sec/model-inversion/feature-extraction", "/vuln/ml-sec/model-inversion/membership-inference", "/vuln/ml-sec/model-inversion/data-reconstruction"},
			Description: "ML model reveals training data through inversion, membership inference, or reconstruction",
			CWE:         "CWE-200",
			OWASP:       "ML03:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-04",
			Name:        "ML-04 - Membership Inference Attack",
			Severity:    "high",
			Endpoints:   []string{"/vuln/ml-sec/membership-inference", "/vuln/ml-sec/membership-inference/confidence-analysis", "/vuln/ml-sec/membership-inference/shadow-model", "/vuln/ml-sec/membership-inference/loss-based"},
			Description: "Attackers determine if specific data was in the training set via confidence or loss analysis",
			CWE:         "CWE-200",
			OWASP:       "ML04:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-05",
			Name:        "ML-05 - Model Theft",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/ml-sec/model-theft", "/vuln/ml-sec/model-theft/model-extraction", "/vuln/ml-sec/model-theft/api-abuse", "/vuln/ml-sec/model-theft/side-channel"},
			Description: "ML model stolen through repeated API queries, extraction attacks, or side channels",
			CWE:         "CWE-200",
			OWASP:       "ML05:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-06",
			Name:        "ML-06 - AI Supply Chain Attacks",
			Severity:    "high",
			Endpoints:   []string{"/vuln/ml-sec/supply-chain", "/vuln/ml-sec/supply-chain/poisoned-pretrained", "/vuln/ml-sec/supply-chain/malicious-framework", "/vuln/ml-sec/supply-chain/compromised-pipeline"},
			Description: "ML supply chain compromised through poisoned pre-trained models or malicious frameworks",
			CWE:         "CWE-1357",
			OWASP:       "ML06:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-07",
			Name:        "ML-07 - Transfer Learning Attack",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/ml-sec/transfer-learning", "/vuln/ml-sec/transfer-learning/backdoored-base", "/vuln/ml-sec/transfer-learning/fine-tune-manipulation", "/vuln/ml-sec/transfer-learning/feature-collision"},
			Description: "Transfer learning from compromised base models introduces backdoors or bias",
			CWE:         "CWE-20",
			OWASP:       "ML07:2023",
			Detectable:  false,
		},
		{
			ID:          "ml-08",
			Name:        "ML-08 - Model Skewing",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/ml-sec/model-skewing", "/vuln/ml-sec/model-skewing/data-drift", "/vuln/ml-sec/model-skewing/concept-drift", "/vuln/ml-sec/model-skewing/distribution-shift"},
			Description: "ML model performance degrades due to data drift, concept drift, or distribution shift",
			CWE:         "CWE-693",
			OWASP:       "ML08:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-09",
			Name:        "ML-09 - Output Integrity Attack",
			Severity:    "high",
			Endpoints:   []string{"/vuln/ml-sec/output-integrity", "/vuln/ml-sec/output-integrity/prediction-tampering", "/vuln/ml-sec/output-integrity/response-manipulation", "/vuln/ml-sec/output-integrity/confidence-spoofing"},
			Description: "ML model outputs tampered with through prediction manipulation or confidence spoofing",
			CWE:         "CWE-345",
			OWASP:       "ML09:2023",
			Detectable:  true,
		},
		{
			ID:          "ml-10",
			Name:        "ML-10 - Model Poisoning",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/ml-sec/model-poisoning", "/vuln/ml-sec/model-poisoning/weight-manipulation", "/vuln/ml-sec/model-poisoning/gradient-attack", "/vuln/ml-sec/model-poisoning/federated-poisoning"},
			Description: "ML model weights directly manipulated through gradient attacks or federated learning poisoning",
			CWE:         "CWE-20",
			OWASP:       "ML10:2023",
			Detectable:  false,
		},
		// --- Data Security Top 10 ---
		{
			ID:          "ds-01",
			Name:        "DS-01 - Injection Flaws",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/data-sec/injection-flaws", "/vuln/data-sec/injection-flaws/sql-injection", "/vuln/data-sec/injection-flaws/nosql-injection", "/vuln/data-sec/injection-flaws/ldap-injection"},
			Description: "Data layer vulnerable to SQL, NoSQL, or LDAP injection through unparameterized queries",
			CWE:         "CWE-89",
			OWASP:       "DS-01",
			Detectable:  true,
		},
		{
			ID:          "ds-02",
			Name:        "DS-02 - Sensitive Data Exposure",
			Severity:    "high",
			Endpoints:   []string{"/vuln/data-sec/sensitive-exposure", "/vuln/data-sec/sensitive-exposure/unmasked-pii", "/vuln/data-sec/sensitive-exposure/api-data-leak", "/vuln/data-sec/sensitive-exposure/debug-dump"},
			Description: "Sensitive data exposed through unmasked PII, API responses, or debug data dumps",
			CWE:         "CWE-200",
			OWASP:       "DS-02",
			Detectable:  true,
		},
		{
			ID:          "ds-03",
			Name:        "DS-03 - Broken Access Control to Data",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/data-sec/broken-access", "/vuln/data-sec/broken-access/horizontal-escalation", "/vuln/data-sec/broken-access/direct-object-ref", "/vuln/data-sec/broken-access/no-row-level"},
			Description: "Data access controls bypassed through horizontal escalation or missing row-level security",
			CWE:         "CWE-639",
			OWASP:       "DS-03",
			Detectable:  true,
		},
		{
			ID:          "ds-04",
			Name:        "DS-04 - Insufficient Data Encryption",
			Severity:    "high",
			Endpoints:   []string{"/vuln/data-sec/insufficient-encryption", "/vuln/data-sec/insufficient-encryption/no-tde", "/vuln/data-sec/insufficient-encryption/weak-algorithm", "/vuln/data-sec/insufficient-encryption/plaintext-backups"},
			Description: "Database lacks transparent encryption, uses weak algorithms, or has plaintext backups",
			CWE:         "CWE-311",
			OWASP:       "DS-04",
			Detectable:  true,
		},
		{
			ID:          "ds-05",
			Name:        "DS-05 - Insecure Data Migration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/data-sec/insecure-migration", "/vuln/data-sec/insecure-migration/unencrypted-export", "/vuln/data-sec/insecure-migration/no-validation", "/vuln/data-sec/insecure-migration/stale-copies"},
			Description: "Data migrations use unencrypted exports, lack validation, or leave stale copies behind",
			CWE:         "CWE-311",
			OWASP:       "DS-05",
			Detectable:  true,
		},
		{
			ID:          "ds-06",
			Name:        "DS-06 - Inadequate Data Backup Security",
			Severity:    "high",
			Endpoints:   []string{"/vuln/data-sec/backup-security", "/vuln/data-sec/backup-security/unencrypted-backup", "/vuln/data-sec/backup-security/public-bucket", "/vuln/data-sec/backup-security/no-access-control"},
			Description: "Database backups stored unencrypted, in public buckets, or without access controls",
			CWE:         "CWE-311",
			OWASP:       "DS-06",
			Detectable:  true,
		},
		{
			ID:          "ds-07",
			Name:        "DS-07 - Weak Database Authentication",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/data-sec/weak-db-auth", "/vuln/data-sec/weak-db-auth/default-creds", "/vuln/data-sec/weak-db-auth/no-auth", "/vuln/data-sec/weak-db-auth/shared-accounts"},
			Description: "Database accessible with default credentials, no authentication, or shared service accounts",
			CWE:         "CWE-798",
			OWASP:       "DS-07",
			Detectable:  true,
		},
		{
			ID:          "ds-08",
			Name:        "DS-08 - Insufficient Audit Logging",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/data-sec/audit-logging", "/vuln/data-sec/audit-logging/no-query-log", "/vuln/data-sec/audit-logging/no-access-log", "/vuln/data-sec/audit-logging/tampered-logs"},
			Description: "Database lacks query logging, access audit trail, or logs are tamperable",
			CWE:         "CWE-778",
			OWASP:       "DS-08",
			Detectable:  true,
		},
		{
			ID:          "ds-09",
			Name:        "DS-09 - Insecure Data-as-a-Service Configuration",
			Severity:    "high",
			Endpoints:   []string{"/vuln/data-sec/daas-config", "/vuln/data-sec/daas-config/public-endpoint", "/vuln/data-sec/daas-config/no-network-isolation", "/vuln/data-sec/daas-config/over-permissive-api"},
			Description: "Cloud database service publicly accessible, no network isolation, or over-permissive APIs",
			CWE:         "CWE-16",
			OWASP:       "DS-09",
			Detectable:  true,
		},
		{
			ID:          "ds-10",
			Name:        "DS-10 - No Data Loss Prevention",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/data-sec/no-dlp", "/vuln/data-sec/no-dlp/no-exfiltration-detection", "/vuln/data-sec/no-dlp/no-masking-policy", "/vuln/data-sec/no-dlp/bulk-export-allowed"},
			Description: "No DLP controls: bulk export allowed, no exfiltration detection, no masking policy",
			CWE:         "CWE-200",
			OWASP:       "DS-10",
			Detectable:  true,
		},
		// --- Web 2025 (OWASP Top 10 2025 Refresh) ---
		{
			ID:          "web25-01",
			Name:        "Web25-01 - Broken Access Control",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/web25/broken-access", "/vuln/web25/broken-access/path-traversal", "/vuln/web25/broken-access/idor", "/vuln/web25/broken-access/metadata-manipulation"},
			Description: "Access control failures including path traversal, IDOR, and metadata manipulation",
			CWE:         "CWE-284",
			OWASP:       "A01:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-02",
			Name:        "Web25-02 - Cryptographic Failures",
			Severity:    "high",
			Endpoints:   []string{"/vuln/web25/crypto-failures", "/vuln/web25/crypto-failures/weak-tls", "/vuln/web25/crypto-failures/broken-hash", "/vuln/web25/crypto-failures/key-exposure"},
			Description: "Weak TLS configuration, broken hash algorithms, or exposed cryptographic keys",
			CWE:         "CWE-327",
			OWASP:       "A02:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-03",
			Name:        "Web25-03 - Injection",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/web25/injection", "/vuln/web25/injection/sql", "/vuln/web25/injection/xss", "/vuln/web25/injection/command"},
			Description: "SQL injection, cross-site scripting, and OS command injection vulnerabilities",
			CWE:         "CWE-89",
			OWASP:       "A03:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-04",
			Name:        "Web25-04 - Insecure Design",
			Severity:    "high",
			Endpoints:   []string{"/vuln/web25/insecure-design", "/vuln/web25/insecure-design/no-threat-model", "/vuln/web25/insecure-design/missing-rate-limit", "/vuln/web25/insecure-design/trust-boundary"},
			Description: "Design flaws: missing threat modeling, no rate limiting, or broken trust boundaries",
			CWE:         "CWE-693",
			OWASP:       "A04:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-05",
			Name:        "Web25-05 - Security Misconfiguration",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/web25/misconfig", "/vuln/web25/misconfig/default-accounts", "/vuln/web25/misconfig/directory-listing", "/vuln/web25/misconfig/stack-traces"},
			Description: "Default accounts, directory listing enabled, or stack traces exposed in responses",
			CWE:         "CWE-16",
			OWASP:       "A05:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-06",
			Name:        "Web25-06 - Vulnerable and Outdated Components",
			Severity:    "high",
			Endpoints:   []string{"/vuln/web25/vulnerable-components", "/vuln/web25/vulnerable-components/outdated-framework", "/vuln/web25/vulnerable-components/known-cve", "/vuln/web25/vulnerable-components/eol-library"},
			Description: "Application uses outdated frameworks, libraries with known CVEs, or EOL components",
			CWE:         "CWE-1035",
			OWASP:       "A06:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-07",
			Name:        "Web25-07 - Identification and Authentication Failures",
			Severity:    "critical",
			Endpoints:   []string{"/vuln/web25/auth-failures", "/vuln/web25/auth-failures/credential-stuffing", "/vuln/web25/auth-failures/session-fixation", "/vuln/web25/auth-failures/weak-password-policy"},
			Description: "Credential stuffing, session fixation, or weak password policies in authentication",
			CWE:         "CWE-287",
			OWASP:       "A07:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-08",
			Name:        "Web25-08 - Software and Data Integrity Failures",
			Severity:    "high",
			Endpoints:   []string{"/vuln/web25/integrity-failures", "/vuln/web25/integrity-failures/unsigned-updates", "/vuln/web25/integrity-failures/deserialization", "/vuln/web25/integrity-failures/ci-tampering"},
			Description: "Unsigned software updates, insecure deserialization, or CI/CD pipeline tampering",
			CWE:         "CWE-502",
			OWASP:       "A08:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-09",
			Name:        "Web25-09 - Security Logging and Monitoring Failures",
			Severity:    "low",
			Endpoints:   []string{"/vuln/web25/logging-failures", "/vuln/web25/logging-failures/no-audit-log", "/vuln/web25/logging-failures/no-alerting", "/vuln/web25/logging-failures/log-injection"},
			Description: "Insufficient security logging, no alerting on suspicious activity, or log injection",
			CWE:         "CWE-778",
			OWASP:       "A09:2025",
			Detectable:  true,
		},
		{
			ID:          "web25-10",
			Name:        "Web25-10 - Server-Side Request Forgery",
			Severity:    "high",
			Endpoints:   []string{"/vuln/web25/ssrf", "/vuln/web25/ssrf/cloud-metadata", "/vuln/web25/ssrf/internal-service", "/vuln/web25/ssrf/protocol-smuggling"},
			Description: "SSRF attacks targeting cloud metadata endpoints, internal services, or protocol smuggling",
			CWE:         "CWE-918",
			OWASP:       "A10:2025",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Honeypot endpoint definitions
// ---------------------------------------------------------------------------

func honeypotVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:       "honeypot-admin",
			Name:     "Honeypot Admin Panels",
			Severity: "info",
			Endpoints: []string{
				"/wp-admin", "/wp-admin/", "/wp-login.php",
				"/administrator", "/administrator/",
				"/admin", "/admin/",
				"/admin/login", "/admin/dashboard",
				"/cpanel", "/cpanel/",
				"/phpmyadmin/", "/phpMyAdmin/",
				"/manager/html",
			},
			Description: "Honeypot endpoints mimicking admin panels to detect scanners",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
		{
			ID:       "honeypot-config",
			Name:     "Honeypot Config Files",
			Severity: "info",
			Endpoints: []string{
				"/.env", "/.env.local", "/.env.production",
				"/config.php", "/config.json",
				"/wp-config.php", "/wp-config.php.bak",
				"/web.config",
				"/.aws/credentials",
			},
			Description: "Honeypot endpoints mimicking exposed config files to detect scanners",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
		{
			ID:       "honeypot-backup",
			Name:     "Honeypot Backup Files",
			Severity: "info",
			Endpoints: []string{
				"/backup.sql", "/backup.zip", "/backup.tar.gz",
				"/db.sql", "/dump.sql", "/database.sql",
			},
			Description: "Honeypot endpoints mimicking backup dumps to detect scanners",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
		{
			ID:       "honeypot-git",
			Name:     "Honeypot Git Exposure",
			Severity: "info",
			Endpoints: []string{
				"/.git/config", "/.git/HEAD", "/.git/index",
				"/.gitignore", "/.git/",
			},
			Description: "Honeypot endpoints mimicking exposed VCS repositories",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
		{
			ID:       "honeypot-debug",
			Name:     "Honeypot Debug Endpoints",
			Severity: "info",
			Endpoints: []string{
				"/debug", "/debug/pprof",
				"/actuator", "/actuator/env", "/actuator/health",
				"/server-status", "/server-info",
				"/phpinfo.php", "/info.php",
				"/swagger-ui/", "/api-docs",
			},
			Description: "Honeypot endpoints mimicking debug and monitoring pages",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
		{
			ID:       "honeypot-shell",
			Name:     "Honeypot Shell/Backdoor",
			Severity: "info",
			Endpoints: []string{
				"/shell.php", "/cmd.php", "/c99.php",
				"/backdoor.php", "/webshell.php",
			},
			Description: "Honeypot endpoints mimicking web shells to detect attackers",
			CWE:         "",
			OWASP:       "",
			Detectable:  false,
		},
	}
}

// honeypotEndpointCount returns the approximate number of honeypot endpoints
// the server registers (admin + config + backup + git + CMS + debug + shells).
func honeypotEndpointCount() int {
	// The honeypot registers ~800 paths in total across all categories
	return 800
}

// ---------------------------------------------------------------------------
// Missing security header findings
// ---------------------------------------------------------------------------

func missingHeaderVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "missing-hsts",
			Name:        "Missing Strict-Transport-Security Header",
			Severity:    "medium",
			Endpoints:   []string{"/"},
			Description: "Server does not set HSTS header, allowing downgrade attacks",
			CWE:         "CWE-319",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "missing-csp",
			Name:        "Missing Content-Security-Policy Header",
			Severity:    "medium",
			Endpoints:   []string{"/"},
			Description: "No CSP header set, increasing risk of XSS and data injection",
			CWE:         "CWE-693",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "missing-x-frame-options",
			Name:        "Missing X-Frame-Options Header",
			Severity:    "medium",
			Endpoints:   []string{"/"},
			Description: "No clickjacking protection header, pages can be framed",
			CWE:         "CWE-1021",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "missing-x-content-type-options",
			Name:        "Missing X-Content-Type-Options Header",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "No nosniff header, browser may MIME-sniff responses",
			CWE:         "CWE-693",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "missing-referrer-policy",
			Name:        "Missing Referrer-Policy Header",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "No referrer policy, browser may leak referrer information",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "missing-permissions-policy",
			Name:        "Missing Permissions-Policy Header",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "No permissions policy header to restrict browser features",
			CWE:         "CWE-693",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Cookie trap findings
// ---------------------------------------------------------------------------

func cookieTrapVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "cookie-no-secure",
			Name:        "Cookies Without Secure Flag",
			Severity:    "medium",
			Endpoints:   []string{"/"},
			Description: "Session and tracking cookies set without the Secure flag on HTTP",
			CWE:         "CWE-614",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "cookie-no-httponly",
			Name:        "Cookies Without HttpOnly Flag",
			Severity:    "medium",
			Endpoints:   []string{"/"},
			Description: "Some cookies set without HttpOnly flag allowing JavaScript access",
			CWE:         "CWE-1004",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "cookie-tracking",
			Name:        "Tracking Cookies Set",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "Multiple tracking and fingerprint cookies set for client identification",
			CWE:         "CWE-359",
			OWASP:       "A09:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Header corruption findings
// ---------------------------------------------------------------------------

func headerCorruptionVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "header-corruption",
			Name:        "HTTP Header Corruption",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "Server corrupts HTTP headers with conflicting content-types, malformed values",
			CWE:         "CWE-436",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "header-huge",
			Name:        "Oversized Response Headers",
			Severity:    "low",
			Endpoints:   []string{"/"},
			Description: "Server sends excessively large response headers to confuse parsers",
			CWE:         "CWE-400",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Server information disclosure
// ---------------------------------------------------------------------------

func serverInfoVulns() []VulnCategory {
	return []VulnCategory{
		{
			ID:          "server-version-disclosure",
			Name:        "Server Version Disclosure",
			Severity:    "info",
			Endpoints:   []string{"/vuln/dashboard/", "/vuln/settings/"},
			Description: "Server header reveals detailed version information (Apache/PHP/OpenSSL)",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "x-powered-by",
			Name:        "X-Powered-By Header Present",
			Severity:    "info",
			Endpoints:   []string{"/vuln/dashboard/", "/vuln/settings/"},
			Description: "X-Powered-By header reveals technology stack (PHP/5.6.40)",
			CWE:         "CWE-200",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
		{
			ID:          "debug-mode-header",
			Name:        "Debug Mode Header",
			Severity:    "medium",
			Endpoints:   []string{"/vuln/dashboard/", "/vuln/settings/"},
			Description: "X-Debug-Mode header indicates debug mode is enabled in production",
			CWE:         "CWE-489",
			OWASP:       "A05:2021",
			Detectable:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func featureEnabled(features map[string]bool, name string) bool {
	v, ok := features[name]
	return ok && v
}

func categorizeFinding(id string) string {
	switch {
	case strings.HasPrefix(id, "owasp-"):
		return "vuln"
	case strings.HasPrefix(id, "honeypot-"):
		return "honeypot"
	case strings.HasPrefix(id, "dashboard-") || strings.HasPrefix(id, "debug-") ||
		strings.HasPrefix(id, "phpinfo-") || strings.HasPrefix(id, "server-status") ||
		strings.HasPrefix(id, "api-keys-") || strings.HasPrefix(id, "user-data-") ||
		strings.HasPrefix(id, "backup-") || strings.HasPrefix(id, "insecure-settings") ||
		strings.HasPrefix(id, "database-") || strings.HasPrefix(id, "email-") ||
		strings.HasPrefix(id, "integration-") || strings.HasPrefix(id, "audit-") ||
		strings.HasPrefix(id, "feature-flags-") || strings.HasPrefix(id, "service-"):
		return "dashboard"
	case strings.HasPrefix(id, "missing-"):
		return "header"
	case strings.HasPrefix(id, "cookie-"):
		return "cookie"
	case strings.HasPrefix(id, "header-"):
		return "header"
	default:
		return "vuln"
	}
}

func computeErrorRate(features map[string]bool, config map[string]interface{}) float64 {
	if !featureEnabled(features, "error_inject") {
		return 0.0
	}
	// Base error rate from default profile: ~35% of requests get errors (1.0 - 0.65 none)
	base := 0.35
	if m, ok := config["error_rate_multiplier"]; ok {
		switch v := m.(type) {
		case float64:
			base *= v
		case int:
			base *= float64(v)
		}
	}
	if base > 1.0 {
		base = 1.0
	}
	return base
}

func computeLabyrinthRate(features map[string]bool, config map[string]interface{}) float64 {
	if !featureEnabled(features, "labyrinth") {
		return 0.0
	}
	// Base labyrinth chance is ~5-10% for non-deep paths, 100% for deep paths
	return 0.08
}

func computeCaptchaRate(features map[string]bool, config map[string]interface{}) float64 {
	if !featureEnabled(features, "captcha") {
		return 0.0
	}
	// Captcha triggers after threshold requests, estimated ~5% of total traffic
	return 0.05
}

func computeBlockRate(features map[string]bool, config map[string]interface{}) float64 {
	if !featureEnabled(features, "random_blocking") {
		return 0.0
	}
	if bc, ok := config["block_chance"]; ok {
		switch v := bc.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return 0.02
}

func computeGrade(detectionRate float64) string {
	switch {
	case detectionRate > 0.80:
		return "A"
	case detectionRate > 0.60:
		return "B"
	case detectionRate > 0.40:
		return "C"
	case detectionRate > 0.20:
		return "D"
	default:
		return "F"
	}
}

// normalizeCWE normalizes CWE identifiers for comparison (e.g. "cwe-79" -> "CWE-79")
func normalizeCWE(cwe string) string {
	s := strings.TrimSpace(cwe)
	s = strings.ToUpper(s)
	// Handle formats like "79", "CWE79", "CWE-79"
	s = strings.TrimPrefix(s, "CWE-")
	s = strings.TrimPrefix(s, "CWE")
	return "CWE-" + s
}

// urlOverlap returns true if the finding URL matches any of the expected endpoints
func urlOverlap(endpoints []string, findingURL string) bool {
	if findingURL == "" {
		return false
	}
	findingLower := strings.ToLower(findingURL)

	// Extract the path portion from the finding URL
	findingPath := findingLower
	if idx := strings.Index(findingLower, "://"); idx >= 0 {
		rest := findingLower[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			findingPath = rest[slashIdx:]
		} else {
			findingPath = "/"
		}
	}

	for _, ep := range endpoints {
		epLower := strings.ToLower(ep)

		// Root path "/" should only match if the finding path is exactly "/"
		if epLower == "/" {
			if findingPath == "/" {
				return true
			}
			continue
		}

		// Check if the finding path starts with or equals the endpoint path
		if strings.HasPrefix(findingPath, epLower) {
			return true
		}

		// Also check if the full finding URL contains the endpoint
		// (handles cases where the endpoint is embedded in query strings, etc.)
		if len(epLower) > 1 && strings.Contains(findingLower, epLower) {
			return true
		}
	}
	return false
}

// keywordMatch checks if a finding's title/description matches a vuln category
// by checking for common keywords
func keywordMatch(vuln VulnCategory, finding Finding) bool {
	vulnTerms := extractKeywords(vuln.ID + " " + vuln.Name + " " + vuln.Description)
	findingText := strings.ToLower(finding.Title + " " + finding.Description + " " + finding.Evidence)

	matchCount := 0
	for _, term := range vulnTerms {
		if strings.Contains(findingText, term) {
			matchCount++
		}
	}
	// Require at least 3 keyword matches to avoid false positives from
	// generic terms like "detected", "found", "server", etc.
	return matchCount >= 3
}

// extractKeywords pulls meaningful terms from a description string
func extractKeywords(text string) []string {
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"is": true, "are": true, "was": true, "were": true, "be": true,
		"in": true, "on": true, "at": true, "to": true, "for": true,
		"of": true, "with": true, "by": true, "from": true, "as": true,
		"via": true, "no": true, "not": true, "this": true, "that": true,
		"all": true, "any": true, "can": true, "may": true, "will": true,
	}

	lower := strings.ToLower(text)
	// Replace common separators
	lower = strings.NewReplacer("-", " ", "_", " ", ":", " ", "/", " ", ".", " ").Replace(lower)
	words := strings.Fields(lower)

	var keywords []string
	seen := make(map[string]bool)
	for _, w := range words {
		if len(w) < 3 || stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		keywords = append(keywords, w)
	}
	return keywords
}

// Ensure math is used (for Min)
var _ = math.Min
