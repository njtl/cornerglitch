package scanner

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

	Grade string `json:"grade"`
}

// MatchedVuln pairs an expected vulnerability with the scanner finding that detected it.
type MatchedVuln struct {
	Expected VulnCategory `json:"expected"`
	Found    Finding      `json:"found"`
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
