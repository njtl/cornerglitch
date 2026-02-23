package waf

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

// Signature represents a single WAF detection rule.
type Signature struct {
	ID          string
	Category    string // sqli, xss, traversal, cmdi, xxe
	Pattern     *regexp.Regexp
	Description string
	Severity    string // critical, high, medium, low
}

// Detection records a match of a signature against a request.
type Detection struct {
	SignatureID  string
	Category     string
	MatchedValue string
	Location     string // url, header, body, param
	Action       string
}

// SignatureDetector checks HTTP requests against a set of attack signatures.
type SignatureDetector struct {
	Enabled     bool
	Signatures  []Signature
	BlockAction string // "block", "log", "challenge"
	mu          sync.RWMutex
	detections  atomic.Int64
}

// NewSignatureDetector creates a SignatureDetector loaded with the default signature set.
func NewSignatureDetector() *SignatureDetector {
	return &SignatureDetector{
		Enabled:     true,
		Signatures:  DefaultSignatures(),
		BlockAction: "block",
	}
}

// Check evaluates a request against all loaded signatures and returns any detections.
func (d *SignatureDetector) Check(req *http.Request) []Detection {
	d.mu.RLock()
	if !d.Enabled {
		d.mu.RUnlock()
		return nil
	}
	sigs := d.Signatures
	action := d.BlockAction
	d.mu.RUnlock()

	var detections []Detection

	// Collect all scannable values from the request
	targets := d.extractTargets(req)

	for _, sig := range sigs {
		for _, t := range targets {
			if sig.Pattern.MatchString(t.value) {
				// Find the actual matched substring for reporting
				matched := sig.Pattern.FindString(t.value)
				if len(matched) > 200 {
					matched = matched[:200]
				}
				detections = append(detections, Detection{
					SignatureID:  sig.ID,
					Category:     sig.Category,
					MatchedValue: matched,
					Location:     t.location,
					Action:       action,
				})
				d.detections.Add(1)
			}
		}
	}

	return detections
}

// ShouldBlock returns true if any of the detections warrant blocking the request.
func (d *SignatureDetector) ShouldBlock(detections []Detection) bool {
	d.mu.RLock()
	action := d.BlockAction
	d.mu.RUnlock()

	if action != "block" {
		return false
	}
	return len(detections) > 0
}

// Detections returns the total number of signature matches observed.
func (d *SignatureDetector) Detections() int64 {
	return d.detections.Load()
}

// scanTarget pairs a value to scan with its location label.
type scanTarget struct {
	value    string
	location string
}

// extractTargets collects all parts of the request that should be scanned.
func (d *SignatureDetector) extractTargets(req *http.Request) []scanTarget {
	var targets []scanTarget

	// URL path and raw query
	targets = append(targets, scanTarget{value: req.URL.Path, location: "url"})
	if req.URL.RawQuery != "" {
		targets = append(targets, scanTarget{value: req.URL.RawQuery, location: "url"})
	}

	// Query parameter values
	for key, values := range req.URL.Query() {
		for _, v := range values {
			targets = append(targets, scanTarget{value: key + "=" + v, location: "param"})
		}
	}

	// Selected headers (commonly used for injection)
	headerNames := []string{
		"Referer", "User-Agent", "Cookie", "X-Forwarded-For",
		"X-Forwarded-Host", "Origin", "Accept", "Content-Type",
	}
	for _, name := range headerNames {
		if val := req.Header.Get(name); val != "" {
			targets = append(targets, scanTarget{value: val, location: "header"})
		}
	}

	// Request body (limited read to avoid memory issues)
	if req.Body != nil && req.ContentLength > 0 && req.ContentLength < 1<<20 {
		// Read up to 1MB of body
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err == nil && len(bodyBytes) > 0 {
			targets = append(targets, scanTarget{value: string(bodyBytes), location: "body"})
			// Reconstruct the body so downstream handlers can still read it
			req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}

	return targets
}

// DefaultSignatures returns a comprehensive set of ~30 attack detection signatures
// covering SQL injection, XSS, path traversal, command injection, and XXE.
func DefaultSignatures() []Signature {
	return []Signature{
		// ===== SQL Injection (10 patterns) =====
		{
			ID:          "sqli-001",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)union\s+(all\s+)?select`),
			Description: "SQL injection: UNION SELECT",
			Severity:    "critical",
		},
		{
			ID:          "sqli-002",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)('\s*or\s+'?1'?\s*=\s*'?1|"\s*or\s+"?1"?\s*=\s*"?1)`),
			Description: "SQL injection: OR 1=1 tautology",
			Severity:    "critical",
		},
		{
			ID:          "sqli-003",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(sleep|benchmark|waitfor\s+delay)\s*\(`),
			Description: "SQL injection: time-based blind (sleep/benchmark)",
			Severity:    "high",
		},
		{
			ID:          "sqli-004",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(drop|alter|create|truncate)\s+(table|database|index)`),
			Description: "SQL injection: DDL statement",
			Severity:    "critical",
		},
		{
			ID:          "sqli-005",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(;\s*(select|insert|update|delete|drop|alter)\s)`),
			Description: "SQL injection: stacked query",
			Severity:    "high",
		},
		{
			ID:          "sqli-006",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(information_schema|mysql\.user|sys\.objects|pg_catalog)`),
			Description: "SQL injection: schema enumeration",
			Severity:    "high",
		},
		{
			ID:          "sqli-007",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(load_file|into\s+(out|dump)file)`),
			Description: "SQL injection: file access",
			Severity:    "critical",
		},
		{
			ID:          "sqli-008",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(concat|group_concat|char)\s*\(.+\)`),
			Description: "SQL injection: string manipulation functions",
			Severity:    "medium",
		},
		{
			ID:          "sqli-009",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)('\s*;\s*--|--\s*$|#\s*$)`),
			Description: "SQL injection: comment termination",
			Severity:    "medium",
		},
		{
			ID:          "sqli-010",
			Category:    "sqli",
			Pattern:     regexp.MustCompile(`(?i)(extractvalue|updatexml|xmltype)\s*\(`),
			Description: "SQL injection: XML-based extraction",
			Severity:    "high",
		},

		// ===== Cross-Site Scripting (8 patterns) =====
		{
			ID:          "xss-001",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)<\s*script[^>]*>`),
			Description: "XSS: script tag injection",
			Severity:    "high",
		},
		{
			ID:          "xss-002",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)\bon(error|load|click|mouseover|focus|blur|submit|change)\s*=`),
			Description: "XSS: event handler injection",
			Severity:    "high",
		},
		{
			ID:          "xss-003",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)javascript\s*:`),
			Description: "XSS: javascript: URI scheme",
			Severity:    "high",
		},
		{
			ID:          "xss-004",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)<\s*img[^>]+\bsrc\s*=\s*[^>]*(javascript|data)\s*:`),
			Description: "XSS: img src with javascript/data URI",
			Severity:    "high",
		},
		{
			ID:          "xss-005",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)<\s*(iframe|embed|object|applet|form)\b`),
			Description: "XSS: dangerous HTML element injection",
			Severity:    "medium",
		},
		{
			ID:          "xss-006",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)(document\.(cookie|location|write)|window\.(location|open))`),
			Description: "XSS: DOM manipulation attempt",
			Severity:    "high",
		},
		{
			ID:          "xss-007",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)<\s*svg[^>]+\bonload\s*=`),
			Description: "XSS: SVG onload injection",
			Severity:    "high",
		},
		{
			ID:          "xss-008",
			Category:    "xss",
			Pattern:     regexp.MustCompile(`(?i)(eval|settimeout|setinterval|function)\s*\(\s*['"]`),
			Description: "XSS: JavaScript eval/timer injection",
			Severity:    "medium",
		},

		// ===== Path Traversal (4 patterns) =====
		{
			ID:          "traversal-001",
			Category:    "traversal",
			Pattern:     regexp.MustCompile(`(\.\.[\\/]){2,}`),
			Description: "Path traversal: repeated ../ or ..\\",
			Severity:    "high",
		},
		{
			ID:          "traversal-002",
			Category:    "traversal",
			Pattern:     regexp.MustCompile(`(?i)(\.\.[\\/])(etc[\\/]passwd|etc[\\/]shadow|windows[\\/]system32)`),
			Description: "Path traversal: OS file access",
			Severity:    "critical",
		},
		{
			ID:          "traversal-003",
			Category:    "traversal",
			Pattern:     regexp.MustCompile(`(?i)(%2e%2e[\\/]|%2e%2e%2f|\.\.%2f|%252e%252e)`),
			Description: "Path traversal: URL-encoded bypass",
			Severity:    "high",
		},
		{
			ID:          "traversal-004",
			Category:    "traversal",
			Pattern:     regexp.MustCompile(`(?i)[\\/](proc[\\/]self|dev[\\/](null|zero|random|urandom))`),
			Description: "Path traversal: Linux special files",
			Severity:    "high",
		},

		// ===== Command Injection (5 patterns) =====
		{
			ID:          "cmdi-001",
			Category:    "cmdi",
			Pattern:     regexp.MustCompile(`[;&|]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ruby|php)\b`),
			Description: "Command injection: pipe/chain to OS command",
			Severity:    "critical",
		},
		{
			ID:          "cmdi-002",
			Category:    "cmdi",
			Pattern:     regexp.MustCompile("(`[^`]+`)"),
			Description: "Command injection: backtick execution",
			Severity:    "high",
		},
		{
			ID:          "cmdi-003",
			Category:    "cmdi",
			Pattern:     regexp.MustCompile(`\$\([^)]+\)`),
			Description: "Command injection: $() subshell execution",
			Severity:    "high",
		},
		{
			ID:          "cmdi-004",
			Category:    "cmdi",
			Pattern:     regexp.MustCompile(`(?i)\b(system|exec|passthru|popen|proc_open|shell_exec)\s*\(`),
			Description: "Command injection: language exec function",
			Severity:    "critical",
		},
		{
			ID:          "cmdi-005",
			Category:    "cmdi",
			Pattern:     regexp.MustCompile(`(?i)(\bping\b|\bnslookup\b|\bdig\b|\btraceroute\b).*(-c\s+\d|[;&|])`),
			Description: "Command injection: network command with chaining",
			Severity:    "high",
		},

		// ===== XXE (3 patterns) =====
		{
			ID:          "xxe-001",
			Category:    "xxe",
			Pattern:     regexp.MustCompile(`(?i)<!\s*DOCTYPE\s[^>]*\[\s*<!`),
			Description: "XXE: DOCTYPE with internal subset (entity declaration)",
			Severity:    "critical",
		},
		{
			ID:          "xxe-002",
			Category:    "xxe",
			Pattern:     regexp.MustCompile(`(?i)<!\s*ENTITY\s`),
			Description: "XXE: ENTITY declaration",
			Severity:    "critical",
		},
		{
			ID:          "xxe-003",
			Category:    "xxe",
			Pattern:     regexp.MustCompile(`(?i)SYSTEM\s+["'][^"']*["']`),
			Description: "XXE: SYSTEM identifier (external entity reference)",
			Severity:    "high",
		},
	}
}
