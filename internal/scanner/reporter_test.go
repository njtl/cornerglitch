package scanner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestReporter_AddResult
// ---------------------------------------------------------------------------

func TestReporter_AddResult(t *testing.T) {
	r := NewReporter()

	result := ScanResult{
		Request: AttackRequest{
			Method:      "GET",
			Path:        "/test",
			Category:    "general",
			Description: "test request",
		},
		StatusCode:  200,
		LatencyMs:   42,
		BodySize:    128,
		BodySnippet: "Hello, World!",
		Headers:     map[string]string{"Content-Type": "text/html"},
	}

	r.AddResult(result)

	r.mu.Lock()
	if len(r.results) != 1 {
		t.Errorf("expected 1 result, got %d", len(r.results))
	}
	if r.results[0].StatusCode != 200 {
		t.Errorf("expected status 200, got %d", r.results[0].StatusCode)
	}
	if r.results[0].Request.Path != "/test" {
		t.Errorf("expected path /test, got %s", r.results[0].Request.Path)
	}
	r.mu.Unlock()
}

func TestReporter_AddResult_Multiple(t *testing.T) {
	r := NewReporter()

	for i := 0; i < 10; i++ {
		r.AddResult(ScanResult{
			Request: AttackRequest{
				Method:      "GET",
				Path:        "/multi",
				Category:    "test",
				Description: "multi test",
			},
			StatusCode: 200 + i,
		})
	}

	r.mu.Lock()
	if len(r.results) != 10 {
		t.Errorf("expected 10 results, got %d", len(r.results))
	}
	r.mu.Unlock()
}

func TestReporter_AddResult_AutoDetectsFindings(t *testing.T) {
	r := NewReporter()

	// A result with SQL error in the body should trigger automatic finding detection.
	result := ScanResult{
		Request: AttackRequest{
			Method:      "GET",
			Path:        "/sql",
			Category:    "sqli",
			Description: "SQL injection test",
		},
		StatusCode:  200,
		BodySnippet: "ERROR: you have an error in your SQL syntax near...",
		Headers:     map[string]string{},
	}

	r.AddResult(result)

	r.mu.Lock()
	if len(r.findings) == 0 {
		t.Error("expected automatic finding detection to generate at least one finding")
	}
	r.mu.Unlock()
}

// ---------------------------------------------------------------------------
// TestReporter_AddFinding
// ---------------------------------------------------------------------------

func TestReporter_AddFinding(t *testing.T) {
	r := NewReporter()

	f := Finding{
		Category:    "xss",
		Severity:    "high",
		URL:         "/vuln/xss",
		Method:      "GET",
		StatusCode:  200,
		Evidence:    "<script>alert(1)</script>",
		Description: "Reflected XSS found",
	}

	r.AddFinding(f)

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.findings))
	}

	if r.findings[0].Category != "xss" {
		t.Errorf("expected category 'xss', got %q", r.findings[0].Category)
	}
	if r.findings[0].Severity != "high" {
		t.Errorf("expected severity 'high', got %q", r.findings[0].Severity)
	}
	if r.findings[0].Evidence != "<script>alert(1)</script>" {
		t.Errorf("unexpected evidence: %q", r.findings[0].Evidence)
	}
}

func TestReporter_AddFinding_MultiSeverity(t *testing.T) {
	r := NewReporter()

	severities := []string{"critical", "high", "medium", "low", "info"}
	for _, sev := range severities {
		r.AddFinding(Finding{
			Category: "test",
			Severity: sev,
			URL:      "/test",
			Method:   "GET",
		})
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(r.findings))
	}
}

// ---------------------------------------------------------------------------
// TestReporter_BuildReport
// ---------------------------------------------------------------------------

func TestReporter_BuildReport(t *testing.T) {
	r := NewReporter()

	// Add some results.
	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:      "GET",
			Path:        "/page1",
			Category:    "general",
			Description: "general test",
		},
		StatusCode: 200,
		Headers:    map[string]string{},
	})
	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:      "GET",
			Path:        "/page2",
			Category:    "sqli",
			Description: "sqli test",
		},
		StatusCode: 500,
		BodySize:   200,
		Error:      "",
		Headers:    map[string]string{},
	})

	// Add a manual finding.
	r.AddFinding(Finding{
		Category:    "xss",
		Severity:    "high",
		URL:         "/xss",
		Method:      "GET",
		StatusCode:  200,
		Description: "XSS found",
	})

	// Add an error.
	r.AddError("connection timeout on /broken")

	cfg := DefaultConfig()
	cfg.Target = "http://example.com"
	cfg.Profile = "default"

	startedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	completedAt := time.Date(2025, 1, 1, 12, 5, 0, 0, time.UTC)

	report := r.BuildReport(cfg, startedAt, completedAt)

	if report == nil {
		t.Fatal("BuildReport returned nil")
	}
	if report.Target != "http://example.com" {
		t.Errorf("expected target http://example.com, got %s", report.Target)
	}
	if report.Profile != "default" {
		t.Errorf("expected profile 'default', got %s", report.Profile)
	}
	if report.TotalRequests != 2 {
		t.Errorf("expected 2 total requests, got %d", report.TotalRequests)
	}
	if report.DurationMs != 300000 {
		t.Errorf("expected duration 300000ms, got %d", report.DurationMs)
	}
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(report.Errors))
	}

	// Check summary.
	if report.Summary == nil {
		t.Fatal("report.Summary is nil")
	}
	if report.Summary.TotalFindings < 1 {
		t.Errorf("expected at least 1 finding, got %d", report.Summary.TotalFindings)
	}
	if report.Summary.High < 1 {
		t.Errorf("expected at least 1 high finding, got %d", report.Summary.High)
	}

	// Check coverage exists.
	if report.Coverage == nil {
		t.Fatal("report.Coverage is nil")
	}

	// Check resilience.
	if report.Resilience == nil {
		t.Fatal("report.Resilience is nil")
	}

	// Check timestamps.
	if report.StartedAt != "2025-01-01T12:00:00Z" {
		t.Errorf("unexpected StartedAt: %s", report.StartedAt)
	}
	if report.CompletedAt != "2025-01-01T12:05:00Z" {
		t.Errorf("unexpected CompletedAt: %s", report.CompletedAt)
	}
}

// ---------------------------------------------------------------------------
// TestReporter_WriteJSON
// ---------------------------------------------------------------------------

func TestReporter_WriteJSON(t *testing.T) {
	r := NewReporter()

	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:      "GET",
			Path:        "/json-test",
			Category:    "test",
			Description: "json test",
		},
		StatusCode: 200,
		Headers:    map[string]string{},
	})

	cfg := DefaultConfig()
	cfg.Target = "http://localhost:8080"

	startedAt := time.Now().Add(-1 * time.Minute)
	completedAt := time.Now()

	report := r.BuildReport(cfg, startedAt, completedAt)

	var buf bytes.Buffer
	err := r.WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Fatal("WriteJSON produced empty output")
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("WriteJSON output is not valid JSON: %v", err)
	}

	// Check required fields exist.
	requiredFields := []string{"target", "profile", "started_at", "completed_at",
		"duration_ms", "total_requests", "findings", "coverage", "resilience", "summary"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("JSON output missing field %q", field)
		}
	}

	// Check target value.
	if parsed["target"] != "http://localhost:8080" {
		t.Errorf("expected target http://localhost:8080, got %v", parsed["target"])
	}
}

func TestReporter_WriteJSON_EmptyReport(t *testing.T) {
	r := NewReporter()

	cfg := DefaultConfig()
	cfg.Target = "http://empty.test"

	report := r.BuildReport(cfg, time.Now(), time.Now())

	var buf bytes.Buffer
	err := r.WriteJSON(&buf, report)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("WriteJSON output is not valid JSON: %v", err)
	}

	if parsed["total_requests"].(float64) != 0 {
		t.Errorf("expected total_requests=0, got %v", parsed["total_requests"])
	}
}

// ---------------------------------------------------------------------------
// TestReporter_Coverage
// ---------------------------------------------------------------------------

func TestReporter_Coverage(t *testing.T) {
	r := NewReporter()

	// Add results from two categories.
	for i := 0; i < 5; i++ {
		r.AddResult(ScanResult{
			Request: AttackRequest{
				Method:   "GET",
				Path:     "/cat-a",
				Category: "sqli",
			},
			StatusCode: 200,
			Headers:    map[string]string{},
		})
	}

	for i := 0; i < 3; i++ {
		r.AddResult(ScanResult{
			Request: AttackRequest{
				Method:   "GET",
				Path:     "/cat-b",
				Category: "xss",
			},
			StatusCode: 200,
			Headers:    map[string]string{},
		})
	}

	// Add findings in the sqli category.
	r.AddFinding(Finding{Category: "sqli", Severity: "high"})
	r.AddFinding(Finding{Category: "sqli", Severity: "medium"})

	cfg := DefaultConfig()
	report := r.BuildReport(cfg, time.Now(), time.Now())

	if report.Coverage == nil {
		t.Fatal("coverage is nil")
	}

	sqliCov, ok := report.Coverage["sqli"]
	if !ok {
		t.Fatal("sqli category not found in coverage")
	}
	if sqliCov.Tested != 5 {
		t.Errorf("expected sqli tested=5, got %d", sqliCov.Tested)
	}
	if sqliCov.Detected != 2 {
		t.Errorf("expected sqli detected=2, got %d", sqliCov.Detected)
	}
	expectedPct := (2.0 / 5.0) * 100
	if sqliCov.CoveragePct != expectedPct {
		t.Errorf("expected sqli coverage_pct=%.1f, got %.1f", expectedPct, sqliCov.CoveragePct)
	}

	xssCov, ok := report.Coverage["xss"]
	if !ok {
		t.Fatal("xss category not found in coverage")
	}
	if xssCov.Tested != 3 {
		t.Errorf("expected xss tested=3, got %d", xssCov.Tested)
	}
	if xssCov.Detected != 0 {
		t.Errorf("expected xss detected=0, got %d", xssCov.Detected)
	}
	if xssCov.CoveragePct != 0 {
		t.Errorf("expected xss coverage_pct=0, got %.1f", xssCov.CoveragePct)
	}
}

// ---------------------------------------------------------------------------
// TestReporter_Resilience
// ---------------------------------------------------------------------------

func TestReporter_Resilience(t *testing.T) {
	r := NewReporter()

	// Add a 500 response with a body (handled).
	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:   "GET",
			Path:     "/err1",
			Category: "test",
		},
		StatusCode: 500,
		BodySize:   200, // > 100 so considered "handled"
		Headers:    map[string]string{},
	})

	// Add a transport error.
	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:   "GET",
			Path:     "/err2",
			Category: "test",
		},
		StatusCode: 0,
		Error:      "connection refused",
		Headers:    map[string]string{},
	})

	// Add a 404 (properly handled).
	r.AddResult(ScanResult{
		Request: AttackRequest{
			Method:   "GET",
			Path:     "/404",
			Category: "test",
		},
		StatusCode: 404,
		Headers:    map[string]string{},
	})

	cfg := DefaultConfig()
	report := r.BuildReport(cfg, time.Now(), time.Now())

	ri := report.Resilience
	if ri == nil {
		t.Fatal("resilience is nil")
	}

	// 500 + transport error = 2 errors encountered
	if ri.ErrorsEncountered != 2 {
		t.Errorf("expected 2 errors encountered, got %d", ri.ErrorsEncountered)
	}

	// 500 with body > 100 is handled, plus 404 is handled
	if ri.ErrorsHandled < 1 {
		t.Errorf("expected at least 1 error handled, got %d", ri.ErrorsHandled)
	}

	if ri.ErrorTypes == nil {
		t.Error("error types map is nil")
	}
}

// ---------------------------------------------------------------------------
// TestReporter_WriteHTML
// ---------------------------------------------------------------------------

func TestReporter_WriteHTML(t *testing.T) {
	r := NewReporter()

	r.AddFinding(Finding{
		Category:    "xss",
		Severity:    "high",
		URL:         "/xss",
		Method:      "GET",
		StatusCode:  200,
		Description: "XSS found",
		Evidence:    "<script>alert(1)</script>",
	})

	cfg := DefaultConfig()
	cfg.Target = "http://example.com"
	report := r.BuildReport(cfg, time.Now().Add(-time.Minute), time.Now())

	var buf bytes.Buffer
	err := r.WriteHTML(&buf, report)
	if err != nil {
		t.Fatalf("WriteHTML returned error: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
	if !strings.Contains(html, "Glitch Scanner Report") {
		t.Error("HTML output missing title")
	}
	if !strings.Contains(html, "example.com") {
		t.Error("HTML output missing target")
	}
	if !strings.Contains(html, "xss") {
		t.Error("HTML output missing finding category")
	}
}

// ---------------------------------------------------------------------------
// TestClassifyError
// ---------------------------------------------------------------------------

func TestClassifyError(t *testing.T) {
	tests := []struct {
		errStr   string
		expected string
	}{
		{"connection timeout exceeded", "timeout"},
		{"context deadline exceeded", "timeout"},
		{"connection refused", "connection_refused"},
		{"connection reset by peer", "connection_reset"},
		{"unexpected EOF", "eof"},
		{"tls handshake failed", "tls_error"},
		{"no such host", "dns_error"},
		{"something completely different", "other"},
	}

	for _, tt := range tests {
		got := classifyError(tt.errStr)
		if got != tt.expected {
			t.Errorf("classifyError(%q) = %q, expected %q", tt.errStr, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSeverityForCategory
// ---------------------------------------------------------------------------

func TestSeverityForCategory(t *testing.T) {
	tests := []struct {
		category string
		expected string
	}{
		{"sql-injection", "critical"},
		{"rce", "critical"},
		{"xss", "high"},
		{"ssrf", "high"},
		{"open-redirect", "medium"},
		{"cors", "medium"},
		{"missing-header", "low"},
		{"cookie", "low"},
		{"unknown-cat", "info"},
	}

	for _, tt := range tests {
		got := severityForCategory(tt.category)
		if got != tt.expected {
			t.Errorf("severityForCategory(%q) = %q, expected %q", tt.category, got, tt.expected)
		}
	}
}
