// Package regression contains regression tests for bugs that have been found
// and fixed. Each test verifies the fix by checking the correct behavior.
//
// Convention: Test names follow TestRegression_<BugID>_<ShortDescription>
// where BugID matches a git commit or task number.
package regression

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/scaneval"
	"github.com/glitchWebServer/internal/scanner"
)

// ---------------------------------------------------------------------------
// Bug: Scanner progress API returned 0/0/0 during crawl phase (Task #69)
//
// Root cause: Engine.Progress() only incremented during executeAll (Phase 3).
// During crawl phase (up to 90s with CrawlFirst=true), all counters stayed
// at zero. Only elapsed_ms updated.
//
// Fix: Added phase tracking via atomic.Value so API reports current phase
// and UI can show phase-appropriate feedback (crawling/generating/scanning).
// ---------------------------------------------------------------------------

func TestRegression_Task69_ScannerPhaseTracking(t *testing.T) {
	cfg := scanner.DefaultConfig()
	cfg.Target = "http://localhost:1"
	cfg.CrawlFirst = true

	eng := scanner.NewEngine(cfg)

	// Before Run, phase must be "init"
	if phase := eng.Phase(); phase != "init" {
		t.Errorf("expected initial phase='init', got %q", phase)
	}

	// Progress must be 0/0/0 initially
	completed, total, findings := eng.Progress()
	if completed != 0 || total != 0 || findings != 0 {
		t.Errorf("expected 0/0/0 progress before run, got %d/%d/%d", completed, total, findings)
	}
}

func TestRegression_Task69_PhaseTransitions(t *testing.T) {
	cfg := scanner.DefaultConfig()
	cfg.Target = "http://localhost:1"
	cfg.CrawlFirst = false
	cfg.Concurrency = 1
	cfg.RateLimit = 100

	eng := scanner.NewEngine(cfg)

	// Register no modules → completes instantly
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := eng.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}

	// After completion, phase must be "done"
	if phase := eng.Phase(); phase != "done" {
		t.Errorf("expected final phase='done', got %q", phase)
	}
}

func TestRegression_Task69_PhaseNeverEmpty(t *testing.T) {
	eng := scanner.NewEngine(scanner.DefaultConfig())
	if phase := eng.Phase(); phase == "" {
		t.Error("Phase() must never return empty string")
	}
}

func TestRegression_Task69_ProfileCrawlFirstSettings(t *testing.T) {
	tests := []struct {
		name       string
		config     *scanner.Config
		crawlFirst bool
	}{
		{"default", scanner.DefaultConfig(), false},
		{"compliance", scanner.ComplianceConfig(), true},
		{"aggressive", scanner.AggressiveConfig(), true},
		{"stealth", scanner.StealthConfig(), true},
		{"nightmare", scanner.NightmareConfig(), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.CrawlFirst != tt.crawlFirst {
				t.Errorf("%s: CrawlFirst=%v, want %v", tt.name, tt.config.CrawlFirst, tt.crawlFirst)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bug: JS/JSON field name mismatch in admin panel (Commit 01d51f8)
//
// Root cause: Go structs use snake_case JSON tags (exit_code, crash_signal,
// not_installed, etc.) but JavaScript referenced PascalCase (ExitCode,
// CrashSignal, NotInstalled). All scanner history/result/comparison views
// displayed empty data.
//
// Fix: Updated all JS to use snake_case matching JSON tags.
// These tests verify JSON serialization produces correct field names.
// ---------------------------------------------------------------------------

func TestRegression_01d51f8_ScanResultFieldNames(t *testing.T) {
	result := scaneval.ScanResult{
		Scanner:      "nuclei",
		ExitCode:     1,
		RawOutput:    "test output",
		Crashed:      true,
		TimedOut:     false,
		RequestCount: 42,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	jsonStr := string(data)

	// Must be snake_case
	requiredFields := []string{
		`"scanner"`, `"exit_code"`, `"raw_output"`,
		`"crashed"`, `"timed_out"`, `"request_count"`,
	}
	for _, field := range requiredFields {
		if !strings.Contains(jsonStr, field) {
			t.Errorf("JSON missing expected snake_case field %s", field)
		}
	}

	// PascalCase must NOT appear
	badFields := []string{
		`"ExitCode"`, `"CrashSignal"`, `"RawOutput"`,
		`"Crashed"`, `"TimedOut"`, `"RequestCount"`,
	}
	for _, field := range badFields {
		if strings.Contains(jsonStr, field) {
			t.Errorf("JSON contains PascalCase field %s — must be snake_case", field)
		}
	}
}

func TestRegression_01d51f8_ComparisonReportTopLevelFields(t *testing.T) {
	report := scaneval.ComparisonReport{
		Scanner:         "nuclei",
		ExpectedVulns:   10,
		FoundVulns:      5,
		DetectionRate:   0.5,
		ScannerCrashed:  false,
		ScannerTimedOut: false,
		ScannerErrors:   []string{"test error"},
		Grade:           "B",
	}

	data, _ := json.Marshal(report)
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	// scanner_crashed/scanner_timed_out/scanner_errors must be TOP-LEVEL
	// The bug: JS looked for nested report.scanner_health.crashed
	for _, field := range []string{"scanner_crashed", "scanner_timed_out", "scanner_errors"} {
		if _, exists := parsed[field]; !exists {
			t.Errorf("%s must be a top-level field", field)
		}
	}

	// Must NOT have nested scanner_health object
	if _, exists := parsed["scanner_health"]; exists {
		t.Error("scanner_health should not exist — fields are top-level")
	}
}

func TestRegression_01d51f8_MatchedVulnStructure(t *testing.T) {
	// Bug: JS accessed item.name instead of item.expected.name for TP items
	mv := scaneval.MatchedVuln{
		Expected: scaneval.VulnCategory{
			Name:      "Test Vuln",
			Endpoints: []string{"/test1", "/test2"},
		},
		Found: scaneval.Finding{
			Title: "Found It",
			URL:   "/test1",
		},
	}

	data, _ := json.Marshal(mv)
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	// expected must be a nested object with name + endpoints (array)
	expected, ok := parsed["expected"].(map[string]interface{})
	if !ok {
		t.Fatal("'expected' must be a nested object in MatchedVuln")
	}
	if expected["name"] != "Test Vuln" {
		t.Errorf("expected.name = %v, want 'Test Vuln'", expected["name"])
	}
	eps, ok := expected["endpoints"].([]interface{})
	if !ok {
		t.Fatal("expected.endpoints must be an array")
	}
	if len(eps) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(eps))
	}

	// found must be a nested object with title + url
	found, ok := parsed["found"].(map[string]interface{})
	if !ok {
		t.Fatal("'found' must be a nested object in MatchedVuln")
	}
	if found["title"] != "Found It" {
		t.Errorf("found.title = %v, want 'Found It'", found["title"])
	}
	if found["url"] != "/test1" {
		t.Errorf("found.url = %v, want '/test1'", found["url"])
	}
}

func TestRegression_01d51f8_VulnCategoryEndpointsIsArray(t *testing.T) {
	// Bug: JS used item.endpoint (singular) instead of item.endpoints (array)
	vc := scaneval.VulnCategory{
		ID:        "test",
		Name:      "Test",
		Severity:  "high",
		Endpoints: []string{"/path1", "/path2", "/path3"},
	}

	data, _ := json.Marshal(vc)
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	if _, exists := parsed["endpoints"]; !exists {
		t.Error("VulnCategory must have 'endpoints' (plural) field")
	}
	if _, exists := parsed["endpoint"]; exists {
		t.Error("VulnCategory must NOT have singular 'endpoint' field")
	}

	eps, ok := parsed["endpoints"].([]interface{})
	if !ok {
		t.Fatal("endpoints must be an array")
	}
	if len(eps) != 3 {
		t.Errorf("expected 3 endpoints, got %d", len(eps))
	}
}

func TestRegression_01d51f8_FindingUseTitleAndURL(t *testing.T) {
	// Bug: JS used item.name and item.endpoint instead of item.title and item.url
	f := scaneval.Finding{
		ID:       "test-finding",
		Title:    "XSS Detected",
		Severity: "high",
		URL:      "http://localhost/test",
	}

	data, _ := json.Marshal(f)
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	if _, exists := parsed["title"]; !exists {
		t.Error("Finding must have 'title' field")
	}
	if _, exists := parsed["url"]; !exists {
		t.Error("Finding must have 'url' field")
	}
	if _, exists := parsed["name"]; exists {
		t.Error("Finding must NOT have 'name' field (use 'title')")
	}
	if _, exists := parsed["endpoint"]; exists {
		t.Error("Finding must NOT have 'endpoint' field (use 'url')")
	}
}
