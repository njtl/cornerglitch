// Package regression contains regression tests for bugs that have been found
// and fixed. Each test verifies the fix by checking the correct behavior.
//
// Convention: Test names follow TestRegression_<BugID>_<ShortDescription>
// where BugID matches a git commit or task number.
package regression

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/scaneval"
	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/storage"
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

// ---------------------------------------------------------------------------
// Bug: Nightmare mode toggled traffic recording on/off
//
// Root cause: FeatureFlags.SetAll(true) set ALL flags including the "recorder"
// flag, which is an operational setting (traffic capture) rather than a chaos
// feature. Enabling/disabling nightmare would start/stop traffic recording.
//
// Fix: Excluded recorder from SetAll().
//
// Verified: SetAll(true/false) does not change the recorder flag.
// ---------------------------------------------------------------------------

func TestRegression_NightmareRecorder(t *testing.T) {
	ff := dashboard.NewFeatureFlags()

	// Explicitly disable recorder
	ff.Set("recorder", false)

	// Enabling all features should not affect recorder
	ff.SetAll(true)
	snap := ff.Snapshot()
	if snap["recorder"] {
		t.Error("SetAll(true) must not enable recorder — it is an operational flag, not a chaos feature")
	}

	// Explicitly enable recorder
	ff.Set("recorder", true)

	// Disabling all features should not affect recorder
	ff.SetAll(false)
	snap = ff.Snapshot()
	if !snap["recorder"] {
		t.Error("SetAll(false) must not disable recorder — it is an operational flag, not a chaos feature")
	}

	// All other flags should be affected
	for name, enabled := range snap {
		if name == "recorder" {
			continue
		}
		if enabled {
			t.Errorf("flag %q should be disabled after SetAll(false)", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Bug: Settings not persisted across restarts
//
// Root cause: Config changes via the admin API were only stored in memory.
// No auto-save mechanism existed to write state to disk.
//
// Fix: Added debounced auto-save that writes .glitch-state.json on every
// config change via the admin API, and auto-loads it on startup.
//
// Verified: ExportConfig + ImportConfig round-trip preserves all settings.
// SetStateFile + TriggerAutoSave writes state file that LoadStateFile reads.
// ---------------------------------------------------------------------------

func TestRegression_SettingsPersistence(t *testing.T) {
	// Use a temp file for the state
	tmp, err := os.CreateTemp("", "glitch-state-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	// Configure state file
	dashboard.SetStateFile(tmp.Name())
	defer dashboard.SetStateFile("") // clean up

	// Change a setting
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 3.5)
	dashboard.GetFeatureFlags().Set("labyrinth", false)

	// Trigger auto-save and wait for debounce
	dashboard.TriggerAutoSave()
	time.Sleep(700 * time.Millisecond)

	// Verify file was written
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatalf("State file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("State file is empty")
	}

	// Verify the file contains valid config
	var export dashboard.ConfigExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("State file is not valid JSON: %v", err)
	}
	if export.Version == "" {
		t.Error("State file missing version")
	}

	// Reset config to defaults
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 1.0)
	dashboard.GetFeatureFlags().Set("labyrinth", true)

	// Load state file — should restore settings
	if !dashboard.LoadStateFile() {
		t.Fatal("LoadStateFile returned false")
	}

	snap := dashboard.GetFeatureFlags().Snapshot()
	if snap["labyrinth"] {
		t.Error("labyrinth should be false after loading state file")
	}
}

// ---------------------------------------------------------------------------
// Bug: Race condition in storage SaveConfig version assignment (Task #1)
//
// Root cause: SaveConfig used a two-step SELECT MAX(version) → INSERT pattern.
// Between the SELECT and INSERT, concurrent writers could read the same MAX
// value and attempt to INSERT the same version number, violating the unique
// constraint or (worse) silently overwriting data.
//
// Fix: Replaced with a single atomic INSERT...SELECT statement:
//   INSERT INTO config_versions (entity, version, data)
//   SELECT $1, COALESCE(MAX(version),0)+1, $2 FROM config_versions WHERE entity = $1
// Added retry logic on unique constraint violations for safety.
// Same fix applied to SaveClientProfile in metrics_store.go.
//
// Verified: 10 concurrent SaveConfig goroutines all get unique version numbers.
// ---------------------------------------------------------------------------

func TestRegression_Task1_ConcurrentSaveConfig(t *testing.T) {
	dsn := os.Getenv("GLITCH_DB_URL")
	if dsn == "" {
		dsn = "postgres://glitch:glitch@localhost:5432/glitch?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := storage.NewWithDSN(ctx, dsn)
	if err != nil {
		t.Skipf("PostgreSQL not available, skipping: %v", err)
	}
	defer store.Close()

	// Use a unique entity name to avoid interference with other tests
	entity := fmt.Sprintf("regression_race_test_%d", time.Now().UnixNano())
	const goroutines = 10

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := map[string]interface{}{"writer": i, "ts": time.Now().UnixNano()}
			if err := store.SaveConfig(ctx, entity, data); err != nil {
				errs <- fmt.Errorf("goroutine %d: %w", i, err)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent SaveConfig failed: %v", err)
	}

	// Verify all goroutines produced unique version numbers
	version, err := store.ConfigVersion(ctx, entity)
	if err != nil {
		t.Fatalf("ConfigVersion error: %v", err)
	}
	if version != goroutines {
		t.Errorf("expected %d unique versions, got %d (race condition!)", goroutines, version)
	}

	// Verify version history has no gaps or duplicates
	history, err := store.ListConfigHistory(ctx, entity, goroutines+1)
	if err != nil {
		t.Fatalf("ListConfigHistory error: %v", err)
	}
	if len(history) != goroutines {
		t.Errorf("expected %d history entries, got %d", goroutines, len(history))
	}

	seen := make(map[int]bool)
	for _, entry := range history {
		if seen[entry.Version] {
			t.Errorf("duplicate version %d found in history", entry.Version)
		}
		seen[entry.Version] = true
	}
	for v := 1; v <= goroutines; v++ {
		if !seen[v] {
			t.Errorf("version %d missing from history (gap detected)", v)
		}
	}

	// Clean up test data
	_, _ = store.DB().ExecContext(ctx, `DELETE FROM config_versions WHERE entity = $1`, entity)
}
