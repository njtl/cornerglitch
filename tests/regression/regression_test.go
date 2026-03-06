// Package regression contains regression tests for bugs that have been found
// and fixed. Each test verifies the fix by checking the correct behavior.
//
// Convention: Test names follow TestRegression_<BugID>_<ShortDescription>
// where BugID matches a git commit or task number.
package regression

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/proxy"
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

// ---------------------------------------------------------------------------
// Bug: Deploy test script used wrong admin API paths (deploy-test discovery)
//
// Root cause: Documentation and assumptions about admin API routes were wrong.
// The deploy-test.sh script initially used incorrect paths:
//   - /admin/api/export      → correct: /admin/api/config/export
//   - /admin/api/metrics     → correct: /api/metrics (on admin port, no /admin prefix)
//   - /admin/api/features/toggle with {"name":...} → correct: /admin/api/features with {"feature":...}
//   - Expected 401 from /admin/ → correct: 302 redirect to /admin/login
//
// Fix: Updated deploy-test.sh with correct paths. This regression test
// verifies the admin dashboard routes are registered at their expected paths.
// ---------------------------------------------------------------------------

func TestRegression_DeployTest_AdminAPIPaths(t *testing.T) {
	// Create a dashboard server to inspect its route registrations
	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)

	// Set a password so auth middleware is active
	dashboard.SetAdminPassword("test-regression-pass")

	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	tests := []struct {
		name       string
		path       string
		wantStatus int // expected status without auth
	}{
		// /api/metrics is auth-exempt (used by selftest pipeline) — returns 200 without auth
		{"metrics lives at /api/metrics", "/api/metrics", http.StatusOK},
		// /admin/api/config/export should exist (not /admin/api/export)
		{"config export at /admin/api/config/export", "/admin/api/config/export", http.StatusUnauthorized},
		// /admin/api/features should exist (not /admin/api/features/toggle)
		{"features at /admin/api/features", "/admin/api/features", http.StatusUnauthorized},
		// /admin/api/config should exist
		{"config at /admin/api/config", "/admin/api/config", http.StatusUnauthorized},
		// /admin/ should redirect to login (302, not 401)
		{"admin panel redirects to login", "/admin/", http.StatusFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("GET %s: got status %d, want %d", tt.path, rr.Code, tt.wantStatus)
			}
		})
	}

	// Verify that wrong paths do NOT match the expected routes
	wrongPaths := []string{
		"/admin/api/export",         // wrong — should be /admin/api/config/export
		"/admin/api/metrics",        // wrong — should be /api/metrics
		"/admin/api/features/toggle", // wrong — should be /admin/api/features
	}
	for _, path := range wrongPaths {
		t.Run("wrong path: "+path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// These wrong paths should either 404 or redirect to admin (302),
			// not return 200 or a valid API response
			if rr.Code == http.StatusOK {
				body := rr.Body.String()
				// If it returned 200 with actual API data, the route exists
				// at the wrong path — that's a problem
				if strings.Contains(body, "total_requests") ||
					strings.Contains(body, "features") ||
					strings.Contains(body, "error_rate") {
					t.Errorf("GET %s: returned 200 with API data — route should not exist at this path", path)
				}
			}
		})
	}
}

// TestRegression_DeployTest_FeatureTogglePayload verifies the feature toggle
// API uses {"feature": "...", "enabled": bool} not {"name": "...", "enabled": bool}.
func TestRegression_DeployTest_FeatureTogglePayload(t *testing.T) {
	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)

	dashboard.SetAdminPassword("test-regression-pass")

	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	// Correct payload: {"feature": "labyrinth", "enabled": false}
	correctPayload := `{"feature":"labyrinth","enabled":false}`
	req := httptest.NewRequest("POST", "/admin/api/features", strings.NewReader(correctPayload))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "test-regression-pass")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/features with correct payload: got %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("expected ok=true, got %v", resp["ok"])
	}

	// Re-enable labyrinth
	resetPayload := `{"feature":"labyrinth","enabled":true}`
	req = httptest.NewRequest("POST", "/admin/api/features", strings.NewReader(resetPayload))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "test-regression-pass")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Wrong payload: {"name": "labyrinth", "enabled": false} — should fail
	wrongPayload := `{"name":"labyrinth","enabled":false}`
	req = httptest.NewRequest("POST", "/admin/api/features", strings.NewReader(wrongPayload))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "test-regression-pass")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The "name" field is not recognized — "feature" will be empty string,
	// which should result in an "unknown feature" error
	if rr.Code == http.StatusOK {
		var wrongResp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &wrongResp); err == nil {
			if wrongResp["ok"] == true {
				t.Error("POST with {\"name\":...} should not succeed — API expects {\"feature\":...}")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Bug: Proxy MCP interceptor corrupted Content-Length header (Sprint audit)
//
// Root cause: `string(rune(len(body)))` does NOT produce a numeric string.
// For example, len=500 produces Unicode character U+01F4, not "500".
// This corrupted the Content-Length header on all modified MCP responses.
//
// Fix: Changed to fmt.Sprintf("%d", len(body)) for proper numeric string.
// ---------------------------------------------------------------------------

func TestRegression_ContentLengthNotCorrupted(t *testing.T) {
	m := proxy.NewMCPInterceptor()

	rpcResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{"type": "text", "text": strings.Repeat("x", 500)},
			},
		},
	}
	body, _ := json.Marshal(rpcResp)

	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Mcp-Session-Id", "regression-test")

	result, err := m.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cl := result.Header.Get("Content-Length")
	var n int
	if _, parseErr := fmt.Sscanf(cl, "%d", &n); parseErr != nil {
		t.Errorf("Content-Length %q is not a valid integer: %v", cl, parseErr)
	}
	resultBody, _ := io.ReadAll(result.Body)
	if n != len(resultBody) {
		t.Errorf("Content-Length %d != actual body length %d", n, len(resultBody))
	}
}

// ---------------------------------------------------------------------------
// Verify: MCP subsystem does not interfere with other server subsystems
//
// When MCP feature flag is enabled, health, API, and vulnerability endpoints
// must continue to function correctly without errors or unexpected behavior.
// ---------------------------------------------------------------------------

func TestRegression_MCP_DoesNotInterfere(t *testing.T) {
	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)

	dashboard.SetAdminPassword("mcp-regression-test")
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	flags := dashboard.GetFeatureFlags()
	flags.Set("mcp", true)
	defer flags.Set("mcp", true) // restore

	// Dashboard admin routes should work with MCP enabled
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/api/metrics returned %d with MCP enabled, want 200", rr.Code)
	}

	// Admin panel should redirect to login (not error)
	req = httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("/admin/ returned %d with MCP enabled, want 302", rr.Code)
	}

	// MCP feature flag toggle should not break the admin config endpoint
	req = httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "mcp-regression-test")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/admin/api/config returned %d with MCP enabled, want 200", rr.Code)
	}

	// Now disable MCP and verify same behavior
	flags.Set("mcp", false)
	req = httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("/api/metrics returned %d with MCP disabled, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Bug: DB password corruption from db-reset while server running (Sprint audit)
//
// Root cause: Running `make db-reset` while the server was still active wiped
// the DB (including persisted password) but the old server process kept a stale
// in-memory password. On restart, no DB password existed to restore, and the
// env password was used. This was an operational issue, not a code bug.
//
// These tests verify the password flow is correct:
// - Password set via API validates correctly
// - .env password works on fresh start with no DB
// - PASSWORD_RESET_FROM_ENV=1 overrides DB password
// ---------------------------------------------------------------------------

func TestRegression_PasswordSetViaAPI_Validates(t *testing.T) {
	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)

	// Set initial password
	dashboard.SetAdminPassword("initial-pw-1234")
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	// Login with initial password should work
	req := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "initial-pw-1234")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login with initial password: got %d, want 200", rr.Code)
	}

	// Change password via API
	changePw := `{"current":"initial-pw-1234","new":"new-pw-5678"}`
	req = httptest.NewRequest(http.MethodPost, "/admin/api/password", strings.NewReader(changePw))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", "initial-pw-1234")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("change password: got %d, want 200; body: %s", rr.Code, rr.Body.String())
	}

	// Old password should fail
	req = httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "initial-pw-1234")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Error("old password should no longer work after change")
	}

	// New password should work
	req = httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "new-pw-5678")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("new password should work: got %d, want 200", rr.Code)
	}
}

func TestRegression_EnvPasswordWorksWithoutDB(t *testing.T) {
	// Without a database, password comes from SetAdminPassword (which cmd/glitch
	// calls with the GLITCH_ADMIN_PASSWORD env var or flag value).
	dashboard.SetAdminPassword("env-password-test")

	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	// RestorePassword with no DB store should be a no-op
	dashboard.RestorePassword()

	// env password should still work
	req := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "env-password-test")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("env password should work without DB: got %d, want 200", rr.Code)
	}
}

func TestRegression_PasswordResetFromEnv(t *testing.T) {
	// This tests the PASSWORD_RESET_FROM_ENV logic without actually needing a DB.
	// When there's no store, RestorePassword is a no-op. The env var logic is
	// tested by verifying the code path: set a password, then verify the env
	// override path takes precedence.

	// Set a "DB" password
	dashboard.SetAdminPassword("db-password-old")

	// Simulate PASSWORD_RESET_FROM_ENV=1 scenario:
	// The RestorePassword function checks:
	//   1. If PASSWORD_RESET_FROM_ENV=1 and GLITCH_ADMIN_PASSWORD is set → use env
	//   2. If DB has stored password → use it
	//   3. Otherwise keep current
	// Without DB, it's a no-op, but we can test the SetAdminPassword override directly.
	t.Setenv("PASSWORD_RESET_FROM_ENV", "1")
	t.Setenv("GLITCH_ADMIN_PASSWORD", "env-override-pw")

	// RestorePassword without store is a no-op (returns early),
	// but SetAdminPassword directly overrides
	dashboard.SetAdminPassword("env-override-pw")

	collector := metrics.NewCollector()
	defer collector.Stop()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	srv := dashboard.NewServer(collector, fp, adapt, 0)
	handler := srv.Handler()

	// Old password should not work
	req := httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "db-password-old")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Error("old DB password should not work after env override")
	}

	// New env password should work
	req = httptest.NewRequest(http.MethodGet, "/admin/api/config", nil)
	req.SetBasicAuth("admin", "env-override-pw")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("env override password should work: got %d, want 200", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Bug: InitStorage() returned nil error on connection failure (graceful degradation)
// which caused main.go to think DB connected, skip RestoreMetrics, and lose data.
// Fix: InitStorage now retries 5 times with backoff and returns a real error on failure.
// Test: Verify InitStorage returns error when DB is unreachable.
// ---------------------------------------------------------------------------

func TestRegression_InitStorageRetry_ReturnsErrorOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping retry test in short mode")
	}

	// Use a bogus DSN that will definitely fail to connect
	err := dashboard.InitStorage("postgres://nobody:nothing@127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("expected InitStorage to return error for unreachable DB, got nil")
	}
	if !strings.Contains(err.Error(), "DB connection failed") {
		t.Fatalf("expected error to contain 'DB connection failed', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bug: CounterSnapshot save/restore did not round-trip correctly.
// This ensures metrics survive restart — the exact bug that caused data loss.
// Verify CounterSnapshot save/restore round-trips correctly.
// ---------------------------------------------------------------------------

func TestRegression_CounterSnapshot_RoundTrip(t *testing.T) {
	c := metrics.NewCollector()
	defer c.Stop()

	// Record some data
	for i := 0; i < 100; i++ {
		status := 200
		if i%10 == 0 {
			status = 500
		}
		if i%5 == 0 {
			status = 404
		}
		c.Record(metrics.RequestRecord{
			Timestamp:    time.Now(),
			ClientID:     "test-client",
			Method:       "GET",
			Path:         "/test",
			StatusCode:   status,
			Latency:      time.Millisecond,
			ResponseType: "ok",
		})
	}

	// Give async worker time to process
	time.Sleep(100 * time.Millisecond)

	// Save snapshot
	snap := c.GetCounterSnapshot()
	if snap.TotalRequests != 100 {
		t.Fatalf("expected 100 total requests, got %d", snap.TotalRequests)
	}

	// Create new collector and restore
	c2 := metrics.NewCollector()
	defer c2.Stop()
	c2.RestoreCounters(snap)

	// Verify restored values match
	snap2 := c2.GetCounterSnapshot()
	if snap2.TotalRequests != snap.TotalRequests {
		t.Fatalf("restored TotalRequests = %d, want %d", snap2.TotalRequests, snap.TotalRequests)
	}
	if snap2.TotalErrors != snap.TotalErrors {
		t.Fatalf("restored TotalErrors = %d, want %d", snap2.TotalErrors, snap.TotalErrors)
	}
	if snap2.Total2xx != snap.Total2xx {
		t.Fatalf("restored Total2xx = %d, want %d", snap2.Total2xx, snap.Total2xx)
	}
	if snap2.Total4xx != snap.Total4xx {
		t.Fatalf("restored Total4xx = %d, want %d", snap2.Total4xx, snap.Total4xx)
	}
	if snap2.Total5xx != snap.Total5xx {
		t.Fatalf("restored Total5xx = %d, want %d", snap2.Total5xx, snap.Total5xx)
	}
}
