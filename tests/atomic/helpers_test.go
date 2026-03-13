// Package atomic provides comprehensive atomic tests for every individual setting
// in the Glitch server, scanner, and proxy. Each test validates a single setting
// in isolation using dual-layer verification (HTTP response + internal state).
//
// Test tiers:
//   - Tier 1 (Smoke): Core settings — run on every build
//   - Tier 2 (Regression): Full atomic suite — run on release candidates
//   - Tier 3 (Comprehensive): Combinations + cross-scope — run on demand
//
// Tags: Use -run flags to select scopes:
//   go test ./tests/atomic/ -run TestServer       # server scope only
//   go test ./tests/atomic/ -run TestScanner      # scanner scope only
//   go test ./tests/atomic/ -run TestProxy        # proxy scope only
//   go test ./tests/atomic/ -run TestCombo        # combination tests
package atomic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cornerglitch/internal/adaptive"
	"github.com/cornerglitch/internal/dashboard"
	"github.com/cornerglitch/internal/fingerprint"
	"github.com/cornerglitch/internal/metrics"
)

// ---------------------------------------------------------------------------
// Test environment — shared HTTP test server for admin API
// ---------------------------------------------------------------------------

var (
	testServerOnce sync.Once
	testMux        *http.ServeMux
	testDashServer *dashboard.Server
)

// setupTestEnv creates a shared admin dashboard mux for all tests.
// Uses httptest for zero-cost request processing — no real TCP needed.
func setupTestEnv(t *testing.T) *http.ServeMux {
	t.Helper()
	testServerOnce.Do(func() {
		collector := metrics.NewCollector()
		fp := fingerprint.NewEngine()
		adapt := adaptive.NewEngine(collector, fp)
		testDashServer = dashboard.NewServer(collector, fp, adapt, 0)
		testMux = http.NewServeMux()
		dashboard.RegisterAdminRoutes(testMux, testDashServer)
	})
	return testMux
}

// ---------------------------------------------------------------------------
// Baseline state management — reset to known state before each test
// ---------------------------------------------------------------------------

// resetFeatureFlags restores all feature flags to their default (all enabled).
func resetFeatureFlags(t *testing.T) {
	t.Helper()
	flags := dashboard.GetFeatureFlags()
	defaults := map[string]bool{
		"labyrinth": true, "error_inject": true, "captcha": true,
		"honeypot": true, "vuln": true, "analytics": true,
		"cdn": true, "oauth": true, "header_corrupt": true,
		"cookie_traps": true, "js_traps": true, "bot_detection": true,
		"random_blocking": true, "framework_emul": true, "search": true,
		"email": true, "i18n": true, "recorder": true,
		"websocket": true, "privacy": true, "health": true, "spider": true,
		"api_chaos": true, "media_chaos": true, "budget_traps": true, "mcp": true, "browser_chaos": true,
	}
	for name, enabled := range defaults {
		flags.Set(name, enabled)
	}
}

// resetAdminConfig restores all admin config to sensible defaults.
func resetAdminConfig(t *testing.T) {
	t.Helper()
	cfg := dashboard.GetAdminConfig()
	cfg.Set("max_labyrinth_depth", 50)
	cfg.Set("error_rate_multiplier", 1.0)
	cfg.Set("captcha_trigger_thresh", 100)
	cfg.Set("block_chance", 0.02)
	cfg.Set("block_duration_sec", 30)
	cfg.Set("bot_score_threshold", 60)
	cfg.Set("header_corrupt_level", 1)
	cfg.Set("delay_min_ms", 0)
	cfg.Set("delay_max_ms", 0)
	cfg.Set("labyrinth_link_density", 8)
	cfg.Set("adaptive_interval_sec", 30)
	cfg.Set("protocol_glitch_enabled", 1) // true
	cfg.Set("protocol_glitch_level", 2)
	cfg.Set("cookie_trap_frequency", 3)
	cfg.Set("js_trap_difficulty", 2)
	cfg.Set("content_cache_ttl_sec", 60)
	cfg.Set("adaptive_aggressive_rps", 10)
	cfg.Set("adaptive_labyrinth_paths", 5)
	cfg.SetString("honeypot_response_style", "realistic")
	cfg.SetString("active_framework", "auto")
	cfg.SetString("content_theme", "default")
	cfg.SetString("recorder_format", "jsonl")
	cfg.ResetErrorWeights()
	cfg.ResetPageTypeWeights()
}

// resetVulnConfig restores all vuln groups to enabled and clears categories.
func resetVulnConfig(t *testing.T) {
	t.Helper()
	vc := dashboard.GetVulnConfig()
	for _, g := range dashboard.VulnGroups {
		vc.SetGroup(g, true)
	}
}

// resetNightmareState ensures nightmare is off for all subsystems.
func resetNightmareState(t *testing.T) {
	t.Helper()
	ns := dashboard.GetNightmareState()
	ns.Reset()
}

// resetAll resets all state to baseline defaults.
func resetAll(t *testing.T) {
	t.Helper()
	resetFeatureFlags(t)
	resetAdminConfig(t)
	resetVulnConfig(t)
	resetNightmareState(t)
	resetSpiderConfig(t)
}

// ---------------------------------------------------------------------------
// HTTP API helpers — call admin API endpoints and parse responses
// ---------------------------------------------------------------------------

// apiPost sends a JSON POST to the given path and returns the parsed response.
func apiPost(t *testing.T, mux *http.ServeMux, path string, body interface{}) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	resp := rec.Result()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s returned %d: %s", path, resp.StatusCode, string(respBody))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("unmarshal response from %s: %v (body: %s)", path, err, string(respBody))
	}
	return result
}

// apiGet sends a GET request and returns the parsed JSON response.
func apiGet(t *testing.T, mux *http.ServeMux, path string) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	resp := rec.Result()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", path, resp.StatusCode, string(respBody))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("unmarshal response from %s: %v (body: %s)", path, err, string(respBody))
	}
	return result
}

// apiGetRaw sends a GET request and returns the raw body bytes.
func apiGetRaw(t *testing.T, mux *http.ServeMux, path string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	resp := rec.Result()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// ---------------------------------------------------------------------------
// Dual-layer verification helpers
// ---------------------------------------------------------------------------

// verifyFeatureFlag checks both API response and internal state for a feature.
func verifyFeatureFlag(t *testing.T, mux *http.ServeMux, name string, expected bool) {
	t.Helper()
	// Layer 1: External — read via API (returns flat map of flag->bool)
	resp := apiGet(t, mux, "/admin/api/features")
	apiVal, ok := resp[name].(bool)
	if !ok {
		t.Fatalf("feature %q not found in API response or wrong type (resp keys: %v)", name, mapKeys(resp))
	}
	if apiVal != expected {
		t.Errorf("[API] feature %q = %v, want %v", name, apiVal, expected)
	}

	// Layer 2: Internal — read via exported getter
	snap := dashboard.GetFeatureFlags().Snapshot()
	internalVal := snap[name]
	if internalVal != expected {
		t.Errorf("[Internal] feature %q = %v, want %v", name, internalVal, expected)
	}
}

// mapKeys returns the keys of a map for diagnostic messages.
func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// verifyConfigValue checks both API response and internal state for a config key.
func verifyConfigValue(t *testing.T, mux *http.ServeMux, key string, expected interface{}) {
	t.Helper()
	// Layer 1: External — read via API
	resp := apiGet(t, mux, "/admin/api/config")
	apiVal, ok := resp[key]
	if !ok {
		t.Fatalf("config key %q not found in API response", key)
	}
	if !valuesEqual(apiVal, expected) {
		t.Errorf("[API] config %q = %v (%T), want %v (%T)", key, apiVal, apiVal, expected, expected)
	}

	// Layer 2: Internal — read via exported getter
	internalCfg := dashboard.GetAdminConfig().Get()
	internalVal, ok := internalCfg[key]
	if !ok {
		t.Fatalf("config key %q not found in internal state", key)
	}
	if !valuesEqual(internalVal, expected) {
		t.Errorf("[Internal] config %q = %v (%T), want %v (%T)", key, internalVal, internalVal, expected, expected)
	}
}

// verifyVulnGroup checks both API response and internal state for a vuln group.
func verifyVulnGroup(t *testing.T, mux *http.ServeMux, group string, expected bool) {
	t.Helper()
	// Layer 1: External — read via API
	resp := apiGet(t, mux, "/admin/api/vulns")
	groups, ok := resp["groups"].(map[string]interface{})
	if !ok {
		t.Fatalf("vulns response 'groups' has unexpected type: %T", resp["groups"])
	}
	apiVal, ok := groups[group].(bool)
	if !ok {
		t.Fatalf("vuln group %q not found or wrong type in API response", group)
	}
	if apiVal != expected {
		t.Errorf("[API] vuln group %q = %v, want %v", group, apiVal, expected)
	}

	// Layer 2: Internal
	internalVal := dashboard.GetVulnConfig().IsGroupEnabled(group)
	if internalVal != expected {
		t.Errorf("[Internal] vuln group %q = %v, want %v", group, internalVal, expected)
	}
}

// valuesEqual compares two values, handling JSON number type coercion.
func valuesEqual(a, b interface{}) bool {
	// JSON numbers are float64, Go ints need coercion
	af, aIsFloat := toFloat64(a)
	bf, bIsFloat := toFloat64(b)
	if aIsFloat && bIsFloat {
		return af == bf
	}
	// String comparison
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr && bIsStr {
		return as == bs
	}
	// Bool comparison
	ab, aIsBool := a.(bool)
	bb, bIsBool := b.(bool)
	if aIsBool && bIsBool {
		return ab == bb
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// makePostRequest creates a POST request with JSON body.
func makePostRequest(t *testing.T, path string, body interface{}) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// makeRecorder creates an httptest.ResponseRecorder.
func makeRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

// resetSpiderConfig restores spider config to defaults.
func resetSpiderConfig(t *testing.T) {
	t.Helper()
	cfg := dashboard.GetSpiderConfig()
	cfg.Set("sitemap_error_rate", 0.15)
	cfg.Set("sitemap_gzip_error_rate", 0.10)
	cfg.Set("favicon_error_rate", 0.20)
	cfg.Set("robots_error_rate", 0.10)
	cfg.Set("meta_error_rate", 0.10)
	cfg.Set("enable_sitemap_index", true)
	cfg.Set("enable_gzip_sitemap", true)
	cfg.Set("sitemap_entry_count", 50)
	cfg.Set("robots_crawl_delay", 2)
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	}
	return 0, false
}
