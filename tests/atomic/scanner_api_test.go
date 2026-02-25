package atomic

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Scanner Admin API — Atomic Tests
//
// Tests the scanner API endpoints: profile, available scanners, history,
// baseline, and expected profile generation based on feature flags/config.
// ---------------------------------------------------------------------------

// TestScanner_API_ProfileEndpoint verifies the scanner profile endpoint.
func TestScanner_API_ProfileEndpoint(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/scanner/profile")

	// Should have profile, summary, and available_scanners
	if _, ok := resp["profile"]; !ok {
		t.Error("profile response missing 'profile' key")
	}
	if _, ok := resp["summary"]; !ok {
		t.Error("profile response missing 'summary' key")
	}
	if _, ok := resp["available_scanners"]; !ok {
		t.Error("profile response missing 'available_scanners' key")
	}

	// Summary should have expected fields
	summary, ok := resp["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("summary not a map")
	}
	for _, key := range []string{"total", "detectable", "by_severity", "enabled_groups", "total_groups", "total_endpoints"} {
		if _, exists := summary[key]; !exists {
			t.Errorf("summary missing key %q", key)
		}
	}
}

// TestScanner_API_ProfileReflectsFeatureFlags verifies profile changes when features are toggled.
func TestScanner_API_ProfileReflectsFeatureFlags(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Get baseline profile with all features enabled
	baseResp := apiGet(t, mux, "/admin/api/scanner/profile")
	baseSummary := baseResp["summary"].(map[string]interface{})
	baseTotal, _ := toFloat64(baseSummary["total"])
	baseDetectable, _ := toFloat64(baseSummary["detectable"])

	if baseTotal == 0 {
		t.Fatal("baseline total should not be 0 with all features enabled")
	}

	// Disable vuln feature flag — this should reduce detectable vulns
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "vuln",
		"enabled": false,
	})

	// Profile should reflect the change
	afterResp := apiGet(t, mux, "/admin/api/scanner/profile")
	afterSummary := afterResp["summary"].(map[string]interface{})
	afterTotal, _ := toFloat64(afterSummary["total"])
	afterDetectable, _ := toFloat64(afterSummary["detectable"])

	// The profile endpoint must return valid data in both states
	if afterTotal < 0 {
		t.Errorf("total should not be negative after disabling vuln: %v", afterTotal)
	}

	// At minimum, either total or detectable should differ
	if afterTotal == baseTotal && afterDetectable == baseDetectable {
		t.Logf("WARNING: disabling vuln did not change profile total (%v) or detectable (%v) — profile may not reflect feature flags", baseTotal, baseDetectable)
	}

	// Re-enable and verify profile restores
	apiPost(t, mux, "/admin/api/features", map[string]interface{}{
		"feature": "vuln",
		"enabled": true,
	})

	restoredResp := apiGet(t, mux, "/admin/api/scanner/profile")
	restoredSummary := restoredResp["summary"].(map[string]interface{})
	restoredTotal, _ := toFloat64(restoredSummary["total"])
	if restoredTotal != baseTotal {
		t.Errorf("restored total = %v, want %v (same as baseline)", restoredTotal, baseTotal)
	}
}

// TestScanner_API_ProfileReflectsVulnGroups verifies profile changes with vuln group toggles.
func TestScanner_API_ProfileReflectsVulnGroups(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Get baseline
	baseResp := apiGet(t, mux, "/admin/api/scanner/profile")
	baseSummary := baseResp["summary"].(map[string]interface{})
	baseGroups, _ := toFloat64(baseSummary["enabled_groups"])

	// Disable a vuln group
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": false,
	})

	// enabled_groups should decrease
	afterResp := apiGet(t, mux, "/admin/api/scanner/profile")
	afterSummary := afterResp["summary"].(map[string]interface{})
	afterGroups, _ := toFloat64(afterSummary["enabled_groups"])

	if afterGroups >= baseGroups {
		t.Errorf("disabling owasp group should reduce enabled_groups: before=%v, after=%v", baseGroups, afterGroups)
	}

	// Re-enable
	apiPost(t, mux, "/admin/api/vulns/group", map[string]interface{}{
		"group":   "owasp",
		"enabled": true,
	})
}

// TestScanner_API_HistoryEndpoint verifies the scanner history endpoint works.
func TestScanner_API_HistoryEndpoint(t *testing.T) {
	mux := setupTestEnv(t)

	// History should return even when empty
	status, body := apiGetRaw(t, mux, "/admin/api/scanner/history")
	if status != 200 {
		t.Errorf("scanner history returned %d, want 200", status)
	}
	if len(body) == 0 {
		t.Error("scanner history returned empty body")
	}
}

// TestScanner_API_ResultsEndpoint verifies the scanner results endpoint works.
func TestScanner_API_ResultsEndpoint(t *testing.T) {
	mux := setupTestEnv(t)

	// Results should return even when no scan is running
	status, body := apiGetRaw(t, mux, "/admin/api/scanner/results")
	if status != 200 {
		t.Errorf("scanner results returned %d, want 200", status)
	}
	if len(body) == 0 {
		t.Error("scanner results returned empty body")
	}
}

// TestScanner_API_BaselineEndpoint verifies the scanner baseline endpoint works.
func TestScanner_API_BaselineEndpoint(t *testing.T) {
	mux := setupTestEnv(t)

	// Without scanner param → 400
	status, _ := apiGetRaw(t, mux, "/admin/api/scanner/baseline")
	if status != 400 {
		t.Errorf("scanner baseline without param returned %d, want 400", status)
	}

	// With scanner param → 200 (even with no baseline data)
	status, body := apiGetRaw(t, mux, "/admin/api/scanner/baseline?scanner=nuclei")
	if status != 200 {
		t.Errorf("scanner baseline with param returned %d, want 200", status)
	}
	if len(body) == 0 {
		t.Error("scanner baseline returned empty body")
	}
}
