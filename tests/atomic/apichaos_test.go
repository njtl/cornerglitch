package atomic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glitchWebServer/internal/apichaos"
	"github.com/glitchWebServer/internal/dashboard"
)

// TestAPIChaos_EngineApply verifies that the API chaos engine produces responses
// for each enabled category.
func TestAPIChaos_EngineApply(t *testing.T) {
	e := apichaos.New()
	e.SetProbability(1.0) // always fire

	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/v1/resource", nil)
		e.Apply(w, r)

		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Every response should have a body
		if len(body) == 0 {
			t.Errorf("iteration %d: got empty body", i)
		}
	}
}

// TestAPIChaos_FeatureFlagToggle verifies the feature flag controls API chaos.
func TestAPIChaos_FeatureFlagToggle(t *testing.T) {
	flags := dashboard.GetFeatureFlags()

	// Disable
	flags.Set("api_chaos", false)
	if flags.IsAPIChaosEnabled() {
		t.Error("expected api_chaos to be disabled")
	}

	// Enable
	flags.Set("api_chaos", true)
	if !flags.IsAPIChaosEnabled() {
		t.Error("expected api_chaos to be enabled")
	}

	// Clean up
	flags.Set("api_chaos", false)
}

// TestAPIChaos_AdminConfigProbability verifies probability config round-trips.
func TestAPIChaos_AdminConfigProbability(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	cfg.Set("api_chaos_probability", 75.0)
	got := cfg.Get()
	if prob, ok := got["api_chaos_probability"].(float64); !ok || prob != 75.0 {
		t.Errorf("expected api_chaos_probability=75, got %v", got["api_chaos_probability"])
	}

	// Restore default
	cfg.Set("api_chaos_probability", 30.0)
}

// TestAPIChaos_CategoryToggle verifies per-category toggle in APIChaosConfig.
func TestAPIChaos_CategoryToggle(t *testing.T) {
	acc := dashboard.GetAPIChaosConfig()

	// Disable one category
	acc.SetCategory("malformed_json", false)
	if acc.IsEnabled("malformed_json") {
		t.Error("expected malformed_json to be disabled")
	}

	// Re-enable
	acc.SetCategory("malformed_json", true)
	if !acc.IsEnabled("malformed_json") {
		t.Error("expected malformed_json to be re-enabled")
	}
}

// TestAPIChaos_SetAll verifies bulk enable/disable.
func TestAPIChaos_SetAll(t *testing.T) {
	acc := dashboard.GetAPIChaosConfig()

	acc.SetAll(false)
	snap := acc.Snapshot()
	for cat, enabled := range snap {
		if enabled {
			t.Errorf("expected %s disabled after SetAll(false)", cat)
		}
	}

	acc.SetAll(true)
	snap = acc.Snapshot()
	for cat, enabled := range snap {
		if !enabled {
			t.Errorf("expected %s enabled after SetAll(true)", cat)
		}
	}
}

// TestAPIChaos_ConfigExportImport verifies API chaos config survives export/import.
func TestAPIChaos_ConfigExportImport(t *testing.T) {
	flags := dashboard.GetFeatureFlags()
	cfg := dashboard.GetAdminConfig()
	acc := dashboard.GetAPIChaosConfig()

	// Set up a specific state
	flags.Set("api_chaos", true)
	cfg.Set("api_chaos_probability", 42.0)
	acc.SetCategory("wrong_format", false)
	acc.SetCategory("auth_chaos", false)

	// Export
	export := dashboard.ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	// Verify export has api_chaos_config
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if _, ok := raw["api_chaos_config"]; !ok {
		t.Fatal("export missing api_chaos_config field")
	}

	// Reset state
	flags.Set("api_chaos", false)
	cfg.Set("api_chaos_probability", 30.0)
	acc.SetAll(true)

	// Import
	var reimport dashboard.ConfigExport
	json.Unmarshal(data, &reimport)
	dashboard.ImportConfig(&reimport)

	// Verify restored state
	if !flags.IsAPIChaosEnabled() {
		t.Error("api_chaos flag not restored")
	}
	got := cfg.Get()
	if prob, ok := got["api_chaos_probability"].(float64); !ok || prob != 42.0 {
		t.Errorf("api_chaos_probability not restored, got %v", got["api_chaos_probability"])
	}
	if acc.IsEnabled("wrong_format") {
		t.Error("wrong_format should be disabled after import")
	}
	if acc.IsEnabled("auth_chaos") {
		t.Error("auth_chaos should be disabled after import")
	}
	if !acc.IsEnabled("malformed_json") {
		t.Error("malformed_json should still be enabled after import")
	}

	// Clean up
	flags.Set("api_chaos", false)
	cfg.Set("api_chaos_probability", 30.0)
	acc.SetAll(true)
}

// TestAPIChaos_AdminRoutes verifies the admin API endpoints exist and respond.
func TestAPIChaos_AdminRoutes(t *testing.T) {
	// We need a running server for route tests — skip if not available
	resp, err := http.Get("http://localhost:8766/admin/api/apichaos")
	if err != nil {
		t.Skip("dashboard not running, skipping route tests")
	}
	defer resp.Body.Close()

	// Should either be 200 (logged in) or 401 (not logged in)
	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		t.Errorf("GET /admin/api/apichaos: unexpected status %d", resp.StatusCode)
	}
}

// TestAPIChaos_SingleCategoryOnly verifies responses come from a specific category
// when only one is enabled.
func TestAPIChaos_SingleCategoryOnly(t *testing.T) {
	e := apichaos.New()
	e.SetProbability(1.0)

	// Disable all, enable only wrong_status
	for _, cat := range []string{
		"malformed_json", "wrong_format", "wrong_headers",
		"redirect_chaos", "error_formats", "slow_partial",
		"data_edge_cases", "encoding_chaos", "auth_chaos",
	} {
		e.SetCategoryEnabled(apichaos.ChaosCategory(cat), false)
	}
	// Keep wrong_status enabled

	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/v1/test", nil)
		e.Apply(w, r)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// wrong_status variants return various status codes (200, 500, 418, 451, 103, 207, 226, 204)
		// and always set Content-Type: application/json
		ct := resp.Header.Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("iteration %d: wrong_status expected JSON content-type, got %q", i, ct)
		}
		if len(body) == 0 {
			t.Errorf("iteration %d: got empty body from wrong_status", i)
		}
	}
}

// TestAPIChaos_SnapshotRestore verifies engine state round-trips.
func TestAPIChaos_SnapshotRestore(t *testing.T) {
	e1 := apichaos.New()
	e1.SetProbability(0.75)
	e1.SetCategoryEnabled(apichaos.MalformedJSON, false)
	e1.SetCategoryEnabled(apichaos.SlowPartial, false)

	snap := e1.Snapshot()

	e2 := apichaos.New()
	e2.Restore(snap)

	if e2.GetProbability() != 0.75 {
		t.Errorf("expected probability 0.75, got %f", e2.GetProbability())
	}
	if e2.IsCategoryEnabled(apichaos.MalformedJSON) {
		t.Error("malformed_json should be disabled after restore")
	}
	if e2.IsCategoryEnabled(apichaos.SlowPartial) {
		t.Error("slow_partial should be disabled after restore")
	}
	if !e2.IsCategoryEnabled(apichaos.WrongFormat) {
		t.Error("wrong_format should still be enabled after restore")
	}
}

// TestAPIChaos_AllCategoriesProduceOutput verifies every category generates a response.
func TestAPIChaos_AllCategoriesProduceOutput(t *testing.T) {
	categories := []string{
		"malformed_json", "wrong_format", "wrong_status", "wrong_headers",
		"redirect_chaos", "error_formats", "data_edge_cases",
		"encoding_chaos", "auth_chaos",
	}
	// Note: slow_partial is excluded because it uses time.Sleep and would slow tests

	for _, cat := range categories {
		t.Run(cat, func(t *testing.T) {
			e := apichaos.New()
			e.SetProbability(1.0)
			// Disable all except this one
			for _, c := range categories {
				e.SetCategoryEnabled(apichaos.ChaosCategory(c), c == cat)
			}
			// Also disable slow_partial
			e.SetCategoryEnabled(apichaos.SlowPartial, false)

			// Run multiple times to hit different variants
			for i := 0; i < 10; i++ {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/%s/%d", cat, i), nil)
				e.Apply(w, r)
				resp := w.Result()
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if len(body) == 0 && resp.StatusCode != http.StatusNoContent {
					t.Errorf("variant %d: got empty body", i)
				}
			}
		})
	}
}

// TestAPIChaos_ShouldApplyProbability verifies probability distribution is roughly correct.
func TestAPIChaos_ShouldApplyProbability(t *testing.T) {
	e := apichaos.New()
	e.SetProbability(0.5)

	hits := 0
	trials := 10000
	for i := 0; i < trials; i++ {
		if e.ShouldApply() {
			hits++
		}
	}

	ratio := float64(hits) / float64(trials)
	if ratio < 0.4 || ratio > 0.6 {
		t.Errorf("expected ~50%% hit rate, got %.2f%%", ratio*100)
	}
}

// TestAPIChaos_NoCategoriesEnabled verifies graceful handling when all categories disabled.
func TestAPIChaos_NoCategoriesEnabled(t *testing.T) {
	e := apichaos.New()
	e.SetProbability(1.0)

	// Disable all categories
	for _, cat := range []string{
		"malformed_json", "wrong_format", "wrong_status", "wrong_headers",
		"redirect_chaos", "error_formats", "slow_partial",
		"data_edge_cases", "encoding_chaos", "auth_chaos",
	} {
		e.SetCategoryEnabled(apichaos.ChaosCategory(cat), false)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/test", nil)
	e.Apply(w, r)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 when no categories enabled, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "no enabled categories") {
		t.Errorf("expected error message about no categories, got: %s", string(body))
	}
}
