package atomic

import (
	"fmt"
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Admin Config — Atomic Tests
//
// Tests every numeric and string config parameter: set, verify, boundary
// values, clamping, reset to default. Dual-layer verification throughout.
// ---------------------------------------------------------------------------

// numericConfigSpec describes a numeric config parameter for table-driven tests.
type numericConfigSpec struct {
	Key      string
	Default  float64
	Min      float64 // expected min after clamping
	Max      float64 // expected max after clamping
	TestVals []float64
}

var numericConfigs = []numericConfigSpec{
	{"max_labyrinth_depth", 50, 1, 100, []float64{1, 25, 50, 75, 100}},
	{"error_rate_multiplier", 1.0, 0, 5.0, []float64{0, 0.5, 1.0, 2.5, 5.0}},
	{"captcha_trigger_thresh", 100, 0, 10000, []float64{0, 1, 50, 100, 500}},
	{"block_chance", 0.02, 0, 1.0, []float64{0, 0.01, 0.1, 0.5, 1.0}},
	{"block_duration_sec", 30, 1, 3600, []float64{1, 10, 30, 300, 3600}},
	{"bot_score_threshold", 60, 0, 100, []float64{0, 20, 60, 80, 100}},
	{"header_corrupt_level", 1, 0, 4, []float64{0, 1, 2, 3, 4}},
	{"delay_min_ms", 0, 0, 10000, []float64{0, 100, 500, 1000}},
	{"delay_max_ms", 0, 0, 10000, []float64{0, 100, 500, 5000}},
	{"labyrinth_link_density", 8, 1, 20, []float64{1, 5, 8, 15, 20}},
	{"adaptive_interval_sec", 30, 5, 300, []float64{5, 15, 30, 120, 300}},
	{"cookie_trap_frequency", 3, 0, 20, []float64{0, 1, 3, 10, 20}},
	{"js_trap_difficulty", 2, 0, 5, []float64{0, 1, 2, 3, 4, 5}},
	{"content_cache_ttl_sec", 60, 0, 3600, []float64{0, 30, 60, 600, 3600}},
	{"adaptive_aggressive_rps", 10, 1, 100, []float64{1, 5, 10, 50, 100}},
	{"adaptive_labyrinth_paths", 5, 1, 50, []float64{1, 3, 5, 25, 50}},
	{"protocol_glitch_level", 2, 0, 4, []float64{0, 1, 2, 3, 4}},
}

// TestServer_Config_NumericDefaults verifies all numeric config defaults.
func TestServer_Config_NumericDefaults(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	for _, spec := range numericConfigs {
		t.Run(spec.Key+"_default", func(t *testing.T) {
			verifyConfigValue(t, mux, spec.Key, spec.Default)
		})
	}
}

// TestServer_Config_NumericSetAndVerify tests setting each value and verifying.
func TestServer_Config_NumericSetAndVerify(t *testing.T) {
	mux := setupTestEnv(t)

	for _, spec := range numericConfigs {
		t.Run(spec.Key, func(t *testing.T) {
			for _, val := range spec.TestVals {
				t.Run(fmtFloat(val), func(t *testing.T) {
					resetAdminConfig(t)

					// Set via API
					resp := apiPost(t, mux, "/admin/api/config", map[string]interface{}{
						"key":   spec.Key,
						"value": val,
					})
					if resp["ok"] != true {
						t.Fatalf("POST config returned ok=%v", resp["ok"])
					}

					// Verify (dual-layer)
					verifyConfigValue(t, mux, spec.Key, val)
				})
			}
		})
	}
}

// TestServer_Config_NumericClamping tests boundary clamping for each parameter.
func TestServer_Config_NumericClamping(t *testing.T) {
	mux := setupTestEnv(t)

	clampTests := []struct {
		key      string
		input    float64
		expected float64
	}{
		// Below min
		{"max_labyrinth_depth", -10, 1},
		{"max_labyrinth_depth", 0, 1},
		{"error_rate_multiplier", -1, 0},
		{"block_chance", -0.5, 0},
		{"block_duration_sec", 0, 1},
		{"block_duration_sec", -5, 1},
		{"header_corrupt_level", -1, 0},
		{"labyrinth_link_density", 0, 1},
		{"labyrinth_link_density", -5, 1},
		{"adaptive_interval_sec", 1, 5},
		{"cookie_trap_frequency", -1, 0},
		{"js_trap_difficulty", -1, 0},
		{"content_cache_ttl_sec", -10, 0},
		{"adaptive_aggressive_rps", 0, 1},
		{"adaptive_labyrinth_paths", 0, 1},
		{"protocol_glitch_level", -1, 0},
		// Above max
		{"max_labyrinth_depth", 200, 100},
		{"error_rate_multiplier", 10, 5.0},
		{"block_chance", 2.0, 1.0},
		{"block_duration_sec", 5000, 3600},
		{"bot_score_threshold", 200, 100},
		{"header_corrupt_level", 10, 4},
		{"labyrinth_link_density", 50, 20},
		{"adaptive_interval_sec", 500, 300},
		{"cookie_trap_frequency", 30, 20},
		{"js_trap_difficulty", 10, 5},
		{"content_cache_ttl_sec", 5000, 3600},
		{"adaptive_aggressive_rps", 200, 100},
		{"adaptive_labyrinth_paths", 100, 50},
		{"protocol_glitch_level", 10, 4},
	}

	for _, tc := range clampTests {
		t.Run(tc.key+"_clamp_"+fmtFloat(tc.input), func(t *testing.T) {
			resetAdminConfig(t)

			apiPost(t, mux, "/admin/api/config", map[string]interface{}{
				"key":   tc.key,
				"value": tc.input,
			})

			verifyConfigValue(t, mux, tc.key, tc.expected)
		})
	}
}

// TestServer_Config_NumericIsolation verifies changing one config doesn't affect others.
func TestServer_Config_NumericIsolation(t *testing.T) {
	mux := setupTestEnv(t)

	for _, target := range numericConfigs {
		t.Run(target.Key, func(t *testing.T) {
			resetAdminConfig(t)

			// Snapshot baseline
			baselineResp := apiGet(t, mux, "/admin/api/config")

			// Change only the target
			newVal := target.Max
			apiPost(t, mux, "/admin/api/config", map[string]interface{}{
				"key":   target.Key,
				"value": newVal,
			})

			// Verify all OTHER configs unchanged
			afterResp := apiGet(t, mux, "/admin/api/config")
			for _, other := range numericConfigs {
				if other.Key == target.Key {
					continue
				}
				before := baselineResp[other.Key]
				after := afterResp[other.Key]
				if !valuesEqual(before, after) {
					t.Errorf("config %q changed from %v to %v when only %q was modified",
						other.Key, before, after, target.Key)
				}
			}
		})
	}
}

// TestServer_Config_UnknownKeyReturnsError tests that unknown config keys are rejected.
func TestServer_Config_UnknownKeyReturnsError(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	unknowns := []string{"nonexistent", "foo", "max_labyrinth", ""}
	for _, key := range unknowns {
		t.Run(key, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/config", map[string]interface{}{
				"key":   key,
				"value": 42,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("unknown config key %q should return error, got 200", key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// String Config Tests
// ---------------------------------------------------------------------------

type stringConfigSpec struct {
	Key      string
	Default  string
	TestVals []string
}

var stringConfigs = []stringConfigSpec{
	{"honeypot_response_style", "realistic", []string{"realistic", "obvious", "minimal"}},
	{"active_framework", "auto", []string{"auto", "express", "django", "rails", "laravel", "spring"}},
	{"content_theme", "default", []string{"default", "dark", "corporate", "minimal", "vibrant"}},
	{"recorder_format", "jsonl", []string{"jsonl", "pcap"}},
}

// TestServer_Config_StringDefaults verifies all string config defaults.
func TestServer_Config_StringDefaults(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	for _, spec := range stringConfigs {
		t.Run(spec.Key+"_default", func(t *testing.T) {
			verifyConfigValue(t, mux, spec.Key, spec.Default)
		})
	}
}

// TestServer_Config_StringSetAndVerify tests setting each string value.
func TestServer_Config_StringSetAndVerify(t *testing.T) {
	mux := setupTestEnv(t)

	for _, spec := range stringConfigs {
		t.Run(spec.Key, func(t *testing.T) {
			for _, val := range spec.TestVals {
				t.Run(val, func(t *testing.T) {
					resetAdminConfig(t)

					resp := apiPost(t, mux, "/admin/api/config", map[string]interface{}{
						"key":   spec.Key,
						"value": val,
					})
					if resp["ok"] != true {
						t.Fatalf("POST config returned ok=%v", resp["ok"])
					}

					verifyConfigValue(t, mux, spec.Key, val)
				})
			}
		})
	}
}

// TestServer_Config_RecorderFormatValidation tests recorder_format only accepts valid values.
func TestServer_Config_RecorderFormatValidation(t *testing.T) {
	mux := setupTestEnv(t)
	resetAdminConfig(t)

	// Set to valid value first
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "recorder_format",
		"value": "pcap",
	})
	verifyConfigValue(t, mux, "recorder_format", "pcap")

	// Try invalid value — should be rejected (stays at pcap)
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "recorder_format",
		"value": "invalid_format",
	})
	// Should still be pcap since "invalid_format" is not "jsonl" or "pcap"
	cfg := dashboard.GetAdminConfig().Get()
	if cfg["recorder_format"] != "pcap" {
		t.Errorf("recorder_format should stay 'pcap' after invalid value, got %v", cfg["recorder_format"])
	}
}

// TestServer_Config_ProtocolGlitchEnabled tests the bool-as-float config.
func TestServer_Config_ProtocolGlitchEnabled(t *testing.T) {
	mux := setupTestEnv(t)
	resetAdminConfig(t)

	// Default is true (1.0)
	verifyConfigValue(t, mux, "protocol_glitch_enabled", true)

	// Disable via API (0.0)
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "protocol_glitch_enabled",
		"value": 0,
	})
	verifyConfigValue(t, mux, "protocol_glitch_enabled", false)

	// Re-enable (any non-zero)
	apiPost(t, mux, "/admin/api/config", map[string]interface{}{
		"key":   "protocol_glitch_enabled",
		"value": 1,
	})
	verifyConfigValue(t, mux, "protocol_glitch_enabled", true)
}

// ---------------------------------------------------------------------------
// Error Weights Tests
// ---------------------------------------------------------------------------

// TestServer_Config_ErrorWeightsSetAndReset tests error weight management.
func TestServer_Config_ErrorWeightsSetAndReset(t *testing.T) {
	mux := setupTestEnv(t)
	resetAdminConfig(t)

	// Default: empty weights map
	weights := dashboard.GetAdminConfig().GetErrorWeights()
	if len(weights) != 0 {
		t.Fatalf("default error weights should be empty, got %d entries", len(weights))
	}

	// Set a weight via API
	apiPost(t, mux, "/admin/api/error-weights", map[string]interface{}{
		"error_type": "500_internal",
		"weight":     0.5,
	})

	// Verify set (internal)
	weights = dashboard.GetAdminConfig().GetErrorWeights()
	if weights["500_internal"] != 0.5 {
		t.Errorf("weight for 500_internal = %v, want 0.5", weights["500_internal"])
	}

	// Set another weight
	apiPost(t, mux, "/admin/api/error-weights", map[string]interface{}{
		"error_type": "connection_reset",
		"weight":     0.3,
	})
	weights = dashboard.GetAdminConfig().GetErrorWeights()
	if len(weights) != 2 {
		t.Errorf("expected 2 weights, got %d", len(weights))
	}

	// Reset via API
	apiPost(t, mux, "/admin/api/error-weights", map[string]interface{}{
		"reset": true,
	})
	weights = dashboard.GetAdminConfig().GetErrorWeights()
	if len(weights) != 0 {
		t.Errorf("after reset, weights should be empty, got %d entries", len(weights))
	}
}

// TestServer_Config_ErrorWeightsClamping tests weight value clamping.
func TestServer_Config_ErrorWeightsClamping(t *testing.T) {
	resetAdminConfig(t)
	cfg := dashboard.GetAdminConfig()

	// Negative clamped to 0
	cfg.SetErrorWeight("test_type", -0.5)
	w := cfg.GetErrorWeights()
	if w["test_type"] != 0 {
		t.Errorf("negative weight should clamp to 0, got %v", w["test_type"])
	}

	// Above 1 clamped to 1
	cfg.SetErrorWeight("test_type", 1.5)
	w = cfg.GetErrorWeights()
	if w["test_type"] != 1.0 {
		t.Errorf("weight > 1 should clamp to 1.0, got %v", w["test_type"])
	}

	cfg.ResetErrorWeights()
}

// ---------------------------------------------------------------------------
// Page Type Weights Tests
// ---------------------------------------------------------------------------

// TestServer_Config_PageTypeWeightsSetAndReset tests page type weight management.
func TestServer_Config_PageTypeWeightsSetAndReset(t *testing.T) {
	mux := setupTestEnv(t)
	resetAdminConfig(t)

	// Default: empty
	weights := dashboard.GetAdminConfig().GetPageTypeWeights()
	if len(weights) != 0 {
		t.Fatalf("default page type weights should be empty, got %d", len(weights))
	}

	// Set via API
	apiPost(t, mux, "/admin/api/page-type-weights", map[string]interface{}{
		"page_type": "json",
		"weight":    0.8,
	})
	weights = dashboard.GetAdminConfig().GetPageTypeWeights()
	if weights["json"] != 0.8 {
		t.Errorf("weight for json = %v, want 0.8", weights["json"])
	}

	// Reset
	apiPost(t, mux, "/admin/api/page-type-weights", map[string]interface{}{
		"reset": true,
	})
	weights = dashboard.GetAdminConfig().GetPageTypeWeights()
	if len(weights) != 0 {
		t.Errorf("after reset, weights should be empty, got %d", len(weights))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fmtFloat(f float64) string {
	if f == float64(int(f)) {
		return fmt.Sprintf("%d", int(f))
	}
	return fmt.Sprintf("%.2f", f)
}
