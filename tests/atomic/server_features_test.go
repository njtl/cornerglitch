package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Feature Flags — Atomic Tests
//
// Tests every feature flag individually: toggle on, verify, toggle off, verify,
// confirm return to baseline. Uses dual-layer verification (API + internal).
// ---------------------------------------------------------------------------

// allFeatureFlags lists every known feature flag for iteration.
var allFeatureFlags = []string{
	"labyrinth", "error_inject", "captcha", "honeypot", "vuln",
	"analytics", "cdn", "oauth", "header_corrupt", "cookie_traps",
	"js_traps", "bot_detection", "random_blocking", "framework_emul",
	"search", "email", "i18n", "recorder", "websocket", "privacy",
	"health", "spider", "api_chaos", "media_chaos",
}

// TestServer_FeatureFlags_AllDefaultEnabled verifies all flags start enabled.
func TestServer_FeatureFlags_AllDefaultEnabled(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	for _, flag := range allFeatureFlags {
		t.Run(flag+"_default_enabled", func(t *testing.T) {
			verifyFeatureFlag(t, mux, flag, true)
		})
	}
}

// TestServer_FeatureFlags_ToggleOff tests disabling each flag individually.
func TestServer_FeatureFlags_ToggleOff(t *testing.T) {
	mux := setupTestEnv(t)

	for _, flag := range allFeatureFlags {
		t.Run(flag, func(t *testing.T) {
			resetAll(t)

			// Baseline: enabled
			verifyFeatureFlag(t, mux, flag, true)

			// Toggle OFF via API
			resp := apiPost(t, mux, "/admin/api/features", map[string]interface{}{
				"feature": flag,
				"enabled": false,
			})
			if resp["ok"] != true {
				t.Fatalf("POST features returned ok=%v", resp["ok"])
			}

			// Verify disabled (dual-layer)
			verifyFeatureFlag(t, mux, flag, false)

			// Toggle back ON via API
			apiPost(t, mux, "/admin/api/features", map[string]interface{}{
				"feature": flag,
				"enabled": true,
			})

			// Verify restored (dual-layer)
			verifyFeatureFlag(t, mux, flag, true)
		})
	}
}

// TestServer_FeatureFlags_ToggleOn tests enabling a disabled flag.
func TestServer_FeatureFlags_ToggleOn(t *testing.T) {
	mux := setupTestEnv(t)

	for _, flag := range allFeatureFlags {
		t.Run(flag, func(t *testing.T) {
			resetAll(t)

			// Start disabled
			dashboard.GetFeatureFlags().Set(flag, false)
			verifyFeatureFlag(t, mux, flag, false)

			// Toggle ON via API
			resp := apiPost(t, mux, "/admin/api/features", map[string]interface{}{
				"feature": flag,
				"enabled": true,
			})
			if resp["ok"] != true {
				t.Fatalf("POST features returned ok=%v", resp["ok"])
			}

			// Verify enabled (dual-layer)
			verifyFeatureFlag(t, mux, flag, true)
		})
	}
}

// TestServer_FeatureFlags_UnknownReturnsError tests that unknown flags are rejected.
func TestServer_FeatureFlags_UnknownReturnsError(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	unknowns := []string{"nonexistent", "foo_bar", "", "labyrinth_extra"}
	for _, name := range unknowns {
		t.Run(name, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/features", map[string]interface{}{
				"feature": name,
				"enabled": true,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("unknown feature %q should return error, got 200", name)
			}
		})
	}
}

// TestServer_FeatureFlags_IsolationNoSideEffects verifies toggling one flag
// doesn't affect any other flag.
func TestServer_FeatureFlags_IsolationNoSideEffects(t *testing.T) {
	mux := setupTestEnv(t)

	for _, targetFlag := range allFeatureFlags {
		t.Run(targetFlag, func(t *testing.T) {
			resetAll(t)

			// Disable only the target flag
			apiPost(t, mux, "/admin/api/features", map[string]interface{}{
				"feature": targetFlag,
				"enabled": false,
			})

			// All OTHER flags must still be enabled
			snap := dashboard.GetFeatureFlags().Snapshot()
			for _, otherFlag := range allFeatureFlags {
				if otherFlag == targetFlag {
					if snap[otherFlag] {
						t.Errorf("target flag %q should be disabled", targetFlag)
					}
					continue
				}
				if !snap[otherFlag] {
					t.Errorf("flag %q was affected by toggling %q", otherFlag, targetFlag)
				}
			}
		})
	}
}

// TestServer_FeatureFlags_SetAllExcludesRecorder verifies SetAll behavior.
func TestServer_FeatureFlags_SetAllExcludesRecorder(t *testing.T) {
	resetAll(t)
	flags := dashboard.GetFeatureFlags()

	// Set recorder to a known state
	flags.Set("recorder", false)

	// SetAll(true) should NOT change recorder
	flags.SetAll(true)
	snap := flags.Snapshot()
	if snap["recorder"] {
		t.Error("SetAll(true) must not change recorder (operational flag)")
	}

	// All other flags should be true
	for _, flag := range allFeatureFlags {
		if flag == "recorder" {
			continue
		}
		if !snap[flag] {
			t.Errorf("SetAll(true) should enable %q", flag)
		}
	}

	// Now set recorder to true and SetAll(false) — recorder should stay true
	flags.Set("recorder", true)
	flags.SetAll(false)
	snap = flags.Snapshot()
	if !snap["recorder"] {
		t.Error("SetAll(false) must not change recorder (operational flag)")
	}
	for _, flag := range allFeatureFlags {
		if flag == "recorder" {
			continue
		}
		if snap[flag] {
			t.Errorf("SetAll(false) should disable %q", flag)
		}
	}
}

// TestServer_FeatureFlags_Snapshot verifies snapshot contains all flags.
func TestServer_FeatureFlags_Snapshot(t *testing.T) {
	resetAll(t)
	snap := dashboard.GetFeatureFlags().Snapshot()

	for _, flag := range allFeatureFlags {
		if _, exists := snap[flag]; !exists {
			t.Errorf("Snapshot() missing flag %q", flag)
		}
	}

	// Verify snapshot length matches expected count
	if len(snap) != len(allFeatureFlags) {
		t.Errorf("Snapshot() has %d flags, want %d", len(snap), len(allFeatureFlags))
	}
}

// TestServer_FeatureFlags_APIResponseFormat verifies API response structure.
// The features GET returns a flat map of flag_name -> bool (not nested).
func TestServer_FeatureFlags_APIResponseFormat(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/features")

	for _, flag := range allFeatureFlags {
		val, exists := resp[flag]
		if !exists {
			t.Errorf("API response missing flag %q", flag)
			continue
		}
		if _, isBool := val.(bool); !isBool {
			t.Errorf("flag %q has type %T, want bool", flag, val)
		}
	}

	// Verify no unexpected keys
	if len(resp) != len(allFeatureFlags) {
		t.Errorf("API response has %d keys, want %d", len(resp), len(allFeatureFlags))
	}
}

// TestServer_FeatureFlags_RapidToggle verifies rapid on/off cycles are safe.
func TestServer_FeatureFlags_RapidToggle(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	flag := "labyrinth"
	for i := 0; i < 100; i++ {
		enabled := i%2 == 0
		apiPost(t, mux, "/admin/api/features", map[string]interface{}{
			"feature": flag,
			"enabled": enabled,
		})
	}

	// After 100 toggles (even count), should be enabled (i=99 → false, i=98 → true)
	// Last toggle: i=99, enabled = false
	verifyFeatureFlag(t, mux, flag, false)
}
