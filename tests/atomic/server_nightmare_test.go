package atomic

import (
	"strings"
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Server Nightmare Mode — Atomic Tests
//
// Tests nightmare activation/deactivation per subsystem, config snapshot/restore,
// and isolation between subsystems.
// ---------------------------------------------------------------------------

// TestServer_Nightmare_DefaultInactive verifies all nightmare modes start inactive.
func TestServer_Nightmare_DefaultInactive(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/nightmare")

	modes := []string{"server", "scanner", "proxy"}
	for _, mode := range modes {
		val, ok := resp[mode].(bool)
		if !ok {
			t.Errorf("nightmare response missing %q or wrong type", mode)
			continue
		}
		if val {
			t.Errorf("nightmare %q should be inactive by default", mode)
		}
	}

	ns := dashboard.GetNightmareState()
	if ns.IsAnyActive() {
		t.Error("IsAnyActive() should be false by default")
	}
}

// TestServer_Nightmare_ServerActivateDeactivate tests server nightmare toggle.
func TestServer_Nightmare_ServerActivateDeactivate(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Capture pre-nightmare config values
	preConfig := dashboard.GetAdminConfig().Get()
	preFeatures := dashboard.GetFeatureFlags().Snapshot()

	// Activate server nightmare
	resp := apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": true,
	})
	if resp["ok"] != true {
		t.Fatalf("nightmare activate returned ok=%v", resp["ok"])
	}

	// Verify server is active
	ns := dashboard.GetNightmareState()
	snap := ns.Snapshot()
	if !snap["server"] {
		t.Error("server nightmare should be active")
	}
	if snap["scanner"] || snap["proxy"] {
		t.Error("scanner/proxy should remain inactive")
	}

	// Verify config changed to extreme values
	cfg := dashboard.GetAdminConfig().Get()
	errMult, _ := toFloat64(cfg["error_rate_multiplier"])
	if errMult != 5.0 {
		t.Errorf("nightmare error_rate_multiplier = %v, want 5.0", errMult)
	}

	// Deactivate server nightmare
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": false,
	})

	// Verify server is inactive
	snap = ns.Snapshot()
	if snap["server"] {
		t.Error("server nightmare should be inactive after deactivation")
	}

	// Verify config restored to pre-nightmare values
	restoredConfig := dashboard.GetAdminConfig().Get()
	for key, preVal := range preConfig {
		restoredVal, exists := restoredConfig[key]
		if !exists {
			continue
		}
		if !valuesEqual(preVal, restoredVal) {
			t.Errorf("config %q not restored: got %v, want %v", key, restoredVal, preVal)
		}
	}

	// Verify features restored
	restoredFeatures := dashboard.GetFeatureFlags().Snapshot()
	for flag, preVal := range preFeatures {
		if restoredFeatures[flag] != preVal {
			t.Errorf("feature %q not restored: got %v, want %v", flag, restoredFeatures[flag], preVal)
		}
	}
}

// TestServer_Nightmare_ScannerActivateDeactivate tests scanner nightmare toggle.
func TestServer_Nightmare_ScannerActivateDeactivate(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Activate scanner nightmare
	resp := apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "scanner",
		"enabled": true,
	})
	if resp["ok"] != true {
		t.Fatalf("nightmare activate returned ok=%v", resp["ok"])
	}

	ns := dashboard.GetNightmareState()
	snap := ns.Snapshot()
	if !snap["scanner"] {
		t.Error("scanner nightmare should be active")
	}
	if snap["server"] || snap["proxy"] {
		t.Error("server/proxy should remain inactive")
	}

	// Deactivate
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "scanner",
		"enabled": false,
	})
	snap = ns.Snapshot()
	if snap["scanner"] {
		t.Error("scanner nightmare should be inactive after deactivation")
	}
}

// TestServer_Nightmare_ProxyActivateDeactivate tests proxy nightmare toggle.
func TestServer_Nightmare_ProxyActivateDeactivate(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Activate proxy nightmare
	resp := apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": true,
	})
	if resp["ok"] != true {
		t.Fatalf("nightmare activate returned ok=%v", resp["ok"])
	}

	ns := dashboard.GetNightmareState()
	snap := ns.Snapshot()
	if !snap["proxy"] {
		t.Error("proxy nightmare should be active")
	}
	if snap["server"] || snap["scanner"] {
		t.Error("server/scanner should remain inactive")
	}

	// Deactivate
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": false,
	})
	snap = ns.Snapshot()
	if snap["proxy"] {
		t.Error("proxy nightmare should be inactive after deactivation")
	}
}

// TestServer_Nightmare_AllMode tests the "all" mode toggle.
func TestServer_Nightmare_AllMode(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Activate all
	resp := apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "all",
		"enabled": true,
	})
	if resp["ok"] != true {
		t.Fatalf("nightmare all activate returned ok=%v", resp["ok"])
	}

	ns := dashboard.GetNightmareState()
	snap := ns.Snapshot()
	if !snap["server"] || !snap["scanner"] || !snap["proxy"] {
		t.Errorf("all modes should be active: %v", snap)
	}
	if !ns.IsAnyActive() {
		t.Error("IsAnyActive should be true")
	}

	// Deactivate all
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "all",
		"enabled": false,
	})

	snap = ns.Snapshot()
	if snap["server"] || snap["scanner"] || snap["proxy"] {
		t.Errorf("all modes should be inactive after deactivation: %v", snap)
	}
	if ns.IsAnyActive() {
		t.Error("IsAnyActive should be false after deactivation")
	}
}

// TestServer_Nightmare_IsolationBetweenSubsystems verifies activating one mode
// doesn't affect others.
func TestServer_Nightmare_IsolationBetweenSubsystems(t *testing.T) {
	mux := setupTestEnv(t)

	modes := []string{"server", "scanner", "proxy"}
	for _, target := range modes {
		t.Run(target, func(t *testing.T) {
			resetAll(t)

			// Activate only target
			apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
				"mode":    target,
				"enabled": true,
			})

			snap := dashboard.GetNightmareState().Snapshot()
			for _, other := range modes {
				if other == target {
					if !snap[other] {
						t.Errorf("target %q should be active", target)
					}
				} else {
					if snap[other] {
						t.Errorf("mode %q should not be affected by activating %q", other, target)
					}
				}
			}

			// Clean up
			apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
				"mode":    target,
				"enabled": false,
			})
		})
	}
}

// TestServer_Nightmare_InvalidModeReturnsError tests that invalid modes are rejected.
func TestServer_Nightmare_InvalidModeReturnsError(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	invalids := []string{"nonexistent", "foo", ""}
	for _, mode := range invalids {
		t.Run(mode, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/nightmare", map[string]interface{}{
				"mode":    mode,
				"enabled": true,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("invalid nightmare mode %q should return error, got 200", mode)
			}
		})
	}
}

// Recorder-nightmare interaction test is in server_combos_test.go
// (TestCombo_NightmarePreservesRecorder) to avoid duplication.

// TestServer_Nightmare_ActiveModes tests the ActiveModes() helper in all states.
func TestServer_Nightmare_ActiveModes(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	ns := dashboard.GetNightmareState()

	// No active modes initially
	modes := ns.ActiveModes()
	if len(modes) != 0 {
		t.Errorf("ActiveModes should be empty, got %v", modes)
	}

	// Activate server → ActiveModes should include "server"
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "server",
		"enabled": true,
	})
	modes = ns.ActiveModes()
	if len(modes) != 1 {
		t.Errorf("after server activate, ActiveModes should have 1 entry, got %v", modes)
	}
	found := false
	for _, m := range modes {
		if strings.EqualFold(m, "server") {
			found = true
		}
	}
	if !found {
		t.Errorf("ActiveModes should contain 'server' (case-insensitive), got %v", modes)
	}

	// Activate scanner too → should have 2
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "scanner",
		"enabled": true,
	})
	modes = ns.ActiveModes()
	if len(modes) != 2 {
		t.Errorf("after server+scanner activate, ActiveModes should have 2, got %v", modes)
	}

	// Activate all → should have 3
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": true,
	})
	modes = ns.ActiveModes()
	if len(modes) != 3 {
		t.Errorf("after all activate, ActiveModes should have 3, got %v", modes)
	}

	// Deactivate all
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "all",
		"enabled": false,
	})
	modes = ns.ActiveModes()
	if len(modes) != 0 {
		t.Errorf("after deactivate all, ActiveModes should be empty, got %v", modes)
	}
}

// TestServer_Nightmare_APIResponseFormat verifies the nightmare GET response.
func TestServer_Nightmare_APIResponseFormat(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	resp := apiGet(t, mux, "/admin/api/nightmare")

	expected := []string{"server", "scanner", "proxy"}
	for _, key := range expected {
		val, ok := resp[key]
		if !ok {
			t.Errorf("nightmare response missing %q", key)
			continue
		}
		if _, isBool := val.(bool); !isBool {
			t.Errorf("nightmare %q has type %T, want bool", key, val)
		}
	}
}
