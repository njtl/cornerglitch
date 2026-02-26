package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Proxy Mode-Specific Behavior — Atomic Tests
//
// Tests mode-specific chaos config values, WAF configuration, and
// cross-mode transitions.
// ---------------------------------------------------------------------------

// modeExpectation describes expected proxy state for a given mode.
type modeExpectation struct {
	Mode       string
	WAFEnabled bool
	// Whether chaos config should have non-zero values
	HasChaos bool
}

var modeExpectations = []modeExpectation{
	{"transparent", false, false},
	{"waf", true, false},
	{"chaos", false, true},
	{"gateway", true, false},
	{"nightmare", true, true},
	{"mirror", false, false},
}

// TestProxy_Modes_WAFAndChaosState verifies each mode sets WAF correctly and
// chaos_config structure is present.
//
// Note: chaos probabilities (latency_prob, etc.) are only populated when an
// actual proxy pipeline is running. In test mode (no proxy server), they stay
// at zero. The HasChaos field documents expected runtime behavior.
func TestProxy_Modes_WAFAndChaosState(t *testing.T) {
	mux := setupTestEnv(t)

	for _, exp := range modeExpectations {
		t.Run(exp.Mode, func(t *testing.T) {
			resetProxyConfig(t)

			apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": exp.Mode,
			})

			status := apiGet(t, mux, "/admin/api/proxy/status")

			// Check WAF enabled matches mode expectation
			waf, ok := status["waf_enabled"].(bool)
			if !ok {
				t.Fatal("waf_enabled not bool")
			}
			if waf != exp.WAFEnabled {
				t.Errorf("waf_enabled = %v for mode %q, want %v", waf, exp.Mode, exp.WAFEnabled)
			}

			// Verify chaos_config structure is always present with required keys
			chaos, ok := status["chaos_config"].(map[string]interface{})
			if !ok {
				t.Fatal("chaos_config not a map")
			}
			for _, key := range []string{"latency_prob", "corrupt_prob", "drop_prob", "reset_prob"} {
				if _, exists := chaos[key]; !exists {
					t.Errorf("chaos_config missing key %q for mode %q", key, exp.Mode)
				}
			}

			// Verify internal mode state matches
			pc := dashboard.GetProxyConfig()
			if pc.GetMode() != exp.Mode {
				t.Errorf("[Internal] mode = %q, want %q", pc.GetMode(), exp.Mode)
			}
		})
	}
}

// TestProxy_Modes_TransparentIsClean verifies transparent mode has no chaos.
func TestProxy_Modes_TransparentIsClean(t *testing.T) {
	mux := setupTestEnv(t)
	resetProxyConfig(t)

	apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
		"mode": "transparent",
	})

	status := apiGet(t, mux, "/admin/api/proxy/status")
	chaos, ok := status["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("chaos_config not a map")
	}

	for _, key := range []string{"latency_prob", "corrupt_prob", "drop_prob", "reset_prob"} {
		val, _ := toFloat64(chaos[key])
		if val != 0 {
			t.Errorf("transparent mode: %s = %v, want 0", key, val)
		}
	}
}

// TestProxy_Modes_MirrorHasSnapshot verifies mirror mode includes a snapshot.
func TestProxy_Modes_MirrorHasSnapshot(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	resetProxyConfig(t)

	apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
		"mode": "mirror",
	})

	mc := dashboard.GetProxyConfig().GetMirror()
	if mc == nil {
		t.Fatal("mirror mode should create a MirrorConfig snapshot")
	}
	if mc.SnapshotTime == "" {
		t.Error("mirror snapshot_time should not be empty")
	}
}

// TestProxy_Modes_CrossModeTransitions verifies all mode-to-mode transitions work.
func TestProxy_Modes_CrossModeTransitions(t *testing.T) {
	mux := setupTestEnv(t)

	for _, from := range allProxyModes {
		for _, to := range allProxyModes {
			if from == to {
				continue
			}
			t.Run(from+"_to_"+to, func(t *testing.T) {
				resetProxyConfig(t)

				// Set initial mode
				apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
					"mode": from,
				})

				// Switch to target mode
				resp := apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
					"mode": to,
				})
				if resp["ok"] != true {
					t.Fatalf("transition %s -> %s failed", from, to)
				}
				if resp["mode"] != to {
					t.Errorf("after transition, mode = %v, want %q", resp["mode"], to)
				}
			})
		}
	}
}

// TestProxy_Modes_NightmareToTransparentRestore tests nightmare deactivation restores mode.
func TestProxy_Modes_NightmareToTransparentRestore(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	resetProxyConfig(t)

	// Start in WAF mode
	apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
		"mode": "waf",
	})

	// Verify we're in WAF mode
	pc := dashboard.GetProxyConfig()
	if pc.GetMode() != "waf" {
		t.Fatalf("should be in waf mode, got %q", pc.GetMode())
	}

	// Activate proxy nightmare — should switch to nightmare mode
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": true,
	})

	// Verify nightmare mode is active
	if pc.GetMode() != "nightmare" {
		t.Errorf("proxy should be in nightmare mode during nightmare, got %q", pc.GetMode())
	}

	// Deactivate proxy nightmare — should restore WAF mode
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": false,
	})

	ns := dashboard.GetNightmareState()
	if ns.Snapshot()["proxy"] {
		t.Error("proxy nightmare should be inactive")
	}

	// Verify WAF mode was restored
	restoredMode := pc.GetMode()
	if restoredMode != "waf" {
		t.Errorf("proxy mode should be restored to 'waf', got %q", restoredMode)
	}

	// Verify WAF is still enabled in status API
	status := apiGet(t, mux, "/admin/api/proxy/status")
	if status["mode"] != "waf" {
		t.Errorf("[API] mode should be 'waf' after restore, got %v", status["mode"])
	}
}

// TestProxy_Modes_RuntimeEndpoint verifies the proxy runtime status endpoint.
func TestProxy_Modes_RuntimeEndpoint(t *testing.T) {
	mux := setupTestEnv(t)

	status, body := apiGetRaw(t, mux, "/admin/api/proxy/runtime")
	if status != 200 {
		t.Errorf("proxy runtime returned %d, want 200", status)
	}
	if len(body) == 0 {
		t.Error("proxy runtime returned empty body")
	}
}

// TestProxy_Modes_AllModesPresent verifies all expected modes exist.
func TestProxy_Modes_AllModesPresent(t *testing.T) {
	expected := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}
	if len(allProxyModes) != len(expected) {
		t.Errorf("ProxyModes has %d modes, want %d", len(allProxyModes), len(expected))
	}

	modeSet := make(map[string]bool)
	for _, m := range allProxyModes {
		modeSet[m] = true
	}
	for _, m := range expected {
		if !modeSet[m] {
			t.Errorf("missing expected proxy mode %q", m)
		}
	}
}
