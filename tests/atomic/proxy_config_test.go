package atomic

import (
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
)

// ---------------------------------------------------------------------------
// Proxy Config — Atomic Tests
//
// Tests proxy mode switching, WAF auto-enable, mirror snapshots,
// chaos config, nightmare mode interaction, and API response format.
// ---------------------------------------------------------------------------

var allProxyModes = dashboard.ProxyModes

// resetProxyConfig restores proxy to default transparent mode and clears mirror.
func resetProxyConfig(t *testing.T) {
	t.Helper()
	pc := dashboard.GetProxyConfig()
	pc.SetMode("transparent")
	pc.SetMirror(nil)
}

// TestProxy_DefaultMode verifies proxy starts in transparent mode.
func TestProxy_DefaultMode(t *testing.T) {
	mux := setupTestEnv(t)
	resetProxyConfig(t)

	pc := dashboard.GetProxyConfig()
	if pc.GetMode() != "transparent" {
		t.Errorf("default mode = %q, want transparent", pc.GetMode())
	}

	// Verify via API
	resp := apiGet(t, mux, "/admin/api/proxy/status")
	if resp["mode"] != "transparent" {
		t.Errorf("[API] mode = %v, want transparent", resp["mode"])
	}
}

// TestProxy_ModeSwitch tests switching to every valid mode.
func TestProxy_ModeSwitch(t *testing.T) {
	mux := setupTestEnv(t)

	for _, mode := range allProxyModes {
		t.Run(mode, func(t *testing.T) {
			resetProxyConfig(t)

			resp := apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": mode,
			})
			if resp["ok"] != true {
				t.Fatalf("POST proxy/mode returned ok=%v", resp["ok"])
			}
			if resp["mode"] != mode {
				t.Errorf("response mode = %v, want %q", resp["mode"], mode)
			}

			// Verify via status
			status := apiGet(t, mux, "/admin/api/proxy/status")
			if status["mode"] != mode {
				t.Errorf("[API status] mode = %v, want %q", status["mode"], mode)
			}

			// Verify internal
			pc := dashboard.GetProxyConfig()
			if pc.GetMode() != mode {
				t.Errorf("[Internal] mode = %q, want %q", pc.GetMode(), mode)
			}
		})
	}
}

// TestProxy_InvalidModeReturnsError tests that invalid modes are rejected.
func TestProxy_InvalidModeReturnsError(t *testing.T) {
	mux := setupTestEnv(t)
	resetProxyConfig(t)

	invalids := []string{"nonexistent", "foo", "", "CHAOS"}
	for _, mode := range invalids {
		t.Run(mode, func(t *testing.T) {
			req := makePostRequest(t, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": mode,
			})
			rec := makeRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code == 200 {
				t.Errorf("invalid proxy mode %q should return error, got 200", mode)
			}
		})
	}
}

// TestProxy_WAFAutoEnable verifies WAF is auto-enabled for specific modes.
func TestProxy_WAFAutoEnable(t *testing.T) {
	mux := setupTestEnv(t)

	wafExpected := map[string]bool{
		"transparent": false,
		"waf":         true,
		"chaos":       false,
		"gateway":     true,
		"nightmare":   true,
		"mirror":      false,
	}

	for mode, expectedWAF := range wafExpected {
		t.Run(mode, func(t *testing.T) {
			resetProxyConfig(t)

			apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": mode,
			})

			// Verify via API
			status := apiGet(t, mux, "/admin/api/proxy/status")
			apiWAF, ok := status["waf_enabled"].(bool)
			if !ok {
				t.Fatalf("waf_enabled not bool in status")
			}
			if apiWAF != expectedWAF {
				t.Errorf("[API] waf_enabled = %v for mode %q, want %v", apiWAF, mode, expectedWAF)
			}
		})
	}
}

// TestProxy_ModeIsolation verifies switching modes doesn't leave stale state.
func TestProxy_ModeIsolation(t *testing.T) {
	mux := setupTestEnv(t)

	for _, mode := range allProxyModes {
		t.Run(mode, func(t *testing.T) {
			resetProxyConfig(t)

			// Switch to target mode
			apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": mode,
			})

			// Switch back to transparent
			apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
				"mode": "transparent",
			})

			// Verify transparent state is clean
			status := apiGet(t, mux, "/admin/api/proxy/status")
			if status["mode"] != "transparent" {
				t.Errorf("after reset, mode = %v, want transparent", status["mode"])
			}
			if waf, ok := status["waf_enabled"].(bool); ok && waf {
				t.Error("WAF should be disabled in transparent mode")
			}
		})
	}
}

// TestProxy_StatusResponseFormat verifies the proxy status API response structure.
func TestProxy_StatusResponseFormat(t *testing.T) {
	mux := setupTestEnv(t)
	resetProxyConfig(t)

	resp := apiGet(t, mux, "/admin/api/proxy/status")

	// Required top-level keys
	requiredKeys := []string{"mode", "waf_enabled", "waf_stats", "chaos_config", "pipeline_stats"}
	for _, key := range requiredKeys {
		if _, exists := resp[key]; !exists {
			t.Errorf("proxy status response missing key %q", key)
		}
	}

	// waf_stats structure
	wafStats, ok := resp["waf_stats"].(map[string]interface{})
	if !ok {
		t.Fatal("waf_stats not a map")
	}
	for _, key := range []string{"detections", "rate_limited", "block_action"} {
		if _, exists := wafStats[key]; !exists {
			t.Errorf("waf_stats missing key %q", key)
		}
	}

	// chaos_config structure
	chaosConfig, ok := resp["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("chaos_config not a map")
	}
	for _, key := range []string{"latency_prob", "corrupt_prob", "drop_prob", "reset_prob"} {
		if _, exists := chaosConfig[key]; !exists {
			t.Errorf("chaos_config missing key %q", key)
		}
	}

	// pipeline_stats structure
	pipelineStats, ok := resp["pipeline_stats"].(map[string]interface{})
	if !ok {
		t.Fatal("pipeline_stats not a map")
	}
	for _, key := range []string{"requests_processed", "responses_processed", "requests_blocked", "responses_modified"} {
		if _, exists := pipelineStats[key]; !exists {
			t.Errorf("pipeline_stats missing key %q", key)
		}
	}
}

// TestProxy_MirrorSnapshot verifies mirror mode captures server settings.
func TestProxy_MirrorSnapshot(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	resetProxyConfig(t)

	// Set some server config values
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 3.5)
	dashboard.GetAdminConfig().Set("header_corrupt_level", 3)

	// Switch to mirror mode
	resp := apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
		"mode": "mirror",
	})
	if resp["ok"] != true {
		t.Fatal("mirror mode switch failed")
	}

	// Should have mirror config
	mc := dashboard.GetProxyConfig().GetMirror()
	if mc == nil {
		t.Fatal("mirror config should not be nil after entering mirror mode")
	}

	if mc.ErrorRateMultiplier != 3.5 {
		t.Errorf("mirror ErrorRateMultiplier = %v, want 3.5", mc.ErrorRateMultiplier)
	}
	if mc.HeaderCorruptLevel != 3 {
		t.Errorf("mirror HeaderCorruptLevel = %v, want 3", mc.HeaderCorruptLevel)
	}
	if mc.SnapshotTime == "" {
		t.Error("mirror SnapshotTime should not be empty")
	}
}

// TestProxy_MirrorRefresh verifies mirror refresh re-snapshots server settings.
func TestProxy_MirrorRefresh(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	resetProxyConfig(t)

	// Enter mirror mode with initial server settings
	apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
		"mode": "mirror",
	})

	mc1 := dashboard.GetProxyConfig().GetMirror()
	if mc1 == nil {
		t.Fatal("mirror config nil after mirror mode")
	}

	// Change server settings
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 4.5)

	// Refresh mirror
	resp := apiPost(t, mux, "/admin/api/proxy/mirror/refresh", map[string]interface{}{})
	if resp["ok"] != true {
		t.Fatal("mirror refresh failed")
	}

	// Mirror should reflect updated server settings
	mc2 := dashboard.GetProxyConfig().GetMirror()
	if mc2 == nil {
		t.Fatal("mirror config nil after refresh")
	}
	if mc2.ErrorRateMultiplier != 4.5 {
		t.Errorf("refreshed mirror ErrorRateMultiplier = %v, want 4.5", mc2.ErrorRateMultiplier)
	}
}

// TestProxy_NightmareMode verifies nightmare affects proxy mode.
func TestProxy_NightmareMode(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)
	resetProxyConfig(t)

	// Activate proxy nightmare
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": true,
	})

	// Verify nightmare state
	ns := dashboard.GetNightmareState()
	if !ns.Snapshot()["proxy"] {
		t.Error("proxy nightmare should be active")
	}

	// Deactivate
	apiPost(t, mux, "/admin/api/nightmare", map[string]interface{}{
		"mode":    "proxy",
		"enabled": false,
	})

	if ns.Snapshot()["proxy"] {
		t.Error("proxy nightmare should be inactive after deactivation")
	}
}

// TestProxy_RapidModeSwitch verifies rapid mode switches are safe.
func TestProxy_RapidModeSwitch(t *testing.T) {
	mux := setupTestEnv(t)
	resetProxyConfig(t)

	for i := 0; i < 50; i++ {
		mode := allProxyModes[i%len(allProxyModes)]
		apiPost(t, mux, "/admin/api/proxy/mode", map[string]interface{}{
			"mode": mode,
		})
	}

	// After 50 switches, should be in a valid state
	pc := dashboard.GetProxyConfig()
	lastMode := allProxyModes[49%len(allProxyModes)]
	if pc.GetMode() != lastMode {
		t.Errorf("after rapid switches, mode = %q, want %q", pc.GetMode(), lastMode)
	}
}
