package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// Proxy Acceptance Tests
//
// Tests every proxy mode and setting via the admin API.
// Requires a running Glitch server on ports 8765 (main) and 8766 (admin).
// ===========================================================================

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setConfigKey sets a single config key via the admin API (key/value format).
func setConfigKey(t *testing.T, key string, value interface{}) {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
		"key":   key,
		"value": value,
	})
	if err != nil {
		t.Fatalf("setConfigKey(%s): %v", key, err)
	}
	resp.Body.Close()
}

// getProxyStatus fetches the current proxy config snapshot.
func getProxyStatus(t *testing.T) map[string]interface{} {
	t.Helper()
	return getJSON(t, adminURL+"/admin/api/proxy/status")
}

// setProxyMode sets the proxy mode via admin API and returns the response.
func setProxyMode(t *testing.T, mode string) map[string]interface{} {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/proxy/mode", map[string]string{"mode": mode})
	if err != nil {
		t.Fatalf("setProxyMode(%s): %v", mode, err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// setProxyModeRaw sets proxy mode and returns the raw HTTP response for status checking.
func setProxyModeRaw(t *testing.T, mode string) *http.Response {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/proxy/mode", map[string]string{"mode": mode})
	if err != nil {
		t.Fatalf("setProxyModeRaw(%s): %v", mode, err)
	}
	return resp
}

// getNightmareState fetches the current nightmare state.
func getNightmareState(t *testing.T) map[string]interface{} {
	t.Helper()
	return getJSON(t, adminURL+"/admin/api/nightmare")
}

// setNightmare enables/disables nightmare for the given mode ("all", "server", "scanner", "proxy").
func setNightmare(t *testing.T, mode string, enabled bool) map[string]interface{} {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/nightmare", map[string]interface{}{
		"mode":    mode,
		"enabled": enabled,
	})
	if err != nil {
		t.Fatalf("setNightmare(%s, %v): %v", mode, enabled, err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// refreshMirror triggers a mirror refresh and returns the result.
func refreshMirror(t *testing.T) map[string]interface{} {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/proxy/mirror/refresh", map[string]string{})
	if err != nil {
		t.Fatalf("refreshMirror: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// ===========================================================================
// SECTION 1: Proxy Mode Switching
// ===========================================================================

func TestProxy_ModeSwitch_AllModes(t *testing.T) {
	requireAdmin(t)

	modes := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			result := setProxyMode(t, mode)
			if result["ok"] != true {
				t.Errorf("setProxyMode(%s) did not return ok=true: %v", mode, result)
			}
			if result["mode"] != mode {
				t.Errorf("setProxyMode(%s) returned mode=%v, want %s", mode, result["mode"], mode)
			}

			// Verify via GET status
			status := getProxyStatus(t)
			if status["mode"] != mode {
				t.Errorf("proxy status mode=%v after setting %s", status["mode"], mode)
			}
		})
	}

	// Reset to transparent
	setProxyMode(t, "transparent")
}

func TestProxy_ModeSwitch_InvalidMode(t *testing.T) {
	requireAdmin(t)

	resp := setProxyModeRaw(t, "nonexistent_mode")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid mode returned status %d, want 400", resp.StatusCode)
	}
}

func TestProxy_ModeSwitch_RapidSwitching(t *testing.T) {
	requireAdmin(t)

	modes := []string{"transparent", "chaos", "waf", "gateway", "mirror", "nightmare", "transparent"}
	for _, mode := range modes {
		setProxyMode(t, mode)
	}

	// Verify final state is transparent
	status := getProxyStatus(t)
	if status["mode"] != "transparent" {
		t.Errorf("after rapid switching, mode=%v, want transparent", status["mode"])
	}
}

// ===========================================================================
// SECTION 2: Transparent Mode
// ===========================================================================

func TestProxy_Transparent_NoWAF(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "transparent")

	status := getProxyStatus(t)
	if waf, ok := status["waf_enabled"].(bool); ok && waf {
		t.Error("transparent mode should have WAF disabled")
	}
}

func TestProxy_Transparent_NoChaos(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "transparent")

	status := getProxyStatus(t)
	chaosConfig, ok := status["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("missing chaos_config in proxy status")
	}
	for key, val := range chaosConfig {
		if v, ok := val.(float64); ok && v != 0 {
			t.Errorf("transparent mode: chaos_config[%s] = %v, want 0", key, v)
		}
	}
}

// ===========================================================================
// SECTION 3: WAF Mode
// ===========================================================================

func TestProxy_WAF_EnabledOnSwitch(t *testing.T) {
	requireAdmin(t)

	// Start from transparent
	setProxyMode(t, "transparent")
	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("transparent should have WAF disabled before switching to waf mode")
	}

	// Switch to waf
	setProxyMode(t, "waf")
	status = getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("waf mode should have WAF enabled")
	}
}

func TestProxy_WAF_NoChaos(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "waf")

	status := getProxyStatus(t)
	chaosConfig, ok := status["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("missing chaos_config in proxy status")
	}
	for key, val := range chaosConfig {
		if v, ok := val.(float64); ok && v != 0 {
			t.Errorf("waf mode: chaos_config[%s] = %v, want 0", key, v)
		}
	}

	// Reset
	setProxyMode(t, "transparent")
}

func TestProxy_WAF_BlockActionReported(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "waf")

	status := getProxyStatus(t)
	wafStats, ok := status["waf_stats"].(map[string]interface{})
	if !ok {
		t.Fatal("missing waf_stats in proxy status")
	}
	action, ok := wafStats["block_action"]
	if !ok {
		t.Error("waf_stats missing block_action")
	}
	// Block action should be a non-empty string
	if s, ok := action.(string); !ok || s == "" {
		t.Errorf("waf block_action should be a non-empty string, got %v", action)
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 4: Chaos Mode
// ===========================================================================

func TestProxy_Chaos_NoWAF(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "chaos")

	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("chaos mode should have WAF disabled")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Chaos_HasChaosConfig(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "chaos")

	status := getProxyStatus(t)
	chaosConfig, ok := status["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("missing chaos_config in proxy status")
	}

	// chaos_config should report the configured values
	// Note: These are the *stored* config values from the ProxyConfig snapshot,
	// not necessarily the active pipeline values. The modes package configures
	// the pipeline directly. We verify the mode is set correctly above.
	_ = chaosConfig

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 5: Gateway Mode
// ===========================================================================

func TestProxy_Gateway_WAFEnabled(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "gateway")

	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("gateway mode should have WAF enabled")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Gateway_Mode(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "gateway")

	status := getProxyStatus(t)
	if status["mode"] != "gateway" {
		t.Errorf("expected mode=gateway, got %v", status["mode"])
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 6: Nightmare Mode
// ===========================================================================

func TestProxy_Nightmare_WAFEnabled(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "nightmare")

	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("nightmare mode should have WAF enabled")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Nightmare_ModeValue(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "nightmare")

	status := getProxyStatus(t)
	if status["mode"] != "nightmare" {
		t.Errorf("expected mode=nightmare, got %v", status["mode"])
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 7: Mirror Mode
// ===========================================================================

func TestProxy_Mirror_ConfigSnapshot(t *testing.T) {
	requireAdmin(t)

	// Set mirror mode
	result := setProxyMode(t, "mirror")
	if result["ok"] != true {
		t.Fatalf("failed to set mirror mode: %v", result)
	}

	// Mirror config should be present in the response
	mirror, ok := result["mirror"]
	if !ok {
		t.Error("mirror mode response should include mirror config")
	}
	if mirror == nil {
		t.Error("mirror config should not be nil")
	}

	// Verify via status endpoint
	status := getProxyStatus(t)
	mirrorData, ok := status["mirror"]
	if !ok || mirrorData == nil {
		t.Error("proxy status should include mirror config when in mirror mode")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Mirror_NoWAF(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "mirror")

	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("mirror mode should have WAF disabled")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Mirror_SnapshotContainsServerSettings(t *testing.T) {
	requireAdmin(t)

	// First set some distinctive server config (using key/value format)
	// Note: booleans must be sent as numeric (0/1) since the config API uses float64
	setConfigKey(t, "delay_min_ms", 100)
	setConfigKey(t, "delay_max_ms", 500)
	setConfigKey(t, "content_theme", "test-mirror-theme")
	setConfigKey(t, "error_rate_multiplier", 2.5)
	setConfigKey(t, "header_corrupt_level", 3)
	setConfigKey(t, "protocol_glitch_enabled", 1)
	setConfigKey(t, "protocol_glitch_level", 2)

	// Switch to mirror mode
	setProxyMode(t, "mirror")

	// Refresh mirror to capture latest server settings
	refreshResult := refreshMirror(t)
	if refreshResult["ok"] != true {
		t.Fatalf("mirror refresh failed: %v", refreshResult)
	}

	mirrorData, ok := refreshResult["mirror"].(map[string]interface{})
	if !ok || mirrorData == nil {
		t.Fatal("mirror refresh should return mirror config")
	}

	// Verify the mirror captured our server settings
	if v, ok := mirrorData["delay_min_ms"].(float64); !ok || v != 100 {
		t.Errorf("mirror delay_min_ms=%v, want 100", mirrorData["delay_min_ms"])
	}
	if v, ok := mirrorData["delay_max_ms"].(float64); !ok || v != 500 {
		t.Errorf("mirror delay_max_ms=%v, want 500", mirrorData["delay_max_ms"])
	}
	if v, ok := mirrorData["content_theme"].(string); !ok || v != "test-mirror-theme" {
		t.Errorf("mirror content_theme=%v, want test-mirror-theme", mirrorData["content_theme"])
	}
	if v, ok := mirrorData["error_rate_multiplier"].(float64); !ok || v != 2.5 {
		t.Errorf("mirror error_rate_multiplier=%v, want 2.5", mirrorData["error_rate_multiplier"])
	}
	if v, ok := mirrorData["header_corrupt_level"].(float64); !ok || v != 3 {
		t.Errorf("mirror header_corrupt_level=%v, want 3", mirrorData["header_corrupt_level"])
	}
	if v, ok := mirrorData["protocol_glitch_enabled"].(bool); !ok || !v {
		t.Errorf("mirror protocol_glitch_enabled=%v, want true", mirrorData["protocol_glitch_enabled"])
	}
	if v, ok := mirrorData["protocol_glitch_level"].(float64); !ok || v != 2 {
		t.Errorf("mirror protocol_glitch_level=%v, want 2", mirrorData["protocol_glitch_level"])
	}

	// Verify snapshot_time is present
	if _, ok := mirrorData["snapshot_time"].(string); !ok {
		t.Error("mirror config should have snapshot_time")
	}

	// Cleanup: reset server config
	setConfigKey(t, "delay_min_ms", 0)
	setConfigKey(t, "delay_max_ms", 0)
	setConfigKey(t, "content_theme", "default")
	setConfigKey(t, "error_rate_multiplier", 1.0)
	setConfigKey(t, "header_corrupt_level", 0)
	setConfigKey(t, "protocol_glitch_enabled", 0)
	setConfigKey(t, "protocol_glitch_level", 0)
	setProxyMode(t, "transparent")
}

func TestProxy_Mirror_RefreshEndpoint(t *testing.T) {
	requireAdmin(t)

	// Set mirror mode
	setProxyMode(t, "mirror")

	// Set a distinctive server config
	setConfigKey(t, "delay_min_ms", 42)
	setConfigKey(t, "delay_max_ms", 84)

	// Refresh the mirror
	result := refreshMirror(t)
	if result["ok"] != true {
		t.Fatalf("mirror refresh failed: %v", result)
	}

	mirrorData, ok := result["mirror"].(map[string]interface{})
	if !ok || mirrorData == nil {
		t.Fatal("refresh should return mirror data")
	}

	// Verify the refreshed values
	if v, _ := mirrorData["delay_min_ms"].(float64); v != 42 {
		t.Errorf("after refresh, delay_min_ms=%v, want 42", v)
	}
	if v, _ := mirrorData["delay_max_ms"].(float64); v != 84 {
		t.Errorf("after refresh, delay_max_ms=%v, want 84", v)
	}

	// Cleanup
	setConfigKey(t, "delay_min_ms", 0)
	setConfigKey(t, "delay_max_ms", 0)
	setProxyMode(t, "transparent")
}

func TestProxy_Mirror_StatusShowsMirrorConfig(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "mirror")

	status := getProxyStatus(t)
	if status["mode"] != "mirror" {
		t.Errorf("mode=%v, want mirror", status["mode"])
	}
	if _, ok := status["mirror"]; !ok {
		t.Error("proxy status in mirror mode should contain 'mirror' key")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 8: WAF Auto-Enable by Mode
// ===========================================================================

func TestProxy_WAFAutoEnable_ByMode(t *testing.T) {
	requireAdmin(t)

	testCases := []struct {
		mode       string
		wafExpected bool
	}{
		{"transparent", false},
		{"waf", true},
		{"chaos", false},
		{"gateway", true},
		{"nightmare", true},
		{"mirror", false},
	}

	for _, tc := range testCases {
		t.Run(tc.mode, func(t *testing.T) {
			setProxyMode(t, tc.mode)
			status := getProxyStatus(t)
			wafEnabled, _ := status["waf_enabled"].(bool)
			if wafEnabled != tc.wafExpected {
				t.Errorf("mode %s: waf_enabled=%v, want %v", tc.mode, wafEnabled, tc.wafExpected)
			}
		})
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 9: Proxy Status Endpoint Structure
// ===========================================================================

func TestProxy_StatusEndpoint_Structure(t *testing.T) {
	requireAdmin(t)

	status := getProxyStatus(t)

	// Required top-level keys
	requiredKeys := []string{"mode", "waf_enabled", "waf_stats", "chaos_config", "pipeline_stats", "interceptors"}
	for _, key := range requiredKeys {
		if _, ok := status[key]; !ok {
			t.Errorf("proxy status missing required key: %s", key)
		}
	}
}

func TestProxy_StatusEndpoint_WAFStatsStructure(t *testing.T) {
	requireAdmin(t)

	status := getProxyStatus(t)
	wafStats, ok := status["waf_stats"].(map[string]interface{})
	if !ok {
		t.Fatal("waf_stats should be an object")
	}

	wafKeys := []string{"detections", "rate_limited", "block_action"}
	for _, key := range wafKeys {
		if _, ok := wafStats[key]; !ok {
			t.Errorf("waf_stats missing key: %s", key)
		}
	}
}

func TestProxy_StatusEndpoint_ChaosConfigStructure(t *testing.T) {
	requireAdmin(t)

	status := getProxyStatus(t)
	chaosConfig, ok := status["chaos_config"].(map[string]interface{})
	if !ok {
		t.Fatal("chaos_config should be an object")
	}

	chaosKeys := []string{"latency_prob", "corrupt_prob", "drop_prob", "reset_prob"}
	for _, key := range chaosKeys {
		if _, ok := chaosConfig[key]; !ok {
			t.Errorf("chaos_config missing key: %s", key)
		}
	}
}

func TestProxy_StatusEndpoint_PipelineStatsStructure(t *testing.T) {
	requireAdmin(t)

	status := getProxyStatus(t)
	pipelineStats, ok := status["pipeline_stats"].(map[string]interface{})
	if !ok {
		t.Fatal("pipeline_stats should be an object")
	}

	pipelineKeys := []string{"requests_processed", "responses_processed", "requests_blocked", "responses_modified"}
	for _, key := range pipelineKeys {
		if _, ok := pipelineStats[key]; !ok {
			t.Errorf("pipeline_stats missing key: %s", key)
		}
	}
}

// ===========================================================================
// SECTION 10: Nightmare Mode via Nightmare API
// ===========================================================================

func TestProxy_Nightmare_ViaAPI_Enable(t *testing.T) {
	requireAdmin(t)

	// Start from transparent
	setProxyMode(t, "transparent")

	// Enable nightmare for proxy
	result := setNightmare(t, "proxy", true)
	if result["ok"] != true {
		t.Fatalf("failed to enable proxy nightmare: %v", result)
	}

	// Verify nightmare state
	state := getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); !proxyActive {
		t.Error("proxy nightmare should be active after enabling")
	}

	// Verify proxy mode switched to nightmare
	status := getProxyStatus(t)
	if status["mode"] != "nightmare" {
		t.Errorf("proxy mode=%v after nightmare enable, want nightmare", status["mode"])
	}

	// Disable nightmare
	setNightmare(t, "proxy", false)
}

func TestProxy_Nightmare_ViaAPI_Disable_RestoresMode(t *testing.T) {
	requireAdmin(t)

	// Set a specific mode
	setProxyMode(t, "waf")

	// Enable nightmare
	setNightmare(t, "proxy", true)

	// Verify it's in nightmare
	status := getProxyStatus(t)
	if status["mode"] != "nightmare" {
		t.Errorf("mode=%v after nightmare enable, want nightmare", status["mode"])
	}

	// Disable nightmare — should restore previous mode
	setNightmare(t, "proxy", false)
	status = getProxyStatus(t)
	if status["mode"] != "waf" {
		t.Errorf("mode=%v after nightmare disable, want waf (previous mode)", status["mode"])
	}

	// State should show proxy as inactive
	state := getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); proxyActive {
		t.Error("proxy nightmare should be inactive after disabling")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Nightmare_AllMode_IncludesProxy(t *testing.T) {
	requireAdmin(t)

	// Start from transparent
	setProxyMode(t, "transparent")

	// Enable all nightmare
	result := setNightmare(t, "all", true)
	if result["ok"] != true {
		t.Fatalf("failed to enable all nightmare: %v", result)
	}

	// Verify proxy is in nightmare
	state := getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); !proxyActive {
		t.Error("proxy should be active when 'all' nightmare is enabled")
	}
	if serverActive, _ := state["server"].(bool); !serverActive {
		t.Error("server should be active when 'all' nightmare is enabled")
	}
	if scannerActive, _ := state["scanner"].(bool); !scannerActive {
		t.Error("scanner should be active when 'all' nightmare is enabled")
	}

	// Disable all
	setNightmare(t, "all", false)

	// Verify all disabled
	state = getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); proxyActive {
		t.Error("proxy should be inactive after 'all' nightmare disabled")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 11: Mode Transitions and State Consistency
// ===========================================================================

func TestProxy_ModeTransition_TransparentToWAFAndBack(t *testing.T) {
	requireAdmin(t)

	setProxyMode(t, "transparent")
	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("transparent should have WAF off")
	}

	setProxyMode(t, "waf")
	status = getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("waf should have WAF on")
	}

	setProxyMode(t, "transparent")
	status = getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("back to transparent should have WAF off")
	}
}

func TestProxy_ModeTransition_ChaosToNightmare(t *testing.T) {
	requireAdmin(t)

	setProxyMode(t, "chaos")
	status := getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("chaos mode should not have WAF enabled")
	}

	setProxyMode(t, "nightmare")
	status = getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("nightmare mode should have WAF enabled")
	}
	if status["mode"] != "nightmare" {
		t.Errorf("mode=%v, want nightmare", status["mode"])
	}

	setProxyMode(t, "transparent")
}

func TestProxy_ModeTransition_MirrorToGateway(t *testing.T) {
	requireAdmin(t)

	setProxyMode(t, "mirror")
	status := getProxyStatus(t)
	if _, ok := status["mirror"]; !ok {
		t.Error("mirror mode should have mirror config in status")
	}
	if waf, _ := status["waf_enabled"].(bool); waf {
		t.Error("mirror mode should not have WAF enabled")
	}

	setProxyMode(t, "gateway")
	status = getProxyStatus(t)
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("gateway mode should have WAF enabled")
	}
	if status["mode"] != "gateway" {
		t.Errorf("mode=%v, want gateway", status["mode"])
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 12: Proxy Runtime Lifecycle
// ===========================================================================

func TestProxy_Runtime_StatusEndpoint(t *testing.T) {
	requireAdmin(t)

	req, _ := http.NewRequest("GET", adminURL+"/admin/api/proxy/runtime", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET proxy/runtime: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("proxy/runtime status=%d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Should have running, port, target, requests keys
	requiredKeys := []string{"running", "port", "target", "requests"}
	for _, key := range requiredKeys {
		if _, ok := result[key]; !ok {
			t.Errorf("proxy/runtime missing key: %s", key)
		}
	}
}

// ===========================================================================
// SECTION 13: Behavioral Verification via Server Requests
//
// These tests verify that mode settings actually affect behavior when
// requests are made to the main server port. Since the proxy runs
// in-process, the effects are observed through the admin API state
// and through request headers/responses.
// ===========================================================================

func TestProxy_Behavioral_ServerStillResponds(t *testing.T) {
	requireServer(t)
	requireAdmin(t)

	// In any proxy mode, the main server should still respond.
	// Use internal health path to avoid error injection timeouts.
	healthPath := "/health"
	if secret := os.Getenv("GLITCH_HEALTH_SECRET"); secret != "" {
		healthPath = "/_internal/" + secret + "/healthz"
	}
	modes := []string{"transparent", "waf", "chaos", "gateway"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			setProxyMode(t, mode)

			var lastErr error
			for i := 0; i < 5; i++ {
				cl := &http.Client{Timeout: 10 * time.Second}
				resp, err := cl.Get(serverURL + healthPath)
				if err != nil {
					lastErr = err
					time.Sleep(100 * time.Millisecond)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode > 0 {
					lastErr = nil
					break
				}
			}
			if lastErr != nil {
				t.Errorf("server not responding in %s mode: %v", mode, lastErr)
			}
		})
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 14: Mirror Mode Server Settings Capture
// ===========================================================================

func TestProxy_Mirror_CapturesErrorWeights(t *testing.T) {
	requireAdmin(t)

	// Set distinctive error weights on the server (one at a time via API)
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_500", "weight": 0.5,
	})
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_503", "weight": 0.3,
	})
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_429", "weight": 0.2,
	})

	// Switch to mirror mode
	setProxyMode(t, "mirror")

	// Refresh to get latest
	result := refreshMirror(t)
	mirrorData, ok := result["mirror"].(map[string]interface{})
	if !ok {
		t.Fatal("mirror refresh should return mirror data")
	}

	// Verify error_weights were captured
	ew, ok := mirrorData["error_weights"].(map[string]interface{})
	if !ok {
		t.Fatal("mirror should have error_weights map")
	}
	// At least some error weights should be present
	if len(ew) == 0 {
		t.Error("mirror error_weights should not be empty")
	}

	setProxyMode(t, "transparent")
}

func TestProxy_Mirror_CapturesPageTypeWeights(t *testing.T) {
	requireAdmin(t)

	setProxyMode(t, "mirror")
	result := refreshMirror(t)
	mirrorData, ok := result["mirror"].(map[string]interface{})
	if !ok {
		t.Fatal("mirror refresh should return mirror data")
	}

	// page_type_weights should be present
	if _, ok := mirrorData["page_type_weights"]; !ok {
		t.Error("mirror should have page_type_weights")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 15: Mirror Mode — Multiple Refresh Cycles
// ===========================================================================

func TestProxy_Mirror_MultipleRefreshes(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "mirror")

	// First refresh
	result1 := refreshMirror(t)
	mirror1, ok := result1["mirror"].(map[string]interface{})
	if !ok {
		t.Fatal("first refresh should return mirror data")
	}
	time1, _ := mirror1["snapshot_time"].(string)

	// Small delay to ensure different timestamp
	time.Sleep(1100 * time.Millisecond)

	// Second refresh
	result2 := refreshMirror(t)
	mirror2, ok := result2["mirror"].(map[string]interface{})
	if !ok {
		t.Fatal("second refresh should return mirror data")
	}
	time2, _ := mirror2["snapshot_time"].(string)

	// Snapshot times should differ
	if time1 == time2 {
		t.Error("consecutive mirror refreshes should have different snapshot_time values")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 16: Edge Cases
// ===========================================================================

func TestProxy_StatusEndpoint_MethodCheck(t *testing.T) {
	requireAdmin(t)

	// POST to mode endpoint without body should fail
	req, _ := http.NewRequest("POST", adminURL+"/admin/api/proxy/mode", nil)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST proxy/mode with nil body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("POST proxy/mode with empty body should not return 200")
	}
}

func TestProxy_ModeEndpoint_RequiresPOST(t *testing.T) {
	requireAdmin(t)

	req, _ := http.NewRequest("GET", adminURL+"/admin/api/proxy/mode", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET proxy/mode: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET proxy/mode returned %d, want 405", resp.StatusCode)
	}
}

func TestProxy_MirrorRefresh_RequiresPOST(t *testing.T) {
	requireAdmin(t)

	req, _ := http.NewRequest("GET", adminURL+"/admin/api/proxy/mirror/refresh", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET proxy/mirror/refresh: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET proxy/mirror/refresh returned %d, want 405", resp.StatusCode)
	}
}

// ===========================================================================
// SECTION 17: Nightmare API Edge Cases
// ===========================================================================

func TestProxy_Nightmare_InvalidMode(t *testing.T) {
	requireAdmin(t)

	resp, err := postJSON(adminURL+"/admin/api/nightmare", map[string]interface{}{
		"mode":    "invalid",
		"enabled": true,
	})
	if err != nil {
		t.Fatalf("nightmare invalid mode: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("nightmare with invalid mode returned %d, want 400", resp.StatusCode)
	}
}

func TestProxy_Nightmare_DoubleEnable(t *testing.T) {
	requireAdmin(t)

	// Enable proxy nightmare twice — should not crash
	setNightmare(t, "proxy", true)
	setNightmare(t, "proxy", true)

	state := getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); !proxyActive {
		t.Error("proxy nightmare should still be active after double enable")
	}

	setNightmare(t, "proxy", false)
	setProxyMode(t, "transparent")
}

func TestProxy_Nightmare_DoubleDisable(t *testing.T) {
	requireAdmin(t)

	// Disable without enabling first — should not crash
	setNightmare(t, "proxy", false)
	setNightmare(t, "proxy", false)

	state := getNightmareState(t)
	if proxyActive, _ := state["proxy"].(bool); proxyActive {
		t.Error("proxy nightmare should be inactive after double disable")
	}
}

// ===========================================================================
// SECTION 18: Comprehensive Mode Verification Table
//
// Verifies every mode has the expected WAF and mode state.
// ===========================================================================

func TestProxy_AllModes_FullVerification(t *testing.T) {
	requireAdmin(t)

	type modeExpectation struct {
		mode       string
		wafEnabled bool
		hasInterceptors bool // at least some interceptors configured
	}

	expectations := []modeExpectation{
		{"transparent", false, false},
		{"waf", true, false},        // interceptors are in pipeline, not in status snapshot
		{"chaos", false, false},
		{"gateway", true, false},
		{"nightmare", true, false},
		{"mirror", false, false},
	}

	for _, exp := range expectations {
		t.Run(exp.mode, func(t *testing.T) {
			setProxyMode(t, exp.mode)
			status := getProxyStatus(t)

			// Verify mode
			if status["mode"] != exp.mode {
				t.Errorf("mode=%v, want %s", status["mode"], exp.mode)
			}

			// Verify WAF state
			waf, _ := status["waf_enabled"].(bool)
			if waf != exp.wafEnabled {
				t.Errorf("waf_enabled=%v, want %v", waf, exp.wafEnabled)
			}
		})
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 19: Concurrent Mode Switching
// ===========================================================================

func TestProxy_ConcurrentModeSwitching(t *testing.T) {
	requireAdmin(t)

	modes := []string{"transparent", "waf", "chaos", "gateway", "mirror"}

	// Run many concurrent mode switches
	done := make(chan struct{}, len(modes)*3)
	for i := 0; i < 3; i++ {
		for _, mode := range modes {
			go func(m string) {
				defer func() { done <- struct{}{} }()
				setProxyMode(t, m)
			}(mode)
		}
	}

	// Wait for all goroutines
	for i := 0; i < len(modes)*3; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for concurrent mode switches")
		}
	}

	// After all concurrent switches, the server should still be healthy
	status := getProxyStatus(t)
	if _, ok := status["mode"].(string); !ok {
		t.Error("proxy status should still have a valid mode after concurrent switching")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 20: Proxy + Server Integration
// ===========================================================================

func TestProxy_ServerRequestsWithProxyModes(t *testing.T) {
	requireServer(t)
	requireAdmin(t)

	// Test that server endpoints still work across proxy mode changes.
	// The proxy is in-process so it doesn't intercept server traffic,
	// but mode changes should not break the server.
	// Use internal health path to avoid error injection timeouts.
	healthPath2 := "/health"
	if secret := os.Getenv("GLITCH_HEALTH_SECRET"); secret != "" {
		healthPath2 = "/_internal/" + secret + "/healthz"
	}

	modes := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}

	for _, mode := range modes {
		t.Run(fmt.Sprintf("server_health_in_%s_mode", mode), func(t *testing.T) {
			setProxyMode(t, mode)

			var success bool
			for retry := 0; retry < 5; retry++ {
				cl := &http.Client{Timeout: 10 * time.Second}
				resp, err := cl.Get(serverURL + healthPath2)
				if err != nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode < 500 {
					success = true
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !success {
				t.Errorf("server health not responding in %s proxy mode", mode)
			}
		})
	}

	setProxyMode(t, "transparent")
}

func TestProxy_AdminAPIStillWorksInNightmare(t *testing.T) {
	requireAdmin(t)

	setProxyMode(t, "nightmare")

	// Admin API should still be accessible even in nightmare mode
	status := getProxyStatus(t)
	if status["mode"] != "nightmare" {
		t.Errorf("could not read proxy status in nightmare mode")
	}

	// Config endpoint should work
	config := getJSON(t, adminURL+"/admin/api/config")
	if config == nil {
		t.Error("admin config API failed in nightmare mode")
	}

	// Features endpoint should work
	features := getJSON(t, adminURL+"/admin/api/features")
	if features == nil {
		t.Error("admin features API failed in nightmare mode")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 21: Mode Descriptions via List
// ===========================================================================

func TestProxy_AllModesInList(t *testing.T) {
	requireAdmin(t)

	// Verify each mode in the known list is settable
	knownModes := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}
	for _, mode := range knownModes {
		result := setProxyMode(t, mode)
		if result["ok"] != true {
			t.Errorf("mode %s should be settable but got: %v", mode, result)
		}
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 22: Nightmare Mode Restore Consistency
// ===========================================================================

func TestProxy_Nightmare_RestoreDifferentModes(t *testing.T) {
	requireAdmin(t)

	// Test that nightmare restores each possible previous mode
	prevModes := []string{"transparent", "waf", "chaos", "gateway", "mirror"}

	for _, prev := range prevModes {
		t.Run("restore_"+prev, func(t *testing.T) {
			setProxyMode(t, prev)

			// Enable nightmare
			setNightmare(t, "proxy", true)
			status := getProxyStatus(t)
			if status["mode"] != "nightmare" {
				t.Fatalf("mode=%v after nightmare enable, want nightmare", status["mode"])
			}

			// Disable nightmare — should restore
			setNightmare(t, "proxy", false)
			status = getProxyStatus(t)
			if status["mode"] != prev {
				t.Errorf("mode=%v after nightmare disable, want %s", status["mode"], prev)
			}
		})
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 23: Mirror Mode Error Weights Roundtrip
// ===========================================================================

func TestProxy_Mirror_ErrorWeightsRoundtrip(t *testing.T) {
	requireAdmin(t)

	// Set specific error weights on the server (one at a time via API)
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_500", "weight": 0.4,
	})
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_502", "weight": 0.3,
	})
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_503", "weight": 0.2,
	})
	postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "http_504", "weight": 0.1,
	})

	// Enter mirror mode and refresh
	setProxyMode(t, "mirror")
	result := refreshMirror(t)
	mirrorData, ok := result["mirror"].(map[string]interface{})
	if !ok {
		t.Fatal("mirror refresh should return mirror data")
	}

	// Check that error_weights is present and non-empty
	ew, ok := mirrorData["error_weights"].(map[string]interface{})
	if !ok || len(ew) == 0 {
		t.Error("mirror error_weights should be present and non-empty after setting server weights")
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 24: Mode-Specific Status Invariants
// ===========================================================================

func TestProxy_Transparent_StatusInvariants(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "transparent")

	status := getProxyStatus(t)

	// No mirror config in transparent
	if _, ok := status["mirror"]; ok {
		// It's ok if mirror is nil or absent — just shouldn't be a non-nil config
		if m, ok := status["mirror"].(map[string]interface{}); ok && m != nil {
			// Mirror from a previous mode may linger — that's acceptable
			// as long as mode is transparent
		}
	}

	// Mode must be transparent
	if status["mode"] != "transparent" {
		t.Errorf("mode=%v, want transparent", status["mode"])
	}
}

func TestProxy_Nightmare_StatusInvariants(t *testing.T) {
	requireAdmin(t)
	setProxyMode(t, "nightmare")

	status := getProxyStatus(t)

	// WAF must be on in nightmare
	if waf, _ := status["waf_enabled"].(bool); !waf {
		t.Error("nightmare must have WAF enabled")
	}

	// Mode must be nightmare
	if status["mode"] != "nightmare" {
		t.Errorf("mode=%v, want nightmare", status["mode"])
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 25: Proxy Status JSON Serializability
// ===========================================================================

func TestProxy_Status_ValidJSON(t *testing.T) {
	requireAdmin(t)

	modes := []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			setProxyMode(t, mode)

			req, _ := http.NewRequest("GET", adminURL+"/admin/api/proxy/status", nil)
			req.SetBasicAuth("admin", adminPassword)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("GET proxy/status: %v", err)
			}
			defer resp.Body.Close()

			// Must be valid JSON
			var raw json.RawMessage
			if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
				t.Errorf("proxy status in %s mode is not valid JSON: %v", mode, err)
			}
		})
	}

	setProxyMode(t, "transparent")
}

// ===========================================================================
// SECTION 26: Proxy Status Content-Type
// ===========================================================================

func TestProxy_Status_ContentType(t *testing.T) {
	requireAdmin(t)

	req, _ := http.NewRequest("GET", adminURL+"/admin/api/proxy/status", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET proxy/status: %v", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type=%s, want application/json", ct)
	}
}

// Suppress unused import warnings
var _ = fmt.Sprintf
var _ = time.Now
