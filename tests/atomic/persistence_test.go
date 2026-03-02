// Package atomic — persistence tests proving settings survive server restarts.
//
// These tests verify the complete persistence chain:
//   1. File-based (.glitch-state.json): ExportConfig → JSON → ImportConfig
//   2. Database (PostgreSQL): SaveFullConfig → LoadFullConfig → ImportConfig
//   3. Round-trip fidelity: every persisted setting is accurately restored
//   4. Non-persisted settings (proxy, scanner) are NOT in the config export
//
// The tests simulate a restart by: changing settings → exporting → resetting all
// settings to defaults → importing → verifying all non-default values are restored.
package atomic

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/storage"
)

// ---------------------------------------------------------------------------
// Category 1: Feature flags persistence
// ---------------------------------------------------------------------------

// TestPersist_FeatureFlags_RoundTrip verifies all 22 feature flags survive
// an export/reset/import cycle (simulates restart from state file).
func TestPersist_FeatureFlags_RoundTrip(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Set every flag to a non-default value (all defaults are true, so set all to false)
	flags := dashboard.GetFeatureFlags()
	allFlags := flags.Snapshot()
	for name := range allFlags {
		flags.Set(name, false)
	}

	// Verify flags are false before export
	snap := flags.Snapshot()
	for name, val := range snap {
		if val {
			t.Fatalf("flag %q should be false before export, got true", name)
		}
	}

	// Export config (simulates auto-save)
	exported := dashboard.ExportConfig()

	// Reset to defaults (simulates fresh startup)
	resetFeatureFlags(t)

	// Verify flags are back to true (defaults)
	snap = flags.Snapshot()
	for name, val := range snap {
		if !val {
			t.Fatalf("flag %q should be true after reset, got false", name)
		}
	}

	// Import (simulates LoadStateFile)
	dashboard.ImportConfig(exported)

	// Verify all flags are restored to false (the non-default values)
	for name := range allFlags {
		verifyFeatureFlag(t, mux, name, false)
	}
}

// TestPersist_FeatureFlags_Selective verifies that selectively disabling a
// few flags persists correctly while others remain enabled.
func TestPersist_FeatureFlags_Selective(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	disabledFlags := []string{"labyrinth", "captcha", "honeypot", "vuln", "spider"}
	flags := dashboard.GetFeatureFlags()
	for _, name := range disabledFlags {
		flags.Set(name, false)
	}

	exported := dashboard.ExportConfig()
	resetFeatureFlags(t)
	dashboard.ImportConfig(exported)

	allFlags := flags.Snapshot()
	for name := range allFlags {
		expected := true
		for _, df := range disabledFlags {
			if name == df {
				expected = false
				break
			}
		}
		verifyFeatureFlag(t, mux, name, expected)
	}
}

// ---------------------------------------------------------------------------
// Category 2: Admin config numeric settings persistence
// ---------------------------------------------------------------------------

// TestPersist_AdminConfig_AllNumeric verifies every numeric config parameter
// survives an export/import cycle with non-default values.
func TestPersist_AdminConfig_AllNumeric(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Set every numeric config to a non-default, boundary-testing value
	nonDefaults := map[string]float64{
		"max_labyrinth_depth":    77,
		"error_rate_multiplier":  3.5,
		"captcha_trigger_thresh": 200,
		"block_chance":           0.5,
		"block_duration_sec":     120,
		"bot_score_threshold":    80,
		"header_corrupt_level":   3,
		"delay_min_ms":           100,
		"delay_max_ms":           500,
		"labyrinth_link_density": 15,
		"adaptive_interval_sec":  60,
		"protocol_glitch_level":  4,
		"cookie_trap_frequency":  10,
		"js_trap_difficulty":     5,
		"content_cache_ttl_sec":  300,
		"adaptive_aggressive_rps":  50,
		"adaptive_labyrinth_paths": 20,
	}

	cfg := dashboard.GetAdminConfig()
	for key, val := range nonDefaults {
		cfg.Set(key, val)
	}

	exported := dashboard.ExportConfig()
	resetAdminConfig(t)
	dashboard.ImportConfig(exported)

	for key, expected := range nonDefaults {
		verifyConfigValue(t, mux, key, expected)
	}
}

// TestPersist_AdminConfig_StringSettings verifies string config parameters
// survive an export/import cycle.
func TestPersist_AdminConfig_StringSettings(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	stringSettings := map[string]string{
		"honeypot_response_style": "aggressive",
		"active_framework":        "rails",
		"content_theme":           "corporate",
		"recorder_format":         "pcap",
	}

	cfg := dashboard.GetAdminConfig()
	for key, val := range stringSettings {
		cfg.SetString(key, val)
	}

	exported := dashboard.ExportConfig()
	resetAdminConfig(t)
	dashboard.ImportConfig(exported)

	for key, expected := range stringSettings {
		verifyConfigValue(t, mux, key, expected)
	}
}

// TestPersist_AdminConfig_ProtocolGlitchEnabled verifies the boolean
// protocol_glitch_enabled setting persists. It's stored as bool internally
// but Set() accepts 0/1 as float64.
func TestPersist_AdminConfig_ProtocolGlitchEnabled(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	cfg := dashboard.GetAdminConfig()
	cfg.Set("protocol_glitch_enabled", 0) // disable (default is 1/true)

	// Verify it's disabled before export
	cfgMap := cfg.Get()
	if cfgMap["protocol_glitch_enabled"] != false {
		t.Fatalf("protocol_glitch_enabled should be false after Set(0), got %v", cfgMap["protocol_glitch_enabled"])
	}

	exported := dashboard.ExportConfig()
	resetAdminConfig(t) // resets to protocol_glitch_enabled=1

	// Verify it's enabled after reset
	cfgMap = cfg.Get()
	if cfgMap["protocol_glitch_enabled"] != true {
		t.Fatalf("protocol_glitch_enabled should be true after reset, got %v", cfgMap["protocol_glitch_enabled"])
	}

	dashboard.ImportConfig(exported)

	// Verify it's disabled again after import
	cfgMap = cfg.Get()
	if cfgMap["protocol_glitch_enabled"] != false {
		t.Errorf("protocol_glitch_enabled should be false after import, got %v (%T)", cfgMap["protocol_glitch_enabled"], cfgMap["protocol_glitch_enabled"])
	}
}

// ---------------------------------------------------------------------------
// Category 3: Vuln config persistence
// ---------------------------------------------------------------------------

// TestPersist_VulnGroups_RoundTrip verifies all vuln groups survive export/import.
func TestPersist_VulnGroups_RoundTrip(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Disable specific groups
	disabledGroups := []string{"api_security", "modern", "specialized"}
	vc := dashboard.GetVulnConfig()
	for _, g := range disabledGroups {
		vc.SetGroup(g, false)
	}

	exported := dashboard.ExportConfig()
	resetVulnConfig(t) // all enabled again
	dashboard.ImportConfig(exported)

	for _, g := range dashboard.VulnGroups {
		expected := true
		for _, dg := range disabledGroups {
			if g == dg {
				expected = false
				break
			}
		}
		verifyVulnGroup(t, mux, g, expected)
	}
}

// TestPersist_VulnGroups_AllDisabled verifies that disabling all groups persists.
func TestPersist_VulnGroups_AllDisabled(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	vc := dashboard.GetVulnConfig()
	for _, g := range dashboard.VulnGroups {
		vc.SetGroup(g, false)
	}

	exported := dashboard.ExportConfig()
	resetVulnConfig(t)
	dashboard.ImportConfig(exported)

	for _, g := range dashboard.VulnGroups {
		verifyVulnGroup(t, mux, g, false)
	}
}

// ---------------------------------------------------------------------------
// Category 4: Error weights persistence
// ---------------------------------------------------------------------------

// TestPersist_ErrorWeights_RoundTrip verifies custom error weights survive export/import.
func TestPersist_ErrorWeights_RoundTrip(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	customWeights := map[string]float64{
		"http_4xx":        0.3,
		"http_5xx":        0.2,
		"connection_reset": 0.15,
		"slow_response":   0.1,
		"empty_body":      0.05,
		"garbage_data":    0.2,
	}

	cfg := dashboard.GetAdminConfig()
	cfg.ResetErrorWeights()
	for errType, weight := range customWeights {
		cfg.SetErrorWeight(errType, weight)
	}

	exported := dashboard.ExportConfig()

	// Verify export has our weights
	if exported.ErrorWeights == nil {
		t.Fatal("ExportConfig returned nil ErrorWeights")
	}
	for errType, expected := range customWeights {
		actual, ok := exported.ErrorWeights[errType]
		if !ok {
			t.Errorf("ErrorWeights missing %q in export", errType)
			continue
		}
		if actual != expected {
			t.Errorf("ErrorWeights[%q] = %v, want %v", errType, actual, expected)
		}
	}

	// Reset and reimport
	resetAdminConfig(t)
	dashboard.ImportConfig(exported)

	// Verify weights restored
	restored := cfg.GetErrorWeights()
	for errType, expected := range customWeights {
		actual, ok := restored[errType]
		if !ok {
			t.Errorf("Restored ErrorWeights missing %q", errType)
			continue
		}
		if actual != expected {
			t.Errorf("Restored ErrorWeights[%q] = %v, want %v", errType, actual, expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Category 5: Page type weights persistence
// ---------------------------------------------------------------------------

// TestPersist_PageTypeWeights_RoundTrip verifies custom page type weights
// survive export/import.
func TestPersist_PageTypeWeights_RoundTrip(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	customWeights := map[string]float64{
		"html":     0.1,
		"json":     0.4,
		"xml":      0.2,
		"plain":    0.1,
		"csv":      0.1,
		"markdown": 0.1,
	}

	cfg := dashboard.GetAdminConfig()
	cfg.ResetPageTypeWeights()
	for pt, weight := range customWeights {
		cfg.SetPageTypeWeight(pt, weight)
	}

	exported := dashboard.ExportConfig()

	if exported.PageTypeWeights == nil {
		t.Fatal("ExportConfig returned nil PageTypeWeights")
	}
	for pt, expected := range customWeights {
		actual, ok := exported.PageTypeWeights[pt]
		if !ok {
			t.Errorf("PageTypeWeights missing %q in export", pt)
			continue
		}
		if actual != expected {
			t.Errorf("PageTypeWeights[%q] = %v, want %v", pt, actual, expected)
		}
	}

	resetAdminConfig(t)
	dashboard.ImportConfig(exported)

	restored := cfg.GetPageTypeWeights()
	for pt, expected := range customWeights {
		actual, ok := restored[pt]
		if !ok {
			t.Errorf("Restored PageTypeWeights missing %q", pt)
			continue
		}
		if actual != expected {
			t.Errorf("Restored PageTypeWeights[%q] = %v, want %v", pt, actual, expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Category 6: Full config JSON round-trip (simulates file save/load)
// ---------------------------------------------------------------------------

// TestPersist_FullConfig_JSONRoundTrip verifies the full export → marshal →
// unmarshal → import chain, exactly as .glitch-state.json persistence works.
func TestPersist_FullConfig_JSONRoundTrip(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Set a variety of non-default settings across all subsystems
	flags := dashboard.GetFeatureFlags()
	flags.Set("labyrinth", false)
	flags.Set("captcha", false)
	flags.Set("spider", false)

	cfg := dashboard.GetAdminConfig()
	cfg.Set("error_rate_multiplier", 4.0)
	cfg.Set("max_labyrinth_depth", 99)
	cfg.Set("header_corrupt_level", 4)
	cfg.Set("delay_min_ms", 50)
	cfg.Set("delay_max_ms", 200)
	cfg.SetString("content_theme", "corporate")
	cfg.SetString("active_framework", "django")

	vc := dashboard.GetVulnConfig()
	vc.SetGroup("owasp", false)
	vc.SetGroup("infrastructure", false)

	cfg.ResetErrorWeights()
	cfg.SetErrorWeight("http_4xx", 0.8)
	cfg.SetErrorWeight("http_5xx", 0.2)

	cfg.ResetPageTypeWeights()
	cfg.SetPageTypeWeight("json", 0.6)
	cfg.SetPageTypeWeight("xml", 0.4)

	// Export
	exported := dashboard.ExportConfig()

	// Marshal to JSON (exactly like auto-save writes to file)
	data, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}

	// Unmarshal from JSON (exactly like LoadStateFile reads from file)
	var reimported dashboard.ConfigExport
	if err := json.Unmarshal(data, &reimported); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Reset all to defaults
	resetAll(t)

	// Import from the JSON-round-tripped config
	dashboard.ImportConfig(&reimported)

	// Verify feature flags
	verifyFeatureFlag(t, mux, "labyrinth", false)
	verifyFeatureFlag(t, mux, "captcha", false)
	verifyFeatureFlag(t, mux, "spider", false)
	verifyFeatureFlag(t, mux, "honeypot", true) // was not changed
	verifyFeatureFlag(t, mux, "vuln", true)     // was not changed

	// Verify numeric config
	verifyConfigValue(t, mux, "error_rate_multiplier", 4.0)
	verifyConfigValue(t, mux, "max_labyrinth_depth", float64(99))
	verifyConfigValue(t, mux, "header_corrupt_level", float64(4))
	verifyConfigValue(t, mux, "delay_min_ms", float64(50))
	verifyConfigValue(t, mux, "delay_max_ms", float64(200))

	// Verify string config
	verifyConfigValue(t, mux, "content_theme", "corporate")
	verifyConfigValue(t, mux, "active_framework", "django")

	// Verify vuln groups
	verifyVulnGroup(t, mux, "owasp", false)
	verifyVulnGroup(t, mux, "infrastructure", false)
	verifyVulnGroup(t, mux, "api_security", true) // was not changed

	// Verify error weights
	ew := cfg.GetErrorWeights()
	if ew["http_4xx"] != 0.8 {
		t.Errorf("ErrorWeights[http_4xx] = %v, want 0.8", ew["http_4xx"])
	}
	if ew["http_5xx"] != 0.2 {
		t.Errorf("ErrorWeights[http_5xx] = %v, want 0.2", ew["http_5xx"])
	}

	// Verify page type weights
	pw := cfg.GetPageTypeWeights()
	if pw["json"] != 0.6 {
		t.Errorf("PageTypeWeights[json] = %v, want 0.6", pw["json"])
	}
	if pw["xml"] != 0.4 {
		t.Errorf("PageTypeWeights[xml] = %v, want 0.4", pw["xml"])
	}
}

// TestPersist_FullConfig_FileRoundTrip writes to an actual temp file and reads
// back, verifying the complete file-based persistence chain.
func TestPersist_FullConfig_FileRoundTrip(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Create a temp file for state
	tmpFile, err := os.CreateTemp("", "glitch-state-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Set non-default values
	flags := dashboard.GetFeatureFlags()
	flags.Set("analytics", false)
	flags.Set("cdn", false)
	flags.Set("oauth", false)

	cfg := dashboard.GetAdminConfig()
	cfg.Set("bot_score_threshold", 90)
	cfg.Set("cookie_trap_frequency", 15)
	cfg.SetString("honeypot_response_style", "aggressive")

	vc := dashboard.GetVulnConfig()
	vc.SetGroup("modern", false)
	vc.SetGroup("dashboard", false)

	// Export and write to file (exactly like TriggerAutoSave)
	exported := dashboard.ExportConfig()
	data, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Reset everything (simulates fresh startup)
	resetAll(t)

	// Read from file and import (exactly like LoadStateFile)
	data, err = os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var reimported dashboard.ConfigExport
	if err := json.Unmarshal(data, &reimported); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	dashboard.ImportConfig(&reimported)

	// Verify
	verifyFeatureFlag(t, mux, "analytics", false)
	verifyFeatureFlag(t, mux, "cdn", false)
	verifyFeatureFlag(t, mux, "oauth", false)
	verifyFeatureFlag(t, mux, "labyrinth", true) // untouched

	verifyConfigValue(t, mux, "bot_score_threshold", float64(90))
	verifyConfigValue(t, mux, "cookie_trap_frequency", float64(15))
	verifyConfigValue(t, mux, "honeypot_response_style", "aggressive")

	verifyVulnGroup(t, mux, "modern", false)
	verifyVulnGroup(t, mux, "dashboard", false)
	verifyVulnGroup(t, mux, "owasp", true) // untouched
}

// ---------------------------------------------------------------------------
// Category 7: Proxy config is NOT persisted
// ---------------------------------------------------------------------------

// TestPersist_ProxyConfig_NotInExport verifies proxy settings are not included
// in the config export — proxy is runtime-only state that resets on restart.
func TestPersist_ProxyConfig_NotInExport(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	// Change proxy settings
	pc := dashboard.GetProxyConfig()
	pc.SetMode("chaos")

	// Export should NOT contain proxy settings
	exported := dashboard.ExportConfig()
	data, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Proxy-related keys should not exist in the export
	proxyKeys := []string{"proxy", "proxy_config", "proxy_mode", "proxy_status"}
	for _, key := range proxyKeys {
		if _, exists := raw[key]; exists {
			t.Errorf("ConfigExport contains proxy key %q — proxy should NOT be persisted", key)
		}
	}

	// Reset proxy back to default
	pc.SetMode("transparent")
}

// TestPersist_ProxyConfig_ResetsOnRestart verifies that proxy config resets
// to defaults after export/import (simulating restart).
func TestPersist_ProxyConfig_ResetsOnRestart(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	pc := dashboard.GetProxyConfig()
	pc.SetMode("waf")

	if pc.GetMode() != "waf" {
		t.Fatalf("proxy mode should be 'waf', got %q", pc.GetMode())
	}

	// Export/import simulates a restart — proxy mode should NOT be restored
	exported := dashboard.ExportConfig()
	dashboard.ImportConfig(exported)

	// Proxy config is NOT part of export/import, so we verify it's unchanged
	// (still waf because import didn't touch it). In a real restart, the proxy
	// would be re-initialized to "transparent" by NewProxyConfig().
	// We verify NewProxyConfig gives "transparent".
	fresh := dashboard.NewProxyConfig()
	if fresh.GetMode() != "transparent" {
		t.Errorf("NewProxyConfig().GetMode() = %q, want 'transparent'", fresh.GetMode())
	}

	// Clean up
	pc.SetMode("transparent")
}

// ---------------------------------------------------------------------------
// Category 8: Scanner config is NOT persisted (runtime-only)
// ---------------------------------------------------------------------------

// TestPersist_ScannerConfig_NotInExport verifies scanner settings are not
// included in the config export.
func TestPersist_ScannerConfig_NotInExport(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	exported := dashboard.ExportConfig()
	data, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	scannerKeys := []string{"scanner", "scanner_config", "scan_profile", "scan_target"}
	for _, key := range scannerKeys {
		if _, exists := raw[key]; exists {
			t.Errorf("ConfigExport contains scanner key %q — scanner should NOT be persisted", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Category 9: ConfigExport structural integrity
// ---------------------------------------------------------------------------

// TestPersist_Export_HasAllSections verifies the config export contains all
// expected top-level sections.
func TestPersist_Export_HasAllSections(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	exported := dashboard.ExportConfig()

	if exported.Version == "" {
		t.Error("ConfigExport.Version is empty")
	}
	if exported.ExportedAt == "" {
		t.Error("ConfigExport.ExportedAt is empty")
	}
	if exported.Features == nil {
		t.Error("ConfigExport.Features is nil")
	}
	if exported.Config == nil {
		t.Error("ConfigExport.Config is nil")
	}
	if exported.VulnConfig == nil {
		t.Error("ConfigExport.VulnConfig is nil")
	}
	// ErrorWeights and PageTypeWeights may be empty maps but should exist
	if exported.ErrorWeights == nil {
		t.Error("ConfigExport.ErrorWeights is nil")
	}
	if exported.PageTypeWeights == nil {
		t.Error("ConfigExport.PageTypeWeights is nil")
	}
}

// TestPersist_Export_FeaturesComplete verifies all 22 feature flags are present.
func TestPersist_Export_FeaturesComplete(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	exported := dashboard.ExportConfig()

	expectedFlags := []string{
		"labyrinth", "error_inject", "captcha", "honeypot", "vuln",
		"analytics", "cdn", "oauth", "header_corrupt", "cookie_traps",
		"js_traps", "bot_detection", "random_blocking", "framework_emul",
		"search", "email", "i18n", "recorder", "websocket", "privacy",
		"health", "spider", "api_chaos", "media_chaos",
	}

	for _, flag := range expectedFlags {
		if _, ok := exported.Features[flag]; !ok {
			t.Errorf("ConfigExport.Features missing flag %q", flag)
		}
	}
}

// TestPersist_Export_ConfigComplete verifies all numeric and string config
// keys are present in the export.
func TestPersist_Export_ConfigComplete(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	exported := dashboard.ExportConfig()

	expectedNumeric := []string{
		"max_labyrinth_depth", "error_rate_multiplier", "captcha_trigger_thresh",
		"block_chance", "block_duration_sec", "bot_score_threshold",
		"header_corrupt_level", "delay_min_ms", "delay_max_ms",
		"labyrinth_link_density", "adaptive_interval_sec", "protocol_glitch_level",
		"cookie_trap_frequency", "js_trap_difficulty", "content_cache_ttl_sec",
		"adaptive_aggressive_rps", "adaptive_labyrinth_paths",
	}
	expectedStrings := []string{
		"honeypot_response_style", "active_framework", "content_theme", "recorder_format",
	}

	for _, key := range expectedNumeric {
		if _, ok := exported.Config[key]; !ok {
			t.Errorf("ConfigExport.Config missing numeric key %q", key)
		}
	}
	for _, key := range expectedStrings {
		if _, ok := exported.Config[key]; !ok {
			t.Errorf("ConfigExport.Config missing string key %q", key)
		}
	}
}

// TestPersist_Export_VulnConfigComplete verifies all vuln groups are present.
func TestPersist_Export_VulnConfigComplete(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	exported := dashboard.ExportConfig()

	groups, ok := exported.VulnConfig["groups"]
	if !ok {
		t.Fatal("VulnConfig missing 'groups' key")
	}
	gmap, ok := groups.(map[string]bool)
	if !ok {
		t.Fatalf("VulnConfig.groups has unexpected type %T", groups)
	}

	for _, g := range dashboard.VulnGroups {
		if _, ok := gmap[g]; !ok {
			t.Errorf("VulnConfig.groups missing group %q", g)
		}
	}
}

// ---------------------------------------------------------------------------
// Category 10: Idempotency — importing the same config twice is safe
// ---------------------------------------------------------------------------

// TestPersist_Import_Idempotent verifies that importing the same config
// multiple times produces identical results.
func TestPersist_Import_Idempotent(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	flags := dashboard.GetFeatureFlags()
	flags.Set("labyrinth", false)
	flags.Set("spider", false)
	cfg := dashboard.GetAdminConfig()
	cfg.Set("error_rate_multiplier", 2.5)
	cfg.SetString("content_theme", "corporate")

	exported := dashboard.ExportConfig()

	// Import twice
	dashboard.ImportConfig(exported)
	dashboard.ImportConfig(exported)

	// Should still match
	snap := flags.Snapshot()
	if snap["labyrinth"] != false {
		t.Error("labyrinth should be false after double import")
	}
	if snap["spider"] != false {
		t.Error("spider should be false after double import")
	}

	cfgMap := cfg.Get()
	if v, _ := toFloat64(cfgMap["error_rate_multiplier"]); v != 2.5 {
		t.Errorf("error_rate_multiplier = %v, want 2.5", v)
	}
	if cfgMap["content_theme"] != "corporate" {
		t.Errorf("content_theme = %v, want 'corporate'", cfgMap["content_theme"])
	}
}

// ---------------------------------------------------------------------------
// Category 11: Export via admin API round-trip
// ---------------------------------------------------------------------------

// TestPersist_AdminAPI_ExportImport verifies the /admin/api/config/export
// and /admin/api/config/import endpoints preserve all settings.
func TestPersist_AdminAPI_ExportImport(t *testing.T) {
	mux := setupTestEnv(t)
	resetAll(t)

	// Change settings
	flags := dashboard.GetFeatureFlags()
	flags.Set("email", false)
	flags.Set("search", false)
	cfg := dashboard.GetAdminConfig()
	cfg.Set("header_corrupt_level", 3)
	cfg.Set("delay_max_ms", 1000)
	cfg.SetString("active_framework", "spring")

	// Export via API
	exportResp := apiGet(t, mux, "/admin/api/config/export")

	// Verify the export response has expected structure
	if _, ok := exportResp["features"]; !ok {
		t.Fatal("Export API response missing 'features'")
	}
	if _, ok := exportResp["config"]; !ok {
		t.Fatal("Export API response missing 'config'")
	}

	// Reset all
	resetAll(t)

	// Import via API
	apiPost(t, mux, "/admin/api/config/import", exportResp)

	// Verify
	verifyFeatureFlag(t, mux, "email", false)
	verifyFeatureFlag(t, mux, "search", false)
	verifyFeatureFlag(t, mux, "labyrinth", true) // untouched
	verifyConfigValue(t, mux, "header_corrupt_level", float64(3))
	verifyConfigValue(t, mux, "delay_max_ms", float64(1000))
	verifyConfigValue(t, mux, "active_framework", "spring")
}

// ---------------------------------------------------------------------------
// Category 12: PostgreSQL persistence (skipped if DB unavailable)
// ---------------------------------------------------------------------------

// testDBStore creates a Store connected to the test database.
// Skips the test if PostgreSQL is not available.
func testDBStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := os.Getenv("GLITCH_TEST_DB_URL")
	if dsn == "" {
		dsn = os.Getenv("GLITCH_DB_URL")
	}
	if dsn == "" {
		dsn = storage.DefaultDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := storage.NewWithDSN(ctx, dsn)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	// Clean config_versions for test isolation
	_, _ = store.DB().ExecContext(ctx, "DELETE FROM config_versions")
	return store
}

// TestPersist_DB_FullConfig_RoundTrip verifies the full config survives
// a PostgreSQL save → load cycle (simulates DB-backed restart).
func TestPersist_DB_FullConfig_RoundTrip(t *testing.T) {
	store := testDBStore(t)
	defer store.Close()
	mux := setupTestEnv(t)
	resetAll(t)

	// Set non-default values
	flags := dashboard.GetFeatureFlags()
	flags.Set("labyrinth", false)
	flags.Set("honeypot", false)
	flags.Set("vuln", false)

	cfg := dashboard.GetAdminConfig()
	cfg.Set("error_rate_multiplier", 3.0)
	cfg.Set("max_labyrinth_depth", 80)
	cfg.SetString("content_theme", "corporate")

	vc := dashboard.GetVulnConfig()
	vc.SetGroup("owasp", false)

	cfg.ResetErrorWeights()
	cfg.SetErrorWeight("http_4xx", 0.7)
	cfg.SetErrorWeight("garbage_data", 0.3)

	cfg.ResetPageTypeWeights()
	cfg.SetPageTypeWeight("json", 0.5)
	cfg.SetPageTypeWeight("html", 0.5)

	// Export and save to DB
	exported := dashboard.ExportConfig()
	dbExport := &storage.FullConfigExport{
		Features:        exported.Features,
		Config:          exported.Config,
		VulnConfig:      exported.VulnConfig,
		ErrorWeights:    exported.ErrorWeights,
		PageTypeWeights: exported.PageTypeWeights,
	}
	ctx := context.Background()
	if err := store.SaveFullConfig(ctx, dbExport); err != nil {
		t.Fatalf("SaveFullConfig: %v", err)
	}

	// Reset all (simulates restart with fresh state)
	resetAll(t)

	// Load from DB (simulates LoadStateFile with DB)
	loaded, err := store.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadFullConfig returned nil")
	}

	// Import (simulates ImportConfig in LoadStateFile)
	dbImport := &dashboard.ConfigExport{
		Version:         "1.0",
		ExportedAt:      time.Now().UTC().Format(time.RFC3339),
		Features:        loaded.Features,
		Config:          loaded.Config,
		VulnConfig:      loaded.VulnConfig,
		ErrorWeights:    loaded.ErrorWeights,
		PageTypeWeights: loaded.PageTypeWeights,
	}
	dashboard.ImportConfig(dbImport)

	// Verify all settings restored
	verifyFeatureFlag(t, mux, "labyrinth", false)
	verifyFeatureFlag(t, mux, "honeypot", false)
	verifyFeatureFlag(t, mux, "vuln", false)
	verifyFeatureFlag(t, mux, "captcha", true) // untouched

	verifyConfigValue(t, mux, "error_rate_multiplier", 3.0)
	verifyConfigValue(t, mux, "max_labyrinth_depth", float64(80))
	verifyConfigValue(t, mux, "content_theme", "corporate")

	verifyVulnGroup(t, mux, "owasp", false)
	verifyVulnGroup(t, mux, "api_security", true) // untouched

	ew := cfg.GetErrorWeights()
	if ew["http_4xx"] != 0.7 {
		t.Errorf("DB-restored ErrorWeights[http_4xx] = %v, want 0.7", ew["http_4xx"])
	}
	if ew["garbage_data"] != 0.3 {
		t.Errorf("DB-restored ErrorWeights[garbage_data] = %v, want 0.3", ew["garbage_data"])
	}

	pw := cfg.GetPageTypeWeights()
	if pw["json"] != 0.5 {
		t.Errorf("DB-restored PageTypeWeights[json] = %v, want 0.5", pw["json"])
	}
	if pw["html"] != 0.5 {
		t.Errorf("DB-restored PageTypeWeights[html] = %v, want 0.5", pw["html"])
	}
}

// TestPersist_DB_ConfigVersioning verifies multiple config saves create
// distinct versions and the latest is always loaded.
func TestPersist_DB_ConfigVersioning(t *testing.T) {
	store := testDBStore(t)
	defer store.Close()
	ctx := context.Background()

	// Save 3 versions of feature flags
	for i := 1; i <= 3; i++ {
		data := map[string]bool{
			"labyrinth": i%2 == 0,
			"version":   true,
		}
		if err := store.SaveConfig(ctx, "test_feature_flags", data); err != nil {
			t.Fatalf("SaveConfig v%d: %v", i, err)
		}
	}

	// Version should be 3
	ver, err := store.ConfigVersion(ctx, "test_feature_flags")
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver != 3 {
		t.Errorf("ConfigVersion = %d, want 3", ver)
	}

	// Load latest — labyrinth should be true (3%2==1, so false... wait 3%2=1, not 0)
	// v1: labyrinth=false (1%2=1, not 0)
	// v2: labyrinth=true  (2%2=0)
	// v3: labyrinth=false (3%2=1, not 0)
	var latest map[string]bool
	found, err := store.LoadConfig(ctx, "test_feature_flags", &latest)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !found {
		t.Fatal("LoadConfig returned not found")
	}
	if latest["labyrinth"] != false {
		t.Errorf("latest labyrinth = %v, want false (v3)", latest["labyrinth"])
	}

	// Load specific version v2
	var v2 map[string]bool
	found, err = store.LoadConfigVersion(ctx, "test_feature_flags", 2, &v2)
	if err != nil {
		t.Fatalf("LoadConfigVersion: %v", err)
	}
	if !found {
		t.Fatal("LoadConfigVersion(2) returned not found")
	}
	if v2["labyrinth"] != true {
		t.Errorf("v2 labyrinth = %v, want true", v2["labyrinth"])
	}
}

// TestPersist_DB_MultipleUpdates verifies that saving multiple times and
// loading always gives the latest settings.
func TestPersist_DB_MultipleUpdates(t *testing.T) {
	store := testDBStore(t)
	defer store.Close()
	mux := setupTestEnv(t)
	ctx := context.Background()

	// First save: error_rate=1.0
	resetAll(t)
	cfg := dashboard.GetAdminConfig()
	cfg.Set("error_rate_multiplier", 1.0)
	exp1 := dashboard.ExportConfig()
	dbExp1 := &storage.FullConfigExport{
		Features:        exp1.Features,
		Config:          exp1.Config,
		VulnConfig:      exp1.VulnConfig,
		ErrorWeights:    exp1.ErrorWeights,
		PageTypeWeights: exp1.PageTypeWeights,
	}
	if err := store.SaveFullConfig(ctx, dbExp1); err != nil {
		t.Fatalf("SaveFullConfig(1): %v", err)
	}

	// Second save: error_rate=4.5
	cfg.Set("error_rate_multiplier", 4.5)
	exp2 := dashboard.ExportConfig()
	dbExp2 := &storage.FullConfigExport{
		Features:        exp2.Features,
		Config:          exp2.Config,
		VulnConfig:      exp2.VulnConfig,
		ErrorWeights:    exp2.ErrorWeights,
		PageTypeWeights: exp2.PageTypeWeights,
	}
	if err := store.SaveFullConfig(ctx, dbExp2); err != nil {
		t.Fatalf("SaveFullConfig(2): %v", err)
	}

	// Reset and load — should get the latest (4.5)
	resetAll(t)
	loaded, err := store.LoadFullConfig(ctx)
	if err != nil {
		t.Fatalf("LoadFullConfig: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadFullConfig returned nil")
	}

	dbImport := &dashboard.ConfigExport{
		Version:         "1.0",
		ExportedAt:      time.Now().UTC().Format(time.RFC3339),
		Features:        loaded.Features,
		Config:          loaded.Config,
		VulnConfig:      loaded.VulnConfig,
		ErrorWeights:    loaded.ErrorWeights,
		PageTypeWeights: loaded.PageTypeWeights,
	}
	dashboard.ImportConfig(dbImport)

	verifyConfigValue(t, mux, "error_rate_multiplier", 4.5)
}

// ---------------------------------------------------------------------------
// Category 13: Concurrent DB writes (race condition safety)
// ---------------------------------------------------------------------------

// TestPersist_DB_ConcurrentWrites verifies that concurrent SaveConfig calls
// all succeed with unique version numbers (no lost writes).
func TestPersist_DB_ConcurrentWrites(t *testing.T) {
	store := testDBStore(t)
	defer store.Close()
	ctx := context.Background()

	const entity = "concurrent_test"
	const writers = 10

	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(n int) {
			data := map[string]int{"writer": n}
			errs <- store.SaveConfig(ctx, entity, data)
		}(i)
	}

	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent write %d failed: %v", i, err)
		}
	}

	// All writes should have succeeded — version should be 10
	ver, err := store.ConfigVersion(ctx, entity)
	if err != nil {
		t.Fatalf("ConfigVersion: %v", err)
	}
	if ver != writers {
		t.Errorf("ConfigVersion = %d, want %d (lost writes!)", ver, writers)
	}

	// Verify all versions exist
	history, err := store.ListConfigHistory(ctx, entity, 20)
	if err != nil {
		t.Fatalf("ListConfigHistory: %v", err)
	}
	if len(history) != writers {
		t.Errorf("history entries = %d, want %d", len(history), writers)
	}
}

// ---------------------------------------------------------------------------
// Category 14: Spider config persistence through export/import
// ---------------------------------------------------------------------------

// TestPersist_SpiderConfig_NotDirectlyExported verifies spider config is
// separate from ConfigExport (spider has its own config management).
func TestPersist_SpiderConfig_NotDirectlyExported(t *testing.T) {
	_ = setupTestEnv(t)
	resetAll(t)

	// Spider config is managed separately from the main config export
	spiderCfg := dashboard.GetSpiderConfig()
	spiderCfg.Set("robots_crawl_delay", 10)
	spiderCfg.Set("sitemap_entry_count", 200)

	exported := dashboard.ExportConfig()
	data, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Spider-specific settings should NOT be in the main config export
	// (they're separate from AdminConfig)
	if cfg, ok := raw["config"].(map[string]interface{}); ok {
		spiderKeys := []string{"robots_crawl_delay", "sitemap_entry_count", "enable_sitemap_index"}
		for _, key := range spiderKeys {
			if _, exists := cfg[key]; exists {
				t.Errorf("ConfigExport.Config contains spider key %q — spider config is separate", key)
			}
		}
	}

	// Clean up
	resetSpiderConfig(t)
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

func init() {
	// Ensure we don't accidentally trigger auto-save to the real state file
	// during tests by not setting a state file path.
}
