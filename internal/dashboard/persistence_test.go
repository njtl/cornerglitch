package dashboard

import (
	"encoding/json"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/cornerglitch/internal/adaptive"
	"github.com/cornerglitch/internal/fingerprint"
	"github.com/cornerglitch/internal/metrics"
	"github.com/cornerglitch/internal/spider"
	"github.com/cornerglitch/internal/storage"
)

// ---------------------------------------------------------------------------
// Core: ExportConfig/ImportConfig round-trip with random values
// ---------------------------------------------------------------------------

// TestPersistence_FullRoundTrip randomizes ALL settings, exports them,
// resets globals to defaults, re-imports, and verifies every field.
// Repeated 3 times with different random seeds.
func TestPersistence_FullRoundTrip(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		t.Run("seed_"+itoa(int(seed)), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			resetGlobals()

			// --- Set random values on all global singletons ---
			expected := randomizeAll(rng)

			// --- Export ---
			export := ExportConfig()

			// --- Verify export captures everything ---
			verifyExport(t, export, expected)

			// --- Reset to defaults (simulates restart) ---
			resetGlobals()

			// --- Re-import (simulates restore on startup) ---
			ImportConfig(export)

			// --- Verify everything survived ---
			verifyGlobals(t, expected)
		})
	}
}

// TestPersistence_JSONRoundTrip tests that ExportConfig survives
// JSON marshal/unmarshal (the actual file/DB persistence path).
func TestPersistence_JSONRoundTrip(t *testing.T) {
	for seed := int64(10); seed <= 12; seed++ {
		t.Run("seed_"+itoa(int(seed)), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			resetGlobals()

			expected := randomizeAll(rng)
			export := ExportConfig()

			// Marshal to JSON (like file save)
			data, err := json.Marshal(export)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			// Unmarshal back (like file load)
			var restored ConfigExport
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Reset and import
			resetGlobals()
			ImportConfig(&restored)

			// Verify
			verifyGlobals(t, expected)
		})
	}
}

// ---------------------------------------------------------------------------
// Server settings: AdminConfig round-trip
// ---------------------------------------------------------------------------

func TestPersistence_AdminConfig(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	resetGlobals()

	// Set every numeric config field to a random value.
	vals := randomAdminConfig(rng)
	for k, v := range vals.numeric {
		globalConfig.Set(k, v)
	}
	for k, v := range vals.strings {
		globalConfig.SetString(k, v)
	}

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	got := globalConfig.Get()
	for k, want := range vals.numeric {
		gotV, ok := got[k]
		if !ok {
			t.Errorf("AdminConfig key %q missing after import", k)
			continue
		}
		// JSON round-trip converts int to float64.
		var gotF float64
		switch v := gotV.(type) {
		case float64:
			gotF = v
		case int:
			gotF = float64(v)
		case int64:
			gotF = float64(v)
		case bool:
			if v {
				gotF = 1
			}
		}
		if math.Abs(gotF-want) > 0.01 {
			t.Errorf("AdminConfig %q: got %v, want %v", k, gotV, want)
		}
	}
	for k, want := range vals.strings {
		gotV, ok := got[k]
		if !ok {
			t.Errorf("AdminConfig string key %q missing after import", k)
			continue
		}
		if gotS, ok := gotV.(string); !ok || gotS != want {
			t.Errorf("AdminConfig %q: got %v, want %q", k, gotV, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Error weights round-trip
// ---------------------------------------------------------------------------

func TestPersistence_ErrorWeights(t *testing.T) {
	resetGlobals()

	weights := map[string]float64{
		"slow_drip":     0.15,
		"timeout":       0.25,
		"connection_reset": 0.10,
		"malformed":     0.50,
	}
	for k, v := range weights {
		globalConfig.SetErrorWeight(k, v)
	}

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	got := globalConfig.GetErrorWeights()
	for k, want := range weights {
		if gotV, ok := got[k]; !ok {
			t.Errorf("error weight %q missing after import", k)
		} else if math.Abs(gotV-want) > 0.001 {
			t.Errorf("error weight %q: got %f, want %f", k, gotV, want)
		}
	}
}

func TestPersistence_ErrorWeights_EmptyKeyFiltered(t *testing.T) {
	resetGlobals()

	// Simulate the empty-key bug.
	globalConfig.mu.Lock()
	globalConfig.ErrorWeights[""] = 0
	globalConfig.ErrorWeights["valid_key"] = 0.5
	globalConfig.mu.Unlock()

	got := globalConfig.GetErrorWeights()
	if _, ok := got[""]; ok {
		t.Error("GetErrorWeights() should filter empty keys")
	}
	if got["valid_key"] != 0.5 {
		t.Errorf("valid_key: got %f, want 0.5", got["valid_key"])
	}
}

func TestPersistence_SetErrorWeight_RejectsEmptyKey(t *testing.T) {
	resetGlobals()
	globalConfig.SetErrorWeight("", 0.5)
	got := globalConfig.GetErrorWeights()
	if _, ok := got[""]; ok {
		t.Error("SetErrorWeight should reject empty key")
	}
}

// ---------------------------------------------------------------------------
// Page type weights round-trip
// ---------------------------------------------------------------------------

func TestPersistence_PageTypeWeights(t *testing.T) {
	resetGlobals()

	weights := map[string]float64{
		"html":  0.40,
		"json":  0.30,
		"xml":   0.15,
		"csv":   0.15,
	}
	for k, v := range weights {
		globalConfig.SetPageTypeWeight(k, v)
	}

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	got := globalConfig.GetPageTypeWeights()
	for k, want := range weights {
		if gotV, ok := got[k]; !ok {
			t.Errorf("page type weight %q missing after import", k)
		} else if math.Abs(gotV-want) > 0.001 {
			t.Errorf("page type weight %q: got %f, want %f", k, gotV, want)
		}
	}
}

func TestPersistence_SetPageTypeWeight_RejectsEmptyKey(t *testing.T) {
	resetGlobals()
	globalConfig.SetPageTypeWeight("", 0.5)
	got := globalConfig.GetPageTypeWeights()
	if len(got) != 0 {
		t.Errorf("SetPageTypeWeight should reject empty key, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Feature flags round-trip
// ---------------------------------------------------------------------------

func TestPersistence_FeatureFlags(t *testing.T) {
	resetGlobals()

	// Disable half the flags randomly.
	rng := rand.New(rand.NewSource(99))
	expected := make(map[string]bool)
	snap := globalFlags.Snapshot()
	for name := range snap {
		val := rng.Intn(2) == 0
		globalFlags.Set(name, val)
		expected[name] = val
	}

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	got := globalFlags.Snapshot()
	for name, want := range expected {
		if got[name] != want {
			t.Errorf("feature flag %q: got %v, want %v", name, got[name], want)
		}
	}
}

// ---------------------------------------------------------------------------
// Vuln config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_VulnConfig(t *testing.T) {
	resetGlobals()

	// Disable some groups.
	globalVulnConfig.SetGroup("owasp", false)
	globalVulnConfig.SetGroup("api_security", false)

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	if globalVulnConfig.IsGroupEnabled("owasp") {
		t.Error("owasp group should be disabled after import")
	}
	if globalVulnConfig.IsGroupEnabled("api_security") {
		t.Error("api_security group should be disabled after import")
	}
	if !globalVulnConfig.IsGroupEnabled("advanced") {
		t.Error("advanced group should still be enabled after import")
	}
}

// ---------------------------------------------------------------------------
// API chaos config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_APIChaosConfig(t *testing.T) {
	resetGlobals()

	globalAPIChaosConfig.SetCategory("auth_chaos", false)
	globalAPIChaosConfig.SetCategory("rate_limit_chaos", true)

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	snap := globalAPIChaosConfig.Snapshot()
	if snap["auth_chaos"] != false {
		t.Error("auth_chaos should be false after import")
	}
	if snap["rate_limit_chaos"] != true {
		t.Error("rate_limit_chaos should be true after import")
	}
}

// ---------------------------------------------------------------------------
// Media chaos config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_MediaChaosConfig(t *testing.T) {
	resetGlobals()

	globalMediaChaosConfig.SetCategory("format_corruption", false)
	globalMediaChaosConfig.SetCategory("slow_delivery", false)

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	snap := globalMediaChaosConfig.Snapshot()
	if snap["format_corruption"] != false {
		t.Error("format_corruption should be false after import")
	}
	if snap["slow_delivery"] != false {
		t.Error("slow_delivery should be false after import")
	}
	if snap["cache_poisoning"] != true {
		t.Error("cache_poisoning should still be true after import")
	}
}

// ---------------------------------------------------------------------------
// Proxy config round-trip (NEW — previously not persisted)
// ---------------------------------------------------------------------------

func TestPersistence_ProxyConfig(t *testing.T) {
	resetGlobals()

	globalProxyConfig.mu.Lock()
	globalProxyConfig.Mode = "waf"
	globalProxyConfig.WAFEnabled = true
	globalProxyConfig.WAFBlockAction = "challenge"
	globalProxyConfig.LatencyProb = 0.15
	globalProxyConfig.CorruptProb = 0.25
	globalProxyConfig.DropProb = 0.05
	globalProxyConfig.ResetProb = 0.10
	globalProxyConfig.mu.Unlock()

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	if globalProxyConfig.GetMode() != "waf" {
		t.Errorf("proxy mode: got %q, want %q", globalProxyConfig.GetMode(), "waf")
	}

	globalProxyConfig.mu.RLock()
	defer globalProxyConfig.mu.RUnlock()
	if !globalProxyConfig.WAFEnabled {
		t.Error("WAFEnabled should be true after import")
	}
	if globalProxyConfig.WAFBlockAction != "challenge" {
		t.Errorf("WAFBlockAction: got %q, want %q", globalProxyConfig.WAFBlockAction, "challenge")
	}
	if math.Abs(globalProxyConfig.LatencyProb-0.15) > 0.001 {
		t.Errorf("LatencyProb: got %f, want 0.15", globalProxyConfig.LatencyProb)
	}
	if math.Abs(globalProxyConfig.CorruptProb-0.25) > 0.001 {
		t.Errorf("CorruptProb: got %f, want 0.25", globalProxyConfig.CorruptProb)
	}
	if math.Abs(globalProxyConfig.DropProb-0.05) > 0.001 {
		t.Errorf("DropProb: got %f, want 0.05", globalProxyConfig.DropProb)
	}
	if math.Abs(globalProxyConfig.ResetProb-0.10) > 0.001 {
		t.Errorf("ResetProb: got %f, want 0.10", globalProxyConfig.ResetProb)
	}
}

func TestPersistence_ProxyConfig_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	globalProxyConfig.mu.Lock()
	globalProxyConfig.Mode = "chaos"
	globalProxyConfig.WAFEnabled = false
	globalProxyConfig.WAFBlockAction = "reject"
	globalProxyConfig.LatencyProb = 0.33
	globalProxyConfig.CorruptProb = 0.44
	globalProxyConfig.DropProb = 0.11
	globalProxyConfig.ResetProb = 0.22
	globalProxyConfig.mu.Unlock()

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	if globalProxyConfig.GetMode() != "chaos" {
		t.Errorf("proxy mode: got %q, want %q", globalProxyConfig.GetMode(), "chaos")
	}
	globalProxyConfig.mu.RLock()
	defer globalProxyConfig.mu.RUnlock()
	if math.Abs(globalProxyConfig.LatencyProb-0.33) > 0.001 {
		t.Errorf("LatencyProb: got %f, want 0.33", globalProxyConfig.LatencyProb)
	}
	if math.Abs(globalProxyConfig.CorruptProb-0.44) > 0.001 {
		t.Errorf("CorruptProb: got %f, want 0.44", globalProxyConfig.CorruptProb)
	}
}

func TestPersistence_ProxyConfig_AllModes(t *testing.T) {
	for _, mode := range ProxyModes {
		t.Run(mode, func(t *testing.T) {
			resetGlobals()
			// Set mode directly (avoid mirror snapshot which reads globalConfig).
			globalProxyConfig.mu.Lock()
			globalProxyConfig.Mode = mode
			globalProxyConfig.mu.Unlock()

			export := ExportConfig()
			data, _ := json.Marshal(export)
			var restored ConfigExport
			json.Unmarshal(data, &restored)

			resetGlobals()
			ImportConfig(&restored)

			if globalProxyConfig.GetMode() != mode {
				t.Errorf("mode: got %q, want %q", globalProxyConfig.GetMode(), mode)
			}
		})
	}
}

func TestPersistence_ProxyConfig_InvalidModeIgnored(t *testing.T) {
	resetGlobals()
	globalProxyConfig.Restore(map[string]interface{}{
		"mode": "invalid_mode_xyz",
	})
	if globalProxyConfig.GetMode() != "transparent" {
		t.Errorf("invalid mode should be ignored, got %q", globalProxyConfig.GetMode())
	}
}

// ---------------------------------------------------------------------------
// ProxyConfig.SnapshotForExport / Restore unit tests
// ---------------------------------------------------------------------------

func TestProxyConfig_SnapshotForExport(t *testing.T) {
	pc := NewProxyConfig()
	pc.mu.Lock()
	pc.Mode = "gateway"
	pc.WAFEnabled = true
	pc.WAFBlockAction = "block"
	pc.LatencyProb = 0.5
	pc.CorruptProb = 0.3
	pc.DropProb = 0.1
	pc.ResetProb = 0.2
	pc.mu.Unlock()

	snap := pc.SnapshotForExport()
	if snap["mode"] != "gateway" {
		t.Errorf("mode: got %v", snap["mode"])
	}
	if snap["waf_enabled"] != true {
		t.Error("waf_enabled should be true")
	}
	if snap["latency_prob"] != 0.5 {
		t.Errorf("latency_prob: got %v", snap["latency_prob"])
	}
}

func TestProxyConfig_Restore(t *testing.T) {
	pc := NewProxyConfig()
	pc.Restore(map[string]interface{}{
		"mode":             "nightmare",
		"waf_enabled":      true,
		"waf_block_action": "tarpit",
		"latency_prob":     0.7,
		"corrupt_prob":     0.5,
		"drop_prob":        0.3,
		"reset_prob":       0.1,
	})
	if pc.GetMode() != "nightmare" {
		t.Errorf("mode: got %q", pc.GetMode())
	}
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	if !pc.WAFEnabled {
		t.Error("WAFEnabled should be true")
	}
	if pc.WAFBlockAction != "tarpit" {
		t.Errorf("WAFBlockAction: got %q", pc.WAFBlockAction)
	}
	if pc.LatencyProb != 0.7 {
		t.Errorf("LatencyProb: got %f", pc.LatencyProb)
	}
}

func TestProxyConfig_Restore_WithMirror(t *testing.T) {
	pc := NewProxyConfig()
	pc.Restore(map[string]interface{}{
		"mode": "mirror",
		"mirror": map[string]interface{}{
			"error_rate_multiplier":   2.5,
			"header_corrupt_level":    float64(3),
			"protocol_glitch_enabled": true,
			"protocol_glitch_level":   float64(4),
			"delay_min_ms":            float64(100),
			"delay_max_ms":            float64(5000),
			"content_theme":           "dark",
			"snapshot_time":           "2026-03-03T10:00:00Z",
			"error_weights": map[string]interface{}{
				"slow_drip": 0.5,
			},
			"page_type_weights": map[string]interface{}{
				"html": 0.9,
			},
		},
	})
	if pc.GetMode() != "mirror" {
		t.Errorf("mode: got %q", pc.GetMode())
	}
	m := pc.GetMirror()
	if m == nil {
		t.Fatal("mirror should not be nil")
	}
	if m.ErrorRateMultiplier != 2.5 {
		t.Errorf("mirror.ErrorRateMultiplier: got %f", m.ErrorRateMultiplier)
	}
	if m.HeaderCorruptLevel != 3 {
		t.Errorf("mirror.HeaderCorruptLevel: got %d", m.HeaderCorruptLevel)
	}
	if !m.ProtocolGlitchEnabled {
		t.Error("mirror.ProtocolGlitchEnabled should be true")
	}
	if m.DelayMinMs != 100 {
		t.Errorf("mirror.DelayMinMs: got %d", m.DelayMinMs)
	}
	if m.ContentTheme != "dark" {
		t.Errorf("mirror.ContentTheme: got %q", m.ContentTheme)
	}
	if len(m.ErrorWeights) != 1 || m.ErrorWeights["slow_drip"] != 0.5 {
		t.Errorf("mirror.ErrorWeights: got %v", m.ErrorWeights)
	}
	if len(m.PageTypeWeights) != 1 || m.PageTypeWeights["html"] != 0.9 {
		t.Errorf("mirror.PageTypeWeights: got %v", m.PageTypeWeights)
	}
}

// ---------------------------------------------------------------------------
// Blocking config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_BlockingConfig(t *testing.T) {
	resetGlobals()

	globalAdaptive.SetBlockEnabled(true)
	globalAdaptive.SetBlockChance(0.75)
	globalAdaptive.SetBlockDuration(120 * time.Second)

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	chance, duration, enabled := globalAdaptive.GetBlockConfig()
	if !enabled {
		t.Error("blocking should be enabled after import")
	}
	if math.Abs(chance-0.75) > 0.001 {
		t.Errorf("block chance: got %f, want 0.75", chance)
	}
	if int(duration.Seconds()) != 120 {
		t.Errorf("block duration: got %v, want 120s", duration)
	}
}

func TestPersistence_BlockingConfig_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	globalAdaptive.SetBlockEnabled(false)
	globalAdaptive.SetBlockChance(0.33)
	globalAdaptive.SetBlockDuration(60 * time.Second)

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	chance, duration, enabled := globalAdaptive.GetBlockConfig()
	if enabled {
		t.Error("blocking should be disabled after JSON import")
	}
	if math.Abs(chance-0.33) > 0.001 {
		t.Errorf("block chance: got %f, want 0.33", chance)
	}
	if int(duration.Seconds()) != 60 {
		t.Errorf("block duration: got %v, want 60s", duration)
	}
}

func TestPersistence_BlockingConfig_PendingMechanism(t *testing.T) {
	// Test the pending blocking config mechanism:
	// If ImportConfig is called before SetAdaptive, the blocking config
	// should be stored as pending and applied when SetAdaptive is called.
	globalFlags = NewFeatureFlags()
	globalConfig = NewAdminConfig()
	globalVulnConfig = NewVulnConfig()
	globalAPIChaosConfig = NewAPIChaosConfig()
	globalMediaChaosConfig = NewMediaChaosConfig()
	globalProxyConfig = NewProxyConfig()
	globalAdaptive = nil // no adaptive engine yet

	export := &ConfigExport{
		Blocking: map[string]interface{}{
			"enabled":      true,
			"chance":       0.88,
			"duration_sec": float64(200),
		},
	}
	ImportConfig(export)

	// Now create the adaptive engine — pending config should be applied.
	col := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	a := adaptive.NewEngine(col, fp)
	SetAdaptive(a)

	chance, duration, enabled := globalAdaptive.GetBlockConfig()
	if !enabled {
		t.Error("blocking should be enabled after pending sync")
	}
	if math.Abs(chance-0.88) > 0.001 {
		t.Errorf("block chance: got %f, want 0.88", chance)
	}
	if int(duration.Seconds()) != 200 {
		t.Errorf("block duration: got %v, want 200s", duration)
	}
}

// ---------------------------------------------------------------------------
// Scanner config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_ScannerConfig(t *testing.T) {
	resetGlobals()

	builtinMu.Lock()
	builtinProfile = "aggressive"
	builtinTarget = "http://example.com:9090"
	builtinModules = []string{"owasp", "injection", "auth"}
	builtinState = "completed"
	builtinMu.Unlock()

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	builtinMu.RLock()
	defer builtinMu.RUnlock()
	if builtinProfile != "aggressive" {
		t.Errorf("scanner profile: got %q, want %q", builtinProfile, "aggressive")
	}
	if builtinTarget != "http://example.com:9090" {
		t.Errorf("scanner target: got %q, want %q", builtinTarget, "http://example.com:9090")
	}
	if len(builtinModules) != 3 || builtinModules[0] != "owasp" || builtinModules[1] != "injection" || builtinModules[2] != "auth" {
		t.Errorf("scanner modules: got %v, want [owasp injection auth]", builtinModules)
	}
	if builtinState != "completed" {
		t.Errorf("scanner state: got %q, want %q", builtinState, "completed")
	}
}

func TestPersistence_ScannerConfig_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	builtinMu.Lock()
	builtinProfile = "stealth"
	builtinTarget = "http://target:8765"
	builtinModules = []string{"fuzzing", "protocol"}
	builtinMu.Unlock()

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	builtinMu.RLock()
	defer builtinMu.RUnlock()
	if builtinProfile != "stealth" {
		t.Errorf("scanner profile: got %q, want %q", builtinProfile, "stealth")
	}
	if builtinTarget != "http://target:8765" {
		t.Errorf("scanner target: got %q, want %q", builtinTarget, "http://target:8765")
	}
	if len(builtinModules) != 2 || builtinModules[0] != "fuzzing" || builtinModules[1] != "protocol" {
		t.Errorf("scanner modules: got %v, want [fuzzing protocol]", builtinModules)
	}
}

func TestPersistence_ScannerConfig_ErrorState(t *testing.T) {
	resetGlobals()

	builtinMu.Lock()
	builtinProfile = "nightmare"
	builtinTarget = "http://localhost:8765"
	builtinState = "error"
	builtinError = "connection refused"
	builtinMu.Unlock()

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	builtinMu.RLock()
	defer builtinMu.RUnlock()
	if builtinState != "error" {
		t.Errorf("scanner state: got %q, want %q", builtinState, "error")
	}
	if builtinError != "connection refused" {
		t.Errorf("scanner error: got %q, want %q", builtinError, "connection refused")
	}
}

func TestPersistence_ScannerConfig_IdleStateNotPersisted(t *testing.T) {
	resetGlobals()

	// When state is "idle" or "running", it should NOT be persisted.
	builtinMu.Lock()
	builtinProfile = "default"
	builtinTarget = "http://localhost:8765"
	builtinState = "idle"
	builtinMu.Unlock()

	export := ExportConfig()
	if export.ScannerConfig == nil {
		t.Fatal("ScannerConfig should not be nil when profile/target are set")
	}
	if _, ok := export.ScannerConfig["last_state"]; ok {
		t.Error("idle state should NOT be exported")
	}
}

func TestPersistence_ScannerConfig_Empty(t *testing.T) {
	resetGlobals()

	// No scanner config set — export should have nil ScannerConfig.
	export := ExportConfig()
	if export.ScannerConfig != nil {
		t.Errorf("expected nil ScannerConfig when no scanner settings, got %v", export.ScannerConfig)
	}

	// Import with nil scanner config should not error.
	resetGlobals()
	ImportConfig(export)

	builtinMu.RLock()
	defer builtinMu.RUnlock()
	if builtinProfile != "" {
		t.Errorf("scanner profile should be empty, got %q", builtinProfile)
	}
}

// ---------------------------------------------------------------------------
// History ID uniqueness
// ---------------------------------------------------------------------------

func TestGenerateHistoryID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := generateHistoryID()
		if id == "" {
			t.Fatal("generateHistoryID returned empty string")
		}
		if ids[id] {
			t.Fatalf("duplicate ID after %d iterations: %s", i, id)
		}
		ids[id] = true
	}
}

// ---------------------------------------------------------------------------
// Nightmare config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_NightmareConfig(t *testing.T) {
	resetGlobals()

	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = true
	globalNightmare.ScannerActive = false
	globalNightmare.ProxyActive = true
	globalNightmare.PreviousProxyMode = "waf"
	globalNightmare.PreviousConfig = map[string]interface{}{
		"error_rate_multiplier": 1.5,
		"max_labyrinth_depth":   float64(10),
	}
	globalNightmare.PreviousFeatures = map[string]bool{
		"labyrinth": true,
		"honeypot":  false,
		"vuln":      true,
	}
	globalNightmare.mu.Unlock()

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	globalNightmare.mu.RLock()
	defer globalNightmare.mu.RUnlock()
	if !globalNightmare.ServerActive {
		t.Error("nightmare server should be active after import")
	}
	if globalNightmare.ScannerActive {
		t.Error("nightmare scanner should NOT be active after import")
	}
	if !globalNightmare.ProxyActive {
		t.Error("nightmare proxy should be active after import")
	}
	if globalNightmare.PreviousProxyMode != "waf" {
		t.Errorf("nightmare previous_proxy_mode: got %q, want %q", globalNightmare.PreviousProxyMode, "waf")
	}
	if globalNightmare.PreviousFeatures == nil {
		t.Fatal("nightmare PreviousFeatures should not be nil")
	}
	if globalNightmare.PreviousFeatures["labyrinth"] != true {
		t.Error("nightmare PreviousFeatures[labyrinth] should be true")
	}
	if globalNightmare.PreviousFeatures["honeypot"] != false {
		t.Error("nightmare PreviousFeatures[honeypot] should be false")
	}
}

func TestPersistence_NightmareConfig_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = true
	globalNightmare.ProxyActive = true
	globalNightmare.PreviousProxyMode = "chaos"
	globalNightmare.PreviousFeatures = map[string]bool{
		"vuln":    true,
		"captcha": false,
	}
	globalNightmare.mu.Unlock()

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	globalNightmare.mu.RLock()
	defer globalNightmare.mu.RUnlock()
	if !globalNightmare.ServerActive {
		t.Error("nightmare server should be active after JSON import")
	}
	if !globalNightmare.ProxyActive {
		t.Error("nightmare proxy should be active after JSON import")
	}
	if globalNightmare.PreviousProxyMode != "chaos" {
		t.Errorf("nightmare previous_proxy_mode: got %q, want %q", globalNightmare.PreviousProxyMode, "chaos")
	}
	// After JSON round-trip, PreviousFeatures comes back as map[string]interface{}
	// and importNightmareConfig should convert it to map[string]bool.
	if globalNightmare.PreviousFeatures == nil {
		t.Fatal("nightmare PreviousFeatures should not be nil after JSON round-trip")
	}
	if globalNightmare.PreviousFeatures["vuln"] != true {
		t.Error("nightmare PreviousFeatures[vuln] should be true after JSON round-trip")
	}
}

func TestPersistence_NightmareConfig_Inactive(t *testing.T) {
	resetGlobals()
	// No nightmare active — should export nil
	export := ExportConfig()
	if export.NightmareConfig != nil {
		t.Errorf("NightmareConfig should be nil when no nightmare is active, got %v", export.NightmareConfig)
	}
}

// ---------------------------------------------------------------------------
// Spider config round-trip
// ---------------------------------------------------------------------------

func TestPersistence_SpiderConfig(t *testing.T) {
	resetGlobals()

	globalSpiderConfig.Set("sitemap_error_rate", 0.5)
	globalSpiderConfig.Set("sitemap_entry_count", 200)
	globalSpiderConfig.Set("robots_crawl_delay", 5)
	globalSpiderConfig.Set("robots_disallow_paths", []string{"/secret/", "/hidden/"})
	globalSpiderConfig.Set("enable_sitemap_index", false)
	globalSpiderConfig.Set("enable_gzip_sitemap", false)

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	snap := globalSpiderConfig.Snapshot()
	if v := snap["sitemap_entry_count"].(int); v != 200 {
		t.Errorf("spider sitemap_entry_count: got %v, want 200", v)
	}
	if v := snap["robots_crawl_delay"].(int); v != 5 {
		t.Errorf("spider robots_crawl_delay: got %v, want 5", v)
	}
	if v := snap["enable_sitemap_index"].(bool); v != false {
		t.Error("spider enable_sitemap_index should be false after import")
	}
	if paths := snap["robots_disallow_paths"].([]string); len(paths) != 2 || paths[0] != "/secret/" {
		t.Errorf("spider robots_disallow_paths: got %v", paths)
	}
}

func TestPersistence_SpiderConfig_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	globalSpiderConfig.Set("sitemap_entry_count", 300)
	globalSpiderConfig.Set("robots_crawl_delay", 8)
	globalSpiderConfig.Set("robots_disallow_paths", []string{"/api/", "/debug/"})

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	snap := globalSpiderConfig.Snapshot()
	// After JSON round-trip, int fields come back as float64 — importSpiderConfig handles coercion.
	if v := snap["sitemap_entry_count"].(int); v != 300 {
		t.Errorf("spider sitemap_entry_count after JSON: got %v, want 300", v)
	}
	if v := snap["robots_crawl_delay"].(int); v != 8 {
		t.Errorf("spider robots_crawl_delay after JSON: got %v, want 8", v)
	}
	// []string comes back as []interface{} from JSON — importSpiderConfig handles conversion.
	if paths := snap["robots_disallow_paths"].([]string); len(paths) != 2 || paths[0] != "/api/" {
		t.Errorf("spider robots_disallow_paths after JSON: got %v", paths)
	}
}

// ---------------------------------------------------------------------------
// Per-client overrides round-trip
// ---------------------------------------------------------------------------

func TestPersistence_Overrides(t *testing.T) {
	resetGlobals()

	globalAdaptive.SetOverride("client_abc", adaptive.BehaviorMode("aggressive"))
	globalAdaptive.SetOverride("client_xyz", adaptive.BehaviorMode("blocked"))

	export := ExportConfig()
	resetGlobals()
	ImportConfig(export)

	overrides := globalAdaptive.GetOverrides()
	if string(overrides["client_abc"]) != "aggressive" {
		t.Errorf("override client_abc: got %v, want %q", overrides["client_abc"], "aggressive")
	}
	if string(overrides["client_xyz"]) != "blocked" {
		t.Errorf("override client_xyz: got %v, want %q", overrides["client_xyz"], "blocked")
	}
}

func TestPersistence_Overrides_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	globalAdaptive.SetOverride("scanner_1", adaptive.BehaviorMode("labyrinth"))
	globalAdaptive.SetOverride("bot_2", adaptive.BehaviorMode("cooperative"))

	export := ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	resetGlobals()
	ImportConfig(&restored)

	overrides := globalAdaptive.GetOverrides()
	if string(overrides["scanner_1"]) != "labyrinth" {
		t.Errorf("override scanner_1: got %v, want %q", overrides["scanner_1"], "labyrinth")
	}
	if string(overrides["bot_2"]) != "cooperative" {
		t.Errorf("override bot_2: got %v, want %q", overrides["bot_2"], "cooperative")
	}
}

func TestPersistence_Overrides_PendingMechanism(t *testing.T) {
	// Test the pending overrides mechanism:
	// If ImportConfig is called before SetAdaptive, overrides should be stored
	// as pending and applied when SetAdaptive is called.
	globalFlags = NewFeatureFlags()
	globalConfig = NewAdminConfig()
	globalVulnConfig = NewVulnConfig()
	globalAPIChaosConfig = NewAPIChaosConfig()
	globalMediaChaosConfig = NewMediaChaosConfig()
	globalProxyConfig = NewProxyConfig()
	globalSpiderConfig = spider.NewConfig()
	globalNightmare = &NightmareState{}
	globalAdaptive = nil // no adaptive engine yet

	pendingBlockingMu.Lock()
	pendingBlocking = nil
	pendingOverrides = nil
	pendingBlockingMu.Unlock()

	export := &ConfigExport{
		Overrides: map[string]string{
			"client_a": "aggressive",
			"client_b": "blocked",
		},
	}
	ImportConfig(export)

	// Now create the adaptive engine — pending overrides should be applied.
	col := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	a := adaptive.NewEngine(col, fp)
	SetAdaptive(a)

	overrides := globalAdaptive.GetOverrides()
	if string(overrides["client_a"]) != "aggressive" {
		t.Errorf("override client_a: got %v, want %q", overrides["client_a"], "aggressive")
	}
	if string(overrides["client_b"]) != "blocked" {
		t.Errorf("override client_b: got %v, want %q", overrides["client_b"], "blocked")
	}
}

func TestPersistence_Overrides_Empty(t *testing.T) {
	resetGlobals()
	// No overrides set — should export nil
	export := ExportConfig()
	if export.Overrides != nil {
		t.Errorf("Overrides should be nil when no overrides are set, got %v", export.Overrides)
	}
}

// ---------------------------------------------------------------------------
// Client profile snapshot round-trip (via metrics)
// ---------------------------------------------------------------------------

func TestPersistence_ClientProfileSnapshot(t *testing.T) {
	col := metrics.NewCollector()

	// Create a snapshot and restore it
	snap := metrics.ClientProfileSnapshot{
		ClientID:        "test_client_1",
		FirstSeen:       time.Now().Add(-time.Hour),
		LastSeen:        time.Now(),
		TotalRequests:   500,
		RequestsPerSec:  10.5,
		PathsVisited:    map[string]int{"/api/users": 50, "/health": 100},
		StatusCodes:     map[int]int{200: 400, 404: 50, 500: 50},
		ErrorsReceived:  100,
		LabyrinthDepth:  5,
		UserAgents:      map[string]int{"Mozilla/5.0": 300, "curl/7.0": 200},
		BurstWindows:    3,
		AdaptiveProfile: "aggressive",
	}

	col.RestoreClientProfile(snap)

	// Retrieve and verify
	cp := col.GetClientProfile("test_client_1")
	if cp == nil {
		t.Fatal("client profile should exist after restore")
	}
	restored := cp.Snapshot()
	if restored.ClientID != "test_client_1" {
		t.Errorf("ClientID: got %q, want %q", restored.ClientID, "test_client_1")
	}
	if restored.TotalRequests != 500 {
		t.Errorf("TotalRequests: got %d, want 500", restored.TotalRequests)
	}
	if restored.AdaptiveProfile != "aggressive" {
		t.Errorf("AdaptiveProfile: got %q, want %q", restored.AdaptiveProfile, "aggressive")
	}
	if restored.PathsVisited["/api/users"] != 50 {
		t.Errorf("PathsVisited[/api/users]: got %d, want 50", restored.PathsVisited["/api/users"])
	}
	if restored.StatusCodes[200] != 400 {
		t.Errorf("StatusCodes[200]: got %d, want 400", restored.StatusCodes[200])
	}
}

func TestPersistence_ClientProfileSnapshot_JSONRoundTrip(t *testing.T) {
	snap := metrics.ClientProfileSnapshot{
		ClientID:        "json_client",
		TotalRequests:   1000,
		PathsVisited:    map[string]int{"/": 500},
		StatusCodes:     map[int]int{200: 900, 503: 100},
		AdaptiveProfile: "normal",
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var restored metrics.ClientProfileSnapshot
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if restored.ClientID != "json_client" {
		t.Errorf("ClientID: got %q, want %q", restored.ClientID, "json_client")
	}
	if restored.TotalRequests != 1000 {
		t.Errorf("TotalRequests: got %d, want 1000", restored.TotalRequests)
	}
	if restored.StatusCodes[200] != 900 {
		t.Errorf("StatusCodes[200]: got %d, want 900", restored.StatusCodes[200])
	}

	// Now restore into collector and verify
	col := metrics.NewCollector()
	col.RestoreClientProfile(restored)
	cp := col.GetClientProfile("json_client")
	if cp == nil {
		t.Fatal("client profile should exist after JSON round-trip restore")
	}
	s := cp.Snapshot()
	if s.TotalRequests != 1000 {
		t.Errorf("TotalRequests after restore: got %d, want 1000", s.TotalRequests)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func itoa(n int) string {
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// resetGlobals resets all global singletons to fresh defaults.
func resetGlobals() {
	globalFlags = NewFeatureFlags()
	globalConfig = NewAdminConfig()
	globalVulnConfig = NewVulnConfig()
	globalAPIChaosConfig = NewAPIChaosConfig()
	globalMediaChaosConfig = NewMediaChaosConfig()
	globalProxyConfig = NewProxyConfig()
	globalSpiderConfig = spider.NewConfig()
	globalNightmare = &NightmareState{}

	// Create a fresh adaptive engine so blocking config can round-trip.
	col := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	a := adaptive.NewEngine(col, fp)
	SetAdaptive(a)

	// Clear pending state.
	pendingBlockingMu.Lock()
	pendingBlocking = nil
	pendingOverrides = nil
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	// Reset scanner defaults.
	builtinMu.Lock()
	builtinProfile = ""
	builtinTarget = ""
	builtinModules = nil
	builtinState = "idle"
	builtinError = ""
	builtinMu.Unlock()
}

type expectedState struct {
	features         map[string]bool
	config           map[string]interface{} // numeric + string values
	errorWeights     map[string]float64
	pageTypeWeights  map[string]float64
	vulnGroups       map[string]bool
	apiChaosCats     map[string]bool
	mediaChaosCats   map[string]bool
	proxyMode        string
	proxyWAFEnabled  bool
	proxyWAFAction   string
	proxyLatencyProb float64
	proxyCorruptProb float64
	proxyDropProb    float64
	proxyResetProb   float64
	blockEnabled     bool
	blockChance      float64
	blockDurationSec int
	scannerProfile   string
	scannerTarget    string
	scannerModules   []string
	scannerState     string
	scannerError     string
	// Nightmare state
	nightmareServerActive  bool
	nightmareScannerActive bool
	nightmareProxyActive   bool
	nightmarePrevProxyMode string
	// Spider config
	spiderSitemapErrorRate    float64
	spiderSitemapEntryCount   int
	spiderRobotsCrawlDelay    int
	spiderRobotsDisallowPaths []string
	spiderEnableSitemapIndex  bool
	spiderEnableGzipSitemap   bool
	// Overrides
	overrides map[string]string
}

type adminConfigVals struct {
	numeric map[string]float64
	strings map[string]string
}

// randomAdminConfig returns random values for all AdminConfig fields.
func randomAdminConfig(rng *rand.Rand) adminConfigVals {
	v := adminConfigVals{
		numeric: map[string]float64{
			"max_labyrinth_depth":            float64(rng.Intn(100) + 1),
			"error_rate_multiplier":          float64(rng.Intn(50)) / 10.0,
			"captcha_trigger_thresh":         float64(rng.Intn(200) + 10),
			"block_chance":                   float64(rng.Intn(100)) / 100.0,
			"block_duration_sec":             float64(rng.Intn(300) + 1),
			"bot_score_threshold":            float64(rng.Intn(100)),
			"header_corrupt_level":           float64(rng.Intn(5)),
			"delay_min_ms":                   float64(rng.Intn(500)),
			"delay_max_ms":                   float64(rng.Intn(5000) + 500),
			"labyrinth_link_density":         float64(rng.Intn(20) + 1),
			"adaptive_interval_sec":          float64(rng.Intn(120) + 10),
			"protocol_glitch_level":          float64(rng.Intn(5)),
			"cookie_trap_frequency":          float64(rng.Intn(10) + 1),
			"js_trap_difficulty":             float64(rng.Intn(5) + 1),
			"content_cache_ttl_sec":          float64(rng.Intn(300) + 10),
			"adaptive_aggressive_rps":        float64(rng.Intn(50) + 1),
			"adaptive_labyrinth_paths":       float64(rng.Intn(20) + 1),
			"api_chaos_probability":          float64(rng.Intn(100)),
			"media_chaos_probability":        float64(rng.Intn(100)),
			"media_chaos_corruption_intensity": float64(rng.Intn(100)),
			"media_chaos_slow_min_ms":        float64(rng.Intn(500) + 1),
			"media_chaos_slow_max_ms":        float64(rng.Intn(5000) + 500),
			"media_chaos_infinite_max_bytes": float64(rng.Intn(100000000) + 1),
			"browser_chaos_level":            float64(rng.Intn(5)),
		},
		strings: map[string]string{
			"honeypot_response_style": []string{"realistic", "minimal", "aggressive"}[rng.Intn(3)],
			"active_framework":        []string{"auto", "rails", "django", "express", "spring", "laravel"}[rng.Intn(6)],
			"content_theme":           []string{"default", "corporate", "minimal"}[rng.Intn(3)],
			"recorder_format":         []string{"jsonl", "pcap"}[rng.Intn(2)],
		},
	}
	// Bool-as-int config values (round-tripped as 0/1).
	for _, key := range []string{"protocol_glitch_enabled", "browser_chaos_enabled"} {
		if rng.Intn(2) == 0 {
			v.numeric[key] = 1
		} else {
			v.numeric[key] = 0
		}
	}
	return v
}

// randomizeAll randomizes all global state and returns the expected values.
func randomizeAll(rng *rand.Rand) expectedState {
	state := expectedState{}

	// Feature flags
	state.features = make(map[string]bool)
	snap := globalFlags.Snapshot()
	for name := range snap {
		val := rng.Intn(2) == 0
		globalFlags.Set(name, val)
		state.features[name] = val
	}

	// AdminConfig numeric + string
	acfg := randomAdminConfig(rng)
	for k, v := range acfg.numeric {
		globalConfig.Set(k, v)
	}
	for k, v := range acfg.strings {
		globalConfig.SetString(k, v)
	}
	state.config = make(map[string]interface{})
	for k, v := range acfg.numeric {
		state.config[k] = v
	}
	for k, v := range acfg.strings {
		state.config[k] = v
	}

	// Error weights — includes HTTP + TCP/network error types
	state.errorWeights = map[string]float64{
		"slow_drip":        float64(rng.Intn(100)) / 100.0,
		"timeout":          float64(rng.Intn(100)) / 100.0,
		"connection_reset": float64(rng.Intn(100)) / 100.0,
		"malformed":        float64(rng.Intn(100)) / 100.0,
		"delayed":          float64(rng.Intn(100)) / 100.0,
		"tcp_reset":        float64(rng.Intn(100)) / 100.0,
		"slow_headers":     float64(rng.Intn(100)) / 100.0,
		"empty_response":   float64(rng.Intn(100)) / 100.0,
		"partial_response": float64(rng.Intn(100)) / 100.0,
	}
	for k, v := range state.errorWeights {
		globalConfig.SetErrorWeight(k, v)
	}

	// Page type weights
	state.pageTypeWeights = map[string]float64{
		"html":  float64(rng.Intn(100)) / 100.0,
		"json":  float64(rng.Intn(100)) / 100.0,
		"xml":   float64(rng.Intn(100)) / 100.0,
		"csv":   float64(rng.Intn(100)) / 100.0,
	}
	for k, v := range state.pageTypeWeights {
		globalConfig.SetPageTypeWeight(k, v)
	}

	// Vuln groups
	state.vulnGroups = make(map[string]bool)
	for _, g := range VulnGroups {
		val := rng.Intn(2) == 0
		globalVulnConfig.SetGroup(g, val)
		state.vulnGroups[g] = val
	}

	// API chaos categories
	state.apiChaosCats = make(map[string]bool)
	acSnap := globalAPIChaosConfig.Snapshot()
	for cat := range acSnap {
		val := rng.Intn(2) == 0
		globalAPIChaosConfig.SetCategory(cat, val)
		state.apiChaosCats[cat] = val
	}

	// Media chaos categories
	state.mediaChaosCats = make(map[string]bool)
	mcSnap := globalMediaChaosConfig.Snapshot()
	for cat := range mcSnap {
		val := rng.Intn(2) == 0
		globalMediaChaosConfig.SetCategory(cat, val)
		state.mediaChaosCats[cat] = val
	}

	// Proxy config
	modes := []string{"transparent", "waf", "chaos", "gateway"}
	state.proxyMode = modes[rng.Intn(len(modes))]
	state.proxyWAFEnabled = rng.Intn(2) == 0
	state.proxyWAFAction = []string{"reject", "block", "challenge", "tarpit"}[rng.Intn(4)]
	state.proxyLatencyProb = float64(rng.Intn(100)) / 100.0
	state.proxyCorruptProb = float64(rng.Intn(100)) / 100.0
	state.proxyDropProb = float64(rng.Intn(100)) / 100.0
	state.proxyResetProb = float64(rng.Intn(100)) / 100.0

	globalProxyConfig.mu.Lock()
	globalProxyConfig.Mode = state.proxyMode
	globalProxyConfig.WAFEnabled = state.proxyWAFEnabled
	globalProxyConfig.WAFBlockAction = state.proxyWAFAction
	globalProxyConfig.LatencyProb = state.proxyLatencyProb
	globalProxyConfig.CorruptProb = state.proxyCorruptProb
	globalProxyConfig.DropProb = state.proxyDropProb
	globalProxyConfig.ResetProb = state.proxyResetProb
	globalProxyConfig.mu.Unlock()

	// Blocking config (via adaptive engine)
	state.blockEnabled = rng.Intn(2) == 0
	state.blockChance = float64(rng.Intn(100)) / 100.0
	state.blockDurationSec = rng.Intn(300) + 1
	if globalAdaptive != nil {
		globalAdaptive.SetBlockEnabled(state.blockEnabled)
		globalAdaptive.SetBlockChance(state.blockChance)
		globalAdaptive.SetBlockDuration(time.Duration(state.blockDurationSec) * time.Second)
	}

	// Scanner config
	profiles := []string{"default", "compliance", "aggressive", "stealth", "nightmare"}
	state.scannerProfile = profiles[rng.Intn(len(profiles))]
	state.scannerTarget = "http://localhost:" + itoa(8000+rng.Intn(1000))
	modChoices := []string{"owasp", "injection", "fuzzing", "protocol", "auth", "crawl"}
	numMods := rng.Intn(len(modChoices)) + 1
	state.scannerModules = modChoices[:numMods]

	// Scanner state — randomly set completed or error
	states := []string{"completed", "error"}
	state.scannerState = states[rng.Intn(len(states))]
	if state.scannerState == "error" {
		state.scannerError = "simulated error " + itoa(rng.Intn(1000))
	}

	builtinMu.Lock()
	builtinProfile = state.scannerProfile
	builtinTarget = state.scannerTarget
	builtinModules = state.scannerModules
	builtinState = state.scannerState
	builtinError = state.scannerError
	builtinMu.Unlock()

	// Nightmare state — randomly activate subsystems
	state.nightmareServerActive = rng.Intn(2) == 0
	state.nightmareScannerActive = rng.Intn(2) == 0
	state.nightmareProxyActive = rng.Intn(2) == 0
	state.nightmarePrevProxyMode = []string{"transparent", "waf", "chaos", "gateway"}[rng.Intn(4)]
	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = state.nightmareServerActive
	globalNightmare.ScannerActive = state.nightmareScannerActive
	globalNightmare.ProxyActive = state.nightmareProxyActive
	globalNightmare.PreviousProxyMode = state.nightmarePrevProxyMode
	if state.nightmareServerActive {
		globalNightmare.PreviousConfig = map[string]interface{}{
			"error_rate_multiplier": 1.0,
		}
		globalNightmare.PreviousFeatures = map[string]bool{
			"labyrinth": true,
			"honeypot":  false,
		}
	}
	globalNightmare.mu.Unlock()

	// Spider config
	state.spiderSitemapErrorRate = float64(rng.Intn(100)) / 100.0
	state.spiderSitemapEntryCount = rng.Intn(500) + 1
	state.spiderRobotsCrawlDelay = rng.Intn(10)
	state.spiderRobotsDisallowPaths = []string{"/test/", "/secret/"}
	state.spiderEnableSitemapIndex = rng.Intn(2) == 0
	state.spiderEnableGzipSitemap = rng.Intn(2) == 0
	globalSpiderConfig.Set("sitemap_error_rate", state.spiderSitemapErrorRate)
	globalSpiderConfig.Set("sitemap_entry_count", state.spiderSitemapEntryCount)
	globalSpiderConfig.Set("robots_crawl_delay", state.spiderRobotsCrawlDelay)
	globalSpiderConfig.Set("robots_disallow_paths", state.spiderRobotsDisallowPaths)
	globalSpiderConfig.Set("enable_sitemap_index", state.spiderEnableSitemapIndex)
	globalSpiderConfig.Set("enable_gzip_sitemap", state.spiderEnableGzipSitemap)

	// Per-client overrides
	behaviorModes := []string{"normal", "cooperative", "aggressive", "labyrinth", "blocked"}
	state.overrides = make(map[string]string)
	numOverrides := rng.Intn(3) + 1
	for i := 0; i < numOverrides; i++ {
		clientID := "client_" + itoa(rng.Intn(1000))
		mode := behaviorModes[rng.Intn(len(behaviorModes))]
		state.overrides[clientID] = mode
		globalAdaptive.SetOverride(clientID, adaptive.BehaviorMode(mode))
	}

	return state
}

// verifyExport checks the export captures all expected values.
func verifyExport(t *testing.T, export *ConfigExport, expected expectedState) {
	t.Helper()

	// Features
	for name, want := range expected.features {
		if got, ok := export.Features[name]; !ok || got != want {
			t.Errorf("export.Features[%q]: got %v, want %v", name, got, want)
		}
	}

	// Error weights
	for k, want := range expected.errorWeights {
		if got, ok := export.ErrorWeights[k]; !ok || math.Abs(got-want) > 0.01 {
			t.Errorf("export.ErrorWeights[%q]: got %v, want %v", k, got, want)
		}
	}

	// Page type weights
	for k, want := range expected.pageTypeWeights {
		if got, ok := export.PageTypeWeights[k]; !ok || math.Abs(got-want) > 0.01 {
			t.Errorf("export.PageTypeWeights[%q]: got %v, want %v", k, got, want)
		}
	}

	// Proxy config
	if export.ProxyConfig == nil {
		t.Error("export.ProxyConfig should not be nil")
		return
	}
	if mode, ok := export.ProxyConfig["mode"].(string); !ok || mode != expected.proxyMode {
		t.Errorf("export.ProxyConfig[mode]: got %v, want %q", export.ProxyConfig["mode"], expected.proxyMode)
	}

	// Blocking config
	if export.Blocking == nil {
		t.Error("export.Blocking should not be nil")
	} else {
		if enabled, ok := export.Blocking["enabled"].(bool); !ok || enabled != expected.blockEnabled {
			t.Errorf("export.Blocking[enabled]: got %v, want %v", export.Blocking["enabled"], expected.blockEnabled)
		}
		if chance, ok := export.Blocking["chance"].(float64); !ok || math.Abs(chance-expected.blockChance) > 0.01 {
			t.Errorf("export.Blocking[chance]: got %v, want %v", export.Blocking["chance"], expected.blockChance)
		}
		if durSec, ok := export.Blocking["duration_sec"].(int); !ok || durSec != expected.blockDurationSec {
			t.Errorf("export.Blocking[duration_sec]: got %v, want %v", export.Blocking["duration_sec"], expected.blockDurationSec)
		}
	}

	// Scanner config
	if export.ScannerConfig == nil {
		t.Error("export.ScannerConfig should not be nil")
	} else {
		if profile, ok := export.ScannerConfig["default_profile"].(string); !ok || profile != expected.scannerProfile {
			t.Errorf("export.ScannerConfig[default_profile]: got %v, want %q", export.ScannerConfig["default_profile"], expected.scannerProfile)
		}
		if target, ok := export.ScannerConfig["default_target"].(string); !ok || target != expected.scannerTarget {
			t.Errorf("export.ScannerConfig[default_target]: got %v, want %q", export.ScannerConfig["default_target"], expected.scannerTarget)
		}
		if state, ok := export.ScannerConfig["last_state"].(string); !ok || state != expected.scannerState {
			t.Errorf("export.ScannerConfig[last_state]: got %v, want %q", export.ScannerConfig["last_state"], expected.scannerState)
		}
		if expected.scannerState == "error" {
			if errMsg, ok := export.ScannerConfig["last_error"].(string); !ok || errMsg != expected.scannerError {
				t.Errorf("export.ScannerConfig[last_error]: got %v, want %q", export.ScannerConfig["last_error"], expected.scannerError)
			}
		}
	}

	// Nightmare config
	if expected.nightmareServerActive || expected.nightmareScannerActive || expected.nightmareProxyActive {
		if export.NightmareConfig == nil {
			t.Error("export.NightmareConfig should not be nil when nightmare is active")
		} else {
			if v, ok := export.NightmareConfig["server_active"].(bool); !ok || v != expected.nightmareServerActive {
				t.Errorf("export.NightmareConfig[server_active]: got %v, want %v", export.NightmareConfig["server_active"], expected.nightmareServerActive)
			}
			if v, ok := export.NightmareConfig["previous_proxy_mode"].(string); !ok || v != expected.nightmarePrevProxyMode {
				t.Errorf("export.NightmareConfig[previous_proxy_mode]: got %v, want %q", export.NightmareConfig["previous_proxy_mode"], expected.nightmarePrevProxyMode)
			}
		}
	}

	// Spider config
	if export.SpiderConfig == nil {
		t.Error("export.SpiderConfig should not be nil")
	} else {
		if v, ok := export.SpiderConfig["sitemap_entry_count"].(int); !ok || v != expected.spiderSitemapEntryCount {
			t.Errorf("export.SpiderConfig[sitemap_entry_count]: got %v, want %d", export.SpiderConfig["sitemap_entry_count"], expected.spiderSitemapEntryCount)
		}
		if v, ok := export.SpiderConfig["enable_sitemap_index"].(bool); !ok || v != expected.spiderEnableSitemapIndex {
			t.Errorf("export.SpiderConfig[enable_sitemap_index]: got %v, want %v", export.SpiderConfig["enable_sitemap_index"], expected.spiderEnableSitemapIndex)
		}
	}

	// Overrides
	if len(expected.overrides) > 0 {
		if export.Overrides == nil {
			t.Error("export.Overrides should not be nil when overrides are set")
		} else {
			for clientID, mode := range expected.overrides {
				if got, ok := export.Overrides[clientID]; !ok || got != mode {
					t.Errorf("export.Overrides[%q]: got %v, want %q", clientID, got, mode)
				}
			}
		}
	}
}

// verifyGlobals checks all global singletons match expected state.
func verifyGlobals(t *testing.T, expected expectedState) {
	t.Helper()

	// Feature flags
	gotFlags := globalFlags.Snapshot()
	for name, want := range expected.features {
		if gotFlags[name] != want {
			t.Errorf("feature %q: got %v, want %v", name, gotFlags[name], want)
		}
	}

	// AdminConfig
	gotCfg := globalConfig.Get()
	for k, want := range expected.config {
		got := gotCfg[k]
		switch w := want.(type) {
		case float64:
			var gotF float64
			switch g := got.(type) {
			case float64:
				gotF = g
			case int:
				gotF = float64(g)
			case int64:
				gotF = float64(g)
			case bool:
				if g {
					gotF = 1
				}
			}
			if math.Abs(gotF-w) > 0.01 {
				t.Errorf("config %q: got %v, want %v", k, got, want)
			}
		case string:
			if gotS, ok := got.(string); !ok || gotS != w {
				t.Errorf("config %q: got %v, want %q", k, got, want)
			}
		}
	}

	// Error weights
	gotEW := globalConfig.GetErrorWeights()
	for k, want := range expected.errorWeights {
		if gotV, ok := gotEW[k]; !ok || math.Abs(gotV-want) > 0.01 {
			t.Errorf("error weight %q: got %v, want %v", k, gotV, want)
		}
	}

	// Page type weights
	gotPW := globalConfig.GetPageTypeWeights()
	for k, want := range expected.pageTypeWeights {
		if gotV, ok := gotPW[k]; !ok || math.Abs(gotV-want) > 0.01 {
			t.Errorf("page type weight %q: got %v, want %v", k, gotV, want)
		}
	}

	// Vuln groups
	for g, want := range expected.vulnGroups {
		if globalVulnConfig.IsGroupEnabled(g) != want {
			t.Errorf("vuln group %q: got %v, want %v", g, globalVulnConfig.IsGroupEnabled(g), want)
		}
	}

	// API chaos categories
	gotAC := globalAPIChaosConfig.Snapshot()
	for cat, want := range expected.apiChaosCats {
		if gotAC[cat] != want {
			t.Errorf("api chaos cat %q: got %v, want %v", cat, gotAC[cat], want)
		}
	}

	// Media chaos categories
	gotMC := globalMediaChaosConfig.Snapshot()
	for cat, want := range expected.mediaChaosCats {
		if gotMC[cat] != want {
			t.Errorf("media chaos cat %q: got %v, want %v", cat, gotMC[cat], want)
		}
	}

	// Proxy config
	if globalProxyConfig.GetMode() != expected.proxyMode {
		t.Errorf("proxy mode: got %q, want %q", globalProxyConfig.GetMode(), expected.proxyMode)
	}
	globalProxyConfig.mu.RLock()
	defer globalProxyConfig.mu.RUnlock()
	if globalProxyConfig.WAFEnabled != expected.proxyWAFEnabled {
		t.Errorf("proxy WAFEnabled: got %v, want %v", globalProxyConfig.WAFEnabled, expected.proxyWAFEnabled)
	}
	if globalProxyConfig.WAFBlockAction != expected.proxyWAFAction {
		t.Errorf("proxy WAFBlockAction: got %q, want %q", globalProxyConfig.WAFBlockAction, expected.proxyWAFAction)
	}
	if math.Abs(globalProxyConfig.LatencyProb-expected.proxyLatencyProb) > 0.01 {
		t.Errorf("proxy LatencyProb: got %f, want %f", globalProxyConfig.LatencyProb, expected.proxyLatencyProb)
	}
	if math.Abs(globalProxyConfig.CorruptProb-expected.proxyCorruptProb) > 0.01 {
		t.Errorf("proxy CorruptProb: got %f, want %f", globalProxyConfig.CorruptProb, expected.proxyCorruptProb)
	}
	if math.Abs(globalProxyConfig.DropProb-expected.proxyDropProb) > 0.01 {
		t.Errorf("proxy DropProb: got %f, want %f", globalProxyConfig.DropProb, expected.proxyDropProb)
	}
	if math.Abs(globalProxyConfig.ResetProb-expected.proxyResetProb) > 0.01 {
		t.Errorf("proxy ResetProb: got %f, want %f", globalProxyConfig.ResetProb, expected.proxyResetProb)
	}

	// Blocking config (via adaptive engine)
	if globalAdaptive != nil {
		chance, duration, enabled := globalAdaptive.GetBlockConfig()
		if enabled != expected.blockEnabled {
			t.Errorf("blocking enabled: got %v, want %v", enabled, expected.blockEnabled)
		}
		if math.Abs(chance-expected.blockChance) > 0.01 {
			t.Errorf("blocking chance: got %f, want %f", chance, expected.blockChance)
		}
		gotDurSec := int(duration.Seconds())
		if gotDurSec != expected.blockDurationSec {
			t.Errorf("blocking duration_sec: got %d, want %d", gotDurSec, expected.blockDurationSec)
		}
	} else {
		t.Error("globalAdaptive should not be nil after resetGlobals")
	}

	// Scanner config — use scoped lock to avoid holding two mutexes via defer.
	func() {
		builtinMu.RLock()
		defer builtinMu.RUnlock()
		if builtinProfile != expected.scannerProfile {
			t.Errorf("scanner profile: got %q, want %q", builtinProfile, expected.scannerProfile)
		}
		if builtinTarget != expected.scannerTarget {
			t.Errorf("scanner target: got %q, want %q", builtinTarget, expected.scannerTarget)
		}
		if len(builtinModules) != len(expected.scannerModules) {
			t.Errorf("scanner modules count: got %d, want %d", len(builtinModules), len(expected.scannerModules))
		} else {
			for i, want := range expected.scannerModules {
				if builtinModules[i] != want {
					t.Errorf("scanner module[%d]: got %q, want %q", i, builtinModules[i], want)
				}
			}
		}
		if builtinState != expected.scannerState {
			t.Errorf("scanner state: got %q, want %q", builtinState, expected.scannerState)
		}
		if builtinError != expected.scannerError {
			t.Errorf("scanner error: got %q, want %q", builtinError, expected.scannerError)
		}
	}()

	// Nightmare state
	func() {
		globalNightmare.mu.RLock()
		defer globalNightmare.mu.RUnlock()
		if globalNightmare.ServerActive != expected.nightmareServerActive {
			t.Errorf("nightmare server_active: got %v, want %v", globalNightmare.ServerActive, expected.nightmareServerActive)
		}
		if globalNightmare.ScannerActive != expected.nightmareScannerActive {
			t.Errorf("nightmare scanner_active: got %v, want %v", globalNightmare.ScannerActive, expected.nightmareScannerActive)
		}
		if globalNightmare.ProxyActive != expected.nightmareProxyActive {
			t.Errorf("nightmare proxy_active: got %v, want %v", globalNightmare.ProxyActive, expected.nightmareProxyActive)
		}
		if globalNightmare.PreviousProxyMode != expected.nightmarePrevProxyMode {
			t.Errorf("nightmare previous_proxy_mode: got %q, want %q", globalNightmare.PreviousProxyMode, expected.nightmarePrevProxyMode)
		}
	}()

	// Spider config
	func() {
		snap := globalSpiderConfig.Snapshot()
		if v, ok := snap["sitemap_entry_count"].(int); !ok || v != expected.spiderSitemapEntryCount {
			t.Errorf("spider sitemap_entry_count: got %v, want %d", snap["sitemap_entry_count"], expected.spiderSitemapEntryCount)
		}
		if v, ok := snap["robots_crawl_delay"].(int); !ok || v != expected.spiderRobotsCrawlDelay {
			t.Errorf("spider robots_crawl_delay: got %v, want %d", snap["robots_crawl_delay"], expected.spiderRobotsCrawlDelay)
		}
		if v, ok := snap["enable_sitemap_index"].(bool); !ok || v != expected.spiderEnableSitemapIndex {
			t.Errorf("spider enable_sitemap_index: got %v, want %v", snap["enable_sitemap_index"], expected.spiderEnableSitemapIndex)
		}
		if v, ok := snap["enable_gzip_sitemap"].(bool); !ok || v != expected.spiderEnableGzipSitemap {
			t.Errorf("spider enable_gzip_sitemap: got %v, want %v", snap["enable_gzip_sitemap"], expected.spiderEnableGzipSitemap)
		}
		if paths, ok := snap["robots_disallow_paths"].([]string); ok {
			if len(paths) != len(expected.spiderRobotsDisallowPaths) {
				t.Errorf("spider robots_disallow_paths len: got %d, want %d", len(paths), len(expected.spiderRobotsDisallowPaths))
			} else {
				for i, want := range expected.spiderRobotsDisallowPaths {
					if paths[i] != want {
						t.Errorf("spider robots_disallow_paths[%d]: got %q, want %q", i, paths[i], want)
					}
				}
			}
		}
	}()

	// Per-client overrides
	if globalAdaptive != nil && len(expected.overrides) > 0 {
		gotOverrides := globalAdaptive.GetOverrides()
		for clientID, wantMode := range expected.overrides {
			if gotMode, ok := gotOverrides[clientID]; !ok || string(gotMode) != wantMode {
				t.Errorf("override %q: got %v, want %q", clientID, gotMode, wantMode)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Password persistence tests
// ---------------------------------------------------------------------------

// TestPersistence_PasswordChangeUpdatesGlobal verifies that ChangePassword
// updates the in-memory password (DB persistence is tested with live DB).
func TestPersistence_PasswordChangeUpdatesGlobal(t *testing.T) {
	SetAdminPassword("original123")
	if err := ChangePassword("original123", "newpass456"); err != nil {
		t.Fatalf("ChangePassword should succeed: %v", err)
	}
	if !checkPassword("newpass456") {
		t.Error("new password should be accepted after change")
	}
	if checkPassword("original123") {
		t.Error("old password should be rejected after change")
	}
}

// TestPersistence_PasswordChangeRejectsWrongCurrent verifies incorrect
// current password is rejected.
func TestPersistence_PasswordChangeRejectsWrongCurrent(t *testing.T) {
	SetAdminPassword("correct")
	err := ChangePassword("wrong", "newpw")
	if err == nil {
		t.Error("ChangePassword should fail with wrong current password")
	}
}

// ---------------------------------------------------------------------------
// Proxy runtime state persistence tests
// ---------------------------------------------------------------------------

// TestPersistence_ProxyRuntimeState verifies that proxy running state
// (port + target) round-trips through export/import.
func TestPersistence_ProxyRuntimeState(t *testing.T) {
	resetGlobals()

	// Simulate proxy config with runtime state.
	proxyConfig := map[string]interface{}{
		"mode":          "chaos",
		"proxy_running": true,
		"proxy_port":    float64(9090),
		"proxy_target":  "http://localhost:8765",
	}

	export := &ConfigExport{
		Version:     "1.0",
		Features:    globalFlags.Snapshot(),
		Config:      globalConfig.Get(),
		VulnConfig:  globalVulnConfig.Snapshot(),
		ProxyConfig: proxyConfig,
	}

	// Clear any pending state.
	pendingBlockingMu.Lock()
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	ImportConfig(export)

	// Verify pending proxy runtime state was captured.
	pendingBlockingMu.Lock()
	state := pendingProxyRuntime
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	if state == nil {
		t.Fatal("pendingProxyRuntime should be set after import with proxy_running=true")
	}
	if state.Port != 9090 {
		t.Errorf("proxy port: got %d, want 9090", state.Port)
	}
	if state.Target != "http://localhost:8765" {
		t.Errorf("proxy target: got %q, want %q", state.Target, "http://localhost:8765")
	}
}

// TestPersistence_ProxyRuntimeState_NotRunning verifies that stopped proxy
// does not set pending runtime state.
func TestPersistence_ProxyRuntimeState_NotRunning(t *testing.T) {
	resetGlobals()

	export := &ConfigExport{
		Version:     "1.0",
		Features:    globalFlags.Snapshot(),
		Config:      globalConfig.Get(),
		VulnConfig:  globalVulnConfig.Snapshot(),
		ProxyConfig: map[string]interface{}{"mode": "transparent"},
	}

	pendingBlockingMu.Lock()
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	ImportConfig(export)

	pendingBlockingMu.Lock()
	state := pendingProxyRuntime
	pendingBlockingMu.Unlock()

	if state != nil {
		t.Error("pendingProxyRuntime should be nil when proxy_running is not set")
	}
}

// TestPersistence_ProxyRuntimeState_JSONRoundTrip verifies that proxy
// runtime state survives JSON serialization.
func TestPersistence_ProxyRuntimeState_JSONRoundTrip(t *testing.T) {
	resetGlobals()

	proxyConfig := map[string]interface{}{
		"mode":          "waf",
		"proxy_running": true,
		"proxy_port":    float64(7070),
		"proxy_target":  "http://backend:3000",
	}

	export := &ConfigExport{
		Version:     "1.0",
		Features:    globalFlags.Snapshot(),
		Config:      globalConfig.Get(),
		VulnConfig:  globalVulnConfig.Snapshot(),
		ProxyConfig: proxyConfig,
	}

	// JSON round-trip
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored ConfigExport
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	pendingBlockingMu.Lock()
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	ImportConfig(&restored)

	pendingBlockingMu.Lock()
	state := pendingProxyRuntime
	pendingProxyRuntime = nil
	pendingBlockingMu.Unlock()

	if state == nil {
		t.Fatal("proxy runtime state should survive JSON round-trip")
	}
	if state.Port != 7070 {
		t.Errorf("proxy port after JSON round-trip: got %d, want 7070", state.Port)
	}
	if state.Target != "http://backend:3000" {
		t.Errorf("proxy target after JSON round-trip: got %q, want %q", state.Target, "http://backend:3000")
	}
}

// ---------------------------------------------------------------------------
// Request logger tests
// ---------------------------------------------------------------------------

// TestPersistence_RequestLoggerSampling verifies the sampling logic of the
// request logger (without needing a real database).
func TestPersistence_RequestLoggerSampling(t *testing.T) {
	// Without globalRequestLogger set, LogRequest should be a no-op.
	LogRequest("client1", "GET", "/test", 200, 1.5, "ok", "test-agent")
	// No panic or error = pass.

	// Verify the counter-based sampling works in isolation.
	rl := &RequestLogger{
		ch:      make(chan storage.RequestLogEntry, 100),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
		sampleN: 5, // log every 5th request
	}

	// Temporarily set as global.
	old := globalRequestLogger
	globalRequestLogger = rl
	defer func() { globalRequestLogger = old }()

	// Send 20 requests — should get 4 logged (5th, 10th, 15th, 20th).
	for i := 0; i < 20; i++ {
		LogRequest("c1", "GET", "/path", 200, 1.0, "ok", "ua")
	}

	count := 0
	for {
		select {
		case <-rl.ch:
			count++
		default:
			goto done
		}
	}
done:
	if count != 4 {
		t.Errorf("expected 4 sampled requests, got %d", count)
	}
}
