package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// VulnConfig tests
// ---------------------------------------------------------------------------

func TestVulnConfig_AllGroupsEnabled(t *testing.T) {
	vc := NewVulnConfig()
	for _, g := range VulnGroups {
		if !vc.IsGroupEnabled(g) {
			t.Errorf("group %q should be enabled by default", g)
		}
	}
}

func TestVulnConfig_SetGroup(t *testing.T) {
	vc := NewVulnConfig()

	for _, g := range VulnGroups {
		vc.SetGroup(g, false)
		if vc.IsGroupEnabled(g) {
			t.Errorf("group %q should be disabled after SetGroup(false)", g)
		}
		vc.SetGroup(g, true)
		if !vc.IsGroupEnabled(g) {
			t.Errorf("group %q should be enabled after SetGroup(true)", g)
		}
	}
}

func TestVulnConfig_UnknownGroupEnabled(t *testing.T) {
	vc := NewVulnConfig()
	if !vc.IsGroupEnabled("nonexistent_group") {
		t.Error("unknown groups should be enabled by default")
	}
}

func TestVulnConfig_Snapshot(t *testing.T) {
	vc := NewVulnConfig()
	vc.SetGroup("owasp", false)
	vc.SetCategory("test-cat", false)

	snap := vc.Snapshot()
	groups := snap["groups"].(map[string]bool)
	cats := snap["categories"].(map[string]bool)

	if groups["owasp"] != false {
		t.Error("snapshot should reflect owasp=false")
	}
	if groups["advanced"] != true {
		t.Error("snapshot should reflect advanced=true")
	}
	if cats["test-cat"] != false {
		t.Error("snapshot should reflect test-cat=false")
	}

	// Ensure all 9 groups are in snapshot
	if len(groups) != len(VulnGroups) {
		t.Errorf("snapshot groups count: got %d, want %d", len(groups), len(VulnGroups))
	}
}

func TestVulnConfig_CategoryToggle(t *testing.T) {
	vc := NewVulnConfig()

	// Default: enabled
	if !vc.IsCategoryEnabled("some-vuln") {
		t.Error("unknown categories should be enabled by default")
	}

	vc.SetCategory("some-vuln", false)
	if vc.IsCategoryEnabled("some-vuln") {
		t.Error("category should be disabled after SetCategory(false)")
	}

	vc.SetCategory("some-vuln", true)
	if !vc.IsCategoryEnabled("some-vuln") {
		t.Error("category should be enabled after SetCategory(true)")
	}
}

// ---------------------------------------------------------------------------
// AdminConfig tests
// ---------------------------------------------------------------------------

func TestAdminConfig_Defaults(t *testing.T) {
	cfg := NewAdminConfig()
	got := cfg.Get()

	if got["max_labyrinth_depth"].(int) != 50 {
		t.Errorf("default max_labyrinth_depth: got %v, want 50", got["max_labyrinth_depth"])
	}
	if got["error_rate_multiplier"].(float64) != 1.0 {
		t.Errorf("default error_rate_multiplier: got %v, want 1.0", got["error_rate_multiplier"])
	}
	if got["honeypot_response_style"].(string) != "realistic" {
		t.Errorf("default honeypot_response_style: got %v, want 'realistic'", got["honeypot_response_style"])
	}
	if got["content_theme"].(string) != "default" {
		t.Errorf("default content_theme: got %v, want 'default'", got["content_theme"])
	}
}

func TestAdminConfig_SetNumeric(t *testing.T) {
	cfg := NewAdminConfig()

	if !cfg.Set("max_labyrinth_depth", 75) {
		t.Error("Set should return true for known key")
	}
	if cfg.Get()["max_labyrinth_depth"].(int) != 75 {
		t.Errorf("max_labyrinth_depth should be 75 after set")
	}

	// Clamping
	cfg.Set("max_labyrinth_depth", 200)
	if cfg.Get()["max_labyrinth_depth"].(int) != 100 {
		t.Errorf("max_labyrinth_depth should be clamped to 100")
	}

	if cfg.Set("unknown_key", 42) {
		t.Error("Set should return false for unknown key")
	}
}

func TestAdminConfig_SetString(t *testing.T) {
	cfg := NewAdminConfig()

	if !cfg.SetString("content_theme", "banking") {
		t.Error("SetString should return true for known key")
	}
	if cfg.Get()["content_theme"].(string) != "banking" {
		t.Errorf("content_theme should be 'banking' after set")
	}

	if !cfg.SetString("honeypot_response_style", "tarpit") {
		t.Error("SetString should accept 'tarpit' for honeypot_response_style")
	}
	if cfg.Get()["honeypot_response_style"].(string) != "tarpit" {
		t.Errorf("honeypot_response_style should be 'tarpit'")
	}

	if cfg.SetString("unknown_key", "val") {
		t.Error("SetString should return false for unknown key")
	}
}

func TestAdminConfig_ErrorWeights(t *testing.T) {
	cfg := NewAdminConfig()

	cfg.SetErrorWeight("500_internal", 0.5)
	cfg.SetErrorWeight("tcp_reset", 0.3)

	weights := cfg.GetErrorWeights()
	if weights["500_internal"] != 0.5 {
		t.Errorf("500_internal weight: got %v, want 0.5", weights["500_internal"])
	}
	if weights["tcp_reset"] != 0.3 {
		t.Errorf("tcp_reset weight: got %v, want 0.3", weights["tcp_reset"])
	}

	cfg.ResetErrorWeights()
	if len(cfg.GetErrorWeights()) != 0 {
		t.Error("error weights should be empty after reset")
	}
}

func TestAdminConfig_PageTypeWeights(t *testing.T) {
	cfg := NewAdminConfig()

	cfg.SetPageTypeWeight("html", 0.4)
	weights := cfg.GetPageTypeWeights()
	if weights["html"] != 0.4 {
		t.Errorf("html weight: got %v, want 0.4", weights["html"])
	}

	cfg.ResetPageTypeWeights()
	if len(cfg.GetPageTypeWeights()) != 0 {
		t.Error("page type weights should be empty after reset")
	}
}

// ---------------------------------------------------------------------------
// FeatureFlags tests
// ---------------------------------------------------------------------------

func TestFeatureFlags_AllEnabled(t *testing.T) {
	ff := NewFeatureFlags()
	snap := ff.Snapshot()
	for name, enabled := range snap {
		if !enabled {
			t.Errorf("feature %q should be enabled by default", name)
		}
	}
}

func TestFeatureFlags_Toggle(t *testing.T) {
	ff := NewFeatureFlags()

	if !ff.Set("labyrinth", false) {
		t.Error("Set should return true for known feature")
	}
	if ff.IsLabyrinthEnabled() {
		t.Error("labyrinth should be disabled")
	}

	ff.Set("labyrinth", true)
	if !ff.IsLabyrinthEnabled() {
		t.Error("labyrinth should be enabled")
	}

	if ff.Set("unknown_feature", true) {
		t.Error("Set should return false for unknown feature")
	}
}

// ---------------------------------------------------------------------------
// Config Export/Import tests
// ---------------------------------------------------------------------------

func TestConfigExportImport(t *testing.T) {
	// Set some custom config
	globalFlags.Set("labyrinth", false)
	globalConfig.SetString("content_theme", "banking")
	globalConfig.SetErrorWeight("tcp_reset", 0.25)
	globalVulnConfig.SetGroup("modern", false)

	defer func() {
		// Reset globals
		globalFlags.Set("labyrinth", true)
		globalConfig.SetString("content_theme", "default")
		globalConfig.ResetErrorWeights()
		globalVulnConfig.SetGroup("modern", true)
	}()

	export := ExportConfig()
	if export.Version != "1.0" {
		t.Errorf("export version: got %q, want '1.0'", export.Version)
	}
	if export.Features["labyrinth"] != false {
		t.Error("exported labyrinth should be false")
	}

	// Reset and reimport
	globalFlags.Set("labyrinth", true)
	globalConfig.SetString("content_theme", "default")
	globalConfig.ResetErrorWeights()
	globalVulnConfig.SetGroup("modern", true)

	ImportConfig(export)

	if globalFlags.IsLabyrinthEnabled() {
		t.Error("after import, labyrinth should be false")
	}
	if globalConfig.Get()["content_theme"].(string) != "banking" {
		t.Error("after import, content_theme should be 'banking'")
	}
	if globalConfig.GetErrorWeights()["tcp_reset"] != 0.25 {
		t.Error("after import, tcp_reset weight should be 0.25")
	}
}

// ---------------------------------------------------------------------------
// API route tests
// ---------------------------------------------------------------------------

func TestVulnsGroupAPI(t *testing.T) {
	// Reset to defaults
	vc := NewVulnConfig()
	origVC := globalVulnConfig
	globalVulnConfig = vc
	defer func() { globalVulnConfig = origVC }()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/vulns/group", func(w http.ResponseWriter, r *http.Request) {
		adminAPIVulnsGroupPost(w, r)
	})

	// Disable modern group
	body := `{"group":"modern","enabled":false}`
	req := httptest.NewRequest("POST", "/admin/api/vulns/group", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Error("response should have ok=true")
	}

	if vc.IsGroupEnabled("modern") {
		t.Error("modern group should be disabled after API call")
	}

	// Verify it shows up in snapshot
	snap := vc.Snapshot()
	groups := snap["groups"].(map[string]bool)
	if groups["modern"] != false {
		t.Error("snapshot should show modern=false")
	}
}

func TestVulnsCategoryAPI(t *testing.T) {
	vc := NewVulnConfig()
	origVC := globalVulnConfig
	globalVulnConfig = vc
	defer func() { globalVulnConfig = origVC }()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/vulns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIVulnsPost(w, r)
		} else {
			adminAPIVulnsGet(w, r)
		}
	})

	// Disable a specific category
	body := `{"id":"apisec-1","enabled":false}`
	req := httptest.NewRequest("POST", "/admin/api/vulns", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}
	if vc.IsCategoryEnabled("apisec-1") {
		t.Error("apisec-1 should be disabled")
	}

	// GET should return the state
	req2 := httptest.NewRequest("GET", "/admin/api/vulns", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &resp)
	cats := resp["categories"].(map[string]interface{})
	if cats["apisec-1"] != false {
		t.Error("GET should return apisec-1=false")
	}
}

func TestErrorWeightsAPI(t *testing.T) {
	origCfg := globalConfig
	globalConfig = NewAdminConfig()
	defer func() { globalConfig = origCfg }()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/error-weights", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIErrorWeightsPost(w, r)
		} else {
			adminAPIErrorWeightsGet(w, r)
		}
	})

	// Set a weight
	body := `{"error_type":"tcp_reset","weight":0.15}`
	req := httptest.NewRequest("POST", "/admin/api/error-weights", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}

	weights := globalConfig.GetErrorWeights()
	if weights["tcp_reset"] != 0.15 {
		t.Errorf("tcp_reset weight: got %v, want 0.15", weights["tcp_reset"])
	}

	// Reset
	body2 := `{"reset":true}`
	req2 := httptest.NewRequest("POST", "/admin/api/error-weights", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	if len(globalConfig.GetErrorWeights()) != 0 {
		t.Error("weights should be empty after reset")
	}
}

func TestConfigStringAPI(t *testing.T) {
	origCfg := globalConfig
	globalConfig = NewAdminConfig()
	defer func() { globalConfig = origCfg }()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIConfigPost(w, r)
		} else {
			adminAPIConfigGet(w, r)
		}
	})

	// Set content theme
	body := `{"key":"content_theme","value":"banking"}`
	req := httptest.NewRequest("POST", "/admin/api/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}

	cfg := globalConfig.Get()
	if cfg["content_theme"].(string) != "banking" {
		t.Errorf("content_theme: got %v, want 'banking'", cfg["content_theme"])
	}

	// Set honeypot style to tarpit
	body2 := `{"key":"honeypot_response_style","value":"tarpit"}`
	req2 := httptest.NewRequest("POST", "/admin/api/config", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	cfg2 := globalConfig.Get()
	if cfg2["honeypot_response_style"].(string) != "tarpit" {
		t.Errorf("honeypot_response_style: got %v, want 'tarpit'", cfg2["honeypot_response_style"])
	}
}

// ---------------------------------------------------------------------------
// ProxyConfig tests
// ---------------------------------------------------------------------------

func TestProxyConfig_Default(t *testing.T) {
	pc := NewProxyConfig()
	if pc.GetMode() != "transparent" {
		t.Errorf("default mode: got %q, want 'transparent'", pc.GetMode())
	}
	snap := pc.Snapshot()
	if snap["mode"].(string) != "transparent" {
		t.Error("snapshot mode should be transparent")
	}
	if snap["waf_enabled"].(bool) != false {
		t.Error("waf_enabled should be false by default")
	}
}

func TestProxyConfig_SetMode(t *testing.T) {
	pc := NewProxyConfig()

	for _, mode := range ProxyModes {
		if !pc.SetMode(mode) {
			t.Errorf("SetMode(%q) should return true", mode)
		}
		if pc.GetMode() != mode {
			t.Errorf("after SetMode(%q), GetMode() = %q", mode, pc.GetMode())
		}
	}

	// Invalid mode
	if pc.SetMode("invalid_mode") {
		t.Error("SetMode('invalid_mode') should return false")
	}
}

func TestProxyConfig_WAFAutoEnable(t *testing.T) {
	pc := NewProxyConfig()

	pc.SetMode("waf")
	snap := pc.Snapshot()
	if snap["waf_enabled"].(bool) != true {
		t.Error("waf mode should auto-enable WAF")
	}

	pc.SetMode("transparent")
	snap = pc.Snapshot()
	if snap["waf_enabled"].(bool) != false {
		t.Error("transparent mode should auto-disable WAF")
	}

	pc.SetMode("nightmare")
	snap = pc.Snapshot()
	if snap["waf_enabled"].(bool) != true {
		t.Error("nightmare mode should auto-enable WAF")
	}
}

func TestProxyModeAPI(t *testing.T) {
	origPC := globalProxyConfig
	globalProxyConfig = NewProxyConfig()
	defer func() { globalProxyConfig = origPC }()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/proxy/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalProxyConfig.Snapshot())
	})
	mux.HandleFunc("/admin/api/proxy/mode", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Mode string `json:"mode"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if !globalProxyConfig.SetMode(req.Mode) {
			http.Error(w, `{"error":"invalid proxy mode"}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "mode": req.Mode})
	})

	// Set mode to nightmare
	body := `{"mode":"nightmare"}`
	req := httptest.NewRequest("POST", "/admin/api/proxy/mode", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("POST status: %d", rec.Code)
	}

	// Verify GET returns nightmare
	req2 := httptest.NewRequest("GET", "/admin/api/proxy/status", nil)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)

	var resp map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &resp)
	if resp["mode"].(string) != "nightmare" {
		t.Errorf("GET proxy/status mode: got %q, want 'nightmare'", resp["mode"])
	}
	if resp["waf_enabled"].(bool) != true {
		t.Error("nightmare mode should have waf_enabled=true")
	}
}
