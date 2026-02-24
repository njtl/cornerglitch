package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/replay"
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

// ---------------------------------------------------------------------------
// Replay API tests
// ---------------------------------------------------------------------------

func TestReplayUploadAPI(t *testing.T) {
	// Create a temporary captures directory.
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/replay/upload", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayUpload(w, r)
	})

	// Build multipart form with a .pcap file.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "test_upload.pcap")
	if err != nil {
		t.Fatal(err)
	}
	// Write some dummy pcap-like content.
	part.Write([]byte("dummy pcap content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/admin/api/replay/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("upload status: %d, body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("upload response should have ok=true, got: %v", resp)
	}
	if resp["file"].(string) != "test_upload.pcap" {
		t.Errorf("file: got %q, want 'test_upload.pcap'", resp["file"])
	}

	// Verify file was created.
	if _, err := os.Stat(filepath.Join("captures", "test_upload.pcap")); os.IsNotExist(err) {
		t.Error("uploaded file should exist in captures/")
	}
}

func TestReplayUploadAPI_BadExtension(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/replay/upload", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayUpload(w, r)
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("file", "malware.exe")
	part.Write([]byte("bad content"))
	writer.Close()

	req := httptest.NewRequest("POST", "/admin/api/replay/upload", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != false {
		t.Error("upload of .exe should be rejected")
	}
}

func TestReplayCleanupAPI(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Create captures dir with some files.
	os.MkdirAll("captures", 0o755)
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("capture_%d.pcap", i)
		data := make([]byte, 1<<20) // 1MB each
		os.WriteFile(filepath.Join("captures", name), data, 0o644)
		// Stagger modification times.
		modTime := time.Now().Add(time.Duration(i) * time.Second)
		os.Chtimes(filepath.Join("captures", name), modTime, modTime)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/replay/cleanup", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayCleanup(w, r)
	})

	// Request cleanup to 2MB max (should delete 3 of 5 files).
	body := `{"max_size_mb": 2}`
	req := httptest.NewRequest("POST", "/admin/api/replay/cleanup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("cleanup status: %d, body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("cleanup should return ok=true")
	}

	deleted := int(resp["deleted"].(float64))
	if deleted != 3 {
		t.Errorf("deleted: got %d, want 3", deleted)
	}

	freedMB := resp["freed_mb"].(float64)
	if freedMB < 2.9 {
		t.Errorf("freed_mb: got %.1f, want ~3.0", freedMB)
	}

	// Verify remaining files.
	entries, _ := os.ReadDir("captures")
	remaining := 0
	for _, e := range entries {
		if !e.IsDir() {
			remaining++
		}
	}
	if remaining != 2 {
		t.Errorf("remaining files: got %d, want 2", remaining)
	}
}

func TestReplayMetadataAPI(t *testing.T) {
	// Save and restore global state.
	replayPlayerMu.Lock()
	origPkts := replayLoadedPkts
	origMeta := replayMetadata
	origFile := replayLoadedFile
	replayPlayerMu.Unlock()
	defer func() {
		replayPlayerMu.Lock()
		replayLoadedPkts = origPkts
		replayMetadata = origMeta
		replayLoadedFile = origFile
		replayPlayerMu.Unlock()
	}()

	now := time.Now()
	replayPlayerMu.Lock()
	replayLoadedPkts = []*replay.Packet{
		{Timestamp: now, Method: "GET", Path: "/test", Host: "localhost", IsRequest: true,
			Headers: map[string]string{}},
		{Timestamp: now.Add(time.Second), Method: "POST", Path: "/api", Host: "localhost", IsRequest: true,
			Headers: map[string]string{}},
	}
	replayMetadata = nil // Force recompute.
	replayPlayerMu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/replay/metadata", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayMetadata(w, r)
	})

	req := httptest.NewRequest("GET", "/admin/api/replay/metadata", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("metadata status: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if int(resp["total_packets"].(float64)) != 2 {
		t.Errorf("total_packets: got %v, want 2", resp["total_packets"])
	}
	if int(resp["total_requests"].(float64)) != 2 {
		t.Errorf("total_requests: got %v, want 2", resp["total_requests"])
	}
}

func TestReplayStatusIncludesMetadata(t *testing.T) {
	replayPlayerMu.Lock()
	origPkts := replayLoadedPkts
	origMeta := replayMetadata
	origFile := replayLoadedFile
	origPlayer := replayPlayer
	replayPlayerMu.Unlock()
	defer func() {
		replayPlayerMu.Lock()
		replayLoadedPkts = origPkts
		replayMetadata = origMeta
		replayLoadedFile = origFile
		replayPlayer = origPlayer
		replayPlayerMu.Unlock()
	}()

	replayPlayerMu.Lock()
	replayLoadedPkts = []*replay.Packet{
		{Timestamp: time.Now(), Method: "GET", Path: "/", IsRequest: true, Headers: map[string]string{}},
	}
	replayMetadata = map[string]interface{}{
		"total_packets": 1,
	}
	replayLoadedFile = "test.pcap"
	replayPlayer = nil
	replayPlayerMu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/api/replay/status", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayStatus(w, r)
	})

	req := httptest.NewRequest("GET", "/admin/api/replay/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status code: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["metadata"] == nil {
		t.Error("status response should include metadata when packets are loaded")
	}
	meta := resp["metadata"].(map[string]interface{})
	if int(meta["total_packets"].(float64)) != 1 {
		t.Errorf("metadata.total_packets: got %v, want 1", meta["total_packets"])
	}
}

// ---------------------------------------------------------------------------
// NightmareState tests
// ---------------------------------------------------------------------------

func TestNightmareState_Default(t *testing.T) {
	ns := &NightmareState{}
	snap := ns.Snapshot()
	if snap["server"] || snap["scanner"] || snap["proxy"] {
		t.Error("nightmare modes should be off by default")
	}
	if ns.IsAnyActive() {
		t.Error("IsAnyActive should be false by default")
	}
}

func TestNightmareState_ToggleModes(t *testing.T) {
	ns := &NightmareState{}
	ns.mu.Lock()
	ns.ServerActive = true
	ns.mu.Unlock()

	if !ns.IsAnyActive() {
		t.Error("IsAnyActive should be true when server is active")
	}

	modes := ns.ActiveModes()
	if len(modes) != 1 || modes[0] != "Server" {
		t.Errorf("ActiveModes: got %v, want [Server]", modes)
	}

	ns.mu.Lock()
	ns.ScannerActive = true
	ns.ProxyActive = true
	ns.mu.Unlock()

	modes = ns.ActiveModes()
	if len(modes) != 3 {
		t.Errorf("ActiveModes: got %d, want 3", len(modes))
	}

	snap := ns.Snapshot()
	if !snap["server"] || !snap["scanner"] || !snap["proxy"] {
		t.Error("all modes should be active")
	}
}

func TestNightmareState_Snapshot(t *testing.T) {
	ns := &NightmareState{}
	ns.mu.Lock()
	ns.ProxyActive = true
	ns.mu.Unlock()

	snap := ns.Snapshot()
	if snap["server"] {
		t.Error("server should be false")
	}
	if snap["scanner"] {
		t.Error("scanner should be false")
	}
	if !snap["proxy"] {
		t.Error("proxy should be true")
	}
}

func TestFeatureFlags_SetAll(t *testing.T) {
	ff := NewFeatureFlags()
	// Disable all (recorder is excluded from SetAll — it stays at its prior value)
	ff.SetAll(false)
	snap := ff.Snapshot()
	for name, enabled := range snap {
		if name == "recorder" {
			// recorder is excluded from SetAll; it keeps its NewFeatureFlags() default (true)
			if !enabled {
				t.Errorf("flag %q should be unchanged (true) after SetAll(false)", name)
			}
			continue
		}
		if enabled {
			t.Errorf("flag %q should be disabled after SetAll(false)", name)
		}
	}
	// Enable all
	ff.SetAll(true)
	snap = ff.Snapshot()
	for name, enabled := range snap {
		if !enabled {
			t.Errorf("flag %q should be enabled after SetAll(true)", name)
		}
	}
	// Verify recorder stays false if explicitly set before SetAll
	ff.Set("recorder", false)
	ff.SetAll(true)
	snap = ff.Snapshot()
	if snap["recorder"] {
		t.Error("recorder should remain false after SetAll(true) when explicitly disabled")
	}
}

// ---------------------------------------------------------------------------
// Nightmare API tests
// ---------------------------------------------------------------------------

func TestAPI_NightmareGet(t *testing.T) {
	// Reset state
	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = false
	globalNightmare.ScannerActive = false
	globalNightmare.ProxyActive = false
	globalNightmare.mu.Unlock()

	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	req := httptest.NewRequest("GET", "/admin/api/nightmare", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}

	var resp map[string]bool
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["server"] || resp["scanner"] || resp["proxy"] {
		t.Error("all modes should be off initially")
	}
}

func TestAPI_NightmareToggleServer(t *testing.T) {
	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = false
	globalNightmare.ScannerActive = false
	globalNightmare.ProxyActive = false
	globalNightmare.mu.Unlock()

	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	body := `{"mode":"server","enabled":true}`
	req := httptest.NewRequest("POST", "/admin/api/nightmare", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d", rec.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Error("expected ok: true")
	}

	state := resp["state"].(map[string]interface{})
	if state["server"] != true {
		t.Error("server nightmare should be active")
	}
	if state["scanner"] == true || state["proxy"] == true {
		t.Error("scanner and proxy should not be affected")
	}

	// Restore
	globalNightmare.mu.Lock()
	globalNightmare.ServerActive = false
	globalNightmare.mu.Unlock()
}

func TestAPI_NightmareInvalidMode(t *testing.T) {
	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	body := `{"mode":"invalid","enabled":true}`
	req := httptest.NewRequest("POST", "/admin/api/nightmare", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Errorf("expected 400 for invalid mode, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Password change tests
// ---------------------------------------------------------------------------

func TestChangePassword_Success(t *testing.T) {
	// Set a known password
	SetAdminPassword("testpass123")
	// Clear sessions for clean test
	sessions = sync.Map{}

	err := ChangePassword("testpass123", "newpass456")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify new password works
	if !checkPassword("newpass456") {
		t.Error("new password should work after change")
	}
	if checkPassword("testpass123") {
		t.Error("old password should not work after change")
	}
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	SetAdminPassword("correctpw")

	err := ChangePassword("wrongpw", "newpw")
	if err == nil {
		t.Error("expected error for wrong current password")
	}
}

func TestAPI_PasswordChange(t *testing.T) {
	SetAdminPassword("apitest123")

	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	body := `{"current":"apitest123","new":"newpass789"}`
	req := httptest.NewRequest("POST", "/admin/api/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status: %d, body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Error("expected ok: true")
	}
}

func TestAPI_PasswordChangeTooShort(t *testing.T) {
	SetAdminPassword("apitest123")

	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	body := `{"current":"apitest123","new":"ab"}`
	req := httptest.NewRequest("POST", "/admin/api/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Errorf("expected 400 for short password, got %d", rec.Code)
	}
}

func TestAPI_PasswordChangeWrongCurrent(t *testing.T) {
	SetAdminPassword("correct789")

	mux := http.NewServeMux()
	s := &Server{}
	RegisterAdminRoutes(mux, s)

	body := `{"current":"wrong","new":"newpass"}`
	req := httptest.NewRequest("POST", "/admin/api/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Errorf("expected 401 for wrong password, got %d", rec.Code)
	}
}

func TestGetNightmareState_Singleton(t *testing.T) {
	ns := GetNightmareState()
	if ns == nil {
		t.Fatal("GetNightmareState should not return nil")
	}
	// Should be the same instance
	ns2 := GetNightmareState()
	if ns != ns2 {
		t.Error("GetNightmareState should return the same singleton")
	}
}
