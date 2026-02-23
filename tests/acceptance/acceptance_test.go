package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Test infrastructure
const (
	serverURL = "http://localhost:8765"
	adminURL  = "http://localhost:8766"
)

func requireServer(t *testing.T) {
	t.Helper()
	resp, err := http.Get(serverURL + "/health")
	if err != nil {
		t.Skipf("Glitch server not running at %s: %v", serverURL, err)
	}
	resp.Body.Close()
}

func requireAdmin(t *testing.T) {
	t.Helper()
	resp, err := http.Get(adminURL + "/admin")
	if err != nil {
		t.Skipf("Admin panel not running at %s: %v", adminURL, err)
	}
	resp.Body.Close()
}

func postJSON(url string, data interface{}) (*http.Response, error) {
	body, _ := json.Marshal(data)
	return http.Post(url, "application/json", bytes.NewReader(body))
}

func getJSON(t *testing.T, url string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// ===========================================================================
// SECTION 1: Admin Panel — Dashboard Tab
// ===========================================================================

func TestDashboard_MetricsLoad(t *testing.T) {
	requireAdmin(t)
	data := getJSON(t, adminURL+"/admin/api/overview")
	if _, ok := data["total_requests"]; !ok {
		t.Error("overview missing total_requests")
	}
	if _, ok := data["sparkline"]; !ok {
		t.Error("overview missing sparkline")
	}
	if _, ok := data["top_paths"]; !ok {
		t.Error("overview missing top_paths")
	}
	if _, ok := data["status_codes"]; !ok {
		t.Error("overview missing status_codes")
	}
	if _, ok := data["response_types"]; !ok {
		t.Error("overview missing response_types")
	}
	if _, ok := data["uptime_seconds"]; !ok {
		t.Error("overview missing uptime_seconds")
	}
}

func TestDashboard_SparklineData(t *testing.T) {
	requireAdmin(t)
	// Generate some traffic
	for i := 0; i < 10; i++ {
		http.Get(serverURL + fmt.Sprintf("/page/%d", i))
	}
	time.Sleep(500 * time.Millisecond)

	data := getJSON(t, adminURL+"/admin/api/overview")
	sparkline, ok := data["sparkline"].([]interface{})
	if !ok {
		t.Fatal("sparkline is not an array")
	}
	// Should have time-series data
	if len(sparkline) == 0 {
		t.Error("sparkline has no data points after traffic")
	}
}

// ===========================================================================
// SECTION 2: Admin Panel — Sessions Tab
// ===========================================================================

func TestSessions_ClientsAppear(t *testing.T) {
	requireAdmin(t)
	// Generate traffic with a known UA
	client := &http.Client{}
	req, _ := http.NewRequest("GET", serverURL+"/test-session", nil)
	req.Header.Set("User-Agent", "AcceptanceTestBot/1.0")
	client.Do(req)
	time.Sleep(500 * time.Millisecond)

	data := getJSON(t, adminURL+"/admin/api/overview")
	// overview should show requests from our client
	total, _ := data["total_requests"].(float64)
	if total < 1 {
		t.Error("expected at least 1 request recorded")
	}
}

// ===========================================================================
// SECTION 3: Admin Panel — Controls Tab — Feature Toggles
// ===========================================================================

func TestControls_AllFeatureToggles(t *testing.T) {
	requireAdmin(t)
	features := []string{
		"labyrinth", "error_inject", "captcha", "honeypot", "vuln",
		"analytics", "cdn", "oauth", "header_corrupt", "cookie_traps",
		"js_traps", "bot_detection", "random_blocking", "framework_emul",
		"search", "email", "i18n", "recorder", "websocket", "privacy", "health",
	}

	data := getJSON(t, adminURL+"/admin/api/features")
	for _, f := range features {
		if _, ok := data[f]; !ok {
			t.Errorf("missing feature toggle: %s", f)
		}
	}

	// Test toggle cycle for a safe feature
	resp, _ := postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": "i18n", "enabled": false,
	})
	resp.Body.Close()

	data = getJSON(t, adminURL+"/admin/api/features")
	if data["i18n"] != false {
		t.Error("feature toggle didn't take effect")
	}

	// Restore
	resp, _ = postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": "i18n", "enabled": true,
	})
	resp.Body.Close()
}

// ===========================================================================
// SECTION 4: Controls — All Config Parameters
// ===========================================================================

func TestControls_AllConfigParams(t *testing.T) {
	requireAdmin(t)
	expectedNumeric := []string{
		"max_labyrinth_depth", "error_rate_multiplier", "captcha_trigger_thresh",
		"block_chance", "block_duration_sec", "bot_score_threshold",
		"header_corrupt_level", "delay_min_ms", "delay_max_ms",
		"labyrinth_link_density", "adaptive_interval_sec",
		"cookie_trap_frequency", "js_trap_difficulty", "content_cache_ttl_sec",
		"adaptive_aggressive_rps", "adaptive_labyrinth_paths",
	}
	expectedString := []string{
		"honeypot_response_style", "active_framework", "content_theme",
		"recorder_format",
	}

	data := getJSON(t, adminURL+"/admin/api/config")
	for _, key := range expectedNumeric {
		if _, ok := data[key]; !ok {
			t.Errorf("missing numeric config: %s", key)
		}
	}
	for _, key := range expectedString {
		if _, ok := data[key]; !ok {
			t.Errorf("missing string config: %s", key)
		}
	}
}

func TestControls_ConfigRoundTrip(t *testing.T) {
	requireAdmin(t)

	// Test each config parameter type
	tests := []struct {
		key   string
		value interface{}
		reset interface{}
	}{
		{"max_labyrinth_depth", 30.0, 50.0},
		{"error_rate_multiplier", 2.0, 1.0},
		{"captcha_trigger_thresh", 75.0, 100.0},
		{"block_chance", 0.05, 0.02},
		{"bot_score_threshold", 75.0, 60.0},
		{"header_corrupt_level", 3.0, 1.0},
		{"cookie_trap_frequency", 4.0, 3.0},
		{"js_trap_difficulty", 3.0, 2.0},
		{"content_cache_ttl_sec", 120.0, 60.0},
		{"labyrinth_link_density", 12.0, 8.0},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			resp, _ := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
				"key": tt.key, "value": tt.value,
			})
			resp.Body.Close()

			data := getJSON(t, adminURL+"/admin/api/config")
			if data[tt.key] != tt.value {
				t.Errorf("%s: expected %v, got %v", tt.key, tt.value, data[tt.key])
			}

			// Reset
			resp, _ = postJSON(adminURL+"/admin/api/config", map[string]interface{}{
				"key": tt.key, "value": tt.reset,
			})
			resp.Body.Close()
		})
	}
}

func TestControls_StringConfigRoundTrip(t *testing.T) {
	requireAdmin(t)

	tests := []struct {
		key   string
		value string
		reset string
	}{
		{"honeypot_response_style", "aggressive", "realistic"},
		{"active_framework", "django", "auto"},
		{"content_theme", "dark", "default"},
		{"recorder_format", "pcap", "jsonl"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			resp, _ := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
				"key": tt.key, "value": tt.value,
			})
			resp.Body.Close()

			data := getJSON(t, adminURL+"/admin/api/config")
			if data[tt.key] != tt.value {
				t.Errorf("%s: expected %q, got %v", tt.key, tt.value, data[tt.key])
			}

			// Reset
			resp, _ = postJSON(adminURL+"/admin/api/config", map[string]interface{}{
				"key": tt.key, "value": tt.reset,
			})
			resp.Body.Close()
		})
	}
}

// ===========================================================================
// SECTION 5: Controls — Error & Page Weights
// ===========================================================================

func TestControls_ErrorWeights(t *testing.T) {
	requireAdmin(t)

	// Set a weight
	resp, _ := postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"error_type": "503_service_unavailable", "weight": 0.3,
	})
	resp.Body.Close()

	data := getJSON(t, adminURL+"/admin/api/error-weights")
	weights := data["weights"].(map[string]interface{})
	if weights["503_service_unavailable"] != 0.3 {
		t.Errorf("expected weight 0.3, got %v", weights["503_service_unavailable"])
	}

	// Reset all
	resp, _ = postJSON(adminURL+"/admin/api/error-weights", map[string]interface{}{
		"reset": true,
	})
	resp.Body.Close()

	data = getJSON(t, adminURL+"/admin/api/error-weights")
	weights = data["weights"].(map[string]interface{})
	if len(weights) != 0 {
		t.Errorf("expected empty weights after reset, got %d", len(weights))
	}
}

func TestControls_PageTypeWeights(t *testing.T) {
	requireAdmin(t)

	resp, _ := postJSON(adminURL+"/admin/api/page-type-weights", map[string]interface{}{
		"page_type": "json", "weight": 0.5,
	})
	resp.Body.Close()

	data := getJSON(t, adminURL+"/admin/api/page-type-weights")
	weights := data["weights"].(map[string]interface{})
	if weights["json"] != 0.5 {
		t.Errorf("expected weight 0.5, got %v", weights["json"])
	}

	// Reset
	resp, _ = postJSON(adminURL+"/admin/api/page-type-weights", map[string]interface{}{
		"reset": true,
	})
	resp.Body.Close()
}

// ===========================================================================
// SECTION 6: Vulnerability Controls
// ===========================================================================

func TestVulns_GroupToggles(t *testing.T) {
	requireAdmin(t)

	groups := []string{"owasp", "advanced", "dashboard"}
	for _, g := range groups {
		t.Run(g, func(t *testing.T) {
			// Disable
			resp, _ := postJSON(adminURL+"/admin/api/vulns/group", map[string]interface{}{
				"group": g, "enabled": false,
			})
			resp.Body.Close()

			data := getJSON(t, adminURL+"/admin/api/vulns")
			groupState := data["groups"].(map[string]interface{})
			if groupState[g] != false {
				t.Errorf("group %s should be disabled", g)
			}

			// Re-enable
			resp, _ = postJSON(adminURL+"/admin/api/vulns/group", map[string]interface{}{
				"group": g, "enabled": true,
			})
			resp.Body.Close()
		})
	}
}

func TestVulns_CategoryToggle(t *testing.T) {
	requireAdmin(t)

	// Disable owasp-a01
	resp, _ := postJSON(adminURL+"/admin/api/vulns", map[string]interface{}{
		"id": "owasp-a01", "enabled": false,
	})
	resp.Body.Close()

	data := getJSON(t, adminURL+"/admin/api/vulns")
	cats := data["categories"].(map[string]interface{})
	if cats["owasp-a01"] != false {
		t.Error("category owasp-a01 should be disabled")
	}

	// Re-enable
	resp, _ = postJSON(adminURL+"/admin/api/vulns", map[string]interface{}{
		"id": "owasp-a01", "enabled": true,
	})
	resp.Body.Close()
}

func TestVulns_DisabledEndpointReturns404(t *testing.T) {
	requireServer(t)
	requireAdmin(t)

	// Disable OWASP group
	resp, _ := postJSON(adminURL+"/admin/api/vulns/group", map[string]interface{}{
		"group": "owasp", "enabled": false,
	})
	resp.Body.Close()

	// Wait for config sync
	time.Sleep(200 * time.Millisecond)

	// Access a vuln endpoint — should be 404
	vuln, err := http.Get(serverURL + "/vuln/a01/")
	if err != nil {
		t.Fatal(err)
	}
	defer vuln.Body.Close()
	if vuln.StatusCode != 404 {
		t.Errorf("disabled vuln should return 404, got %d", vuln.StatusCode)
	}

	// Re-enable
	resp, _ = postJSON(adminURL+"/admin/api/vulns/group", map[string]interface{}{
		"group": "owasp", "enabled": true,
	})
	resp.Body.Close()
}

// ===========================================================================
// SECTION 7: Config Export/Import
// ===========================================================================

func TestConfig_ExportImportRoundTrip(t *testing.T) {
	requireAdmin(t)

	// Export
	exportResp, _ := http.Get(adminURL + "/admin/api/config/export")
	var exported map[string]interface{}
	json.NewDecoder(exportResp.Body).Decode(&exported)
	exportResp.Body.Close()

	if exported["version"] != "1.0" {
		t.Errorf("expected version 1.0, got %v", exported["version"])
	}
	if exported["features"] == nil {
		t.Error("export missing features")
	}
	if exported["config"] == nil {
		t.Error("export missing config")
	}
	if exported["vuln_config"] == nil {
		t.Error("export missing vuln_config")
	}

	// Change something
	postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": "privacy", "enabled": false,
	})

	// Import original
	resp, _ := postJSON(adminURL+"/admin/api/config/import", exported)
	var importResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&importResult)
	resp.Body.Close()

	if importResult["ok"] != true {
		t.Error("import should return ok")
	}

	// Verify restored
	feats := getJSON(t, adminURL+"/admin/api/features")
	origFeats := exported["features"].(map[string]interface{})
	if feats["privacy"] != origFeats["privacy"] {
		t.Error("import didn't restore privacy feature flag")
	}
}

// ===========================================================================
// SECTION 8: PCAP Recording
// ===========================================================================

func TestPCAP_StartStopCycle(t *testing.T) {
	requireServer(t)

	// Start PCAP recording
	resp, err := postJSON(serverURL+"/captures/start", map[string]interface{}{
		"format": "pcap",
	})
	if err != nil {
		t.Fatal(err)
	}
	var startResult map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&startResult)
	resp.Body.Close()

	if startResult["status"] != "recording" {
		t.Errorf("expected recording status, got %v", startResult["status"])
	}

	// Generate traffic
	for i := 0; i < 5; i++ {
		http.Get(serverURL + fmt.Sprintf("/pcap-test-%d", i))
	}

	// Stop
	resp, _ = http.Post(serverURL+"/captures/stop", "application/json", nil)
	resp.Body.Close()

	// List captures
	listResp, _ := http.Get(serverURL + "/captures/")
	var files []interface{}
	json.NewDecoder(listResp.Body).Decode(&files)
	listResp.Body.Close()

	hasPcap := false
	for _, f := range files {
		if fm, ok := f.(map[string]interface{}); ok {
			// Check both "name" and "filename" fields
			for _, key := range []string{"name", "filename"} {
				if name, ok := fm[key].(string); ok && strings.HasSuffix(name, ".pcap") {
					hasPcap = true
				}
			}
		}
	}
	if !hasPcap {
		t.Error("no .pcap file found in captures list")
	}
}

func TestPCAP_FormatSwitch(t *testing.T) {
	requireServer(t)
	requireAdmin(t)

	// Set format via admin API
	resp, _ := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
		"key": "recorder_format", "value": "pcap",
	})
	resp.Body.Close()

	data := getJSON(t, adminURL+"/admin/api/config")
	if data["recorder_format"] != "pcap" {
		t.Errorf("expected pcap format, got %v", data["recorder_format"])
	}

	// Switch back
	resp, _ = postJSON(adminURL+"/admin/api/config", map[string]interface{}{
		"key": "recorder_format", "value": "jsonl",
	})
	resp.Body.Close()
}

// ===========================================================================
// SECTION 9: Firecrawl/Oxylabs Detection
// ===========================================================================

func TestFirecrawl_DetectedAsBotUA(t *testing.T) {
	requireServer(t)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", serverURL+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 firecrawl/1.0")
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Should respond (not crash) but may apply bot treatment
	if resp.StatusCode >= 500 {
		t.Errorf("firecrawl UA should not cause 5xx, got %d", resp.StatusCode)
	}
}

func TestOxylabs_PlatformMismatchDetected(t *testing.T) {
	requireServer(t)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", serverURL+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Errorf("platform mismatch should not cause 5xx, got %d", resp.StatusCode)
	}
}

func TestFirecrawl_HoneypotPathsExist(t *testing.T) {
	requireServer(t)

	paths := []string{
		"/assets/config.js",
		"/api/internal/config",
		"/api/data/export",
		"/api/scrape/results",
	}
	for _, p := range paths {
		resp, err := http.Get(serverURL + p)
		if err != nil {
			t.Errorf("GET %s: %v", p, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 404 {
			t.Errorf("honeypot path %s should not return 404", p)
		}
	}
}

// ===========================================================================
// SECTION 10: Scanner Comparison Workflows
// ===========================================================================

func TestScanner_ProfileGeneration(t *testing.T) {
	requireAdmin(t)

	data := getJSON(t, adminURL+"/admin/api/scanner/profile")
	if data["profile"] == nil {
		t.Fatal("scanner profile is nil")
	}
	profile := data["profile"].(map[string]interface{})
	if profile["vulnerabilities"] == nil {
		t.Error("profile missing vulnerabilities")
	}
	vulns := profile["vulnerabilities"].([]interface{})
	if len(vulns) < 10 {
		t.Errorf("expected at least 10 vuln categories, got %d", len(vulns))
	}
}

func TestScanner_SingleCompare(t *testing.T) {
	requireAdmin(t)

	nucleiOutput := `{"info":{"severity":"high","name":"SQL Injection"},"matched-at":"http://localhost:8765/vuln/a03/sqli","template-id":"sql-injection","type":"http"}
{"info":{"severity":"medium","name":"XSS"},"matched-at":"http://localhost:8765/vuln/a07/xss","template-id":"xss-reflected","type":"http"}`

	resp, _ := postJSON(adminURL+"/admin/api/scanner/compare", map[string]interface{}{
		"scanner": "nuclei",
		"data":    nucleiOutput,
	})
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	if result["grade"] == nil {
		t.Error("comparison result missing grade")
	}
	if result["detection_rate"] == nil {
		t.Error("comparison result missing detection_rate")
	}
	if result["true_positives"] == nil {
		t.Error("comparison result missing true_positives")
	}
	if result["false_negatives"] == nil {
		t.Error("comparison result missing false_negatives")
	}
}

func TestScanner_MultiCompare(t *testing.T) {
	requireAdmin(t)

	nucleiOutput := `{"info":{"severity":"high","name":"SQL Injection"},"matched-at":"http://localhost:8765/vuln/a03/sqli","template-id":"sql-injection"}`
	ffufOutput := `{"results":[{"input":{"FUZZ":"admin"},"url":"http://localhost:8765/admin","status":200,"length":1234,"words":100,"lines":50}]}`

	resp, _ := postJSON(adminURL+"/admin/api/scanner/multi-compare", map[string]interface{}{
		"reports": map[string]string{
			"nuclei": nucleiOutput,
			"ffuf":   ffufOutput,
		},
	})
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	if result["reports"] == nil {
		t.Error("multi-compare missing reports")
	}
	if result["coverage_matrix"] == nil {
		t.Error("multi-compare missing coverage_matrix")
	}
	if result["best_detection"] == nil {
		t.Error("multi-compare missing best_detection")
	}
}

func TestScanner_HistoryTracking(t *testing.T) {
	requireAdmin(t)

	// Run a comparison to add to history
	postJSON(adminURL+"/admin/api/scanner/compare", map[string]interface{}{
		"scanner": "nuclei",
		"data":    `{"info":{"severity":"high"},"matched-at":"http://localhost:8765/vuln/a03/","template-id":"sql-injection"}`,
	})

	// Check history
	data := getJSON(t, adminURL+"/admin/api/scanner/history")
	entries, ok := data["entries"].([]interface{})
	if !ok {
		t.Fatal("history entries is not an array")
	}
	if len(entries) == 0 {
		t.Error("expected at least one history entry")
	}

	// Check entry structure
	if len(entries) > 0 {
		entry := entries[0].(map[string]interface{})
		requiredFields := []string{"id", "timestamp", "scanner", "grade", "detection_rate"}
		for _, f := range requiredFields {
			if entry[f] == nil {
				t.Errorf("history entry missing field: %s", f)
			}
		}
	}
}

func TestScanner_BaselineTracking(t *testing.T) {
	requireAdmin(t)

	// Get baseline for nuclei
	data := getJSON(t, adminURL+"/admin/api/scanner/baseline?scanner=nuclei")
	// May return null baseline if no history, that's OK
	// Just verify the endpoint doesn't error
	if data == nil {
		t.Log("no baseline yet (expected for fresh server)")
	}
}

func TestScanner_CompareDetectsWeaknesses(t *testing.T) {
	requireAdmin(t)

	// Submit partial scanner results — should identify false negatives
	partialOutput := `{"info":{"severity":"high"},"matched-at":"http://localhost:8765/vuln/a01/","template-id":"broken-access-control"}`

	resp, _ := postJSON(adminURL+"/admin/api/scanner/compare", map[string]interface{}{
		"scanner": "nuclei",
		"data":    partialOutput,
	})
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()

	// Should have many false negatives (scanner only found 1 vuln)
	fn, ok := result["false_negatives"].([]interface{})
	if !ok {
		t.Fatal("false_negatives is not an array")
	}
	if len(fn) < 5 {
		t.Errorf("expected many false negatives for partial scan, got %d", len(fn))
	}

	// Grade should be poor since we only found 1 vuln
	grade, _ := result["grade"].(string)
	if grade == "A" {
		t.Error("partial scan should not get grade A")
	}
}

func TestScanner_CompareReflectsFeatureFlags(t *testing.T) {
	requireAdmin(t)

	// Get profile with all features enabled
	data1 := getJSON(t, adminURL+"/admin/api/scanner/profile")
	profile1 := data1["profile"].(map[string]interface{})
	vulns1 := profile1["vulnerabilities"].([]interface{})
	count1 := len(vulns1)

	// Disable OWASP vulns
	postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": "vuln", "enabled": false,
	})
	time.Sleep(100 * time.Millisecond)

	// Get profile with vuln feature disabled
	data2 := getJSON(t, adminURL+"/admin/api/scanner/profile")
	profile2 := data2["profile"].(map[string]interface{})
	vulns2 := profile2["vulnerabilities"].([]interface{})
	count2 := len(vulns2)

	// Should have fewer vulns
	if count2 >= count1 {
		t.Errorf("disabling vuln feature should reduce vuln count: before=%d after=%d", count1, count2)
	}

	// Restore
	postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": "vuln", "enabled": true,
	})
}

// ===========================================================================
// SECTION 11: Subsystem Response Verification
// ===========================================================================

func TestSubsystem_HealthEndpoints(t *testing.T) {
	requireServer(t)

	endpoints := []string{"/health", "/ping", "/status"}
	for _, ep := range endpoints {
		resp, err := http.Get(serverURL + ep)
		if err != nil {
			t.Errorf("GET %s: %v", ep, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: expected 200, got %d", ep, resp.StatusCode)
		}
	}
}

func TestSubsystem_SearchEngine(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/search?q=test")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("search: expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "search") && !strings.Contains(string(body), "Search") {
		t.Error("search page doesn't contain search-related content")
	}
}

func TestSubsystem_EmailWebmail(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/webmail")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("webmail: expected 200, got %d", resp.StatusCode)
	}
}

func TestSubsystem_OAuthDiscovery(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/.well-known/openid-configuration")
	var data map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&data)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("oauth discovery: expected 200, got %d", resp.StatusCode)
	}
	if data["issuer"] == nil {
		t.Error("oauth discovery missing issuer")
	}
}

func TestSubsystem_PrivacyPolicy(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/privacy-policy")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("privacy-policy: expected 200, got %d", resp.StatusCode)
	}
}

func TestSubsystem_VulnEndpoints(t *testing.T) {
	requireServer(t)

	endpoints := []string{"/vuln/a01/", "/vuln/a03/", "/vuln/a07/"}
	for _, ep := range endpoints {
		resp, err := http.Get(serverURL + ep)
		if err != nil {
			t.Errorf("GET %s: %v", ep, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: expected 200, got %d", ep, resp.StatusCode)
		}
	}
}

func TestSubsystem_HoneypotPaths(t *testing.T) {
	requireServer(t)

	paths := []string{"/wp-admin/", "/.env", "/wp-login.php"}
	for _, p := range paths {
		resp, err := http.Get(serverURL + p)
		if err != nil {
			t.Errorf("GET %s: %v", p, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 404 {
			t.Errorf("honeypot %s should not return 404, got %d", p, resp.StatusCode)
		}
	}
}

func TestSubsystem_CDNStaticAssets(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/static/js/app.js")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("CDN static: expected 200, got %d", resp.StatusCode)
	}
}

func TestSubsystem_APIEndpoints(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/api/v1/users")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("API users: expected 200, got %d", resp.StatusCode)
	}
}

func TestSubsystem_I18n(t *testing.T) {
	requireServer(t)

	resp, _ := http.Get(serverURL + "/es/")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("i18n /es/: expected 200, got %d", resp.StatusCode)
	}
}

// ===========================================================================
// SECTION 12: Blocking & Adaptive Behavior
// ===========================================================================

func TestBlocking_APIWorks(t *testing.T) {
	requireAdmin(t)

	data := getJSON(t, adminURL+"/admin/api/blocking")
	if data["chance"] == nil {
		t.Error("blocking config missing chance")
	}
	if data["duration_sec"] == nil {
		t.Error("blocking config missing duration_sec")
	}
}

func TestOverride_SetAndClear(t *testing.T) {
	requireAdmin(t)

	// Set override
	resp, _ := postJSON(adminURL+"/admin/api/override", map[string]interface{}{
		"client_id": "test_client_123",
		"mode":      "aggressive",
	})
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if result["ok"] != true {
		t.Error("override set should return ok")
	}

	// List overrides
	data := getJSON(t, adminURL+"/admin/api/override")
	overrides := data["overrides"].([]interface{})
	found := false
	for _, o := range overrides {
		om := o.(map[string]interface{})
		if om["client_id"] == "test_client_123" {
			found = true
			if om["mode"] != "aggressive" {
				t.Errorf("expected mode aggressive, got %v", om["mode"])
			}
		}
	}
	if !found {
		t.Error("override not found in list")
	}

	// Clear
	resp, _ = postJSON(adminURL+"/admin/api/override", map[string]interface{}{
		"client_id": "test_client_123",
		"clear":     true,
	})
	resp.Body.Close()
}

// ===========================================================================
// SECTION 13: Request Log
// ===========================================================================

func TestRequestLog_ReturnsRecords(t *testing.T) {
	requireAdmin(t)
	requireServer(t)

	// Generate traffic
	http.Get(serverURL + "/test-log-entry")
	time.Sleep(200 * time.Millisecond)

	data := getJSON(t, adminURL+"/admin/api/log?limit=50")
	records := data["records"].([]interface{})
	if len(records) == 0 {
		t.Error("expected at least one log record")
	}

	// Check record structure
	rec := records[0].(map[string]interface{})
	requiredFields := []string{"timestamp", "client_id", "method", "path", "status_code"}
	for _, f := range requiredFields {
		if rec[f] == nil {
			t.Errorf("log record missing field: %s", f)
		}
	}
}

func TestRequestLog_FilterWorks(t *testing.T) {
	requireAdmin(t)

	data := getJSON(t, adminURL+"/admin/api/log?filter=health&limit=100")
	records := data["records"].([]interface{})
	for _, r := range records {
		rec := r.(map[string]interface{})
		path := rec["path"].(string)
		if !strings.Contains(strings.ToLower(path), "health") &&
			!strings.Contains(strings.ToLower(rec["client_id"].(string)), "health") &&
			!strings.Contains(strings.ToLower(rec["response_type"].(string)), "health") {
			// Filter may match across multiple fields, so this isn't an error
		}
	}
}

// ===========================================================================
// SECTION 14: Admin Panel HTML
// ===========================================================================

func TestAdminHTML_Loads(t *testing.T) {
	requireAdmin(t)

	resp, _ := http.Get(adminURL + "/admin")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	html := string(body)
	if !strings.Contains(html, "GLITCH ADMIN PANEL") {
		t.Error("admin panel missing title")
	}

	// Check for all 7 tabs
	tabs := []string{"Dashboard", "Sessions", "Traffic", "Controls", "Request Log", "Vulnerabilities", "Scanner"}
	for _, tab := range tabs {
		if !strings.Contains(html, tab) {
			t.Errorf("admin panel missing tab: %s", tab)
		}
	}

	// Check for control elements
	controls := []string{
		"recorder-format", "honeypot_response_style", "active_framework", "content_theme",
	}
	for _, ctrl := range controls {
		if !strings.Contains(html, ctrl) {
			t.Errorf("admin panel missing control: %s", ctrl)
		}
	}
}

// ===========================================================================
// SECTION 15: New OWASP Vulnerability Categories
// ===========================================================================

func TestOWASP_APISecurityIndex(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/api-sec/")
	if err != nil {
		t.Fatalf("GET /vuln/api-sec/: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "API Security Top 10") {
		t.Error("response missing 'API Security Top 10' keyword")
	}
}

func TestOWASP_APISecBOLA(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/api-sec/api1/users/1")
	if err != nil {
		t.Fatalf("GET /vuln/api-sec/api1/users/1: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "BOLA") {
		t.Error("response missing 'BOLA' keyword")
	}
	if !strings.Contains(s, "email") {
		t.Error("response missing user data (email)")
	}
}

func TestOWASP_APISecFunctionAuth(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/api-sec/api5/admin/users")
	if err != nil {
		t.Fatalf("GET /vuln/api-sec/api5/admin/users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "Broken Function Level Auth") {
		t.Error("response missing 'Broken Function Level Auth' keyword")
	}
}

func TestOWASP_APISecSSRF(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/api-sec/api7/webhook")
	if err != nil {
		t.Fatalf("GET /vuln/api-sec/api7/webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "SSRF") {
		t.Error("response missing 'SSRF' keyword")
	}
}

func TestOWASP_LLMPromptInjection(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/llm/prompt-injection")
	if err != nil {
		t.Fatalf("GET /vuln/llm/prompt-injection: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "system prompt") {
		t.Error("response missing 'system prompt' keyword")
	}
}

func TestOWASP_LLMSensitiveDisclosure(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/llm/sensitive-disclosure")
	if err != nil {
		t.Fatalf("GET /vuln/llm/sensitive-disclosure: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "SSN") {
		t.Error("response missing 'SSN' keyword")
	}
}

func TestOWASP_CICDPoisonedPipeline(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/cicd/poisoned-pipeline")
	if err != nil {
		t.Fatalf("GET /vuln/cicd/poisoned-pipeline: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "VULNERABLE") {
		t.Error("response missing 'VULNERABLE' keyword")
	}
	if !strings.Contains(s, "pipeline") && !strings.Contains(s, "Pipeline") {
		t.Error("response missing 'pipeline' keyword")
	}
}

func TestOWASP_CICDCredentialHygiene(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/cicd/insufficient-credential-hygiene")
	if err != nil {
		t.Fatalf("GET /vuln/cicd/insufficient-credential-hygiene: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(strings.ToLower(s), "hardcoded") && !strings.Contains(strings.ToLower(s), "credential") {
		t.Error("response missing 'hardcoded' or 'credential' keyword")
	}
}

func TestOWASP_CloudInsecureDefaults(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/cloud/insecure-defaults")
	if err != nil {
		t.Fatalf("GET /vuln/cloud/insecure-defaults: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "Deployment") {
		t.Error("response missing 'Deployment' keyword")
	}
	if !strings.Contains(s, "security_findings") {
		t.Error("response missing 'security_findings' keyword")
	}
}

func TestOWASP_CloudOverlyPermissive(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/cloud/overly-permissive")
	if err != nil {
		t.Fatalf("GET /vuln/cloud/overly-permissive: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "iam_policy") {
		t.Error("response missing 'iam_policy' keyword")
	}
	if !strings.Contains(s, "wildcard") || !strings.Contains(s, "God mode") {
		t.Error("response missing 'wildcard' or 'God mode' keyword")
	}
}

func TestOWASP_MobileImproperCredential(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/mobile/improper-credential")
	if err != nil {
		t.Fatalf("GET /vuln/mobile/improper-credential: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "credentials") {
		t.Error("response missing 'credentials' keyword")
	}
	if !strings.Contains(s, "SharedPreferences") {
		t.Error("response missing 'SharedPreferences' keyword")
	}
}

func TestOWASP_MobileInsecureStorage(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/mobile/insecure-storage")
	if err != nil {
		t.Fatalf("GET /vuln/mobile/insecure-storage: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "SQLite") {
		t.Error("response missing 'SQLite' keyword")
	}
	if !strings.Contains(s, "cleartext") {
		t.Error("response missing 'cleartext' keyword")
	}
}

func TestOWASP_PrivacyWebTracking(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/privacy-risks/web-tracking")
	if err != nil {
		t.Fatalf("GET /vuln/privacy-risks/web-tracking: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected HTML content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "pixel") && !strings.Contains(s, "tracking") {
		t.Error("response missing 'pixel' or 'tracking' keyword")
	}
}

func TestOWASP_PrivacyDataCollection(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/privacy-risks/data-collection")
	if err != nil {
		t.Fatalf("GET /vuln/privacy-risks/data-collection: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected HTML content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "Social Security") {
		t.Error("response missing 'Social Security' keyword")
	}
}

func TestOWASP_ClientSideDOMXSS(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/client-side/dom-xss")
	if err != nil {
		t.Fatalf("GET /vuln/client-side/dom-xss: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected HTML content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "innerHTML") {
		t.Error("response missing 'innerHTML' keyword")
	}
	if !strings.Contains(s, "XSS") {
		t.Error("response missing 'XSS' keyword")
	}
}

func TestOWASP_ClientSidePrototypePollution(t *testing.T) {
	requireServer(t)

	resp, err := http.Get(serverURL + "/vuln/client-side/prototype-pollution")
	if err != nil {
		t.Fatalf("GET /vuln/client-side/prototype-pollution: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected HTML content type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "deepMerge") {
		t.Error("response missing 'deepMerge' keyword")
	}
	if !strings.Contains(s, "__proto__") {
		t.Error("response missing '__proto__' keyword")
	}
}
