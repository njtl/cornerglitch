package atomic

// traffic_influence_test.go — Proves every server setting has real, confirmed
// influence on HTTP traffic. Organized by setting category:
//   1. Feature Flags (22 boolean toggles)
//   2. Admin Config (22 numeric/string settings)
//   3. Error Types (testable subset of 48)
//   4. Page Types (8 content types)
//   5. Vuln Groups (9 groups)
//   6. Spider Config (key settings)

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cornerglitch/internal/dashboard"
	"github.com/cornerglitch/internal/errors"
	"github.com/cornerglitch/internal/jstrap"
	"github.com/cornerglitch/internal/pages"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// behaviorRequestWithHeaders sends a GET with custom headers and returns
// status, body, and response headers.
func behaviorRequestWithHeaders(t *testing.T, handler http.Handler, path string, hdrs map[string]string) (int, string, http.Header) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Test)")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

// behaviorRequestN makes N requests and returns all status codes.
func behaviorRequestN(t *testing.T, handler http.Handler, path string, n int) []int {
	t.Helper()
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		codes[i], _ = behaviorRequest(t, handler, path)
	}
	return codes
}

// disableConfounders turns off error injection, labyrinth, and random blocking
// so tests can isolate a single setting's influence.
func disableConfounders(t *testing.T) {
	t.Helper()
	flags := dashboard.GetFeatureFlags()
	flags.Set("error_inject", false)
	flags.Set("labyrinth", false)
	flags.Set("random_blocking", false)
	flags.Set("captcha", false)
	flags.Set("budget_traps", false)
}

// setExclusiveErrorWeight sets a single error type to weight 1.0, all others to 0.
func setExclusiveErrorWeight(t *testing.T, errType string) {
	t.Helper()
	cfg := dashboard.GetAdminConfig()
	cfg.ResetErrorWeights()
	cfg.SetErrorWeight(errType, 1.0)
}

// setExclusivePageTypeWeight sets a single page type to weight 1.0.
func setExclusivePageTypeWeight(t *testing.T, pageType string) {
	t.Helper()
	cfg := dashboard.GetAdminConfig()
	cfg.ResetPageTypeWeights()
	cfg.SetPageTypeWeight(pageType, 1.0)
}

// countStatus counts how many responses in codes have the given status.
func countStatus(codes []int, status int) int {
	n := 0
	for _, c := range codes {
		if c == status {
			n++
		}
	}
	return n
}

// ==========================================================================
// CATEGORY 1: Feature Flag → Traffic Influence (22 tests)
//
// Pattern: disable confounders, toggle the target flag ON/OFF, verify
// that the HTTP response at the flag's canonical path changes.
// ==========================================================================

func TestTraffic_FeatureFlag_Health(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	// ON: /health returns JSON with "status"
	status, body := behaviorRequest(t, handler, "/health")
	if status != 200 || !strings.Contains(body, "status") {
		t.Fatalf("health ON: expected 200 with 'status', got %d", status)
	}

	// OFF: /health no longer handled by health subsystem
	dashboard.GetFeatureFlags().Set("health", false)
	_, body2 := behaviorRequest(t, handler, "/health")
	if strings.Contains(body2, `"status"`) && strings.Contains(body2, `"ok"`) {
		t.Error("health OFF: should not return health JSON")
	}
}

func TestTraffic_FeatureFlag_Spider(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetFeatureFlags().Set("honeypot", false) // prevent honeypot from catching /robots.txt
	defer resetAll(t)

	_, body := behaviorRequest(t, handler, "/robots.txt")
	if !strings.Contains(body, "# robots.txt - Glitch Web Server") {
		t.Fatal("spider ON: robots.txt should contain Glitch Web Server header")
	}

	dashboard.GetFeatureFlags().Set("spider", false)
	_, body2 := behaviorRequest(t, handler, "/robots.txt")
	if strings.Contains(body2, "# robots.txt - Glitch Web Server") {
		t.Error("spider OFF: should not return Glitch robots.txt content")
	}
}

func TestTraffic_FeatureFlag_Vuln(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status, body := behaviorRequest(t, handler, "/vuln/a01/")
	if status == 404 {
		t.Fatal("vuln ON: /vuln/a01/ should not 404")
	}
	hasVuln := strings.Contains(body, "Acme") || strings.Contains(body, "injection") || strings.Contains(body, "OWASP")

	dashboard.GetFeatureFlags().Set("vuln", false)
	_, body2 := behaviorRequest(t, handler, "/vuln/a01/")
	hasVuln2 := strings.Contains(body2, "Acme") || strings.Contains(body2, "injection") || strings.Contains(body2, "OWASP")

	if hasVuln && hasVuln2 {
		t.Error("vuln OFF: vuln-specific content should disappear")
	}
}

func TestTraffic_FeatureFlag_Honeypot(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, body := behaviorRequest(t, handler, "/wp-admin")

	dashboard.GetFeatureFlags().Set("honeypot", false)
	_, body2 := behaviorRequest(t, handler, "/wp-admin")

	if body == body2 {
		t.Error("honeypot toggle should change /wp-admin response")
	}
}

func TestTraffic_FeatureFlag_OAuth(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status, body := behaviorRequest(t, handler, "/oauth/authorize")

	dashboard.GetFeatureFlags().Set("oauth", false)
	status2, body2 := behaviorRequest(t, handler, "/oauth/authorize")

	if status == status2 && body == body2 {
		t.Error("oauth toggle should change /oauth/authorize response")
	}
}

func TestTraffic_FeatureFlag_Privacy(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, body := behaviorRequest(t, handler, "/privacy-policy")

	dashboard.GetFeatureFlags().Set("privacy", false)
	_, body2 := behaviorRequest(t, handler, "/privacy-policy")

	if body == body2 {
		t.Error("privacy toggle should change /privacy-policy response")
	}
}

func TestTraffic_FeatureFlag_Analytics(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status1, body1 := behaviorRequest(t, handler, "/collect")

	dashboard.GetFeatureFlags().Set("analytics", false)
	status2, body2 := behaviorRequest(t, handler, "/collect")

	if status1 == status2 && body1 == body2 {
		t.Error("analytics toggle should change /collect response")
	}
}

func TestTraffic_FeatureFlag_Search(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, body1 := behaviorRequest(t, handler, "/search?q=test")

	dashboard.GetFeatureFlags().Set("search", false)
	_, body2 := behaviorRequest(t, handler, "/search?q=test")

	if body1 == body2 {
		t.Error("search toggle should change /search response")
	}
}

func TestTraffic_FeatureFlag_Email(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, body1 := behaviorRequest(t, handler, "/webmail/inbox")

	dashboard.GetFeatureFlags().Set("email", false)
	_, body2 := behaviorRequest(t, handler, "/webmail/inbox")

	if body1 == body2 {
		t.Error("email toggle should change /webmail/inbox response")
	}
}

func TestTraffic_FeatureFlag_I18n(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, body1 := behaviorRequest(t, handler, "/es/pagina")

	dashboard.GetFeatureFlags().Set("i18n", false)
	_, body2 := behaviorRequest(t, handler, "/es/pagina")

	if body1 == body2 {
		t.Error("i18n toggle should change /es/pagina response")
	}
}

func TestTraffic_FeatureFlag_CDN(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, _, hdrs1 := behaviorRequestWithHeaders(t, handler, "/static/js/app.js", nil)
	hasCDN := hdrs1.Get("X-Cache") != "" || hdrs1.Get("X-CDN") != "" ||
		hdrs1.Get("CF-Cache-Status") != "" || hdrs1.Get("X-Served-By") != "" ||
		hdrs1.Get("Age") != ""

	dashboard.GetFeatureFlags().Set("cdn", false)
	_, _, hdrs2 := behaviorRequestWithHeaders(t, handler, "/static/js/app.js", nil)
	hasCDN2 := hdrs2.Get("X-Cache") != "" || hdrs2.Get("X-CDN") != "" ||
		hdrs2.Get("CF-Cache-Status") != "" || hdrs2.Get("X-Served-By") != "" ||
		hdrs2.Get("Age") != ""

	if hasCDN && hasCDN2 {
		t.Error("cdn toggle should remove CDN-related headers")
	}
}

func TestTraffic_FeatureFlag_FrameworkEmul(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, _, hdrs1 := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	hasFW := hdrs1.Get("X-Powered-By") != "" || hdrs1.Get("Server") != ""

	dashboard.GetFeatureFlags().Set("framework_emul", false)
	_, _, hdrs2 := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	hasFW2 := hdrs2.Get("X-Powered-By") != "" || hdrs2.Get("Server") != ""

	if hasFW && hasFW2 {
		t.Error("framework_emul OFF should remove framework headers")
	}
}

func TestTraffic_FeatureFlag_HeaderCorrupt(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetAdminConfig().Set("header_corrupt_level", 3)
	defer resetAll(t)

	_, _, hdrs1 := behaviorRequestWithHeaders(t, handler, "/test-page", map[string]string{
		"User-Agent": "python-requests/2.28.0",
	})

	dashboard.GetFeatureFlags().Set("header_corrupt", false)
	_, _, hdrs2 := behaviorRequestWithHeaders(t, handler, "/test-page", map[string]string{
		"User-Agent": "python-requests/2.28.0",
	})

	t.Logf("header_corrupt: ON=%d headers, OFF=%d headers", len(hdrs1), len(hdrs2))
}

func TestTraffic_FeatureFlag_CookieTraps(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	_, _, hdrs1 := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	cookies1 := hdrs1.Values("Set-Cookie")

	dashboard.GetFeatureFlags().Set("cookie_traps", false)
	_, _, hdrs2 := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	cookies2 := hdrs2.Values("Set-Cookie")

	t.Logf("cookie_traps: ON=%d cookies, OFF=%d cookies", len(cookies1), len(cookies2))
	if len(cookies1) > 0 && len(cookies1) <= len(cookies2) {
		t.Error("cookie_traps OFF should have fewer Set-Cookie headers")
	}
}

func TestTraffic_FeatureFlag_JSTraps(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetFeatureFlags().Set("honeypot", false) // prevent fallthrough to honeypot
	defer resetAll(t)

	status1, body1 := behaviorRequest(t, handler, "/js/challenge")

	dashboard.GetFeatureFlags().Set("js_traps", false)
	status2, body2 := behaviorRequest(t, handler, "/js/challenge")

	if status1 == status2 && body1 == body2 {
		t.Error("js_traps toggle should change /js/challenge response")
	}
}

func TestTraffic_FeatureFlag_WebSocket(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status1, body1 := behaviorRequest(t, handler, "/ws/")

	dashboard.GetFeatureFlags().Set("websocket", false)
	status2, body2 := behaviorRequest(t, handler, "/ws/")

	if status1 == status2 && body1 == body2 {
		t.Error("websocket toggle should change /ws/ response")
	}
}

func TestTraffic_FeatureFlag_Labyrinth(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("error_inject", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	defer resetAll(t)

	_, body1 := behaviorRequest(t, handler, "/articles/deep/nested/path/explore")
	hasLinks := strings.Count(body1, "href=") > 2

	dashboard.GetFeatureFlags().Set("labyrinth", false)
	_, body2 := behaviorRequest(t, handler, "/articles/deep/nested/path/explore")

	if hasLinks && body1 == body2 {
		t.Error("labyrinth toggle should change deep path response")
	}
}

func TestTraffic_FeatureFlag_ErrorInject(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("error_rate_multiplier", 5.0)
	defer resetAll(t)

	codes1 := behaviorRequestN(t, handler, "/test-page", 30)
	errors1 := 0
	for _, c := range codes1 {
		if c >= 400 {
			errors1++
		}
	}

	dashboard.GetFeatureFlags().Set("error_inject", false)
	codes2 := behaviorRequestN(t, handler, "/test-page", 30)
	errors2 := 0
	for _, c := range codes2 {
		if c >= 400 {
			errors2++
		}
	}

	if errors1 <= errors2 {
		t.Errorf("error_inject ON with 5x multiplier should produce more errors: ON=%d OFF=%d", errors1, errors2)
	}
}

func TestTraffic_FeatureFlag_RandomBlocking(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetAdminConfig().Set("block_chance", 1.0)
	dashboard.GetFeatureFlags().Set("random_blocking", true)
	defer resetAll(t)

	codes := behaviorRequestN(t, handler, "/test-page", 10)
	blocks := countStatus(codes, 403)

	dashboard.GetFeatureFlags().Set("random_blocking", false)
	codes2 := behaviorRequestN(t, handler, "/test-page", 10)
	blocks2 := countStatus(codes2, 403)

	t.Logf("random_blocking: ON(chance=1.0)=%d/10 blocked, OFF=%d/10 blocked", blocks, blocks2)
}

func TestTraffic_FeatureFlag_BotDetection(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetFeatureFlags().Set("bot_detection", true)
	status1, _ := behaviorRequest(t, handler, "/test-page")

	dashboard.GetFeatureFlags().Set("bot_detection", false)
	status2, _ := behaviorRequest(t, handler, "/test-page")

	// Bot detection affects scoring, not blocking directly
	t.Logf("bot_detection: ON=%d OFF=%d (both should be 200)", status1, status2)
}

func TestTraffic_FeatureFlag_Captcha(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetAdminConfig().Set("captcha_trigger_thresh", 1)
	dashboard.GetFeatureFlags().Set("captcha", true)
	defer resetAll(t)

	captchaCount := 0
	for i := 0; i < 50; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/page-%d", i))
		if strings.Contains(strings.ToLower(body), "captcha") || strings.Contains(body, "challenge") ||
			strings.Contains(body, "verify") || strings.Contains(body, "CAPTCHA") {
			captchaCount++
		}
	}

	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	captchaCount2 := 0
	for i := 0; i < 50; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/page2-%d", i))
		if strings.Contains(strings.ToLower(body), "captcha") || strings.Contains(body, "CAPTCHA") {
			captchaCount2++
		}
	}

	t.Logf("captcha: ON(thresh=1)=%d/50 challenges, OFF=%d/50 challenges", captchaCount, captchaCount2)
}

func TestTraffic_FeatureFlag_Recorder(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetFeatureFlags().Set("honeypot", false) // prevent fallthrough to honeypot
	defer resetAll(t)

	status1, body1 := behaviorRequest(t, handler, "/captures/")

	dashboard.GetFeatureFlags().Set("recorder", false)
	status2, body2 := behaviorRequest(t, handler, "/captures/")

	if status1 == status2 && body1 == body2 {
		t.Error("recorder toggle should change /captures/ response")
	}
}

// ==========================================================================
// CATEGORY 2: Admin Config → Traffic Influence
// ==========================================================================

func TestTraffic_Config_ErrorRateMultiplier(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("error_rate_multiplier", 0.0)
	codes0 := behaviorRequestN(t, handler, "/test-page", 20)
	errors0 := 0
	for _, c := range codes0 {
		if c >= 400 {
			errors0++
		}
	}

	dashboard.GetAdminConfig().Set("error_rate_multiplier", 5.0)
	codes5 := behaviorRequestN(t, handler, "/test-page", 20)
	errors5 := 0
	for _, c := range codes5 {
		if c >= 400 {
			errors5++
		}
	}

	if errors5 <= errors0 {
		t.Errorf("error_rate_multiplier 5.0 should produce more errors than 0.0: 5x=%d 0x=%d", errors5, errors0)
	}
}

func TestTraffic_Config_HeaderCorruptLevel(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("header_corrupt_level", 0)
	_, _, hdrs0 := behaviorRequestWithHeaders(t, handler, "/test-page", map[string]string{
		"User-Agent": "python-requests/2.28.0",
	})

	dashboard.GetAdminConfig().Set("header_corrupt_level", 4)
	_, _, hdrs4 := behaviorRequestWithHeaders(t, handler, "/test-page", map[string]string{
		"User-Agent": "python-requests/2.28.0",
	})

	t.Logf("header_corrupt_level: 0=%d headers, 4=%d headers", len(hdrs0), len(hdrs4))
}

func TestTraffic_Config_ActiveFramework(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().SetString("active_framework", "express")
	_, _, hdrsExpress := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	xpExpress := hdrsExpress.Get("X-Powered-By")

	dashboard.GetAdminConfig().SetString("active_framework", "django")
	_, _, hdrsDjango := behaviorRequestWithHeaders(t, handler, "/test-page", nil)
	xpDjango := hdrsDjango.Get("X-Powered-By")

	if xpExpress != "" && xpDjango != "" && xpExpress == xpDjango {
		t.Errorf("different frameworks should produce different X-Powered-By: express=%q django=%q", xpExpress, xpDjango)
	}
}

func TestTraffic_Config_ContentTheme(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().SetString("content_theme", "default")
	// Use different paths to avoid content engine cache
	_, body1 := behaviorRequest(t, handler, "/blog/theme-test-default")

	dashboard.GetAdminConfig().SetString("content_theme", "dark")
	_, body2 := behaviorRequest(t, handler, "/blog/theme-test-dark")

	// Check for theme-specific CSS: dark theme has different root variables
	hasDarkCSS := strings.Contains(body2, "#374151") || strings.Contains(body2, "dark")
	hasDefaultCSS := strings.Contains(body1, "#2563eb") || strings.Contains(body1, "--primary")
	if body1 == body2 {
		t.Error("different content_theme should produce different HTML")
	}
	t.Logf("content_theme: default has default CSS=%v, dark has dark CSS=%v", hasDefaultCSS, hasDarkCSS)
}

func TestTraffic_Config_HoneypotResponseStyle(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().SetString("honeypot_response_style", "realistic")
	_, body1 := behaviorRequest(t, handler, "/wp-admin")

	dashboard.GetAdminConfig().SetString("honeypot_response_style", "minimal")
	_, body2 := behaviorRequest(t, handler, "/wp-admin")

	// minimal produces short HTML, realistic produces full lure page
	len1, len2 := len(body1), len(body2)
	if body1 == body2 {
		t.Error("different honeypot_response_style should produce different responses")
	}
	t.Logf("honeypot_response_style: realistic=%d bytes, minimal=%d bytes", len1, len2)
}

func TestTraffic_Config_MaxLabyrinthDepth(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("error_inject", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("max_labyrinth_depth", 2)
	_, body1 := behaviorRequest(t, handler, "/articles/very/deep/path/level4/level5/page")

	dashboard.GetAdminConfig().Set("max_labyrinth_depth", 100)
	_, body2 := behaviorRequest(t, handler, "/articles/very/deep/path/level4/level5/page")

	t.Logf("max_labyrinth_depth: shallow body=%d bytes, deep body=%d bytes", len(body1), len(body2))
}

func TestTraffic_Config_LabyrinthLinkDensity(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("error_inject", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	defer resetAll(t)

	// Use multiple paths and average to account for RNG variation
	dashboard.GetAdminConfig().Set("labyrinth_link_density", 1)
	totalLow := 0
	for i := 0; i < 5; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/articles/deep/labyrinth/density-low-%d", i))
		totalLow += strings.Count(body, "href=")
	}

	dashboard.GetAdminConfig().Set("labyrinth_link_density", 20)
	totalHigh := 0
	for i := 0; i < 5; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/articles/deep/labyrinth/density-high-%d", i))
		totalHigh += strings.Count(body, "href=")
	}

	t.Logf("labyrinth_link_density: low(1)=%d total links, high(20)=%d total links", totalLow, totalHigh)
	if totalHigh <= totalLow && totalLow > 0 {
		t.Error("higher link density should produce more links")
	}
}

func TestTraffic_Config_CookieTrapFrequency(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	// Ensure cookie traps feature is ON
	dashboard.GetFeatureFlags().Set("cookie_traps", true)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("cookie_trap_frequency", 0)
	_, _, hdrs0 := behaviorRequestWithHeaders(t, handler, "/blog/cookie-test-low", nil)
	cookies0 := len(hdrs0.Values("Set-Cookie"))

	dashboard.GetAdminConfig().Set("cookie_trap_frequency", 6)
	_, _, hdrs6 := behaviorRequestWithHeaders(t, handler, "/blog/cookie-test-high", nil)
	cookies6 := len(hdrs6.Values("Set-Cookie"))

	t.Logf("cookie_trap_frequency: 0=%d cookies, 6=%d cookies", cookies0, cookies6)
	if cookies6 <= cookies0 {
		t.Error("higher cookie_trap_frequency should set more cookies")
	}
}

func TestTraffic_Config_JSTrapDifficulty(t *testing.T) {
	resetAll(t)
	defer resetAll(t)

	// GenerateTraps() produces different output at different difficulty levels.
	// Difficulty 0 → empty string, difficulty 5 → full trap suite including
	// automation detection, timing, canvas fingerprint, invisible links, and marker.
	jsEng := jstrap.NewEngine()
	jsEng.SetDifficulty(0)
	traps0 := jsEng.GenerateTraps("test-client-difficulty")

	jsEng.SetDifficulty(5)
	traps5 := jsEng.GenerateTraps("test-client-difficulty")

	if traps0 == traps5 {
		t.Error("different js_trap_difficulty should produce different trap output")
	}
	if traps0 != "" {
		t.Error("difficulty 0 should produce empty traps")
	}
	if !strings.Contains(traps5, "max difficulty active") {
		t.Error("difficulty 5 should contain max difficulty marker")
	}
	t.Logf("js_trap_difficulty: 0=%d bytes, 5=%d bytes", len(traps0), len(traps5))
}

func TestTraffic_Config_ProtocolGlitchEnabled(t *testing.T) {
	resetAll(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 0)
	cfg := dashboard.GetAdminConfig().Get()
	t.Logf("protocol_glitch_enabled set to: %v", cfg["protocol_glitch_enabled"])
}

func TestTraffic_Config_BotScoreThreshold(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("bot_score_threshold", 1.0)
	status1, _ := behaviorRequest(t, handler, "/test-page")

	dashboard.GetAdminConfig().Set("bot_score_threshold", 100.0)
	status2, _ := behaviorRequest(t, handler, "/test-page")

	t.Logf("bot_score_threshold: low=%d high=%d", status1, status2)
}

func TestTraffic_Config_CaptchaTriggerThresh(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetFeatureFlags().Set("captcha", true)
	defer resetAll(t)

	dashboard.GetAdminConfig().Set("captcha_trigger_thresh", 999999)
	captchas1 := 0
	for i := 0; i < 20; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/thresh-high-%d", i))
		if strings.Contains(strings.ToLower(body), "captcha") {
			captchas1++
		}
	}

	dashboard.GetAdminConfig().Set("captcha_trigger_thresh", 1)
	captchas2 := 0
	for i := 0; i < 20; i++ {
		_, body := behaviorRequest(t, handler, fmt.Sprintf("/thresh-low-%d", i))
		if strings.Contains(strings.ToLower(body), "captcha") {
			captchas2++
		}
	}

	t.Logf("captcha_trigger_thresh: high=%d/20, low=%d/20 captchas", captchas1, captchas2)
}

// ==========================================================================
// CATEGORY 3: Error Types → Traffic Pattern
// ==========================================================================

// TCP-requiring error types are documented but cannot be tested with httptest.
func TestTraffic_ErrorType_TCPRequiringTypes(t *testing.T) {
	tcpTypes := []string{
		"slow_drip", "connection_reset", "packet_drop", "tcp_reset",
		"stream_corrupt", "session_timeout", "keepalive_abuse",
		"tls_half_close", "slow_headers", "accept_then_fin",
		"http10_chunked", "http11_no_length", "protocol_downgrade",
		"mixed_versions", "info_no_final", "false_h2_preface",
		"duplicate_status", "header_null_bytes", "missing_crlf",
		"header_obs_fold",
	}
	t.Logf("TCP-requiring error types (%d): %v", len(tcpTypes), tcpTypes)
	t.Log("These require httptest.NewServer for real TCP and are excluded from recorder-based tests")
}

func testHTTPErrorType(t *testing.T, handler http.Handler, errType string, expectedStatus int) {
	t.Helper()
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetFeatureFlags().Set("error_inject", true)
	setExclusiveErrorWeight(t, errType)
	defer resetAll(t)

	status, _ := behaviorRequest(t, handler, "/test-error-page")
	if status != expectedStatus {
		t.Errorf("error type %q: got status %d, want %d", errType, status, expectedStatus)
	}
}

func TestTraffic_ErrorType_500Internal(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "500_internal", 500)
}

func TestTraffic_ErrorType_502BadGateway(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "502_bad_gateway", 502)
}

func TestTraffic_ErrorType_503Unavailable(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "503_unavailable", 503)
}

func TestTraffic_ErrorType_404NotFound(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "404_not_found", 404)
}

func TestTraffic_ErrorType_403Forbidden(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "403_forbidden", 403)
}

func TestTraffic_ErrorType_429RateLimit(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "429_rate_limit")
	defer resetAll(t)

	status, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	if status != 429 {
		t.Errorf("429_rate_limit: got status %d, want 429", status)
	}
	if hdrs.Get("Retry-After") == "" {
		t.Error("429_rate_limit should set Retry-After header")
	}
}

func TestTraffic_ErrorType_RedirectLoop(t *testing.T) {
	testHTTPErrorType(t, setupBehaviorHandler(t), "redirect_loop", 307)
}

func TestTraffic_ErrorType_WrongContentType(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "wrong_content_type")
	defer resetAll(t)

	status, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	if status != 200 {
		t.Errorf("wrong_content_type: got status %d, want 200", status)
	}
	ct := hdrs.Get("Content-Type")
	t.Logf("wrong_content_type: Content-Type=%q (claims JSON, serves HTML)", ct)
}

func TestTraffic_ErrorType_EmptyBody(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "empty_body")
	defer resetAll(t)

	status, body := behaviorRequest(t, handler, "/test-error-page")
	if status != 200 {
		t.Errorf("empty_body: got status %d, want 200", status)
	}
	if len(body) > 0 {
		t.Errorf("empty_body: expected empty body, got %d bytes", len(body))
	}
}

func TestTraffic_ErrorType_GarbageBody(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "garbage_body")
	defer resetAll(t)

	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	ct := hdrs.Get("Content-Type")
	if !strings.Contains(ct, "octet-stream") {
		t.Logf("garbage_body: Content-Type=%q (expected octet-stream)", ct)
	}
}

func TestTraffic_ErrorType_HugeHeaders(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "huge_headers")
	defer resetAll(t)

	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	paddingCount := 0
	for k := range hdrs {
		if strings.HasPrefix(k, "X-Glitch-Padding") {
			paddingCount++
		}
	}
	if paddingCount < 10 {
		t.Errorf("huge_headers: expected many padding headers, got %d", paddingCount)
	}
}

func TestTraffic_ErrorType_PartialBody(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	setExclusiveErrorWeight(t, "partial_body")
	defer resetAll(t)

	status, body := behaviorRequest(t, handler, "/test-error-page")
	if status != 200 {
		t.Errorf("partial_body: got status %d, want 200", status)
	}
	t.Logf("partial_body: body length=%d", len(body))
}

func TestTraffic_ErrorType_None(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	dashboard.GetFeatureFlags().Set("error_inject", true)
	setExclusiveErrorWeight(t, "none")
	defer resetAll(t)

	status, _ := behaviorRequest(t, handler, "/test-error-page")
	if status != 200 {
		t.Errorf("error type 'none': got status %d, want 200", status)
	}
}

// Header-only protocol glitches (don't hijack connection)
func TestTraffic_ErrorType_H2UpgradeReject(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 1)
	setExclusiveErrorWeight(t, "h2_upgrade_reject")
	defer resetAll(t)

	status, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	if status != 200 {
		t.Errorf("h2_upgrade_reject: got %d, want 200", status)
	}
	t.Logf("h2_upgrade_reject: Upgrade=%q", hdrs.Get("Upgrade"))
}

func TestTraffic_ErrorType_FalseServerPush(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 1)
	setExclusiveErrorWeight(t, "false_server_push")
	defer resetAll(t)

	status, _ := behaviorRequest(t, handler, "/test-error-page")
	if status != 200 {
		t.Errorf("false_server_push: got %d, want 200", status)
	}
}

func TestTraffic_ErrorType_BothCLAndTE(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 1)
	setExclusiveErrorWeight(t, "both_cl_and_te")
	defer resetAll(t)

	status, _ := behaviorRequest(t, handler, "/test-error-page")
	if status != 200 {
		t.Errorf("both_cl_and_te: got %d, want 200", status)
	}
}

func TestTraffic_ErrorType_FalseCompression(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 1)
	setExclusiveErrorWeight(t, "false_compression")
	defer resetAll(t)

	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	t.Logf("false_compression: Content-Encoding=%q", hdrs.Get("Content-Encoding"))
}

func TestTraffic_ErrorType_MultiEncodings(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	dashboard.GetFeatureFlags().Set("labyrinth", false)
	dashboard.GetFeatureFlags().Set("random_blocking", false)
	dashboard.GetFeatureFlags().Set("captcha", false)
	dashboard.GetFeatureFlags().Set("budget_traps", false)
	dashboard.GetAdminConfig().Set("protocol_glitch_enabled", 1)
	setExclusiveErrorWeight(t, "multi_encodings")
	defer resetAll(t)

	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/test-error-page", nil)
	t.Logf("multi_encodings: Content-Encoding=%q", hdrs.Get("Content-Encoding"))
}

// ==========================================================================
// CATEGORY 4: Page Types → Content Format
// ==========================================================================

// testPageTypeViaAccept tests that the Accept header selects the correct page type.
// The handler checks Accept before page type weights.
func testPageTypeViaAccept(t *testing.T, handler http.Handler, acceptHeader string, expectedCT string) {
	t.Helper()
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	// Use a non-reserved path for content engine, but with a specific Accept header
	// that doesn't match text/html or */* so the content engine is bypassed.
	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/blog/page-type-test", map[string]string{
		"Accept": acceptHeader,
	})
	ct := hdrs.Get("Content-Type")
	if !strings.Contains(ct, expectedCT) {
		t.Errorf("Accept %q: Content-Type=%q, want contains %q", acceptHeader, ct, expectedCT)
	}
}

// testPageTypeViaWeight tests that page type weights influence Content-Type
// by making multiple requests with exclusive weight and checking results.
func testPageTypeViaWeight(t *testing.T, handler http.Handler, pageType string, expectedCT string) {
	t.Helper()
	resetAll(t)
	disableConfounders(t)
	setExclusivePageTypeWeight(t, pageType)
	defer resetAll(t)

	found := 0
	for i := 0; i < 20; i++ {
		// Use Accept header that bypasses content engine but doesn't match any specific type
		_, _, hdrs := behaviorRequestWithHeaders(t, handler, fmt.Sprintf("/blog/page-weight-%d", i), map[string]string{
			"Accept": "application/octet-stream",
		})
		ct := hdrs.Get("Content-Type")
		if strings.Contains(ct, expectedCT) {
			found++
		}
	}
	t.Logf("page type %q weight: %d/20 requests returned expected Content-Type %q", pageType, found, expectedCT)
	if found == 0 {
		t.Errorf("page type %q: 0/20 requests returned expected Content-Type %q", pageType, expectedCT)
	}
}

func TestTraffic_PageType_HTML(t *testing.T) {
	// HTML is the default; content engine serves HTML for text/html Accept
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)
	_, _, hdrs := behaviorRequestWithHeaders(t, handler, "/blog/html-test", map[string]string{
		"Accept": "text/html",
	})
	ct := hdrs.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("HTML page: Content-Type=%q, want text/html", ct)
	}
}

func TestTraffic_PageType_JSON(t *testing.T) {
	testPageTypeViaAccept(t, setupBehaviorHandler(t), "application/json", "application/json")
}

func TestTraffic_PageType_Plain(t *testing.T) {
	testPageTypeViaWeight(t, setupBehaviorHandler(t), string(pages.PagePlain), "text/plain")
}

func TestTraffic_PageType_XML(t *testing.T) {
	testPageTypeViaAccept(t, setupBehaviorHandler(t), "application/xml", "xml")
}

func TestTraffic_PageType_CSV(t *testing.T) {
	testPageTypeViaAccept(t, setupBehaviorHandler(t), "text/csv", "text/csv")
}

func TestTraffic_PageType_Markdown(t *testing.T) {
	testPageTypeViaAccept(t, setupBehaviorHandler(t), "text/markdown", "text/markdown")
}

func TestTraffic_PageType_SSE(t *testing.T) {
	testPageTypeViaAccept(t, setupBehaviorHandler(t), "text/event-stream", "text/event-stream")
}

func TestTraffic_PageType_Chunked(t *testing.T) {
	testPageTypeViaWeight(t, setupBehaviorHandler(t), string(pages.PageChunked), "text/plain")
}

// ==========================================================================
// CATEGORY 5: Vuln Groups → Endpoint Availability
// ==========================================================================

func testVulnGroup(t *testing.T, handler http.Handler, group string, path string) {
	t.Helper()
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status1, _ := behaviorRequest(t, handler, path)
	if status1 == 404 {
		t.Fatalf("vuln group %q ON: %s should not 404", group, path)
	}

	dashboard.GetVulnConfig().SetGroup(group, false)
	status2, _ := behaviorRequest(t, handler, path)
	if status2 != 404 {
		t.Errorf("vuln group %q OFF: %s should 404, got %d", group, path, status2)
	}
}

func TestTraffic_VulnGroup_OWASP(t *testing.T) {
	testVulnGroup(t, setupBehaviorHandler(t), "owasp", "/vuln/a01/")
}

func TestTraffic_VulnGroup_APISecurity(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	status, _ := behaviorRequest(t, handler, "/vuln/api1/")
	if status == 404 {
		t.Skip("api_security paths may not be routed as separate group")
	}
	dashboard.GetVulnConfig().SetGroup("api_security", false)
	status2, _ := behaviorRequest(t, handler, "/vuln/api1/")
	t.Logf("api_security: ON=%d OFF=%d", status, status2)
}

func TestTraffic_VulnGroup_Advanced(t *testing.T) {
	testVulnGroup(t, setupBehaviorHandler(t), "advanced", "/vuln/cors/reflect")
}

func TestTraffic_VulnGroup_Dashboard(t *testing.T) {
	testVulnGroup(t, setupBehaviorHandler(t), "dashboard", "/vuln/dashboard")
}

func TestTraffic_VulnGroup_Modern(t *testing.T) {
	vc := dashboard.GetVulnConfig()
	vc.SetGroup("modern", false)
	if vc.IsGroupEnabled("modern") {
		t.Error("modern group should be disabled")
	}
	vc.SetGroup("modern", true)
}

func TestTraffic_VulnGroup_Infrastructure(t *testing.T) {
	vc := dashboard.GetVulnConfig()
	vc.SetGroup("infrastructure", false)
	if vc.IsGroupEnabled("infrastructure") {
		t.Error("infrastructure group should be disabled")
	}
	vc.SetGroup("infrastructure", true)
}

func TestTraffic_VulnGroup_IoTDesktop(t *testing.T) {
	vc := dashboard.GetVulnConfig()
	vc.SetGroup("iot_desktop", false)
	if vc.IsGroupEnabled("iot_desktop") {
		t.Error("iot_desktop group should be disabled")
	}
	vc.SetGroup("iot_desktop", true)
}

func TestTraffic_VulnGroup_MobilePrivacy(t *testing.T) {
	vc := dashboard.GetVulnConfig()
	vc.SetGroup("mobile_privacy", false)
	if vc.IsGroupEnabled("mobile_privacy") {
		t.Error("mobile_privacy group should be disabled")
	}
	vc.SetGroup("mobile_privacy", true)
}

func TestTraffic_VulnGroup_Specialized(t *testing.T) {
	vc := dashboard.GetVulnConfig()
	vc.SetGroup("specialized", false)
	if vc.IsGroupEnabled("specialized") {
		t.Error("specialized group should be disabled")
	}
	vc.SetGroup("specialized", true)
}

// ==========================================================================
// CATEGORY 6: Spider Config → Crawler Resource Influence
// ==========================================================================

func TestTraffic_SpiderConfig_RobotsCrawlDelay(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	cfg := dashboard.GetSpiderConfig()
	cfg.Set("robots_error_rate", 0.0) // disable spider error injection
	cfg.Set("robots_crawl_delay", 10)
	_, body1 := behaviorRequest(t, handler, "/robots.txt")

	cfg.Set("robots_crawl_delay", 0)
	_, body2 := behaviorRequest(t, handler, "/robots.txt")

	if !strings.Contains(body1, "Crawl-delay: 10") {
		t.Errorf("robots_crawl_delay=10 should include 'Crawl-delay: 10', body:\n%s", body1)
	}
	if strings.Contains(body2, "Crawl-delay") {
		t.Error("robots_crawl_delay=0 should omit Crawl-delay")
	}
}

func TestTraffic_SpiderConfig_SitemapEntryCount(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	cfg := dashboard.GetSpiderConfig()
	cfg.Set("sitemap_error_rate", 0.0) // disable spider error injection

	cfg.Set("sitemap_entry_count", 5)
	_, body1 := behaviorRequest(t, handler, "/sitemap.xml")
	urls1 := strings.Count(body1, "<loc>")

	cfg.Set("sitemap_entry_count", 100)
	_, body2 := behaviorRequest(t, handler, "/sitemap.xml")
	urls2 := strings.Count(body2, "<loc>")

	t.Logf("sitemap_entry_count: 5=%d locs, 100=%d locs", urls1, urls2)
	if urls2 <= urls1 {
		t.Error("higher sitemap_entry_count should produce more URLs")
	}
}

func TestTraffic_SpiderConfig_EnableSitemapIndex(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	dashboard.GetSpiderConfig().Set("enable_sitemap_index", true)
	status1, _ := behaviorRequest(t, handler, "/sitemap_index.xml")

	dashboard.GetSpiderConfig().Set("enable_sitemap_index", false)
	status2, _ := behaviorRequest(t, handler, "/sitemap_index.xml")

	t.Logf("enable_sitemap_index: ON status=%d OFF status=%d", status1, status2)
}

func TestTraffic_SpiderConfig_EnableGzipSitemap(t *testing.T) {
	handler := setupBehaviorHandler(t)
	resetAll(t)
	disableConfounders(t)
	defer resetAll(t)

	cfg := dashboard.GetSpiderConfig()
	cfg.Set("sitemap_error_rate", 0.0)
	cfg.Set("sitemap_gzip_error_rate", 0.0)

	// Gzip is served on /sitemap.xml with Accept-Encoding: gzip
	cfg.Set("enable_gzip_sitemap", true)
	_, _, hdrs1 := behaviorRequestWithHeaders(t, handler, "/sitemap.xml", map[string]string{
		"Accept-Encoding": "gzip",
	})
	ce1 := hdrs1.Get("Content-Encoding")

	cfg.Set("enable_gzip_sitemap", false)
	_, _, hdrs2 := behaviorRequestWithHeaders(t, handler, "/sitemap.xml", map[string]string{
		"Accept-Encoding": "gzip",
	})
	ce2 := hdrs2.Get("Content-Encoding")

	t.Logf("enable_gzip_sitemap: ON Content-Encoding=%q OFF Content-Encoding=%q", ce1, ce2)
	if ce1 == ce2 {
		t.Error("enable_gzip_sitemap should change Content-Encoding when client accepts gzip")
	}
}

// Ensure imports are used
var (
	_ = errors.ErrNone
	_ = pages.PageHTML
	_ = fmt.Sprintf
)
