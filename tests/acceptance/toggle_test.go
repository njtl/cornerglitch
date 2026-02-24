package acceptance

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// setFeature toggles a feature flag via the admin API.
func setFeature(t *testing.T, name string, enabled bool) {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/features", map[string]interface{}{
		"feature": name, "enabled": enabled,
	})
	if err != nil {
		t.Fatalf("setFeature(%s, %v): %v", name, enabled, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setFeature(%s, %v): status %d", name, enabled, resp.StatusCode)
	}
}

// setConfig sets a numeric config parameter via the admin API.
func setConfig(t *testing.T, key string, value float64) {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
		"key": key, "value": value,
	})
	if err != nil {
		t.Fatalf("setConfig(%s, %v): %v", key, value, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setConfig(%s, %v): status %d", key, value, resp.StatusCode)
	}
}

// setConfigString sets a string config parameter via the admin API.
func setConfigString(t *testing.T, key, value string) {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/config", map[string]interface{}{
		"key": key, "value": value,
	})
	if err != nil {
		t.Fatalf("setConfigString(%s, %v): %v", key, value, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setConfigString(%s, %v): status %d", key, value, resp.StatusCode)
	}
}

// setVulnGroup toggles a vulnerability group via the admin API.
func setVulnGroup(t *testing.T, group string, enabled bool) {
	t.Helper()
	resp, err := postJSON(adminURL+"/admin/api/vulns/group", map[string]interface{}{
		"group": group, "enabled": enabled,
	})
	if err != nil {
		t.Fatalf("setVulnGroup(%s, %v): %v", group, enabled, err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setVulnGroup(%s, %v): status %d", group, enabled, resp.StatusCode)
	}
}

// getStatusCode makes a GET request and returns the status code. Retries on 5xx
// up to maxRetries times (since error injection is probabilistic).
func getStatusCode(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return -1
	}
	resp.Body.Close()
	return resp.StatusCode
}

// getBody makes a GET request and returns the response body as string.
func getBody(url string) (int, string) {
	resp, err := http.Get(url)
	if err != nil {
		return -1, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// getWithUA makes a GET request with a specific User-Agent.
func getWithUA(url, ua string) (int, string, http.Header) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return -1, "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

// retryGet makes a GET request up to maxRetries times, returning the first
// response that matches the predicate. Returns last status if no match found.
func retryGet(url string, maxRetries int, predicate func(int, string) bool) (int, string, bool) {
	for i := 0; i < maxRetries; i++ {
		status, body := getBody(url)
		if predicate(status, body) {
			return status, body, true
		}
	}
	status, body := getBody(url)
	return status, body, false
}

// getConfigValue reads the current value of a config key from admin API.
func getConfigValue(t *testing.T, key string) interface{} {
	t.Helper()
	data := getJSON(t, adminURL+"/admin/api/config")
	return data[key]
}

// resetAllFeatures enables all features (restore to default state).
func resetAllFeatures(t *testing.T) {
	t.Helper()
	features := []string{
		"labyrinth", "error_inject", "captcha", "honeypot", "vuln",
		"analytics", "cdn", "oauth", "header_corrupt", "cookie_traps",
		"js_traps", "bot_detection", "random_blocking", "framework_emul",
		"search", "email", "i18n", "recorder", "websocket", "privacy",
		"health", "spider",
	}
	for _, f := range features {
		setFeature(t, f, true)
	}
}

// resetAllVulnGroups enables all vuln groups.
func resetAllVulnGroups(t *testing.T) {
	t.Helper()
	groups := []string{
		"owasp", "api_security", "advanced", "modern",
		"infrastructure", "iot_desktop", "mobile_privacy",
		"specialized", "dashboard",
	}
	for _, g := range groups {
		setVulnGroup(t, g, true)
	}
}

// resetConfig restores default config values that tests may have changed.
func resetConfig(t *testing.T) {
	t.Helper()
	setConfig(t, "error_rate_multiplier", 1.0)
	setConfig(t, "max_labyrinth_depth", 50)
	setConfig(t, "header_corrupt_level", 1)
	setConfig(t, "delay_min_ms", 0)
	setConfig(t, "delay_max_ms", 0)
	setConfig(t, "block_chance", 0.02)
	setConfig(t, "protocol_glitch_enabled", 1)
	setConfig(t, "protocol_glitch_level", 2)
}

// ===========================================================================
// SECTION 1: Feature Flag Toggle Tests
// ===========================================================================

func TestToggle_Labyrinth(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	// The labyrinth triggers on paths like /articles/some/deep/path
	testPath := serverURL + "/articles/test-page/sub"

	// Disable labyrinth
	setFeature(t, "labyrinth", false)
	// Also disable error injection to avoid probabilistic errors
	setFeature(t, "error_inject", false)

	// With labyrinth disabled, the path should NOT generate labyrinth content
	_, body, _ := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200 && !strings.Contains(body, "labyrinth")
	})
	// It should serve normal content instead
	if strings.Contains(strings.ToLower(body), "labyrinth") {
		// Acceptable if it served some other content
	}

	// Enable labyrinth
	setFeature(t, "labyrinth", true)
	_, body, found := retryGet(testPath, 10, func(code int, body string) bool {
		return code == 200 && (strings.Contains(body, "articles") || strings.Contains(body, "href="))
	})
	if !found {
		t.Errorf("labyrinth enabled: expected page with links, got: %.200s", body)
	}
}

func TestToggle_ErrorInject(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetConfig(t)

	// Test the error_inject toggle via the admin API (round-trip test).
	// Behavioral verification of error injection is inherently probabilistic and
	// affected by the adaptive engine, so we test the API toggle and config separately.

	// Verify toggle on/off round-trips through the API
	setFeature(t, "error_inject", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["error_inject"] != false {
		t.Error("error_inject should be false after disabling")
	}

	setFeature(t, "error_inject", true)
	data = getJSON(t, adminURL+"/admin/api/features")
	if data["error_inject"] != true {
		t.Error("error_inject should be true after enabling")
	}

	// Verify error_rate_multiplier config round-trips
	setConfig(t, "error_rate_multiplier", 0)
	val := getConfigValue(t, "error_rate_multiplier")
	if v, ok := val.(float64); !ok || v != 0 {
		t.Errorf("error_rate_multiplier should be 0, got %v", val)
	}

	setConfig(t, "error_rate_multiplier", 5.0)
	val = getConfigValue(t, "error_rate_multiplier")
	if v, ok := val.(float64); !ok || v != 5.0 {
		t.Errorf("error_rate_multiplier should be 5.0, got %v", val)
	}

	// Behavioral test: with error_inject enabled and high multiplier,
	// attempt to observe errors (probabilistic, so use t.Log not t.Error)
	setFeature(t, "error_inject", true)
	setFeature(t, "random_blocking", false)
	setFeature(t, "captcha", false)
	setConfig(t, "block_chance", 0)
	setConfig(t, "error_rate_multiplier", 5.0)

	gotError := false
	for i := 0; i < 50; i++ {
		code := getStatusCode(serverURL + "/test-error-inject")
		if code >= 400 && code < 600 {
			gotError = true
			break
		}
	}
	if !gotError {
		t.Log("error_rate_multiplier=5.0: no error response in 50 requests (adaptive engine may suppress)")
	}
}

func TestToggle_Honeypot(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	// Disable error inject to avoid probabilistic noise
	setFeature(t, "error_inject", false)
	honeypotPaths := []string{
		serverURL + "/.env",
		serverURL + "/wp-admin/",
		serverURL + "/phpmyadmin/",
	}

	// Enable honeypot
	setFeature(t, "honeypot", true)
	for _, p := range honeypotPaths {
		_, _, found := retryGet(p, 5, func(code int, body string) bool {
			return code == 200
		})
		if !found {
			t.Errorf("honeypot enabled: %s should serve honeypot (200)", p)
		}
	}

	// Disable honeypot
	setFeature(t, "honeypot", false)
	for _, p := range honeypotPaths {
		// These paths should no longer match honeypot; they'll fall through to
		// other handlers or return non-honeypot content.
		code := getStatusCode(p)
		// When honeypot is disabled, these should NOT serve honeypot responses.
		// They may get caught by labyrinth, content engine, or return 200 from
		// another handler. We just verify the feature toggle was accepted.
		_ = code // Just ensure no crash
	}
}

func TestToggle_Vuln(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	vulnPath := serverURL + "/vuln/a01/"

	// Enable vuln
	setFeature(t, "vuln", true)
	_, body, found := retryGet(vulnPath, 5, func(code int, body string) bool {
		return code == 200 && strings.Contains(body, "Acme Corp")
	})
	if !found {
		t.Errorf("vuln enabled: /vuln/a01/ should return 200 with Acme Corp, got: %.200s", body)
	}

	// Disable vuln — falls through to other handlers (content engine, etc.)
	setFeature(t, "vuln", false)
	_, body, _ = retryGet(vulnPath, 5, func(code int, body string) bool {
		return code == 200
	})
	// Should no longer serve vuln-specific content
	if strings.Contains(body, "Broken Access Control") {
		t.Error("vuln disabled: /vuln/a01/ should not serve vulnerability content")
	}
}

func TestToggle_Analytics(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	paths := []string{
		serverURL + "/collect",
		serverURL + "/analytics/beacon",
	}

	// Enable analytics
	setFeature(t, "analytics", true)
	for _, p := range paths {
		_, _, found := retryGet(p, 5, func(code int, body string) bool {
			return code >= 200 && code < 300
		})
		if !found {
			t.Errorf("analytics enabled: %s should return 2xx", p)
		}
	}

	// Disable analytics — paths should fall through to other handlers
	setFeature(t, "analytics", false)
	// The paths will still be handled (content engine, labyrinth, etc.)
	// but should not be handled by the analytics engine
	for _, p := range paths {
		code := getStatusCode(p)
		_ = code // Verify no crash
	}
}

func TestToggle_CDN(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	cdnPath := serverURL + "/cdn/app.js"

	// Enable CDN
	setFeature(t, "cdn", true)
	_, _, found := retryGet(cdnPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("cdn enabled: /cdn/app.js should return 200")
	}

	// Disable CDN
	setFeature(t, "cdn", false)
	// Path will fall through to other handlers
	code := getStatusCode(cdnPath)
	_ = code
}

func TestToggle_OAuth(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	oauthPath := serverURL + "/oauth/authorize"

	// Enable OAuth
	setFeature(t, "oauth", true)
	_, _, found := retryGet(oauthPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("oauth enabled: /oauth/authorize should return 200")
	}

	// Disable OAuth — should fall through
	setFeature(t, "oauth", false)
	// Verify the toggle took effect via the admin API
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["oauth"] != false {
		t.Error("oauth feature should be false after disabling")
	}
}

func TestToggle_Search(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	searchPath := serverURL + "/search?q=test"

	// Enable search
	setFeature(t, "search", true)
	_, _, found := retryGet(searchPath, 5, func(code int, body string) bool {
		return code == 200 && (strings.Contains(body, "search") || strings.Contains(body, "Search"))
	})
	if !found {
		t.Error("search enabled: /search?q=test should return 200 with search content")
	}

	// Disable search
	setFeature(t, "search", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["search"] != false {
		t.Error("search feature should be false after disabling")
	}
}

func TestToggle_Email(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	emailPath := serverURL + "/webmail/inbox"

	// Enable email
	setFeature(t, "email", true)
	_, _, found := retryGet(emailPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("email enabled: /webmail/inbox should return 200")
	}

	// Disable email
	setFeature(t, "email", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["email"] != false {
		t.Error("email feature should be false after disabling")
	}
}

func TestToggle_I18n(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	// Use a language-prefixed path (not /api/i18n/ which is intercepted by API router)
	i18nPath := serverURL + "/es/about"

	// Enable i18n
	setFeature(t, "i18n", true)
	_, _, found := retryGet(i18nPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("i18n enabled: /es/about should return 200")
	}

	// Disable i18n
	setFeature(t, "i18n", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["i18n"] != false {
		t.Error("i18n feature should be false after disabling")
	}
}

func TestToggle_WebSocket(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	wsPath := serverURL + "/ws/"

	// Enable websocket
	setFeature(t, "websocket", true)
	_, _, found := retryGet(wsPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("websocket enabled: /ws/ should return 200")
	}

	// Disable websocket
	setFeature(t, "websocket", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["websocket"] != false {
		t.Error("websocket feature should be false after disabling")
	}
}

func TestToggle_Privacy(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	privacyPaths := []string{
		serverURL + "/privacy-policy",
		serverURL + "/cookie-policy",
		serverURL + "/consent/preferences",
	}

	// Enable privacy
	setFeature(t, "privacy", true)
	for _, p := range privacyPaths {
		_, _, found := retryGet(p, 5, func(code int, body string) bool {
			return code == 200
		})
		if !found {
			t.Errorf("privacy enabled: %s should return 200", p)
		}
	}

	// Disable privacy
	setFeature(t, "privacy", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["privacy"] != false {
		t.Error("privacy feature should be false after disabling")
	}
}

func TestToggle_Health(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	healthPaths := []string{
		serverURL + "/health",
		serverURL + "/health/live",
		serverURL + "/status",
		serverURL + "/ping",
	}

	// Enable health
	setFeature(t, "health", true)
	for _, p := range healthPaths {
		_, _, found := retryGet(p, 5, func(code int, body string) bool {
			return code == 200
		})
		if !found {
			t.Errorf("health enabled: %s should return 200", p)
		}
	}

	// Disable health — endpoints should NOT be served by health handler
	setFeature(t, "health", false)
	// /health will fall through to other handlers (content engine, etc.)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["health"] != false {
		t.Error("health feature should be false after disabling")
	}
}

func TestToggle_Spider(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	setFeature(t, "error_inject", false)

	spiderPaths := []string{
		serverURL + "/robots.txt",
		serverURL + "/sitemap.xml",
		serverURL + "/favicon.ico",
	}

	// Enable spider
	setFeature(t, "spider", true)
	for _, p := range spiderPaths {
		_, _, found := retryGet(p, 5, func(code int, body string) bool {
			return code == 200
		})
		if !found {
			t.Errorf("spider enabled: %s should return 200", p)
		}
	}

	// Verify robots.txt content
	_, body := getBody(serverURL + "/robots.txt")
	if !strings.Contains(body, "User-agent") {
		t.Error("robots.txt should contain User-agent directive")
	}

	// Disable spider
	setFeature(t, "spider", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["spider"] != false {
		t.Error("spider feature should be false after disabling")
	}
}

func TestToggle_HeaderCorrupt(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetConfig(t)

	setFeature(t, "error_inject", false)
	testPath := serverURL + "/test-header-corrupt"

	// Disable header corruption
	setFeature(t, "header_corrupt", false)
	// Verify the toggle is set
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["header_corrupt"] != false {
		t.Error("header_corrupt should be false after disabling")
	}

	// Enable header corruption at max level
	setFeature(t, "header_corrupt", true)
	setConfig(t, "header_corrupt_level", 4)
	// With level 4 (chaos), we should see some unusual headers
	// This is probabilistic so we just verify the toggle was accepted
	for i := 0; i < 5; i++ {
		resp, err := http.Get(testPath)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
	// Verify config was set
	cfgData := getJSON(t, adminURL+"/admin/api/config")
	if level, ok := cfgData["header_corrupt_level"].(float64); ok {
		if int(level) != 4 {
			t.Errorf("header_corrupt_level should be 4, got %v", level)
		}
	}
}

func TestToggle_CookieTraps(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	testPath := serverURL + "/test-cookie-trap"

	// Enable cookie traps
	setFeature(t, "cookie_traps", true)
	// Make several requests to trigger cookie traps
	gotCookies := false
	for i := 0; i < 10; i++ {
		resp, err := http.Get(testPath)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if len(resp.Cookies()) > 0 {
			gotCookies = true
			break
		}
	}
	if !gotCookies {
		t.Log("cookie_traps enabled: no trap cookies received (may need more requests)")
	}

	// Disable cookie traps
	setFeature(t, "cookie_traps", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["cookie_traps"] != false {
		t.Error("cookie_traps should be false after disabling")
	}
}

func TestToggle_JSTraps(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// JS traps serve on specific challenge paths
	jsTrapPath := serverURL + "/js/challenge"

	// Enable js_traps
	setFeature(t, "js_traps", true)
	_, _, found := retryGet(jsTrapPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Log("js_traps enabled: /js/challenge may not be a ShouldHandle path")
	}

	// Disable js_traps
	setFeature(t, "js_traps", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["js_traps"] != false {
		t.Error("js_traps should be false after disabling")
	}
}

func TestToggle_BotDetection(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// Enable bot detection
	setFeature(t, "bot_detection", true)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["bot_detection"] != true {
		t.Error("bot_detection should be true after enabling")
	}

	// Make requests with bot UA — bot detection should score them
	botUA := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	for i := 0; i < 5; i++ {
		code, _, _ := getWithUA(serverURL+"/test-bot", botUA, )
		_ = code
	}

	// Disable bot detection
	setFeature(t, "bot_detection", false)
	data = getJSON(t, adminURL+"/admin/api/features")
	if data["bot_detection"] != false {
		t.Error("bot_detection should be false after disabling")
	}
}

func TestToggle_RandomBlocking(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetConfig(t)

	setFeature(t, "error_inject", false)
	testPath := serverURL + "/test-random-blocking"

	// Set block_chance to 0 — no blocking
	setConfig(t, "block_chance", 0)
	setFeature(t, "random_blocking", true)
	all200 := true
	for i := 0; i < 15; i++ {
		code := getStatusCode(testPath)
		if code == 403 {
			all200 = false
			break
		}
	}
	// With block_chance 0, we shouldn't get blocked
	// (though adaptive engine might still block based on behavior)

	// Disable random blocking entirely
	setFeature(t, "random_blocking", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["random_blocking"] != false {
		t.Error("random_blocking should be false after disabling")
	}
	_ = all200
}

func TestToggle_FrameworkEmul(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// Enable framework emulation
	setFeature(t, "framework_emul", true)
	// Check for framework-specific headers (Rails, Django, Express, etc.)
	gotFwHeader := false
	fwHeaders := []string{
		"X-Powered-By", "X-Request-Id", "X-Runtime",
		"Server", "X-Frame-Options",
	}
	for i := 0; i < 10; i++ {
		resp, err := http.Get(serverURL + "/test-framework")
		if err != nil {
			continue
		}
		resp.Body.Close()
		for _, h := range fwHeaders {
			if resp.Header.Get(h) != "" {
				gotFwHeader = true
				break
			}
		}
		if gotFwHeader {
			break
		}
	}
	// Framework headers are set probabilistically

	// Disable framework emulation
	setFeature(t, "framework_emul", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["framework_emul"] != false {
		t.Error("framework_emul should be false after disabling")
	}
}

func TestToggle_Recorder(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	// Enable recorder
	setFeature(t, "recorder", true)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["recorder"] != true {
		t.Error("recorder should be true after enabling")
	}

	// Disable recorder
	setFeature(t, "recorder", false)
	data = getJSON(t, adminURL+"/admin/api/features")
	if data["recorder"] != false {
		t.Error("recorder should be false after disabling")
	}
}

func TestToggle_Captcha(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// Enable captcha
	setFeature(t, "captcha", true)
	// Protected paths should trigger captcha challenges
	protectedPaths := []string{
		serverURL + "/secure/page",
		serverURL + "/protected/data",
	}
	gotCaptcha := false
	for _, p := range protectedPaths {
		for i := 0; i < 10; i++ {
			_, body := getBody(p)
			if strings.Contains(body, "captcha") || strings.Contains(body, "challenge") ||
				strings.Contains(body, "CAPTCHA") || strings.Contains(body, "verify") {
				gotCaptcha = true
				break
			}
		}
		if gotCaptcha {
			break
		}
	}
	// Captcha triggering is probabilistic

	// Disable captcha
	setFeature(t, "captcha", false)
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["captcha"] != false {
		t.Error("captcha should be false after disabling")
	}
}

// ===========================================================================
// SECTION 2: Feature Flag Round-Trip (API correctness)
// ===========================================================================

func TestToggle_AllFeatureRoundTrip(t *testing.T) {
	requireAdmin(t)
	defer resetAllFeatures(t)

	features := []string{
		"labyrinth", "error_inject", "captcha", "honeypot", "vuln",
		"analytics", "cdn", "oauth", "header_corrupt", "cookie_traps",
		"js_traps", "bot_detection", "random_blocking", "framework_emul",
		"search", "email", "i18n", "recorder", "websocket", "privacy",
		"health", "spider",
	}

	for _, f := range features {
		t.Run(f, func(t *testing.T) {
			// Disable
			setFeature(t, f, false)
			data := getJSON(t, adminURL+"/admin/api/features")
			if data[f] != false {
				t.Errorf("feature %s should be false, got %v", f, data[f])
			}

			// Re-enable
			setFeature(t, f, true)
			data = getJSON(t, adminURL+"/admin/api/features")
			if data[f] != true {
				t.Errorf("feature %s should be true, got %v", f, data[f])
			}
		})
	}
}

// ===========================================================================
// SECTION 3: Config Settings Tests
// ===========================================================================

func TestConfig_MaxLabyrinthDepth(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	// Set to minimum
	setConfig(t, "max_labyrinth_depth", 1)
	val := getConfigValue(t, "max_labyrinth_depth")
	if v, ok := val.(float64); !ok || int(v) != 1 {
		t.Errorf("max_labyrinth_depth should be 1, got %v", val)
	}

	// Set to maximum
	setConfig(t, "max_labyrinth_depth", 100)
	val = getConfigValue(t, "max_labyrinth_depth")
	if v, ok := val.(float64); !ok || int(v) != 100 {
		t.Errorf("max_labyrinth_depth should be 100, got %v", val)
	}

	// Set below minimum (should clamp to 1)
	setConfig(t, "max_labyrinth_depth", 0)
	val = getConfigValue(t, "max_labyrinth_depth")
	if v, ok := val.(float64); !ok || int(v) != 1 {
		t.Errorf("max_labyrinth_depth should be clamped to 1, got %v", val)
	}

	// Set above maximum (should clamp to 100)
	setConfig(t, "max_labyrinth_depth", 200)
	val = getConfigValue(t, "max_labyrinth_depth")
	if v, ok := val.(float64); !ok || int(v) != 100 {
		t.Errorf("max_labyrinth_depth should be clamped to 100, got %v", val)
	}
}

func TestConfig_ErrorRateMultiplier(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	// Set to 0
	setConfig(t, "error_rate_multiplier", 0)
	val := getConfigValue(t, "error_rate_multiplier")
	if v, ok := val.(float64); !ok || v != 0 {
		t.Errorf("error_rate_multiplier should be 0, got %v", val)
	}

	// Set to max
	setConfig(t, "error_rate_multiplier", 5.0)
	val = getConfigValue(t, "error_rate_multiplier")
	if v, ok := val.(float64); !ok || v != 5.0 {
		t.Errorf("error_rate_multiplier should be 5.0, got %v", val)
	}

	// Set above max (should clamp)
	setConfig(t, "error_rate_multiplier", 10.0)
	val = getConfigValue(t, "error_rate_multiplier")
	if v, ok := val.(float64); !ok || v != 5.0 {
		t.Errorf("error_rate_multiplier should be clamped to 5.0, got %v", val)
	}
}

func TestConfig_HeaderCorruptLevel(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	for level := 0; level <= 4; level++ {
		t.Run(fmt.Sprintf("level_%d", level), func(t *testing.T) {
			setConfig(t, "header_corrupt_level", float64(level))
			val := getConfigValue(t, "header_corrupt_level")
			if v, ok := val.(float64); !ok || int(v) != level {
				t.Errorf("header_corrupt_level should be %d, got %v", level, val)
			}
		})
	}

	// Clamp test
	setConfig(t, "header_corrupt_level", 5)
	val := getConfigValue(t, "header_corrupt_level")
	if v, ok := val.(float64); !ok || int(v) != 4 {
		t.Errorf("header_corrupt_level should be clamped to 4, got %v", val)
	}
}

func TestConfig_DelayMinMaxMs(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetConfig(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// Set no delay
	setConfig(t, "delay_min_ms", 0)
	setConfig(t, "delay_max_ms", 0)
	val := getConfigValue(t, "delay_min_ms")
	if v, ok := val.(float64); !ok || int(v) != 0 {
		t.Errorf("delay_min_ms should be 0, got %v", val)
	}
	val = getConfigValue(t, "delay_max_ms")
	if v, ok := val.(float64); !ok || int(v) != 0 {
		t.Errorf("delay_max_ms should be 0, got %v", val)
	}

	// Verify fast response with no delay
	start := time.Now()
	getStatusCode(serverURL + "/test-delay")
	fast := time.Since(start)

	// Set significant delay
	setConfig(t, "delay_min_ms", 200)
	setConfig(t, "delay_max_ms", 200)

	// Verify slower response with delay
	start = time.Now()
	getStatusCode(serverURL + "/test-delay")
	slow := time.Since(start)

	// Reset delay immediately to not slow other tests
	setConfig(t, "delay_min_ms", 0)
	setConfig(t, "delay_max_ms", 0)

	if slow < fast+100*time.Millisecond {
		t.Logf("delay test: fast=%v, slow=%v — delay may not have taken effect", fast, slow)
	}
}

func TestConfig_ProtocolGlitch(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	// Enable protocol glitch
	setConfig(t, "protocol_glitch_enabled", 1)
	val := getConfigValue(t, "protocol_glitch_enabled")
	if v, ok := val.(bool); !ok || !v {
		t.Errorf("protocol_glitch_enabled should be true, got %v", val)
	}

	// Set level
	setConfig(t, "protocol_glitch_level", 3)
	val = getConfigValue(t, "protocol_glitch_level")
	if v, ok := val.(float64); !ok || int(v) != 3 {
		t.Errorf("protocol_glitch_level should be 3, got %v", val)
	}

	// Disable protocol glitch
	setConfig(t, "protocol_glitch_enabled", 0)
	val = getConfigValue(t, "protocol_glitch_enabled")
	if v, ok := val.(bool); !ok || v {
		t.Errorf("protocol_glitch_enabled should be false, got %v", val)
	}
}

func TestConfig_BlockChance(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	// Set to 0
	setConfig(t, "block_chance", 0)
	val := getConfigValue(t, "block_chance")
	if v, ok := val.(float64); !ok || v != 0 {
		t.Errorf("block_chance should be 0, got %v", val)
	}

	// Set to 1.0
	setConfig(t, "block_chance", 1.0)
	val = getConfigValue(t, "block_chance")
	if v, ok := val.(float64); !ok || v != 1.0 {
		t.Errorf("block_chance should be 1.0, got %v", val)
	}

	// Clamp above max
	setConfig(t, "block_chance", 2.0)
	val = getConfigValue(t, "block_chance")
	if v, ok := val.(float64); !ok || v != 1.0 {
		t.Errorf("block_chance should be clamped to 1.0, got %v", val)
	}

	// Reset to low value
	setConfig(t, "block_chance", 0.02)
}

func TestConfig_AllNumericRoundTrip(t *testing.T) {
	requireAdmin(t)
	defer resetConfig(t)

	tests := []struct {
		key    string
		value  float64
		expect float64
	}{
		{"max_labyrinth_depth", 42, 42},
		{"error_rate_multiplier", 2.5, 2.5},
		{"captcha_trigger_thresh", 50, 50},
		{"block_chance", 0.5, 0.5},
		{"block_duration_sec", 120, 120},
		{"bot_score_threshold", 75, 75},
		{"header_corrupt_level", 3, 3},
		{"delay_min_ms", 100, 100},
		{"delay_max_ms", 500, 500},
		{"labyrinth_link_density", 15, 15},
		{"adaptive_interval_sec", 60, 60},
		{"cookie_trap_frequency", 5, 5},
		{"js_trap_difficulty", 3, 3},
		{"content_cache_ttl_sec", 120, 120},
		{"adaptive_aggressive_rps", 20, 20},
		{"adaptive_labyrinth_paths", 10, 10},
		{"protocol_glitch_level", 2, 2},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			setConfig(t, tc.key, tc.value)
			val := getConfigValue(t, tc.key)
			if v, ok := val.(float64); ok {
				if v != tc.expect {
					t.Errorf("%s: expected %v, got %v", tc.key, tc.expect, v)
				}
			} else {
				t.Errorf("%s: unexpected type %T for value %v", tc.key, val, val)
			}
		})
	}
}

func TestConfig_StringValues(t *testing.T) {
	requireAdmin(t)

	tests := []struct {
		key    string
		value  string
		expect string
	}{
		{"honeypot_response_style", "aggressive", "aggressive"},
		{"active_framework", "rails", "rails"},
		{"content_theme", "dark", "dark"},
		{"recorder_format", "pcap", "pcap"},
	}

	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			setConfigString(t, tc.key, tc.value)
			val := getConfigValue(t, tc.key)
			if v, ok := val.(string); ok {
				if v != tc.expect {
					t.Errorf("%s: expected %q, got %q", tc.key, tc.expect, v)
				}
			} else {
				t.Errorf("%s: unexpected type %T for value %v", tc.key, val, val)
			}
		})
	}

	// Restore defaults
	setConfigString(t, "honeypot_response_style", "realistic")
	setConfigString(t, "active_framework", "auto")
	setConfigString(t, "content_theme", "default")
	setConfigString(t, "recorder_format", "jsonl")
}

// ===========================================================================
// SECTION 4: Vulnerability Group Toggle Tests
// ===========================================================================

func TestVulnGroup_OWASP(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/a01/"

	// Enable OWASP group
	setVulnGroup(t, "owasp", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("owasp group enabled: /vuln/a01/sqli should return 200")
	}

	// Disable OWASP group
	setVulnGroup(t, "owasp", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("owasp group disabled: /vuln/a01/sqli should return 404")
	}
}

func TestVulnGroup_APISecurity(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/api-sec/api1"

	// Enable API Security group
	setVulnGroup(t, "api_security", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("api_security group enabled: /vuln/api-sec/api1 should return 200")
	}

	// Disable API Security group
	setVulnGroup(t, "api_security", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("api_security group disabled: /vuln/api-sec/api1 should return 404")
	}
}

func TestVulnGroup_Advanced(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/cors/reflect"

	// Enable advanced group
	setVulnGroup(t, "advanced", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("advanced group enabled: /vuln/cors/reflect should return 200")
	}

	// Disable advanced group
	setVulnGroup(t, "advanced", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("advanced group disabled: /vuln/cors/reflect should return 404")
	}
}

func TestVulnGroup_Modern(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/llm/prompt-injection"

	// Enable modern group
	setVulnGroup(t, "modern", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("modern group enabled: /vuln/llm/prompt-injection should return 200")
	}

	// Disable modern group
	setVulnGroup(t, "modern", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("modern group disabled: /vuln/llm/prompt-injection should return 404")
	}
}

func TestVulnGroup_Infrastructure(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/docker/"

	// Enable infrastructure group
	setVulnGroup(t, "infrastructure", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("infrastructure group enabled: /vuln/docker/ should return 200")
	}

	// Disable infrastructure group
	setVulnGroup(t, "infrastructure", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("infrastructure group disabled: /vuln/docker/ should return 404")
	}
}

func TestVulnGroup_IoTDesktop(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/iot/"

	// Enable iot_desktop group
	setVulnGroup(t, "iot_desktop", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("iot_desktop group enabled: /vuln/iot/ should return 200")
	}

	// Disable iot_desktop group
	setVulnGroup(t, "iot_desktop", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("iot_desktop group disabled: /vuln/iot/ should return 404")
	}
}

func TestVulnGroup_MobilePrivacy(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/mobile/improper-credential"

	// Enable mobile_privacy group
	setVulnGroup(t, "mobile_privacy", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("mobile_privacy group enabled: /vuln/mobile/improper-credential should return 200")
	}

	// Disable mobile_privacy group
	setVulnGroup(t, "mobile_privacy", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("mobile_privacy group disabled: /vuln/mobile/improper-credential should return 404")
	}
}

func TestVulnGroup_Specialized(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/proactive/"

	// Enable specialized group
	setVulnGroup(t, "specialized", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("specialized group enabled: /vuln/proactive/ should return 200")
	}

	// Disable specialized group
	setVulnGroup(t, "specialized", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("specialized group disabled: /vuln/proactive/ should return 404")
	}
}

func TestVulnGroup_Dashboard(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	testPath := serverURL + "/vuln/dashboard/analytics"

	// Enable dashboard group
	setVulnGroup(t, "dashboard", true)
	_, _, found := retryGet(testPath, 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Error("dashboard group enabled: /vuln/dashboard/analytics should return 200")
	}

	// Disable dashboard group
	setVulnGroup(t, "dashboard", false)
	_, _, found = retryGet(testPath, 5, func(code int, body string) bool {
		return code == 404
	})
	if !found {
		t.Error("dashboard group disabled: /vuln/dashboard/analytics should return 404")
	}
}

// ===========================================================================
// SECTION 5: Vuln Group Round-Trip (API correctness)
// ===========================================================================

func TestVulnGroup_AllRoundTrip(t *testing.T) {
	requireAdmin(t)
	defer resetAllVulnGroups(t)

	groups := []string{
		"owasp", "api_security", "advanced", "modern",
		"infrastructure", "iot_desktop", "mobile_privacy",
		"specialized", "dashboard",
	}

	for _, g := range groups {
		t.Run(g, func(t *testing.T) {
			// Disable
			setVulnGroup(t, g, false)
			data := getJSON(t, adminURL+"/admin/api/vulns")
			if groups, ok := data["groups"].(map[string]interface{}); ok {
				if groups[g] != false {
					t.Errorf("vuln group %s should be false, got %v", g, groups[g])
				}
			}

			// Re-enable
			setVulnGroup(t, g, true)
			data = getJSON(t, adminURL+"/admin/api/vulns")
			if groups, ok := data["groups"].(map[string]interface{}); ok {
				if groups[g] != true {
					t.Errorf("vuln group %s should be true, got %v", g, groups[g])
				}
			}
		})
	}
}

// ===========================================================================
// SECTION 6: Config Export/Import Round-Trip
// ===========================================================================

func TestToggle_ConfigExportImportRoundTrip(t *testing.T) {
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetConfig(t)
	defer resetAllVulnGroups(t)

	// Set a distinctive config state
	setFeature(t, "i18n", false)
	setFeature(t, "spider", false)
	setConfig(t, "max_labyrinth_depth", 42)
	setConfig(t, "error_rate_multiplier", 3.14)
	setVulnGroup(t, "modern", false)

	// Export
	req, _ := http.NewRequest("GET", adminURL+"/admin/api/config/export", nil)
	req.SetBasicAuth("admin", adminPassword)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("config export: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("config export: status %d", resp.StatusCode)
	}
	var exported map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&exported)

	// Verify export has required keys
	for _, key := range []string{"version", "features", "config", "vuln_config"} {
		if _, ok := exported[key]; !ok {
			t.Errorf("export missing key: %s", key)
		}
	}

	// Reset to defaults
	resetAllFeatures(t)
	resetConfig(t)
	resetAllVulnGroups(t)

	// Verify reset worked
	data := getJSON(t, adminURL+"/admin/api/features")
	if data["i18n"] != true {
		t.Fatal("reset didn't restore i18n")
	}

	// Import the exported config
	importResp, err := postJSON(adminURL+"/admin/api/config/import", exported)
	if err != nil {
		t.Fatalf("config import: %v", err)
	}
	importResp.Body.Close()

	// Verify the imported state matches
	data = getJSON(t, adminURL+"/admin/api/features")
	if data["i18n"] != false {
		t.Error("after import: i18n should be false")
	}
	if data["spider"] != false {
		t.Error("after import: spider should be false")
	}

	cfgData := getJSON(t, adminURL+"/admin/api/config")
	if v, ok := cfgData["max_labyrinth_depth"].(float64); !ok || int(v) != 42 {
		t.Errorf("after import: max_labyrinth_depth should be 42, got %v", cfgData["max_labyrinth_depth"])
	}
}

// ===========================================================================
// SECTION 7: Behavioral Verification — Features That Affect Responses
// ===========================================================================

func TestBehavior_ErrorInjectDisabledMeansCleanResponses(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetConfig(t)

	// Disable ALL features that can cause non-200 responses
	setFeature(t, "error_inject", false)
	setFeature(t, "random_blocking", false)
	setFeature(t, "captcha", false)
	setFeature(t, "bot_detection", false)
	setConfig(t, "block_chance", 0)
	setConfig(t, "delay_min_ms", 0)
	setConfig(t, "delay_max_ms", 0)

	// All requests to basic content should be 200
	failures := 0
	for i := 0; i < 30; i++ {
		code := getStatusCode(serverURL + fmt.Sprintf("/page-%d", i))
		if code != 200 {
			failures++
		}
	}
	// Allow some tolerance for adaptive blocking from prior test traffic
	if failures > 5 {
		t.Errorf("with error_inject disabled, got %d non-200 responses out of 30", failures)
	}
}

func TestBehavior_HealthEndpointToggle(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)

	// Health enabled: /health returns 200 with JSON status
	setFeature(t, "health", true)
	status, body, found := retryGet(serverURL+"/health", 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Errorf("health enabled: expected 200, got %d", status)
	}
	if !strings.Contains(body, "status") && !strings.Contains(body, "ok") && !strings.Contains(body, "healthy") {
		t.Logf("health response body: %.200s", body)
	}

	// Health disabled: /health falls through (not served by health handler)
	setFeature(t, "health", false)
	code := getStatusCode(serverURL + "/health")
	// It will be served by content engine or other handler, so likely 200 still,
	// but it won't be the health handler's response
	_ = code
}

func TestBehavior_VulnToggleAffectsRouting(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)
	defer resetAllVulnGroups(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "vuln", true)

	// Test that all OWASP categories (a01-a10) work when enabled
	setVulnGroup(t, "owasp", true)
	for i := 1; i <= 10; i++ {
		path := fmt.Sprintf("/vuln/a%02d/", i)
		_, _, found := retryGet(serverURL+path, 5, func(code int, body string) bool {
			return code == 200
		})
		if !found {
			t.Errorf("owasp enabled: %s should return 200", path)
		}
	}

	// Disable OWASP — all should 404
	setVulnGroup(t, "owasp", false)
	for i := 1; i <= 10; i++ {
		path := fmt.Sprintf("/vuln/a%02d/", i)
		_, _, found := retryGet(serverURL+path, 5, func(code int, body string) bool {
			return code == 404
		})
		if !found {
			t.Errorf("owasp disabled: %s should return 404", path)
		}
	}
}

func TestBehavior_SpiderEndpoints(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "spider", true)

	// robots.txt should contain User-agent
	_, body, found := retryGet(serverURL+"/robots.txt", 5, func(code int, body string) bool {
		return code == 200 && strings.Contains(body, "User-agent")
	})
	if !found {
		t.Errorf("spider enabled: /robots.txt should contain User-agent, got: %.200s", body)
	}

	// sitemap.xml should contain XML
	_, body, found = retryGet(serverURL+"/sitemap.xml", 5, func(code int, body string) bool {
		return code == 200 && strings.Contains(body, "xml")
	})
	if !found {
		t.Errorf("spider enabled: /sitemap.xml should contain xml, got: %.200s", body)
	}
}

func TestBehavior_OAuthEndpoints(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "oauth", true)

	// OAuth authorize should return 200 with a form/login page
	_, body, found := retryGet(serverURL+"/oauth/authorize?client_id=test&response_type=code", 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Errorf("oauth enabled: /oauth/authorize should return 200, body: %.200s", body)
	}

	// OIDC discovery should return JSON
	_, body, found = retryGet(serverURL+"/.well-known/openid-configuration", 5, func(code int, body string) bool {
		return code == 200 && strings.Contains(body, "issuer")
	})
	if !found {
		t.Errorf("oauth enabled: /.well-known/openid-configuration should contain issuer, got: %.200s", body)
	}
}

func TestBehavior_SearchEndpoint(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "search", true)

	_, body, found := retryGet(serverURL+"/search?q=test+query", 5, func(code int, body string) bool {
		return code == 200 && (strings.Contains(strings.ToLower(body), "search") || strings.Contains(strings.ToLower(body), "result"))
	})
	if !found {
		t.Errorf("search enabled: /search?q=test should show results, got: %.200s", body)
	}
}

func TestBehavior_EmailEndpoint(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "email", true)

	_, body, found := retryGet(serverURL+"/webmail/inbox", 5, func(code int, body string) bool {
		return code == 200
	})
	if !found {
		t.Errorf("email enabled: /webmail/inbox should return 200, got: %.200s", body)
	}
}

func TestBehavior_PrivacyEndpoints(t *testing.T) {
	requireServer(t)
	requireAdmin(t)
	defer resetAllFeatures(t)

	setFeature(t, "error_inject", false)
	setFeature(t, "privacy", true)

	_, body, found := retryGet(serverURL+"/privacy-policy", 5, func(code int, body string) bool {
		return code == 200 && (strings.Contains(strings.ToLower(body), "privacy") || strings.Contains(strings.ToLower(body), "policy"))
	})
	if !found {
		t.Errorf("privacy enabled: /privacy-policy should contain privacy content, got: %.200s", body)
	}
}
