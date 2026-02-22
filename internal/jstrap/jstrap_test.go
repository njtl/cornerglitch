package jstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.challenges == nil {
		t.Fatal("challenges map not initialized")
	}
}

func TestGenerateTraps_ProducesValidHTML(t *testing.T) {
	e := NewEngine()
	e.SetDifficulty(3) // automation + timing + canvas
	result := e.GenerateTraps("test-client-123")

	if result == "" {
		t.Fatal("GenerateTraps returned empty string")
	}

	// Must contain script tags
	if !strings.Contains(result, "<script>") {
		t.Error("missing opening <script> tag")
	}
	if !strings.Contains(result, "</script>") {
		t.Error("missing closing </script> tag")
	}

	// Count opening and closing script tags — they should match
	openCount := strings.Count(result, "<script>")
	closeCount := strings.Count(result, "</script>")
	if openCount != closeCount {
		t.Errorf("mismatched script tags: %d opening, %d closing", openCount, closeCount)
	}

	// Should contain 3 script blocks (automation, timing, canvas)
	if openCount < 3 {
		t.Errorf("expected at least 3 script blocks, got %d", openCount)
	}
}

func TestGenerateTraps_DefaultDifficulty(t *testing.T) {
	e := NewEngine()
	// Default difficulty is 2: automation + timing only
	result := e.GenerateTraps("default-client")

	openCount := strings.Count(result, "<script>")
	if openCount != 2 {
		t.Errorf("expected 2 script blocks at default difficulty, got %d", openCount)
	}
}

func TestGenerateTraps_DifficultyZero(t *testing.T) {
	e := NewEngine()
	e.SetDifficulty(0)
	result := e.GenerateTraps("zero-client")

	if result != "" {
		t.Error("expected empty string at difficulty 0")
	}
}

func TestGenerateTraps_ContainsAutomationDetection(t *testing.T) {
	e := NewEngine()
	result := e.GenerateTraps("detect-client")

	checks := []string{
		"navigator.webdriver",
		"navigator.plugins",
		"__playwright_binding__",
		"__puppeteer_evaluation_script__",
		"cdc_adoQpoasnfa76pfcZLmcfl_Array",
		"WEBGL_debug_renderer_info",
		"screen.width",
		"window.innerWidth",
		"viewportExceedsScreen",
		"/api/beacon",
		"GlitchTrap",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("automation detection script missing: %s", check)
		}
	}
}

func TestGenerateTraps_ContainsTimingTrap(t *testing.T) {
	e := NewEngine()
	result := e.GenerateTraps("timing-client")

	checks := []string{
		"Date.now()",
		"mousemove",
		"deltaMs",
		"suspicious",
		"timing",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("timing trap missing: %s", check)
		}
	}
}

func TestGenerateTraps_ContainsCanvasFingerprint(t *testing.T) {
	e := NewEngine()
	e.SetDifficulty(3) // canvas fingerprint requires difficulty >= 3
	result := e.GenerateTraps("canvas-client")

	checks := []string{
		"canvas",
		"getContext('2d')",
		"fillRect",
		"fillText",
		"toDataURL",
		"canvas_fp",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("canvas fingerprint missing: %s", check)
		}
	}
}

func TestGenerateTraps_Deterministic(t *testing.T) {
	e := NewEngine()
	result1 := e.GenerateTraps("deterministic-client")
	result2 := e.GenerateTraps("deterministic-client")

	if result1 != result2 {
		t.Error("GenerateTraps is not deterministic for the same clientID")
	}
}

func TestGenerateTraps_DifferentPerClient(t *testing.T) {
	e := NewEngine()
	result1 := e.GenerateTraps("client-alpha")
	result2 := e.GenerateTraps("client-beta")

	if result1 == result2 {
		t.Error("GenerateTraps produced identical output for different clients")
	}
}

func TestGenerateJSRenderedContent_IncludesLoadingShell(t *testing.T) {
	e := NewEngine()
	result := e.GenerateJSRenderedContent("render-client", "/test/page")

	if result == "" {
		t.Fatal("GenerateJSRenderedContent returned empty string")
	}

	// Must include loading placeholder
	if !strings.Contains(result, "Loading...") {
		t.Error("missing loading placeholder")
	}

	// Must include noscript fallback
	if !strings.Contains(result, "<noscript>") {
		t.Error("missing noscript fallback")
	}

	// Must include spinner
	if !strings.Contains(result, "spinner") {
		t.Error("missing loading spinner")
	}
}

func TestGenerateJSRenderedContent_IncludesEncodedContent(t *testing.T) {
	e := NewEngine()
	result := e.GenerateJSRenderedContent("render-client", "/test/page")

	// Must include data-content attribute with base64 data
	if !strings.Contains(result, "data-content=") {
		t.Error("missing data-content attribute")
	}

	// Must include atob for decoding
	if !strings.Contains(result, "atob(") {
		t.Error("missing atob() call for base64 decoding")
	}

	// Must include the JS that renders content
	if !strings.Contains(result, "getElementById('app')") {
		t.Error("missing app element reference in script")
	}
}

func TestGenerateJSRenderedContent_ValidHTML(t *testing.T) {
	e := NewEngine()
	result := e.GenerateJSRenderedContent("html-client", "/test")

	requiredTags := []string{
		"<!DOCTYPE html>",
		"<html",
		"<head>",
		"</head>",
		"<body>",
		"</body>",
		"</html>",
		"<meta charset=",
	}

	for _, tag := range requiredTags {
		if !strings.Contains(result, tag) {
			t.Errorf("missing HTML tag: %s", tag)
		}
	}
}

func TestGenerateJSRenderedContent_IncludesTraps(t *testing.T) {
	e := NewEngine()
	result := e.GenerateJSRenderedContent("trap-client", "/test")

	// The JS-rendered page should also include detection traps
	if !strings.Contains(result, "navigator.webdriver") {
		t.Error("JS-rendered content should include automation detection traps")
	}
}

func TestGenerateJSRenderedContent_Deterministic(t *testing.T) {
	e := NewEngine()
	r1 := e.GenerateJSRenderedContent("det-client", "/same/path")
	r2 := e.GenerateJSRenderedContent("det-client", "/same/path")

	if r1 != r2 {
		t.Error("GenerateJSRenderedContent is not deterministic")
	}
}

func TestGenerateInvisibleLinks_CreatesHiddenElements(t *testing.T) {
	e := NewEngine()
	result := e.GenerateInvisibleLinks("link-client", "/test")

	if result == "" {
		t.Fatal("GenerateInvisibleLinks returned empty string")
	}

	// Must contain links
	if !strings.Contains(result, "<a href=") {
		t.Error("missing anchor tags")
	}

	// Check all 5 hiding styles are present
	hidingStyles := []string{
		"display:none",
		"visibility:hidden",
		"position:absolute;left:-9999px",
		"opacity:0;height:0",
		"font-size:0;color:transparent",
	}

	for _, style := range hidingStyles {
		if !strings.Contains(result, style) {
			t.Errorf("missing hiding style: %s", style)
		}
	}
}

func TestGenerateInvisibleLinks_PointsToHoneypotPaths(t *testing.T) {
	e := NewEngine()
	result := e.GenerateInvisibleLinks("honey-client", "/test")

	// All links should point to labyrinth-style honeypot paths
	if !strings.Contains(result, "/articles/hidden-trap-") {
		t.Error("links should point to /articles/hidden-trap-<hash> paths")
	}

	// Count the number of links — should be 5 (one per hiding style)
	linkCount := strings.Count(result, "<a href=")
	if linkCount != 5 {
		t.Errorf("expected 5 invisible links, got %d", linkCount)
	}
}

func TestGenerateInvisibleLinks_HasAccessibilityHiding(t *testing.T) {
	e := NewEngine()
	result := e.GenerateInvisibleLinks("a11y-client", "/test")

	// Links should have aria-hidden and tabindex=-1 to avoid screen reader exposure
	if !strings.Contains(result, `aria-hidden="true"`) {
		t.Error("invisible links should have aria-hidden=\"true\"")
	}
	if !strings.Contains(result, `tabindex="-1"`) {
		t.Error("invisible links should have tabindex=\"-1\"")
	}
}

func TestGenerateInvisibleLinks_Deterministic(t *testing.T) {
	e := NewEngine()
	r1 := e.GenerateInvisibleLinks("det-link-client", "/same")
	r2 := e.GenerateInvisibleLinks("det-link-client", "/same")

	if r1 != r2 {
		t.Error("GenerateInvisibleLinks is not deterministic")
	}
}

func TestShouldHandle_MatchesCorrectPaths(t *testing.T) {
	e := NewEngine()

	positiveCases := []string{
		"/js/challenge",
		"/api/beacon",
	}

	for _, path := range positiveCases {
		if !e.ShouldHandle(path) {
			t.Errorf("ShouldHandle should return true for %q", path)
		}
	}

	negativeCases := []string{
		"/",
		"/js",
		"/js/other",
		"/api/metrics",
		"/api/beacons",
		"/articles/some-page",
		"/admin",
		"/js/challenge/extra",
	}

	for _, path := range negativeCases {
		if e.ShouldHandle(path) {
			t.Errorf("ShouldHandle should return false for %q", path)
		}
	}
}

func TestServeHTTP_ChallengeEndpoint(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/js/challenge", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}

	body := w.Body.String()

	// Should be a valid HTML page
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("challenge page missing DOCTYPE")
	}
	if !strings.Contains(body, "<script>") {
		t.Error("challenge page missing script tag")
	}

	// Should contain challenge computation logic
	if !strings.Contains(body, "glitch-verified") {
		t.Error("challenge page missing verification logic")
	}

	// Should contain cookie setting
	if !strings.Contains(body, "glitch_js_verified") {
		t.Error("challenge page missing cookie setting")
	}

	// Content-Type should be HTML
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content type, got %s", ct)
	}

	// Should have no-cache header
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Error("challenge page should have no-store cache control")
	}
}

func TestServeHTTP_BeaconEndpoint(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/api/beacon?d=eyJ0ZXN0IjogdHJ1ZX0=", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}

	// Should return a GIF image
	ct := w.Header().Get("Content-Type")
	if ct != "image/gif" {
		t.Errorf("expected image/gif content type, got %s", ct)
	}

	// Should return the 1x1 transparent GIF (43 bytes)
	body := w.Body.Bytes()
	if len(body) == 0 {
		t.Error("beacon returned empty body")
	}

	// Verify GIF magic bytes
	if len(body) >= 6 {
		magic := string(body[:6])
		if magic != "GIF89a" {
			t.Errorf("expected GIF89a magic, got %q", magic)
		}
	}
}

func TestServeHTTP_UnknownPath(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/unknown/path", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("expected status 404 for unknown path, got %d", status)
	}
}

func TestVerifyChallenge_NoCookie(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/some/page", nil)

	if e.VerifyChallenge(req) {
		t.Error("VerifyChallenge should return false when no cookie is present")
	}
}

func TestVerifyChallenge_InvalidCookie(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/some/page", nil)
	req.AddCookie(&http.Cookie{Name: "glitch_js_verified", Value: "invalid-value"})

	if e.VerifyChallenge(req) {
		t.Error("VerifyChallenge should return false for invalid cookie value")
	}
}

func TestVerifyChallenge_ValidChallenge(t *testing.T) {
	e := NewEngine()

	// First, request the challenge page to register a challenge
	challengeReq := httptest.NewRequest("GET", "/js/challenge", nil)
	challengeReq.RemoteAddr = "1.2.3.4:5678"
	challengeReq.Header.Set("User-Agent", "TestBrowser/1.0")
	w := httptest.NewRecorder()

	e.ServeHTTP(w, challengeReq)

	// Derive the same clientID the server uses
	h := sha256.Sum256([]byte(challengeReq.RemoteAddr + challengeReq.UserAgent()))
	clientID := fmt.Sprintf("anon_%s", hex.EncodeToString(h[:8]))

	// Get the stored challenge
	e.mu.RLock()
	record, exists := e.challenges[clientID]
	e.mu.RUnlock()

	if !exists {
		t.Fatal("challenge was not stored after serving challenge page")
	}

	// Verify with the correct cookie
	verifyReq := httptest.NewRequest("GET", "/some/page", nil)
	verifyReq.RemoteAddr = challengeReq.RemoteAddr
	verifyReq.Header.Set("User-Agent", challengeReq.Header.Get("User-Agent"))
	verifyReq.AddCookie(&http.Cookie{Name: "glitch_js_verified", Value: record.answer})

	if !e.VerifyChallenge(verifyReq) {
		t.Error("VerifyChallenge should return true for valid challenge answer")
	}
}

func TestGenerateTraps_AllHTMLValid(t *testing.T) {
	e := NewEngine()

	// Test multiple clients to ensure consistent validity
	clients := []string{"client-a", "client-b", "client-c", "client-d", "client-e"}

	for _, clientID := range clients {
		result := e.GenerateTraps(clientID)

		// Every opening script tag must have a closing tag
		opens := strings.Count(result, "<script>")
		closes := strings.Count(result, "</script>")
		if opens != closes {
			t.Errorf("client %s: mismatched script tags: %d open, %d close", clientID, opens, closes)
		}

		// No empty script blocks
		if strings.Contains(result, "<script></script>") {
			t.Errorf("client %s: contains empty script block", clientID)
		}

		// Should contain actual JavaScript
		if !strings.Contains(result, "function") || !strings.Contains(result, "var ") {
			t.Errorf("client %s: script blocks lack JavaScript content", clientID)
		}
	}
}

func TestGenerateJSRenderedContent_AllHTMLValid(t *testing.T) {
	e := NewEngine()

	paths := []string{"/page/1", "/articles/test", "/deep/nested/path"}

	for _, path := range paths {
		result := e.GenerateJSRenderedContent("valid-html-client", path)

		// Check for proper HTML structure
		if !strings.Contains(result, "<!DOCTYPE html>") {
			t.Errorf("path %s: missing DOCTYPE", path)
		}

		opens := strings.Count(result, "<script>")
		closes := strings.Count(result, "</script>")
		if opens != closes {
			t.Errorf("path %s: mismatched script tags: %d open, %d close", path, opens, closes)
		}

		// Check body tags
		if !strings.Contains(result, "<body>") || !strings.Contains(result, "</body>") {
			t.Errorf("path %s: missing body tags", path)
		}
	}
}

func TestThreadSafety(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup

	// Run concurrent operations on the engine
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			clientID := fmt.Sprintf("client-%d", id)

			// Concurrent GenerateTraps
			_ = e.GenerateTraps(clientID)

			// Concurrent GenerateJSRenderedContent
			_ = e.GenerateJSRenderedContent(clientID, "/path")

			// Concurrent GenerateInvisibleLinks
			_ = e.GenerateInvisibleLinks(clientID, "/path")

			// Concurrent ShouldHandle
			_ = e.ShouldHandle("/js/challenge")
			_ = e.ShouldHandle("/api/beacon")

			// Concurrent ServeHTTP (challenge)
			req := httptest.NewRequest("GET", "/js/challenge", nil)
			req.RemoteAddr = fmt.Sprintf("127.0.0.%d:1234", id%256)
			w := httptest.NewRecorder()
			_ = e.ServeHTTP(w, req)

			// Concurrent ServeHTTP (beacon)
			req2 := httptest.NewRequest("GET", "/api/beacon?d=dGVzdA==", nil)
			w2 := httptest.NewRecorder()
			_ = e.ServeHTTP(w2, req2)

			// Concurrent VerifyChallenge
			req3 := httptest.NewRequest("GET", "/page", nil)
			req3.RemoteAddr = fmt.Sprintf("127.0.0.%d:1234", id%256)
			req3.AddCookie(&http.Cookie{Name: "glitch_js_verified", Value: "test-value"})
			_ = e.VerifyChallenge(req3)
		}(i)
	}

	wg.Wait()
	// If we reach here without a race condition panic, the test passes
}

func TestBeaconEndpoint_CORSHeaders(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/api/beacon?d=dGVzdA==", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	// Beacon should allow cross-origin requests
	cors := w.Header().Get("Access-Control-Allow-Origin")
	if cors != "*" {
		t.Errorf("beacon should have CORS header set to *, got %q", cors)
	}
}

func TestBeaconEndpoint_NoCaching(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest("GET", "/api/beacon?d=dGVzdA==", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Error("beacon should have no-store cache control")
	}
}
