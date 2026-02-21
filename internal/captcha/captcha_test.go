package captcha

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. NewEngine creates an engine with all 8 challenge types
// ---------------------------------------------------------------------------

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if len(e.challenges) != int(challengeCount) {
		t.Fatalf("expected %d challenge types, got %d", int(challengeCount), len(e.challenges))
	}
	// Verify each challenge type is present in order
	for i := 0; i < int(challengeCount); i++ {
		if e.challenges[i] != ChallengeType(i) {
			t.Errorf("challenges[%d] = %d, want %d", i, e.challenges[i], i)
		}
	}
}

func TestChallengeCountIsEight(t *testing.T) {
	if int(challengeCount) != 8 {
		t.Fatalf("expected 8 challenge types, got %d", int(challengeCount))
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldChallenge returns true for protected paths
// ---------------------------------------------------------------------------

func TestShouldChallenge_ProtectedPaths(t *testing.T) {
	e := NewEngine()
	protectedPaths := []string{
		"/secure/",
		"/secure/login",
		"/secure/admin/panel",
		"/protected/",
		"/protected/resource",
		"/protected/deep/nested/path",
		"/members/",
		"/members/profile",
		"/members/settings/account",
	}
	for _, path := range protectedPaths {
		if !e.ShouldChallenge(path, "browser", 0) {
			t.Errorf("ShouldChallenge(%q, \"browser\", 0) = false, want true", path)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. ShouldChallenge returns false for normal paths with normal clients
// ---------------------------------------------------------------------------

func TestShouldChallenge_NormalPathNormalClient(t *testing.T) {
	e := NewEngine()
	normalPaths := []string{
		"/",
		"/index.html",
		"/about",
		"/api/data",
		"/securepath",   // does NOT start with /secure/
		"/protectedfoo", // does NOT start with /protected/
		"/membership",   // does NOT start with /members/
	}
	for _, path := range normalPaths {
		if e.ShouldChallenge(path, "browser", 0) {
			t.Errorf("ShouldChallenge(%q, \"browser\", 0) = true, want false", path)
		}
	}
}

func TestShouldChallenge_UnknownClientLowRequestCount(t *testing.T) {
	e := NewEngine()
	// "unknown" class with requestCount <= 100 should always return false
	for i := 0; i < 100; i++ {
		if e.ShouldChallenge("/some/path", "unknown", 50) {
			t.Fatal("ShouldChallenge returned true for unknown client with requestCount=50 on a normal path")
		}
	}
}

// ---------------------------------------------------------------------------
// 4. SelectChallenge is deterministic (same clientID = same challenge)
// ---------------------------------------------------------------------------

func TestSelectChallenge_Deterministic(t *testing.T) {
	e := NewEngine()
	clientIDs := []string{
		"client-abc-123",
		"user@example.com",
		"192.168.1.1-Mozilla/5.0",
		"",
		"a very long client identifier string that goes on and on",
	}
	for _, id := range clientIDs {
		first := e.SelectChallenge(id)
		for i := 0; i < 50; i++ {
			got := e.SelectChallenge(id)
			if got != first {
				t.Errorf("SelectChallenge(%q) returned %d on call %d, but %d on first call", id, got, i+2, first)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 5. SelectChallenge returns different challenges for different clientIDs
// ---------------------------------------------------------------------------

func TestSelectChallenge_DifferentClients(t *testing.T) {
	e := NewEngine()
	// Use a large enough sample to ensure we see at least 2 distinct challenge types
	seen := make(map[ChallengeType]bool)
	for i := 0; i < 100; i++ {
		ct := e.SelectChallenge(fmt.Sprintf("client-%d", i))
		seen[ct] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 distinct challenge types across 100 clients, got %d", len(seen))
	}
}

func TestSelectChallenge_AllTypesReachable(t *testing.T) {
	e := NewEngine()
	seen := make(map[ChallengeType]bool)
	// With enough clients, we should cover all 8 types
	for i := 0; i < 10000; i++ {
		ct := e.SelectChallenge(fmt.Sprintf("exhaustive-client-%d", i))
		seen[ct] = true
	}
	for i := 0; i < int(challengeCount); i++ {
		if !seen[ChallengeType(i)] {
			t.Errorf("challenge type %d was never selected across 10000 clients", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. ServeChallenge returns 403 and writes HTML for each challenge type
// ---------------------------------------------------------------------------

func TestServeChallenge_Returns403AndHTML(t *testing.T) {
	e := NewEngine()
	challenges := []ChallengeType{
		ChallengeRecaptchaV2,
		ChallengeRecaptchaV3,
		ChallengeHCaptcha,
		ChallengeTurnstile,
		ChallengeCloudflareUAM,
		ChallengeAWSWAF,
		ChallengeMathProblem,
		ChallengeSVGText,
	}
	for _, ct := range challenges {
		req := httptest.NewRequest(http.MethodGet, "/test/path?q=1", nil)
		w := httptest.NewRecorder()

		status := e.ServeChallenge(w, req, ct)

		if status != http.StatusForbidden {
			t.Errorf("challenge type %d: returned status %d, want %d", ct, status, http.StatusForbidden)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("challenge type %d: recorder status %d, want %d", ct, w.Code, http.StatusForbidden)
		}
		body := w.Body.String()
		if !strings.Contains(body, "<!DOCTYPE html>") {
			t.Errorf("challenge type %d: response body does not contain <!DOCTYPE html>", ct)
		}
		if len(body) < 100 {
			t.Errorf("challenge type %d: response body suspiciously short (%d bytes)", ct, len(body))
		}
	}
}

func TestServeChallenge_DefaultFallback(t *testing.T) {
	e := NewEngine()
	// Use an invalid challenge type to trigger the default branch
	req := httptest.NewRequest(http.MethodGet, "/fallback", nil)
	w := httptest.NewRecorder()

	status := e.ServeChallenge(w, req, ChallengeType(999))

	if status != http.StatusForbidden {
		t.Errorf("default challenge: returned status %d, want %d", status, http.StatusForbidden)
	}
	body := w.Body.String()
	// Default falls back to recaptchaV2Page which contains "reCAPTCHA"
	if !strings.Contains(body, "reCAPTCHA") {
		t.Error("default challenge: expected fallback to reCAPTCHA v2 page")
	}
}

// ---------------------------------------------------------------------------
// 7. ServeChallenge sets proper Content-Type and Cache-Control headers
// ---------------------------------------------------------------------------

func TestServeChallenge_Headers(t *testing.T) {
	e := NewEngine()
	challenges := []ChallengeType{
		ChallengeRecaptchaV2,
		ChallengeRecaptchaV3,
		ChallengeHCaptcha,
		ChallengeTurnstile,
		ChallengeCloudflareUAM,
		ChallengeAWSWAF,
		ChallengeMathProblem,
		ChallengeSVGText,
	}
	for _, ct := range challenges {
		req := httptest.NewRequest(http.MethodGet, "/header-test", nil)
		w := httptest.NewRecorder()
		e.ServeChallenge(w, req, ct)

		contentType := w.Header().Get("Content-Type")
		if contentType != "text/html; charset=utf-8" {
			t.Errorf("challenge type %d: Content-Type = %q, want %q", ct, contentType, "text/html; charset=utf-8")
		}

		cacheControl := w.Header().Get("Cache-Control")
		if cacheControl != "no-store, no-cache, must-revalidate" {
			t.Errorf("challenge type %d: Cache-Control = %q, want %q", ct, cacheControl, "no-store, no-cache, must-revalidate")
		}
	}
}

func TestServeChallenge_RecaptchaV3SetsScoreHeader(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/v3-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeRecaptchaV3)

	score := w.Header().Get("X-ReCaptcha-Score")
	if score != "0.9" {
		t.Errorf("reCAPTCHA v3: X-ReCaptcha-Score = %q, want %q", score, "0.9")
	}
}

// ---------------------------------------------------------------------------
// 8. HandleVerify processes POST and returns 302 or 403
// ---------------------------------------------------------------------------

func TestHandleVerify_Redirect(t *testing.T) {
	e := NewEngine()
	// Run many times to ensure we hit the 302 redirect path (50% chance)
	gotRedirect := false
	gotEscalation := false
	for i := 0; i < 200; i++ {
		form := url.Values{}
		form.Set("redirect", "/original/page")
		form.Set("csrf_token", "sometoken")
		form.Set("challenge_type", "recaptcha_v2")
		req := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		status := e.HandleVerify(w, req)

		if status == http.StatusFound {
			gotRedirect = true
			if w.Code != http.StatusFound {
				t.Errorf("redirect case: recorder status %d, want %d", w.Code, http.StatusFound)
			}
			loc := w.Header().Get("Location")
			if loc != "/original/page" {
				t.Errorf("redirect case: Location = %q, want %q", loc, "/original/page")
			}
		} else if status == http.StatusForbidden {
			gotEscalation = true
			if w.Code != http.StatusForbidden {
				t.Errorf("escalation case: recorder status %d, want %d", w.Code, http.StatusForbidden)
			}
			body := w.Body.String()
			if !strings.Contains(body, "<!DOCTYPE html>") {
				t.Error("escalation case: response body does not contain HTML")
			}
		} else {
			t.Errorf("unexpected status %d", status)
		}
	}
	if !gotRedirect {
		t.Error("never got a 302 redirect after 200 attempts (expected ~50% chance)")
	}
	if !gotEscalation {
		t.Error("never got a 403 escalation after 200 attempts (expected ~50% chance)")
	}
}

// ---------------------------------------------------------------------------
// 9. HandleVerify with empty redirect defaults to "/"
// ---------------------------------------------------------------------------

func TestHandleVerify_EmptyRedirectDefaultsToRoot(t *testing.T) {
	e := NewEngine()
	// Run many times to guarantee we hit the redirect path at least once
	for i := 0; i < 200; i++ {
		form := url.Values{}
		// Do not set redirect — it should default to "/"
		form.Set("csrf_token", "token")
		req := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		status := e.HandleVerify(w, req)
		if status == http.StatusFound {
			loc := w.Header().Get("Location")
			if loc != "/" {
				t.Errorf("empty redirect: Location = %q, want %q", loc, "/")
			}
			return // Found the redirect case, test passes
		}
	}
	t.Fatal("never got a 302 redirect after 200 attempts to verify empty redirect defaults to /")
}

// ---------------------------------------------------------------------------
// 10. csrfToken is deterministic
// ---------------------------------------------------------------------------

func TestCsrfToken_Deterministic(t *testing.T) {
	e := NewEngine()
	paths := []string{"/", "/secure/login", "/members/profile", "/test?q=1", ""}
	for _, path := range paths {
		first := e.csrfToken(path)
		for i := 0; i < 20; i++ {
			got := e.csrfToken(path)
			if got != first {
				t.Errorf("csrfToken(%q) returned %q on call %d, but %q on first call", path, got, i+2, first)
			}
		}
	}
}

func TestCsrfToken_DifferentPathsDifferentTokens(t *testing.T) {
	e := NewEngine()
	token1 := e.csrfToken("/path-a")
	token2 := e.csrfToken("/path-b")
	if token1 == token2 {
		t.Errorf("csrfToken returned same token for different paths: %q", token1)
	}
}

func TestCsrfToken_MatchesExpectedFormat(t *testing.T) {
	e := NewEngine()
	token := e.csrfToken("/test")
	// csrfToken returns hex encoding of first 16 bytes of SHA-256 = 32 hex chars
	if len(token) != 32 {
		t.Errorf("csrfToken length = %d, want 32", len(token))
	}
	// Verify it matches the expected computation
	h := sha256.Sum256([]byte("csrf-salt-glitch:/test"))
	expected := fmt.Sprintf("%x", h[:16])
	if token != expected {
		t.Errorf("csrfToken(/test) = %q, want %q", token, expected)
	}
}

// ---------------------------------------------------------------------------
// 11. Each challenge page contains the proper form action "/captcha/verify"
// ---------------------------------------------------------------------------

func TestServeChallenge_ContainsFormAction(t *testing.T) {
	e := NewEngine()
	challenges := []ChallengeType{
		ChallengeRecaptchaV2,
		ChallengeRecaptchaV3,
		ChallengeHCaptcha,
		ChallengeTurnstile,
		ChallengeCloudflareUAM,
		ChallengeAWSWAF,
		ChallengeMathProblem,
		ChallengeSVGText,
	}
	for _, ct := range challenges {
		req := httptest.NewRequest(http.MethodGet, "/form-action-test", nil)
		w := httptest.NewRecorder()
		e.ServeChallenge(w, req, ct)

		body := w.Body.String()
		if !strings.Contains(body, `action="/captcha/verify"`) {
			t.Errorf("challenge type %d: response body does not contain form action /captcha/verify", ct)
		}
	}
}

// ---------------------------------------------------------------------------
// 12. Each challenge page includes hidden redirect and csrf_token fields
// ---------------------------------------------------------------------------

func TestServeChallenge_ContainsHiddenFields(t *testing.T) {
	e := NewEngine()
	challenges := []ChallengeType{
		ChallengeRecaptchaV2,
		ChallengeRecaptchaV3,
		ChallengeHCaptcha,
		ChallengeTurnstile,
		ChallengeCloudflareUAM,
		ChallengeAWSWAF,
		ChallengeMathProblem,
		ChallengeSVGText,
	}
	for _, ct := range challenges {
		req := httptest.NewRequest(http.MethodGet, "/hidden-field-test?key=val", nil)
		w := httptest.NewRecorder()
		e.ServeChallenge(w, req, ct)

		body := w.Body.String()

		// Check redirect hidden field with the full path+query
		if !strings.Contains(body, `name="redirect"`) {
			t.Errorf("challenge type %d: missing hidden redirect field", ct)
		}
		if !strings.Contains(body, `/hidden-field-test?key=val`) {
			t.Errorf("challenge type %d: redirect value does not contain the full path with query", ct)
		}

		// Check csrf_token hidden field
		if !strings.Contains(body, `name="csrf_token"`) {
			t.Errorf("challenge type %d: missing hidden csrf_token field", ct)
		}

		// The csrf token should be based on just the path (not the query)
		expectedCSRF := e.csrfToken("/hidden-field-test")
		if !strings.Contains(body, expectedCSRF) {
			t.Errorf("challenge type %d: csrf token %q not found in body", ct, expectedCSRF)
		}
	}
}

// ---------------------------------------------------------------------------
// 13. Math problem page contains math operators
// ---------------------------------------------------------------------------

func TestMathProblemPage_ContainsMathOperators(t *testing.T) {
	e := NewEngine()
	// Test many paths to ensure we see at least some of the operators
	seenPlus := false
	seenMinus := false
	seenTimes := false
	for i := 0; i < 200; i++ {
		path := fmt.Sprintf("/math-test/%d", i)
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		e.ServeChallenge(w, req, ChallengeMathProblem)

		body := w.Body.String()
		if strings.Contains(body, " + ") {
			seenPlus = true
		}
		if strings.Contains(body, " - ") {
			seenMinus = true
		}
		// The multiplication sign is rendered as &times;
		if strings.Contains(body, "&times;") {
			seenTimes = true
		}
	}
	if !seenPlus {
		t.Error("never saw '+' operator across 200 math problem paths")
	}
	if !seenMinus {
		t.Error("never saw '-' operator across 200 math problem paths")
	}
	if !seenTimes {
		t.Error("never saw '&times;' (multiplication) operator across 200 math problem paths")
	}
}

func TestMathProblemPage_IsDeterministic(t *testing.T) {
	e := NewEngine()
	req1 := httptest.NewRequest(http.MethodGet, "/math-det", nil)
	w1 := httptest.NewRecorder()
	e.ServeChallenge(w1, req1, ChallengeMathProblem)

	req2 := httptest.NewRequest(http.MethodGet, "/math-det", nil)
	w2 := httptest.NewRecorder()
	e.ServeChallenge(w2, req2, ChallengeMathProblem)

	if w1.Body.String() != w2.Body.String() {
		t.Error("math problem page is not deterministic for the same path")
	}
}

func TestMathProblemPage_ContainsChallengeTypeField(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/math-type", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeMathProblem)

	body := w.Body.String()
	if !strings.Contains(body, `value="math"`) {
		t.Error("math problem page does not contain challenge_type=math hidden field")
	}
}

// ---------------------------------------------------------------------------
// 14. SVG text page contains an SVG element
// ---------------------------------------------------------------------------

func TestSVGTextPage_ContainsSVG(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/svg-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeSVGText)

	body := w.Body.String()
	if !strings.Contains(body, "<svg") {
		t.Error("SVG text page does not contain <svg element")
	}
	if !strings.Contains(body, "</svg>") {
		t.Error("SVG text page does not contain closing </svg> tag")
	}
	if !strings.Contains(body, `xmlns="http://www.w3.org/2000/svg"`) {
		t.Error("SVG text page does not contain SVG namespace declaration")
	}
}

func TestSVGTextPage_ContainsTextElements(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/svg-text-elements", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeSVGText)

	body := w.Body.String()
	if !strings.Contains(body, "<text") {
		t.Error("SVG text page does not contain <text elements for CAPTCHA characters")
	}
}

func TestSVGTextPage_IsDeterministic(t *testing.T) {
	e := NewEngine()
	req1 := httptest.NewRequest(http.MethodGet, "/svg-det", nil)
	w1 := httptest.NewRecorder()
	e.ServeChallenge(w1, req1, ChallengeSVGText)

	req2 := httptest.NewRequest(http.MethodGet, "/svg-det", nil)
	w2 := httptest.NewRecorder()
	e.ServeChallenge(w2, req2, ChallengeSVGText)

	if w1.Body.String() != w2.Body.String() {
		t.Error("SVG text page is not deterministic for the same path")
	}
}

func TestSVGTextPage_ContainsChallengeTypeField(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/svg-type", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeSVGText)

	body := w.Body.String()
	if !strings.Contains(body, `value="svg_text"`) {
		t.Error("SVG text page does not contain challenge_type=svg_text hidden field")
	}
}

func TestSVGTextPage_ContainsNoiseElements(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/svg-noise", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeSVGText)

	body := w.Body.String()
	// SVG page should have noise lines and circles
	if !strings.Contains(body, "<line") {
		t.Error("SVG text page does not contain noise <line elements")
	}
	if !strings.Contains(body, "<circle") {
		t.Error("SVG text page does not contain noise <circle elements")
	}
}

// ---------------------------------------------------------------------------
// Additional edge case tests
// ---------------------------------------------------------------------------

func TestServeChallenge_RedirectIncludesQueryString(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar&baz=qux", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeRecaptchaV2)

	body := w.Body.String()
	if !strings.Contains(body, "/test?foo=bar&amp;baz=qux") && !strings.Contains(body, "/test?foo=bar&baz=qux") {
		t.Error("redirect value does not include the query string")
	}
}

func TestServeChallenge_SpecificChallengeTypeNames(t *testing.T) {
	e := NewEngine()
	typeNames := map[ChallengeType]string{
		ChallengeRecaptchaV2:   "recaptcha_v2",
		ChallengeRecaptchaV3:   "recaptcha_v3",
		ChallengeHCaptcha:      "hcaptcha",
		ChallengeTurnstile:     "turnstile",
		ChallengeCloudflareUAM: "cloudflare_uam",
		ChallengeAWSWAF:        "aws_waf",
		ChallengeMathProblem:   "math",
		ChallengeSVGText:       "svg_text",
	}
	for ct, name := range typeNames {
		req := httptest.NewRequest(http.MethodGet, "/type-name-test", nil)
		w := httptest.NewRecorder()
		e.ServeChallenge(w, req, ct)

		body := w.Body.String()
		expected := fmt.Sprintf(`value="%s"`, name)
		if !strings.Contains(body, expected) {
			t.Errorf("challenge type %d: expected challenge_type value %q in body", ct, name)
		}
	}
}

func TestShouldChallenge_ProtectedPathBoundary(t *testing.T) {
	e := NewEngine()
	// Paths that look like protected paths but are not (no trailing slash match)
	nonProtected := []string{
		"/secure",      // missing trailing slash
		"/protected",   // missing trailing slash
		"/members",     // missing trailing slash
		"/securefoo/",  // different prefix
		"/SECURE/",     // case sensitive
		"/Protected/",  // case sensitive
		"/Members/",    // case sensitive
	}
	for _, path := range nonProtected {
		// These should not be unconditionally challenged
		// (with "browser" class and low request count)
		if e.ShouldChallenge(path, "browser", 0) {
			t.Errorf("ShouldChallenge(%q, \"browser\", 0) = true, want false", path)
		}
	}
}

func TestHandleVerify_EscalationSetsHeaders(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 200; i++ {
		form := url.Values{}
		form.Set("redirect", "/some/page")
		form.Set("csrf_token", "test-token")
		req := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		status := e.HandleVerify(w, req)
		if status == http.StatusForbidden {
			ct := w.Header().Get("Content-Type")
			if ct != "text/html; charset=utf-8" {
				t.Errorf("escalation: Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
			}
			cc := w.Header().Get("Cache-Control")
			if cc != "no-store, no-cache, must-revalidate" {
				t.Errorf("escalation: Cache-Control = %q, want %q", cc, "no-store, no-cache, must-revalidate")
			}
			return
		}
	}
	t.Fatal("never got an escalation response to verify headers")
}

func TestHandleVerify_EscalationContainsFormAction(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 200; i++ {
		form := url.Values{}
		form.Set("redirect", "/escalation/test")
		form.Set("csrf_token", "abc")
		req := httptest.NewRequest(http.MethodPost, "/captcha/verify", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		status := e.HandleVerify(w, req)
		if status == http.StatusForbidden {
			body := w.Body.String()
			if !strings.Contains(body, `action="/captcha/verify"`) {
				t.Error("escalation page does not contain form action /captcha/verify")
			}
			if !strings.Contains(body, "/escalation/test") {
				t.Error("escalation page does not contain the original redirect path")
			}
			return
		}
	}
	t.Fatal("never got an escalation response to verify form action")
}

func TestPathSeed_Deterministic(t *testing.T) {
	paths := []string{"/", "/test", "/a/b/c", ""}
	for _, p := range paths {
		first := pathSeed(p)
		for i := 0; i < 20; i++ {
			got := pathSeed(p)
			if got != first {
				t.Errorf("pathSeed(%q) returned %d on call %d, but %d on first call", p, got, i+2, first)
			}
		}
	}
}

func TestPathSeed_DifferentPaths(t *testing.T) {
	s1 := pathSeed("/path-a")
	s2 := pathSeed("/path-b")
	if s1 == s2 {
		t.Error("pathSeed returned same value for different paths")
	}
}

func TestServeChallenge_RecaptchaV2ContainsGrid(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/grid-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeRecaptchaV2)

	body := w.Body.String()
	if !strings.Contains(body, "image-grid") {
		t.Error("reCAPTCHA v2 page does not contain image grid")
	}
	if !strings.Contains(body, "I'm not a robot") {
		t.Error("reCAPTCHA v2 page does not contain 'I'm not a robot' text")
	}
}

func TestServeChallenge_HCaptchaContainsGrid(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/hcaptcha-grid", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeHCaptcha)

	body := w.Body.String()
	if !strings.Contains(body, "hCaptcha") {
		t.Error("hCaptcha page does not contain 'hCaptcha' text")
	}
	if !strings.Contains(body, "hc-grid") {
		t.Error("hCaptcha page does not contain grid")
	}
}

func TestServeChallenge_TurnstileContent(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/ts-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeTurnstile)

	body := w.Body.String()
	if !strings.Contains(body, "Turnstile") {
		t.Error("Turnstile page does not contain 'Turnstile' text")
	}
	if !strings.Contains(body, "cf-turnstile") {
		t.Error("Turnstile page does not contain cf-turnstile class")
	}
}

func TestServeChallenge_CloudflareUAMContent(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/uam-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeCloudflareUAM)

	body := w.Body.String()
	if !strings.Contains(body, "Cloudflare") {
		t.Error("Cloudflare UAM page does not contain 'Cloudflare' text")
	}
	if !strings.Contains(body, "Ray ID") {
		t.Error("Cloudflare UAM page does not contain Ray ID")
	}
}

func TestServeChallenge_AWSWAFContent(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/aws-test", nil)
	w := httptest.NewRecorder()
	e.ServeChallenge(w, req, ChallengeAWSWAF)

	body := w.Body.String()
	if !strings.Contains(body, "AWS WAF") {
		t.Error("AWS WAF page does not contain 'AWS WAF' text")
	}
	if !strings.Contains(body, "Request ID") {
		t.Error("AWS WAF page does not contain Request ID")
	}
}
