package privacy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// extractConsentRaw extracts the raw __consent cookie value from the
// Set-Cookie header. Go's http.SetCookie sanitizes the JSON by stripping
// internal double-quote characters, so the value looks like
// "{necessary:true,analytics:true}" rather than valid JSON. We return the
// raw string for substring-based assertions.
func extractConsentRaw(rec *httptest.ResponseRecorder) string {
	for _, line := range rec.Header()["Set-Cookie"] {
		if !strings.HasPrefix(line, "__consent=") {
			continue
		}
		val := strings.TrimPrefix(line, "__consent=")
		if idx := strings.Index(val, "; "); idx != -1 {
			val = val[:idx]
		}
		return val
	}
	return ""
}

// assertConsentValue checks whether a specific key has the expected boolean
// value in the sanitized __consent cookie string. Because http.SetCookie
// strips inner double-quotes, the cookie looks like
// "{necessary:true,analytics:false,...}" so we look for "key:true" or "key:false".
func assertConsentValue(t *testing.T, raw string, key string, want bool) {
	t.Helper()
	needle := key + ":true"
	if !want {
		needle = key + ":false"
	}
	if !strings.Contains(raw, needle) {
		t.Errorf("__consent cookie missing %q; raw value: %s", needle, raw)
	}
}

// ---------------------------------------------------------------------------
// 1. NewHandler creates a handler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldHandle: true for all privacy/consent paths
// ---------------------------------------------------------------------------

func TestShouldHandle_PrivacyPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/privacy-policy",
		"/terms-of-service",
		"/cookie-policy",
		"/.well-known/gpc",
		"/consent/preferences",
		"/consent/accept",
		"/consent/reject",
	}
	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. ShouldHandle: false for unrelated paths
// ---------------------------------------------------------------------------

func TestShouldHandle_UnrelatedPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/",
		"/index.html",
		"/about",
		"/api/metrics",
		"/consent",
		"/consent/",
		"/privacy",
		"/well-known/gpc",
		"/cookie-policy/extra",
		"/privacy-policy/details",
	}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. GET /privacy-policy returns HTML with privacy policy content (3000+ words)
// ---------------------------------------------------------------------------

func TestServePrivacyPolicy_StatusAndContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/privacy-policy", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("response code = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestServePrivacyPolicy_ContainsExpectedContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/privacy-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()

	needles := []string{
		"Privacy Policy",
		"GlitchApp",
		"GDPR",
		"CCPA",
		"Data Retention",
		"Your Rights",
		"California Privacy Rights",
		"Data Security",
		"Children",
		"Contact Information",
	}
	for _, s := range needles {
		if !strings.Contains(body, s) {
			t.Errorf("privacy policy body missing expected text: %q", s)
		}
	}
}

func TestServePrivacyPolicy_MinimumWordCount(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/privacy-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	wordCount := len(strings.Fields(body))
	if wordCount < 3000 {
		t.Errorf("privacy policy word count = %d, want >= 3000", wordCount)
	}
}

// ---------------------------------------------------------------------------
// 5. GET /terms-of-service returns HTML with ToS content
// ---------------------------------------------------------------------------

func TestServeTermsOfService_StatusAndContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/terms-of-service", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestServeTermsOfService_ContainsExpectedContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/terms-of-service", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()

	needles := []string{
		"Terms of Service",
		"GlitchApp",
		"Acceptance of Terms",
		"Intellectual Property",
		"Limitation of Liability",
		"Governing Law",
		"Dispute Resolution",
		"Termination",
	}
	for _, s := range needles {
		if !strings.Contains(body, s) {
			t.Errorf("terms of service body missing expected text: %q", s)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. GET /cookie-policy returns HTML with cookie categories table
// ---------------------------------------------------------------------------

func TestServeCookiePolicy_StatusAndContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/cookie-policy", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestServeCookiePolicy_ContainsCookieTables(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/cookie-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()

	// Must contain table elements
	if !strings.Contains(body, "<table") {
		t.Error("cookie policy missing <table> elements")
	}

	// Must list cookie categories
	categories := []string{
		"Necessary Cookies",
		"Analytics Cookies",
		"Marketing Cookies",
		"Preference Cookies",
	}
	for _, cat := range categories {
		if !strings.Contains(body, cat) {
			t.Errorf("cookie policy missing category: %q", cat)
		}
	}

	// Must list specific cookie names
	cookieNames := []string{
		"__session_id",
		"CookieConsent",
		"__consent",
		"_gdpr_consent",
		"_ga",
		"_fbp",
	}
	for _, cn := range cookieNames {
		if !strings.Contains(body, cn) {
			t.Errorf("cookie policy missing cookie name: %q", cn)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. GET /.well-known/gpc returns JSON with gpc:true
// ---------------------------------------------------------------------------

func TestServeGPC_StatusAndContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/gpc", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

func TestServeGPC_ResponseBody(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/gpc", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	var result map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse GPC JSON: %v", err)
	}

	gpcVal, ok := result["gpc"]
	if !ok {
		t.Fatal("GPC response missing 'gpc' key")
	}
	if gpcVal != true {
		t.Errorf("gpc = %v, want true", gpcVal)
	}

	if _, ok := result["lastUpdate"]; !ok {
		t.Error("GPC response missing 'lastUpdate' key")
	}
}

// ---------------------------------------------------------------------------
// 8. GET /consent/preferences returns HTML with toggle switches
// ---------------------------------------------------------------------------

func TestServePreferencesPage_StatusAndContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent/preferences", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
}

func TestServePreferencesPage_ContainsToggleSwitches(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent/preferences", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()

	// Must contain toggle-related elements
	if !strings.Contains(body, "toggle") {
		t.Error("preferences page missing toggle class")
	}
	if !strings.Contains(body, "slider") {
		t.Error("preferences page missing slider class")
	}

	// Must contain category labels
	categories := []string{
		"Necessary Cookies",
		"Analytics Cookies",
		"Marketing Cookies",
		"Preference Cookies",
		"Social Media Cookies",
	}
	for _, cat := range categories {
		if !strings.Contains(body, cat) {
			t.Errorf("preferences page missing category: %q", cat)
		}
	}

	// Must contain form with correct action
	if !strings.Contains(body, `action="/consent/preferences"`) {
		t.Error("preferences page missing form action /consent/preferences")
	}

	// Must contain checkboxes for analytics, marketing, preferences
	checkboxNames := []string{
		`name="analytics"`,
		`name="marketing"`,
		`name="preferences"`,
		`name="social_media"`,
	}
	for _, n := range checkboxNames {
		if !strings.Contains(body, n) {
			t.Errorf("preferences page missing checkbox: %q", n)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. POST /consent/accept sets consent cookies and redirects
// ---------------------------------------------------------------------------

func TestAcceptAll_SetsConsentCookiesAndRedirects(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/accept", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", status, http.StatusSeeOther)
	}

	// Check redirect location defaults to "/" when no Referer
	loc := rec.Header().Get("Location")
	if loc != "/" {
		t.Errorf("Location = %q, want %q", loc, "/")
	}

	// Check that consent cookies are set
	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	if _, ok := cookieMap["__consent"]; !ok {
		t.Error("missing __consent cookie")
	}
	if _, ok := cookieMap["_gdpr_consent"]; !ok {
		t.Error("missing _gdpr_consent cookie")
	}
	if _, ok := cookieMap["CookieConsent"]; !ok {
		t.Error("missing CookieConsent cookie")
	}

	// __consent should have all categories true
	consentRaw := extractConsentRaw(rec)
	if consentRaw == "" {
		t.Fatal("__consent cookie not found in raw headers")
	}
	for _, key := range []string{"necessary", "analytics", "marketing", "preferences"} {
		assertConsentValue(t, consentRaw, key, true)
	}

	// _gdpr_consent should be "accepted"
	if cookieMap["_gdpr_consent"].Value != "accepted" {
		t.Errorf("_gdpr_consent = %q, want %q", cookieMap["_gdpr_consent"].Value, "accepted")
	}
}

func TestAcceptAll_RedirectsToReferer(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/accept", nil)
	req.Header.Set("Referer", "/some-page")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "/some-page" {
		t.Errorf("Location = %q, want %q", loc, "/some-page")
	}
}

// ---------------------------------------------------------------------------
// 10. POST /consent/reject sets minimal consent cookies and redirects
// ---------------------------------------------------------------------------

func TestRejectAll_SetsMinimalCookiesAndRedirects(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/reject", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", status, http.StatusSeeOther)
	}

	loc := rec.Header().Get("Location")
	if loc != "/" {
		t.Errorf("Location = %q, want %q", loc, "/")
	}

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// __consent should have only necessary=true, rest false
	consentRaw := extractConsentRaw(rec)
	if consentRaw == "" {
		t.Fatal("__consent cookie not found in raw headers")
	}
	assertConsentValue(t, consentRaw, "necessary", true)
	for _, key := range []string{"analytics", "marketing", "preferences"} {
		assertConsentValue(t, consentRaw, key, false)
	}

	// _gdpr_consent should be "necessary_only"
	if cookieMap["_gdpr_consent"].Value != "necessary_only" {
		t.Errorf("_gdpr_consent = %q, want %q", cookieMap["_gdpr_consent"].Value, "necessary_only")
	}
}

func TestRejectAll_RedirectsToReferer(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/reject", nil)
	req.Header.Set("Referer", "/dashboard")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("Location = %q, want %q", loc, "/dashboard")
	}
}

// ---------------------------------------------------------------------------
// 11. POST /consent/preferences processes form and sets cookies
// ---------------------------------------------------------------------------

func TestProcessPreferences_SelectiveConsent(t *testing.T) {
	h := NewHandler()
	formBody := strings.NewReader("analytics=true&marketing=false&preferences=true")
	req := httptest.NewRequest(http.MethodPost, "/consent/preferences", formBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", status, http.StatusSeeOther)
	}

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	consentRaw := extractConsentRaw(rec)
	if consentRaw == "" {
		t.Fatal("__consent cookie not found in raw headers")
	}

	assertConsentValue(t, consentRaw, "necessary", true)
	assertConsentValue(t, consentRaw, "analytics", true)
	assertConsentValue(t, consentRaw, "marketing", false)
	assertConsentValue(t, consentRaw, "preferences", true)

	// Not all accepted, so should be "necessary_only"
	if cookieMap["_gdpr_consent"].Value != "necessary_only" {
		t.Errorf("_gdpr_consent = %q, want %q", cookieMap["_gdpr_consent"].Value, "necessary_only")
	}
}

func TestProcessPreferences_AllAccepted(t *testing.T) {
	h := NewHandler()
	formBody := strings.NewReader("analytics=true&marketing=true&preferences=true")
	req := httptest.NewRequest(http.MethodPost, "/consent/preferences", formBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	if cookieMap["_gdpr_consent"].Value != "accepted" {
		t.Errorf("_gdpr_consent = %q, want %q", cookieMap["_gdpr_consent"].Value, "accepted")
	}
}

func TestProcessPreferences_RedirectsToReferer(t *testing.T) {
	h := NewHandler()
	formBody := strings.NewReader("analytics=true&marketing=true&preferences=true")
	req := httptest.NewRequest(http.MethodPost, "/consent/preferences", formBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "/settings")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	if loc != "/settings" {
		t.Errorf("Location = %q, want %q", loc, "/settings")
	}
}

// ---------------------------------------------------------------------------
// 12. DNT header causes Tk: N response header
// ---------------------------------------------------------------------------

func TestDNTHeader_SetsTkHeader(t *testing.T) {
	h := NewHandler()
	paths := []string{"/privacy-policy", "/terms-of-service", "/cookie-policy", "/.well-known/gpc"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("DNT", "1")
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		tk := rec.Header().Get("Tk")
		if tk != "N" {
			t.Errorf("path=%q: Tk header = %q, want %q", p, tk, "N")
		}
	}
}

func TestNoDNTHeader_NoTkHeader(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/privacy-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	tk := rec.Header().Get("Tk")
	if tk != "" {
		t.Errorf("Tk header = %q, want empty (no DNT sent)", tk)
	}
}

func TestDNTHeader_OnPostEndpoints(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/accept", nil)
	req.Header.Set("DNT", "1")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	tk := rec.Header().Get("Tk")
	if tk != "N" {
		t.Errorf("Tk header = %q, want %q on POST /consent/accept with DNT", tk, "N")
	}
}

// ---------------------------------------------------------------------------
// 13. ConsentBanner("onetrust") returns HTML with bottom bar
// ---------------------------------------------------------------------------

func TestConsentBanner_OneTrust(t *testing.T) {
	h := NewHandler()
	banner := h.ConsentBanner("onetrust")

	if banner == "" {
		t.Fatal("onetrust banner is empty")
	}
	if !strings.Contains(banner, "onetrust-consent-sdk") {
		t.Error("onetrust banner missing 'onetrust-consent-sdk' id")
	}
	if !strings.Contains(banner, "position:fixed;bottom:0") {
		t.Error("onetrust banner missing bottom positioning (not a bottom bar)")
	}
	if !strings.Contains(banner, "Accept All") {
		t.Error("onetrust banner missing 'Accept All' button")
	}
	if !strings.Contains(banner, "Reject All") {
		t.Error("onetrust banner missing 'Reject All' button")
	}
	if !strings.Contains(banner, "We value your privacy") {
		t.Error("onetrust banner missing 'We value your privacy' text")
	}
}

// ---------------------------------------------------------------------------
// 14. ConsentBanner("cookiebot") returns HTML with modal
// ---------------------------------------------------------------------------

func TestConsentBanner_CookieBot(t *testing.T) {
	h := NewHandler()
	banner := h.ConsentBanner("cookiebot")

	if banner == "" {
		t.Fatal("cookiebot banner is empty")
	}
	if !strings.Contains(banner, "CybotCookiebotDialog") {
		t.Error("cookiebot banner missing 'CybotCookiebotDialog' id")
	}
	// Modal: centered with transform:translate(-50%,-50%)
	if !strings.Contains(banner, "translate(-50%,-50%)") {
		t.Error("cookiebot banner missing modal centering transform")
	}
	// Should have an overlay
	if !strings.Contains(banner, "CybotCookiebotDialogOverlay") {
		t.Error("cookiebot banner missing overlay element")
	}
	// Should have tab structure
	if !strings.Contains(banner, "Consent") && !strings.Contains(banner, "Details") && !strings.Contains(banner, "About") {
		t.Error("cookiebot banner missing tab structure")
	}
	if !strings.Contains(banner, "Accept All") {
		t.Error("cookiebot banner missing 'Accept All' button")
	}
}

// ---------------------------------------------------------------------------
// 15. ConsentBanner("minimal") returns HTML with floating box
// ---------------------------------------------------------------------------

func TestConsentBanner_Minimal(t *testing.T) {
	h := NewHandler()
	banner := h.ConsentBanner("minimal")

	if banner == "" {
		t.Fatal("minimal banner is empty")
	}
	if !strings.Contains(banner, "cookie-notice-minimal") {
		t.Error("minimal banner missing 'cookie-notice-minimal' id")
	}
	// Floating box: fixed position, bottom-left, with max-width
	if !strings.Contains(banner, "position:fixed") {
		t.Error("minimal banner missing fixed positioning")
	}
	if !strings.Contains(banner, "bottom:20px") {
		t.Error("minimal banner missing bottom:20px")
	}
	if !strings.Contains(banner, "left:20px") {
		t.Error("minimal banner missing left:20px")
	}
	if !strings.Contains(banner, "max-width:340px") {
		t.Error("minimal banner missing max-width:340px (not a floating box)")
	}
	if !strings.Contains(banner, "Accept") {
		t.Error("minimal banner missing Accept button")
	}
}

// ---------------------------------------------------------------------------
// 16. ConsentSnippet() returns non-empty HTML
// ---------------------------------------------------------------------------

func TestConsentSnippet_NonEmpty(t *testing.T) {
	h := NewHandler()
	// Call multiple times to exercise the random selection
	for i := 0; i < 10; i++ {
		snippet := h.ConsentSnippet()
		if snippet == "" {
			t.Fatalf("ConsentSnippet() returned empty string on iteration %d", i)
		}
		if !strings.Contains(snippet, "<div") {
			t.Errorf("ConsentSnippet() missing HTML div element on iteration %d", i)
		}
		if !strings.Contains(snippet, "<script>") {
			t.Errorf("ConsentSnippet() missing script tag on iteration %d", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 17. Consent cookies have correct attributes (Path, SameSite, MaxAge)
// ---------------------------------------------------------------------------

func TestConsentCookieAttributes(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/accept", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	expectedNames := map[string]bool{
		"__consent":      false,
		"_gdpr_consent":  false,
		"CookieConsent":  false,
	}

	for _, c := range cookies {
		if _, expected := expectedNames[c.Name]; !expected {
			continue
		}
		expectedNames[c.Name] = true

		// Path must be "/"
		if c.Path != "/" {
			t.Errorf("cookie %q: Path = %q, want %q", c.Name, c.Path, "/")
		}

		// MaxAge must be 1 year (31536000 seconds)
		if c.MaxAge != 31536000 {
			t.Errorf("cookie %q: MaxAge = %d, want %d", c.Name, c.MaxAge, 31536000)
		}

		// SameSite must be Lax
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("cookie %q: SameSite = %v, want %v", c.Name, c.SameSite, http.SameSiteLaxMode)
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("cookie %q not found in response", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional tests for edge cases and fuller coverage
// ---------------------------------------------------------------------------

func TestConsentBanner_UnknownStyleDefaultsToOneTrust(t *testing.T) {
	h := NewHandler()
	banner := h.ConsentBanner("unknown-style")
	oneTrust := h.ConsentBanner("onetrust")

	if banner != oneTrust {
		t.Error("unknown style did not default to onetrust banner")
	}
}

func TestServeHTTP_UnknownPath_Returns404(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", status, http.StatusNotFound)
	}
}

func TestConsentAccept_GETMethodNotHandled(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent/accept", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	// GET on /consent/accept is not handled; should 404
	if status != http.StatusNotFound {
		t.Errorf("GET /consent/accept status = %d, want %d", status, http.StatusNotFound)
	}
}

func TestConsentReject_GETMethodNotHandled(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent/reject", nil)
	rec := httptest.NewRecorder()

	status := h.ServeHTTP(rec, req)

	if status != http.StatusNotFound {
		t.Errorf("GET /consent/reject status = %d, want %d", status, http.StatusNotFound)
	}
}

func TestPrivacyPolicy_ContainsHTMLDoctype(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/privacy-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Error("privacy policy does not start with <!DOCTYPE html>")
	}
}

func TestTermsOfService_ContainsHTMLDoctype(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/terms-of-service", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Error("terms of service does not start with <!DOCTYPE html>")
	}
}

func TestCookiePolicy_ContainsHTMLDoctype(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/cookie-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.HasPrefix(body, "<!DOCTYPE html>") {
		t.Error("cookie policy does not start with <!DOCTYPE html>")
	}
}

func TestRejectCookies_CookieConsentSetToTrue(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodPost, "/consent/reject", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	// Even on reject, CookieConsent should be "true" (indicates consent was given)
	if cookieMap["CookieConsent"].Value != "true" {
		t.Errorf("CookieConsent = %q, want %q", cookieMap["CookieConsent"].Value, "true")
	}
}

func TestProcessPreferences_NoneAccepted(t *testing.T) {
	h := NewHandler()
	formBody := strings.NewReader("analytics=false&marketing=false&preferences=false")
	req := httptest.NewRequest(http.MethodPost, "/consent/preferences", formBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}

	consentRaw := extractConsentRaw(rec)
	if consentRaw == "" {
		t.Fatal("__consent cookie not found in raw headers")
	}

	assertConsentValue(t, consentRaw, "necessary", true)
	assertConsentValue(t, consentRaw, "analytics", false)
	assertConsentValue(t, consentRaw, "marketing", false)
	assertConsentValue(t, consentRaw, "preferences", false)

	if cookieMap["_gdpr_consent"].Value != "necessary_only" {
		t.Errorf("_gdpr_consent = %q, want %q", cookieMap["_gdpr_consent"].Value, "necessary_only")
	}
}

func TestConsentBanner_AllStylesContainScript(t *testing.T) {
	h := NewHandler()
	styles := []string{"onetrust", "cookiebot", "minimal"}
	for _, style := range styles {
		banner := h.ConsentBanner(style)
		if !strings.Contains(banner, "<script>") {
			t.Errorf("banner style %q missing <script> tag", style)
		}
		if !strings.Contains(banner, "CookieConsent") {
			t.Errorf("banner style %q missing CookieConsent check", style)
		}
	}
}

func TestConsentBanner_AllStylesContainConsentEndpoints(t *testing.T) {
	h := NewHandler()
	styles := []string{"onetrust", "cookiebot", "minimal"}
	for _, style := range styles {
		banner := h.ConsentBanner(style)
		if !strings.Contains(banner, "/consent/accept") {
			t.Errorf("banner style %q missing /consent/accept endpoint", style)
		}
	}
}

func TestPreferencesPage_ContainsSaveButton(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/consent/preferences", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Save Preferences") {
		t.Error("preferences page missing 'Save Preferences' button")
	}
}

func TestCookiePolicy_ContainsGPCSection(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/cookie-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Global Privacy Control") {
		t.Error("cookie policy missing Global Privacy Control section")
	}
	if !strings.Contains(body, "/.well-known/gpc") {
		t.Error("cookie policy missing reference to /.well-known/gpc")
	}
}

func TestCookiePolicy_ContainsDNTSection(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/cookie-policy", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Do Not Track") {
		t.Error("cookie policy missing Do Not Track section")
	}
	if !strings.Contains(body, "Tk: N") {
		t.Error("cookie policy missing reference to Tk: N header")
	}
}
