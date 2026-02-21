package cookies

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// helper: call SetTraps on a recorder and return the recorded cookies.
func setTrapsAndGetCookies(t *testing.T, tracker *Tracker, clientID string) []*http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, r, clientID)
	resp := w.Result()
	defer resp.Body.Close()
	return resp.Cookies()
}

// cookieMap converts a cookie slice to a name -> *http.Cookie map.
func cookieMap(cookies []*http.Cookie) map[string]*http.Cookie {
	m := make(map[string]*http.Cookie, len(cookies))
	for _, c := range cookies {
		m[c.Name] = c
	}
	return m
}

// -----------------------------------------------------------------------
// SetTraps tests
// -----------------------------------------------------------------------

func TestSetTraps_SetsAllCookies(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_abc123")
	cm := cookieMap(cookies)

	expected := []string{
		cookieSession,
		cookieFP,
		cookieTrap,
		cookieDomain,
		cookieSecure,
		cookieSameSite,
	}

	for _, name := range expected {
		if _, ok := cm[name]; !ok {
			t.Errorf("expected cookie %q to be set, but it was not", name)
		}
	}
}

func TestSetTraps_SessionCookie_Properties(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_sess_test")
	cm := cookieMap(cookies)

	c := cm[cookieSession]
	if c == nil {
		t.Fatal("session cookie missing")
	}
	if !c.HttpOnly {
		t.Error("session cookie should be HttpOnly")
	}
	if c.Path != "/" {
		t.Errorf("session cookie Path = %q, want /", c.Path)
	}
	if c.MaxAge != 86400 {
		t.Errorf("session cookie MaxAge = %d, want 86400", c.MaxAge)
	}
}

func TestSetTraps_TrapCookie_MaxAgeZero(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_trap_test")
	cm := cookieMap(cookies)

	c := cm[cookieTrap]
	if c == nil {
		t.Fatal("trap cookie missing")
	}
	if c.MaxAge != 0 {
		t.Errorf("trap cookie MaxAge = %d, want 0", c.MaxAge)
	}
	if c.Expires.IsZero() {
		t.Error("trap cookie should have a far-future Expires value")
	}
}

func TestSetTraps_DomainMismatchCookie(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_domain_test")
	cm := cookieMap(cookies)

	c := cm[cookieDomain]
	if c == nil {
		t.Fatal("domain mismatch cookie missing")
	}
	// Go's http.SetCookie strips the leading dot from Domain per RFC 6265.
	// The wire format still includes "Domain=invalid-domain.test" which is
	// what matters for the trap — browsers reject it because it doesn't
	// match the request host.
	if c.Domain != "invalid-domain.test" && c.Domain != ".invalid-domain.test" {
		t.Errorf("domain cookie Domain = %q, want invalid-domain.test", c.Domain)
	}
}

func TestSetTraps_SecureCookie(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_secure_test")
	cm := cookieMap(cookies)

	c := cm[cookieSecure]
	if c == nil {
		t.Fatal("secure cookie missing")
	}
	if !c.Secure {
		t.Error("secure cookie should have Secure flag set")
	}
}

func TestSetTraps_SameSiteCookie(t *testing.T) {
	tracker := NewTracker()
	cookies := setTrapsAndGetCookies(t, tracker, "client_ss_test")
	cm := cookieMap(cookies)

	c := cm[cookieSameSite]
	if c == nil {
		t.Fatal("samesite cookie missing")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("samesite cookie SameSite = %v, want Strict", c.SameSite)
	}
	if c.Path != "/external/callback" {
		t.Errorf("samesite cookie Path = %q, want /external/callback", c.Path)
	}
}

func TestSetTraps_DeterministicValues(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_deterministic"

	c1 := setTrapsAndGetCookies(t, tracker, clientID)
	c2 := setTrapsAndGetCookies(t, tracker, clientID)

	cm1 := cookieMap(c1)
	cm2 := cookieMap(c2)

	for _, name := range []string{cookieSession, cookieFP, cookieTrap, cookieDomain, cookieSecure, cookieSameSite} {
		if cm1[name].Value != cm2[name].Value {
			t.Errorf("cookie %q not deterministic: %q != %q", name, cm1[name].Value, cm2[name].Value)
		}
	}
}

func TestSetTraps_DifferentClientsGetDifferentValues(t *testing.T) {
	tracker := NewTracker()
	c1 := setTrapsAndGetCookies(t, tracker, "client_aaa")
	c2 := setTrapsAndGetCookies(t, tracker, "client_bbb")

	cm1 := cookieMap(c1)
	cm2 := cookieMap(c2)

	if cm1[cookieSession].Value == cm2[cookieSession].Value {
		t.Error("different clients got the same session cookie value")
	}
}

// -----------------------------------------------------------------------
// Analyze tests
// -----------------------------------------------------------------------

func TestAnalyze_FirstRequest_NoCookies(t *testing.T) {
	tracker := NewTracker()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	analysis := tracker.Analyze(r, "client_new")

	if analysis.BotScore != 0.0 {
		t.Errorf("first request BotScore = %f, want 0.0", analysis.BotScore)
	}
	if analysis.CookieConsistency != 1.0 {
		t.Errorf("first request CookieConsistency = %f, want 1.0", analysis.CookieConsistency)
	}
}

func TestAnalyze_SubsequentRequest_WithSessionCookie(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_returning"

	// First request: set traps
	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Build second request with the session and fingerprint cookies
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/page", nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieSession || c.Name == cookieFP {
			req2.AddCookie(c)
		}
	}

	analysis := tracker.Analyze(req2, clientID)

	if !analysis.HasSessionCookie {
		t.Error("expected HasSessionCookie = true")
	}
	if !analysis.HasFingerprint {
		t.Error("expected HasFingerprint = true")
	}
	if analysis.HasTrapCookie {
		t.Error("expected HasTrapCookie = false")
	}
	if analysis.BotScore != 0.0 {
		t.Errorf("BotScore = %f, want 0.0 for well-behaved client", analysis.BotScore)
	}
	if analysis.CookieConsistency != 1.0 {
		t.Errorf("CookieConsistency = %f, want 1.0", analysis.CookieConsistency)
	}
}

func TestAnalyze_SubsequentRequest_NoCookies(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_no_jar"

	// Set traps first
	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)

	// Second request with no cookies at all
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	analysis := tracker.Analyze(req2, clientID)

	if analysis.HasSessionCookie {
		t.Error("expected HasSessionCookie = false")
	}
	if analysis.HasFingerprint {
		t.Error("expected HasFingerprint = false")
	}
	if analysis.BotScore < 0.4 {
		t.Errorf("BotScore = %f, want >= 0.4 for client missing all expected cookies", analysis.BotScore)
	}
	if len(analysis.MissingExpected) != 2 {
		t.Errorf("MissingExpected length = %d, want 2 (session + fp)", len(analysis.MissingExpected))
	}
}

func TestAnalyze_TrapCookieSentBack(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_bot_trap"

	// Set traps
	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Bot sends back ALL cookies including the trap
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		req2.AddCookie(c)
	}

	analysis := tracker.Analyze(req2, clientID)

	if !analysis.HasTrapCookie {
		t.Error("expected HasTrapCookie = true when trap cookie is sent back")
	}
	if analysis.BotScore < 0.3 {
		t.Errorf("BotScore = %f, want >= 0.3 for trap cookie present", analysis.BotScore)
	}
	if len(analysis.UnexpectedPresent) == 0 {
		t.Error("expected UnexpectedPresent to contain trap cookies")
	}
}

func TestAnalyze_DomainMismatchCookieSentBack(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_bot_domain"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Bot sends back only the domain mismatch cookie (and session + fp for clarity)
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieSession || c.Name == cookieFP || c.Name == cookieDomain {
			req2.AddCookie(c)
		}
	}

	analysis := tracker.Analyze(req2, clientID)

	if !analysis.HasTrapCookie {
		t.Error("expected HasTrapCookie = true for domain mismatch cookie")
	}

	found := false
	for _, name := range analysis.UnexpectedPresent {
		if name == cookieDomain {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in UnexpectedPresent", cookieDomain)
	}
}

func TestAnalyze_SecureCookieOnHTTP(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_bot_secure"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Bot sends back the Secure cookie on plain HTTP
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieSession || c.Name == cookieFP || c.Name == cookieSecure {
			req2.AddCookie(c)
		}
	}
	// Ensure TLS is nil (plain HTTP)
	req2.TLS = nil

	analysis := tracker.Analyze(req2, clientID)

	if !analysis.HasTrapCookie {
		t.Error("expected HasTrapCookie = true for Secure cookie on HTTP")
	}

	found := false
	for _, name := range analysis.UnexpectedPresent {
		if name == cookieSecure {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in UnexpectedPresent", cookieSecure)
	}
}

func TestAnalyze_CookieBomb(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_bomb"

	// Set traps first
	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Build a request with an enormous Cookie header
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	// Add the legitimate cookies
	for _, c := range resp.Cookies() {
		if c.Name == cookieSession || c.Name == cookieFP {
			req2.AddCookie(c)
		}
	}
	// Add a massive junk cookie to exceed the threshold
	bigVal := strings.Repeat("x", maxCookieHeaderLen+1)
	req2.AddCookie(&http.Cookie{Name: "bomb", Value: bigVal})

	analysis := tracker.Analyze(req2, clientID)

	if analysis.BotScore < 0.2 {
		t.Errorf("BotScore = %f, want >= 0.2 for cookie bomb", analysis.BotScore)
	}
}

func TestAnalyze_AllCookiesPresent_Bot(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_all_cookies_bot"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Send back every single cookie (a bot that accepts everything)
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		req2.AddCookie(c)
	}

	analysis := tracker.Analyze(req2, clientID)

	// Should detect trap cookies
	if !analysis.HasTrapCookie {
		t.Error("expected HasTrapCookie = true when all cookies are returned")
	}
	if analysis.BotScore < 0.3 {
		t.Errorf("BotScore = %f, want >= 0.3 for bot returning all cookies", analysis.BotScore)
	}
}

func TestAnalyze_PartialCookies(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_partial"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Only send back the session cookie (fingerprint missing)
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieSession {
			req2.AddCookie(c)
		}
	}

	analysis := tracker.Analyze(req2, clientID)

	if !analysis.HasSessionCookie {
		t.Error("expected HasSessionCookie = true")
	}
	if analysis.HasFingerprint {
		t.Error("expected HasFingerprint = false (fingerprint cookie not sent)")
	}
	// Bot score should be moderate (missing fingerprint, but has session)
	if analysis.BotScore < 0.1 {
		t.Errorf("BotScore = %f, want >= 0.1 for missing fingerprint", analysis.BotScore)
	}
	if analysis.BotScore > 0.5 {
		t.Errorf("BotScore = %f, want <= 0.5 (session present)", analysis.BotScore)
	}
}

func TestAnalyze_BotScoreCapping(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_max_bot"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)
	resp := w.Result()
	defer resp.Body.Close()

	// Send back all trap cookies, no legitimate cookies, and a cookie bomb
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range resp.Cookies() {
		if c.Name == cookieTrap || c.Name == cookieDomain || c.Name == cookieSecure {
			req2.AddCookie(c)
		}
	}
	bigVal := strings.Repeat("y", maxCookieHeaderLen+1)
	req2.AddCookie(&http.Cookie{Name: "overflow", Value: bigVal})

	analysis := tracker.Analyze(req2, clientID)

	if analysis.BotScore > 1.0 {
		t.Errorf("BotScore = %f, must not exceed 1.0", analysis.BotScore)
	}
}

// -----------------------------------------------------------------------
// JS Storage generation tests
// -----------------------------------------------------------------------

func TestGenerateJSStorage_ValidJS(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_js_test")

	if !strings.HasPrefix(js, "<script>") {
		t.Error("expected JS to start with <script>")
	}
	if !strings.HasSuffix(js, "</script>") {
		t.Error("expected JS to end with </script>")
	}
}

func TestGenerateJSStorage_ContainsLocalStorage(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_ls")

	if !strings.Contains(js, "localStorage.setItem") {
		t.Error("expected JS to contain localStorage.setItem")
	}
}

func TestGenerateJSStorage_ContainsSessionStorage(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_ss")

	if !strings.Contains(js, "sessionStorage.setItem") {
		t.Error("expected JS to contain sessionStorage.setItem")
	}
}

func TestGenerateJSStorage_ContainsDocumentCookie(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_dc")

	if !strings.Contains(js, "document.cookie") {
		t.Error("expected JS to contain document.cookie")
	}
}

func TestGenerateJSStorage_ContainsCanaryElement(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_canary")

	if !strings.Contains(js, "createElement") {
		t.Error("expected JS to contain createElement for canary element")
	}
	if !strings.Contains(js, "display") {
		t.Error("expected canary element to be hidden (display:none)")
	}
	if !strings.Contains(js, "data-token") {
		t.Error("expected canary element to have data-token attribute")
	}
}

func TestGenerateJSStorage_Deterministic(t *testing.T) {
	tracker := NewTracker()
	js1 := tracker.GenerateJSStorage("client_det")
	js2 := tracker.GenerateJSStorage("client_det")

	if js1 != js2 {
		t.Error("GenerateJSStorage should be deterministic for the same clientID")
	}
}

func TestGenerateJSStorage_DifferentClients(t *testing.T) {
	tracker := NewTracker()
	js1 := tracker.GenerateJSStorage("client_x")
	js2 := tracker.GenerateJSStorage("client_y")

	if js1 == js2 {
		t.Error("different clients should produce different JS")
	}
}

func TestGenerateJSStorage_ContainsTryCatch(t *testing.T) {
	tracker := NewTracker()
	js := tracker.GenerateJSStorage("client_tc")

	if !strings.Contains(js, "try") || !strings.Contains(js, "catch") {
		t.Error("expected JS to contain try/catch for error handling")
	}
}

// -----------------------------------------------------------------------
// Thread safety tests
// -----------------------------------------------------------------------

func TestTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewTracker()
	const goroutines = 50
	const iterations = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			clientID := "client_concurrent_" + strings.Repeat("x", id%5)

			for j := 0; j < iterations; j++ {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
				tracker.SetTraps(w, r, clientID)

				r2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
				tracker.Analyze(r2, clientID)

				_ = tracker.GenerateJSStorage(clientID)
			}
		}(i)
	}

	wg.Wait()
}

// -----------------------------------------------------------------------
// Edge case tests
// -----------------------------------------------------------------------

func TestAnalyze_UnknownClient(t *testing.T) {
	tracker := NewTracker()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	// Analyze a client we have never seen
	analysis := tracker.Analyze(r, "client_never_seen")

	if analysis.BotScore != 0.0 {
		t.Errorf("BotScore for unknown client should be 0.0, got %f", analysis.BotScore)
	}
	if analysis.CookieConsistency != 1.0 {
		t.Errorf("CookieConsistency for unknown client should be 1.0, got %f", analysis.CookieConsistency)
	}
}

func TestNewTracker_NotNil(t *testing.T) {
	tracker := NewTracker()
	if tracker == nil {
		t.Fatal("NewTracker() returned nil")
	}
	if tracker.clients == nil {
		t.Fatal("NewTracker() clients map is nil")
	}
}

func TestDeterministicValue_Consistency(t *testing.T) {
	v1 := deterministicValue("abc", "purpose")
	v2 := deterministicValue("abc", "purpose")
	if v1 != v2 {
		t.Error("deterministicValue should return the same value for the same inputs")
	}
}

func TestDeterministicValue_DifferentPurposes(t *testing.T) {
	v1 := deterministicValue("abc", "session")
	v2 := deterministicValue("abc", "fingerprint")
	if v1 == v2 {
		t.Error("deterministicValue should differ for different purposes")
	}
}

func TestAnalyze_WrongCookieValue(t *testing.T) {
	tracker := NewTracker()
	clientID := "client_wrong_val"

	w := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	tracker.SetTraps(w, req1, clientID)

	// Send back session cookie with wrong value
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req2.AddCookie(&http.Cookie{Name: cookieSession, Value: "wrong_value"})

	analysis := tracker.Analyze(req2, clientID)

	if analysis.HasSessionCookie {
		t.Error("expected HasSessionCookie = false when value doesn't match")
	}
}
