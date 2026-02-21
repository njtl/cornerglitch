package framework

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. NewEmulator
// ---------------------------------------------------------------------------

func TestNewEmulator_NotNil(t *testing.T) {
	e := NewEmulator()
	if e == nil {
		t.Fatal("NewEmulator returned nil")
	}
}

func TestNewEmulator_Has12Frameworks(t *testing.T) {
	e := NewEmulator()
	if got := len(e.frameworks); got != 12 {
		t.Fatalf("expected 12 frameworks, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// 2. ForClient determinism
// ---------------------------------------------------------------------------

func TestForClient_Deterministic(t *testing.T) {
	e := NewEmulator()
	clientID := "determinism-test-client"
	fw1 := e.ForClient(clientID)
	fw2 := e.ForClient(clientID)
	if fw1.Name != fw2.Name {
		t.Fatalf("ForClient not deterministic: got %q then %q for same clientID", fw1.Name, fw2.Name)
	}
}

func TestForClient_DeterministicAcrossInstances(t *testing.T) {
	e1 := NewEmulator()
	e2 := NewEmulator()
	clientID := "cross-instance-test"
	fw1 := e1.ForClient(clientID)
	fw2 := e2.ForClient(clientID)
	if fw1.Name != fw2.Name {
		t.Fatalf("ForClient not deterministic across instances: got %q and %q", fw1.Name, fw2.Name)
	}
}

// ---------------------------------------------------------------------------
// 3. ForClient variety
// ---------------------------------------------------------------------------

func TestForClient_Variety(t *testing.T) {
	e := NewEmulator()
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		fw := e.ForClient(fmt.Sprintf("variety-client-%d", i))
		seen[fw.Name] = true
	}
	if len(seen) < 3 {
		t.Fatalf("expected at least 3 different frameworks from 100 clients, got %d: %v", len(seen), seen)
	}
}

// ---------------------------------------------------------------------------
// 4. Apply sets Server header
// ---------------------------------------------------------------------------

func TestApply_SetsServerHeader(t *testing.T) {
	e := NewEmulator()
	// Django has ServerHeader = "WSGIServer/0.2 CPython/3.11.5"
	fw := djangoFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "server-header-test")
	got := w.Header().Get("Server")
	if got != fw.ServerHeader {
		t.Fatalf("expected Server header %q, got %q", fw.ServerHeader, got)
	}
}

func TestApply_NoServerHeaderWhenEmpty(t *testing.T) {
	e := NewEmulator()
	// Express has an empty ServerHeader
	fw := expressFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "no-server-header-test")
	got := w.Header().Get("Server")
	if got != "" {
		t.Fatalf("expected empty Server header for Express, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// 5. Apply sets X-Powered-By
// ---------------------------------------------------------------------------

func TestApply_SetsPoweredBy_Express(t *testing.T) {
	e := NewEmulator()
	fw := expressFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "powered-by-test")
	got := w.Header().Get("X-Powered-By")
	if got != "Express" {
		t.Fatalf("expected X-Powered-By %q, got %q", "Express", got)
	}
}

func TestApply_SetsPoweredBy_ASPNET(t *testing.T) {
	e := NewEmulator()
	fw := aspnetFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "aspnet-powered-by-test")
	got := w.Header().Get("X-Powered-By")
	if got != "ASP.NET" {
		t.Fatalf("expected X-Powered-By %q, got %q", "ASP.NET", got)
	}
}

func TestApply_SetsPoweredBy_Laravel(t *testing.T) {
	e := NewEmulator()
	fw := laravelFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "laravel-powered-by-test")
	got := w.Header().Get("X-Powered-By")
	if got != "PHP/8.2.0" {
		t.Fatalf("expected X-Powered-By %q, got %q", "PHP/8.2.0", got)
	}
}

func TestApply_NoPoweredByWhenEmpty(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "no-powered-by-test")
	got := w.Header().Get("X-Powered-By")
	if got != "" {
		t.Fatalf("expected empty X-Powered-By for Django, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// 6. Apply sets cookies
// ---------------------------------------------------------------------------

func TestApply_SetsCookies_Django(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "cookie-test-django")
	cookies := w.Result().Cookies()
	names := cookieNames(cookies)
	for _, expected := range []string{"csrftoken", "sessionid"} {
		if !containsStr(names, expected) {
			t.Fatalf("missing expected cookie %q in %v", expected, names)
		}
	}
}

func TestApply_SetsCookies_Express(t *testing.T) {
	e := NewEmulator()
	fw := expressFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "cookie-test-express")
	cookies := w.Result().Cookies()
	names := cookieNames(cookies)
	if !containsStr(names, "connect.sid") {
		t.Fatalf("missing expected cookie 'connect.sid' in %v", names)
	}
}

func TestApply_SetsCookies_Laravel(t *testing.T) {
	e := NewEmulator()
	fw := laravelFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "cookie-test-laravel")
	cookies := w.Result().Cookies()
	names := cookieNames(cookies)
	for _, expected := range []string{"laravel_session", "XSRF-TOKEN"} {
		if !containsStr(names, expected) {
			t.Fatalf("missing expected cookie %q in %v", expected, names)
		}
	}
}

func TestApply_NoCookies_FastAPI(t *testing.T) {
	e := NewEmulator()
	fw := fastapiFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "cookie-test-fastapi")
	cookies := w.Result().Cookies()
	if len(cookies) != 0 {
		t.Fatalf("expected no cookies for FastAPI, got %d", len(cookies))
	}
}

// ---------------------------------------------------------------------------
// 7. Apply sets framework-specific headers
// ---------------------------------------------------------------------------

func TestApply_DjangoXFrameOptions(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "header-test-django")
	got := w.Header().Get("X-Frame-Options")
	if got != "DENY" {
		t.Fatalf("expected X-Frame-Options %q for Django, got %q", "DENY", got)
	}
}

func TestApply_RailsXRuntime(t *testing.T) {
	e := NewEmulator()
	fw := railsFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "header-test-rails")
	got := w.Header().Get("X-Runtime")
	if got != "0.042369" {
		t.Fatalf("expected X-Runtime %q for Rails, got %q", "0.042369", got)
	}
}

func TestApply_SpringBootXApplicationContext(t *testing.T) {
	e := NewEmulator()
	fw := springBootFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "header-test-spring")
	got := w.Header().Get("X-Application-Context")
	if got != "application" {
		t.Fatalf("expected X-Application-Context %q for Spring Boot, got %q", "application", got)
	}
}

func TestApply_ASPNETXAspNetVersion(t *testing.T) {
	e := NewEmulator()
	fw := aspnetFrameworkPtr()
	w := httptest.NewRecorder()
	e.Apply(w, fw, "header-test-aspnet")
	got := w.Header().Get("X-AspNet-Version")
	if got != "4.0.30319" {
		t.Fatalf("expected X-AspNet-Version %q for ASP.NET, got %q", "4.0.30319", got)
	}
}

// ---------------------------------------------------------------------------
// 8. ErrorPage returns non-empty for each framework
// ---------------------------------------------------------------------------

func TestErrorPage_NonEmpty_AllFrameworks(t *testing.T) {
	e := NewEmulator()
	for _, fw := range e.frameworks {
		fw := fw
		t.Run(fw.Name, func(t *testing.T) {
			page := e.ErrorPage(&fw, 500)
			if page == "" {
				t.Fatalf("ErrorPage returned empty string for framework %q", fw.Name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. ErrorPage contains status code
// ---------------------------------------------------------------------------

func TestErrorPage_ContainsStatusCode(t *testing.T) {
	e := NewEmulator()
	for _, fw := range e.frameworks {
		fw := fw
		t.Run(fw.Name, func(t *testing.T) {
			page := e.ErrorPage(&fw, 500)
			// Some frameworks (e.g. FastAPI) emit only the status text, not the
			// numeric code. Accept either the number or the standard text.
			if !strings.Contains(page, "500") && !strings.Contains(page, "Internal Server Error") {
				t.Fatalf("ErrorPage for %q does not contain '500' or status text: %s", fw.Name, page)
			}
		})
	}
}

func TestErrorPage_ContainsStatusCode_404(t *testing.T) {
	e := NewEmulator()
	for _, fw := range e.frameworks {
		fw := fw
		t.Run(fw.Name, func(t *testing.T) {
			page := e.ErrorPage(&fw, 404)
			if !strings.Contains(page, "404") && !strings.Contains(page, "Not Found") {
				t.Fatalf("ErrorPage for %q does not contain '404' or status text: %s", fw.Name, page)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. ErrorPage is framework-specific
// ---------------------------------------------------------------------------

func TestErrorPage_ExpressContainsJSON(t *testing.T) {
	e := NewEmulator()
	fw := expressFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, `"error"`) {
		t.Fatalf("Express error page should contain JSON 'error' key, got: %s", page)
	}
}

func TestErrorPage_DjangoContainsDjango(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Django") {
		t.Fatalf("Django error page should contain 'Django', got: %s", page)
	}
}

func TestErrorPage_RailsContainsSorry(t *testing.T) {
	e := NewEmulator()
	fw := railsFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "sorry") {
		t.Fatalf("Rails error page should contain 'sorry', got: %s", page)
	}
}

func TestErrorPage_LaravelContainsLaravel(t *testing.T) {
	e := NewEmulator()
	fw := laravelFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Laravel") {
		t.Fatalf("Laravel error page should contain 'Laravel', got: %s", page)
	}
}

func TestErrorPage_SpringBootContainsWhitelabel(t *testing.T) {
	e := NewEmulator()
	fw := springBootFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Whitelabel") {
		t.Fatalf("Spring Boot error page should contain 'Whitelabel', got: %s", page)
	}
}

func TestErrorPage_ASPNETContainsIIS(t *testing.T) {
	e := NewEmulator()
	fw := aspnetFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "IIS") {
		t.Fatalf("ASP.NET error page should contain 'IIS', got: %s", page)
	}
}

func TestErrorPage_FlaskContainsWerkzeug(t *testing.T) {
	e := NewEmulator()
	fw := flaskFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Werkzeug") {
		t.Fatalf("Flask error page should contain 'Werkzeug', got: %s", page)
	}
}

func TestErrorPage_NginxContainsNginx(t *testing.T) {
	e := NewEmulator()
	fw := nginxFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "nginx") {
		t.Fatalf("nginx error page should contain 'nginx', got: %s", page)
	}
}

func TestErrorPage_CaddyContainsCaddy(t *testing.T) {
	e := NewEmulator()
	fw := caddyFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Caddy") {
		t.Fatalf("Caddy error page should contain 'Caddy', got: %s", page)
	}
}

func TestErrorPage_NextjsContainsNextError(t *testing.T) {
	e := NewEmulator()
	fw := nextjsFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "next-error") {
		t.Fatalf("Next.js error page should contain 'next-error', got: %s", page)
	}
}

func TestErrorPage_FastAPIContainsJSON(t *testing.T) {
	e := NewEmulator()
	fw := fastapiFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, `"detail"`) {
		t.Fatalf("FastAPI error page should contain JSON 'detail' key, got: %s", page)
	}
}

func TestErrorPage_ApacheContainsApache(t *testing.T) {
	e := NewEmulator()
	fw := apacheFrameworkPtr()
	page := e.ErrorPage(fw, 500)
	if !strings.Contains(page, "Apache") {
		t.Fatalf("Apache error page should contain 'Apache', got: %s", page)
	}
}

// ---------------------------------------------------------------------------
// 11. Cookie session IDs are deterministic
// ---------------------------------------------------------------------------

func TestCookieSessionID_Deterministic(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()
	clientID := "deterministic-cookie-test"

	w1 := httptest.NewRecorder()
	e.Apply(w1, fw, clientID)
	val1 := cookieValue(w1, "sessionid")

	w2 := httptest.NewRecorder()
	e.Apply(w2, fw, clientID)
	val2 := cookieValue(w2, "sessionid")

	if val1 != val2 {
		t.Fatalf("cookie values not deterministic: %q vs %q", val1, val2)
	}
}

// ---------------------------------------------------------------------------
// 12. Cookie session IDs differ per client
// ---------------------------------------------------------------------------

func TestCookieSessionID_DiffersPerClient(t *testing.T) {
	e := NewEmulator()
	fw := djangoFrameworkPtr()

	w1 := httptest.NewRecorder()
	e.Apply(w1, fw, "client-alpha")
	val1 := cookieValue(w1, "sessionid")

	w2 := httptest.NewRecorder()
	e.Apply(w2, fw, "client-beta")
	val2 := cookieValue(w2, "sessionid")

	if val1 == val2 {
		t.Fatalf("cookie values should differ for different clients, both got %q", val1)
	}
}

// ---------------------------------------------------------------------------
// 13. All 12 frameworks accessible via ForClient
// ---------------------------------------------------------------------------

func TestAllFrameworksAccessible(t *testing.T) {
	e := NewEmulator()
	expected := map[string]bool{
		"Express.js":    false,
		"Django":        false,
		"Ruby on Rails": false,
		"Laravel":       false,
		"Spring Boot":   false,
		"ASP.NET":       false,
		"Flask":         false,
		"FastAPI":       false,
		"Next.js":       false,
		"nginx":         false,
		"Apache":        false,
		"Caddy":         false,
	}

	// Try enough clients to cover all 12 frameworks.
	for i := 0; i < 10000; i++ {
		fw := e.ForClient(fmt.Sprintf("coverage-client-%d", i))
		expected[fw.Name] = true
	}

	for name, found := range expected {
		if !found {
			t.Errorf("framework %q was never selected by ForClient", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func expressFrameworkPtr() *Framework {
	fw := expressFramework()
	return &fw
}

func djangoFrameworkPtr() *Framework {
	fw := djangoFramework()
	return &fw
}

func railsFrameworkPtr() *Framework {
	fw := railsFramework()
	return &fw
}

func laravelFrameworkPtr() *Framework {
	fw := laravelFramework()
	return &fw
}

func springBootFrameworkPtr() *Framework {
	fw := springBootFramework()
	return &fw
}

func aspnetFrameworkPtr() *Framework {
	fw := aspnetFramework()
	return &fw
}

func flaskFrameworkPtr() *Framework {
	fw := flaskFramework()
	return &fw
}

func fastapiFrameworkPtr() *Framework {
	fw := fastapiFramework()
	return &fw
}

func nextjsFrameworkPtr() *Framework {
	fw := nextjsFramework()
	return &fw
}

func nginxFrameworkPtr() *Framework {
	fw := nginxFramework()
	return &fw
}

func apacheFrameworkPtr() *Framework {
	fw := apacheFramework()
	return &fw
}

func caddyFrameworkPtr() *Framework {
	fw := caddyFramework()
	return &fw
}

func cookieNames(cookies []*http.Cookie) []string {
	var names []string
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return names
}

func cookieValue(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
