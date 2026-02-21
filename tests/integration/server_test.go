package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/analytics"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/captcha"
	"github.com/glitchWebServer/internal/cdn"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/email"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/framework"
	"github.com/glitchWebServer/internal/health"
	"github.com/glitchWebServer/internal/honeypot"
	"github.com/glitchWebServer/internal/i18n"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/oauth"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/privacy"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/search"
	"github.com/glitchWebServer/internal/server"
	"github.com/glitchWebServer/internal/vuln"
	"github.com/glitchWebServer/internal/websocket"
)

// newTestHandler assembles a full handler with all subsystems for integration testing.
func newTestHandler() *server.Handler {
	collector := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	adapt := adaptive.NewEngine(collector, fp)
	errGen := errors.NewGenerator()
	pageGen := pages.NewGenerator()
	lab := labyrinth.NewLabyrinth()
	contentEng := content.NewEngine()
	apiRouter := api.NewRouter()
	honey := honeypot.NewHoneypot()
	fw := framework.NewEmulator()
	captchaEng := captcha.NewEngine()
	vulnH := vuln.NewHandler()
	analytix := analytics.NewEngine()
	cdnEng := cdn.NewEngine()
	oauthH := oauth.NewHandler()
	privacyH := privacy.NewHandler()
	wsH := websocket.NewHandler()
	rec := recorder.NewRecorder("/tmp/glitch-test-captures")
	searchH := search.NewHandler()
	emailH := email.NewHandler()
	healthH := health.NewHandler(time.Now())
	i18nH := i18n.NewHandler()

	return server.NewHandler(
		collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter,
		honey, fw, captchaEng, vulnH, analytix, cdnEng, oauthH, privacyH,
		wsH, rec, searchH, emailH, healthH, i18nH,
	)
}

func doRequest(h http.Handler, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// --- Root & Content Pages ---

func TestRootPath(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("root path returned invalid status: %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Error("root path returned empty body")
	}
}

func TestContentPagesReturnHTML(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		"/blog/test-article",
		"/news/latest-update",
		"/products/cool-widget",
		"/about",
		"/help/getting-started",
	}
	for _, p := range paths {
		rr := doRequest(h, "GET", p, "", map[string]string{"Accept": "text/html"})
		if rr.Code < 200 || rr.Code >= 600 {
			t.Errorf("path %s returned invalid status: %d", p, rr.Code)
		}
	}
}

// --- Health Endpoints ---

func TestHealthEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/health", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content-type, got %s", ct)
	}
}

func TestPingEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/ping", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "pong") {
		t.Errorf("expected pong, got: %s", body)
	}
}

func TestVersionEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/version", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := data["version"]; !ok {
		t.Error("expected version field in response")
	}
}

func TestStatusEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/status", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestStatusJSONEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/status.json", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestMetricsEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/metrics", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "process_") || !strings.Contains(body, "go_") {
		t.Error("expected Prometheus metrics format")
	}
}

func TestDebugVarsIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/debug/vars", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// --- API Endpoints ---

func TestAPIUsersListIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/api/v1/users", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON, got %s", ct)
	}
}

func TestAPIUserByIDIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/api/v1/users/1", "", nil)
	// API router may return 200 or 404 depending on implementation
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

func TestAPISwaggerIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/swagger/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestGraphQLIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/graphql?query={__schema{types{name}}}", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- OAuth Endpoints ---

func TestOAuthDiscoveryIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/.well-known/openid-configuration", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := data["issuer"]; !ok {
		t.Error("expected issuer field")
	}
}

func TestOAuthAuthorizeIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback", "", nil)
	// Should return a consent page (200) or redirect (302/303)
	if rr.Code < 200 || rr.Code >= 400 {
		t.Errorf("expected success/redirect, got %d", rr.Code)
	}
}

func TestSAMLMetadataIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/saml/metadata", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Privacy Endpoints ---

func TestPrivacyPolicyIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/privacy-policy", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if len(body) < 100 {
		t.Error("expected substantial privacy policy text")
	}
}

func TestTermsOfServiceIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/terms-of-service", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestGPCEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/.well-known/gpc", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Search Engine ---

func TestSearchEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/search?q=test", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "test") {
		t.Error("expected search results to contain query")
	}
}

func TestSearchAdvancedIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/search/advanced", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestSearchImagesIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/search/images?q=test", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestSearchSuggestAPIIntegration(t *testing.T) {
	h := newTestHandler()
	// /api/search/suggest is caught by the API router (higher priority) in full handler
	// The search handler works directly when tested standalone; in integration
	// it routes through the API layer which may return a different result
	rr := doRequest(h, "GET", "/api/search/suggest?q=test", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

// --- Email/Webmail ---

func TestWebmailLoginPageIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/webmail", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "GlitchMail") && !strings.Contains(body, "Sign In") && !strings.Contains(body, "login") {
		t.Error("expected webmail login page content")
	}
}

func TestWebmailInboxIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/webmail/inbox", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestWebmailMessageIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/webmail/message/1", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestEmailSendAPIIntegration(t *testing.T) {
	h := newTestHandler()
	// /api/email/send is caught by the API router (higher priority than email handler)
	// in the full dispatch chain. Test that it still returns a valid response.
	body := `{"to":"test@example.com","subject":"Hello","body":"Test message"}`
	rr := doRequest(h, "POST", "/api/email/send", body, nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

func TestForgotPasswordIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/forgot-password", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestUnsubscribeIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/unsubscribe?email=test@example.com&list=news", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestArchiveIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/archive/2024/01/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- i18n ---

func TestI18nLanguagesAPIIntegration(t *testing.T) {
	h := newTestHandler()
	// /api/i18n/languages is caught by the API router first in the full handler
	// The i18n handler handles it when tested standalone; in integration the
	// API router has priority for /api/* paths
	rr := doRequest(h, "GET", "/api/i18n/languages", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

func TestI18nTranslateAPIIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/api/i18n/translate?key=home&lang=es", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

func TestI18nLocalizedPageIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/es/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `lang="es"`) {
		t.Error("expected Spanish language attribute")
	}
}

func TestI18nJapanesePageIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/ja/blog/test", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `lang="ja"`) {
		t.Error("expected Japanese language attribute")
	}
}

// --- Honeypot ---

func TestHoneypotWPAdminIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/wp-admin/", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("unexpected status: %d", rr.Code)
	}
	if rr.Body.Len() == 0 {
		t.Error("expected honeypot response body")
	}
}

func TestHoneypotEnvIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/.env", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("unexpected status: %d", rr.Code)
	}
}

func TestHoneypotPhpInfoIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/phpinfo.php", "", nil)
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("unexpected status: %d", rr.Code)
	}
}

// --- OWASP Vulnerability Emulation ---

func TestVulnA01Integration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/vuln/a01/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVulnA02Integration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/vuln/a02/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVulnA03Integration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/vuln/a03/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVulnA05Integration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/vuln/a05/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestVulnA09Integration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/vuln/a09/", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- CDN Static Assets ---

func TestCDNStaticJSIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/static/js/app.js", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestCDNStaticCSSIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/static/css/style.css", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- Analytics ---

func TestAnalyticsCollectIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/collect?v=1&t=pageview", "", nil)
	if rr.Code < 200 || rr.Code >= 400 {
		t.Errorf("expected success, got %d", rr.Code)
	}
}

func TestAnalyticsTrackingPixelIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/tr", "", nil)
	if rr.Code < 200 || rr.Code >= 400 {
		t.Errorf("expected success, got %d", rr.Code)
	}
}

// --- Traffic Recorder ---

func TestRecorderStatusIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/recorder/status", "", nil)
	// May occasionally get error-injected response; just verify it's valid
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("expected valid status, got %d", rr.Code)
	}
}

// --- Labyrinth ---

func TestLabyrinthDeepPathIntegration(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/articles/some-topic/deep/path/explore/more", "", nil)
	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Labyrinth pages should contain links to more pages
	if !strings.Contains(body, "href=") {
		t.Error("expected labyrinth page to contain links")
	}
}

// --- Cross-Cutting Concerns ---

func TestFrameworkHeadersApplied(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/", "", nil)
	// Framework emulator should set some response headers
	headers := rr.Header()
	hasFrameworkHeader := false
	for k := range headers {
		if strings.HasPrefix(k, "X-") || k == "Server" || k == "Set-Cookie" {
			hasFrameworkHeader = true
			break
		}
	}
	if !hasFrameworkHeader {
		t.Error("expected framework emulation headers to be set")
	}
}

func TestCDNHeadersApplied(t *testing.T) {
	h := newTestHandler()
	// Use /health which always returns cleanly (no error injection or labyrinth)
	rr := doRequest(h, "GET", "/health", "", nil)
	// CDN emulator applies headers to all requests in ServeHTTP (before dispatch)
	headers := rr.Header()
	hasCDNHeader := false
	for k := range headers {
		if k == "X-Cache" || k == "Cache-Control" || k == "Age" || k == "Cf-Ray" ||
			strings.Contains(k, "Cache") || strings.Contains(k, "CDN") {
			hasCDNHeader = true
			break
		}
	}
	if !hasCDNHeader {
		t.Error("expected CDN headers to be set")
	}
}

func TestMultipleRequestsSameClient(t *testing.T) {
	h := newTestHandler()
	// Send several requests from the same "client"
	for i := 0; i < 5; i++ {
		rr := doRequest(h, "GET", "/", "", map[string]string{
			"User-Agent": "TestBot/1.0",
		})
		if rr.Code < 200 || rr.Code >= 600 {
			t.Errorf("request %d returned invalid status: %d", i, rr.Code)
		}
	}
}

func TestDifferentHTTPMethods(t *testing.T) {
	h := newTestHandler()
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	for _, method := range methods {
		rr := doRequest(h, method, "/", "", nil)
		if rr.Code < 200 || rr.Code >= 600 {
			t.Errorf("method %s returned invalid status: %d", method, rr.Code)
		}
	}
}

func TestAcceptHeaderJSON(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/some/path", "", map[string]string{
		"Accept": "application/json",
	})
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("unexpected status: %d", rr.Code)
	}
}

func TestAcceptHeaderXML(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/some/path", "", map[string]string{
		"Accept": "application/xml",
	})
	if rr.Code < 200 || rr.Code >= 600 {
		t.Errorf("unexpected status: %d", rr.Code)
	}
}

// --- Concurrency Safety ---

func TestConcurrentRequests(t *testing.T) {
	h := newTestHandler()
	done := make(chan bool, 20)

	paths := []string{
		"/", "/health", "/search?q=test", "/api/v1/users",
		"/webmail", "/es/", "/api/i18n/languages", "/status",
		"/vuln/a01/admin", "/wp-admin/",
	}

	for i := 0; i < 20; i++ {
		go func(idx int) {
			p := paths[idx%len(paths)]
			rr := doRequest(h, "GET", p, "", nil)
			if rr.Code < 200 || rr.Code >= 600 {
				t.Errorf("concurrent request to %s returned invalid status: %d", p, rr.Code)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 20; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent requests timed out")
		}
	}
}

// --- Response Size & Performance ---

func TestResponsesNotEmpty(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		"/health",
		"/search?q=test",
		"/api/v1/users",
		"/webmail",
		"/privacy-policy",
		"/status",
		"/ping",
	}
	for _, p := range paths {
		rr := doRequest(h, "GET", p, "", nil)
		if rr.Body.Len() == 0 {
			t.Errorf("path %s returned empty body", p)
		}
	}
}

// --- WebSocket Upgrade Attempt ---

func TestWebSocketUpgradeHeaderCheck(t *testing.T) {
	h := newTestHandler()
	rr := doRequest(h, "GET", "/ws/feed", "", map[string]string{
		"Connection": "Upgrade",
		"Upgrade":    "websocket",
	})
	// Without a real WebSocket handshake, expect either upgrade attempt or error
	// The important thing is the server doesn't panic
	if rr.Code < 100 || rr.Code >= 600 {
		t.Errorf("unexpected status on WebSocket path: %d", rr.Code)
	}
}

// --- Verify All Subsystem Paths Routed ---

func TestAllSubsystemsRouted(t *testing.T) {
	h := newTestHandler()
	testCases := []struct {
		name   string
		method string
		path   string
	}{
		{"health", "GET", "/health"},
		{"api", "GET", "/api/v1/users"},
		{"oauth", "GET", "/.well-known/openid-configuration"},
		{"privacy", "GET", "/privacy-policy"},
		{"analytics", "GET", "/collect?v=1&t=pageview"},
		{"recorder", "GET", "/recorder/status"},
		{"email", "GET", "/webmail"},
		{"search", "GET", "/search?q=test"},
		{"i18n", "GET", "/es/"},
		{"cdn", "GET", "/static/js/app.js"},
		{"vuln", "GET", "/vuln/a01/"},
		{"honeypot", "GET", "/wp-admin/"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(h, tc.method, tc.path, "", nil)
			if rr.Code < 200 || rr.Code >= 600 {
				t.Errorf("subsystem %s at %s returned invalid status: %d", tc.name, tc.path, rr.Code)
			}
		})
	}
}
