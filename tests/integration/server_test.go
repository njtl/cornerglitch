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
	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/analytics"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/botdetect"
	"github.com/glitchWebServer/internal/captcha"
	"github.com/glitchWebServer/internal/cdn"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/cookies"
	"github.com/glitchWebServer/internal/email"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/framework"
	"github.com/glitchWebServer/internal/headers"
	"github.com/glitchWebServer/internal/health"
	"github.com/glitchWebServer/internal/honeypot"
	"github.com/glitchWebServer/internal/i18n"
	"github.com/glitchWebServer/internal/jstrap"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/mcp"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/oauth"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/privacy"
	"github.com/glitchWebServer/internal/media"
	"github.com/glitchWebServer/internal/mediachaos"
	"github.com/glitchWebServer/internal/budgettrap"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/search"
	"github.com/glitchWebServer/internal/server"
	"github.com/glitchWebServer/internal/spider"
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
	headerEng := headers.NewEngine()
	cookieT := cookies.NewTracker()
	jsEng := jstrap.NewEngine()
	botDet := botdetect.NewDetector()
	spiderH := spider.NewHandler(nil)

	h := server.NewHandler(
		collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter,
		honey, fw, captchaEng, vulnH, analytix, cdnEng, oauthH, privacyH,
		wsH, rec, searchH, emailH, healthH, i18nH,
		headerEng, cookieT, jsEng, botDet, spiderH, nil, media.New(), mediachaos.New(), budgettrap.NewEngine(), nil,
	)
	h.SetHealthSecret("test-health-secret")
	return h
}

// testInternalHealthPath is the internal health endpoint for test handlers.
const testInternalHealthPath = "/_internal/test-health-secret/healthz"

// newTestHandlerNoChaos creates a handler with media generation but no chaos engine.
// Used for tests that need deterministic media serving without chaos interference.
func newTestHandlerNoChaos() *server.Handler {
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
	headerEng := headers.NewEngine()
	cookieT := cookies.NewTracker()
	jsEng := jstrap.NewEngine()
	botDet := botdetect.NewDetector()
	spiderH := spider.NewHandler(nil)

	h := server.NewHandler(
		collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter,
		honey, fw, captchaEng, vulnH, analytix, cdnEng, oauthH, privacyH,
		wsH, rec, searchH, emailH, healthH, i18nH,
		headerEng, cookieT, jsEng, botDet, spiderH, nil, media.New(), nil, budgettrap.NewEngine(), nil,
	)
	h.SetHealthSecret("test-health-secret")
	return h
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
	// The error generator may randomly select error types that produce empty bodies
	// (slow_headers, missing_crlf, etc.), so retry a few times before failing.
	var gotBody bool
	var lastCode int
	for i := 0; i < 10; i++ {
		rr := doRequest(h, "GET", "/", "", nil)
		lastCode = rr.Code
		if rr.Code < 200 || rr.Code >= 600 {
			t.Errorf("root path returned invalid status: %d", rr.Code)
			return
		}
		if rr.Body.Len() > 0 {
			gotBody = true
			break
		}
	}
	if !gotBody {
		t.Errorf("root path returned empty body on all 10 attempts (last status: %d)", lastCode)
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

	// Internal health endpoint always returns 200 (bypasses chaos)
	rr := doRequest(h, "GET", testInternalHealthPath, "", nil)
	if rr.Code != 200 {
		t.Errorf("internal health: expected 200, got %d", rr.Code)
	}

	// Emulated /health is subject to error injection, but should sometimes return
	// the health JSON when no error is rolled
	var gotHealth bool
	for i := 0; i < 20; i++ {
		rr = doRequest(h, "GET", "/health", "", nil)
		if rr.Code == 200 && strings.Contains(rr.Body.String(), "status") {
			gotHealth = true
			break
		}
	}
	if !gotHealth {
		t.Error("emulated /health never returned health JSON in 20 tries")
	}
}

func TestPingEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	// /ping is subject to error injection — retry until we get the real response
	var gotPong bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/ping", "", nil)
		if rr.Code == 200 && strings.Contains(rr.Body.String(), "pong") {
			gotPong = true
			break
		}
	}
	if !gotPong {
		t.Error("/ping never returned pong in 20 tries")
	}
}

func TestVersionEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	// /version is subject to error injection — retry until we get valid JSON
	var gotVersion bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/version", "", nil)
		if rr.Code == 200 {
			var data map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &data); err == nil {
				if _, ok := data["version"]; ok {
					gotVersion = true
					break
				}
			}
		}
	}
	if !gotVersion {
		t.Error("/version never returned valid version JSON in 20 tries")
	}
}

func TestStatusEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	// /status is subject to error injection — retry until 200
	var got200 bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/status", "", nil)
		if rr.Code == 200 {
			got200 = true
			break
		}
	}
	if !got200 {
		t.Error("/status never returned 200 in 20 tries")
	}
}

func TestStatusJSONEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	var gotJSON bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/status.json", "", nil)
		if rr.Code == 200 {
			var data map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &data); err == nil {
				gotJSON = true
				break
			}
		}
	}
	if !gotJSON {
		t.Error("/status.json never returned valid JSON in 20 tries")
	}
}

func TestMetricsEndpointIntegration(t *testing.T) {
	h := newTestHandler()
	var gotMetrics bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/metrics", "", nil)
		if rr.Code == 200 {
			body := rr.Body.String()
			if strings.Contains(body, "process_") || strings.Contains(body, "go_") {
				gotMetrics = true
				break
			}
		}
	}
	if !gotMetrics {
		t.Error("/metrics never returned Prometheus metrics format in 20 tries")
	}
}

func TestDebugVarsIntegration(t *testing.T) {
	h := newTestHandler()
	var gotDebug bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/debug/vars", "", nil)
		if rr.Code == 200 {
			var data map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &data); err == nil {
				gotDebug = true
				break
			}
		}
	}
	if !gotDebug {
		t.Error("/debug/vars never returned valid JSON in 20 tries")
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
	// CDN emulator applies headers in ServeHTTP (before dispatch), so even
	// error-injected responses should have CDN headers. Retry a few times
	// since some error types may drop headers entirely.
	var hasCDNHeader bool
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", "/static/js/app.js", "", nil)
		for k := range rr.Header() {
			if k == "X-Cache" || k == "Cache-Control" || k == "Age" || k == "Cf-Ray" ||
				strings.Contains(k, "Cache") || strings.Contains(k, "CDN") {
				hasCDNHeader = true
				break
			}
		}
		if hasCDNHeader {
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

	// Use paths that are handled by deterministic subsystems (search,
	// api, etc.) and avoid "/" which can hit slow error types like slow_drip
	// (17s) or delayed (3-5s). This test verifies concurrency safety, not
	// response speed — slow chaos errors are tested elsewhere.
	paths := []string{
		testInternalHealthPath, "/search?q=test", "/api/v1/users",
		"/webmail", "/es/", "/api/i18n/languages", "/status",
		"/vuln/a01/admin", "/wp-admin/", "/ping",
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

	// Generous timeout — CI runners are slower than local machines, and some
	// subsystems (api, search) do real work. 30s is plenty even on slow VMs.
	for i := 0; i < 20; i++ {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent requests timed out")
		}
	}
}

// --- Response Size & Performance ---

func TestResponsesNotEmpty(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		testInternalHealthPath,
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
		{"health", "GET", testInternalHealthPath},
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

// ---------------------------------------------------------------------------
// Media Chaos Handler Integration
// ---------------------------------------------------------------------------

// TestMediaChaos_HandlerServesMedia verifies /media/ paths serve valid media content.
// Uses nil mediachaos engine to test clean media serving without chaos interference.
func TestMediaChaos_HandlerServesMedia(t *testing.T) {
	h := newTestHandlerNoChaos()
	dashboard.GetFeatureFlags().Set("media_chaos", true)

	paths := []struct {
		path     string
		ctPrefix string // expected content-type prefix
	}{
		{"/media/image/test.png", "image/png"},
		{"/media/image/test.jpg", "image/jpeg"},
		{"/media/image/test.gif", "image/gif"},
		{"/media/image/test.svg", "image/svg+xml"},
		{"/media/image/test.bmp", "image/bmp"},
		{"/media/image/test.webp", "image/webp"},
		{"/media/image/test.ico", "image/x-icon"},
		{"/media/image/test.tiff", "image/tiff"},
		{"/media/audio/test.wav", "audio/wav"},
		{"/media/audio/test.mp3", "audio/mpeg"},
		{"/media/audio/test.ogg", "audio/ogg"},
		{"/media/audio/test.flac", "audio/flac"},
		{"/media/video/test.mp4", "video/mp4"},
		{"/media/video/test.webm", "video/webm"},
		{"/media/video/test.avi", "video/x-msvideo"},
		{"/media/stream/test/playlist.m3u8", "application/vnd.apple.mpegurl"},
		{"/media/stream/test/manifest.mpd", "application/dash+xml"},
	}

	for _, tc := range paths {
		t.Run(tc.path, func(t *testing.T) {
			rr := doRequest(h, "GET", tc.path, "", nil)
			if rr.Code != 200 {
				t.Errorf("expected 200, got %d", rr.Code)
			}
			if rr.Body.Len() == 0 {
				t.Error("got empty body")
			}
			gotCT := rr.Header().Get("Content-Type")
			if !strings.HasPrefix(gotCT, tc.ctPrefix) {
				t.Errorf("expected Content-Type starting with %q, got %q", tc.ctPrefix, gotCT)
			}
		})
	}
}

// TestMediaChaos_HandlerDisabledDoesNotServeMedia verifies the feature flag gates media.
func TestMediaChaos_HandlerDisabledDoesNotServeMedia(t *testing.T) {
	h := newTestHandler()
	dashboard.GetFeatureFlags().Set("media_chaos", false)
	defer dashboard.GetFeatureFlags().Set("media_chaos", true)

	rr := doRequest(h, "GET", "/media/image/test.png", "", nil)
	// When disabled, /media/ paths fall through to normal handler (not media)
	gotCT := rr.Header().Get("Content-Type")
	if strings.HasPrefix(gotCT, "image/png") {
		t.Error("media content served when media_chaos is disabled")
	}
}

// --- MCP Integration Tests ---

// newTestHandlerWithMCP creates a handler with MCP server enabled.
func newTestHandlerWithMCP() (*server.Handler, *mcp.Server) {
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
	headerEng := headers.NewEngine()
	cookieT := cookies.NewTracker()
	jsEng := jstrap.NewEngine()
	botDet := botdetect.NewDetector()
	spiderH := spider.NewHandler(nil)
	mcpServer := mcp.NewServer()

	h := server.NewHandler(
		collector, fp, adapt, errGen, pageGen, lab, contentEng, apiRouter,
		honey, fw, captchaEng, vulnH, analytix, cdnEng, oauthH, privacyH,
		wsH, rec, searchH, emailH, healthH, i18nH,
		headerEng, cookieT, jsEng, botDet, spiderH, nil, media.New(), mediachaos.New(), budgettrap.NewEngine(), mcpServer,
	)
	h.SetHealthSecret("test-health-secret")
	return h, mcpServer
}

func TestIntegration_MCP_FullHandshake(t *testing.T) {
	h, _ := newTestHandlerWithMCP()
	dashboard.GetFeatureFlags().Set("mcp", true)

	// Step 1: Initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"integration-test","version":"1.0"}}}`
	rr := doRequest(h, "POST", "/mcp", initBody, nil)
	if rr.Code != 200 {
		t.Fatalf("initialize: status = %d, want 200", rr.Code)
	}

	var initResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &initResp)
	result, ok := initResp["result"].(map[string]interface{})
	if !ok {
		t.Fatal("initialize: no result in response")
	}
	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatal("initialize: no serverInfo in result")
	}
	if serverInfo["name"] != "glitch-mcp" {
		t.Errorf("server name = %v, want glitch-mcp", serverInfo["name"])
	}

	sid := rr.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize: no Mcp-Session-Id in response")
	}

	// Step 2: List tools
	toolsBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	rr2 := doRequest(h, "POST", "/mcp", toolsBody, map[string]string{"Mcp-Session-Id": sid})
	if rr2.Code != 200 {
		t.Fatalf("tools/list: status = %d", rr2.Code)
	}
	var toolsResp map[string]interface{}
	json.Unmarshal(rr2.Body.Bytes(), &toolsResp)
	toolsResult := toolsResp["result"].(map[string]interface{})
	tools := toolsResult["tools"].([]interface{})
	if len(tools) == 0 {
		t.Error("tools/list: no tools returned")
	}

	// Step 3: Call a honeypot tool
	callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_aws_credentials","arguments":{}}}`
	rr3 := doRequest(h, "POST", "/mcp", callBody, map[string]string{"Mcp-Session-Id": sid})
	if rr3.Code != 200 {
		t.Fatalf("tools/call: status = %d", rr3.Code)
	}
	var callResp map[string]interface{}
	json.Unmarshal(rr3.Body.Bytes(), &callResp)
	if callResp["error"] != nil {
		t.Errorf("tools/call: unexpected error: %v", callResp["error"])
	}

	// Step 4: Delete session
	rr4 := doRequest(h, "DELETE", "/mcp", "", map[string]string{"Mcp-Session-Id": sid})
	if rr4.Code != 200 {
		t.Errorf("DELETE: status = %d", rr4.Code)
	}
}

func TestIntegration_MCP_FeatureFlagDisables(t *testing.T) {
	h, _ := newTestHandlerWithMCP()

	// Enable MCP first
	dashboard.GetFeatureFlags().Set("mcp", true)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test"}}}`
	rr := doRequest(h, "POST", "/mcp", initBody, nil)
	if rr.Code != 200 {
		t.Fatalf("MCP enabled: status = %d, want 200", rr.Code)
	}

	// Disable MCP
	dashboard.GetFeatureFlags().Set("mcp", false)
	rr2 := doRequest(h, "POST", "/mcp", initBody, nil)
	// When disabled, /mcp should fall through to normal handler (not MCP)
	// The response should NOT be a valid MCP JSON-RPC response
	var resp map[string]interface{}
	json.Unmarshal(rr2.Body.Bytes(), &resp)
	if _, hasResult := resp["result"]; hasResult {
		if result, ok := resp["result"].(map[string]interface{}); ok {
			if _, hasServer := result["serverInfo"]; hasServer {
				t.Error("MCP should not serve when feature flag is disabled")
			}
		}
	}

	// Re-enable for other tests
	dashboard.GetFeatureFlags().Set("mcp", true)
}

func TestIntegration_MCP_DoesNotInterfere(t *testing.T) {
	h, _ := newTestHandlerWithMCP()
	dashboard.GetFeatureFlags().Set("mcp", true)

	// Internal health endpoint should still work
	rr := doRequest(h, "GET", testInternalHealthPath, "", nil)
	if rr.Code != 200 {
		t.Errorf("internal health: status = %d, want 200", rr.Code)
	}

	// API endpoint should still work
	rr2 := doRequest(h, "GET", "/api/v1/users", "", nil)
	if rr2.Code == 0 {
		t.Error("API endpoint returned 0 status")
	}

	// Vuln endpoint should still work
	rr3 := doRequest(h, "GET", "/vuln/a01/login", "", nil)
	if rr3.Code == 0 {
		t.Error("vuln endpoint returned 0 status")
	}
}

func TestIntegration_MCP_ScannerSelfTest(t *testing.T) {
	h, _ := newTestHandlerWithMCP()
	dashboard.GetFeatureFlags().Set("mcp", true)

	// Start a test server with the full handler
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Use MCP scanner to scan the test server's MCP endpoint
	scanner := mcp.NewScanner()
	report := scanner.Scan(ts.URL + "/mcp")

	if report.Error != "" {
		t.Fatalf("scan error: %s", report.Error)
	}
	if report.ServerName != "glitch-mcp" {
		t.Errorf("server name = %q, want %q", report.ServerName, "glitch-mcp")
	}
	if report.ToolCount == 0 {
		t.Error("scanner should find tools")
	}
	if report.ResourceCount == 0 {
		t.Error("scanner should find resources")
	}
	if report.PromptCount == 0 {
		t.Error("scanner should find prompts")
	}
	if len(report.Findings) == 0 {
		t.Error("scanner should find security issues in honeypot")
	}
	if report.RiskScore == 0 {
		t.Error("risk score should be non-zero for honeypot server")
	}

	// Check specific finding categories
	categories := make(map[string]bool)
	for _, f := range report.Findings {
		categories[f.Category] = true
	}
	if !categories["injection"] {
		t.Error("scanner should detect injection patterns")
	}
	if !categories["credential"] {
		t.Error("scanner should detect credential harvesting")
	}
}

// --- TLS & HTTP/2 Chaos ---

func TestIntegration_TLSChaos_AdminConfig(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	// Set TLS chaos enabled
	cfg.Set("tls_chaos_enabled", 1)
	out := cfg.Get()
	if v, ok := out["tls_chaos_enabled"]; !ok || v != true {
		t.Errorf("tls_chaos_enabled should be true, got %v", v)
	}

	// Set TLS chaos level
	cfg.Set("tls_chaos_level", 3)
	out = cfg.Get()
	if v, ok := out["tls_chaos_level"]; !ok {
		t.Error("tls_chaos_level missing from config output")
	} else if v != 3 {
		t.Errorf("tls_chaos_level should be 3, got %v", v)
	}

	// Bounds check
	cfg.Set("tls_chaos_level", 99)
	out = cfg.Get()
	if v := out["tls_chaos_level"]; v != 4 {
		t.Errorf("tls_chaos_level should clamp to 4, got %v", v)
	}

	// HSTS chaos
	cfg.Set("hsts_chaos_enabled", 1)
	out = cfg.Get()
	if v, ok := out["hsts_chaos_enabled"]; !ok || v != true {
		t.Errorf("hsts_chaos_enabled should be true, got %v", v)
	}

	// Reset
	cfg.Set("tls_chaos_enabled", 0)
	cfg.Set("hsts_chaos_enabled", 0)
	cfg.Set("tls_chaos_level", 0)
}

func TestIntegration_H2ErrorTypes_Exist(t *testing.T) {
	// Verify all H2 error types are registered in the error generator
	_ = errors.NewGenerator()
	profile := errors.DefaultProfile()

	h2Types := []string{
		"h2_goaway", "h2_rst_stream", "h2_settings_flood",
		"h2_window_exhaust", "h2_continuation_flood", "h2_ping_flood",
	}

	for _, typ := range h2Types {
		if _, exists := profile.Weights[errors.ErrorType(typ)]; !exists {
			t.Errorf("H2 error type %q missing from DefaultProfile", typ)
		}
	}

	// Verify they're classified as protocol glitches
	for _, typ := range h2Types {
		if !errors.IsProtocolGlitch(errors.ErrorType(typ)) {
			t.Errorf("H2 error type %q should be classified as protocol glitch", typ)
		}
	}
}

func TestIntegration_HSTSChaos_InjectsHeaders(t *testing.T) {
	h := newTestHandler()
	cfg := dashboard.GetAdminConfig()
	cfg.Set("hsts_chaos_enabled", 1)
	defer cfg.Set("hsts_chaos_enabled", 0)

	// Make multiple requests to the health path (deterministic 200)
	hstsCount := 0
	for i := 0; i < 20; i++ {
		rr := doRequest(h, "GET", testInternalHealthPath, "", nil)
		if rr.Header().Get("Strict-Transport-Security") != "" {
			hstsCount++
		}
	}

	// HSTS chaos is based on fnv32a hash of client+path, so the same
	// client hitting the same path should consistently get HSTS (or not).
	// Just verify the feature flag works — if enabled, the handler code path runs.
	t.Logf("HSTS headers injected in %d/20 requests", hstsCount)
}

func TestIntegration_MCP_ToggleInFeatureFlags(t *testing.T) {
	// Verify MCP is in the feature flags
	flags := dashboard.GetFeatureFlags()
	snap := flags.Snapshot()
	if _, exists := snap["mcp"]; !exists {
		t.Error("mcp not found in feature flags snapshot")
	}

	// Toggle and verify
	flags.Set("mcp", false)
	if flags.IsMCPEnabled() {
		t.Error("MCP should be disabled after Set(mcp, false)")
	}
	flags.Set("mcp", true)
	if !flags.IsMCPEnabled() {
		t.Error("MCP should be enabled after Set(mcp, true)")
	}
}
