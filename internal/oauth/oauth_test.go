package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. NewHandler creates a handler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

func TestNewHandlerType(t *testing.T) {
	h := NewHandler()
	if h.issuerBase != "" {
		t.Fatalf("expected empty issuerBase on fresh handler, got %q", h.issuerBase)
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldHandle: true for all OAuth/SAML/social/OIDC paths
// ---------------------------------------------------------------------------

func TestShouldHandleTruePaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/callback",
		"/oauth/userinfo",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/saml/metadata",
		"/saml/sso",
		"/saml/acs",
		"/auth/google",
		"/auth/github",
		"/auth/facebook",
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

func TestShouldHandleFalsePaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/",
		"/about",
		"/api/v1/users",
		"/login",
		"/auth/twitter",
		"/.well-known/other",
		"/saml",
		"/oauth",
	}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. GET /oauth/authorize returns HTML consent page with form
// ---------------------------------------------------------------------------

func TestGetAuthorizeReturnsHTMLConsent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?client_id=test-app&scope=openid+profile&state=xyz", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html content-type, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("expected HTML body to contain a <form> element")
	}
	if !strings.Contains(body, "test-app") {
		t.Error("expected HTML body to contain client_id 'test-app'")
	}
	if !strings.Contains(body, `name="action"`) {
		t.Error("expected form to contain action buttons")
	}
}

func TestGetAuthorizeDefaultsClientID(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "glitch-app-") {
		t.Error("expected default client_id with prefix 'glitch-app-'")
	}
}

func TestGetAuthorizeIncludesScopes(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?scope=openid+email+profile", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()

	for _, scope := range []string{"openid", "email", "profile"} {
		if !strings.Contains(body, scope) {
			t.Errorf("expected body to contain scope %q", scope)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. POST /oauth/authorize generates redirect with code and state
// ---------------------------------------------------------------------------

func TestPostAuthorizeAllowRedirectsWithCode(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"action":       {"allow"},
		"redirect_uri": {"http://example.com/cb"},
		"state":        {"test-state-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusFound {
		t.Fatalf("expected status 302, got %d", status)
	}

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse Location header: %v", err)
	}

	code := u.Query().Get("code")
	if code == "" {
		t.Error("expected code in redirect URL")
	}
	if !strings.HasPrefix(code, "glitch_code_") {
		t.Errorf("expected code to start with 'glitch_code_', got %q", code)
	}

	state := u.Query().Get("state")
	if state != "test-state-123" {
		t.Errorf("expected state 'test-state-123', got %q", state)
	}
}

func TestPostAuthorizeAllowDefaultRedirectURI(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"action": {"allow"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/oauth/callback") {
		t.Errorf("expected default redirect to /oauth/callback, got %q", loc)
	}
}

// ---------------------------------------------------------------------------
// 6. POST /oauth/authorize with action=deny redirects with error
// ---------------------------------------------------------------------------

func TestPostAuthorizeDenyRedirectsWithError(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"action":       {"deny"},
		"redirect_uri": {"http://example.com/cb"},
		"state":        {"deny-state"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusFound {
		t.Fatalf("expected status 302, got %d", status)
	}

	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse Location: %v", err)
	}

	errVal := u.Query().Get("error")
	if errVal != "access_denied" {
		t.Errorf("expected error=access_denied, got %q", errVal)
	}

	desc := u.Query().Get("error_description")
	if desc == "" {
		t.Error("expected error_description in deny redirect")
	}

	state := u.Query().Get("state")
	if state != "deny-state" {
		t.Errorf("expected state='deny-state', got %q", state)
	}
}

func TestPostAuthorizeDenyHasNoCode(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"action":       {"deny"},
		"redirect_uri": {"http://example.com/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	loc := w.Header().Get("Location")
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" {
		t.Error("deny response should not contain a code parameter")
	}
}

// ---------------------------------------------------------------------------
// 7. POST /oauth/token with grant_type=authorization_code returns tokens
// ---------------------------------------------------------------------------

func TestPostTokenAuthorizationCode(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"glitch_code_abc123"},
		"client_id":  {"test-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if resp["access_token"] == nil {
		t.Error("expected access_token in response")
	}
	if resp["refresh_token"] == nil {
		t.Error("expected refresh_token in response")
	}
	if resp["id_token"] == nil {
		t.Error("expected id_token in response for authorization_code grant")
	}
}

// ---------------------------------------------------------------------------
// 8. POST /oauth/token with grant_type=client_credentials returns tokens
// ---------------------------------------------------------------------------

func TestPostTokenClientCredentials(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if resp["access_token"] == nil {
		t.Error("expected access_token in response")
	}
	if resp["refresh_token"] == nil {
		t.Error("expected refresh_token in response")
	}
	// client_credentials should NOT include id_token
	if resp["id_token"] != nil {
		t.Error("client_credentials grant should not include id_token")
	}
}

// ---------------------------------------------------------------------------
// 9. Token response includes access_token, token_type, expires_in
// ---------------------------------------------------------------------------

func TestTokenResponseRequiredFields(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"glitch_code_test"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if _, ok := resp["access_token"]; !ok {
		t.Error("missing access_token field")
	}
	tokenType, ok := resp["token_type"]
	if !ok {
		t.Error("missing token_type field")
	} else if tokenType != "Bearer" {
		t.Errorf("expected token_type='Bearer', got %q", tokenType)
	}
	expiresIn, ok := resp["expires_in"]
	if !ok {
		t.Error("missing expires_in field")
	} else if expiresIn.(float64) != 3600 {
		t.Errorf("expected expires_in=3600, got %v", expiresIn)
	}
	if _, ok := resp["scope"]; !ok {
		t.Error("missing scope field")
	}
}

func TestTokenResponseCacheHeaders(t *testing.T) {
	h := NewHandler()
	form := url.Values{"grant_type": {"authorization_code"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control=no-store, got %q", cc)
	}
	if pragma := w.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("expected Pragma=no-cache, got %q", pragma)
	}
}

// ---------------------------------------------------------------------------
// 10. GET /oauth/callback returns HTML page
// ---------------------------------------------------------------------------

func TestGetCallbackReturnsHTML(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=test_code_123&state=abc", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "OAuth 2.0 Callback") {
		t.Error("expected callback page title")
	}
	if !strings.Contains(body, "test_code_123") {
		t.Error("expected code to appear in callback page")
	}
}

func TestGetCallbackWithError(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?error=access_denied&error_description=denied", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "Authorization Failed") {
		t.Error("expected error message in callback page")
	}
	if !strings.Contains(body, "access_denied") {
		t.Error("expected error type in callback page")
	}
}

func TestGetCallbackNoParams(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "No Authorization Data") {
		t.Error("expected 'No Authorization Data' message when no params present")
	}
}

// ---------------------------------------------------------------------------
// 11. GET /oauth/userinfo returns JSON user profile
// ---------------------------------------------------------------------------

func TestGetUserInfoWithBearer(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer fake-token-123")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}

	var profile map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&profile); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	requiredFields := []string{"sub", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "picture", "locale"}
	for _, f := range requiredFields {
		if _, ok := profile[f]; !ok {
			t.Errorf("missing required field %q in userinfo response", f)
		}
	}

	if profile["email"] != "user@glitch.example" {
		t.Errorf("expected email='user@glitch.example', got %q", profile["email"])
	}
}

func TestGetUserInfoWithoutBearerReturns401(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", status)
	}

	authHeader := w.Header().Get("WWW-Authenticate")
	if authHeader == "" {
		t.Error("expected WWW-Authenticate header on 401 response")
	}
}

func TestGetUserInfoWithNonBearerAuthReturns401(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for Basic auth, got %d", status)
	}
}

// ---------------------------------------------------------------------------
// 12. GET /.well-known/openid-configuration returns OIDC discovery JSON
// ---------------------------------------------------------------------------

func TestOIDCDiscovery(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}

	var doc map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("failed to decode OIDC discovery: %v", err)
	}

	requiredKeys := []string{
		"issuer", "authorization_endpoint", "token_endpoint",
		"userinfo_endpoint", "jwks_uri", "scopes_supported",
		"response_types_supported", "grant_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, k := range requiredKeys {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing required OIDC discovery field: %q", k)
		}
	}
}

func TestOIDCDiscoveryEndpointURLs(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "auth.example.com"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var doc map[string]interface{}
	json.NewDecoder(w.Body).Decode(&doc)

	authEndpoint, _ := doc["authorization_endpoint"].(string)
	if !strings.Contains(authEndpoint, "/oauth/authorize") {
		t.Errorf("authorization_endpoint should contain /oauth/authorize, got %q", authEndpoint)
	}

	tokenEndpoint, _ := doc["token_endpoint"].(string)
	if !strings.Contains(tokenEndpoint, "/oauth/token") {
		t.Errorf("token_endpoint should contain /oauth/token, got %q", tokenEndpoint)
	}

	jwksURI, _ := doc["jwks_uri"].(string)
	if !strings.Contains(jwksURI, "/.well-known/jwks.json") {
		t.Errorf("jwks_uri should contain /.well-known/jwks.json, got %q", jwksURI)
	}
}

// ---------------------------------------------------------------------------
// 13. GET /.well-known/jwks.json returns JWKS with keys array
// ---------------------------------------------------------------------------

func TestJWKSResponse(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %q", ct)
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}

	keys, ok := jwks["keys"]
	if !ok {
		t.Fatal("JWKS response missing 'keys' field")
	}

	keysArr, ok := keys.([]interface{})
	if !ok {
		t.Fatal("'keys' field is not an array")
	}

	if len(keysArr) < 1 {
		t.Error("expected at least 1 key in JWKS")
	}
}

func TestJWKSKeyStructure(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	json.NewDecoder(w.Body).Decode(&jwks)

	for i, key := range jwks.Keys {
		for _, field := range []string{"kty", "use", "alg", "kid", "n", "e"} {
			if _, ok := key[field]; !ok {
				t.Errorf("key[%d] missing field %q", i, field)
			}
		}
		if key["kty"] != "RSA" {
			t.Errorf("key[%d] kty=%v, want RSA", i, key["kty"])
		}
		if key["alg"] != "RS256" {
			t.Errorf("key[%d] alg=%v, want RS256", i, key["alg"])
		}
	}
}

// ---------------------------------------------------------------------------
// 14. GET /saml/metadata returns XML
// ---------------------------------------------------------------------------

func TestSAMLMetadataReturnsXML(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Errorf("expected application/xml content-type, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<?xml") {
		t.Error("expected XML declaration")
	}
	if !strings.Contains(body, "EntityDescriptor") {
		t.Error("expected EntityDescriptor element in SAML metadata")
	}
	if !strings.Contains(body, "SPSSODescriptor") {
		t.Error("expected SPSSODescriptor element in SAML metadata")
	}
	if !strings.Contains(body, "AssertionConsumerService") {
		t.Error("expected AssertionConsumerService element in SAML metadata")
	}
}

// ---------------------------------------------------------------------------
// 15. GET /saml/sso returns HTML
// ---------------------------------------------------------------------------

func TestSAMLSSOReturnsHTML(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "SAMLResponse") {
		t.Error("expected SAMLResponse field in SSO form")
	}
	if !strings.Contains(body, "saml-form") {
		t.Error("expected saml-form id in SSO page")
	}
	if !strings.Contains(body, "Single Sign-On") {
		t.Error("expected 'Single Sign-On' text in SSO page")
	}
}

// ---------------------------------------------------------------------------
// 16. POST /saml/acs returns HTML
// ---------------------------------------------------------------------------

func TestSAMLACSReturnsHTML(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"SAMLResponse": {"base64encodedresponse"},
		"RelayState":   {"https://example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "SAML Login Successful") {
		t.Error("expected 'SAML Login Successful' in ACS response")
	}
	if !strings.Contains(body, "user@glitch.example") {
		t.Error("expected user email in ACS response")
	}
}

// ---------------------------------------------------------------------------
// 17. GET /auth/google returns branded login HTML
// ---------------------------------------------------------------------------

func TestAuthGoogleBrandedLogin(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Google") {
		t.Error("expected 'Google' branding in login page")
	}
	if !strings.Contains(body, "Sign in with Google") {
		t.Error("expected 'Sign in with Google' title")
	}
	if !strings.Contains(body, "#4285F4") {
		t.Error("expected Google brand color #4285F4")
	}
}

// ---------------------------------------------------------------------------
// 18. GET /auth/github returns branded login HTML
// ---------------------------------------------------------------------------

func TestAuthGitHubBrandedLogin(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "GitHub") {
		t.Error("expected 'GitHub' branding in login page")
	}
	if !strings.Contains(body, "Sign in with GitHub") {
		t.Error("expected 'Sign in with GitHub' title")
	}
	if !strings.Contains(body, "#24292e") {
		t.Error("expected GitHub brand color #24292e")
	}
}

// ---------------------------------------------------------------------------
// 19. GET /auth/facebook returns branded login HTML
// ---------------------------------------------------------------------------

func TestAuthFacebookBrandedLogin(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/auth/facebook", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Facebook") {
		t.Error("expected 'Facebook' branding in login page")
	}
	if !strings.Contains(body, "Sign in with Facebook") {
		t.Error("expected 'Sign in with Facebook' title")
	}
	if !strings.Contains(body, "#1877F2") {
		t.Error("expected Facebook brand color #1877F2")
	}
}

// ---------------------------------------------------------------------------
// 20. JWT tokens in response are properly formatted (3 dot-separated parts)
// ---------------------------------------------------------------------------

func TestJWTTokenFormat(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"glitch_code_jwt_test"},
		"client_id":  {"test-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	tokens := []string{"access_token", "refresh_token", "id_token"}
	for _, tokenName := range tokens {
		tok, ok := resp[tokenName].(string)
		if !ok {
			t.Errorf("expected %s to be a string", tokenName)
			continue
		}
		parts := strings.Split(tok, ".")
		if len(parts) != 3 {
			t.Errorf("%s: expected 3 dot-separated parts, got %d", tokenName, len(parts))
		}
		for i, part := range parts {
			if part == "" {
				t.Errorf("%s: part %d is empty", tokenName, i)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Additional tests for broader coverage (tests 21-40)
// ---------------------------------------------------------------------------

// 21. GET /oauth/token returns token info JSON
func TestGetTokenInfoEndpoint(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", status)
	}

	var info map[string]interface{}
	json.NewDecoder(w.Body).Decode(&info)

	if _, ok := info["supported_grant_types"]; !ok {
		t.Error("expected supported_grant_types in token info response")
	}
	if info["token_type"] != "Bearer" {
		t.Errorf("expected token_type='Bearer', got %v", info["token_type"])
	}
}

// 22. Token with refresh_token grant includes id_token
func TestTokenRefreshTokenGrantIncludesIDToken(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"some_refresh_token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["id_token"] == nil {
		t.Error("refresh_token grant should include id_token")
	}
}

// 23. Default grant_type falls back to authorization_code
func TestTokenDefaultGrantType(t *testing.T) {
	h := NewHandler()
	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	// default is authorization_code, which includes id_token
	if resp["id_token"] == nil {
		t.Error("default grant_type should be authorization_code and include id_token")
	}
}

// 24. Unknown path returns 404
func TestUnknownPathReturns404(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/nonexistent", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", status)
	}
}

// 25. Social login pages contain form elements
func TestSocialLoginContainsForm(t *testing.T) {
	providers := []string{"/auth/google", "/auth/github", "/auth/facebook"}
	h := NewHandler()

	for _, p := range providers {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)
		body := w.Body.String()

		if !strings.Contains(body, "<form") {
			t.Errorf("%s: expected <form> element in social login page", p)
		}
		if !strings.Contains(body, `type="email"`) {
			t.Errorf("%s: expected email input field", p)
		}
		if !strings.Contains(body, `type="password"`) {
			t.Errorf("%s: expected password input field", p)
		}
		if !strings.Contains(body, "GlitchAuth") {
			t.Errorf("%s: expected GlitchAuth mention in footer", p)
		}
	}
}

// 26. POST /oauth/authorize with invalid redirect_uri returns 400
func TestPostAuthorizeInvalidRedirectURI(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"action":       {"allow"},
		"redirect_uri": {"://bad-uri"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid redirect_uri, got %d", status)
	}
}

// 27. Token endpoint default scope is "openid profile email"
func TestTokenDefaultScope(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	scope, ok := resp["scope"].(string)
	if !ok {
		t.Fatal("expected scope to be a string")
	}
	if scope != "openid profile email" {
		t.Errorf("expected default scope 'openid profile email', got %q", scope)
	}
}

// 28. Token endpoint preserves custom scope
func TestTokenCustomScope(t *testing.T) {
	h := NewHandler()
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read write admin"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["scope"] != "read write admin" {
		t.Errorf("expected scope='read write admin', got %v", resp["scope"])
	}
}

// 29. OIDC discovery includes claims_supported
func TestOIDCDiscoveryClaimsSupported(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var doc map[string]interface{}
	json.NewDecoder(w.Body).Decode(&doc)

	claims, ok := doc["claims_supported"].([]interface{})
	if !ok {
		t.Fatal("expected claims_supported to be an array")
	}

	expected := map[string]bool{"sub": false, "email": false, "name": false}
	for _, c := range claims {
		if s, ok := c.(string); ok {
			expected[s] = true
		}
	}
	for k, found := range expected {
		if !found {
			t.Errorf("expected claim %q in claims_supported", k)
		}
	}
}

// 30. SAML metadata contains certificate data
func TestSAMLMetadataContainsCertificate(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "X509Certificate") {
		t.Error("expected X509Certificate element in SAML metadata")
	}
	if !strings.Contains(body, "KeyDescriptor") {
		t.Error("expected KeyDescriptor element in SAML metadata")
	}
}

// 31. SAML SSO contains base64-encoded SAMLResponse
func TestSAMLSSOContainsEncodedResponse(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/saml/sso", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "RelayState") {
		t.Error("expected RelayState field in SSO form")
	}
	if !strings.Contains(body, `action="`) {
		t.Error("expected form action in SSO page")
	}
	if !strings.Contains(body, "/saml/acs") {
		t.Error("expected /saml/acs as form action")
	}
}

// 32. signJWT produces valid 3-part tokens
func TestSignJWTFormat(t *testing.T) {
	claims := map[string]interface{}{
		"sub":  "test-user",
		"name": "Test",
		"exp":  1234567890,
	}
	token := signJWT(claims)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT, got %d", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

// 33. signJWT header contains HS256 alg
func TestSignJWTHeader(t *testing.T) {
	claims := map[string]interface{}{"sub": "test"}
	token := signJWT(claims)
	parts := strings.Split(token, ".")

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode JWT header: %v", err)
	}

	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse JWT header JSON: %v", err)
	}

	if header["alg"] != "HS256" {
		t.Errorf("expected alg=HS256, got %q", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("expected typ=JWT, got %q", header["typ"])
	}
}

// 34. signJWT payload contains claims
func TestSignJWTPayload(t *testing.T) {
	claims := map[string]interface{}{
		"sub":  "user-42",
		"name": "Test User",
	}
	token := signJWT(claims)
	parts := strings.Split(token, ".")

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("failed to parse JWT payload JSON: %v", err)
	}

	if payload["sub"] != "user-42" {
		t.Errorf("expected sub='user-42', got %v", payload["sub"])
	}
	if payload["name"] != "Test User" {
		t.Errorf("expected name='Test User', got %v", payload["name"])
	}
}

// 35. signJWT produces deterministic output for same claims
func TestSignJWTDeterministic(t *testing.T) {
	claims := map[string]interface{}{
		"sub": "fixed-user",
		"exp": 9999999999,
	}
	token1 := signJWT(claims)
	token2 := signJWT(claims)
	if token1 != token2 {
		t.Error("signJWT should produce deterministic output for identical claims")
	}
}

// 36. ShouldHandle covers sub-paths under /oauth/ and /saml/
func TestShouldHandleOAuthSubPaths(t *testing.T) {
	h := NewHandler()
	subPaths := []string{
		"/oauth/register",
		"/oauth/logout",
		"/oauth/revoke",
		"/oauth/introspect",
		"/saml/logout",
		"/saml/some-other",
	}
	for _, p := range subPaths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true (prefix match)", p)
		}
	}
}

// 37. UserInfo bearer token is case-insensitive
func TestUserInfoBearerCaseInsensitive(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "BEARER my-token")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("expected status 200 with uppercase BEARER, got %d", status)
	}
}

// 38. Issuer base uses Host header
func TestIssuerBaseFromHostHeader(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "my-auth.example.com:9000"
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	var doc map[string]interface{}
	json.NewDecoder(w.Body).Decode(&doc)

	issuer, _ := doc["issuer"].(string)
	if !strings.Contains(issuer, "my-auth.example.com:9000") {
		t.Errorf("expected issuer to contain host 'my-auth.example.com:9000', got %q", issuer)
	}
}

// 39. Callback page with code includes token exchange form
func TestCallbackPageWithCodeHasExchangeForm(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=test_code_xyz&state=s123", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "Exchange Code for Token") {
		t.Error("expected 'Exchange Code for Token' button")
	}
	if !strings.Contains(body, "authorization_code") {
		t.Error("expected grant_type=authorization_code hidden input")
	}
}

// 40. Social login pages contain provider name in hidden field
func TestSocialLoginProviderHiddenField(t *testing.T) {
	tests := []struct {
		path     string
		provider string
	}{
		{"/auth/google", "google"},
		{"/auth/github", "github"},
		{"/auth/facebook", "facebook"},
	}

	h := NewHandler()
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)
		body := w.Body.String()

		expected := fmt.Sprintf(`value="%s"`, tt.provider)
		if !strings.Contains(body, expected) {
			t.Errorf("%s: expected hidden provider field with value=%q", tt.path, tt.provider)
		}
	}
}
