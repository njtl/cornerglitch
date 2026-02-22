package vuln

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers — reuse doGet/doPost from owasp_test.go; add method-specific helpers
// ---------------------------------------------------------------------------

func doAdvancedGet(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)
	return rec
}

func doAdvancedPost(t *testing.T, h *Handler, path string, body string, ct string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)
	return rec
}

func doAdvancedMethod(t *testing.T, h *Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)
	return rec
}

func doAdvancedGetWithHeaders(t *testing.T, h *Handler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// AdvancedShouldHandle
// ---------------------------------------------------------------------------

func TestAdvancedShouldHandle(t *testing.T) {
	h := NewHandler()

	shouldMatch := []string{
		"/vuln/cors/reflect",
		"/vuln/cors/wildcard",
		"/vuln/cors/null",
		"/vuln/redirect?url=http://evil.com",
		"/vuln/xxe/parse",
		"/vuln/xxe/upload",
		"/vuln/ssti/render?name=test",
		"/vuln/ssti/preview",
		"/vuln/crlf/set?lang=en",
		"/vuln/host/reset",
		"/vuln/host/cache",
		"/vuln/verb/admin",
		"/vuln/verb/delete",
		"/vuln/hpp/transfer?from=a&to=b",
		"/vuln/hpp/search?q=test",
		"/vuln/upload/",
		"/vuln/upload/process",
		"/vuln/cmd/ping?host=127.0.0.1",
		"/vuln/cmd/dns?domain=example.com",
		"/vuln/cmd/whois?target=example.com",
		"/vuln/graphql/",
		"/vuln/graphql/batch",
		"/vuln/graphql/depth",
		"/vuln/jwt/none",
		"/vuln/jwt/weak",
		"/vuln/jwt/kid",
		"/vuln/jwt/jwks",
		"/vuln/race/coupon",
		"/vuln/race/transfer",
		"/vuln/deserialize/java",
		"/vuln/deserialize/python",
		"/vuln/deserialize/php",
		"/vuln/path/..%2f..%2fetc/passwd",
	}

	for _, p := range shouldMatch {
		u, _ := url.Parse(p)
		if !h.AdvancedShouldHandle(u.Path) {
			t.Errorf("AdvancedShouldHandle(%q) = false, want true", u.Path)
		}
	}

	shouldNotMatch := []string{
		"/", "/vuln/a01/", "/vuln/a02/", "/admin/users", "/login",
	}
	for _, p := range shouldNotMatch {
		if h.AdvancedShouldHandle(p) {
			t.Errorf("AdvancedShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 1. CORS Misconfiguration
// ---------------------------------------------------------------------------

func TestCORS_Reflect(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/vuln/cors/reflect", nil)
	req.Header.Set("Origin", "https://attacker.com")
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://attacker.com" {
		t.Errorf("ACAO = %q, want %q", got, "https://attacker.com")
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Error("Access-Control-Allow-Credentials not set to true")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "cors-misconfiguration" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want cors-misconfiguration", got)
	}
}

func TestCORS_Wildcard(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/cors/wildcard")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want *", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Error("credentials not set to true")
	}
	if !strings.Contains(rec.Body.String(), "api_key") {
		t.Error("response should contain sensitive data")
	}
}

func TestCORS_Null(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/vuln/cors/null", nil)
	req.Header.Set("Origin", "null")
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "null" {
		t.Errorf("ACAO = %q, want null", got)
	}
}

// ---------------------------------------------------------------------------
// 2. Open Redirect
// ---------------------------------------------------------------------------

func TestRedirect_URL(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/redirect?url=https://evil.com")

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "https://evil.com" {
		t.Errorf("Location = %q, want https://evil.com", got)
	}
	if !strings.Contains(rec.Body.String(), "meta http-equiv=\"refresh\"") {
		t.Error("response should contain meta refresh tag")
	}
}

func TestRedirect_Next(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/redirect?next=https://phish.com")
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://phish.com" {
		t.Errorf("Location = %q, want https://phish.com", got)
	}
}

func TestRedirect_ReturnTo(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/redirect?return_to=https://trap.net")
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://trap.net" {
		t.Errorf("Location = %q, want https://trap.net", got)
	}
}

func TestRedirect_NoParam(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/redirect")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 when no redirect param", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 3. XXE
// ---------------------------------------------------------------------------

func TestXXE_Parse(t *testing.T) {
	h := NewHandler()
	xml := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
	rec := doAdvancedPost(t, h, "/vuln/xxe/parse", xml, "application/xml")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0") {
		t.Error("XXE response should contain fake /etc/passwd content")
	}
	if !strings.Contains(body, "entity-resolution") {
		t.Error("XXE response should contain entity-resolution element")
	}
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "xxe" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want xxe", got)
	}
}

func TestXXE_Upload_Form(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/xxe/upload")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Error("upload page should contain a form")
	}
}

// ---------------------------------------------------------------------------
// 4. SSTI
// ---------------------------------------------------------------------------

func TestSSTI_RenderMath(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/ssti/render?name={{7*7}}")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "49") {
		t.Error("SSTI should calculate {{7*7}} = 49")
	}
}

func TestSSTI_RenderAddition(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/ssti/render?name={{3+5}}")
	if !strings.Contains(rec.Body.String(), "8") {
		t.Error("SSTI should calculate {{3+5}} = 8")
	}
}

func TestSSTI_RenderConfig(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/ssti/render?name={{config}}")
	if !strings.Contains(rec.Body.String(), "SECRET_KEY") {
		t.Error("SSTI should expose config with SECRET_KEY")
	}
}

func TestSSTI_RenderClass(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/ssti/render?name={{''.__class__}}")
	if !strings.Contains(rec.Body.String(), "class") {
		t.Error("SSTI should return class info")
	}
}

func TestSSTI_Preview(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedPost(t, h, "/vuln/ssti/preview", "template={{7*7}}", "application/x-www-form-urlencoded")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "49") {
		t.Error("SSTI preview should evaluate {{7*7}} = 49")
	}
}

func TestSSTI_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/ssti/render?name=test")
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "ssti" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want ssti", got)
	}
}

// ---------------------------------------------------------------------------
// 5. CRLF Injection
// ---------------------------------------------------------------------------

func TestCRLF_NormalParam(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/crlf/set?lang=en")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Language"); got != "en" {
		t.Errorf("X-Language = %q, want en", got)
	}
	// Should NOT have injected cookie
	cookies := rec.Header().Values("Set-Cookie")
	for _, c := range cookies {
		if strings.Contains(c, "admin=true") {
			t.Error("should not inject admin cookie without CRLF")
		}
	}
}

func TestCRLF_Injection(t *testing.T) {
	h := NewHandler()
	// Simulate CRLF injection in raw query
	rec := doAdvancedGet(t, h, "/vuln/crlf/set?lang=en%0d%0aSet-Cookie:%20admin=true")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	// Check that the injected cookie appears
	cookies := rec.Header().Values("Set-Cookie")
	found := false
	for _, c := range cookies {
		if strings.Contains(c, "admin=true") {
			found = true
			break
		}
	}
	if !found {
		t.Error("CRLF injection should produce Set-Cookie: admin=true header")
	}

	if got := rec.Header().Get("X-Injected"); got != "true" {
		t.Error("CRLF injection should set X-Injected: true")
	}
}

// ---------------------------------------------------------------------------
// 6. Host Header Injection
// ---------------------------------------------------------------------------

func TestHost_Reset(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGetWithHeaders(t, h, "/vuln/host/reset", map[string]string{
		"X-Forwarded-Host": "evil.com",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "evil.com") {
		t.Error("Host header injection: reset link should contain the attacker host")
	}
}

func TestHost_Cache(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGetWithHeaders(t, h, "/vuln/host/cache", map[string]string{
		"X-Forwarded-Host": "attacker.io",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "attacker.io") {
		t.Error("Host header injection: cached page should use attacker host in links")
	}
	if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "public") {
		t.Error("Cache-Control should be public")
	}
}

// ---------------------------------------------------------------------------
// 7. Verb Tampering
// ---------------------------------------------------------------------------

func TestVerb_AdminGET(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/verb/admin")
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /vuln/verb/admin: status = %d, want 403", rec.Code)
	}
}

func TestVerb_AdminPUT(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedMethod(t, h, http.MethodPut, "/vuln/verb/admin")
	if rec.Code != http.StatusOK {
		t.Errorf("PUT /vuln/verb/admin: status = %d, want 200", rec.Code)
	}
}

func TestVerb_AdminHEAD(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedMethod(t, h, http.MethodHead, "/vuln/verb/admin")
	if rec.Code != http.StatusOK {
		t.Errorf("HEAD /vuln/verb/admin: status = %d, want 200", rec.Code)
	}
}

func TestVerb_AdminPATCH(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedMethod(t, h, http.MethodPatch, "/vuln/verb/admin")
	if rec.Code != http.StatusOK {
		t.Errorf("PATCH /vuln/verb/admin: status = %d, want 200", rec.Code)
	}
}

func TestVerb_AdminOPTIONS(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedMethod(t, h, http.MethodOptions, "/vuln/verb/admin")
	if rec.Code != http.StatusOK {
		t.Errorf("OPTIONS /vuln/verb/admin: status = %d, want 200", rec.Code)
	}
}

func TestVerb_Delete(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/verb/delete")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "deleted") {
		t.Error("verb/delete should confirm deletion")
	}
}

// ---------------------------------------------------------------------------
// 8. HTTP Parameter Pollution
// ---------------------------------------------------------------------------

func TestHPP_Transfer(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/hpp/transfer?from=user&to=admin&amount=100")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "admin") {
		t.Error("HPP transfer should show 'to' value")
	}
}

func TestHPP_TransferDuplicate(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/hpp/transfer?from=user&to=admin&to=attacker&amount=100")
	body := rec.Body.String()
	// Last value should be used
	if !strings.Contains(body, "attacker") {
		t.Error("HPP should use the last value of duplicate 'to' parameter")
	}
}

func TestHPP_Search(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/hpp/search?q=safe&q=<script>alert(1)</script>")
	body := rec.Body.String()
	if !strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("HPP search should reflect the last parameter value without sanitization")
	}
}

// ---------------------------------------------------------------------------
// 9. Insecure File Upload
// ---------------------------------------------------------------------------

func TestUpload_Form(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/upload/")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Error("upload page should contain a form")
	}
}

func TestUpload_Process(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedPost(t, h, "/vuln/upload/process", "filename=shell.php", "application/x-www-form-urlencoded")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "shell.php") {
		t.Error("upload should return the unsanitized filename")
	}
	if !strings.Contains(body, "/uploads/shell.php") {
		t.Error("upload should show file accessible path")
	}
}

// ---------------------------------------------------------------------------
// 10. Command Injection
// ---------------------------------------------------------------------------

func TestCmd_Ping(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/cmd/ping?host=127.0.0.1")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ping -c 4 127.0.0.1") {
		t.Error("ping should show the command being executed")
	}
	if !strings.Contains(body, "icmp_seq=") {
		t.Error("ping should show icmp output")
	}
}

func TestCmd_PingInjection(t *testing.T) {
	h := NewHandler()
	// Use pipe for injection (Go 1.17+ treats raw ; as query separator)
	rec := doAdvancedGet(t, h, "/vuln/cmd/ping?host=127.0.0.1|id")
	body := rec.Body.String()
	if !strings.Contains(body, "127.0.0.1") {
		t.Error("should show normal ping output")
	}
	if !strings.Contains(body, "www-data") {
		t.Error("command injection should show output of 'id'")
	}
}

func TestCmd_DNS(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/cmd/dns?domain=example.com")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "nslookup example.com") {
		t.Error("dns should show the command being executed")
	}
}

func TestCmd_DNSInjection(t *testing.T) {
	h := NewHandler()
	// Use pipe for injection (Go 1.17+ treats raw ; as query separator)
	rec := doAdvancedGet(t, h, "/vuln/cmd/dns?domain=example.com|whoami")
	body := rec.Body.String()
	if !strings.Contains(body, "www-data") {
		t.Error("command injection should show whoami output")
	}
}

func TestCmd_Whois(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/cmd/whois?target=example.com")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "whois example.com") {
		t.Error("whois should show command being executed")
	}
}

func TestCmd_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/cmd/ping?host=127.0.0.1")
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "command-injection" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want command-injection", got)
	}
}

// ---------------------------------------------------------------------------
// 11. GraphQL
// ---------------------------------------------------------------------------

func TestGraphQL_Introspection(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/graphql/")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "__schema") {
		t.Error("GraphQL introspection should return schema")
	}
	if !strings.Contains(body, "Query") {
		t.Error("GraphQL introspection should contain Query type")
	}
}

func TestGraphQL_Batch(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/graphql/batch")
	body := rec.Body.String()
	if !strings.HasPrefix(body, "[") {
		t.Error("GraphQL batch should return array")
	}
	if !strings.Contains(body, "api_key") {
		t.Error("batch response should contain sensitive data")
	}
}

func TestGraphQL_Depth(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/graphql/depth")
	body := rec.Body.String()
	if !strings.Contains(body, "friends") {
		t.Error("depth response should contain nested friends")
	}
	// Count nesting by looking for repeated "friends" keys
	if strings.Count(body, "friends") < 5 {
		t.Error("depth response should be deeply nested")
	}
}

// ---------------------------------------------------------------------------
// 12. JWT
// ---------------------------------------------------------------------------

func TestJWT_None(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/none")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "token") {
		t.Error("JWT none should return a token")
	}
	// Check JWT format (header.payload.)
	if !strings.Contains(body, "none") {
		t.Error("JWT should use alg:none")
	}
}

func TestJWT_Weak(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/weak")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// JWT format: three dot-separated parts
	if !strings.Contains(body, "HS256") {
		t.Error("weak JWT should use HS256")
	}
	if !strings.Contains(body, "secret") {
		t.Error("response should mention signing key 'secret'")
	}
}

func TestJWT_WeakFormat(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/weak")
	body := rec.Body.String()
	// The token value should contain two dots (three parts)
	// Extract a crude check by looking for base64 characters with dots
	if !strings.Contains(body, "eyJ") {
		t.Error("JWT should start with base64-encoded header (eyJ...)")
	}
}

func TestJWT_Kid(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/kid")
	body := rec.Body.String()
	if !strings.Contains(body, "/dev/null") {
		t.Error("JWT kid should reference /dev/null")
	}
}

func TestJWT_JWKS(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/jwks")
	body := rec.Body.String()
	if !strings.Contains(body, "keys") {
		t.Error("JWKS should contain keys array")
	}
	if !strings.Contains(body, "RSA") {
		t.Error("JWKS should contain RSA keys")
	}
}

func TestJWT_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/jwt/none")
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "jwt" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want jwt", got)
	}
}

// ---------------------------------------------------------------------------
// 13. Race Condition
// ---------------------------------------------------------------------------

func TestRace_Coupon(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/race/coupon?code=FREESHIP")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "applied") {
		t.Error("coupon should always succeed")
	}
	if !strings.Contains(body, "FREESHIP") {
		t.Error("coupon code should be reflected")
	}
}

func TestRace_Transfer(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/race/transfer?amount=500")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "500") {
		t.Error("transfer amount should be reflected")
	}
}

// ---------------------------------------------------------------------------
// 14. Insecure Deserialization Extended
// ---------------------------------------------------------------------------

func TestDeserialize_Java(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedPost(t, h, "/vuln/deserialize/java",
		"\xac\xed\x00\x05sr\x00\x1ecom.example.User", "application/octet-stream")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "java-serialized-object") {
		t.Error("java deserialization should identify format")
	}
	if !strings.Contains(body, "deserialized") {
		t.Error("java deserialization should report status")
	}
}

func TestDeserialize_Java_DefaultPayload(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/deserialize/java")
	body := rec.Body.String()
	if !strings.Contains(body, "aced0005") {
		t.Error("default java payload should contain magic bytes reference")
	}
}

func TestDeserialize_Python(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedPost(t, h, "/vuln/deserialize/python",
		"cos\nsystem\n(S'id'\ntR.", "application/octet-stream")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unpickled") {
		t.Error("python deserialization should report unpickled status")
	}
}

func TestDeserialize_PHP(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedPost(t, h, "/vuln/deserialize/php",
		`O:4:"User":1:{s:4:"name";s:5:"admin";}`, "application/octet-stream")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unserialized") {
		t.Error("php deserialization should report unserialized status")
	}
	if !strings.Contains(body, "__wakeup") {
		t.Error("php deserialization should mention magic methods")
	}
}

func TestDeserialize_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/deserialize/java")
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "insecure-deserialization" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want insecure-deserialization", got)
	}
}

// ---------------------------------------------------------------------------
// 15. Path Normalization
// ---------------------------------------------------------------------------

func TestPathNorm_DoubleEncoded(t *testing.T) {
	h := NewHandler()
	// Simulate double-encoded path: ..%2f..%2fetc/passwd
	req := httptest.NewRequest(http.MethodGet, "/vuln/path/test", nil)
	req.URL.Path = "/vuln/path/..%2f..%2fetc/passwd"
	req.URL.RawPath = "/vuln/path/..%252f..%252fetc/passwd"
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0") {
		t.Error("path traversal should return fake /etc/passwd content")
	}
}

func TestPathNorm_DotSegment(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/vuln/path/test", nil)
	req.URL.Path = "/vuln/path/....//....//etc/passwd"
	rec := httptest.NewRecorder()
	h.ServeAdvanced(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0") {
		t.Error("dot-segment bypass should return fake /etc/passwd")
	}
}

func TestPathNorm_NoTraversal(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/path/normal-file.txt")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// Should show info page, not /etc/passwd
	if strings.Contains(body, "root:x:0:0") {
		t.Error("non-traversal path should not return /etc/passwd")
	}
}

func TestPathNorm_VulnTypeHeader(t *testing.T) {
	h := NewHandler()
	rec := doAdvancedGet(t, h, "/vuln/path/normal")
	if got := rec.Header().Get("X-Glitch-Vuln-Type"); got != "path-normalization" {
		t.Errorf("X-Glitch-Vuln-Type = %q, want path-normalization", got)
	}
}

// ---------------------------------------------------------------------------
// All 15 categories produce correct vuln-type headers
// ---------------------------------------------------------------------------

func TestAllAdvanced_VulnTypeHeaders(t *testing.T) {
	h := NewHandler()

	tests := []struct {
		path     string
		wantType string
	}{
		{"/vuln/cors/reflect", "cors-misconfiguration"},
		{"/vuln/redirect?url=http://x.com", "open-redirect"},
		{"/vuln/xxe/upload", "xxe"},
		{"/vuln/ssti/render?name=test", "ssti"},
		{"/vuln/crlf/set?lang=en", "crlf-injection"},
		{"/vuln/host/reset", "host-header-injection"},
		{"/vuln/verb/admin", "verb-tampering"},
		{"/vuln/hpp/transfer?from=a&to=b", "parameter-pollution"},
		{"/vuln/upload/", "insecure-upload"},
		{"/vuln/cmd/ping?host=x", "command-injection"},
		{"/vuln/graphql/", "graphql"},
		{"/vuln/jwt/none", "jwt"},
		{"/vuln/race/coupon", "race-condition"},
		{"/vuln/deserialize/java", "insecure-deserialization"},
		{"/vuln/path/test", "path-normalization"},
	}

	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			rec := doAdvancedGet(t, h, tt.path)
			got := rec.Header().Get("X-Glitch-Vuln-Type")
			if got != tt.wantType {
				t.Errorf("%s: X-Glitch-Vuln-Type = %q, want %q", tt.path, got, tt.wantType)
			}
		})
	}
}
