package honeypot

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. ShouldHandle tests
// ---------------------------------------------------------------------------

func TestShouldHandle_ScannerPaths(t *testing.T) {
	h := NewHoneypot()
	scannerPaths := []string{
		"/.env",
		"/admin",
		"/wp-login.php",
		"/.git/config",
		"/phpinfo.php",
		"/backup.sql",
		"/phpmyadmin/",
		"/shell.php",
		"/.ssh/id_rsa",
		"/debug",
		"/actuator/health",
		"/docker-compose.yml",
	}
	for _, p := range scannerPaths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_RobotsTxt(t *testing.T) {
	h := NewHoneypot()
	if !h.ShouldHandle("/robots.txt") {
		t.Error("ShouldHandle(/robots.txt) = false, want true")
	}
}

func TestShouldHandle_NormalPaths(t *testing.T) {
	h := NewHoneypot()
	normalPaths := []string{
		"/",
		"/products/widget",
		"/contact-us",
		"/api/v1/users/123",
	}
	for _, p := range normalPaths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. IsScanner tests
// ---------------------------------------------------------------------------

func TestIsScanner_KnownScannerUAs(t *testing.T) {
	h := NewHoneypot()
	scannerUAs := []string{
		"sqlmap/1.5",
		"Nikto/2.1",
		"gobuster/3.1",
		"Nuclei v2.9.10",
		"Mozilla/5.0 (compatible; Nessus NASL)",
		"FFUF v1.5.0",
	}
	for _, ua := range scannerUAs {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		if !h.IsScanner(req) {
			t.Errorf("IsScanner(%q) = false, want true", ua)
		}
	}
}

func TestIsScanner_NormalUAs(t *testing.T) {
	h := NewHoneypot()
	normalUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"curl/7.68.0",
		"",
	}
	for _, ua := range normalUAs {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		if h.IsScanner(req) {
			t.Errorf("IsScanner(%q) = true, want false", ua)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. ServeHTTP tests for each LureType
// ---------------------------------------------------------------------------

func TestServeHTTP_LureAdminPanel(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Glitch CMS") {
		t.Error("admin panel response missing 'Glitch CMS'")
	}
	if !strings.Contains(body, "<form") {
		t.Error("admin panel response missing login form")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("admin panel response missing HTML closing tag")
	}
}

func TestServeHTTP_LureConfigFile(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/.env", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	// /.env maps to LureConfigFile which dispatches to serveConfigEnv
	if !strings.Contains(body, "APP_NAME") {
		t.Error("config file response missing expected env content")
	}
}

func TestServeHTTP_LureEnvFile(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/.env.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "DATABASE_URL") {
		t.Error("env file response missing DATABASE_URL")
	}
}

func TestServeHTTP_LureGitExposure_Config(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/.git/config", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "[remote \"origin\"]") {
		t.Error("git config response missing remote origin")
	}
	if !strings.Contains(body, "github.com") {
		t.Error("git config response missing github.com URL")
	}
}

func TestServeHTTP_LureBackupDump(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/backup.sql", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "MySQL dump") || !strings.Contains(body, "CREATE TABLE") {
		t.Error("backup dump response missing SQL content")
	}
}

func TestServeHTTP_LureLoginPage(t *testing.T) {
	h := NewHoneypot()
	// /signin is mapped to LureLoginPage
	req := httptest.NewRequest("GET", "/signin", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("login page response missing login form")
	}
	if !strings.Contains(body, "password") {
		t.Error("login page response missing password field")
	}
}

func TestServeHTTP_LureAPIKey(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/api_keys.json", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "api_key") {
		t.Error("API key response missing 'api_key'")
	}
	if !strings.Contains(body, "secret_key") {
		t.Error("API key response missing 'secret_key'")
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestServeHTTP_LureDebugInfo(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/debug", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	// /debug goes to serveServerStatus (default branch)
	if len(body) == 0 {
		t.Error("debug info response is empty")
	}
}

func TestServeHTTP_LureDBDump(t *testing.T) {
	h := NewHoneypot()
	// /db/ is mapped to LureDBDump
	req := httptest.NewRequest("GET", "/db/", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "CREATE TABLE") {
		t.Error("DB dump response missing CREATE TABLE")
	}
}

func TestServeHTTP_LureShellAccess(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/shell.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "uid=") || !strings.Contains(body, "gid=") {
		t.Error("shell access response missing uid/gid")
	}
}

func TestServeHTTP_LureWordPress(t *testing.T) {
	h := NewHoneypot()
	// /wordpress/wp-login.php is mapped to LureWordPress
	req := httptest.NewRequest("GET", "/wordpress/wp-login.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "WordPress") {
		t.Error("WordPress response missing 'WordPress'")
	}
}

func TestServeHTTP_LurePhpMyAdmin(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/phpinfo.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "phpMyAdmin") {
		t.Error("phpMyAdmin response missing 'phpMyAdmin'")
	}
}

// ---------------------------------------------------------------------------
// 4. Honeypot header test
// ---------------------------------------------------------------------------

func TestHoneypotHeader(t *testing.T) {
	h := NewHoneypot()
	paths := []string{
		"/admin",
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/shell.php",
		"/phpinfo.php",
		"/robots.txt",
	}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		val := w.Header().Get("X-Glitch-Honeypot")
		if val != "true" {
			t.Errorf("path %q: X-Glitch-Honeypot = %q, want %q", p, val, "true")
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Robots.txt test
// ---------------------------------------------------------------------------

func TestRobotsTxt(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "User-agent") {
		t.Error("robots.txt missing User-agent")
	}
	if !strings.Contains(body, "Allow:") {
		t.Error("robots.txt missing Allow entry")
	}
	if !strings.Contains(body, "Disallow:") {
		t.Error("robots.txt missing Disallow entries")
	}
	if !strings.Contains(body, "Sitemap:") {
		t.Error("robots.txt missing Sitemap entry")
	}
}

// ---------------------------------------------------------------------------
// 6. Determinism test
// ---------------------------------------------------------------------------

func TestDeterminism(t *testing.T) {
	h := NewHoneypot()
	paths := []string{
		"/admin",
		"/.env",
		"/.git/config",
		"/backup.sql",
		"/shell.php",
	}
	for _, p := range paths {
		req1 := httptest.NewRequest("GET", p, nil)
		w1 := httptest.NewRecorder()
		h.ServeHTTP(w1, req1)

		req2 := httptest.NewRequest("GET", p, nil)
		w2 := httptest.NewRecorder()
		h.ServeHTTP(w2, req2)

		if w1.Body.String() != w2.Body.String() {
			t.Errorf("path %q: two requests produced different content", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. Hits counter test
// ---------------------------------------------------------------------------

func TestHitsCounter(t *testing.T) {
	h := NewHoneypot()
	before := atomic.LoadInt64(&h.Hits)

	paths := []string{"/admin", "/.env", "/robots.txt", "/shell.php", "/backup.sql"}
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
	}

	after := atomic.LoadInt64(&h.Hits)
	if after-before != int64(len(paths)) {
		t.Errorf("Hits counter incremented by %d, want %d", after-before, len(paths))
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests
// ---------------------------------------------------------------------------

func TestServeHTTP_UnknownPath_ReturnsNotFound(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/totally-unknown-path-xyz", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", status, http.StatusNotFound)
	}
}

func TestServeHTTP_ConfigPHP(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/config.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<?php") {
		t.Error("config.php response missing PHP opening tag")
	}
}

func TestServeHTTP_ConfigYAML(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/config.yml", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "database:") {
		t.Error("config.yml response missing database section")
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/yaml" {
		t.Errorf("Content-Type = %q, want text/yaml", ct)
	}
}

func TestServeHTTP_ConfigJSON(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/config.json", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "\"database\"") {
		t.Error("config.json response missing database key")
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestServeHTTP_GitHead(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/.git/HEAD", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "ref: refs/heads/") {
		t.Errorf("git HEAD response = %q, want prefix 'ref: refs/heads/'", body)
	}
}

func TestServeHTTP_BackupArchive(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/backup.zip", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("backup archive response is empty")
	}
}

func TestServeHTTP_ActuatorEndpoint(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/actuator/health", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "\"status\"") {
		t.Error("actuator response missing status field")
	}
}

func TestServeHTTP_DebugPprof(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/debug/pprof", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "goroutine") {
		t.Error("pprof response missing goroutine info")
	}
}

func TestServeHTTP_WPAdminRedirect(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/wp-admin/admin-ajax.php", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusFound {
		t.Errorf("status = %d, want %d", status, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "wp-login.php") {
		t.Errorf("Location = %q, missing wp-login.php redirect", loc)
	}
}

func TestServeHTTP_GitReflog(t *testing.T) {
	h := NewHoneypot()
	// /.git/logs/refs/ contains "/logs/" and does NOT end with "/HEAD",
	// so it routes to serveGitReflog.
	req := httptest.NewRequest("GET", "/.git/logs/refs/", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "commit:") && !strings.Contains(body, "checkout:") && !strings.Contains(body, "merge:") {
		t.Error("git reflog response missing expected reflog entries")
	}
}

func TestServeHTTP_CredentialPaths(t *testing.T) {
	h := NewHoneypot()
	// Credential paths are mapped to LureAPIKey
	req := httptest.NewRequest("GET", "/.ssh/id_rsa", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "api_key") {
		t.Error("credential path response missing api_key")
	}
}

func TestServeHTTP_EnvFileDatabaseURL(t *testing.T) {
	h := NewHoneypot()
	req := httptest.NewRequest("GET", "/.env.json", nil)
	w := httptest.NewRecorder()
	status := h.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "DATABASE_URL") {
		t.Error("env file response missing DATABASE_URL")
	}
}

// ---------------------------------------------------------------------------
// Firecrawl honeypot path tests
// ---------------------------------------------------------------------------

func TestFirecrawlHoneypotPaths(t *testing.T) {
	h := NewHoneypot()

	firecrawlPaths := []string{
		"/assets/config.js",
		"/assets/app.config.js",
		"/api/internal/config",
		"/api/internal/keys",
		"/_next/data/config.json",
		"/api/v1/internal/status",
		"/api/internal/health",
		"/api/private/tokens",
	}

	for _, p := range firecrawlPaths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true (Firecrawl-targeted path)", p)
		}
	}

	// Verify they are mapped to LureConfigFile
	for _, p := range firecrawlPaths {
		lureType, ok := h.paths[p]
		if !ok {
			t.Errorf("path %q not registered in honeypot", p)
			continue
		}
		if lureType != LureConfigFile {
			t.Errorf("path %q lure type = %d, want LureConfigFile (%d)", p, lureType, LureConfigFile)
		}
	}

	// Verify they serve content
	for _, p := range firecrawlPaths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		status := h.ServeHTTP(w, req)
		if status != http.StatusOK {
			t.Errorf("path %q status = %d, want %d", p, status, http.StatusOK)
		}
		if w.Body.Len() == 0 {
			t.Errorf("path %q returned empty body", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Oxylabs honeypot path tests
// ---------------------------------------------------------------------------

func TestOxylabsHoneypotPaths(t *testing.T) {
	h := NewHoneypot()

	oxylabsPaths := []string{
		"/api/data/export",
		"/api/scrape/results",
		"/api/v2/data/bulk",
		"/api/crawl/queue",
		"/data/feed.json",
		"/api/search/results.json",
		"/api/products/all.json",
		"/api/listings/feed",
	}

	for _, p := range oxylabsPaths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true (Oxylabs-targeted path)", p)
		}
	}

	// Verify they are mapped to LureAPIKey
	for _, p := range oxylabsPaths {
		lureType, ok := h.paths[p]
		if !ok {
			t.Errorf("path %q not registered in honeypot", p)
			continue
		}
		if lureType != LureAPIKey {
			t.Errorf("path %q lure type = %d, want LureAPIKey (%d)", p, lureType, LureAPIKey)
		}
	}

	// Verify they serve content with correct content type
	for _, p := range oxylabsPaths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		status := h.ServeHTTP(w, req)
		if status != http.StatusOK {
			t.Errorf("path %q status = %d, want %d", p, status, http.StatusOK)
		}
		if w.Body.Len() == 0 {
			t.Errorf("path %q returned empty body", p)
		}
		body := w.Body.String()
		if !strings.Contains(body, "api_key") {
			t.Errorf("path %q response missing 'api_key'", p)
		}
	}
}
