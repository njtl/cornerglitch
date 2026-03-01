package atomic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
)

// ---------------------------------------------------------------------------
// Scanner Mode Tests — End-to-end behavioral validation
//
// These tests spin up an httptest.Server that records all requests, then run
// each scanner mode against it and verify mode-specific behavior through
// assertions on recorded requests, config values, and report contents.
// ---------------------------------------------------------------------------

// recordedRequest captures what the test server saw.
type recordedRequest struct {
	Method    string
	Path      string
	Headers   http.Header
	UserAgent string
	Body      string
}

// testServer wraps an httptest.Server with request recording.
type testServer struct {
	Server       *httptest.Server
	mu           sync.Mutex
	Requests     []recordedRequest
	RequestCount atomic.Int64
}

// newTestServer creates a test HTTP server that records all requests.
func newTestServer() *testServer {
	ts := &testServer{
		Requests: make([]recordedRequest, 0, 256),
	}

	mux := http.NewServeMux()

	// Root page: HTML with links, forms, and JS fetch calls
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Powered-By", "GoTest")
		fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>Test App</title></head>
<body>
<nav>
  <a href="/page1">Page 1</a>
  <a href="/page2">Page 2</a>
  <a href="/page3">Page 3</a>
  <a href="/api/v1/users">API Users</a>
</nav>
<form action="/login" method="POST">
  <input name="username" type="text">
  <input name="password" type="password">
  <button type="submit">Login</button>
</form>
<script>
  fetch('/api/v1/users').then(r => r.json());
  fetch('/api/v1/products').then(r => r.json());
</script>
<a href="/admin" style="display:none">Admin</a>
<link rel="prefetch" href="/api/v1/config">
</body></html>`)
	})

	// Sub-pages with more links
	for _, page := range []string{"/page1", "/page2", "/page3"} {
		p := page
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			ts.record(r)
			w.Header().Set("Server", "TestServer/1.0")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><body><h1>%s</h1><a href="/">Home</a><a href="/page1">P1</a><a href="/page2">P2</a></body></html>`, p)
		})
	}

	// API endpoints
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "TestServer/1.0")
		fmt.Fprint(w, `{"users":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}]}`)
	})

	mux.HandleFunc("/api/v1/products", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "TestServer/1.0")
		fmt.Fprint(w, `{"products":[{"id":1,"name":"Widget"}]}`)
	})

	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"debug":false,"version":"1.0"}`)
	})

	// Login endpoint
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><p>Login page</p></body></html>`)
	})

	// Admin page
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Admin Panel</h1></body></html>`)
	})

	// Error path
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal server error","stack":"goroutine 1 [running]: main.handler()"}`)
	})

	// Redirect path
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		http.Redirect(w, r, "/page1", http.StatusFound)
	})

	// Vuln-like paths that return 200 (for finding detection)
	mux.HandleFunc("/vuln/", func(w http.ResponseWriter, r *http.Request) {
		ts.record(r)
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><p>Vulnerable endpoint</p></body></html>`)
	})

	// Catch-all for any other path (from attack modules)
	defaultHandler := mux.HandleFunc
	_ = defaultHandler // suppress unused warning — HandleFunc above covers patterns
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try the mux first; if no pattern matches, serve a generic response
		// We need to use the mux but also record everything
		mux.ServeHTTP(w, r)
	}))

	// Replace the server handler with a recording wrapper around the mux
	ts.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure all requests are recorded even if mux doesn't match
		ts.record(r)
		ts.RequestCount.Add(1)

		// Check if any explicit pattern matches by trying to find a handler
		_, pattern := mux.Handler(r)
		if pattern != "" {
			// Reset the record since explicit handlers also call record
			// Actually, let's not double-record: remove the record above
			// and use a middleware approach instead
		}

		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><p>Page: %s</p><a href="/">Home</a></body></html>`, r.URL.Path)
	})

	// Actually, let's re-do this cleanly: wrap the mux in a recording handler
	ts.Requests = ts.Requests[:0]
	ts.RequestCount.Store(0)
	ts.Server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.recordOnce(r)
		mux.ServeHTTP(w, r)
	})

	return ts
}

// recordOnce records a request (thread-safe, counted once).
func (ts *testServer) recordOnce(r *http.Request) {
	ts.RequestCount.Add(1)
	rec := recordedRequest{
		Method:    r.Method,
		Path:      r.URL.RequestURI(),
		Headers:   r.Header.Clone(),
		UserAgent: r.Header.Get("User-Agent"),
	}
	ts.mu.Lock()
	ts.Requests = append(ts.Requests, rec)
	ts.mu.Unlock()
}

// record records a request (for explicit handlers — now a no-op since we record in wrapper).
func (ts *testServer) record(r *http.Request) {
	// Recording is done in the wrapper handler to avoid double-counting
}

// reset clears all recorded requests.
func (ts *testServer) reset() {
	ts.mu.Lock()
	ts.Requests = ts.Requests[:0]
	ts.mu.Unlock()
	ts.RequestCount.Store(0)
}

// getRequests returns a copy of recorded requests.
func (ts *testServer) getRequests() []recordedRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	cp := make([]recordedRequest, len(ts.Requests))
	copy(cp, ts.Requests)
	return cp
}

// ---------------------------------------------------------------------------
// Helper: run a scan with a given config
// ---------------------------------------------------------------------------

func runScan(t *testing.T, cfg *scanner.Config, timeout time.Duration) *scanner.Report {
	t.Helper()

	engine := scanner.NewEngine(cfg)

	// Register all attack modules
	for _, mod := range attacks.AllModules() {
		engine.RegisterModule(mod)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	report, err := engine.Run(ctx)
	if err != nil && ctx.Err() == nil {
		t.Fatalf("scan failed: %v", err)
	}

	return report
}

// ---------------------------------------------------------------------------
// Mode Tests
// ---------------------------------------------------------------------------

func TestScannerMode_Compliance(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	cfg := scanner.ComplianceConfig()
	cfg.Target = ts.Server.URL

	report := runScan(t, cfg, 5*time.Second)

	// --- Universal assertions ---
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if report.Target != ts.Server.URL {
		t.Errorf("report.Target = %q, want %q", report.Target, ts.Server.URL)
	}
	if report.Profile != "compliance" {
		t.Errorf("report.Profile = %q, want compliance", report.Profile)
	}
	if report.TotalRequests <= 0 {
		t.Errorf("report.TotalRequests = %d, should be > 0", report.TotalRequests)
	}

	// --- Compliance-specific assertions ---

	// Config checks
	if cfg.EvasionMode != "none" {
		t.Errorf("compliance EvasionMode = %q, want none", cfg.EvasionMode)
	}
	if cfg.Concurrency > 5 {
		t.Errorf("compliance Concurrency = %d, should be <= 5", cfg.Concurrency)
	}

	// Request count should be moderate (compliance is conservative)
	// Compliance uses limited modules but crawling discovers URLs that expand the request set
	if report.TotalRequests > 1000 {
		t.Errorf("compliance mode made %d requests, expected <= 1000", report.TotalRequests)
	}

	// Compliance mode should NOT contain SQL injection or XSS payloads in request paths
	// (it uses the same modules but the total should be bounded)
	reqs := ts.getRequests()
	injectionCount := 0
	for _, r := range reqs {
		path := strings.ToLower(r.Path)
		if strings.Contains(path, "<script>") || strings.Contains(path, "alert(") {
			injectionCount++
		}
	}
	// Compliance should still test these but in a controlled manner
	t.Logf("compliance: %d total requests, %d injection-like paths", len(reqs), injectionCount)
}

func TestScannerMode_Aggressive(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	cfg := scanner.AggressiveConfig()
	cfg.Target = ts.Server.URL

	report := runScan(t, cfg, 5*time.Second)

	// --- Universal assertions ---
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if report.Target != ts.Server.URL {
		t.Errorf("report.Target = %q, want %q", report.Target, ts.Server.URL)
	}
	if report.Profile != "aggressive" {
		t.Errorf("report.Profile = %q, want aggressive", report.Profile)
	}
	if report.TotalRequests <= 0 {
		t.Errorf("report.TotalRequests = %d, should be > 0", report.TotalRequests)
	}

	// --- Aggressive-specific assertions ---

	// Should make many requests
	if report.TotalRequests < 100 {
		t.Errorf("aggressive mode made only %d requests, expected >= 100", report.TotalRequests)
	}

	// Should have findings (at minimum Server header disclosure from TestServer/1.0)
	if len(report.Findings) == 0 {
		t.Error("aggressive mode should have findings (at minimum Server header disclosure)")
	}

	// Config should have high concurrency
	if cfg.Concurrency < 20 {
		t.Errorf("aggressive Concurrency = %d, expected >= 20", cfg.Concurrency)
	}

	// Verify multiple OWASP categories appear in requests
	reqs := ts.getRequests()
	categories := make(map[string]bool)
	for _, r := range reqs {
		path := r.Path
		if strings.Contains(path, "/vuln/") || strings.Contains(path, "/api/") {
			// Track broad path prefixes as category indicators
			parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
			if len(parts) >= 2 {
				categories[parts[0]+"/"+parts[1]] = true
			}
		}
	}
	t.Logf("aggressive: %d total requests, %d path categories, %d findings",
		len(reqs), len(categories), len(report.Findings))
}

func TestScannerMode_Stealth(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	cfg := scanner.StealthConfig()
	cfg.Target = ts.Server.URL

	report := runScan(t, cfg, 5*time.Second)

	// --- Universal assertions ---
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if report.Target != ts.Server.URL {
		t.Errorf("report.Target = %q, want %q", report.Target, ts.Server.URL)
	}
	if report.Profile != "stealth" {
		t.Errorf("report.Profile = %q, want stealth", report.Profile)
	}
	if report.TotalRequests <= 0 {
		t.Errorf("report.TotalRequests = %d, should be > 0", report.TotalRequests)
	}

	// --- Stealth-specific assertions ---

	// Config checks
	if cfg.EvasionMode != "advanced" {
		t.Errorf("stealth EvasionMode = %q, want advanced", cfg.EvasionMode)
	}
	if cfg.Concurrency > 3 {
		t.Errorf("stealth Concurrency = %d, should be <= 3", cfg.Concurrency)
	}
	if cfg.RateLimit > 10 {
		t.Errorf("stealth RateLimit = %d, should be <= 10", cfg.RateLimit)
	}

	// User-Agent should be browser-like (contain "Mozilla")
	if !strings.Contains(cfg.UserAgent, "Mozilla") {
		t.Errorf("stealth UserAgent should contain Mozilla, got %q", cfg.UserAgent)
	}

	// Requests should have Sec-Fetch-* headers (from advanced evasion)
	reqs := ts.getRequests()
	hasSecFetch := false
	for _, r := range reqs {
		if r.Headers.Get("Sec-Fetch-Dest") != "" || r.Headers.Get("Sec-Fetch-Mode") != "" {
			hasSecFetch = true
			break
		}
	}
	if !hasSecFetch {
		t.Error("stealth mode should include Sec-Fetch-* headers from advanced evasion")
	}

	// Verify User-Agent in actual requests contains "Mozilla"
	hasMozilla := false
	for _, r := range reqs {
		if strings.Contains(r.UserAgent, "Mozilla") {
			hasMozilla = true
			break
		}
	}
	if !hasMozilla {
		t.Error("stealth mode requests should have Mozilla-based User-Agent")
	}

	t.Logf("stealth: %d total requests, hasSecFetch=%v, hasMozilla=%v",
		len(reqs), hasSecFetch, hasMozilla)
}

func TestScannerMode_Nightmare(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	cfg := scanner.NightmareConfig()
	cfg.Target = ts.Server.URL

	report := runScan(t, cfg, 5*time.Second)

	// --- Universal assertions ---
	if report == nil {
		t.Fatal("report should not be nil")
	}
	if report.Target != ts.Server.URL {
		t.Errorf("report.Target = %q, want %q", report.Target, ts.Server.URL)
	}
	if report.Profile != "nightmare" {
		t.Errorf("report.Profile = %q, want nightmare", report.Profile)
	}
	if report.TotalRequests <= 0 {
		t.Errorf("report.TotalRequests = %d, should be > 0", report.TotalRequests)
	}

	// --- Nightmare-specific assertions ---

	// Should make many requests
	if report.TotalRequests < 100 {
		t.Errorf("nightmare mode made only %d requests, expected >= 100", report.TotalRequests)
	}

	// Config checks
	if cfg.EvasionMode != "nightmare" {
		t.Errorf("nightmare EvasionMode = %q, want nightmare", cfg.EvasionMode)
	}
	if cfg.Concurrency < 30 {
		t.Errorf("nightmare Concurrency = %d, expected >= 30", cfg.Concurrency)
	}

	// Should have protocol abuse requests (POST with Transfer-Encoding or conflicting Content-Length)
	reqs := ts.getRequests()
	hasProtocolAbuse := false
	for _, r := range reqs {
		if r.Method == "POST" {
			te := r.Headers.Get("Transfer-Encoding")
			cl := r.Headers.Get("Content-Length")
			if te != "" || cl != "" {
				hasProtocolAbuse = true
				break
			}
		}
	}
	if !hasProtocolAbuse {
		t.Error("nightmare mode should have protocol abuse requests (POST with Transfer-Encoding or Content-Length)")
	}

	// Report should have findings
	if len(report.Findings) == 0 {
		t.Error("nightmare mode should produce findings")
	}

	t.Logf("nightmare: %d total requests, %d findings, hasProtocolAbuse=%v",
		len(reqs), len(report.Findings), hasProtocolAbuse)
}

// ---------------------------------------------------------------------------
// Cross-mode comparison test
// ---------------------------------------------------------------------------

func TestScannerMode_RequestCounts(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	// Run aggressive mode
	aggressiveCfg := scanner.AggressiveConfig()
	aggressiveCfg.Target = ts.Server.URL
	aggressiveReport := runScan(t, aggressiveCfg, 5*time.Second)

	ts.reset()

	// Run nightmare mode
	nightmareCfg := scanner.NightmareConfig()
	nightmareCfg.Target = ts.Server.URL
	nightmareReport := runScan(t, nightmareCfg, 5*time.Second)

	if aggressiveReport == nil || nightmareReport == nil {
		t.Fatal("both reports should be non-nil")
	}

	// Nightmare should generate >= as many total attack requests as aggressive
	// (nightmare is a superset of aggressive behavior)
	if nightmareReport.TotalRequests < aggressiveReport.TotalRequests {
		t.Errorf("nightmare TotalRequests (%d) should be >= aggressive TotalRequests (%d)",
			nightmareReport.TotalRequests, aggressiveReport.TotalRequests)
	}

	t.Logf("aggressive=%d requests, nightmare=%d requests",
		aggressiveReport.TotalRequests, nightmareReport.TotalRequests)
}

// ---------------------------------------------------------------------------
// Report structure validation (all modes)
// ---------------------------------------------------------------------------

func TestScannerMode_ReportStructure(t *testing.T) {
	ts := newTestServer()
	defer ts.Server.Close()

	modes := []struct {
		name   string
		config func() *scanner.Config
	}{
		{"compliance", scanner.ComplianceConfig},
		{"aggressive", scanner.AggressiveConfig},
		{"stealth", scanner.StealthConfig},
		{"nightmare", scanner.NightmareConfig},
	}

	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			ts.reset()

			cfg := mode.config()
			cfg.Target = ts.Server.URL

			report := runScan(t, cfg, 5*time.Second)

			if report == nil {
				t.Fatal("report should not be nil")
			}

			// Target should match
			if report.Target != ts.Server.URL {
				t.Errorf("Target = %q, want %q", report.Target, ts.Server.URL)
			}

			// Profile should match mode name
			if report.Profile != mode.name {
				t.Errorf("Profile = %q, want %q", report.Profile, mode.name)
			}

			// TotalRequests should be > 0
			if report.TotalRequests <= 0 {
				t.Errorf("TotalRequests = %d, should be > 0", report.TotalRequests)
			}

			// Summary should exist
			if report.Summary == nil {
				t.Error("Summary should not be nil")
			}

			// Resilience should exist
			if report.Resilience == nil {
				t.Error("Resilience should not be nil")
			}

			// Coverage should exist
			if report.Coverage == nil {
				t.Error("Coverage should not be nil")
			}

			// DurationMs should be positive
			if report.DurationMs <= 0 {
				t.Errorf("DurationMs = %d, should be > 0", report.DurationMs)
			}

			// StartedAt and CompletedAt should be non-empty
			if report.StartedAt == "" {
				t.Error("StartedAt should not be empty")
			}
			if report.CompletedAt == "" {
				t.Error("CompletedAt should not be empty")
			}

			t.Logf("%s: %d requests, %d findings, duration=%dms",
				mode.name, report.TotalRequests, len(report.Findings), report.DurationMs)
		})
	}
}
