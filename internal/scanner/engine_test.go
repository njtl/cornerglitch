package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock attack module used by engine tests
// ---------------------------------------------------------------------------

type mockModule struct {
	name     string
	category string
	requests []AttackRequest
}

func (m *mockModule) Name() string     { return m.name }
func (m *mockModule) Category() string { return m.category }
func (m *mockModule) GenerateRequests(target string) []AttackRequest {
	return m.requests
}

// ---------------------------------------------------------------------------
// TestNewEngine
// ---------------------------------------------------------------------------

func TestNewEngine(t *testing.T) {
	t.Run("nil_config_uses_defaults", func(t *testing.T) {
		e := NewEngine(nil)
		if e == nil {
			t.Fatal("NewEngine(nil) returned nil")
		}
		if e.config == nil {
			t.Fatal("engine.config is nil")
		}
		if e.config.Concurrency != 10 {
			t.Errorf("expected default concurrency 10, got %d", e.config.Concurrency)
		}
		if e.config.RateLimit != 100 {
			t.Errorf("expected default rate limit 100, got %d", e.config.RateLimit)
		}
	})

	t.Run("custom_config", func(t *testing.T) {
		cfg := &Config{
			Target:      "http://localhost:9999",
			Concurrency: 5,
			RateLimit:   50,
			Timeout:     5 * time.Second,
		}
		e := NewEngine(cfg)
		if e.config.Target != "http://localhost:9999" {
			t.Errorf("expected target http://localhost:9999, got %s", e.config.Target)
		}
		if e.config.Concurrency != 5 {
			t.Errorf("expected concurrency 5, got %d", e.config.Concurrency)
		}
	})

	t.Run("with_proxy_url", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.ProxyURL = "http://proxy.local:8080"
		e := NewEngine(cfg)
		if e == nil {
			t.Fatal("NewEngine with proxy URL returned nil")
		}
	})

	t.Run("reporter_initialized", func(t *testing.T) {
		e := NewEngine(nil)
		if e.reporter == nil {
			t.Fatal("engine.reporter is nil")
		}
	})

	t.Run("modules_empty_initially", func(t *testing.T) {
		e := NewEngine(nil)
		if len(e.modules) != 0 {
			t.Errorf("expected 0 modules, got %d", len(e.modules))
		}
	})
}

// ---------------------------------------------------------------------------
// TestEngine_RegisterModule
// ---------------------------------------------------------------------------

func TestEngine_RegisterModule(t *testing.T) {
	e := NewEngine(nil)

	mod1 := &mockModule{name: "alpha", category: "cat1"}
	mod2 := &mockModule{name: "beta", category: "cat2"}

	e.RegisterModule(mod1)
	if len(e.modules) != 1 {
		t.Fatalf("expected 1 module, got %d", len(e.modules))
	}
	if e.modules[0].Name() != "alpha" {
		t.Errorf("expected module name 'alpha', got %q", e.modules[0].Name())
	}

	e.RegisterModule(mod2)
	if len(e.modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(e.modules))
	}
	if e.modules[1].Name() != "beta" {
		t.Errorf("expected module name 'beta', got %q", e.modules[1].Name())
	}
}

// ---------------------------------------------------------------------------
// TestEngine_Progress
// ---------------------------------------------------------------------------

func TestEngine_Progress(t *testing.T) {
	e := NewEngine(nil)

	completed, total, findings := e.Progress()
	if completed != 0 || total != 0 || findings != 0 {
		t.Errorf("expected all zeros, got completed=%d total=%d findings=%d",
			completed, total, findings)
	}

	// Manually set atomic values to verify Progress reads them.
	e.completed.Store(5)
	e.total.Store(10)
	e.found.Store(3)

	completed, total, findings = e.Progress()
	if completed != 5 {
		t.Errorf("expected completed=5, got %d", completed)
	}
	if total != 10 {
		t.Errorf("expected total=10, got %d", total)
	}
	if findings != 3 {
		t.Errorf("expected findings=3, got %d", findings)
	}
}

// ---------------------------------------------------------------------------
// TestEngine_Run
// ---------------------------------------------------------------------------

func TestEngine_Run(t *testing.T) {
	// Create a test HTTP server that returns 200 with a body.
	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Hello</body></html>")
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 2
	cfg.RateLimit = 1000 // high rate to finish quickly
	cfg.Timeout = 5 * time.Second

	e := NewEngine(cfg)

	// Register a module that generates a few requests.
	mod := &mockModule{
		name:     "test-mod",
		category: "test",
		requests: []AttackRequest{
			{Method: "GET", Path: "/path1", Category: "test", Description: "test req 1"},
			{Method: "GET", Path: "/path2", Category: "test", Description: "test req 2"},
			{Method: "POST", Path: "/path3", Body: "data=1", BodyType: "application/x-www-form-urlencoded", Category: "test", Description: "test req 3"},
		},
	}
	e.RegisterModule(mod)

	ctx := context.Background()
	report, err := e.Run(ctx)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if report == nil {
		t.Fatal("report is nil")
	}
	if report.TotalRequests != 3 {
		t.Errorf("expected 3 total requests in report, got %d", report.TotalRequests)
	}
	if report.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, report.Target)
	}
	if requestCount.Load() != 3 {
		t.Errorf("expected backend to receive 3 requests, got %d", requestCount.Load())
	}

	// Verify progress reflects completion.
	completed, total, _ := e.Progress()
	if completed != 3 {
		t.Errorf("expected completed=3, got %d", completed)
	}
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
}

func TestEngine_Run_NoModules(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	e := NewEngine(cfg)

	report, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.TotalRequests != 0 {
		t.Errorf("expected 0 total requests, got %d", report.TotalRequests)
	}
}

func TestEngine_Run_AlreadyRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // slow handler to keep the scan running
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 1
	cfg.RateLimit = 1000
	e := NewEngine(cfg)

	mod := &mockModule{
		name:     "slow",
		category: "test",
		requests: []AttackRequest{
			{Method: "GET", Path: "/slow1", Category: "test", Description: "slow req"},
			{Method: "GET", Path: "/slow2", Category: "test", Description: "slow req"},
			{Method: "GET", Path: "/slow3", Category: "test", Description: "slow req"},
		},
	}
	e.RegisterModule(mod)

	// Start the first run in background.
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(context.Background())
	}()

	// Give it a moment to start.
	time.Sleep(50 * time.Millisecond)

	// Second Run should fail because already running.
	_, err := e.Run(context.Background())
	if err == nil {
		t.Error("expected error when running scan twice concurrently")
	}

	// Wait for first run to finish.
	<-done
}

// ---------------------------------------------------------------------------
// TestEngine_Stop
// ---------------------------------------------------------------------------

func TestEngine_Stop(t *testing.T) {
	// Server that sleeps long enough that we can cancel.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 1
	cfg.RateLimit = 1000
	cfg.Timeout = 5 * time.Second

	e := NewEngine(cfg)

	// Generate many requests to keep the scan busy.
	var reqs []AttackRequest
	for i := 0; i < 50; i++ {
		reqs = append(reqs, AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("/stop-test/%d", i),
			Category:    "test",
			Description: "stop test",
		})
	}
	e.RegisterModule(&mockModule{name: "many", category: "test", requests: reqs})

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(context.Background())
	}()

	// Give it a moment to start, then stop.
	time.Sleep(100 * time.Millisecond)
	e.Stop()

	// Should finish quickly after Stop.
	select {
	case <-done:
		// Good: scan stopped.
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not stop within 5 seconds")
	}

	// After stopping, completed should be less than total.
	completed, total, _ := e.Progress()
	if total != 50 {
		t.Errorf("expected total=50, got %d", total)
	}
	if completed >= 50 {
		t.Errorf("expected completed < 50 after stop, got %d", completed)
	}
}

// ---------------------------------------------------------------------------
// TestEngine_RateLimit
// ---------------------------------------------------------------------------

func TestEngine_RateLimit(t *testing.T) {
	var requestCount atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 5
	cfg.RateLimit = 20 // 20 requests per second
	cfg.Timeout = 5 * time.Second

	e := NewEngine(cfg)

	// Generate exactly 20 requests. At 20 rps, should take ~1 second.
	var reqs []AttackRequest
	for i := 0; i < 20; i++ {
		reqs = append(reqs, AttackRequest{
			Method:      "GET",
			Path:        fmt.Sprintf("/rate/%d", i),
			Category:    "test",
			Description: "rate test",
		})
	}
	e.RegisterModule(&mockModule{name: "rate", category: "test", requests: reqs})

	start := time.Now()
	report, err := e.Run(context.Background())
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if report.TotalRequests != 20 {
		t.Errorf("expected 20 total requests, got %d", report.TotalRequests)
	}

	// With 20 rps, 20 requests should take at least ~900ms (allowing some tolerance).
	if elapsed < 800*time.Millisecond {
		t.Errorf("expected scan to take at least 800ms at 20 rps, took %s", elapsed)
	}
	// But shouldn't take more than 5s (generous upper bound).
	if elapsed > 5*time.Second {
		t.Errorf("expected scan to finish within 5s, took %s", elapsed)
	}
}

// ---------------------------------------------------------------------------
// TestEngine_EnabledModules
// ---------------------------------------------------------------------------

func TestEngine_EnabledModules(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 2
	cfg.RateLimit = 1000
	cfg.EnabledModules = []string{"alpha"} // Only enable alpha

	e := NewEngine(cfg)

	e.RegisterModule(&mockModule{
		name:     "alpha",
		category: "cat-a",
		requests: []AttackRequest{
			{Method: "GET", Path: "/alpha", Category: "cat-a", Description: "alpha req"},
		},
	})
	e.RegisterModule(&mockModule{
		name:     "beta",
		category: "cat-b",
		requests: []AttackRequest{
			{Method: "GET", Path: "/beta", Category: "cat-b", Description: "beta req"},
		},
	})

	report, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// Only alpha's request should have been executed.
	if report.TotalRequests != 1 {
		t.Errorf("expected 1 request (alpha only), got %d", report.TotalRequests)
	}
}

// ---------------------------------------------------------------------------
// TestEngine_FindingsDetection
// ---------------------------------------------------------------------------

func TestEngine_FindingsDetection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(http.StatusOK)
		// Return body with SQL error to trigger finding detection.
		fmt.Fprint(w, "Error: mysql_fetch_array(): you have an error in your SQL syntax")
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.Target = ts.URL
	cfg.Concurrency = 1
	cfg.RateLimit = 1000

	e := NewEngine(cfg)
	e.RegisterModule(&mockModule{
		name:     "sqli",
		category: "sql-injection",
		requests: []AttackRequest{
			{Method: "GET", Path: "/inject", Category: "sql-injection", Description: "sqli test"},
		},
	})

	report, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(report.Findings) == 0 {
		t.Error("expected at least one finding from SQL error in response")
	}

	foundSQL := false
	for _, f := range report.Findings {
		if f.Category == "sql-injection" {
			foundSQL = true
			break
		}
	}
	if !foundSQL {
		t.Error("expected to find sql-injection finding")
	}
}
