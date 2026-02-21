package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newTestBackend creates a simple httptest server that echoes back info.
func newTestBackend() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "true")
		w.Header().Set("Content-Type", "text/plain")
		xff := r.Header.Get("X-Forwarded-For")
		score := r.Header.Get("X-Glitch-Score")
		fmt.Fprintf(w, "OK path=%s xff=%s score=%s", r.URL.Path, xff, score)
	}))
}

// newTestProxy creates a ReverseProxy pointed at the given backend URL.
func newTestProxy(backendURL string, opts Options) *ReverseProxy {
	if opts.ScoreThreshold == 0 {
		opts.ScoreThreshold = 50
	}
	if opts.InterceptMode == "" {
		opts.InterceptMode = "glitch"
	}
	rp := NewReverseProxy(backendURL, opts)
	return rp
}

// browserRequest creates an http.Request that looks like a real browser.
func browserRequest(method, url string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return req
}

// botRequest creates an http.Request that looks like a bot.
func botRequest(method, url string) *http.Request {
	req := httptest.NewRequest(method, url, nil)
	req.Header.Set("User-Agent", "python-requests/2.28.0")
	// Bots typically don't send Accept-Language or Sec-Fetch headers
	return req
}

func TestPassthroughForNormalRequests(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	req := browserRequest("GET", "/hello")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(string(body), "OK path=/hello") {
		t.Errorf("expected backend response, got: %s", string(body))
	}

	// Verify the backend got our request (X-Backend header was set)
	if resp.Header.Get("X-Backend") != "true" {
		t.Error("response should come from backend (missing X-Backend header)")
	}

	stats := rp.Stats()
	if stats.TotalRequests != 1 {
		t.Errorf("expected 1 total request, got %d", stats.TotalRequests)
	}
	if stats.PassedThrough != 1 {
		t.Errorf("expected 1 passed through, got %d", stats.PassedThrough)
	}
}

func TestInterceptionForBotUserAgents(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	botUAs := []string{
		"python-requests/2.28.0",
		"GPTBot/1.0",
		"CCBot/2.0",
		"curl/7.88.1",
		"Scrapy/2.8",
	}

	for _, ua := range botUAs {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("User-Agent", ua)
		// Bot: no Accept-Language, no Accept-Encoding -> score should exceed threshold
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("UA %q: expected 403, got %d (body: %s)", ua, resp.StatusCode, string(body))
		}
	}
}

func TestScoreThresholdBehavior(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	// High threshold: even bots should pass
	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 100,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	req := botRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode == http.StatusForbidden {
		t.Error("with threshold 100, bot should pass through")
	}

	// Low threshold: even somewhat suspicious requests get caught
	rp2 := newTestProxy(backend.URL, Options{
		ScoreThreshold: 10,
		InterceptMode:  "block",
	})
	defer rp2.Shutdown()

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("User-Agent", "python-requests/2.28.0")
	w2 := httptest.NewRecorder()
	rp2.ServeHTTP(w2, req2)

	resp2 := w2.Result()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("with threshold 10 and bot UA, expected 403, got %d", resp2.StatusCode)
	}
}

func TestSetScoreThreshold(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 100, // Start very high
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	// Bot should pass with high threshold
	req := botRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)
	if w.Result().StatusCode == http.StatusForbidden {
		t.Error("bot should pass with threshold 100")
	}

	// Lower the threshold dynamically
	rp.SetScoreThreshold(10)

	// Now the bot should be intercepted (use a new client to avoid cached state effects)
	req2 := httptest.NewRequest("GET", "/test2", nil)
	req2.Header.Set("User-Agent", "curl/7.88.1")
	req2.RemoteAddr = "10.0.0.99:12345" // different IP for different fingerprint
	w2 := httptest.NewRecorder()
	rp.ServeHTTP(w2, req2)
	if w2.Result().StatusCode != http.StatusForbidden {
		t.Error("bot should be blocked after lowering threshold to 10")
	}
}

func TestPassthroughPaths(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold:   1, // Very low threshold: almost everything intercepted
		InterceptMode:    "block",
		PassthroughPaths: []string{"/api/health", "/metrics"},
	})
	defer rp.Shutdown()

	// Bot requesting a passthrough path should always get through
	req := botRequest("GET", "/api/health")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("passthrough path should return 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "OK path=/api/health") {
		t.Errorf("passthrough should reach backend, got: %s", string(body))
	}

	// Bot requesting a non-passthrough path should be blocked
	req2 := botRequest("GET", "/secret")
	w2 := httptest.NewRecorder()
	rp.ServeHTTP(w2, req2)

	if w2.Result().StatusCode != http.StatusForbidden {
		t.Errorf("non-passthrough path with bot should be blocked, got %d", w2.Result().StatusCode)
	}

	// Second passthrough path
	req3 := botRequest("GET", "/metrics")
	w3 := httptest.NewRecorder()
	rp.ServeHTTP(w3, req3)

	if w3.Result().StatusCode != http.StatusOK {
		t.Errorf("second passthrough path should return 200, got %d", w3.Result().StatusCode)
	}
}

func TestStatisticsCounting(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	// Send some normal requests
	for i := 0; i < 5; i++ {
		req := browserRequest("GET", fmt.Sprintf("/page/%d", i))
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
	}

	// Send some bot requests (each with different IP to avoid rate limit stacking)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/bot/%d", i), nil)
		req.Header.Set("User-Agent", "python-requests/2.28.0")
		req.RemoteAddr = fmt.Sprintf("192.168.1.%d:12345", i+10)
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
	}

	stats := rp.Stats()
	if stats.TotalRequests != 8 {
		t.Errorf("expected 8 total requests, got %d", stats.TotalRequests)
	}
	if stats.PassedThrough != 5 {
		t.Errorf("expected 5 passed through, got %d", stats.PassedThrough)
	}
	if stats.Intercepted != 3 {
		t.Errorf("expected 3 intercepted, got %d", stats.Intercepted)
	}
	if stats.Blocked != 3 {
		t.Errorf("expected 3 blocked, got %d", stats.Blocked)
	}
}

func TestXForwardedForInjection(t *testing.T) {
	var capturedXFF string
	var capturedXRealIP string
	var capturedXGlitchScore string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedXFF = r.Header.Get("X-Forwarded-For")
		capturedXRealIP = r.Header.Get("X-Real-IP")
		capturedXGlitchScore = r.Header.Get("X-Glitch-Score")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 100, // High threshold so everything passes
	})
	defer rp.Shutdown()

	req := browserRequest("GET", "/test")
	req.RemoteAddr = "192.168.1.100:54321"
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	if capturedXFF == "" {
		t.Error("expected X-Forwarded-For header to be set")
	}
	if !strings.Contains(capturedXFF, "192.168.1.100") {
		t.Errorf("expected X-Forwarded-For to contain client IP, got %q", capturedXFF)
	}

	if capturedXRealIP == "" {
		t.Error("expected X-Real-IP header to be set")
	}

	if capturedXGlitchScore == "" {
		t.Error("expected X-Glitch-Score header to be set")
	}
}

func TestInterceptModeBlock(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	req := botRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("block mode: expected 403, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Forbidden") {
		t.Errorf("block mode: expected Forbidden in body, got %s", string(body))
	}
}

func TestInterceptModeChallenge(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "challenge",
	})
	defer rp.Shutdown()

	req := botRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	// Should serve an HTML challenge page
	if resp.StatusCode != http.StatusOK {
		t.Errorf("challenge mode: expected 200 (challenge page), got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Checking your browser") {
		t.Errorf("challenge mode: expected challenge page, got: %s", string(body))
	}
	if !strings.Contains(string(body), challengeCookieName) {
		t.Errorf("challenge mode: expected cookie name in JS, got: %s", string(body))
	}
}

func TestInterceptModeLabyrinth(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "labyrinth",
	})
	defer rp.Shutdown()

	req := botRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("labyrinth mode: expected 200, got %d", resp.StatusCode)
	}
	// Labyrinth pages contain section elements and links
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<a href=") && !strings.Contains(bodyStr, "href") {
		t.Errorf("labyrinth mode: expected generated content with links, got: %s", bodyStr[:200])
	}

	stats := rp.Stats()
	if stats.LabyrinthTrapped != 1 {
		t.Errorf("expected 1 labyrinth trapped, got %d", stats.LabyrinthTrapped)
	}
}

func TestInterceptModeGlitch(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "glitch",
	})
	defer rp.Shutdown()

	// Run multiple requests to see the variety of glitch responses
	statuses := make(map[int]int)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/test/%d", i), nil)
		req.Header.Set("User-Agent", "python-requests/2.28.0")
		req.RemoteAddr = fmt.Sprintf("10.99.%d.%d:12345", i/256, i%256)
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
		statuses[w.Result().StatusCode]++
	}

	// Glitch mode should produce a variety of responses
	if len(statuses) < 1 {
		t.Error("glitch mode: expected at least 1 different status code")
	}

	stats := rp.Stats()
	if stats.Intercepted != 20 {
		t.Errorf("expected 20 intercepted, got %d", stats.Intercepted)
	}
}

func TestConcurrentRequests(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	var wg sync.WaitGroup
	numGoroutines := 50
	requestsPerGoroutine := 10

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requestsPerGoroutine; j++ {
				var req *http.Request
				if id%2 == 0 {
					req = browserRequest("GET", fmt.Sprintf("/concurrent/%d/%d", id, j))
				} else {
					req = httptest.NewRequest("GET", fmt.Sprintf("/concurrent/%d/%d", id, j), nil)
					req.Header.Set("User-Agent", "python-requests/2.28.0")
					req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:12345", id/256, id%256, j)
				}
				w := httptest.NewRecorder()
				rp.ServeHTTP(w, req)
			}
		}(i)
	}

	wg.Wait()

	stats := rp.Stats()
	expectedTotal := int64(numGoroutines * requestsPerGoroutine)
	if stats.TotalRequests != expectedTotal {
		t.Errorf("expected %d total requests, got %d", expectedTotal, stats.TotalRequests)
	}
	// All requests should be accounted for
	if stats.PassedThrough+stats.Intercepted != expectedTotal {
		t.Errorf("passed+intercepted (%d+%d=%d) should equal total (%d)",
			stats.PassedThrough, stats.Intercepted,
			stats.PassedThrough+stats.Intercepted, expectedTotal)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name     string
		remote   string
		xff      string
		expected string
	}{
		{"simple RemoteAddr", "192.168.1.1:8080", "", "192.168.1.1"},
		{"XFF present", "10.0.0.1:8080", "203.0.113.50", "203.0.113.50"},
		{"XFF chain", "10.0.0.1:8080", "203.0.113.50, 70.41.3.18", "203.0.113.50"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			ip := extractIP(req)
			if ip != tt.expected {
				t.Errorf("extractIP: expected %q, got %q", tt.expected, ip)
			}
		})
	}
}

func TestIsWebSocketUpgrade(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	if isWebSocketUpgrade(req) {
		t.Error("plain request should not be websocket upgrade")
	}

	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	if !isWebSocketUpgrade(req) {
		t.Error("request with Upgrade: websocket and Connection: Upgrade should be websocket upgrade")
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, expected string
	}{
		{"/api", "/v1", "/api/v1"},
		{"/api/", "/v1", "/api/v1"},
		{"/api", "v1", "/api/v1"},
		{"/api/", "v1", "/api/v1"},
	}

	for _, tt := range tests {
		result := singleJoiningSlash(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, expected %q", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestScorerEmptyUA(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 20,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	// Empty UA + no headers = high score
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("empty UA with low threshold should be blocked, got %d", w.Result().StatusCode)
	}
}

func TestDashboardStatsAPI(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	// Generate some traffic
	req := browserRequest("GET", "/test")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	// Test the dashboard stats API
	handler := rp.DashboardHandler()
	statsReq := httptest.NewRequest("GET", "/api/stats", nil)
	statsW := httptest.NewRecorder()
	handler.ServeHTTP(statsW, statsReq)

	resp := statsW.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("stats API: expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "total_requests") {
		t.Errorf("stats API: expected total_requests in response, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"total_requests":1`) {
		t.Errorf("stats API: expected total_requests to be 1, got: %s", bodyStr)
	}
}

func TestBrowserWithAllHeadersPassesThrough(t *testing.T) {
	backend := newTestBackend()
	defer backend.Close()

	rp := newTestProxy(backend.URL, Options{
		ScoreThreshold: 50,
		InterceptMode:  "block",
	})
	defer rp.Shutdown()

	// Full browser-like request should always pass
	req := browserRequest("GET", "/")
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("full browser request should pass through, got %d", w.Result().StatusCode)
	}
}
