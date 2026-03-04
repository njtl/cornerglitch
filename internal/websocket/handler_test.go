package websocket

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helper: wrap Handler.ServeHTTP as an http.Handler for httptest usage.
// ---------------------------------------------------------------------------

type handlerAdapter struct {
	h *Handler
}

func (a *handlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.h.ServeHTTP(w, r)
}

// computeAcceptKey computes the expected Sec-WebSocket-Accept value for a
// given client key, following RFC 6455 Section 4.2.2.
func computeAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-5AB53E09BE11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// 1. NewHandler creates a handler
// ---------------------------------------------------------------------------

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.endpoints == nil {
		t.Fatal("NewHandler endpoints map is nil")
	}
}

func TestNewHandlerRegistersAllEndpoints(t *testing.T) {
	h := NewHandler()
	expected := []string{"/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, ep := range expected {
		if _, ok := h.endpoints[ep]; !ok {
			t.Errorf("NewHandler missing endpoint %q", ep)
		}
	}
}

func TestNewHandlerEndpointCount(t *testing.T) {
	h := NewHandler()
	if got := len(h.endpoints); got != 8 {
		t.Errorf("expected 8 endpoints, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldHandle: true for valid WebSocket paths
// ---------------------------------------------------------------------------

func TestShouldHandleValidPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{"/ws/", "/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandleWsWithoutTrailingSlash(t *testing.T) {
	h := NewHandler()
	if !h.ShouldHandle("/ws") {
		t.Error("ShouldHandle(\"/ws\") = false, want true")
	}
}

// ---------------------------------------------------------------------------
// 3. ShouldHandle: false for non-WebSocket paths
// ---------------------------------------------------------------------------

func TestShouldHandleInvalidPaths(t *testing.T) {
	h := NewHandler()
	paths := []string{"/", "/about", "/api/v1/users", "/ws/unknown", "/websocket", "/ws/feed/extra"}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Non-WebSocket GET to /ws/ returns HTML info page (200)
// ---------------------------------------------------------------------------

func TestIndexPageReturns200(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("ServeHTTP returned %d, want %d", code, http.StatusOK)
	}
	if w.Code != http.StatusOK {
		t.Errorf("response code %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIndexPageContentType(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// ---------------------------------------------------------------------------
// 5. Non-WebSocket GET to /ws/feed returns HTML info page (200)
// ---------------------------------------------------------------------------

func TestFeedInfoPageReturns200(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("ServeHTTP returned %d, want %d", code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// 6. Non-WebSocket GET to /ws/ticker returns HTML info page (200)
// ---------------------------------------------------------------------------

func TestTickerInfoPageReturns200(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/ticker", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("ServeHTTP returned %d, want %d", code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// 7. Info pages contain proper content descriptions
// ---------------------------------------------------------------------------

func TestIndexPageContainsEndpointList(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	expected := []string{"/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, ep := range expected {
		if !strings.Contains(body, ep) {
			t.Errorf("index page missing endpoint %q", ep)
		}
	}
}

func TestIndexPageContainsEndpointNames(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	names := []string{"Social Media Feed", "Push Notifications", "Chat Room", "Price Ticker", "Server Metrics"}
	for _, name := range names {
		if !strings.Contains(body, name) {
			t.Errorf("index page missing endpoint name %q", name)
		}
	}
}

func TestFeedInfoPageContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "Social Media Feed") {
		t.Error("feed info page missing title 'Social Media Feed'")
	}
	if !strings.Contains(body, "Real-time social media activity stream") {
		t.Error("feed info page missing description")
	}
}

func TestTickerInfoPageContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/ticker", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "Price Ticker") {
		t.Error("ticker info page missing title 'Price Ticker'")
	}
	if !strings.Contains(body, "Stock and crypto price ticker") {
		t.Error("ticker info page missing description")
	}
}

func TestNotificationsInfoPageContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/notifications", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "Push Notifications") {
		t.Error("notifications info page missing title")
	}
	if !strings.Contains(body, "Push notification stream") {
		t.Error("notifications info page missing description")
	}
}

func TestMetricsInfoPageContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "Server Metrics") {
		t.Error("metrics info page missing title")
	}
	if !strings.Contains(body, "Live server metrics stream") {
		t.Error("metrics info page missing description")
	}
}

// ---------------------------------------------------------------------------
// 8. Non-WebSocket request to /ws/chat returns HTML with chat info
// ---------------------------------------------------------------------------

func TestChatInfoPageContent(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/chat", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("ServeHTTP returned %d, want %d", code, http.StatusOK)
	}
	body := w.Body.String()

	if !strings.Contains(body, "Chat Room") {
		t.Error("chat info page missing title 'Chat Room'")
	}
	if !strings.Contains(body, "Interactive chat room with bot participants") {
		t.Error("chat info page missing description")
	}
}

// ---------------------------------------------------------------------------
// 9. Multiple info pages have different content (feed vs ticker vs chat)
// ---------------------------------------------------------------------------

func TestInfoPagesAreDifferent(t *testing.T) {
	h := NewHandler()

	getBody := func(path string) string {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Body.String()
	}

	feed := getBody("/ws/feed")
	ticker := getBody("/ws/ticker")
	chat := getBody("/ws/chat")

	if feed == ticker {
		t.Error("feed and ticker info pages are identical")
	}
	if feed == chat {
		t.Error("feed and chat info pages are identical")
	}
	if ticker == chat {
		t.Error("ticker and chat info pages are identical")
	}
}

// ---------------------------------------------------------------------------
// 10. Info pages contain JavaScript example code
// ---------------------------------------------------------------------------

func TestIndexPageContainsJSExample(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "new WebSocket") {
		t.Error("index page missing WebSocket JS example")
	}
	if !strings.Contains(body, "ws.onmessage") {
		t.Error("index page missing onmessage handler in JS example")
	}
}

func TestEndpointInfoPagesContainJSExample(t *testing.T) {
	h := NewHandler()
	paths := []string{"/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body := w.Body.String()

		if !strings.Contains(body, "new WebSocket") {
			t.Errorf("info page %s missing WebSocket JS example", p)
		}
		if !strings.Contains(body, "ws.onopen") {
			t.Errorf("info page %s missing onopen handler in JS example", p)
		}
		if !strings.Contains(body, "ws.onclose") {
			t.Errorf("info page %s missing onclose handler in JS example", p)
		}
	}
}

func TestEndpointInfoPagesContainMessageFormatExample(t *testing.T) {
	h := NewHandler()
	cases := []struct {
		path     string
		contains string
	}{
		{"/ws/feed", `"type":"post"`},
		{"/ws/notifications", `"type":"notification"`},
		{"/ws/chat", `"type":"system"`},
		{"/ws/ticker", `"type":"tick"`},
		{"/ws/metrics", `"type":"metrics"`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body := w.Body.String()
		if !strings.Contains(body, tc.contains) {
			t.Errorf("info page %s missing message example containing %q", tc.path, tc.contains)
		}
	}
}

// ---------------------------------------------------------------------------
// 11. WebSocket upgrade: proper headers get 101 via raw connection
// ---------------------------------------------------------------------------

func TestWebSocketUpgradeReturns101(t *testing.T) {
	h := NewHandler()
	adapter := &handlerAdapter{h: h}
	srv := httptest.NewServer(adapter)
	defer srv.Close()

	// Dial the server directly.
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	clientKey := "dGhlIHNhbXBsZSBub25jZQ=="
	reqStr := "GET /ws/feed HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + clientKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("write request failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line failed: %v", err)
	}

	if !strings.Contains(statusLine, "101") {
		t.Errorf("expected 101 in status line, got: %q", strings.TrimSpace(statusLine))
	}

	// Read remaining headers to find Sec-WebSocket-Accept.
	var acceptValue string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header failed: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Sec-WebSocket-Accept:") {
			acceptValue = strings.TrimSpace(strings.TrimPrefix(line, "Sec-WebSocket-Accept:"))
		}
	}

	expectedAccept := computeAcceptKey(clientKey)
	if acceptValue != expectedAccept {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", acceptValue, expectedAccept)
	}
}

// ---------------------------------------------------------------------------
// 12. Request without Upgrade header gets HTML info page instead
// ---------------------------------------------------------------------------

func TestNoUpgradeHeaderGetsInfoPage(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	// No Upgrade/Connection headers set.
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("expected 200 for non-upgrade request, got %d", code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<html") {
		t.Error("expected HTML response for non-upgrade request")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: WebSocket accept key computation
// ---------------------------------------------------------------------------

func TestComputeAcceptKeyKnownVector(t *testing.T) {
	// Verified with Python hashlib: SHA-1(key + GUID) base64-encoded.
	// key = "dGhlIHNhbXBsZSBub25jZQ==" (a common test nonce)
	clientKey := "dGhlIHNhbXBsZSBub25jZQ=="
	expected := "8haHJUsdD+p0KCPAk25IMBaafok="
	got := computeAcceptKey(clientKey)
	if got != expected {
		t.Errorf("computeAcceptKey(%q) = %q, want %q", clientKey, got, expected)
	}
}

func TestComputeAcceptKeyMatchesServerHandshake(t *testing.T) {
	// Verify our helper matches what the actual server produces during upgrade.
	h := NewHandler()
	adapter := &handlerAdapter{h: h}
	srv := httptest.NewServer(adapter)
	defer srv.Close()

	clientKey := "x3JJHMbDL1EzLkh9GBhXDw=="

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	reqStr := "GET /ws/feed HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + clientKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("write request failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	var serverAccept string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header failed: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Sec-WebSocket-Accept:") {
			serverAccept = strings.TrimSpace(strings.TrimPrefix(line, "Sec-WebSocket-Accept:"))
		}
	}

	helperAccept := computeAcceptKey(clientKey)
	if serverAccept != helperAccept {
		t.Errorf("server produced %q but helper computed %q", serverAccept, helperAccept)
	}
}

// ---------------------------------------------------------------------------
// Additional tests: unknown endpoint returns 404
// ---------------------------------------------------------------------------

func TestUnknownEndpointReturns404(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/nonexistent", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown endpoint, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// Additional tests: isWebSocketUpgrade logic
// ---------------------------------------------------------------------------

func TestIsWebSocketUpgradeWithProperHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should return true with proper headers")
	}
}

func TestIsWebSocketUpgradeWithMixedCase(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "WebSocket")
	if !isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should be case-insensitive")
	}
}

func TestIsWebSocketUpgradeMultiValueConnection(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Connection", "keep-alive, Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should handle comma-separated Connection values")
	}
}

func TestIsWebSocketUpgradeMissingUpgradeHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Connection", "Upgrade")
	// No Upgrade header.
	if isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should return false without Upgrade header")
	}
}

func TestIsWebSocketUpgradeMissingConnectionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Upgrade", "websocket")
	// No Connection header.
	if isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should return false without Connection header")
	}
}

func TestIsWebSocketUpgradeWrongUpgradeValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	if isWebSocketUpgrade(req) {
		t.Error("isWebSocketUpgrade should return false when Upgrade is not 'websocket'")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: headerContains
// ---------------------------------------------------------------------------

func TestHeaderContainsSingleValue(t *testing.T) {
	if !headerContains("Upgrade", "upgrade") {
		t.Error("headerContains should match case-insensitively")
	}
}

func TestHeaderContainsMultipleValues(t *testing.T) {
	if !headerContains("keep-alive, Upgrade", "upgrade") {
		t.Error("headerContains should find token in comma-separated list")
	}
}

func TestHeaderContainsNotPresent(t *testing.T) {
	if headerContains("keep-alive, close", "upgrade") {
		t.Error("headerContains should return false when token is absent")
	}
}

func TestHeaderContainsEmpty(t *testing.T) {
	if headerContains("", "upgrade") {
		t.Error("headerContains should return false for empty header")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: sanitize
// ---------------------------------------------------------------------------

func TestSanitizeEscapesQuotes(t *testing.T) {
	input := `He said "hello"`
	got := sanitize(input)
	if !strings.Contains(got, `\"hello\"`) {
		t.Errorf("sanitize(%q) = %q, expected escaped quotes", input, got)
	}
}

func TestSanitizeEscapesBackslash(t *testing.T) {
	input := `path\to\file`
	got := sanitize(input)
	if !strings.Contains(got, `path\\to\\file`) {
		t.Errorf("sanitize(%q) = %q, expected escaped backslashes", input, got)
	}
}

func TestSanitizeEscapesNewlines(t *testing.T) {
	input := "line1\nline2\rline3\ttab"
	got := sanitize(input)
	if strings.Contains(got, "\n") || strings.Contains(got, "\r") || strings.Contains(got, "\t") {
		t.Errorf("sanitize did not escape control characters: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Additional tests: pathSeed determinism
// ---------------------------------------------------------------------------

func TestPathSeedDeterministic(t *testing.T) {
	s1 := pathSeed("/ws/feed")
	s2 := pathSeed("/ws/feed")
	if s1 != s2 {
		t.Errorf("pathSeed is not deterministic: %d != %d", s1, s2)
	}
}

func TestPathSeedDifferentPaths(t *testing.T) {
	s1 := pathSeed("/ws/feed")
	s2 := pathSeed("/ws/ticker")
	if s1 == s2 {
		t.Error("pathSeed returned same value for different paths")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: WebSocket upgrade with raw connection for multiple endpoints
// ---------------------------------------------------------------------------

func TestWebSocketUpgradeContainsUpgradeHeaders(t *testing.T) {
	h := NewHandler()
	adapter := &handlerAdapter{h: h}
	srv := httptest.NewServer(adapter)
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	clientKey := "dGhlIHNhbXBsZSBub25jZQ=="
	reqStr := "GET /ws/ticker HTTP/1.1\r\n" +
		"Host: " + strings.TrimPrefix(srv.URL, "http://") + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + clientKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(reqStr))
	if err != nil {
		t.Fatalf("write request failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	var foundUpgrade, foundConnection bool
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header failed: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.EqualFold(line, "Upgrade: websocket") {
			foundUpgrade = true
		}
		if strings.EqualFold(line, "Connection: Upgrade") {
			foundConnection = true
		}
	}

	if !foundUpgrade {
		t.Error("101 response missing 'Upgrade: websocket' header")
	}
	if !foundConnection {
		t.Error("101 response missing 'Connection: Upgrade' header")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: Index page structure
// ---------------------------------------------------------------------------

func TestIndexPageHasTitle(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "<title>") {
		t.Error("index page missing <title> tag")
	}
	if !strings.Contains(body, "WebSocket Endpoints") {
		t.Error("index page missing 'WebSocket Endpoints' in content")
	}
}

func TestIndexPageHasTableStructure(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := w.Body.String()

	if !strings.Contains(body, "<table") {
		t.Error("index page missing <table> element")
	}
	if !strings.Contains(body, "<thead>") {
		t.Error("index page missing <thead> element")
	}
	if !strings.Contains(body, "Path") && !strings.Contains(body, "Name") {
		t.Error("index page missing table header labels")
	}
}

// ---------------------------------------------------------------------------
// Additional tests: Endpoint info page links back to index
// ---------------------------------------------------------------------------

func TestEndpointInfoPagesLinkBackToIndex(t *testing.T) {
	h := NewHandler()
	paths := []string{"/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body := w.Body.String()

		if !strings.Contains(body, `href="/ws/"`) {
			t.Errorf("info page %s missing back link to /ws/", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional tests: Endpoint info pages mention inactivity timeout
// ---------------------------------------------------------------------------

func TestEndpointInfoPagesMentionTimeout(t *testing.T) {
	h := NewHandler()
	paths := []string{"/ws/feed", "/ws/notifications", "/ws/chat", "/ws/ticker", "/ws/metrics"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		body := w.Body.String()

		if !strings.Contains(body, "5 minutes") {
			t.Errorf("info page %s missing inactivity timeout mention", p)
		}
	}
}

// ---------------------------------------------------------------------------
// Additional tests: /ws without trailing slash
// ---------------------------------------------------------------------------

func TestWsWithoutTrailingSlashReturnsIndex(t *testing.T) {
	h := NewHandler()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	w := httptest.NewRecorder()
	code := h.ServeHTTP(w, req)
	if code != http.StatusOK {
		t.Errorf("expected 200 for /ws, got %d", code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "WebSocket Endpoints") {
		t.Error("/ws should serve the same index page as /ws/")
	}
}
