package analytics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// 1. NewEngine creates an engine
// ---------------------------------------------------------------------------

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
}

func TestNewEngineBufferSizes(t *testing.T) {
	e := NewEngine()
	if e.bufferSize != 1000 {
		t.Errorf("expected beacon buffer size 1000, got %d", e.bufferSize)
	}
	if e.eventSize != 500 {
		t.Errorf("expected event buffer size 500, got %d", e.eventSize)
	}
}

func TestNewEngineSlicesAllocated(t *testing.T) {
	e := NewEngine()
	if len(e.beacons) != 1000 {
		t.Errorf("expected beacons slice length 1000, got %d", len(e.beacons))
	}
	if len(e.events) != 500 {
		t.Errorf("expected events slice length 500, got %d", len(e.events))
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldHandle: true for known analytics paths
// ---------------------------------------------------------------------------

func TestShouldHandleTruePaths(t *testing.T) {
	e := NewEngine()
	truePaths := []string{"/collect", "/tr", "/events", "/analytics/beacon", "/analytics/config"}
	for _, p := range truePaths {
		if !e.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. ShouldHandle: false for non-analytics paths
// ---------------------------------------------------------------------------

func TestShouldHandleFalsePaths(t *testing.T) {
	e := NewEngine()
	falsePaths := []string{"/", "/about", "/api/v1/users", "/favicon.ico", "/index.html", "/collect/extra"}
	for _, p := range falsePaths {
		if e.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. /collect GET - returns 1x1 GIF with proper content-type
// ---------------------------------------------------------------------------

func TestCollectGETReturnsGIF(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/collect?v=1&tid=UA-000000-1&t=pageview", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "image/gif" {
		t.Errorf("expected Content-Type image/gif, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != len(transparentGIF) {
		t.Errorf("expected GIF body length %d, got %d", len(transparentGIF), len(body))
	}
}

func TestCollectGETNoCacheHeaders(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/collect", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	resp := w.Result()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache, no-store, must-revalidate" {
		t.Errorf("unexpected Cache-Control: %q", cc)
	}
	if pragma := resp.Header.Get("Pragma"); pragma != "no-cache" {
		t.Errorf("unexpected Pragma: %q", pragma)
	}
	if exp := resp.Header.Get("Expires"); exp != "0" {
		t.Errorf("unexpected Expires: %q", exp)
	}
}

func TestCollectGETRecordsQueryParams(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/collect?v=1&tid=UA-000000-1&cid=abc&t=pageview&dp=/home", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	b := beacons[0]
	if b.Endpoint != "/collect" {
		t.Errorf("expected endpoint /collect, got %q", b.Endpoint)
	}
	if b.Params["tid"] != "UA-000000-1" {
		t.Errorf("expected tid=UA-000000-1, got %q", b.Params["tid"])
	}
	if b.Params["dp"] != "/home" {
		t.Errorf("expected dp=/home, got %q", b.Params["dp"])
	}
}

// ---------------------------------------------------------------------------
// 5. /collect POST - records beacon with body and returns GIF
// ---------------------------------------------------------------------------

func TestCollectPOSTRecordsBeaconAndReturnsGIF(t *testing.T) {
	e := NewEngine()
	bodyContent := "v=1&tid=UA-000000-1&t=event&ec=video&ea=play"
	req := httptest.NewRequest(http.MethodPost, "/collect?v=1&tid=UA-000000-1", strings.NewReader(bodyContent))
	req.Header.Set("User-Agent", "TestBot/1.0")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}

	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "image/gif" {
		t.Errorf("expected Content-Type image/gif, got %q", ct)
	}
	gifBody, _ := io.ReadAll(resp.Body)
	if len(gifBody) != len(transparentGIF) {
		t.Errorf("expected GIF body length %d, got %d", len(transparentGIF), len(gifBody))
	}

	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	if beacons[0].Body != bodyContent {
		t.Errorf("expected body %q, got %q", bodyContent, beacons[0].Body)
	}
	if beacons[0].UserAgent != "TestBot/1.0" {
		t.Errorf("expected User-Agent TestBot/1.0, got %q", beacons[0].UserAgent)
	}
}

// ---------------------------------------------------------------------------
// 6. /tr GET - returns 1x1 GIF
// ---------------------------------------------------------------------------

func TestTrackingPixelGETReturnsGIF(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/tr?id=000000000000000&ev=PageView&noscript=1", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "image/gif" {
		t.Errorf("expected Content-Type image/gif, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != len(transparentGIF) {
		t.Errorf("expected GIF body length %d, got %d", len(transparentGIF), len(body))
	}
}

func TestTrackingPixelRecordsParams(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/tr?id=123&ev=PageView", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	b := beacons[0]
	if b.Endpoint != "/tr" {
		t.Errorf("expected endpoint /tr, got %q", b.Endpoint)
	}
	if b.Params["id"] != "123" {
		t.Errorf("expected param id=123, got %q", b.Params["id"])
	}
	if b.Params["ev"] != "PageView" {
		t.Errorf("expected param ev=PageView, got %q", b.Params["ev"])
	}
}

// ---------------------------------------------------------------------------
// 7. /events POST - accepts JSON, returns acknowledgment
// ---------------------------------------------------------------------------

func TestEventsPOSTAcceptsJSON(t *testing.T) {
	e := NewEngine()
	eventJSON := `{"event":"link_click","target":"https://example.com","page":"/home","timestamp":1700000000}`
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(eventJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %q", result["status"])
	}
	if result["message"] != "event recorded" {
		t.Errorf("expected message 'event recorded', got %q", result["message"])
	}
}

func TestEventsPOSTRecordsEventAndBeacon(t *testing.T) {
	e := NewEngine()
	eventJSON := `{"event":"scroll_depth","target":"75%","page":"/article","timestamp":1700000000}`
	req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(eventJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	// Check beacon
	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	if beacons[0].Endpoint != "/events" {
		t.Errorf("expected endpoint /events, got %q", beacons[0].Endpoint)
	}
	if !strings.Contains(beacons[0].Body, "scroll_depth") {
		t.Error("expected beacon body to contain 'scroll_depth'")
	}

	// Check event record
	events := e.getRecentEvents(1)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Event != "scroll_depth" {
		t.Errorf("expected event scroll_depth, got %q", events[0].Event)
	}
	if events[0].Target != "75%" {
		t.Errorf("expected target 75%%, got %q", events[0].Target)
	}
}

func TestEventsPOSTEmptyBody(t *testing.T) {
	e := NewEngine()
	// httptest.NewRequest with nil body sets r.Body to http.NoBody (not nil),
	// so the handler reads zero bytes and still succeeds. Verify it returns 200.
	req := httptest.NewRequest(http.MethodPost, "/events", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	// With http.NoBody, r.Body is non-nil so the handler reads an empty body
	// and returns 200 with a success acknowledgment.
	if status != http.StatusOK {
		t.Errorf("expected status 200 (http.NoBody is non-nil), got %d", status)
	}
}

func TestEventsPOSTNilBodyDirect(t *testing.T) {
	// Directly test handleEvents by crafting a request with r.Body explicitly nil.
	e := NewEngine()
	req := httptest.NewRequest(http.MethodPost, "/events", nil)
	req.Body = nil // explicitly set to nil
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusBadRequest {
		t.Errorf("expected status 400 for nil body, got %d", status)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if !strings.Contains(string(body), "empty body") {
		t.Error("expected error message about empty body")
	}
}

// ---------------------------------------------------------------------------
// 8. /events GET - returns recent events as JSON
// ---------------------------------------------------------------------------

func TestEventsGETReturnsRecentEvents(t *testing.T) {
	e := NewEngine()

	// Insert some events via POST first
	for i := 0; i < 3; i++ {
		eventJSON := `{"event":"page_view","target":"","page":"/page","timestamp":1700000000}`
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(eventJSON))
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
	}

	// GET events
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	w := httptest.NewRecorder()
	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	count, ok := result["count"].(float64)
	if !ok {
		t.Fatal("expected count field in response")
	}
	if int(count) != 3 {
		t.Errorf("expected 3 events, got %d", int(count))
	}
	events, ok := result["events"].([]interface{})
	if !ok {
		t.Fatal("expected events array in response")
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events in array, got %d", len(events))
	}
}

func TestEventsGETEmptyReturnsEmptyArray(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	count := int(result["count"].(float64))
	if count != 0 {
		t.Errorf("expected 0 events, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// 9. /analytics/beacon POST - returns 204 No Content
// ---------------------------------------------------------------------------

func TestBeaconPOSTReturns204(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodPost, "/analytics/beacon", strings.NewReader(`{"action":"pageview"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", status)
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("expected response code 204, got %d", w.Code)
	}
}

func TestBeaconPOSTRecordsBeacon(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodPost, "/analytics/beacon?cid=test123", strings.NewReader(`{"action":"click"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	b := beacons[0]
	if b.Endpoint != "/analytics/beacon" {
		t.Errorf("expected endpoint /analytics/beacon, got %q", b.Endpoint)
	}
	if b.Params["cid"] != "test123" {
		t.Errorf("expected param cid=test123, got %q", b.Params["cid"])
	}
	if !strings.Contains(b.Body, "click") {
		t.Error("expected body to contain 'click'")
	}
}

// ---------------------------------------------------------------------------
// 10. /analytics/config GET - returns JSON with tracking IDs
// ---------------------------------------------------------------------------

func TestConfigGETReturnsJSON(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/analytics/config", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestConfigContainsTrackingIDs(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/analytics/config", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	var config map[string]interface{}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	trackingIDs, ok := config["tracking_ids"].(map[string]interface{})
	if !ok {
		t.Fatal("expected tracking_ids object in config")
	}

	expectedIDs := map[string]string{
		"google_analytics_4": "G-GL1TCH0001",
		"google_analytics":   "UA-000000-1",
		"google_tag_manager": "GTM-GL1TCH",
		"facebook_pixel":     "000000000000000",
		"segment_write_key":  "gl1tch_fake_segment_write_key",
	}
	for key, expected := range expectedIDs {
		got, ok := trackingIDs[key].(string)
		if !ok {
			t.Errorf("missing tracking_ids key %q", key)
			continue
		}
		if got != expected {
			t.Errorf("tracking_ids[%q] = %q, want %q", key, got, expected)
		}
	}
}

func TestConfigContainsEndpoints(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/analytics/config", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	var config map[string]interface{}
	json.Unmarshal(body, &config)

	endpoints, ok := config["endpoints"].(map[string]interface{})
	if !ok {
		t.Fatal("expected endpoints object in config")
	}
	expectedEndpoints := map[string]string{
		"collect": "/collect",
		"pixel":   "/tr",
		"events":  "/events",
		"beacon":  "/analytics/beacon",
		"config":  "/analytics/config",
	}
	for key, expected := range expectedEndpoints {
		got, ok := endpoints[key].(string)
		if !ok {
			t.Errorf("missing endpoints key %q", key)
			continue
		}
		if got != expected {
			t.Errorf("endpoints[%q] = %q, want %q", key, got, expected)
		}
	}
}

func TestConfigCacheHeader(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/analytics/config", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	if cc := w.Result().Header.Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("unexpected Cache-Control: %q", cc)
	}
}

// ---------------------------------------------------------------------------
// 11. Snippet(pageURL) - contains Google Analytics, Facebook Pixel, GTM, Hotjar, Segment
// ---------------------------------------------------------------------------

func TestSnippetContainsGoogleAnalytics(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/test-page")

	if !strings.Contains(snippet, "G-GL1TCH0001") {
		t.Error("snippet missing Google Analytics 4 tracking ID")
	}
	if !strings.Contains(snippet, "UA-000000-1") {
		t.Error("snippet missing Universal Analytics tracking ID")
	}
	if !strings.Contains(snippet, "googletagmanager.com/gtag/js") {
		t.Error("snippet missing gtag.js script reference")
	}
	if !strings.Contains(snippet, "gtag('config'") {
		t.Error("snippet missing gtag config call")
	}
}

func TestSnippetContainsFacebookPixel(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/test-page")

	if !strings.Contains(snippet, "fbevents.js") {
		t.Error("snippet missing Facebook Pixel fbevents.js")
	}
	if !strings.Contains(snippet, "fbq('init'") {
		t.Error("snippet missing fbq init call")
	}
	if !strings.Contains(snippet, "fbq('track', 'PageView')") {
		t.Error("snippet missing fbq PageView track call")
	}
	if !strings.Contains(snippet, "000000000000000") {
		t.Error("snippet missing Facebook Pixel ID")
	}
}

func TestSnippetContainsGTM(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/test-page")

	if !strings.Contains(snippet, "GTM-GL1TCH") {
		t.Error("snippet missing GTM container ID")
	}
	if !strings.Contains(snippet, "googletagmanager.com/gtm.js") {
		t.Error("snippet missing GTM script reference")
	}
}

func TestSnippetContainsHotjar(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/test-page")

	if !strings.Contains(snippet, "hotjar.com") {
		t.Error("snippet missing Hotjar script reference")
	}
	if !strings.Contains(snippet, "hj(") {
		t.Error("snippet missing hj function call")
	}
}

func TestSnippetContainsSegment(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/test-page")

	if !strings.Contains(snippet, "segment.com") {
		t.Error("snippet missing Segment CDN reference")
	}
	if !strings.Contains(snippet, "gl1tch_fake_segment_write_key") {
		t.Error("snippet missing Segment write key")
	}
	if !strings.Contains(snippet, "analytics.page(") {
		t.Error("snippet missing analytics.page call")
	}
}

func TestSnippetEmbeddsPageURL(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/my/page")

	if !strings.Contains(snippet, "/my/page") {
		t.Error("snippet should contain the pageURL")
	}
}

// ---------------------------------------------------------------------------
// 12. Snippet escapes special characters in pageURL
// ---------------------------------------------------------------------------

func TestSnippetEscapesSingleQuotes(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page?name=it's")

	if strings.Contains(snippet, "it's") {
		t.Error("snippet should escape single quotes")
	}
	if !strings.Contains(snippet, "it\\'s") {
		t.Error("snippet should contain escaped single quote")
	}
}

func TestSnippetEscapesHTMLAngleBrackets(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page?q=<script>alert(1)</script>")

	// The snippet itself has <script> tags from the template, so we check
	// specifically that the injected URL has been escaped.
	escaped := jsEscape("/page?q=<script>alert(1)</script>")
	if !strings.Contains(escaped, "\\x3c") {
		t.Fatal("jsEscape should convert < to \\x3c")
	}
	if !strings.Contains(snippet, escaped) {
		t.Error("snippet should contain the escaped pageURL with \\x3c and \\x3e")
	}
	// Ensure the raw dangerous input is NOT present as a page_path value
	if strings.Contains(snippet, "page_path: '/page?q=<script>") {
		t.Error("snippet should not contain unescaped angle brackets in page_path")
	}
}

func TestSnippetEscapesBackslashes(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page\\path")

	// The backslash should be doubled
	if !strings.Contains(snippet, "/page\\\\path") {
		t.Error("snippet should escape backslashes")
	}
}

func TestSnippetEscapesNewlines(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page\ninjection")

	if strings.Contains(snippet, "/page\ninjection") {
		t.Error("snippet should escape newline characters")
	}
}

func TestSnippetEscapesCarriageReturns(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page\rinjection")

	if strings.Contains(snippet, "/page\rinjection") {
		t.Error("snippet should escape carriage return characters")
	}
}

// ---------------------------------------------------------------------------
// 13. GetRecentBeacons returns recorded beacons
// ---------------------------------------------------------------------------

func TestGetRecentBeaconsEmpty(t *testing.T) {
	e := NewEngine()
	beacons := e.GetRecentBeacons(10)
	if len(beacons) != 0 {
		t.Errorf("expected 0 beacons from fresh engine, got %d", len(beacons))
	}
}

func TestGetRecentBeaconsReturnsCorrectCount(t *testing.T) {
	e := NewEngine()

	// Record 5 beacons via /collect
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/collect?n="+string(rune('0'+i)), nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
	}

	beacons := e.GetRecentBeacons(3)
	if len(beacons) != 3 {
		t.Errorf("expected 3 beacons, got %d", len(beacons))
	}

	allBeacons := e.GetRecentBeacons(10)
	if len(allBeacons) != 5 {
		t.Errorf("expected 5 beacons, got %d", len(allBeacons))
	}
}

func TestGetRecentBeaconsMostRecentFirst(t *testing.T) {
	e := NewEngine()

	// Record beacons to two different endpoints to distinguish them
	req1 := httptest.NewRequest(http.MethodGet, "/collect?order=first", nil)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest(http.MethodGet, "/tr?order=second", nil)
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	beacons := e.GetRecentBeacons(2)
	if len(beacons) != 2 {
		t.Fatalf("expected 2 beacons, got %d", len(beacons))
	}
	// Most recent should be /tr
	if beacons[0].Endpoint != "/tr" {
		t.Errorf("expected most recent beacon endpoint /tr, got %q", beacons[0].Endpoint)
	}
	if beacons[1].Endpoint != "/collect" {
		t.Errorf("expected second beacon endpoint /collect, got %q", beacons[1].Endpoint)
	}
}

func TestGetRecentBeaconsClampsToBufferSize(t *testing.T) {
	e := NewEngine()

	req := httptest.NewRequest(http.MethodGet, "/collect", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	// Ask for more than buffer size
	beacons := e.GetRecentBeacons(5000)
	if len(beacons) != 1 {
		t.Errorf("expected 1 beacon, got %d", len(beacons))
	}
}

// ---------------------------------------------------------------------------
// 14. Ring buffer doesn't exceed capacity
// ---------------------------------------------------------------------------

func TestBeaconRingBufferCapacity(t *testing.T) {
	e := NewEngine()

	// Record more beacons than the buffer size
	for i := 0; i < 1050; i++ {
		req := httptest.NewRequest(http.MethodGet, "/collect", nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
	}

	// The slice length should still be the original buffer size
	e.mu.RLock()
	sliceLen := len(e.beacons)
	e.mu.RUnlock()
	if sliceLen != 1000 {
		t.Errorf("expected beacon slice length to remain at 1000, got %d", sliceLen)
	}

	// Should return at most bufferSize beacons
	beacons := e.GetRecentBeacons(2000)
	if len(beacons) != 1000 {
		t.Errorf("expected max 1000 beacons from ring buffer, got %d", len(beacons))
	}
}

func TestEventRingBufferCapacity(t *testing.T) {
	e := NewEngine()

	// Record more events than the event buffer size
	for i := 0; i < 550; i++ {
		eventJSON := `{"event":"test","target":"t","page":"/p","timestamp":1}`
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(eventJSON))
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
	}

	e.mu.RLock()
	sliceLen := len(e.events)
	e.mu.RUnlock()
	if sliceLen != 500 {
		t.Errorf("expected event slice length to remain at 500, got %d", sliceLen)
	}

	events := e.getRecentEvents(1000)
	if len(events) != 500 {
		t.Errorf("expected max 500 events from ring buffer, got %d", len(events))
	}
}

// ---------------------------------------------------------------------------
// 15. Thread safety (concurrent beacon recording)
// ---------------------------------------------------------------------------

func TestConcurrentBeaconRecording(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup
	numGoroutines := 50
	requestsPerGoroutine := 20

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < requestsPerGoroutine; i++ {
				req := httptest.NewRequest(http.MethodGet, "/collect?t=concurrent", nil)
				w := httptest.NewRecorder()
				e.ServeHTTP(w, req)
			}
		}()
	}
	wg.Wait()

	total := numGoroutines * requestsPerGoroutine // 1000
	beacons := e.GetRecentBeacons(total)
	if len(beacons) != total {
		t.Errorf("expected %d beacons after concurrent writes, got %d", total, len(beacons))
	}
}

func TestConcurrentMixedEndpoints(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup

	// Concurrently hit multiple endpoints
	wg.Add(4)

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest(http.MethodGet, "/collect", nil)
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest(http.MethodGet, "/tr", nil)
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			eventJSON := `{"event":"concurrent","target":"x","page":"/y","timestamp":1}`
			req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(eventJSON))
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest(http.MethodPost, "/analytics/beacon", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
		}
	}()

	wg.Wait()

	// Total beacons: /collect (100) + /tr (100) + /events (100) + /analytics/beacon (100) = 400
	beacons := e.GetRecentBeacons(500)
	if len(beacons) != 400 {
		t.Errorf("expected 400 beacons after concurrent mixed writes, got %d", len(beacons))
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	e := NewEngine()
	var wg sync.WaitGroup

	// Writers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			req := httptest.NewRequest(http.MethodGet, "/collect", nil)
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
		}
	}()

	// Readers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = e.GetRecentBeacons(10)
		}
	}()

	wg.Wait()
	// If we get here without a race condition panic, the test passes
}

// ---------------------------------------------------------------------------
// Additional edge case tests
// ---------------------------------------------------------------------------

func TestServeHTTPUnknownPath(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", status)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("expected response code 404, got %d", w.Code)
	}
}

func TestCollectGETNoQueryParams(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/collect", nil)
	w := httptest.NewRecorder()
	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("expected status 200, got %d", status)
	}
	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	if len(beacons[0].Params) != 0 {
		t.Errorf("expected empty params, got %d params", len(beacons[0].Params))
	}
}

func TestCollectGETExtraQueryParams(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/collect?v=1&tid=UA-1&custom_param=hello", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	beacons := e.GetRecentBeacons(1)
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}
	if beacons[0].Params["custom_param"] != "hello" {
		t.Errorf("expected custom_param=hello, got %q", beacons[0].Params["custom_param"])
	}
}

func TestJsEscapeFunction(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`normal/path`, `normal/path`},
		{`path'with'quotes`, `path\'with\'quotes`},
		{`path\with\backslashes`, `path\\with\\backslashes`},
		{"path\nwith\nnewlines", `path\nwith\nnewlines`},
		{"path\rwith\rcarriage", `path\rwith\rcarriage`},
		{`<script>alert(1)</script>`, `\x3cscript\x3ealert(1)\x3c/script\x3e`},
		{`mix<'>\`, `mix\x3c\'\x3e\\`},
	}
	for _, tt := range tests {
		got := jsEscape(tt.input)
		if got != tt.expected {
			t.Errorf("jsEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSnippetContainsEventTracking(t *testing.T) {
	e := NewEngine()
	snippet := e.Snippet("/page")

	if !strings.Contains(snippet, "link_click") {
		t.Error("snippet should contain link click tracking")
	}
	if !strings.Contains(snippet, "scroll_depth") {
		t.Error("snippet should contain scroll depth tracking")
	}
	if !strings.Contains(snippet, "time_on_page") {
		t.Error("snippet should contain time on page tracking")
	}
	if !strings.Contains(snippet, "sendBeacon") {
		t.Error("snippet should contain navigator.sendBeacon usage")
	}
}

func TestConfigContainsConsentAndSampling(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/analytics/config", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	var config map[string]interface{}
	json.Unmarshal(body, &config)

	if _, ok := config["consent"]; !ok {
		t.Error("config should contain consent section")
	}
	if _, ok := config["sampling"]; !ok {
		t.Error("config should contain sampling section")
	}
	if _, ok := config["configured_events"]; !ok {
		t.Error("config should contain configured_events section")
	}
	if _, ok := config["goals"]; !ok {
		t.Error("config should contain goals section")
	}
}
