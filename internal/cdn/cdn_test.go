package cdn

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
	if e.cache == nil {
		t.Fatal("NewEngine should initialize the cache map")
	}
}

// ---------------------------------------------------------------------------
// 2. ShouldHandle: true for static prefixed paths
// ---------------------------------------------------------------------------

func TestShouldHandle_StaticPrefixes(t *testing.T) {
	e := NewEngine()
	prefixes := []string{
		"/static/app.js",
		"/assets/style.css",
		"/cdn/bundle.js",
		"/_next/static/chunks/main.js",
		"/dist/vendor.js",
		"/build/output.css",
	}
	for _, path := range prefixes {
		if !e.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = false, want true", path)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. ShouldHandle: false for non-static paths
// ---------------------------------------------------------------------------

func TestShouldHandle_NonStaticPaths(t *testing.T) {
	e := NewEngine()
	paths := []string{
		"/",
		"/about",
		"/api/v1/users",
		"/login",
		"/images/photo.jpg",        // not under a static prefix
		"/some/random/path",
		"/staticpage",              // no trailing slash
		"/app.js",                  // extension but not under static prefix
	}
	for _, path := range paths {
		if e.ShouldHandle(path) {
			t.Errorf("ShouldHandle(%q) = true, want false", path)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. ServeHTTP returns appropriate content for .js files
// ---------------------------------------------------------------------------

func TestServeHTTP_JSFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "application/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/javascript; charset=utf-8")
	}
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("body is empty for .js file")
	}
	// JS body should contain webpack-style content
	if !strings.Contains(body, "function") {
		t.Error("JS body does not look like JavaScript (missing 'function' keyword)")
	}
}

// ---------------------------------------------------------------------------
// 5. ServeHTTP returns appropriate content for .css files
// ---------------------------------------------------------------------------

func TestServeHTTP_CSSFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/styles.css", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/css; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/css; charset=utf-8")
	}
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("body is empty for .css file")
	}
	// CSS body should contain style-like content
	if !strings.Contains(body, "{") || !strings.Contains(body, "}") {
		t.Error("CSS body does not look like CSS (missing braces)")
	}
}

// ---------------------------------------------------------------------------
// 6. ServeHTTP returns appropriate content for .woff/.woff2 font files
// ---------------------------------------------------------------------------

func TestServeHTTP_WoffFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/font.woff", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "font/woff" {
		t.Errorf("Content-Type = %q, want %q", ct, "font/woff")
	}
	body := w.Body.Bytes()
	if len(body) < 4 {
		t.Fatal("woff body too short")
	}
	if string(body[:4]) != "wOFF" {
		t.Errorf("woff body should start with 'wOFF' magic bytes, got %q", body[:4])
	}
}

func TestServeHTTP_Woff2File(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/font.woff2", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "font/woff2" {
		t.Errorf("Content-Type = %q, want %q", ct, "font/woff2")
	}
	body := w.Body.Bytes()
	if len(body) < 4 {
		t.Fatal("woff2 body too short")
	}
	// Both .woff and .woff2 are dispatched with fontType "woff" in generateAssetBody,
	// so the magic bytes are "wOFF" for both.
	if string(body[:4]) != "wOFF" {
		t.Errorf("woff2 body should start with 'wOFF' magic bytes, got %q", body[:4])
	}
}

// ---------------------------------------------------------------------------
// 7. ServeHTTP returns 1x1 pixel for .png, .jpg, .gif, .ico
// ---------------------------------------------------------------------------

func TestServeHTTP_PNGFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/pixel.png", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want %q", ct, "image/png")
	}
	body := w.Body.Bytes()
	// PNG signature: 0x89 P N G
	if len(body) < 8 || body[0] != 0x89 || body[1] != 0x50 || body[2] != 0x4e || body[3] != 0x47 {
		t.Error("PNG body does not have valid PNG signature")
	}
}

func TestServeHTTP_JPGFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/photo.jpg", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/jpeg" {
		t.Errorf("Content-Type = %q, want %q", ct, "image/jpeg")
	}
	body := w.Body.Bytes()
	// JPEG starts with 0xFF 0xD8
	if len(body) < 2 || body[0] != 0xff || body[1] != 0xd8 {
		t.Error("JPG body does not have valid JPEG signature")
	}
}

func TestServeHTTP_GIFFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/anim.gif", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/gif" {
		t.Errorf("Content-Type = %q, want %q", ct, "image/gif")
	}
	body := w.Body.Bytes()
	// GIF89a signature
	if len(body) < 6 || string(body[:6]) != "GIF89a" {
		t.Error("GIF body does not have valid GIF89a signature")
	}
}

func TestServeHTTP_ICOFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/favicon.ico", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("Content-Type = %q, want %q", ct, "image/x-icon")
	}
	body := w.Body.Bytes()
	// ICO header: reserved=0x0000, type=0x0100 (icon)
	if len(body) < 4 || body[0] != 0x00 || body[1] != 0x00 || body[2] != 0x01 || body[3] != 0x00 {
		t.Error("ICO body does not have valid ICO header")
	}
}

// ---------------------------------------------------------------------------
// 8. ServeHTTP returns JSON for .map files
// ---------------------------------------------------------------------------

func TestServeHTTP_MapFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js.map", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	body := w.Body.String()
	if !strings.Contains(body, `"version":3`) {
		t.Error("source map body does not contain version:3")
	}
	if !strings.Contains(body, `"mappings"`) {
		t.Error("source map body does not contain mappings field")
	}
}

// ---------------------------------------------------------------------------
// 9. Conditional request: If-None-Match with correct ETag returns 304
// ---------------------------------------------------------------------------

func TestServeHTTP_ConditionalRequest_MatchingETag(t *testing.T) {
	e := NewEngine()
	path := "/static/app.js"

	// First request to get the ETag
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)
	etag := w1.Result().Header.Get("ETag")
	if etag == "" {
		t.Fatal("first request did not return an ETag")
	}

	// Second request with matching If-None-Match
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	status := e.ServeHTTP(w2, req2)

	if status != http.StatusNotModified {
		t.Errorf("status = %d, want %d", status, http.StatusNotModified)
	}
	if w2.Body.Len() != 0 {
		t.Errorf("body should be empty for 304, got %d bytes", w2.Body.Len())
	}
}

// ---------------------------------------------------------------------------
// 10. Conditional request: If-None-Match with wrong ETag returns 200
// ---------------------------------------------------------------------------

func TestServeHTTP_ConditionalRequest_WrongETag(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("If-None-Match", `"not-the-right-etag"`)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if w.Body.Len() == 0 {
		t.Error("body should not be empty for mismatched ETag")
	}
}

// ---------------------------------------------------------------------------
// 11. CDN headers are applied via ApplyHeaders
// ---------------------------------------------------------------------------

func TestApplyHeaders_CommonHeaders(t *testing.T) {
	e := NewEngine()
	w := httptest.NewRecorder()

	e.ApplyHeaders(w, "/static/app.js", "test-client")

	headers := w.Result().Header
	checks := map[string]string{
		"Cache-Control":          "public, max-age=31536000, immutable",
		"Accept-Ranges":          "bytes",
		"X-Content-Type-Options": "nosniff",
		"Vary":                   "Accept-Encoding",
	}
	for name, want := range checks {
		got := headers.Get(name)
		if got != want {
			t.Errorf("header %s = %q, want %q", name, got, want)
		}
	}
	// ETag should be set
	if etag := headers.Get("ETag"); etag == "" {
		t.Error("ETag header should be set by ApplyHeaders")
	}
}

// ---------------------------------------------------------------------------
// 12. CDN personality headers are present
// ---------------------------------------------------------------------------

func TestApplyHeaders_PersonalityHeaders(t *testing.T) {
	e := NewEngine()

	// Try multiple client IDs to cover different CDN personalities.
	// We just need to verify that at least one personality's headers show up.
	personalityHeaderSets := [][]string{
		{"Server", "CF-Ray", "CF-Cache-Status"},           // Cloudflare
		{"X-Cache", "X-Amz-Cf-Id", "X-Amz-Cf-Pop"},      // CloudFront
		{"Server", "X-Cache", "X-Cache-Key"},              // Akamai
		{"X-Cache", "X-Cache-Hits", "X-Served-By"},        // Fastly
		{"X-Varnish", "X-Cache", "Age"},                   // Varnish
	}

	found := false
	for i := 0; i < 100 && !found; i++ {
		clientID := "personality-probe-" + strings.Repeat("x", i)
		w := httptest.NewRecorder()
		e.ApplyHeaders(w, "/static/app.js", clientID)
		headers := w.Result().Header

		for _, headerSet := range personalityHeaderSets {
			allPresent := true
			for _, h := range headerSet {
				if headers.Get(h) == "" {
					allPresent = false
					break
				}
			}
			if allPresent {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("no CDN personality headers found after testing multiple client IDs")
	}
}

// ---------------------------------------------------------------------------
// 13. Cache behavior: first request = MISS, second request = HIT
// ---------------------------------------------------------------------------

func TestCacheBehavior_MissThenHit(t *testing.T) {
	e := NewEngine()
	clientID := "cache-test-client"
	path := "/static/cached.js"

	// First call should be a MISS
	status1 := e.getCacheStatus(clientID, path)
	if status1 != "MISS" {
		t.Errorf("first getCacheStatus = %q, want MISS", status1)
	}

	// Second call should be a HIT
	status2 := e.getCacheStatus(clientID, path)
	if status2 != "HIT" {
		t.Errorf("second getCacheStatus = %q, want HIT", status2)
	}

	// Third call should still be HIT
	status3 := e.getCacheStatus(clientID, path)
	if status3 != "HIT" {
		t.Errorf("third getCacheStatus = %q, want HIT", status3)
	}
}

// ---------------------------------------------------------------------------
// 14. Deterministic: same path produces same ETag
// ---------------------------------------------------------------------------

func TestDeterministicETag(t *testing.T) {
	path := "/static/deterministic.js"
	etag1 := computeETag(path)
	etag2 := computeETag(path)
	if etag1 != etag2 {
		t.Errorf("ETags differ for same path: %q vs %q", etag1, etag2)
	}
	// ETag should be quoted
	if !strings.HasPrefix(etag1, `"`) || !strings.HasSuffix(etag1, `"`) {
		t.Errorf("ETag should be quoted, got %q", etag1)
	}
}

// ---------------------------------------------------------------------------
// 15. Different paths produce different content
// ---------------------------------------------------------------------------

func TestDifferentPathsDifferentContent(t *testing.T) {
	e := NewEngine()

	paths := []string{"/static/a.js", "/static/b.js", "/static/c.js"}
	bodies := make(map[string]string)
	etags := make(map[string]string)

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)

		body := w.Body.String()
		etag := w.Result().Header.Get("ETag")

		// Check body uniqueness
		for prevPath, prevBody := range bodies {
			if body == prevBody {
				t.Errorf("paths %q and %q produced identical bodies", prevPath, path)
			}
		}
		bodies[path] = body

		// Check ETag uniqueness
		for prevPath, prevEtag := range etags {
			if etag == prevEtag {
				t.Errorf("paths %q and %q produced identical ETags", prevPath, path)
			}
		}
		etags[path] = etag
	}
}

// ---------------------------------------------------------------------------
// 16. ServeHTTP sets Content-Length header
// ---------------------------------------------------------------------------

func TestServeHTTP_ContentLength(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	cl := w.Result().Header.Get("Content-Length")
	if cl == "" {
		t.Error("Content-Length header should be set")
	}
	if cl == "0" {
		t.Error("Content-Length should not be 0 for a .js file")
	}
}

// ---------------------------------------------------------------------------
// 17. ServeHTTP uses X-Client-ID header, falls back to "unknown"
// ---------------------------------------------------------------------------

func TestServeHTTP_ClientIDFallback(t *testing.T) {
	e := NewEngine()

	// Without X-Client-ID header
	req1 := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)

	// With X-Client-ID header
	req2 := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req2.Header.Set("X-Client-ID", "specific-client")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req2)

	// Both should succeed with 200
	if w1.Code != http.StatusOK {
		t.Errorf("without X-Client-ID: status = %d, want %d", w1.Code, http.StatusOK)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("with X-Client-ID: status = %d, want %d", w2.Code, http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// 18. Range request returns 206 Partial Content
// ---------------------------------------------------------------------------

func TestServeHTTP_RangeRequest(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Range", "bytes=0-99")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", status, http.StatusPartialContent)
	}
	cr := w.Result().Header.Get("Content-Range")
	if cr == "" {
		t.Error("Content-Range header should be set for range requests")
	}
	if !strings.HasPrefix(cr, "bytes 0-99/") {
		t.Errorf("Content-Range = %q, want prefix 'bytes 0-99/'", cr)
	}
	if w.Body.Len() != 100 {
		t.Errorf("body length = %d, want 100", w.Body.Len())
	}
}

// ---------------------------------------------------------------------------
// 19. Invalid Range returns 416
// ---------------------------------------------------------------------------

func TestServeHTTP_InvalidRange(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Range", "bytes=999999999-999999999")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status = %d, want %d", status, http.StatusRequestedRangeNotSatisfiable)
	}
}

// ---------------------------------------------------------------------------
// 20. SVG file returns valid SVG content
// ---------------------------------------------------------------------------

func TestServeHTTP_SVGFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/icon.svg", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("Content-Type = %q, want %q", ct, "image/svg+xml")
	}
	body := w.Body.String()
	if !strings.Contains(body, "<svg") {
		t.Error("SVG body does not contain <svg tag")
	}
	if !strings.Contains(body, "</svg>") {
		t.Error("SVG body does not contain closing </svg> tag")
	}
}

// ---------------------------------------------------------------------------
// 21. JSON asset returns valid JSON
// ---------------------------------------------------------------------------

func TestServeHTTP_JSONFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/config.json", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "{") || !strings.HasSuffix(body, "}") {
		t.Error("JSON body should start with '{' and end with '}'")
	}
}

// ---------------------------------------------------------------------------
// 22. Manifest JSON returns app manifest
// ---------------------------------------------------------------------------

func TestServeHTTP_ManifestJSON(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/manifest.json", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `"name"`) {
		t.Error("manifest.json should contain 'name' field")
	}
	if !strings.Contains(body, `"start_url"`) {
		t.Error("manifest.json should contain 'start_url' field")
	}
}

// ---------------------------------------------------------------------------
// 23. TTF font file has correct magic bytes and content type
// ---------------------------------------------------------------------------

func TestServeHTTP_TTFFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/font.ttf", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "font/ttf" {
		t.Errorf("Content-Type = %q, want %q", ct, "font/ttf")
	}
	body := w.Body.Bytes()
	if len(body) < 4 {
		t.Fatal("ttf body too short")
	}
	// TTF magic: 0x00 0x01 0x00 0x00
	if body[0] != 0x00 || body[1] != 0x01 || body[2] != 0x00 || body[3] != 0x00 {
		t.Errorf("ttf body has wrong magic bytes: %x %x %x %x", body[0], body[1], body[2], body[3])
	}
}

// ---------------------------------------------------------------------------
// 24. Directory listing for unknown extensions
// ---------------------------------------------------------------------------

func TestServeHTTP_DirectoryListing(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/somedir/", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/html; charset=utf-8")
	}
	body := w.Body.String()
	if !strings.Contains(body, "Index of") {
		t.Error("directory listing should contain 'Index of'")
	}
	if !strings.Contains(body, "Glitch CDN Server") {
		t.Error("directory listing should contain 'Glitch CDN Server' signature")
	}
}

// ---------------------------------------------------------------------------
// 25. Conditional request with weak ETag (W/ prefix) returns 304
// ---------------------------------------------------------------------------

func TestServeHTTP_ConditionalRequest_WeakETag(t *testing.T) {
	e := NewEngine()
	path := "/static/weak.js"

	// Get the ETag first
	req1 := httptest.NewRequest(http.MethodGet, path, nil)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req1)
	etag := w1.Result().Header.Get("ETag")

	// Send with W/ prefix
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	req2.Header.Set("If-None-Match", "W/"+etag)
	w2 := httptest.NewRecorder()
	status := e.ServeHTTP(w2, req2)

	if status != http.StatusNotModified {
		t.Errorf("status = %d, want %d for weak ETag match", status, http.StatusNotModified)
	}
}

// ---------------------------------------------------------------------------
// 26. selectPersonality is deterministic per client
// ---------------------------------------------------------------------------

func TestSelectPersonality_Deterministic(t *testing.T) {
	p1 := selectPersonality("client-abc")
	p2 := selectPersonality("client-abc")
	if p1 != p2 {
		t.Errorf("selectPersonality is not deterministic: %d vs %d", p1, p2)
	}
}

// ---------------------------------------------------------------------------
// 27. selectPersonality gives different results for different clients
// ---------------------------------------------------------------------------

func TestSelectPersonality_DifferentClients(t *testing.T) {
	seen := make(map[cdnPersonality]bool)
	// Try enough clients to statistically cover all 5 personalities
	for i := 0; i < 200; i++ {
		clientID := "client-" + strings.Repeat("z", i)
		p := selectPersonality(clientID)
		seen[p] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected at least 2 different personalities across 200 clients, got %d", len(seen))
	}
}

// ---------------------------------------------------------------------------
// 28. getCacheEntry returns nil for uncached path
// ---------------------------------------------------------------------------

func TestGetCacheEntry_Nil(t *testing.T) {
	e := NewEngine()
	entry := e.getCacheEntry("no-client", "/no-path")
	if entry != nil {
		t.Error("getCacheEntry should return nil for uncached path")
	}
}

// ---------------------------------------------------------------------------
// 29. getCacheEntry returns entry after getCacheStatus
// ---------------------------------------------------------------------------

func TestGetCacheEntry_AfterAccess(t *testing.T) {
	e := NewEngine()
	clientID := "entry-client"
	path := "/static/entry.js"

	e.getCacheStatus(clientID, path)
	entry := e.getCacheEntry(clientID, path)
	if entry == nil {
		t.Fatal("getCacheEntry should return non-nil after getCacheStatus")
	}
	if entry.hits != 1 {
		t.Errorf("hits = %d, want 1", entry.hits)
	}

	e.getCacheStatus(clientID, path)
	entry = e.getCacheEntry(clientID, path)
	if entry.hits != 2 {
		t.Errorf("hits = %d, want 2 after second access", entry.hits)
	}
}

// ---------------------------------------------------------------------------
// 30. Suffix range request (bytes=-N)
// ---------------------------------------------------------------------------

func TestServeHTTP_SuffixRange(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	req.Header.Set("Range", "bytes=-50")
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)

	if status != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", status, http.StatusPartialContent)
	}
	if w.Body.Len() != 50 {
		t.Errorf("body length = %d, want 50 for suffix range", w.Body.Len())
	}
}

// ---------------------------------------------------------------------------
// 31. parseRange edge cases
// ---------------------------------------------------------------------------

func TestParseRange_InvalidFormats(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		size    int
		wantOK  bool
	}{
		{"not bytes prefix", "items=0-10", 100, false},
		{"multi-range", "bytes=0-10,20-30", 100, false},
		{"empty suffix", "bytes=-", 100, false},
		{"start beyond size", "bytes=200-300", 100, false},
		{"negative start", "bytes=-1-10", 100, false},
		{"valid simple range", "bytes=0-49", 100, true},
		{"open-ended range", "bytes=10-", 100, true},
		{"suffix range", "bytes=-20", 100, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ok := parseRange(tc.header, tc.size)
			if ok != tc.wantOK {
				t.Errorf("parseRange(%q, %d) ok = %v, want %v", tc.header, tc.size, ok, tc.wantOK)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 32. Full request via ServeHTTP sets ETag header
// ---------------------------------------------------------------------------

func TestServeHTTP_SetsETag(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/bundle.js", nil)
	w := httptest.NewRecorder()

	e.ServeHTTP(w, req)

	etag := w.Result().Header.Get("ETag")
	if etag == "" {
		t.Error("ETag header should be set in response")
	}
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Errorf("ETag should be double-quoted, got %q", etag)
	}
}

// ---------------------------------------------------------------------------
// 33. Cache is per-client: different clients get independent MISS
// ---------------------------------------------------------------------------

func TestCacheBehavior_PerClient(t *testing.T) {
	e := NewEngine()
	path := "/static/shared.js"

	s1 := e.getCacheStatus("client-A", path)
	s2 := e.getCacheStatus("client-B", path)

	if s1 != "MISS" {
		t.Errorf("client-A first access = %q, want MISS", s1)
	}
	if s2 != "MISS" {
		t.Errorf("client-B first access = %q, want MISS (independent of client-A)", s2)
	}
}

// ---------------------------------------------------------------------------
// 34. JS body starts with webpack-style IIFE
// ---------------------------------------------------------------------------

func TestGenerateJS_WebpackBoilerplate(t *testing.T) {
	body := string(generateJS("/static/app.js"))
	if !strings.HasPrefix(body, "!function(e)") {
		t.Error("JS body should start with webpack IIFE (!function(e))")
	}
	// Body should contain module-like patterns
	if !strings.Contains(body, "var ") {
		t.Error("JS body should contain variable declarations")
	}
}

// ---------------------------------------------------------------------------
// 35. CSS body starts with reset and contains selectors
// ---------------------------------------------------------------------------

func TestGenerateCSS_ContainsCSSReset(t *testing.T) {
	body := string(generateCSS("/static/styles.css"))
	if !strings.Contains(body, "box-sizing:border-box") {
		t.Error("CSS body should contain box-sizing reset")
	}
	if !strings.Contains(body, "font-family:") {
		t.Error("CSS body should contain font-family declaration")
	}
}

// ---------------------------------------------------------------------------
// 36. Font body size is in expected range (20KB - 100KB)
// ---------------------------------------------------------------------------

func TestGenerateFont_SizeRange(t *testing.T) {
	body := generateFont("/static/font.woff", "woff")
	if len(body) < 20*1024 {
		t.Errorf("font body too small: %d bytes, want >= %d", len(body), 20*1024)
	}
	if len(body) > 100*1024 {
		t.Errorf("font body too large: %d bytes, want <= %d", len(body), 100*1024)
	}
}

// ---------------------------------------------------------------------------
// 37. Deterministic body: same path produces same body
// ---------------------------------------------------------------------------

func TestDeterministicBody(t *testing.T) {
	body1 := generateAssetBody("/static/deterministic.js")
	body2 := generateAssetBody("/static/deterministic.js")
	if string(body1) != string(body2) {
		t.Error("generateAssetBody should produce identical output for the same path")
	}
}

// ---------------------------------------------------------------------------
// 38. All 5 CDN personalities are reachable
// ---------------------------------------------------------------------------

func TestAllPersonalities_Reachable(t *testing.T) {
	seen := make(map[cdnPersonality]bool)
	for i := 0; i < 1000; i++ {
		clientID := "probe-" + strings.Repeat("a", i%50) + strings.Repeat("b", i/50)
		p := selectPersonality(clientID)
		seen[p] = true
		if len(seen) == numPersonalities {
			break
		}
	}
	if len(seen) != numPersonalities {
		t.Errorf("covered %d of %d personalities", len(seen), numPersonalities)
	}
}

// ---------------------------------------------------------------------------
// 39. Concurrent access to cache is safe
// ---------------------------------------------------------------------------

func TestCacheConcurrency(t *testing.T) {
	e := NewEngine()
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			clientID := "concurrent-client"
			path := "/static/concurrent.js"
			for j := 0; j < 100; j++ {
				e.getCacheStatus(clientID, path)
				e.getCacheEntry(clientID, path)
			}
		}(i)
	}

	for i := 0; i < 50; i++ {
		<-done
	}
	// If we reach here without a race/panic, the test passes
}

// ---------------------------------------------------------------------------
// 40. EOT font has correct magic bytes
// ---------------------------------------------------------------------------

func TestServeHTTP_EOTFile(t *testing.T) {
	e := NewEngine()
	req := httptest.NewRequest(http.MethodGet, "/static/font.eot", nil)
	w := httptest.NewRecorder()

	status := e.ServeHTTP(w, req)
	resp := w.Result()

	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/vnd.ms-fontobject" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/vnd.ms-fontobject")
	}
	body := w.Body.Bytes()
	if len(body) < 4 {
		t.Fatal("eot body too short")
	}
}
