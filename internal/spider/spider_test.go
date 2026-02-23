package spider

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- ShouldHandle routing tests ---

func TestShouldHandle_KnownPaths(t *testing.T) {
	h := NewHandler(NewConfig())

	paths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/favicon.ico",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
		"/manifest.json",
		"/browserconfig.xml",
		"/humans.txt",
		"/ads.txt",
		"/.well-known/security.txt",
		"/sitemap-1.xml",
		"/sitemap-2.xml",
		"/sitemap-3.xml",
	}

	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_UnknownPaths(t *testing.T) {
	h := NewHandler(NewConfig())

	paths := []string{
		"/",
		"/about",
		"/api/v1/users",
		"/sitemap-abc.xml",
		"/sitemap-.xml",
		"/robots.txt.bak",
		"/favicon.png",
	}

	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// --- Config tests ---

func TestConfig_Defaults(t *testing.T) {
	cfg := NewConfig()

	if cfg.SitemapEntryCount != 50 {
		t.Errorf("default SitemapEntryCount = %d, want 50", cfg.SitemapEntryCount)
	}
	if cfg.RobotsCrawlDelay != 2 {
		t.Errorf("default RobotsCrawlDelay = %d, want 2", cfg.RobotsCrawlDelay)
	}
	if !cfg.EnableSitemapIndex {
		t.Error("default EnableSitemapIndex should be true")
	}
	if !cfg.EnableGzipSitemap {
		t.Error("default EnableGzipSitemap should be true")
	}
}

func TestConfig_GetSet(t *testing.T) {
	cfg := NewConfig()

	// Test Set and Get for float64
	ok := cfg.Set("sitemap_error_rate", 0.75)
	if !ok {
		t.Error("Set sitemap_error_rate should return true")
	}
	val := cfg.Get("sitemap_error_rate")
	if v, ok := val.(float64); !ok || v != 0.75 {
		t.Errorf("Get sitemap_error_rate = %v, want 0.75", val)
	}

	// Test Set and Get for int
	ok = cfg.Set("sitemap_entry_count", 100)
	if !ok {
		t.Error("Set sitemap_entry_count should return true")
	}
	val = cfg.Get("sitemap_entry_count")
	if v, ok := val.(int); !ok || v != 100 {
		t.Errorf("Get sitemap_entry_count = %v, want 100", val)
	}

	// Test Set and Get for bool
	ok = cfg.Set("enable_sitemap_index", false)
	if !ok {
		t.Error("Set enable_sitemap_index should return true")
	}
	val = cfg.Get("enable_sitemap_index")
	if v, ok := val.(bool); !ok || v != false {
		t.Errorf("Get enable_sitemap_index = %v, want false", val)
	}

	// Test unknown key
	ok = cfg.Set("nonexistent_key", 42)
	if ok {
		t.Error("Set nonexistent_key should return false")
	}
	val = cfg.Get("nonexistent_key")
	if val != nil {
		t.Errorf("Get nonexistent_key = %v, want nil", val)
	}

	// Test wrong type
	ok = cfg.Set("sitemap_error_rate", "not a float")
	if ok {
		t.Error("Set sitemap_error_rate with string should return false")
	}
}

func TestConfig_Snapshot(t *testing.T) {
	cfg := NewConfig()
	snap := cfg.Snapshot()

	expectedKeys := []string{
		"sitemap_error_rate",
		"sitemap_gzip_error_rate",
		"sitemap_entry_count",
		"favicon_error_rate",
		"robots_crawl_delay",
		"robots_disallow_paths",
		"robots_error_rate",
		"meta_error_rate",
		"enable_sitemap_index",
		"enable_gzip_sitemap",
	}

	for _, k := range expectedKeys {
		if _, exists := snap[k]; !exists {
			t.Errorf("Snapshot missing key %q", k)
		}
	}

	if len(snap) != len(expectedKeys) {
		t.Errorf("Snapshot has %d keys, want %d", len(snap), len(expectedKeys))
	}
}

func TestConfig_ClampFloat(t *testing.T) {
	cfg := NewConfig()

	cfg.Set("sitemap_error_rate", 1.5)
	if v := cfg.Get("sitemap_error_rate").(float64); v != 1.0 {
		t.Errorf("clamped sitemap_error_rate = %f, want 1.0", v)
	}

	cfg.Set("sitemap_error_rate", -0.5)
	if v := cfg.Get("sitemap_error_rate").(float64); v != 0.0 {
		t.Errorf("clamped sitemap_error_rate = %f, want 0.0", v)
	}
}

// --- Robots.txt tests ---

func TestRobots_ValidResponse(t *testing.T) {
	cfg := NewConfig()
	cfg.RobotsErrorRate = 0.0 // no errors
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("robots.txt status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "User-agent: *") {
		t.Error("robots.txt missing 'User-agent: *'")
	}
	if !strings.Contains(body, "Disallow:") {
		t.Error("robots.txt missing Disallow directives")
	}
	if !strings.Contains(body, "Crawl-delay:") {
		t.Error("robots.txt missing Crawl-delay")
	}
	if !strings.Contains(body, "Sitemap:") {
		t.Error("robots.txt missing Sitemap reference")
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("robots.txt Content-Type = %q, want text/plain", ct)
	}
}

func TestRobots_ErrorInjection(t *testing.T) {
	cfg := NewConfig()
	cfg.RobotsErrorRate = 1.0 // always error
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	body := w.Body.String()

	// The response should be broken in some way:
	// either truncated, wrong content type, empty, or 500 error
	if status == 200 && strings.Contains(body, "User-agent: *") && strings.Contains(body, "Disallow:") && strings.Contains(body, "Sitemap:") {
		t.Error("expected broken robots.txt when error rate is 1.0, but got valid response")
	}
}

// --- Sitemap tests ---

func TestSitemap_ValidXML(t *testing.T) {
	cfg := NewConfig()
	cfg.SitemapErrorRate = 0.0
	cfg.SitemapGzipErrorRate = 0.0
	cfg.EnableGzipSitemap = false
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("sitemap.xml status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<urlset") {
		t.Error("sitemap.xml missing <urlset> element")
	}
	if !strings.Contains(body, "<loc>") {
		t.Error("sitemap.xml missing <loc> elements")
	}
	if !strings.Contains(body, "</urlset>") {
		t.Error("sitemap.xml not properly closed")
	}

	// Verify it's valid XML
	decoder := xml.NewDecoder(strings.NewReader(body))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("sitemap.xml is not valid XML: %v", err)
			break
		}
	}

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Errorf("sitemap.xml Content-Type = %q, want application/xml", ct)
	}
}

func TestSitemap_ErrorInjection(t *testing.T) {
	cfg := NewConfig()
	cfg.SitemapErrorRate = 1.0
	cfg.SitemapGzipErrorRate = 0.0
	cfg.EnableGzipSitemap = false
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()

	// Valid XML check — should fail since we injected errors
	decoder := xml.NewDecoder(strings.NewReader(body))
	valid := true
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			valid = false
			break
		}
	}
	// With error rate 1.0, the sitemap should be broken
	if valid && strings.Contains(body, "</urlset>") {
		t.Error("expected broken sitemap XML when error rate is 1.0")
	}
}

func TestSitemapIndex_ValidXML(t *testing.T) {
	cfg := NewConfig()
	cfg.SitemapErrorRate = 0.0
	cfg.EnableSitemapIndex = true
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap_index.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("sitemap_index.xml status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<sitemapindex") {
		t.Error("sitemap_index.xml missing <sitemapindex> element")
	}
	if !strings.Contains(body, "sitemap-1.xml") {
		t.Error("sitemap_index.xml missing reference to sitemap-1.xml")
	}
	if !strings.Contains(body, "sitemap-2.xml") {
		t.Error("sitemap_index.xml missing reference to sitemap-2.xml")
	}
}

func TestSitemapIndex_Disabled(t *testing.T) {
	cfg := NewConfig()
	cfg.EnableSitemapIndex = false
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap_index.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 404 {
		t.Errorf("disabled sitemap_index.xml status = %d, want 404", status)
	}
}

func TestSitemapN_ValidSubSitemap(t *testing.T) {
	cfg := NewConfig()
	cfg.SitemapErrorRate = 0.0
	cfg.EnableGzipSitemap = false
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap-1.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("sitemap-1.xml status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<urlset") {
		t.Error("sitemap-1.xml missing <urlset> element")
	}
}

func TestSitemapN_OutOfRange(t *testing.T) {
	cfg := NewConfig()
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap-99.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 404 {
		t.Errorf("sitemap-99.xml status = %d, want 404", status)
	}
}

func TestSitemap_GzipCompressed(t *testing.T) {
	cfg := NewConfig()
	cfg.SitemapErrorRate = 0.0
	cfg.SitemapGzipErrorRate = 0.0
	cfg.EnableGzipSitemap = true
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/sitemap.xml", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("gzip sitemap status = %d, want 200", status)
	}

	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Error("expected Content-Encoding: gzip")
	}

	// Decompress and verify
	gz, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gz.Close()

	decompressed, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if !strings.Contains(string(decompressed), "<urlset") {
		t.Error("decompressed sitemap missing <urlset>")
	}
}

// --- Favicon tests ---

func TestFavicon_ValidICO(t *testing.T) {
	cfg := NewConfig()
	cfg.FaviconErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("favicon.ico status = %d, want 200", status)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "image/x-icon" {
		t.Errorf("favicon.ico Content-Type = %q, want image/x-icon", ct)
	}

	body := w.Body.Bytes()
	// Validate ICO header: first 4 bytes should be 00 00 01 00
	if len(body) < 6 {
		t.Fatalf("favicon.ico too small: %d bytes", len(body))
	}
	if body[0] != 0 || body[1] != 0 || body[2] != 1 || body[3] != 0 {
		t.Error("favicon.ico invalid ICO magic bytes")
	}
	// Image count should be 1
	imageCount := binary.LittleEndian.Uint16(body[4:6])
	if imageCount != 1 {
		t.Errorf("favicon.ico image count = %d, want 1", imageCount)
	}
}

func TestFavicon_ErrorInjection(t *testing.T) {
	cfg := NewConfig()
	cfg.FaviconErrorRate = 1.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.Bytes()

	// With error rate 1.0, the response should NOT be a valid ICO
	// (unless by extreme coincidence the garbage matches ICO format)
	if len(body) >= 6 && body[0] == 0 && body[1] == 0 && body[2] == 1 && body[3] == 0 {
		// Check if it has proper pixel data — a truncated ICO header alone is still broken
		if len(body) > 22 {
			t.Error("expected broken favicon when error rate is 1.0")
		}
	}
}

func TestAppleTouchIcon_ValidPNG(t *testing.T) {
	cfg := NewConfig()
	cfg.FaviconErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/apple-touch-icon.png", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("apple-touch-icon.png status = %d, want 200", status)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "image/png" {
		t.Errorf("apple-touch-icon.png Content-Type = %q, want image/png", ct)
	}

	body := w.Body.Bytes()
	// Validate PNG signature (8 bytes)
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(body) < 8 {
		t.Fatalf("apple-touch-icon.png too small: %d bytes", len(body))
	}
	for i, b := range pngSig {
		if body[i] != b {
			t.Errorf("PNG signature byte %d: got 0x%02X, want 0x%02X", i, body[i], b)
		}
	}
}

// --- Meta files tests ---

func TestManifest_ValidJSON(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/manifest.json", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("manifest.json status = %d, want 200", status)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Errorf("manifest.json is not valid JSON: %v", err)
	}

	if name, ok := m["name"].(string); !ok || name != "Glitch Web Server" {
		t.Errorf("manifest.json name = %v, want 'Glitch Web Server'", m["name"])
	}
}

func TestBrowserconfig_ValidXML(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/browserconfig.xml", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("browserconfig.xml status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<browserconfig>") {
		t.Error("browserconfig.xml missing <browserconfig> element")
	}
	if !strings.Contains(body, "<TileColor>") {
		t.Error("browserconfig.xml missing <TileColor> element")
	}
}

func TestHumans_ValidContent(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/humans.txt", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("humans.txt status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "/* TEAM */") {
		t.Error("humans.txt missing TEAM section")
	}
	if !strings.Contains(body, "/* SITE */") {
		t.Error("humans.txt missing SITE section")
	}
}

func TestAds_ValidContent(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/ads.txt", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("ads.txt status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "google.com") {
		t.Error("ads.txt missing google.com entry")
	}
	if !strings.Contains(body, "DIRECT") {
		t.Error("ads.txt missing DIRECT relationship")
	}
}

func TestSecurity_ValidContent(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 0.0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/.well-known/security.txt", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 200 {
		t.Errorf("security.txt status = %d, want 200", status)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Contact:") {
		t.Error("security.txt missing Contact field")
	}
	if !strings.Contains(body, "Expires:") {
		t.Error("security.txt missing Expires field")
	}
	if !strings.Contains(body, "Policy:") {
		t.Error("security.txt missing Policy field")
	}
}

func TestMeta_ErrorInjection(t *testing.T) {
	cfg := NewConfig()
	cfg.MetaErrorRate = 1.0
	h := NewHandler(cfg)

	endpoints := []string{
		"/manifest.json",
		"/browserconfig.xml",
		"/humans.txt",
		"/ads.txt",
		"/.well-known/security.txt",
	}

	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		w := httptest.NewRecorder()

		status := h.ServeHTTP(w, req)
		body := w.Body.String()

		// Each broken response should be either: empty, garbage, 500, or truncated
		// At minimum it should not be the full valid content
		if status == 200 && len(body) > 200 {
			// If it looks like valid full content, something is wrong
			if ep == "/manifest.json" {
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(body), &m); err == nil {
					if _, ok := m["name"]; ok {
						t.Errorf("expected broken %s when error rate is 1.0, got valid JSON", ep)
					}
				}
			}
		}
	}
}

// --- Handler nil config test ---

func TestHandler_NilConfig(t *testing.T) {
	h := NewHandler(nil)
	if h.cfg == nil {
		t.Error("NewHandler(nil) should create default config")
	}
	if h.cfg.SitemapEntryCount != 50 {
		t.Errorf("default config SitemapEntryCount = %d, want 50", h.cfg.SitemapEntryCount)
	}
}

// --- Unknown path test ---

func TestHandler_UnknownPath(t *testing.T) {
	h := NewHandler(NewConfig())

	req := httptest.NewRequest("GET", "/unknown-path", nil)
	w := httptest.NewRecorder()

	status := h.ServeHTTP(w, req)

	if status != 404 {
		t.Errorf("unknown path status = %d, want 404", status)
	}
}

// --- ICO binary format validation ---

func TestBuildICO_Format(t *testing.T) {
	ico := buildICO()

	// ICO header: 6 bytes
	// Dir entry: 16 bytes
	// BMP header: 40 bytes
	// Pixel data: 16*16*4 = 1024 bytes
	expectedSize := 6 + 16 + 40 + 1024
	if len(ico) != expectedSize {
		t.Errorf("ICO size = %d, want %d", len(ico), expectedSize)
	}

	// Check width/height in directory entry
	if ico[6] != 16 { // width
		t.Errorf("ICO width = %d, want 16", ico[6])
	}
	if ico[7] != 16 { // height
		t.Errorf("ICO height = %d, want 16", ico[7])
	}
}

// --- PNG binary format validation ---

func TestBuildMinimalPNG_Format(t *testing.T) {
	png := buildMinimalPNG(0xFF, 0x00, 0x00) // red

	// Check PNG signature
	sig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(png) < 8 {
		t.Fatalf("PNG too small: %d bytes", len(png))
	}
	for i, b := range sig {
		if png[i] != b {
			t.Errorf("PNG sig[%d] = 0x%02X, want 0x%02X", i, png[i], b)
		}
	}

	// Check IHDR chunk type at offset 12 (after 4-byte length + 8-byte sig - 4 = 12)
	// Actually: sig(8) + length(4) = offset 12 for chunk type
	ihdrType := string(png[12:16])
	if ihdrType != "IHDR" {
		t.Errorf("first chunk type = %q, want IHDR", ihdrType)
	}
}

// --- Deterministic seeding test ---

func TestSeedRand_Deterministic(t *testing.T) {
	rng1 := seedRand("/test/path")
	rng2 := seedRand("/test/path")

	for i := 0; i < 10; i++ {
		v1 := rng1.Float64()
		v2 := rng2.Float64()
		if v1 != v2 {
			t.Errorf("seedRand not deterministic: iteration %d, %f != %f", i, v1, v2)
		}
	}

	// Different paths should produce different sequences
	rng3 := seedRand("/different/path")
	rng4 := seedRand("/test/path")
	same := true
	for i := 0; i < 10; i++ {
		if rng3.Float64() != rng4.Float64() {
			same = false
			break
		}
	}
	if same {
		t.Error("different paths should produce different random sequences")
	}
}

// --- Robots with no crawl delay ---

func TestRobots_NoCrawlDelay(t *testing.T) {
	cfg := NewConfig()
	cfg.RobotsErrorRate = 0.0
	cfg.RobotsCrawlDelay = 0
	h := NewHandler(cfg)

	req := httptest.NewRequest("GET", "/robots.txt", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	// When crawl delay is 0, the "Crawl-delay:" for User-agent: * should not appear
	lines := strings.Split(body, "\n")
	inWildcard := false
	for _, line := range lines {
		if strings.HasPrefix(line, "User-agent: *") {
			inWildcard = true
			continue
		}
		if inWildcard && strings.HasPrefix(line, "User-agent:") {
			break
		}
		if inWildcard && strings.HasPrefix(line, "Crawl-delay:") {
			t.Error("robots.txt should not have Crawl-delay when set to 0")
		}
	}
}
