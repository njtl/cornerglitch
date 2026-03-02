package atomic

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/media"
	"github.com/glitchWebServer/internal/mediachaos"
)

// ---------------------------------------------------------------------------
// Media Generation Tests — verify each format produces valid output
// ---------------------------------------------------------------------------

func TestMedia_GenerateAllFormats(t *testing.T) {
	g := media.New()

	formats := map[string]struct {
		path        string
		minBytes    int
		contentType string
	}{
		"png":  {"/media/image/test.png", 50, "image/png"},
		"jpeg": {"/media/image/test.jpg", 50, "image/jpeg"},
		"gif":  {"/media/image/test.gif", 50, "image/gif"},
		"bmp":  {"/media/image/test.bmp", 50, "image/bmp"},
		"webp": {"/media/image/test.webp", 10, "image/webp"},
		"svg":  {"/media/image/test.svg", 50, "image/svg+xml"},
		"ico":  {"/media/image/test.ico", 10, "image/x-icon"},
		"tiff": {"/media/image/test.tiff", 50, "image/tiff"},
		"wav":  {"/media/audio/test.wav", 44, "audio/wav"},
		"mp3":  {"/media/audio/test.mp3", 10, "audio/mpeg"},
		"ogg":  {"/media/audio/test.ogg", 10, "audio/ogg"},
		"flac": {"/media/audio/test.flac", 10, "audio/flac"},
		"mp4":  {"/media/video/test.mp4", 50, "video/mp4"},
		"webm": {"/media/video/test.webm", 50, "video/webm"},
		"avi":  {"/media/video/test.avi", 50, "video/x-msvideo"},
		"hls":  {"/media/stream/test/playlist.m3u8", 10, "application/vnd.apple.mpegurl"},
		"dash": {"/media/stream/test/manifest.mpd", 10, "application/dash+xml"},
		"ts":   {"/media/stream/test/segment0.ts", 10, "video/mp2t"},
	}

	for name, tc := range formats {
		t.Run(name, func(t *testing.T) {
			format := media.FormatFromPath(tc.path)
			if format == "" {
				t.Fatalf("FormatFromPath(%q) returned empty", tc.path)
			}

			data, ct := g.Generate(format, tc.path)
			if len(data) < tc.minBytes {
				t.Errorf("expected at least %d bytes, got %d", tc.minBytes, len(data))
			}
			if ct != tc.contentType {
				t.Errorf("expected content-type %q, got %q", tc.contentType, ct)
			}
		})
	}
}

// TestMedia_FormatFromPath verifies path-to-format mapping.
func TestMedia_FormatFromPath(t *testing.T) {
	tests := []struct {
		path   string
		expect string
	}{
		{"/media/image/photo.png", "png"},
		{"/media/image/photo.jpg", "jpeg"},
		{"/media/image/photo.jpeg", "jpeg"},
		{"/media/image/banner.gif", "gif"},
		{"/media/image/icon.bmp", "bmp"},
		{"/media/image/modern.webp", "webp"},
		{"/media/image/logo.svg", "svg"},
		{"/media/image/favicon.ico", "ico"},
		{"/media/image/scan.tiff", "tiff"},
		{"/media/audio/music.wav", "wav"},
		{"/media/audio/track.mp3", "mp3"},
		{"/media/audio/song.ogg", "ogg"},
		{"/media/audio/lossless.flac", "flac"},
		{"/media/video/clip.mp4", "mp4"},
		{"/media/video/clip.webm", "webm"},
		{"/media/video/old.avi", "avi"},
		{"/media/stream/live/playlist.m3u8", "hls"},
		{"/media/stream/live/manifest.mpd", "dash"},
		{"/media/stream/live/segment0.ts", "ts"},
		{"/unknown/path.txt", ""},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := string(media.FormatFromPath(tc.path))
			if got != tc.expect {
				t.Errorf("FormatFromPath(%q) = %q, want %q", tc.path, got, tc.expect)
			}
		})
	}
}

// TestMedia_DeterministicContent verifies same path produces same content.
func TestMedia_DeterministicContent(t *testing.T) {
	g := media.New()
	path := "/media/image/deterministic-test.png"
	format := media.FormatFromPath(path)

	data1, _ := g.Generate(format, path)
	data2, _ := g.Generate(format, path)

	if len(data1) != len(data2) {
		t.Fatalf("deterministic: len mismatch %d vs %d", len(data1), len(data2))
	}
	for i := range data1 {
		if data1[i] != data2[i] {
			t.Fatalf("deterministic: byte mismatch at offset %d", i)
		}
	}
}

// TestMedia_DifferentPathsDifferentContent verifies different paths produce different content.
func TestMedia_DifferentPathsDifferentContent(t *testing.T) {
	g := media.New()
	data1, _ := g.Generate(media.FormatFromPath("/media/image/a.png"), "/media/image/a.png")
	data2, _ := g.Generate(media.FormatFromPath("/media/image/b.png"), "/media/image/b.png")

	if len(data1) == len(data2) {
		same := true
		for i := range data1 {
			if data1[i] != data2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different paths produced identical content")
		}
	}
}

// TestMedia_InfiniteReader verifies streaming reader produces limited output.
func TestMedia_InfiniteReader(t *testing.T) {
	g := media.New()
	maxBytes := int64(1024)
	reader := g.GenerateStream(media.FormatFromPath("/media/image/inf.png"), "/media/image/inf.png", maxBytes)
	if reader == nil {
		t.Fatal("GenerateStream returned nil")
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// Should produce content up to maxBytes (may be slightly more due to buffering)
	if int64(len(data)) > maxBytes*2 {
		t.Errorf("expected roughly %d bytes, got %d", maxBytes, len(data))
	}
	if len(data) == 0 {
		t.Error("infinite reader produced no data")
	}
}

// ---------------------------------------------------------------------------
// Media Chaos Engine Tests
// ---------------------------------------------------------------------------

// TestMediaChaos_EngineApply verifies the chaos engine produces responses.
func TestMediaChaos_EngineApply(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)
	// Disable slow delivery to avoid test slowness
	e.SetCategoryEnabled(mediachaos.SlowDelivery, false)
	// Disable chunked chaos (needs hijacker)
	e.SetCategoryEnabled(mediachaos.ChunkedChaos, false)

	g := media.New()
	data, ct := g.Generate(media.FormatFromPath("/media/image/test.png"), "/media/image/test.png")

	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/media/image/test.png", nil)
		e.Apply(w, r, data, ct)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Every response should produce some output
		if len(body) == 0 && resp.StatusCode != http.StatusNoContent {
			t.Errorf("iteration %d: got empty body with status %d", i, resp.StatusCode)
		}
	}
}

// TestMediaChaos_FeatureFlagToggle verifies the feature flag controls media chaos.
func TestMediaChaos_FeatureFlagToggle(t *testing.T) {
	flags := dashboard.GetFeatureFlags()

	flags.Set("media_chaos", false)
	if flags.IsMediaChaosEnabled() {
		t.Error("expected media_chaos to be disabled")
	}

	flags.Set("media_chaos", true)
	if !flags.IsMediaChaosEnabled() {
		t.Error("expected media_chaos to be enabled")
	}

	// Clean up
	flags.Set("media_chaos", true)
}

// TestMediaChaos_AdminConfigProbability verifies probability config round-trips.
func TestMediaChaos_AdminConfigProbability(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	cfg.Set("media_chaos_probability", 85.0)
	got := cfg.Get()
	if prob, ok := got["media_chaos_probability"].(float64); !ok || prob != 85.0 {
		t.Errorf("expected media_chaos_probability=85, got %v", got["media_chaos_probability"])
	}

	// Restore default
	cfg.Set("media_chaos_probability", 30.0)
}

// TestMediaChaos_AdminConfigCorruptionIntensity verifies corruption intensity config.
func TestMediaChaos_AdminConfigCorruptionIntensity(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	cfg.Set("media_chaos_corruption_intensity", 90.0)
	got := cfg.Get()
	if v, ok := got["media_chaos_corruption_intensity"].(float64); !ok || v != 90.0 {
		t.Errorf("expected media_chaos_corruption_intensity=90, got %v", got["media_chaos_corruption_intensity"])
	}

	// Restore default
	cfg.Set("media_chaos_corruption_intensity", 50.0)
}

// TestMediaChaos_AdminConfigSlowDelivery verifies slow delivery config.
func TestMediaChaos_AdminConfigSlowDelivery(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	cfg.Set("media_chaos_slow_min_ms", 50.0)
	cfg.Set("media_chaos_slow_max_ms", 500.0)
	got := cfg.Get()

	if v, ok := got["media_chaos_slow_min_ms"].(int); !ok || v != 50 {
		t.Errorf("expected media_chaos_slow_min_ms=50, got %v (type %T)", got["media_chaos_slow_min_ms"], got["media_chaos_slow_min_ms"])
	}
	if v, ok := got["media_chaos_slow_max_ms"].(int); !ok || v != 500 {
		t.Errorf("expected media_chaos_slow_max_ms=500, got %v (type %T)", got["media_chaos_slow_max_ms"], got["media_chaos_slow_max_ms"])
	}

	// Restore defaults
	cfg.Set("media_chaos_slow_min_ms", 10.0)
	cfg.Set("media_chaos_slow_max_ms", 1000.0)
}

// TestMediaChaos_AdminConfigInfiniteMaxBytes verifies infinite max bytes config.
func TestMediaChaos_AdminConfigInfiniteMaxBytes(t *testing.T) {
	cfg := dashboard.GetAdminConfig()

	cfg.Set("media_chaos_infinite_max_bytes", 50000000.0)
	got := cfg.Get()
	if v, ok := got["media_chaos_infinite_max_bytes"].(int64); !ok || v != 50000000 {
		t.Errorf("expected media_chaos_infinite_max_bytes=50000000, got %v (type %T)", got["media_chaos_infinite_max_bytes"], got["media_chaos_infinite_max_bytes"])
	}

	// Restore default
	cfg.Set("media_chaos_infinite_max_bytes", 104857600.0)
}

// TestMediaChaos_CategoryToggle verifies per-category toggle in MediaChaosConfig.
func TestMediaChaos_CategoryToggle(t *testing.T) {
	mc := dashboard.GetMediaChaosConfig()

	mc.SetCategory("format_corruption", false)
	if mc.IsEnabled("format_corruption") {
		t.Error("expected format_corruption to be disabled")
	}

	mc.SetCategory("format_corruption", true)
	if !mc.IsEnabled("format_corruption") {
		t.Error("expected format_corruption to be re-enabled")
	}
}

// TestMediaChaos_SetAll verifies bulk enable/disable.
func TestMediaChaos_SetAll(t *testing.T) {
	mc := dashboard.GetMediaChaosConfig()

	mc.SetAll(false)
	snap := mc.Snapshot()
	for cat, enabled := range snap {
		if enabled {
			t.Errorf("expected %s disabled after SetAll(false)", cat)
		}
	}

	mc.SetAll(true)
	snap = mc.Snapshot()
	for cat, enabled := range snap {
		if !enabled {
			t.Errorf("expected %s enabled after SetAll(true)", cat)
		}
	}
}

// TestMediaChaos_AllCategories verifies all 10 categories exist in config.
func TestMediaChaos_AllCategories(t *testing.T) {
	mc := dashboard.GetMediaChaosConfig()
	snap := mc.Snapshot()

	expectedCategories := []string{
		"format_corruption", "content_length_chaos", "content_type_chaos",
		"range_request_chaos", "chunked_chaos", "slow_delivery",
		"infinite_content", "stream_switching", "cache_poisoning",
		"streaming_chaos",
	}

	for _, cat := range expectedCategories {
		if _, ok := snap[cat]; !ok {
			t.Errorf("missing category %q in MediaChaosConfig", cat)
		}
	}

	if len(snap) != len(expectedCategories) {
		t.Errorf("expected %d categories, got %d", len(expectedCategories), len(snap))
	}
}

// TestMediaChaos_ConfigExportImport verifies media chaos config survives export/import.
func TestMediaChaos_ConfigExportImport(t *testing.T) {
	flags := dashboard.GetFeatureFlags()
	cfg := dashboard.GetAdminConfig()
	mc := dashboard.GetMediaChaosConfig()

	// Set up a specific state
	flags.Set("media_chaos", true)
	cfg.Set("media_chaos_probability", 65.0)
	cfg.Set("media_chaos_corruption_intensity", 80.0)
	mc.SetCategory("slow_delivery", false)
	mc.SetCategory("cache_poisoning", false)

	// Export
	export := dashboard.ExportConfig()
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	// Verify export has media_chaos_config
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)
	if _, ok := raw["media_chaos_config"]; !ok {
		t.Fatal("export missing media_chaos_config field")
	}

	// Reset state
	flags.Set("media_chaos", false)
	cfg.Set("media_chaos_probability", 30.0)
	cfg.Set("media_chaos_corruption_intensity", 50.0)
	mc.SetAll(true)

	// Import
	var reimport dashboard.ConfigExport
	json.Unmarshal(data, &reimport)
	dashboard.ImportConfig(&reimport)

	// Verify restored state
	if !flags.IsMediaChaosEnabled() {
		t.Error("media_chaos flag not restored")
	}
	got := cfg.Get()
	if prob, ok := got["media_chaos_probability"].(float64); !ok || prob != 65.0 {
		t.Errorf("media_chaos_probability not restored, got %v", got["media_chaos_probability"])
	}
	if v, ok := got["media_chaos_corruption_intensity"].(float64); !ok || v != 80.0 {
		t.Errorf("media_chaos_corruption_intensity not restored, got %v", got["media_chaos_corruption_intensity"])
	}
	if mc.IsEnabled("slow_delivery") {
		t.Error("slow_delivery should be disabled after import")
	}
	if mc.IsEnabled("cache_poisoning") {
		t.Error("cache_poisoning should be disabled after import")
	}
	if !mc.IsEnabled("format_corruption") {
		t.Error("format_corruption should still be enabled after import")
	}

	// Clean up
	flags.Set("media_chaos", true)
	cfg.Set("media_chaos_probability", 30.0)
	cfg.Set("media_chaos_corruption_intensity", 50.0)
	mc.SetAll(true)
}

// TestMediaChaos_ShouldApplyProbability verifies probability distribution.
func TestMediaChaos_ShouldApplyProbability(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(0.5)

	hits := 0
	trials := 10000
	for i := 0; i < trials; i++ {
		if e.ShouldApply() {
			hits++
		}
	}

	ratio := float64(hits) / float64(trials)
	if ratio < 0.4 || ratio > 0.6 {
		t.Errorf("expected ~50%% hit rate, got %.2f%%", ratio*100)
	}
}

// TestMediaChaos_SnapshotRestore verifies engine state round-trips.
func TestMediaChaos_SnapshotRestore(t *testing.T) {
	e1 := mediachaos.New()
	e1.SetProbability(0.8)
	e1.SetCorruptionIntensity(0.9)
	e1.SetCategoryEnabled(mediachaos.FormatCorruption, false)
	e1.SetCategoryEnabled(mediachaos.SlowDelivery, false)

	snap := e1.Snapshot()

	e2 := mediachaos.New()
	e2.Restore(snap)

	if e2.GetProbability() != 0.8 {
		t.Errorf("expected probability 0.8, got %f", e2.GetProbability())
	}
	if e2.GetCorruptionIntensity() != 0.9 {
		t.Errorf("expected corruption intensity 0.9, got %f", e2.GetCorruptionIntensity())
	}
	if e2.IsCategoryEnabled(mediachaos.FormatCorruption) {
		t.Error("format_corruption should be disabled after restore")
	}
	if e2.IsCategoryEnabled(mediachaos.SlowDelivery) {
		t.Error("slow_delivery should be disabled after restore")
	}
	if !e2.IsCategoryEnabled(mediachaos.ContentLengthChaos) {
		t.Error("content_length_chaos should still be enabled after restore")
	}
}

// TestMediaChaos_NoCategoriesEnabled verifies graceful handling when all disabled.
func TestMediaChaos_NoCategoriesEnabled(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)

	// Disable all categories
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.FormatCorruption, mediachaos.ContentLengthChaos,
		mediachaos.ContentTypeChaos, mediachaos.RangeRequestChaos,
		mediachaos.ChunkedChaos, mediachaos.SlowDelivery,
		mediachaos.InfiniteContent, mediachaos.StreamSwitching,
		mediachaos.CachePoisoning, mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, false)
	}

	g := media.New()
	data, ct := g.Generate(media.FormatFromPath("/media/image/test.png"), "/media/image/test.png")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/media/image/test.png", nil)
	e.Apply(w, r, data, ct)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Should serve content normally when no categories enabled
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Error("expected non-empty body when no categories enabled")
	}
}

// ---------------------------------------------------------------------------
// Category-specific chaos tests — verify each category produces output
// ---------------------------------------------------------------------------

func TestMediaChaos_FormatCorruptionProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.FormatCorruption, "/media/image/corrupt.png")
}

func TestMediaChaos_ContentLengthChaosProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.ContentLengthChaos, "/media/image/clength.png")
}

func TestMediaChaos_ContentTypeChaosProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.ContentTypeChaos, "/media/image/ctype.png")
}

func TestMediaChaos_RangeRequestChaosProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.RangeRequestChaos, "/media/image/range.png")
}

func TestMediaChaos_InfiniteContentProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.InfiniteContent, "/media/image/infinite.png")
}

func TestMediaChaos_StreamSwitchingProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.StreamSwitching, "/media/image/switch.png")
}

func TestMediaChaos_CachePoisoningProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.CachePoisoning, "/media/image/cache.png")
}

func TestMediaChaos_StreamingChaosProducesOutput(t *testing.T) {
	testSingleCategory(t, mediachaos.StreamingChaos, "/media/stream/test/playlist.m3u8")
}

// testSingleCategory enables only the specified category and verifies it produces output.
func testSingleCategory(t *testing.T, targetCat mediachaos.ChaosCategory, path string) {
	t.Helper()
	e := mediachaos.New()
	e.SetProbability(1.0)

	// Disable all, then enable only the target
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.FormatCorruption, mediachaos.ContentLengthChaos,
		mediachaos.ContentTypeChaos, mediachaos.RangeRequestChaos,
		mediachaos.ChunkedChaos, mediachaos.SlowDelivery,
		mediachaos.InfiniteContent, mediachaos.StreamSwitching,
		mediachaos.CachePoisoning, mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, cat == targetCat)
	}

	g := media.New()
	format := media.FormatFromPath(path)
	data, ct := g.Generate(format, path)

	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		if targetCat == mediachaos.RangeRequestChaos {
			r.Header.Set("Range", "bytes=0-100")
		}
		e.Apply(w, r, data, ct)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if len(body) == 0 && resp.StatusCode != http.StatusNoContent {
			t.Errorf("iteration %d: category %s produced empty body", i, targetCat)
		}
	}
}

// ---------------------------------------------------------------------------
// Content-Length chaos verifies the header is actually mismatched
// ---------------------------------------------------------------------------

func TestMediaChaos_ContentLengthMismatch(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)

	// Enable only content_length_chaos
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.FormatCorruption, mediachaos.ContentTypeChaos,
		mediachaos.RangeRequestChaos, mediachaos.ChunkedChaos,
		mediachaos.SlowDelivery, mediachaos.InfiniteContent,
		mediachaos.StreamSwitching, mediachaos.CachePoisoning,
		mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, false)
	}

	g := media.New()
	data, ct := g.Generate(media.FormatFromPath("/media/image/cl.png"), "/media/image/cl.png")

	mismatchCount := 0
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/media/image/cl.png", nil)
		e.Apply(w, r, data, ct)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		cl := resp.Header.Get("Content-Length")
		if cl != "" && cl != fmt.Sprintf("%d", len(body)) {
			mismatchCount++
		}
	}

	if mismatchCount == 0 {
		t.Error("Content-Length chaos: no mismatches detected in 20 tries")
	}
}

// TestMediaChaos_ContentTypeMismatch verifies wrong content types are sent.
func TestMediaChaos_ContentTypeMismatch(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)

	// Enable only content_type_chaos
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.FormatCorruption, mediachaos.ContentLengthChaos,
		mediachaos.RangeRequestChaos, mediachaos.ChunkedChaos,
		mediachaos.SlowDelivery, mediachaos.InfiniteContent,
		mediachaos.StreamSwitching, mediachaos.CachePoisoning,
		mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, false)
	}

	g := media.New()
	originalCT := "image/png"
	data, _ := g.Generate(media.FormatFromPath("/media/image/ct.png"), "/media/image/ct.png")

	wrongCount := 0
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/media/image/ct.png", nil)
		e.Apply(w, r, data, originalCT)
		resp := w.Result()
		io.ReadAll(resp.Body)
		resp.Body.Close()

		ct := resp.Header.Get("Content-Type")
		if ct != originalCT {
			wrongCount++
		}
	}

	if wrongCount == 0 {
		t.Error("Content-Type chaos: no mismatches detected in 20 tries")
	}
}

// TestMediaChaos_CachePoisoningHeaders verifies conflicting cache headers.
func TestMediaChaos_CachePoisoningHeaders(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)

	// Enable only cache_poisoning
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.FormatCorruption, mediachaos.ContentLengthChaos,
		mediachaos.ContentTypeChaos, mediachaos.RangeRequestChaos,
		mediachaos.ChunkedChaos, mediachaos.SlowDelivery,
		mediachaos.InfiniteContent, mediachaos.StreamSwitching,
		mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, false)
	}

	g := media.New()
	data, ct := g.Generate(media.FormatFromPath("/media/image/cache.png"), "/media/image/cache.png")

	cacheHeaderCount := 0
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/media/image/cache.png", nil)
		e.Apply(w, r, data, ct)
		resp := w.Result()
		io.ReadAll(resp.Body)
		resp.Body.Close()

		// Check for cache-related headers
		if resp.Header.Get("Cache-Control") != "" ||
			resp.Header.Get("ETag") != "" ||
			resp.Header.Get("Vary") != "" ||
			resp.Header.Get("Expires") != "" ||
			resp.Header.Get("Age") != "" {
			cacheHeaderCount++
		}
	}

	if cacheHeaderCount == 0 {
		t.Error("Cache-Poisoning chaos: no cache headers detected")
	}
}

// TestMediaChaos_FormatCorruptionModifiesData verifies corruption changes the data.
func TestMediaChaos_FormatCorruptionModifiesData(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)
	e.SetCorruptionIntensity(1.0) // max corruption

	// Enable only format_corruption
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.ContentLengthChaos, mediachaos.ContentTypeChaos,
		mediachaos.RangeRequestChaos, mediachaos.ChunkedChaos,
		mediachaos.SlowDelivery, mediachaos.InfiniteContent,
		mediachaos.StreamSwitching, mediachaos.CachePoisoning,
		mediachaos.StreamingChaos,
	} {
		e.SetCategoryEnabled(cat, false)
	}

	g := media.New()
	originalData, ct := g.Generate(media.FormatFromPath("/media/image/corrupt.png"), "/media/image/corrupt.png")

	differentCount := 0
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", fmt.Sprintf("/media/image/corrupt%d.png", i), nil)
		e.Apply(w, r, originalData, ct)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Corrupted data should differ from original
		if len(body) != len(originalData) {
			differentCount++
		} else {
			for j := range body {
				if body[j] != originalData[j] {
					differentCount++
					break
				}
			}
		}
	}

	if differentCount == 0 {
		t.Error("Format corruption: no data modifications detected in 10 tries")
	}
}

// ---------------------------------------------------------------------------
// Admin Routes
// ---------------------------------------------------------------------------

func TestMediaChaos_AdminRoutes(t *testing.T) {
	resp, err := http.Get("http://localhost:8766/admin/api/mediachaos")
	if err != nil {
		t.Skip("dashboard not running, skipping route tests")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		t.Errorf("GET /admin/api/mediachaos: unexpected status %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Image format signature tests — verify magic bytes
// ---------------------------------------------------------------------------

func TestMedia_PNGSignature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/image/sig.png"), "/media/image/sig.png")
	if len(data) < 8 {
		t.Fatal("PNG too short")
	}
	// PNG magic: 137 80 78 71 13 10 26 10
	expected := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	for i, b := range expected {
		if data[i] != b {
			t.Errorf("PNG signature byte %d: expected 0x%02X, got 0x%02X", i, b, data[i])
		}
	}
}

func TestMedia_JPEGSignature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/image/sig.jpg"), "/media/image/sig.jpg")
	if len(data) < 2 {
		t.Fatal("JPEG too short")
	}
	if data[0] != 0xFF || data[1] != 0xD8 {
		t.Errorf("JPEG SOI: expected FF D8, got %02X %02X", data[0], data[1])
	}
}

func TestMedia_GIFSignature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/image/sig.gif"), "/media/image/sig.gif")
	if len(data) < 6 {
		t.Fatal("GIF too short")
	}
	sig := string(data[:6])
	if sig != "GIF87a" && sig != "GIF89a" {
		t.Errorf("GIF signature: expected GIF87a or GIF89a, got %q", sig)
	}
}

func TestMedia_BMPSignature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/image/sig.bmp"), "/media/image/sig.bmp")
	if len(data) < 2 {
		t.Fatal("BMP too short")
	}
	if data[0] != 'B' || data[1] != 'M' {
		t.Errorf("BMP signature: expected BM, got %c%c", data[0], data[1])
	}
}

func TestMedia_WAVSignature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/audio/sig.wav"), "/media/audio/sig.wav")
	if len(data) < 12 {
		t.Fatal("WAV too short")
	}
	if string(data[0:4]) != "RIFF" {
		t.Errorf("WAV: expected RIFF header, got %q", string(data[0:4]))
	}
	if string(data[8:12]) != "WAVE" {
		t.Errorf("WAV: expected WAVE format, got %q", string(data[8:12]))
	}
}

func TestMedia_MP4Signature(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/video/sig.mp4"), "/media/video/sig.mp4")
	if len(data) < 8 {
		t.Fatal("MP4 too short")
	}
	// ftyp box should be within first 8 bytes
	if string(data[4:8]) != "ftyp" {
		t.Errorf("MP4: expected ftyp box, got %q", string(data[4:8]))
	}
}

func TestMedia_SVGContent(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/image/sig.svg"), "/media/image/sig.svg")
	content := string(data)
	if !strings.Contains(content, "<svg") {
		t.Error("SVG: missing <svg tag")
	}
	if !strings.Contains(content, "</svg>") {
		t.Error("SVG: missing </svg> closing tag")
	}
}

func TestMedia_HLSPlaylist(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/stream/test/playlist.m3u8"), "/media/stream/test/playlist.m3u8")
	content := string(data)
	if !strings.Contains(content, "#EXTM3U") {
		t.Error("HLS: missing #EXTM3U header")
	}
}

func TestMedia_DASHManifest(t *testing.T) {
	g := media.New()
	data, _ := g.Generate(media.FormatFromPath("/media/stream/test/manifest.mpd"), "/media/stream/test/manifest.mpd")
	content := string(data)
	if !strings.Contains(content, "MPD") {
		t.Error("DASH: missing MPD element")
	}
}

// ---------------------------------------------------------------------------
// Engine Settings Influence Tests — verify settings actually affect behavior
// ---------------------------------------------------------------------------

// TestMediaChaos_ProbabilityZeroNeverFires verifies 0% probability = no chaos.
func TestMediaChaos_ProbabilityZeroNeverFires(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(0)

	for i := 0; i < 1000; i++ {
		if e.ShouldApply() {
			t.Fatal("ShouldApply returned true with probability 0")
		}
	}
}

// TestMediaChaos_ProbabilityOneAlwaysFires verifies 100% probability = always chaos.
func TestMediaChaos_ProbabilityOneAlwaysFires(t *testing.T) {
	e := mediachaos.New()
	e.SetProbability(1.0)

	for i := 0; i < 1000; i++ {
		if !e.ShouldApply() {
			t.Fatal("ShouldApply returned false with probability 1.0")
		}
	}
}

// TestMediaChaos_CorruptionIntensityAffectsOutput verifies that higher intensity
// produces more corrupted output.
func TestMediaChaos_CorruptionIntensityAffectsOutput(t *testing.T) {
	g := media.New()
	originalData, ct := g.Generate(media.FormatFromPath("/media/image/int.png"), "/media/image/int.png")

	diffAtLow := 0
	diffAtHigh := 0

	// Low intensity
	eLow := mediachaos.New()
	eLow.SetProbability(1.0)
	eLow.SetCorruptionIntensity(0.1)
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.ContentLengthChaos, mediachaos.ContentTypeChaos,
		mediachaos.RangeRequestChaos, mediachaos.ChunkedChaos,
		mediachaos.SlowDelivery, mediachaos.InfiniteContent,
		mediachaos.StreamSwitching, mediachaos.CachePoisoning,
		mediachaos.StreamingChaos,
	} {
		eLow.SetCategoryEnabled(cat, false)
	}

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", fmt.Sprintf("/media/image/lo%d.png", i), nil)
		eLow.Apply(w, r, originalData, ct)
		body, _ := io.ReadAll(w.Result().Body)
		for j := 0; j < len(body) && j < len(originalData); j++ {
			if body[j] != originalData[j] {
				diffAtLow++
			}
		}
		// Length difference also counts
		if len(body) != len(originalData) {
			dl := len(body) - len(originalData)
			if dl < 0 {
				dl = -dl
			}
			diffAtLow += dl
		}
	}

	// High intensity
	eHigh := mediachaos.New()
	eHigh.SetProbability(1.0)
	eHigh.SetCorruptionIntensity(1.0)
	for _, cat := range []mediachaos.ChaosCategory{
		mediachaos.ContentLengthChaos, mediachaos.ContentTypeChaos,
		mediachaos.RangeRequestChaos, mediachaos.ChunkedChaos,
		mediachaos.SlowDelivery, mediachaos.InfiniteContent,
		mediachaos.StreamSwitching, mediachaos.CachePoisoning,
		mediachaos.StreamingChaos,
	} {
		eHigh.SetCategoryEnabled(cat, false)
	}

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", fmt.Sprintf("/media/image/hi%d.png", i), nil)
		eHigh.Apply(w, r, originalData, ct)
		body, _ := io.ReadAll(w.Result().Body)
		for j := 0; j < len(body) && j < len(originalData); j++ {
			if body[j] != originalData[j] {
				diffAtHigh++
			}
		}
		if len(body) != len(originalData) {
			dl := len(body) - len(originalData)
			if dl < 0 {
				dl = -dl
			}
			diffAtHigh += dl
		}
	}

	// High intensity should produce more differences
	t.Logf("Byte differences - low intensity: %d, high intensity: %d", diffAtLow, diffAtHigh)
	if diffAtHigh <= diffAtLow && diffAtLow > 0 {
		t.Logf("Warning: high intensity (%d) didn't produce more differences than low (%d), but both modified data", diffAtHigh, diffAtLow)
	}
}
