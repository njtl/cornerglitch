package mediachaos

import (
	"math/rand"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Engine creation & defaults
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New() returned nil")
	}
	if got := e.GetProbability(); got != 0.3 {
		t.Errorf("default probability = %f, want 0.3", got)
	}
	if got := e.GetCorruptionIntensity(); got != 0.5 {
		t.Errorf("default corruption intensity = %f, want 0.5", got)
	}
	cats := e.Categories()
	for _, c := range allCategories {
		if !cats[c] {
			t.Errorf("category %s not enabled by default", c)
		}
	}
}

// ---------------------------------------------------------------------------
// Probability
// ---------------------------------------------------------------------------

func TestSetProbability(t *testing.T) {
	e := New()
	for _, tc := range []struct {
		set, want float64
	}{
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{-0.1, 0.0},  // clamped
		{1.5, 1.0},   // clamped
	} {
		e.SetProbability(tc.set)
		if got := e.GetProbability(); got != tc.want {
			t.Errorf("SetProbability(%f): got %f, want %f", tc.set, got, tc.want)
		}
	}
}

func TestShouldApply_ZeroProbability(t *testing.T) {
	e := New()
	e.SetProbability(0.0)
	for i := 0; i < 100; i++ {
		if e.ShouldApply() {
			t.Fatal("ShouldApply() returned true with probability 0")
		}
	}
}

func TestShouldApply_OneProbability(t *testing.T) {
	e := New()
	e.SetProbability(1.0)
	for i := 0; i < 100; i++ {
		if !e.ShouldApply() {
			t.Fatal("ShouldApply() returned false with probability 1")
		}
	}
}

// ---------------------------------------------------------------------------
// Category enable/disable
// ---------------------------------------------------------------------------

func TestCategoryEnableDisable(t *testing.T) {
	e := New()
	e.SetCategoryEnabled(FormatCorruption, false)
	if e.IsCategoryEnabled(FormatCorruption) {
		t.Error("FormatCorruption should be disabled")
	}
	e.SetCategoryEnabled(FormatCorruption, true)
	if !e.IsCategoryEnabled(FormatCorruption) {
		t.Error("FormatCorruption should be enabled")
	}
}

func TestCategoriesSnapshot(t *testing.T) {
	e := New()
	snap := e.Categories()
	// Mutating the snapshot must not affect the engine.
	snap[FormatCorruption] = false
	if !e.IsCategoryEnabled(FormatCorruption) {
		t.Error("snapshot mutation leaked into engine")
	}
}

// ---------------------------------------------------------------------------
// Corruption intensity
// ---------------------------------------------------------------------------

func TestSetCorruptionIntensity(t *testing.T) {
	e := New()
	for _, tc := range []struct {
		set, want float64
	}{
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{-0.1, 0.0},
		{1.5, 1.0},
	} {
		e.SetCorruptionIntensity(tc.set)
		if got := e.GetCorruptionIntensity(); got != tc.want {
			t.Errorf("SetCorruptionIntensity(%f): got %f, want %f", tc.set, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Slow delivery config
// ---------------------------------------------------------------------------

func TestSlowDeliveryConfig(t *testing.T) {
	e := New()
	e.SetSlowMinMs(50)
	e.SetSlowMaxMs(200)
	// No getter exposed — just ensure no panic.
}

func TestInfiniteMaxBytesConfig(t *testing.T) {
	e := New()
	e.SetInfiniteMaxBytes(1024)
	// No getter exposed — just ensure no panic.
}

// ---------------------------------------------------------------------------
// Snapshot & Restore
// ---------------------------------------------------------------------------

func TestSnapshotRestore(t *testing.T) {
	e := New()
	e.SetProbability(0.75)
	e.SetCorruptionIntensity(0.9)
	e.SetCategoryEnabled(SlowDelivery, false)
	e.SetSlowMinMs(20)
	e.SetSlowMaxMs(500)
	e.SetInfiniteMaxBytes(2048)

	snap := e.Snapshot()

	e2 := New()
	e2.Restore(snap)

	if got := e2.GetProbability(); got != 0.75 {
		t.Errorf("restored probability = %f, want 0.75", got)
	}
	if got := e2.GetCorruptionIntensity(); got != 0.9 {
		t.Errorf("restored corruptionIntensity = %f, want 0.9", got)
	}
	if e2.IsCategoryEnabled(SlowDelivery) {
		t.Error("SlowDelivery should be disabled after restore")
	}
}

func TestRestore_PartialSnapshot(t *testing.T) {
	e := New()
	e.SetProbability(0.1)
	// Restore with only probability — other fields stay at previous values.
	e.Restore(map[string]interface{}{"probability": 0.8})
	if got := e.GetProbability(); got != 0.8 {
		t.Errorf("probability = %f, want 0.8", got)
	}
	if got := e.GetCorruptionIntensity(); got != 0.5 {
		t.Errorf("corruptionIntensity should stay at default 0.5, got %f", got)
	}
}

func TestRestore_CategoriesAsMapStringInterface(t *testing.T) {
	// JSON unmarshalling produces map[string]interface{}, not map[string]bool.
	e := New()
	e.Restore(map[string]interface{}{
		"categories": map[string]interface{}{
			"format_corruption": false,
		},
	})
	if e.IsCategoryEnabled(FormatCorruption) {
		t.Error("FormatCorruption should be disabled via map[string]interface{} restore")
	}
}

func TestRestore_ClampsValues(t *testing.T) {
	e := New()
	e.Restore(map[string]interface{}{
		"probability":         2.0,
		"corruptionIntensity": -1.0,
	})
	if got := e.GetProbability(); got != 1.0 {
		t.Errorf("probability should clamp to 1.0, got %f", got)
	}
	if got := e.GetCorruptionIntensity(); got != 0.0 {
		t.Errorf("corruptionIntensity should clamp to 0.0, got %f", got)
	}
}

// ---------------------------------------------------------------------------
// Apply — no categories enabled → passthrough
// ---------------------------------------------------------------------------

func TestApply_NoCategoriesEnabled(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}

	body := []byte("hello world test data that should pass through")
	ct := "text/plain"
	r := httptest.NewRequest("GET", "/media/test.txt", nil)
	w := httptest.NewRecorder()

	e.Apply(w, r, body, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Header().Get("Content-Type") != ct {
		t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), ct)
	}
	if w.Body.String() != string(body) {
		t.Error("body was modified despite no categories enabled")
	}
}

// ---------------------------------------------------------------------------
// Apply — deterministic category selection
// ---------------------------------------------------------------------------

func TestApply_DeterministicCategorySelection(t *testing.T) {
	// With all categories enabled, the same path should always pick the same category.
	// We verify by enabling only one category at a time and checking the response differs.
	// More directly: calling Apply twice with the same path yields the same result.
	e := New()
	e.SetProbability(1.0)
	// Only enable FormatCorruption so we get deterministic output.
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(FormatCorruption, true)

	body := makeSamplePNG()
	ct := "image/png"

	r1 := httptest.NewRequest("GET", "/media/test.png", nil)
	w1 := httptest.NewRecorder()
	e.Apply(w1, r1, body, ct)

	r2 := httptest.NewRequest("GET", "/media/test.png", nil)
	w2 := httptest.NewRecorder()
	e.Apply(w2, r2, body, ct)

	if w1.Body.String() != w2.Body.String() {
		t.Error("Apply should produce deterministic output for the same path")
	}
}

// ---------------------------------------------------------------------------
// Apply — each chaos category produces a response
// ---------------------------------------------------------------------------

func TestApply_EachCategory(t *testing.T) {
	body := makeSamplePNG()
	ct := "image/png"

	for _, cat := range allCategories {
		// Skip SlowDelivery and InfiniteContent in tests — they're slow.
		if cat == SlowDelivery || cat == InfiniteContent {
			continue
		}
		t.Run(string(cat), func(t *testing.T) {
			e := New()
			e.SetProbability(1.0)
			e.SetSlowMinMs(0)
			e.SetSlowMaxMs(1)
			e.SetInfiniteMaxBytes(100)
			for _, c := range allCategories {
				e.SetCategoryEnabled(c, false)
			}
			e.SetCategoryEnabled(cat, true)

			r := httptest.NewRequest("GET", "/media/test.png", nil)
			w := httptest.NewRecorder()
			e.Apply(w, r, body, ct)

			// ChunkedChaos falls back to ContentLengthChaos with httptest.ResponseRecorder
			// (no Hijacker support). All categories should produce status 200 or 206.
			if w.Code != 200 && w.Code != 206 {
				t.Errorf("status = %d, want 200 or 206", w.Code)
			}
			if w.Body.Len() == 0 {
				t.Error("empty response body")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Format corruption — all 18 formats
// ---------------------------------------------------------------------------

func TestFormatCorruption_AllFormats(t *testing.T) {
	type formatCase struct {
		name        string
		contentType string
		sampleData  func() []byte
	}

	cases := []formatCase{
		{"PNG", "image/png", makeSamplePNG},
		{"JPEG", "image/jpeg", makeSampleJPEG},
		{"GIF", "image/gif", makeSampleGIF},
		{"WebP", "image/webp", makeSampleWebP},
		{"BMP", "image/bmp", makeSampleBMP},
		{"SVG", "image/svg+xml", makeSampleSVG},
		{"ICO", "image/x-icon", makeSampleICO},
		{"TIFF", "image/tiff", makeSampleTIFF},
		{"WAV", "audio/wav", makeSampleWAV},
		{"MP3", "audio/mpeg", makeSampleMP3},
		{"OGG", "audio/ogg", makeSampleOGG},
		{"FLAC", "audio/flac", makeSampleFLAC},
		{"MP4", "video/mp4", makeSampleMP4},
		{"WebM", "video/webm", makeSampleWebM},
		{"AVI", "video/x-msvideo", makeSampleAVI},
		{"TS", "video/mp2t", makeSampleTS},
		{"HLS", "application/vnd.apple.mpegurl", makeSampleHLS},
		{"DASH", "application/dash+xml", makeSampleDASH},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.sampleData()
			e := New()
			for _, c := range allCategories {
				e.SetCategoryEnabled(c, false)
			}
			e.SetCategoryEnabled(FormatCorruption, true)

			r := httptest.NewRequest("GET", "/media/test."+strings.ToLower(tc.name), nil)
			w := httptest.NewRecorder()
			e.Apply(w, r, data, tc.contentType)

			if w.Code != 200 {
				t.Errorf("status = %d, want 200", w.Code)
			}
			if w.Body.Len() == 0 {
				t.Error("empty response body after corruption")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Format corruption — extension fallbacks
// ---------------------------------------------------------------------------

func TestFormatCorruption_ExtensionFallback(t *testing.T) {
	cases := []struct {
		ext         string
		contentType string // generic/unknown content-type
		sampleData  func() []byte
	}{
		{".webp", "application/octet-stream", makeSampleWebP},
		{".bmp", "application/octet-stream", makeSampleBMP},
		{".svg", "application/octet-stream", makeSampleSVG},
		{".ico", "application/octet-stream", makeSampleICO},
		{".tiff", "application/octet-stream", makeSampleTIFF},
		{".mp3", "application/octet-stream", makeSampleMP3},
		{".ogg", "application/octet-stream", makeSampleOGG},
		{".flac", "application/octet-stream", makeSampleFLAC},
		{".mp4", "application/octet-stream", makeSampleMP4},
		{".webm", "application/octet-stream", makeSampleWebM},
		{".avi", "application/octet-stream", makeSampleAVI},
		{".ts", "application/octet-stream", makeSampleTS},
		{".m3u8", "application/octet-stream", makeSampleHLS},
		{".mpd", "application/octet-stream", makeSampleDASH},
	}

	for _, tc := range cases {
		t.Run(tc.ext, func(t *testing.T) {
			data := tc.sampleData()
			e := New()
			for _, c := range allCategories {
				e.SetCategoryEnabled(c, false)
			}
			e.SetCategoryEnabled(FormatCorruption, true)

			r := httptest.NewRequest("GET", "/media/file"+tc.ext, nil)
			w := httptest.NewRecorder()
			e.Apply(w, r, data, tc.contentType)

			if w.Code != 200 {
				t.Errorf("status = %d, want 200", w.Code)
			}
			if w.Body.Len() == 0 {
				t.Error("empty response body for extension fallback")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Corruption produces different output from input
// ---------------------------------------------------------------------------

func TestCorruption_ModifiesData(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	data := makeSamplePNG()
	corrupted := corruptPNG(data, 0.8, rng)

	if len(corrupted) == 0 {
		t.Fatal("corruption produced empty output")
	}
	// With intensity 0.8 on a real PNG, output should differ.
	same := true
	if len(data) != len(corrupted) {
		same = false
	} else {
		for i := range data {
			if data[i] != corrupted[i] {
				same = false
				break
			}
		}
	}
	if same {
		t.Error("corruption at intensity 0.8 produced identical output")
	}
}

// ---------------------------------------------------------------------------
// Corruption intensity levels
// ---------------------------------------------------------------------------

func TestIntensityLevel(t *testing.T) {
	cases := []struct {
		intensity float64
		want      int
	}{
		{0.0, 0},
		{0.2, 0},
		{0.32, 0},
		{0.33, 1}, // boundary: < 0.33 → 0, >= 0.33 → 1
		{0.5, 1},
		{0.66, 1},
		{0.67, 2}, // boundary: < 0.67 → 1, >= 0.67 → 2
		{0.8, 2},
		{1.0, 2},
	}
	for _, tc := range cases {
		got := intensityLevel(tc.intensity)
		if got != tc.want {
			t.Errorf("intensityLevel(%f) = %d, want %d", tc.intensity, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Corruption — small/empty data doesn't panic
// ---------------------------------------------------------------------------

func TestCorruption_SmallData(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	fns := []struct {
		name string
		fn   func([]byte, float64, *rand.Rand) []byte
	}{
		{"corruptPNG", corruptPNG},
		{"corruptJPEG", corruptJPEG},
		{"corruptGIF", corruptGIF},
		{"corruptWebP", corruptWebP},
		{"corruptBMP", corruptBMP},
		{"corruptSVG", corruptSVG},
		{"corruptICO", corruptICO},
		{"corruptTIFF", corruptTIFF},
		{"corruptWAV", corruptWAV},
		{"corruptMP3", corruptMP3},
		{"corruptOGG", corruptOGG},
		{"corruptFLAC", corruptFLAC},
		{"corruptMP4", corruptMP4},
		{"corruptWebM", corruptWebM},
		{"corruptAVI", corruptAVI},
		{"corruptTS", corruptTS},
	}

	for _, tc := range fns {
		t.Run(tc.name+"_empty", func(t *testing.T) {
			_ = tc.fn([]byte{}, 0.5, rng)
		})
		t.Run(tc.name+"_small", func(t *testing.T) {
			_ = tc.fn([]byte{0x01, 0x02, 0x03}, 0.5, rng)
		})
	}

	// HLS and DASH take no rng/intensity.
	t.Run("corruptHLS_empty", func(t *testing.T) { _ = corruptHLS([]byte{}) })
	t.Run("corruptHLS_small", func(t *testing.T) { _ = corruptHLS([]byte("short")) })
	t.Run("corruptDASH_empty", func(t *testing.T) { _ = corruptDASH([]byte{}) })
	t.Run("corruptDASH_small", func(t *testing.T) { _ = corruptDASH([]byte("short")) })
}

// ---------------------------------------------------------------------------
// ContentLengthChaos — header mismatch
// ---------------------------------------------------------------------------

func TestContentLengthChaos(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(ContentLengthChaos, true)

	body := makeSamplePNG()
	ct := "image/png"

	// Run several times to hit different variants.
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/media/cl-test.png", nil)
		w := httptest.NewRecorder()
		e.Apply(w, r, body, ct)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// ContentTypeChaos — wrong/missing content-type
// ---------------------------------------------------------------------------

func TestContentTypeChaos(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(ContentTypeChaos, true)

	body := makeSamplePNG()
	ct := "image/png"

	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/media/ct-test.png", nil)
		w := httptest.NewRecorder()
		e.Apply(w, r, body, ct)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// RangeRequestChaos — with and without Range header
// ---------------------------------------------------------------------------

func TestRangeRequestChaos_WithRange(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(RangeRequestChaos, true)

	body := makeSamplePNG()
	ct := "image/png"

	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/media/range-test.png", nil)
		r.Header.Set("Range", "bytes=0-99")
		w := httptest.NewRecorder()
		e.Apply(w, r, body, ct)

		if w.Code != 200 && w.Code != 206 {
			t.Errorf("status = %d, want 200 or 206", w.Code)
		}
	}
}

func TestRangeRequestChaos_WithoutRange(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(RangeRequestChaos, true)

	body := makeSamplePNG()
	ct := "image/png"

	r := httptest.NewRequest("GET", "/media/range-test2.png", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, body, ct)

	// Without Range header, should serve normally.
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.String() != string(body) {
		t.Error("body should be unmodified when no Range header")
	}
}

// ---------------------------------------------------------------------------
// ChunkedChaos — falls back since httptest.ResponseRecorder doesn't support Hijack
// ---------------------------------------------------------------------------

func TestChunkedChaos_FallbackToContentLength(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(ChunkedChaos, true)

	body := makeSamplePNG()
	ct := "image/png"

	r := httptest.NewRequest("GET", "/media/chunked-test.png", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, body, ct)

	// Should fall back to ContentLengthChaos.
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body")
	}
}

// ---------------------------------------------------------------------------
// StreamSwitching — produces some response
// ---------------------------------------------------------------------------

func TestStreamSwitching(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(StreamSwitching, true)

	body := makeSamplePNG()
	ct := "image/png"

	for i := 0; i < 10; i++ {
		r := httptest.NewRequest("GET", "/media/switch-test.png", nil)
		w := httptest.NewRecorder()
		e.Apply(w, r, body, ct)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
		if w.Body.Len() == 0 {
			t.Error("empty response body")
		}
	}
}

// ---------------------------------------------------------------------------
// CachePoisoning — conflicting cache headers
// ---------------------------------------------------------------------------

func TestCachePoisoning(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(CachePoisoning, true)

	body := makeSamplePNG()
	ct := "image/png"

	for i := 0; i < 20; i++ {
		r := httptest.NewRequest("GET", "/media/cache-test.png", nil)
		w := httptest.NewRecorder()
		e.Apply(w, r, body, ct)

		if w.Code != 200 {
			t.Errorf("status = %d, want 200", w.Code)
		}
		// Body should be the original data (cache poisoning only affects headers).
		if w.Body.String() != string(body) {
			t.Error("body should be unmodified for cache poisoning")
		}
	}
}

// ---------------------------------------------------------------------------
// StreamingChaos — HLS playlist corruption
// ---------------------------------------------------------------------------

func TestStreamingChaos_HLS(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(StreamingChaos, true)

	data := makeSampleHLS()
	ct := "application/vnd.apple.mpegurl"

	r := httptest.NewRequest("GET", "/media/stream.m3u8", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, data, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body for HLS streaming chaos")
	}
}

func TestStreamingChaos_DASH(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(StreamingChaos, true)

	data := makeSampleDASH()
	ct := "application/dash+xml"

	r := httptest.NewRequest("GET", "/media/stream.mpd", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, data, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body for DASH streaming chaos")
	}
}

func TestStreamingChaos_FallbackToGenericCorruption(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(StreamingChaos, true)

	data := makeSamplePNG()
	ct := "image/png"

	r := httptest.NewRequest("GET", "/media/fallback.png", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, data, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body for streaming chaos fallback")
	}
}

// ---------------------------------------------------------------------------
// HLS corruption specifics
// ---------------------------------------------------------------------------

func TestCorruptHLS_ValidPlaylist(t *testing.T) {
	data := makeSampleHLS()
	for i := 0; i < 20; i++ {
		result := corruptHLS(data)
		if len(result) == 0 {
			t.Fatal("corruptHLS produced empty output")
		}
	}
}

// ---------------------------------------------------------------------------
// DASH corruption specifics
// ---------------------------------------------------------------------------

func TestCorruptDASH_ValidManifest(t *testing.T) {
	data := makeSampleDASH()
	for i := 0; i < 20; i++ {
		result := corruptDASH(data)
		if len(result) == 0 {
			t.Fatal("corruptDASH produced empty output")
		}
	}
}

// ---------------------------------------------------------------------------
// corruptGeneric — covers all variant paths
// ---------------------------------------------------------------------------

func TestCorruptGeneric(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	for seed := int64(0); seed < 30; seed++ {
		rng := rand.New(rand.NewSource(seed))
		result := corruptGeneric(data, 0.5, rng)
		if len(result) == 0 {
			t.Fatalf("corruptGeneric produced empty output at seed %d", seed)
		}
	}
}

// ---------------------------------------------------------------------------
// wrongContentType
// ---------------------------------------------------------------------------

func TestWrongContentType(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"image/png", "video/mp4"},
		{"image/jpeg", "audio/mpeg"},
		{"image/gif", "application/pdf"},
		{"video/mp4", "image/png"},
		{"audio/mpeg", "image/jpeg"},
		{"audio/wav", "video/webm"},
		{"application/vnd.apple.mpegurl", "text/plain"},
		{"application/dash+xml", "text/html"},
		{"text/html", "application/octet-stream"}, // fallback
	}
	for _, tc := range cases {
		got := wrongContentType(tc.input)
		if got != tc.want {
			t.Errorf("wrongContentType(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// switchedFormatData
// ---------------------------------------------------------------------------

func TestSwitchedFormatData(t *testing.T) {
	cases := []struct {
		ct     string
		prefix []byte
	}{
		{"image/png", []byte{0xFF, 0xD8}},         // JPEG SOI
		{"image/jpeg", []byte{0x89, 0x50, 0x4E}},  // PNG magic
		{"video/mp4", []byte{0x1A, 0x45, 0xDF}},   // WebM EBML
		{"audio/mpeg", []byte("RIFF")},             // WAV
		{"text/plain", []byte("%PDF")},             // default: PDF
	}
	for _, tc := range cases {
		data := switchedFormatData(tc.ct)
		if len(data) < len(tc.prefix) {
			t.Errorf("switchedFormatData(%q) too short", tc.ct)
			continue
		}
		for i, b := range tc.prefix {
			if data[i] != b {
				t.Errorf("switchedFormatData(%q)[%d] = 0x%02X, want 0x%02X", tc.ct, i, data[i], b)
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	e := New()
	done := make(chan struct{})

	// Writer goroutine — configures the engine.
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			e.SetProbability(float64(i%10) / 10.0)
			e.SetCorruptionIntensity(float64(i%10) / 10.0)
			e.SetCategoryEnabled(FormatCorruption, i%2 == 0)
			_ = e.Snapshot()
			_ = e.Categories()
			e.Restore(map[string]interface{}{"probability": 0.5})
		}
	}()

	// Reader goroutine — applies chaos.
	body := makeSamplePNG()
	for i := 0; i < 200; i++ {
		r := httptest.NewRequest("GET", "/media/concurrent.png", nil)
		w := httptest.NewRecorder()
		e.Apply(w, r, body, "image/png")
		_ = e.ShouldApply()
		_ = e.GetProbability()
		_ = e.GetCorruptionIntensity()
	}

	<-done
}

// ---------------------------------------------------------------------------
// Sample data generators — minimal valid structures for each format
// ---------------------------------------------------------------------------

func makeSamplePNG() []byte {
	// Minimal valid PNG: magic + IHDR + empty IDAT + IEND.
	data := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
		0x00, 0x00, 0x00, 0x0D, // IHDR length = 13
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // width = 1
		0x00, 0x00, 0x00, 0x01, // height = 1
		0x08, 0x02, // 8-bit RGB
		0x00, 0x00, 0x00, // compression, filter, interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
	}
	// Pad to reasonable size.
	padding := make([]byte, 100)
	return append(data, padding...)
}

func makeSampleJPEG() []byte {
	data := []byte{
		0xFF, 0xD8, 0xFF, 0xE0, // SOI + APP0 marker
		0x00, 0x10, // length
		0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
	}
	padding := make([]byte, 100)
	data = append(data, padding...)
	data = append(data, 0xFF, 0xD9) // EOI
	return data
}

func makeSampleGIF() []byte {
	data := []byte("GIF89a")
	data = append(data, 0x01, 0x00, 0x01, 0x00) // 1x1
	data = append(data, 0x80, 0x00, 0x00)        // GCT flag, bg, aspect
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleWebP() []byte {
	// RIFF....WEBPVP8L
	data := []byte("RIFF")
	data = append(data, 0x00, 0x00, 0x00, 0x00) // file size placeholder
	data = append(data, []byte("WEBP")...)
	data = append(data, []byte("VP8L")...)
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleBMP() []byte {
	data := []byte{'B', 'M'}
	data = append(data, make([]byte, 52)...) // header
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleSVG() []byte {
	return []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect x="0" y="0" width="100" height="100" fill="red"/></svg>`)
}

func makeSampleICO() []byte {
	data := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00} // ICO magic + 1 image
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleTIFF() []byte {
	// Little-endian TIFF.
	data := []byte{'I', 'I', 0x2A, 0x00}
	data = append(data, 0x08, 0x00, 0x00, 0x00) // IFD offset
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleWAV() []byte {
	data := []byte("RIFF")
	data = append(data, 0x00, 0x00, 0x00, 0x00) // file size placeholder
	data = append(data, []byte("WAVEfmt ")...)
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleMP3() []byte {
	// ID3v2 header + sync bytes.
	data := []byte("ID3")
	data = append(data, 0x03, 0x00, 0x00) // version 2.3
	data = append(data, make([]byte, 100)...)
	// Add frame sync.
	data = append(data, 0xFF, 0xFB, 0x90, 0x00)
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleOGG() []byte {
	data := []byte("OggS")
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleFLAC() []byte {
	data := []byte("fLaC")
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleMP4() []byte {
	// ftyp box.
	data := []byte{
		0x00, 0x00, 0x00, 0x14, // size = 20
		0x66, 0x74, 0x79, 0x70, // "ftyp"
		0x69, 0x73, 0x6F, 0x6D, // "isom"
		0x00, 0x00, 0x00, 0x00, // minor version
		0x69, 0x73, 0x6F, 0x6D, // "isom" compatible
	}
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleWebM() []byte {
	data := []byte{0x1A, 0x45, 0xDF, 0xA3} // EBML magic
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleAVI() []byte {
	data := []byte("RIFF")
	data = append(data, 0x00, 0x00, 0x00, 0x00) // size
	data = append(data, []byte("AVI ")...)
	data = append(data, make([]byte, 100)...)
	return data
}

func makeSampleTS() []byte {
	// TS packets are 188 bytes starting with 0x47.
	data := make([]byte, 0, 188*3)
	for i := 0; i < 3; i++ {
		pkt := make([]byte, 188)
		pkt[0] = 0x47
		data = append(data, pkt...)
	}
	return data
}

func makeSampleHLS() []byte {
	return []byte(`#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
segment0.ts
#EXTINF:10.0,
segment1.ts
#EXTINF:10.0,
segment2.ts
#EXT-X-ENDLIST
`)
}

func makeSampleDASH() []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static" mediaPresentationDuration="PT60S">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <Representation id="1" bandwidth="1000000" width="1280" height="720">
        <BaseURL>video.mp4</BaseURL>
      </Representation>
    </AdaptationSet>
  </Period>
</MPD>
`)
}

// ---------------------------------------------------------------------------
// Apply method via full HTTP handler path verification
// ---------------------------------------------------------------------------

func TestApply_WritesContentTypeHeader(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(CachePoisoning, true) // Preserves original content-type.

	body := makeSamplePNG()
	ct := "image/png"
	r := httptest.NewRequest("GET", "/media/header-test.png", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, body, ct)

	got := w.Header().Get("Content-Type")
	if got != ct {
		t.Errorf("Content-Type = %q, want %q", got, ct)
	}
}

// ---------------------------------------------------------------------------
// Apply with InfiniteContent (capped for test)
// ---------------------------------------------------------------------------

func TestApply_InfiniteContent_Capped(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(InfiniteContent, true)
	e.SetInfiniteMaxBytes(512) // Small cap for fast test.

	body := makeSamplePNG()
	ct := "image/png"
	r := httptest.NewRequest("GET", "/media/infinite-test.png", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, body, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	// Body should be >= original data + some garbage.
	if w.Body.Len() < len(body) {
		t.Errorf("body len = %d, want >= %d", w.Body.Len(), len(body))
	}
}

// ---------------------------------------------------------------------------
// Apply with SlowDelivery (minimal delay for test)
// ---------------------------------------------------------------------------

func TestApply_SlowDelivery_MinimalDelay(t *testing.T) {
	e := New()
	for _, c := range allCategories {
		e.SetCategoryEnabled(c, false)
	}
	e.SetCategoryEnabled(SlowDelivery, true)
	e.SetSlowMinMs(0)
	e.SetSlowMaxMs(1) // Minimal delay.

	body := []byte("quick test data")
	ct := "text/plain"
	r := httptest.NewRequest("GET", "/media/slow-test.txt", nil)
	w := httptest.NewRecorder()
	e.Apply(w, r, body, ct)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body")
	}
}

// ---------------------------------------------------------------------------
// All chaos categories are in allCategories
// ---------------------------------------------------------------------------

func TestAllCategoriesCompleteness(t *testing.T) {
	expected := []ChaosCategory{
		FormatCorruption,
		ContentLengthChaos,
		ContentTypeChaos,
		RangeRequestChaos,
		ChunkedChaos,
		SlowDelivery,
		InfiniteContent,
		StreamSwitching,
		CachePoisoning,
		StreamingChaos,
	}
	if len(allCategories) != len(expected) {
		t.Fatalf("allCategories has %d entries, want %d", len(allCategories), len(expected))
	}
	m := make(map[ChaosCategory]bool)
	for _, c := range allCategories {
		m[c] = true
	}
	for _, c := range expected {
		if !m[c] {
			t.Errorf("missing category %s in allCategories", c)
		}
	}
}
