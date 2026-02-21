package headers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNewEngine(t *testing.T) {
	eng := NewEngine()
	if eng == nil {
		t.Fatal("NewEngine returned nil")
	}
}

// --- ShouldCorrupt ---

func TestShouldCorrupt_BrowserExempt(t *testing.T) {
	eng := NewEngine()
	if eng.ShouldCorrupt("browser") {
		t.Error("ShouldCorrupt should return false for browser")
	}
}

func TestShouldCorrupt_ScrapersCorrupted(t *testing.T) {
	eng := NewEngine()
	classes := []string{
		"ai_scraper", "script_bot", "load_tester",
		"api_tester", "search_bot", "unknown",
	}
	for _, cls := range classes {
		if !eng.ShouldCorrupt(cls) {
			t.Errorf("ShouldCorrupt should return true for %q", cls)
		}
	}
}

func TestShouldCorrupt_UnrecognizedClass(t *testing.T) {
	eng := NewEngine()
	if !eng.ShouldCorrupt("something_new") {
		t.Error("ShouldCorrupt should return true for unrecognized class")
	}
}

// --- LevelNone ---

func TestApply_NoneLevel_NoHeaders(t *testing.T) {
	eng := NewEngine()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	eng.Apply(rec, req, "client-abc", LevelNone)

	// No custom headers should be set
	for k := range rec.Header() {
		if strings.HasPrefix(k, "X-") || k == "Set-Cookie" || k == "Content-Security-Policy" {
			t.Errorf("LevelNone should not set header %q", k)
		}
	}
}

// --- LevelSubtle ---

func TestApply_Subtle_ProducesExpectedHeaders(t *testing.T) {
	eng := NewEngine()

	// Run many seeds to get coverage of probabilistic techniques
	found := map[string]bool{
		"Set-Cookie":              false,
		"Vary":                    false,
		"X-Robots-Tag":           false,
		"Content-Security-Policy": false,
	}
	frameworkHeaders := map[string]bool{
		"X-Powered-By":    false,
		"X-AspNet-Version": false,
		"Server":           false,
		"X-Generator":      false,
		"X-Drupal-Cache":   false,
	}

	for i := 0; i < 200; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/page-%d", i), nil)
		clientID := fmt.Sprintf("client-subtle-%d", i)
		eng.Apply(rec, req, clientID, LevelSubtle)

		for k := range found {
			if rec.Header().Get(k) != "" || len(rec.Header()[k]) > 0 {
				found[k] = true
			}
		}
		for k := range frameworkHeaders {
			if rec.Header().Get(k) != "" {
				frameworkHeaders[k] = true
			}
		}
	}

	for k, v := range found {
		if !v {
			t.Errorf("subtle level never produced header %q across 200 requests", k)
		}
	}

	// At least one framework header should have appeared
	anyFramework := false
	for _, v := range frameworkHeaders {
		if v {
			anyFramework = true
			break
		}
	}
	if !anyFramework {
		t.Error("subtle level never produced any framework header")
	}
}

func TestApply_Subtle_SetCookieDuplicates(t *testing.T) {
	eng := NewEngine()

	// Try many seeds until we find one that triggers the cookie technique
	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/dup-cookie-test-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-cookie-dup-%d", i), LevelSubtle)

		cookies := rec.Header()["Set-Cookie"]
		if len(cookies) >= 2 {
			// Verify we have both a session cookie and a trap cookie
			hasSession := false
			hasTrap := false
			for _, c := range cookies {
				if strings.Contains(c, "sid=") {
					hasSession = true
				}
				if strings.Contains(c, "Max-Age=0") && strings.Contains(c, "Expires=") {
					hasTrap = true
				}
			}
			if hasSession && hasTrap {
				return // success
			}
		}
	}
	t.Error("never produced duplicate Set-Cookie with session + trap cookie")
}

func TestApply_Subtle_HTTPCompliance(t *testing.T) {
	// Subtle level should not set headers that break standard HTTP.
	// Specifically: no Content-Length mismatch, no Content-Encoding lies,
	// no Transfer-Encoding manipulation.
	eng := NewEngine()

	for i := 0; i < 200; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/compliance-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-compliance-%d", i), LevelSubtle)

		if cl := rec.Header().Get("Content-Length"); cl != "" {
			t.Errorf("subtle level should not set Content-Length, got %q", cl)
		}
		if ce := rec.Header().Get("Content-Encoding"); ce != "" {
			t.Errorf("subtle level should not set Content-Encoding, got %q", ce)
		}
		if te := rec.Header().Get("Transfer-Encoding"); te != "" {
			t.Errorf("subtle level should not set Transfer-Encoding, got %q", te)
		}
	}
}

// --- LevelModerate ---

func TestApply_Moderate_DuplicateContentType(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/mod-ct-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-mod-%d", i), LevelModerate)

		ct := rec.Header()["Content-Type"]
		if len(ct) >= 2 {
			if ct[0] != "application/json; charset=utf-8" {
				t.Errorf("first Content-Type should be application/json, got %q", ct[0])
			}
			if ct[1] != "text/html; charset=utf-8" {
				t.Errorf("second Content-Type should be text/html, got %q", ct[1])
			}
			return // success
		}
	}
	t.Error("moderate level never produced duplicate Content-Type headers")
}

func TestApply_Moderate_ConflictingCacheControl(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/mod-cache-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-cache-%d", i), LevelModerate)

		cc := rec.Header()["Cache-Control"]
		if len(cc) >= 2 {
			hasPublic := false
			hasNoCache := false
			for _, v := range cc {
				if strings.Contains(v, "public") {
					hasPublic = true
				}
				if strings.Contains(v, "no-cache") {
					hasNoCache = true
				}
			}
			if hasPublic && hasNoCache {
				return // success
			}
		}
	}
	t.Error("moderate level never produced conflicting Cache-Control headers")
}

func TestApply_Moderate_TraceHeaders(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/mod-trace-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-trace-%d", i), LevelModerate)

		traceCount := 0
		for k := range rec.Header() {
			if strings.HasPrefix(k, "X-Trace-") {
				traceCount++
			}
		}
		if traceCount >= 15 {
			// Verify each trace header is ~1KB
			for k, vals := range rec.Header() {
				if strings.HasPrefix(k, "X-Trace-") {
					for _, v := range vals {
						if len(v) < 500 {
							t.Errorf("X-Trace header value too short: %d bytes", len(v))
						}
					}
				}
			}
			return // success
		}
	}
	t.Error("moderate level never produced long X-Trace headers")
}

func TestApply_Moderate_ETag(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/mod-etag-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-etag-%d", i), LevelModerate)

		etag := rec.Header().Get("ETag")
		if etag != "" {
			if !strings.HasPrefix(etag, `W/"`) {
				t.Errorf("ETag should be a weak validator, got %q", etag)
			}
			return // success
		}
	}
	t.Error("moderate level never produced ETag header")
}

func TestApply_Moderate_WrongDomainCookie(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/mod-domain-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-domain-%d", i), LevelModerate)

		for _, cookie := range rec.Header()["Set-Cookie"] {
			if strings.Contains(cookie, "different-domain.com") {
				return // success
			}
		}
	}
	t.Error("moderate level never produced wrong-domain cookie")
}

// --- LevelAggressive ---

func TestApply_Aggressive_ContentLengthMismatch(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/agg-cl-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-agg-cl-%d", i), LevelAggressive)

		cl := rec.Header().Get("Content-Length")
		if cl != "" {
			return // success
		}
	}
	t.Error("aggressive level never produced Content-Length mismatch")
}

func TestApply_Aggressive_FakeGzip(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/agg-gzip-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-agg-gzip-%d", i), LevelAggressive)

		ce := rec.Header().Get("Content-Encoding")
		if ce == "gzip" {
			return // success
		}
	}
	t.Error("aggressive level never produced fake gzip Content-Encoding")
}

func TestApply_Aggressive_GarbagePadding(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/agg-pad-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-agg-pad-%d", i), LevelAggressive)

		padCount := 0
		for k := range rec.Header() {
			if strings.HasPrefix(k, "X-Pad-") {
				padCount++
			}
		}
		if padCount >= 50 {
			return // success
		}
	}
	t.Error("aggressive level never produced 50+ garbage padding headers")
}

func TestApply_Aggressive_KeepAlive(t *testing.T) {
	eng := NewEngine()

	for i := 0; i < 500; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/agg-ka-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-agg-ka-%d", i), LevelAggressive)

		if rec.Header().Get("Connection") == "keep-alive" && rec.Header().Get("Keep-Alive") != "" {
			return // success
		}
	}
	t.Error("aggressive level never produced Keep-Alive promise headers")
}

// --- LevelChaos ---

func TestApply_Chaos_AdditionalHeaders(t *testing.T) {
	eng := NewEngine()

	// Chaos always adds contradictory headers, so a single request suffices.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/chaos-headers-test", nil)
	eng.Apply(rec, req, "client-chaos-hdr", LevelChaos)

	if rec.Header().Get("Warning") == "" {
		t.Error("chaos level should always produce Warning header")
	}
	if len(rec.Header()["Www-Authenticate"]) == 0 {
		t.Error("chaos level should always produce WWW-Authenticate header")
	}
	if rec.Header().Get("Content-Disposition") == "" {
		t.Error("chaos level should always produce Content-Disposition header")
	}
}

func TestApply_Chaos_IncludesAllLowerLevels(t *testing.T) {
	eng := NewEngine()

	// Chaos should include subtle+moderate+aggressive headers.
	// Use enough iterations to hit probabilistic techniques but break early.
	hasSubtle := false     // X-Robots-Tag
	hasModerate := false   // ETag
	hasAggressive := false // X-Pad-*

	for i := 0; i < 200; i++ {
		if hasSubtle && hasModerate && hasAggressive {
			break
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", fmt.Sprintf("/chaos-all-%d", i), nil)
		eng.Apply(rec, req, fmt.Sprintf("client-chaos-all-%d", i), LevelChaos)

		if rec.Header().Get("X-Robots-Tag") != "" {
			hasSubtle = true
		}
		if rec.Header().Get("ETag") != "" {
			hasModerate = true
		}
		for k := range rec.Header() {
			if strings.HasPrefix(k, "X-Pad-") {
				hasAggressive = true
			}
		}
	}

	if !hasSubtle {
		t.Error("chaos level never included subtle techniques")
	}
	if !hasModerate {
		t.Error("chaos level never included moderate techniques")
	}
	if !hasAggressive {
		t.Error("chaos level never included aggressive techniques")
	}
}

// --- Determinism ---

func TestApply_Deterministic(t *testing.T) {
	eng := NewEngine()
	clientID := "client-deterministic-test"
	path := "/determinism-check"

	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", path, nil)
	eng.Apply(rec1, req1, clientID, LevelModerate)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", path, nil)
	eng.Apply(rec2, req2, clientID, LevelModerate)

	// Compare all headers except time-dependent ones (ETag contains time.Now)
	for k, v1 := range rec1.Header() {
		if k == "Etag" {
			continue // ETag is intentionally time-dependent
		}
		v2, ok := rec2.Header()[k]
		if !ok {
			t.Errorf("header %q present in first response but not second", k)
			continue
		}
		if len(v1) != len(v2) {
			t.Errorf("header %q: different number of values (%d vs %d)", k, len(v1), len(v2))
			continue
		}
		for i := range v1 {
			if v1[i] != v2[i] {
				t.Errorf("header %q[%d]: %q != %q", k, i, v1[i], v2[i])
			}
		}
	}
}

// --- Thread safety ---

func TestApply_ThreadSafety(t *testing.T) {
	eng := NewEngine()
	// Exclude LevelChaos from thread-safety test because its drip-feed
	// technique includes time.Sleep, making the test unnecessarily slow.
	// Chaos correctness is covered by dedicated tests above.
	levels := []CorruptionLevel{LevelNone, LevelSubtle, LevelModerate, LevelAggressive}

	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", fmt.Sprintf("/concurrent-%d-%d", idx, j), nil)
				level := levels[idx%len(levels)]
				clientID := fmt.Sprintf("client-concurrent-%d", idx)
				eng.Apply(rec, req, clientID, level)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without panic/race, the engine is thread-safe
}

// --- CorruptionLevel values ---

func TestCorruptionLevelConstants(t *testing.T) {
	levels := map[CorruptionLevel]string{
		LevelNone:       "none",
		LevelSubtle:     "subtle",
		LevelModerate:   "moderate",
		LevelAggressive: "aggressive",
		LevelChaos:      "chaos",
	}
	for level, expected := range levels {
		if string(level) != expected {
			t.Errorf("CorruptionLevel %v should be %q", level, expected)
		}
	}
}

// --- Duplicate header verification ---

func TestDuplicateHeaders_RawSliceAssignment(t *testing.T) {
	// Verify that w.Header()["Key"] = []string{...} actually creates
	// duplicate header values, which is the core mechanism for several techniques.
	rec := httptest.NewRecorder()
	rec.Header()["Content-Type"] = []string{"application/json", "text/html"}

	vals := rec.Header()["Content-Type"]
	if len(vals) != 2 {
		t.Fatalf("expected 2 Content-Type values, got %d", len(vals))
	}
	if vals[0] != "application/json" {
		t.Errorf("first Content-Type should be application/json, got %q", vals[0])
	}
	if vals[1] != "text/html" {
		t.Errorf("second Content-Type should be text/html, got %q", vals[1])
	}
}

// --- Helper function tests ---

func TestBitFunction(t *testing.T) {
	// bit(seed, slot, 1.0) should always return true
	for i := 0; i < 100; i++ {
		if !bit(uint64(i), i, 1.0) {
			t.Errorf("bit(%d, %d, 1.0) should be true", i, i)
		}
	}

	// bit(seed, slot, 0.0) should always return false
	for i := 0; i < 100; i++ {
		if bit(uint64(i), i, 0.0) {
			t.Errorf("bit(%d, %d, 0.0) should be false", i, i)
		}
	}
}

func TestNthDeterministic(t *testing.T) {
	// Same seed and n should always produce the same result
	for i := 0; i < 50; i++ {
		a := nth(12345, i)
		b := nth(12345, i)
		if a != b {
			t.Errorf("nth(12345, %d) not deterministic: %d != %d", i, a, b)
		}
	}

	// Different n values should produce different results
	a := nth(12345, 0)
	b := nth(12345, 1)
	if a == b {
		t.Error("nth with different n produced identical results (statistically improbable)")
	}
}

// --- Integration-style: verify escalation of levels ---

func TestLevelEscalation_MoreHeadersAtHigherLevels(t *testing.T) {
	eng := NewEngine()

	counts := make(map[CorruptionLevel]int)
	levels := []CorruptionLevel{LevelNone, LevelSubtle, LevelModerate, LevelAggressive}

	for _, level := range levels {
		total := 0
		for i := 0; i < 100; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", fmt.Sprintf("/escalation-%d", i), nil)
			eng.Apply(rec, req, fmt.Sprintf("client-escalation-%d", i), level)
			total += len(rec.Header())
		}
		counts[level] = total
	}

	// Each higher level should produce at least as many headers on average
	if counts[LevelSubtle] <= counts[LevelNone] {
		t.Errorf("subtle (%d) should produce more headers than none (%d)", counts[LevelSubtle], counts[LevelNone])
	}
	if counts[LevelModerate] <= counts[LevelSubtle] {
		t.Errorf("moderate (%d) should produce more headers than subtle (%d)", counts[LevelModerate], counts[LevelSubtle])
	}
	if counts[LevelAggressive] <= counts[LevelModerate] {
		t.Errorf("aggressive (%d) should produce more headers than moderate (%d)", counts[LevelAggressive], counts[LevelModerate])
	}
}

// --- Verify ShouldCorrupt edge cases ---

func TestShouldCorrupt_AllClientClasses(t *testing.T) {
	eng := NewEngine()
	tests := []struct {
		class    string
		expected bool
	}{
		{"browser", false},
		{"search_bot", true},
		{"ai_scraper", true},
		{"script_bot", true},
		{"load_tester", true},
		{"api_tester", true},
		{"unknown", true},
		{"", true},
		{"new_class", true},
	}
	for _, tt := range tests {
		got := eng.ShouldCorrupt(tt.class)
		if got != tt.expected {
			t.Errorf("ShouldCorrupt(%q) = %v, want %v", tt.class, got, tt.expected)
		}
	}
}

// --- Verify the engine is truly stateless ---

func TestEngine_Stateless(t *testing.T) {
	eng := NewEngine()

	// Apply multiple times with different levels; engine should have no state
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/state1", nil)
	eng.Apply(rec1, req1, "client-a", LevelAggressive)

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/state2", nil)
	eng.Apply(rec2, req2, "client-b", LevelSubtle)

	// Applying subtle after aggressive should not carry over aggressive headers
	for k := range rec2.Header() {
		if strings.HasPrefix(k, "X-Pad-") {
			t.Errorf("subtle request should not have aggressive padding header %q", k)
		}
	}
}
