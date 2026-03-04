package budgettrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e.IsEnabled() {
		t.Error("new engine should be disabled by default")
	}
	if e.GetThreshold() != 10 {
		t.Errorf("default threshold: got %d, want 10", e.GetThreshold())
	}
}

func TestSetEnabled(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if !e.IsEnabled() {
		t.Error("engine should be enabled after SetEnabled(true)")
	}
	e.SetEnabled(false)
	if e.IsEnabled() {
		t.Error("engine should be disabled after SetEnabled(false)")
	}
}

func TestSetThreshold(t *testing.T) {
	e := NewEngine()
	e.SetThreshold(50)
	if e.GetThreshold() != 50 {
		t.Errorf("threshold: got %d, want 50", e.GetThreshold())
	}
	// Minimum clamp
	e.SetThreshold(0)
	if e.GetThreshold() != 1 {
		t.Errorf("threshold should clamp to 1, got %d", e.GetThreshold())
	}
	e.SetThreshold(-5)
	if e.GetThreshold() != 1 {
		t.Errorf("negative threshold should clamp to 1, got %d", e.GetThreshold())
	}
}

func TestShouldHandle(t *testing.T) {
	e := NewEngine()
	e.SetThreshold(10)

	// Disabled engine: never handle
	if e.ShouldHandle("client1", 100) {
		t.Error("disabled engine should never handle")
	}

	e.SetEnabled(true)

	// Below threshold: don't handle
	if e.ShouldHandle("client1", 5) {
		t.Error("should not handle when below threshold")
	}

	// At threshold: don't handle (must exceed)
	if e.ShouldHandle("client1", 10) {
		t.Error("should not handle when exactly at threshold")
	}

	// Above threshold: handle
	if !e.ShouldHandle("client1", 11) {
		t.Error("should handle when above threshold")
	}
}

func TestApplyLevel1(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetThreshold(10)

	// Level 1: threshold+1 to threshold*5
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	status, trapType := e.Apply(w, r, "testclient", 20)

	if status != http.StatusOK {
		t.Errorf("level 1 status: got %d, want 200", status)
	}
	// trapType should be one of: tarpit, breadcrumbs
	if trapType != "tarpit" && trapType != "breadcrumbs" {
		t.Errorf("level 1 trap type: got %q, want tarpit or breadcrumbs", trapType)
	}
}

func TestApplyLevel2(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetThreshold(10)

	// Level 2: threshold*5+1 to threshold*10
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	status, trapType := e.Apply(w, r, "testclient", 60)

	if status != http.StatusOK {
		t.Errorf("level 2 status: got %d, want 200", status)
	}
	valid := map[string]bool{"tarpit": true, "breadcrumbs": true, "streaming_bait": true}
	if !valid[trapType] {
		t.Errorf("level 2 trap type: got %q, want one of tarpit/breadcrumbs/streaming_bait", trapType)
	}
}

func TestApplyLevel3(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetThreshold(10)

	// Level 3: beyond threshold*10
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	status, trapType := e.Apply(w, r, "testclient", 200)

	if status != http.StatusOK {
		t.Errorf("level 3 status: got %d, want 200", status)
	}
	valid := map[string]bool{"tarpit": true, "streaming_bait": true, "pagination_trap": true, "expansion": true}
	if !valid[trapType] {
		t.Errorf("level 3 trap type: got %q, want one of tarpit/streaming_bait/pagination_trap/expansion", trapType)
	}
}

func TestApplyDeterministic(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetThreshold(5)

	// Same client+path+requests should produce same result
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/deterministic-test", nil)
		status1, type1 := e.Apply(w, r, "fixed-client", 30)

		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest("GET", "/deterministic-test", nil)
		status2, type2 := e.Apply(w2, r2, "fixed-client", 30)

		if status1 != status2 || type1 != type2 {
			t.Errorf("iteration %d: not deterministic: %d/%s vs %d/%s", i, status1, type1, status2, type2)
		}
	}
}

func TestBreadcrumbHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	rng := seedRNG("test", "/test")
	InjectBreadcrumbHeaders(w, rng)

	resp := w.Result()
	// Should have at least one of the fake headers
	hasDebugHeader := false
	for name := range resp.Header {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "debug") || strings.Contains(lower, "powered") ||
			strings.Contains(lower, "server") || strings.Contains(lower, "request-id") {
			hasDebugHeader = true
			break
		}
	}
	if !hasDebugHeader {
		t.Error("InjectBreadcrumbHeaders should set at least one fake header")
	}
}

func TestBreadcrumbHTML(t *testing.T) {
	rng := seedRNG("test", "/test")
	html := GenerateBreadcrumbHTML(rng)

	if html == "" {
		t.Error("GenerateBreadcrumbHTML should not return empty string")
	}
	// Should contain HTML comment patterns (breadcrumbs inject debug-looking comments)
	if !strings.Contains(html, "<!--") {
		t.Error("breadcrumb HTML should contain HTML comments")
	}
}

func TestSeedRNGDeterministic(t *testing.T) {
	r1 := seedRNG("client1", "/path")
	r2 := seedRNG("client1", "/path")

	// Same seed should produce same sequence
	for i := 0; i < 10; i++ {
		v1 := r1.Float64()
		v2 := r2.Float64()
		if v1 != v2 {
			t.Errorf("seedRNG not deterministic at step %d: %f vs %f", i, v1, v2)
		}
	}

	// Different input should produce different sequence
	r3 := seedRNG("client2", "/path")
	r4 := seedRNG("client1", "/other")
	same := true
	for i := 0; i < 5; i++ {
		if r3.Float64() != r4.Float64() {
			same = false
			break
		}
	}
	if same {
		t.Error("different inputs should produce different RNG sequences")
	}
}
