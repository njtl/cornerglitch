package browserchaos

import (
	"strings"
	"testing"
)

func TestNewEngine_DefaultDisabled(t *testing.T) {
	e := NewEngine()
	if e.IsEnabled() {
		t.Error("new engine should be disabled by default")
	}
	if e.GetLevel() != 0 {
		t.Errorf("new engine level should be 0, got %d", e.GetLevel())
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

func TestSetLevel_Clamping(t *testing.T) {
	e := NewEngine()
	e.SetLevel(-5)
	if e.GetLevel() != 0 {
		t.Errorf("negative level should clamp to 0, got %d", e.GetLevel())
	}
	e.SetLevel(99)
	if e.GetLevel() != 4 {
		t.Errorf("excessive level should clamp to 4, got %d", e.GetLevel())
	}
	e.SetLevel(3)
	if e.GetLevel() != 3 {
		t.Errorf("valid level 3 should be stored, got %d", e.GetLevel())
	}
}

func TestGeneratePayload_DisabledReturnsEmpty(t *testing.T) {
	e := NewEngine()
	result := e.GeneratePayload("/test")
	if result != "" {
		t.Error("disabled engine should return empty payload")
	}
}

func TestGeneratePayload_LevelZeroReturnsEmpty(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(0)
	result := e.GeneratePayload("/test")
	if result != "" {
		t.Error("level 0 should return empty payload")
	}
}

func TestGeneratePayload_Level1_NetworkIdleStall(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(1)
	result := e.GeneratePayload("/test-page")

	if !strings.Contains(result, "setInterval") {
		t.Error("level 1 should contain network idle stall (setInterval)")
	}
	if !strings.Contains(result, "fetch(") {
		t.Error("level 1 should contain fetch calls")
	}
	// Should NOT contain higher-level attacks
	if strings.Contains(result, "serviceWorker") {
		t.Error("level 1 should not contain ServiceWorker poison")
	}
	if strings.Contains(result, "indexedDB") {
		t.Error("level 1 should not contain IndexedDB bomb")
	}
}

func TestGeneratePayload_Level2_ServiceWorkerAndMemory(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(2)
	result := e.GeneratePayload("/test-page")

	if !strings.Contains(result, "setInterval") {
		t.Error("level 2 should contain network idle stall")
	}
	if !strings.Contains(result, "serviceWorker") {
		t.Error("level 2 should contain ServiceWorker registration")
	}
	if !strings.Contains(result, "indexedDB") {
		t.Error("level 2 should contain IndexedDB bomb")
	}
	if !strings.Contains(result, "createObjectURL") {
		t.Error("level 2 should contain Blob URL leaks")
	}
	// Should NOT contain level 3+ attacks
	if strings.Contains(result, "calc(") {
		t.Error("level 2 should not contain CSS calc bomb")
	}
}

func TestGeneratePayload_Level3_CSSBombAndLinks(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(3)
	result := e.GeneratePayload("/test-page")

	if !strings.Contains(result, "calc(") {
		t.Error("level 3 should contain CSS calc bomb")
	}
	if !strings.Contains(result, "blur(") {
		t.Error("level 3 should contain filter stacking")
	}
	if !strings.Contains(result, "grid-template-columns") {
		t.Error("level 3 should contain CSS grid bomb")
	}
	if !strings.Contains(result, `<a href="/p/`) {
		t.Error("level 3 should contain link flood")
	}
	// Should NOT contain level 4 attacks
	if strings.Contains(result, "WebAssembly") {
		t.Error("level 3 should not contain WASM bomb")
	}
}

func TestGeneratePayload_Level4_Everything(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(4)
	result := e.GeneratePayload("/test-page")

	checks := map[string]string{
		"setInterval":       "network idle stall",
		"serviceWorker":     "ServiceWorker poison",
		"indexedDB":         "IndexedDB bomb",
		"createObjectURL":   "Blob URL leaks",
		"calc(":             "CSS calc bomb",
		"blur(":             "filter stacking",
		"grid-template":     "CSS grid bomb",
		"WebAssembly":       "WASM CPU bomb",
		"webgl":             "WebGL exhaustion",
		"AudioContext":      "audio context exhaustion",
		"caches":            "Cache API pollution",
		`<a href="/p/`:      "link flood",
	}

	for needle, desc := range checks {
		if !strings.Contains(result, needle) {
			t.Errorf("level 4 should contain %s (looking for %q)", desc, needle)
		}
	}
}

func TestGeneratePayload_Deterministic(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(4)

	result1 := e.GeneratePayload("/same/path")
	result2 := e.GeneratePayload("/same/path")

	if result1 != result2 {
		t.Error("same path should produce identical payloads (deterministic)")
	}

	result3 := e.GeneratePayload("/different/path")
	if result1 == result3 {
		t.Error("different paths should produce different payloads")
	}
}

func TestGeneratePayload_Level4_LinkCount(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(4)
	result := e.GeneratePayload("/test")

	linkCount := strings.Count(result, `<a href="/p/`)
	if linkCount < 1000 {
		t.Errorf("level 4 should generate 2000 links, got %d", linkCount)
	}
}

func TestGeneratePayload_Level3_LinkCount(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(3)
	result := e.GeneratePayload("/test")

	linkCount := strings.Count(result, `<a href="/p/`)
	if linkCount < 100 {
		t.Errorf("level 3 should generate 500 links, got %d", linkCount)
	}
}

func TestSnapshot(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(3)

	snap := e.Snapshot()
	if enabled, ok := snap["enabled"].(bool); !ok || !enabled {
		t.Error("snapshot should contain enabled=true")
	}
	if level, ok := snap["level"].(int); !ok || level != 3 {
		t.Errorf("snapshot should contain level=3, got %v", snap["level"])
	}
}

func TestRestore(t *testing.T) {
	e := NewEngine()
	e.Restore(map[string]interface{}{
		"enabled": true,
		"level":   float64(4), // JSON numbers come as float64
	})

	if !e.IsEnabled() {
		t.Error("restore should set enabled=true")
	}
	if e.GetLevel() != 4 {
		t.Errorf("restore should set level=4, got %d", e.GetLevel())
	}
}

func TestJsStringLiteral(t *testing.T) {
	result := jsStringLiteral("hello 'world'\nnewline")
	if !strings.HasPrefix(result, "'") || !strings.HasSuffix(result, "'") {
		t.Error("should be wrapped in single quotes")
	}
	if strings.Contains(result, "\n") {
		t.Error("newlines should be escaped")
	}
	if !strings.Contains(result, "\\'") {
		t.Error("single quotes should be escaped")
	}
}

func TestGeneratePayload_Level2_ServiceWorkerContent(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(2)
	result := e.GeneratePayload("/test")

	// SW should register with scope '/'
	if !strings.Contains(result, "scope:'/'") {
		t.Error("ServiceWorker should register with root scope")
	}
	// SW should use Blob URL (inline, no external fetch needed)
	if !strings.Contains(result, "Blob(") {
		t.Error("ServiceWorker should use Blob URL for inline registration")
	}
}

func TestGeneratePayload_Level4_SVGBomb(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	e.SetLevel(4)
	result := e.GeneratePayload("/test")

	if !strings.Contains(result, "<svg") {
		t.Error("level 4 should contain SVG recursion bomb")
	}
	if !strings.Contains(result, "feGaussianBlur") {
		t.Error("level 4 SVG bomb should use filter")
	}
}
