package adaptive

import (
	"testing"

	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/metrics"
)

func TestNewEngine(t *testing.T) {
	c := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	e := NewEngine(c, fp)
	if e == nil {
		t.Fatal("NewEngine should not return nil")
	}
	chance, dur, enabled := e.GetBlockConfig()
	if chance != 0.02 {
		t.Fatalf("expected default blockChance 0.02, got %f", chance)
	}
	if dur.Seconds() != 30 {
		t.Fatalf("expected default blockDuration 30s, got %s", dur)
	}
	if !enabled {
		t.Fatal("expected blocking to be enabled by default")
	}
}

func TestGetBehavior_NewClient(t *testing.T) {
	c := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	e := NewEngine(c, fp)
	// Disable random blocking so the test is deterministic
	e.SetBlockEnabled(false)

	behavior := e.Decide("new-client-1", fingerprint.ClassBrowser)
	if behavior == nil {
		t.Fatal("Decide should not return nil")
	}
	if behavior.Mode != ModeNormal {
		t.Fatalf("new client should get ModeNormal, got %s", behavior.Mode)
	}
}

func TestGetBehavior_Deterministic(t *testing.T) {
	c := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	e := NewEngine(c, fp)
	e.SetBlockEnabled(false)

	b1 := e.Decide("client-det", fingerprint.ClassUnknown)
	b2 := e.Decide("client-det", fingerprint.ClassUnknown)
	if b1.Mode != b2.Mode {
		t.Fatalf("same client should get consistent mode: %s vs %s", b1.Mode, b2.Mode)
	}
}

func TestMode_Names(t *testing.T) {
	modes := map[BehaviorMode]string{
		ModeNormal:       "normal",
		ModeCooperative:  "cooperative",
		ModeAggressive:   "aggressive",
		ModeLabyrinth:    "labyrinth",
		ModeMirror:       "mirror",
		ModeEscalating:   "escalating",
		ModeIntermittent: "intermittent",
		ModeBlocked:      "blocked",
	}
	for mode, expected := range modes {
		if string(mode) != expected {
			t.Fatalf("mode %v should have string value %q, got %q", mode, expected, string(mode))
		}
	}
}

func TestGetBehavior_ReturnsNilForUnknown(t *testing.T) {
	c := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	e := NewEngine(c, fp)
	// GetBehavior (read-only) returns nil if Decide was never called
	b := e.GetBehavior("never-seen-client")
	if b != nil {
		t.Fatal("GetBehavior should return nil for a client that was never decided")
	}
}

func TestSetOverride(t *testing.T) {
	c := metrics.NewCollector()
	fp := fingerprint.NewEngine()
	e := NewEngine(c, fp)
	e.SetBlockEnabled(false)

	e.SetOverride("client-override", ModeAggressive)
	b := e.Decide("client-override", fingerprint.ClassBrowser)
	if b.Mode != ModeAggressive {
		t.Fatalf("override should force ModeAggressive, got %s", b.Mode)
	}

	e.ClearOverride("client-override")
	overrides := e.GetOverrides()
	if _, ok := overrides["client-override"]; ok {
		t.Fatal("override should be cleared")
	}
}
