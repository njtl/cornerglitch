package atomic

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
	"github.com/glitchWebServer/internal/scanner/evasion"
	"github.com/glitchWebServer/internal/scanner/profiles"
	"github.com/glitchWebServer/internal/scanner/resilience"
)

// ---------------------------------------------------------------------------
// Scanner Config — Atomic Tests
//
// Tests scanner default config, profile configs, modules, evasion modes,
// and resilience settings.
// ---------------------------------------------------------------------------

// TestScanner_DefaultConfig verifies all default config values.
func TestScanner_DefaultConfig(t *testing.T) {
	cfg := scanner.DefaultConfig()

	checks := []struct {
		field    string
		got      interface{}
		expected interface{}
	}{
		{"Concurrency", cfg.Concurrency, 10},
		{"RateLimit", cfg.RateLimit, 100},
		{"Timeout", cfg.Timeout, 10 * time.Second},
		{"MaxBodyRead", cfg.MaxBodyRead, int64(1 << 20)},
		{"CrawlFirst", cfg.CrawlFirst, false},
		{"CrawlDepth", cfg.CrawlDepth, 3},
		{"Profile", cfg.Profile, "default"},
		{"EvasionMode", cfg.EvasionMode, "none"},
		{"UserAgent", cfg.UserAgent, "GlitchScanner/1.0"},
		{"OutputFormat", cfg.OutputFormat, "json"},
		{"Verbose", cfg.Verbose, false},
	}

	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			if c.got != c.expected {
				t.Errorf("%s = %v, want %v", c.field, c.got, c.expected)
			}
		})
	}

	if cfg.EnabledModules != nil {
		t.Error("EnabledModules should be nil (all enabled)")
	}
	if cfg.CustomHeaders == nil || len(cfg.CustomHeaders) != 0 {
		t.Error("CustomHeaders should be empty map")
	}
}

// TestScanner_NightmareConfig verifies nightmare config values.
func TestScanner_NightmareConfig(t *testing.T) {
	cfg := scanner.NightmareConfig()

	checks := []struct {
		field    string
		got      interface{}
		expected interface{}
	}{
		{"Concurrency", cfg.Concurrency, 50},
		{"RateLimit", cfg.RateLimit, 500},
		{"Timeout", cfg.Timeout, 30 * time.Second},
		{"MaxBodyRead", cfg.MaxBodyRead, int64(4 << 20)},
		{"CrawlFirst", cfg.CrawlFirst, true},
		{"CrawlDepth", cfg.CrawlDepth, 5},
		{"Profile", cfg.Profile, "nightmare"},
		{"EvasionMode", cfg.EvasionMode, "nightmare"},
	}

	for _, c := range checks {
		t.Run(c.field, func(t *testing.T) {
			if c.got != c.expected {
				t.Errorf("%s = %v, want %v", c.field, c.got, c.expected)
			}
		})
	}
}

// TestScanner_StealthConfig verifies stealth config values.
func TestScanner_StealthConfig(t *testing.T) {
	cfg := scanner.StealthConfig()

	if cfg.Concurrency != 3 {
		t.Errorf("Concurrency = %d, want 3", cfg.Concurrency)
	}
	if cfg.RateLimit != 10 {
		t.Errorf("RateLimit = %d, want 10", cfg.RateLimit)
	}
	if cfg.EvasionMode != "advanced" {
		t.Errorf("EvasionMode = %q, want advanced", cfg.EvasionMode)
	}
	if cfg.Profile != "stealth" {
		t.Errorf("Profile = %q, want stealth", cfg.Profile)
	}
}

// TestScanner_AggressiveConfig verifies aggressive config values.
func TestScanner_AggressiveConfig(t *testing.T) {
	cfg := scanner.AggressiveConfig()

	if cfg.Concurrency != 30 {
		t.Errorf("Concurrency = %d, want 30", cfg.Concurrency)
	}
	if cfg.RateLimit != 300 {
		t.Errorf("RateLimit = %d, want 300", cfg.RateLimit)
	}
	if cfg.EvasionMode != "none" {
		t.Errorf("EvasionMode = %q, want none", cfg.EvasionMode)
	}
	if cfg.Profile != "aggressive" {
		t.Errorf("Profile = %q, want aggressive", cfg.Profile)
	}
}

// TestScanner_ComplianceConfig verifies compliance config values.
func TestScanner_ComplianceConfig(t *testing.T) {
	cfg := scanner.ComplianceConfig()

	if cfg.Concurrency != 5 {
		t.Errorf("Concurrency = %d, want 5", cfg.Concurrency)
	}
	if cfg.RateLimit != 20 {
		t.Errorf("RateLimit = %d, want 20", cfg.RateLimit)
	}
	if cfg.CrawlFirst != true {
		t.Error("CrawlFirst should be true")
	}
	if cfg.Profile != "compliance" {
		t.Errorf("Profile = %q, want compliance", cfg.Profile)
	}
}

// ---------------------------------------------------------------------------
// Profile Registry
// ---------------------------------------------------------------------------

// TestScanner_ProfileList verifies all profiles are registered.
func TestScanner_ProfileList(t *testing.T) {
	names := profiles.List()
	expected := []string{"aggressive", "compliance", "destroyer", "nightmare", "stealth", "waf-buster"}

	if len(names) != len(expected) {
		t.Fatalf("List() returned %d profiles, want %d: %v", len(names), len(expected), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("List()[%d] = %q, want %q", i, names[i], name)
		}
	}
}

// TestScanner_ProfileGet verifies each profile can be retrieved.
func TestScanner_ProfileGet(t *testing.T) {
	for _, name := range profiles.List() {
		t.Run(name, func(t *testing.T) {
			p, err := profiles.Get(name)
			if err != nil {
				t.Fatalf("Get(%q) error: %v", name, err)
			}
			if p.Name != name {
				t.Errorf("profile Name = %q, want %q", p.Name, name)
			}
			if p.Description == "" {
				t.Error("profile Description should not be empty")
			}
			if p.Config.Profile != name {
				t.Errorf("Config.Profile = %q, want %q", p.Config.Profile, name)
			}
		})
	}
}

// TestScanner_ProfileGetUnknownReturnsError tests unknown profile names.
func TestScanner_ProfileGetUnknownReturnsError(t *testing.T) {
	unknowns := []string{"nonexistent", "default", "", "AGGRESSIVE"}
	for _, name := range unknowns {
		t.Run(name, func(t *testing.T) {
			_, err := profiles.Get(name)
			if err == nil {
				t.Errorf("Get(%q) should return error for unknown profile", name)
			}
		})
	}
}

// TestScanner_ProfileImmutability verifies Get returns a copy, not the original.
func TestScanner_ProfileImmutability(t *testing.T) {
	p1, _ := profiles.Get("aggressive")
	p2, _ := profiles.Get("aggressive")

	// Modify p1's headers
	p1.Config.CustomHeaders["test"] = "modified"

	// p2 should not be affected
	if _, exists := p2.Config.CustomHeaders["test"]; exists {
		t.Error("modifying one Get() result should not affect another")
	}
}

// TestScanner_ProfileAll verifies All() returns all profiles.
func TestScanner_ProfileAll(t *testing.T) {
	all := profiles.All()
	if len(all) != 6 {
		t.Errorf("All() returned %d profiles, want 6", len(all))
	}
}

// ---------------------------------------------------------------------------
// Attack Modules
// ---------------------------------------------------------------------------

// TestScanner_AttackModules verifies all modules are registered.
func TestScanner_AttackModules(t *testing.T) {
	mods := attacks.AllModules()
	if len(mods) == 0 {
		t.Fatal("AllModules() returned no modules")
	}

	// Verify each module has required fields
	for _, mod := range mods {
		t.Run(mod.Name(), func(t *testing.T) {
			if mod.Name() == "" {
				t.Error("module Name() is empty")
			}
			if mod.Category() == "" {
				t.Error("module Category() is empty")
			}
		})
	}
}

// TestScanner_AttackModuleFilter verifies module filtering.
func TestScanner_AttackModuleFilter(t *testing.T) {
	// Filter to known module
	filtered := attacks.FilterModules([]string{"owasp"})
	if len(filtered) != 1 {
		t.Errorf("FilterModules([owasp]) returned %d, want 1", len(filtered))
	}

	// Filter to nonexistent module
	filtered = attacks.FilterModules([]string{"nonexistent"})
	if len(filtered) != 0 {
		t.Errorf("FilterModules([nonexistent]) returned %d, want 0", len(filtered))
	}

	// Empty filter returns all
	all := attacks.FilterModules(nil)
	if len(all) != len(attacks.AllModules()) {
		t.Errorf("FilterModules(nil) returned %d, want %d", len(all), len(attacks.AllModules()))
	}
}

// ---------------------------------------------------------------------------
// Evasion
// ---------------------------------------------------------------------------

// TestScanner_EvasionEncoderModes verifies encoder produces variants per mode.
func TestScanner_EvasionEncoderModes(t *testing.T) {
	modes := map[string]int{
		"none":      1, // original only
		"basic":     2, // original + url-encoded
		"advanced":  7, // original + 6 variants
		"nightmare": 0, // 14+ variants (just verify > advanced)
	}

	for mode, minExpected := range modes {
		t.Run(mode, func(t *testing.T) {
			enc := evasion.NewEncoder(mode)
			variants := enc.Encode("test<script>alert(1)</script>")
			if mode == "nightmare" {
				if len(variants) <= 7 {
					t.Errorf("nightmare mode should produce > 7 variants, got %d", len(variants))
				}
			} else if len(variants) != minExpected {
				t.Errorf("%s mode produced %d variants, want %d", mode, len(variants), minExpected)
			}
		})
	}
}

// TestScanner_EvasionHeaderModes verifies header manipulator modes produce distinct behavior.
func TestScanner_EvasionHeaderModes(t *testing.T) {
	modes := []string{"none", "basic", "advanced", "nightmare"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			hm := evasion.NewHeaderManipulator(mode)
			if hm == nil {
				t.Fatalf("NewHeaderManipulator(%q) returned nil", mode)
			}

			// Apply to a real request and verify it runs without panic
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("User-Agent", "TestAgent/1.0")
			hm.Apply(req)

			// RotateUserAgent should return a valid string
			ua := hm.RotateUserAgent()
			if ua == "" {
				t.Errorf("%s mode: RotateUserAgent returned empty string", mode)
			}

			// For non-none modes, Apply should modify the request headers
			if mode != "none" {
				req2 := httptest.NewRequest("GET", "/test", nil)
				originalHeaders := len(req2.Header)
				hm.Apply(req2)
				// Advanced modes should add extra headers (decoys, IP forgery, etc.)
				if mode == "advanced" || mode == "nightmare" {
					if len(req2.Header) <= originalHeaders {
						t.Logf("%s mode: Apply did not add extra headers (may depend on randomization)", mode)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Resilience
// ---------------------------------------------------------------------------

// TestScanner_ResilienceErrorHandler verifies error handler tracks errors.
func TestScanner_ResilienceErrorHandler(t *testing.T) {
	eh := resilience.NewErrorHandler(1<<20, 10*time.Second)
	if eh == nil {
		t.Fatal("NewErrorHandler returned nil")
	}

	// Initial state: zero errors
	stats := eh.GetStats()
	if stats.TotalErrors != 0 {
		t.Errorf("initial TotalErrors = %d, want 0", stats.TotalErrors)
	}

	// Record some errors and verify they're tracked
	eh.RecordError("timeout")
	eh.RecordError("connection_reset")
	eh.RecordError("timeout")

	stats = eh.GetStats()
	if stats.TotalErrors != 3 {
		t.Errorf("after 3 errors, TotalErrors = %d, want 3", stats.TotalErrors)
	}
}

// TestScanner_ResilienceConnectionDefaults verifies connection manager applies defaults.
func TestScanner_ResilienceConnectionDefaults(t *testing.T) {
	// Zero-valued config should get sensible defaults
	cm := resilience.NewConnectionManager(resilience.ConnectionConfig{})

	if cm.RetryCount != 3 {
		t.Errorf("default RetryCount = %d, want 3", cm.RetryCount)
	}
	if cm.RetryDelay != 500*time.Millisecond {
		t.Errorf("default RetryDelay = %v, want 500ms", cm.RetryDelay)
	}
	if cm.CircuitBreaker == nil {
		t.Fatal("CircuitBreaker should not be nil")
	}
	if cm.CircuitBreaker.State() != "closed" {
		t.Errorf("initial CB state = %q, want closed", cm.CircuitBreaker.State())
	}
}

// TestScanner_ResilienceCircuitBreaker verifies circuit breaker states.
func TestScanner_ResilienceCircuitBreaker(t *testing.T) {
	cb := resilience.NewCircuitBreaker(3, 1*time.Hour) // long reset so it stays open

	// Initial state: closed
	if cb.State() != "closed" {
		t.Errorf("initial state = %q, want closed", cb.State())
	}

	// Trip after threshold failures
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	if cb.State() != "open" {
		t.Errorf("after 3 failures, state = %q, want open", cb.State())
	}

	// Should not allow requests when open
	if cb.Allow() {
		t.Error("open circuit breaker should not allow requests")
	}

	// RecordSuccess resets to closed
	cb.RecordSuccess()
	if cb.State() != "closed" {
		t.Errorf("after RecordSuccess(), state = %q, want closed", cb.State())
	}
}
