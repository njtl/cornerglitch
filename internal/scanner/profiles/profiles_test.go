package profiles

import (
	"sort"
	"testing"
	"time"
)

func TestList(t *testing.T) {
	names := List()
	expected := []string{"aggressive", "compliance", "destroyer", "nightmare", "stealth", "waf-buster"}

	if len(names) != len(expected) {
		t.Fatalf("List() returned %d profiles, want %d", len(names), len(expected))
	}

	// List() returns alphabetical order
	if !sort.StringsAreSorted(names) {
		t.Errorf("List() is not sorted: %v", names)
	}

	for i, name := range expected {
		if names[i] != name {
			t.Errorf("List()[%d] = %q, want %q", i, names[i], name)
		}
	}
}

func TestGetAllProfiles(t *testing.T) {
	for _, name := range List() {
		p, err := Get(name)
		if err != nil {
			t.Errorf("Get(%q) returned error: %v", name, err)
			continue
		}
		if p == nil {
			t.Errorf("Get(%q) returned nil", name)
			continue
		}
		if p.Name != name {
			t.Errorf("Get(%q).Name = %q, want %q", name, p.Name, name)
		}
		if p.Description == "" {
			t.Errorf("Get(%q).Description is empty", name)
		}
		if p.Config.Profile != name {
			t.Errorf("Get(%q).Config.Profile = %q, want %q", name, p.Config.Profile, name)
		}
		if p.Config.OutputFormat != "json" {
			t.Errorf("Get(%q).Config.OutputFormat = %q, want %q", name, p.Config.OutputFormat, "json")
		}
		if p.Config.UserAgent == "" {
			t.Errorf("Get(%q).Config.UserAgent is empty", name)
		}
		if p.Config.Timeout <= 0 {
			t.Errorf("Get(%q).Config.Timeout = %v, should be positive", name, p.Config.Timeout)
		}
		if p.Config.Concurrency <= 0 {
			t.Errorf("Get(%q).Config.Concurrency = %d, should be positive", name, p.Config.Concurrency)
		}
	}
}

func TestGetUnknownProfile(t *testing.T) {
	_, err := Get("nonexistent")
	if err == nil {
		t.Fatal("Get(\"nonexistent\") should return an error")
	}
}

func TestGetReturnsCopy(t *testing.T) {
	p1, _ := Get("aggressive")
	p2, _ := Get("aggressive")

	p1.Config.Concurrency = 9999
	if p2.Config.Concurrency == 9999 {
		t.Error("Get should return a copy; modifying one should not affect another")
	}
}

func TestGetReturnsCopyCustomHeaders(t *testing.T) {
	p1, _ := Get("stealth")
	p2, _ := Get("stealth")

	p1.Config.CustomHeaders["X-Test"] = "modified"
	if _, ok := p2.Config.CustomHeaders["X-Test"]; ok {
		t.Error("Get should deep-copy CustomHeaders; modifying one should not affect another")
	}
}

func TestGetReturnsCopyEnabledModules(t *testing.T) {
	p1, _ := Get("aggressive")
	p2, _ := Get("aggressive")

	if len(p1.Config.EnabledModules) > 0 {
		p1.Config.EnabledModules[0] = "MUTATED"
		if p2.Config.EnabledModules[0] == "MUTATED" {
			t.Error("Get should deep-copy EnabledModules; modifying one should not affect another")
		}
	}
}

func TestAll(t *testing.T) {
	all := All()
	names := List()
	if len(all) != len(names) {
		t.Fatalf("All() returned %d profiles, want %d", len(all), len(names))
	}
	for i, p := range all {
		if p.Name != names[i] {
			t.Errorf("All()[%d].Name = %q, want %q", i, p.Name, names[i])
		}
	}
}

func TestComplianceProfile(t *testing.T) {
	p, _ := Get("compliance")

	if p.Config.Concurrency > 10 {
		t.Errorf("compliance Concurrency = %d, expected low value (<= 10)", p.Config.Concurrency)
	}
	if p.Config.EvasionMode != "none" {
		t.Errorf("compliance EvasionMode = %q, want %q", p.Config.EvasionMode, "none")
	}
	if !p.Config.CrawlFirst {
		t.Error("compliance should have CrawlFirst = true")
	}
	if p.Config.EnabledModules == nil || len(p.Config.EnabledModules) == 0 {
		t.Error("compliance should have specific enabled modules")
	}
}

func TestAggressiveProfile(t *testing.T) {
	p, _ := Get("aggressive")

	if p.Config.Concurrency < 20 {
		t.Errorf("aggressive Concurrency = %d, expected >= 20", p.Config.Concurrency)
	}
	if p.Config.RateLimit < 100 {
		t.Errorf("aggressive RateLimit = %d, expected >= 100", p.Config.RateLimit)
	}
	if p.Config.EvasionMode != "none" {
		t.Errorf("aggressive EvasionMode = %q, want %q", p.Config.EvasionMode, "none")
	}
	if !p.Config.Verbose {
		t.Error("aggressive should have Verbose = true")
	}
	if p.Config.EnabledModules == nil || len(p.Config.EnabledModules) < 10 {
		t.Error("aggressive should have many enabled modules")
	}
}

func TestStealthProfile(t *testing.T) {
	p, _ := Get("stealth")

	if p.Config.Concurrency != 1 {
		t.Errorf("stealth Concurrency = %d, want 1", p.Config.Concurrency)
	}
	if p.Config.RateLimit > 5 {
		t.Errorf("stealth RateLimit = %d, expected <= 5", p.Config.RateLimit)
	}
	if p.Config.EvasionMode != "advanced" {
		t.Errorf("stealth EvasionMode = %q, want %q", p.Config.EvasionMode, "advanced")
	}
	if p.Config.CustomHeaders == nil || len(p.Config.CustomHeaders) == 0 {
		t.Error("stealth should have custom browser-like headers")
	}
	if _, ok := p.Config.CustomHeaders["Accept"]; !ok {
		t.Error("stealth should have Accept header set")
	}
}

func TestNightmareProfile(t *testing.T) {
	p, _ := Get("nightmare")

	if p.Config.Concurrency < 50 {
		t.Errorf("nightmare Concurrency = %d, expected >= 50", p.Config.Concurrency)
	}
	if p.Config.RateLimit != 0 {
		t.Errorf("nightmare RateLimit = %d, expected 0 (unlimited)", p.Config.RateLimit)
	}
	if p.Config.EvasionMode != "nightmare" {
		t.Errorf("nightmare EvasionMode = %q, want %q", p.Config.EvasionMode, "nightmare")
	}
	if p.Config.CrawlDepth < 5 {
		t.Errorf("nightmare CrawlDepth = %d, expected >= 5", p.Config.CrawlDepth)
	}
	if p.Config.EnabledModules == nil || len(p.Config.EnabledModules) < 15 {
		t.Error("nightmare should have many enabled modules including protocol abuse")
	}
}

func TestDestroyerProfile(t *testing.T) {
	p, _ := Get("destroyer")

	if p.Config.Concurrency < 100 {
		t.Errorf("destroyer Concurrency = %d, expected >= 100", p.Config.Concurrency)
	}
	if p.Config.RateLimit != 0 {
		t.Errorf("destroyer RateLimit = %d, expected 0 (unlimited)", p.Config.RateLimit)
	}
	if p.Config.CrawlFirst {
		t.Error("destroyer should skip crawling (CrawlFirst = false)")
	}
	if p.Config.Timeout < 30*time.Second {
		t.Errorf("destroyer Timeout = %v, expected >= 30s", p.Config.Timeout)
	}
}

func TestWAFBusterProfile(t *testing.T) {
	p, err := Get("waf-buster")
	if err != nil {
		t.Fatalf("Get(\"waf-buster\") returned error: %v", err)
	}

	if p.Config.Concurrency != 30 {
		t.Errorf("waf-buster Concurrency = %d, want 30", p.Config.Concurrency)
	}
	if p.Config.RateLimit != 100 {
		t.Errorf("waf-buster RateLimit = %d, want 100", p.Config.RateLimit)
	}
	if p.Config.Timeout != 30*time.Second {
		t.Errorf("waf-buster Timeout = %v, want 30s", p.Config.Timeout)
	}
	if p.Config.CrawlFirst {
		t.Error("waf-buster should have CrawlFirst = false")
	}
	if p.Config.EvasionMode != "nightmare" {
		t.Errorf("waf-buster EvasionMode = %q, want %q", p.Config.EvasionMode, "nightmare")
	}

	// Verify enabled modules include waf and other expected modules
	moduleSet := make(map[string]bool)
	for _, m := range p.Config.EnabledModules {
		moduleSet[m] = true
	}
	requiredModules := []string{"waf", "slowhttp", "breakage", "protocol", "h3", "owasp", "injection"}
	for _, m := range requiredModules {
		if !moduleSet[m] {
			t.Errorf("waf-buster should include module %q", m)
		}
	}

	if !p.Config.Verbose {
		t.Error("waf-buster should have Verbose = true")
	}
}

func TestNightmareHigherIntensityThanAggressive(t *testing.T) {
	nm, _ := Get("nightmare")
	ag, _ := Get("aggressive")

	if nm.Config.Concurrency <= ag.Config.Concurrency {
		t.Errorf("nightmare Concurrency (%d) should exceed aggressive (%d)", nm.Config.Concurrency, ag.Config.Concurrency)
	}
	if nm.Config.CrawlDepth <= ag.Config.CrawlDepth {
		t.Errorf("nightmare CrawlDepth (%d) should exceed aggressive (%d)", nm.Config.CrawlDepth, ag.Config.CrawlDepth)
	}
}

func TestDestroyerHigherConcurrencyThanNightmare(t *testing.T) {
	de, _ := Get("destroyer")
	nm, _ := Get("nightmare")

	if de.Config.Concurrency <= nm.Config.Concurrency {
		t.Errorf("destroyer Concurrency (%d) should exceed nightmare (%d)", de.Config.Concurrency, nm.Config.Concurrency)
	}
}

func TestStealthLowestConcurrency(t *testing.T) {
	stealth, _ := Get("stealth")
	for _, name := range List() {
		if name == "stealth" {
			continue
		}
		p, _ := Get(name)
		if p.Config.Concurrency < stealth.Config.Concurrency {
			t.Errorf("%s Concurrency (%d) is lower than stealth (%d)", name, p.Config.Concurrency, stealth.Config.Concurrency)
		}
	}
}

func TestEvasionModes(t *testing.T) {
	validEvasion := map[string]bool{"none": true, "basic": true, "advanced": true, "nightmare": true}
	for _, name := range List() {
		p, _ := Get(name)
		if !validEvasion[p.Config.EvasionMode] {
			t.Errorf("%s has invalid EvasionMode %q", name, p.Config.EvasionMode)
		}
	}
}

func TestMaxBodyReadPositive(t *testing.T) {
	for _, name := range List() {
		p, _ := Get(name)
		if p.Config.MaxBodyRead <= 0 {
			t.Errorf("%s MaxBodyRead = %d, should be positive", name, p.Config.MaxBodyRead)
		}
	}
}
