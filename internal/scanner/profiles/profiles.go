// Package profiles provides predefined scan configurations for common use
// cases. Each profile bundles concurrency, rate limiting, evasion, and module
// settings into a coherent scanning strategy.
package profiles

import (
	"fmt"
	"sort"
	"time"

	scanner "github.com/cornerglitch/internal/scanner"
)

// Profile is a named, documented scan configuration. It wraps a scanner.Config
// with metadata describing its intended use case.
type Profile struct {
	Name        string
	Description string
	Config      scanner.Config
}

// registry holds all known profiles, keyed by lowercase name.
var registry = map[string]*Profile{
	"compliance":  complianceProfile(),
	"aggressive":  aggressiveProfile(),
	"stealth":     stealthProfile(),
	"nightmare":   nightmareProfile(),
	"destroyer":   destroyerProfile(),
	"waf-buster":  wafBusterProfile(),
}

// Get returns the profile with the given name, or an error if no profile
// exists with that name. Names are case-sensitive and should be lowercase.
func Get(name string) (*Profile, error) {
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q; available: %v", name, List())
	}
	// Return a copy so callers can't mutate the registry.
	cp := *p
	cpConfig := p.Config
	if p.Config.CustomHeaders != nil {
		cpConfig.CustomHeaders = make(map[string]string, len(p.Config.CustomHeaders))
		for k, v := range p.Config.CustomHeaders {
			cpConfig.CustomHeaders[k] = v
		}
	}
	if p.Config.EnabledModules != nil {
		cpConfig.EnabledModules = make([]string, len(p.Config.EnabledModules))
		copy(cpConfig.EnabledModules, p.Config.EnabledModules)
	}
	cp.Config = cpConfig
	return &cp, nil
}

// List returns the names of all available profiles in alphabetical order.
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns every registered profile, sorted by name.
func All() []*Profile {
	names := List()
	profiles := make([]*Profile, 0, len(names))
	for _, name := range names {
		p, _ := Get(name)
		profiles = append(profiles, p)
	}
	return profiles
}

// complianceProfile returns a polite, standards-compliant configuration for
// baseline security testing. Low concurrency, moderate rate limiting, no
// evasion techniques, and only standard detection modules.
func complianceProfile() *Profile {
	return &Profile{
		Name: "compliance",
		Description: "Polite, standards-compliant scanning for baseline security assessment. " +
			"Low concurrency and rate limiting to avoid disruption. No evasion techniques. " +
			"Suitable for production environments with change-control requirements.",
		Config: scanner.Config{
			Concurrency:    2,
			RateLimit:      10,
			Timeout:        15 * time.Second,
			MaxBodyRead:    1 << 20, // 1 MB
			CrawlFirst:     true,
			CrawlDepth:     2,
			Profile:        "compliance",
			EnabledModules: []string{"headers", "tls", "cookies", "cors", "csp"},
			EvasionMode:    "none",
			UserAgent:      "GlitchScanner/1.0 (Compliance Audit)",
			CustomHeaders:  make(map[string]string),
			OutputFormat:   "json",
			Verbose:        false,
		},
	}
}

// aggressiveProfile returns a high-throughput configuration with all modules
// enabled and no evasion. Designed for maximum coverage and speed on targets
// where stealth is not a concern.
func aggressiveProfile() *Profile {
	return &Profile{
		Name: "aggressive",
		Description: "High-concurrency, full-coverage scan with all attack modules enabled. " +
			"No evasion techniques — prioritizes speed and thoroughness over stealth. " +
			"All known attack payloads are tested.",
		Config: scanner.Config{
			Concurrency: 50,
			RateLimit:   500,
			Timeout:     10 * time.Second,
			MaxBodyRead: 2 << 20, // 2 MB
			CrawlFirst:  true,
			CrawlDepth:  5,
			Profile:     "aggressive",
			EnabledModules: []string{
				"headers", "tls", "cookies", "cors", "csp",
				"xss", "sqli", "path-traversal", "command-injection",
				"ssti", "ssrf", "open-redirect", "file-upload",
				"xxe", "deserialization", "ldap-injection",
				"nosql-injection", "graphql", "websocket",
				"http-smuggling", "cache-poisoning",
			},
			EvasionMode:   "none",
			UserAgent:     "GlitchScanner/1.0 (Aggressive)",
			CustomHeaders: make(map[string]string),
			OutputFormat:  "json",
			Verbose:       true,
		},
	}
}

// stealthProfile returns a low-and-slow configuration with realistic browser
// behavior and advanced evasion. Designed to avoid triggering bot detection,
// WAFs, and rate limiters.
func stealthProfile() *Profile {
	return &Profile{
		Name: "stealth",
		Description: "Low-rate stealth scan with realistic browser fingerprinting and advanced " +
			"evasion techniques. Single-threaded with randomized delays between requests. " +
			"User-Agent rotation mimics real browser diversity.",
		Config: scanner.Config{
			Concurrency:    1,
			RateLimit:      2,
			Timeout:        20 * time.Second,
			MaxBodyRead:    1 << 20, // 1 MB
			CrawlFirst:     true,
			CrawlDepth:     3,
			Profile:        "stealth",
			EnabledModules: nil, // all modules, but fired slowly
			EvasionMode:    "advanced",
			UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			CustomHeaders: map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate, br",
			},
			OutputFormat: "json",
			Verbose:      false,
		},
	}
}

// destroyerProfile returns a maximum-aggression configuration focused on
// crashing, hanging, or OOMing the target server. No evasion, no rate limit,
// all attack modules with emphasis on server-killing techniques.
func destroyerProfile() *Profile {
	return &Profile{
		Name: "destroyer",
		Description: "Server destruction profile. Maximum concurrency with no rate limiting. " +
			"All attack modules enabled including slow HTTP, compression bombs, ReDoS, " +
			"multipart bombs, and connection exhaustion. Designed to find crashes, hangs, " +
			"and OOM conditions in target servers. WARNING: Will likely crash the target.",
		Config: scanner.Config{
			Concurrency: 200,
			RateLimit:   0, // unlimited
			Timeout:     60 * time.Second,
			MaxBodyRead: 8 << 20, // 8 MB
			CrawlFirst:  false,   // skip crawling, go straight to attacks
			CrawlDepth:  0,
			Profile:     "destroyer",
			EnabledModules: nil, // all modules
			EvasionMode:    "none",
			UserAgent:      "GlitchScanner/1.0 (Destroyer)",
			CustomHeaders: map[string]string{
				"Connection": "keep-alive",
				"Keep-Alive": "timeout=600, max=99999",
			},
			OutputFormat: "json",
			Verbose:      true,
		},
	}
}

// wafBusterProfile returns a WAF-focused configuration emphasizing encoding
// bypass, request smuggling, and resource exhaustion attacks. Skips crawling
// and goes straight to WAF bypass payloads with nightmare-level evasion.
func wafBusterProfile() *Profile {
	return &Profile{
		Name: "waf-buster",
		Description: "WAF bypass specialist profile. Targets Web Application Firewalls with encoding " +
			"tricks, request smuggling, parser confusion, CVE-specific payloads, and resource " +
			"exhaustion attacks. Nightmare evasion mode applies all encoding variants. " +
			"Skips crawling — goes straight to WAF bypass attacks.",
		Config: scanner.Config{
			Concurrency: 30,
			RateLimit:   100,
			Timeout:     30 * time.Second,
			MaxBodyRead: 2 << 20, // 2 MB
			CrawlFirst:  false,
			CrawlDepth:  0,
			Profile:     "waf-buster",
			EnabledModules: []string{
				"waf", "slowhttp", "breakage", "protocol",
				"h3", "owasp", "injection",
			},
			EvasionMode:   "nightmare",
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			CustomHeaders: make(map[string]string),
			OutputFormat:  "json",
			Verbose:       true,
		},
	}
}

// nightmareProfile returns an extreme configuration designed to overwhelm,
// crash, or confuse the target. Maximum concurrency with no rate limiting,
// all modules including protocol-level abuse, and nightmare-level evasion
// with forged headers, encoding tricks, and cache busting.
func nightmareProfile() *Profile {
	return &Profile{
		Name: "nightmare",
		Description: "Maximum-intensity scan designed to stress-test and overwhelm the target. " +
			"100 concurrent workers with no rate limiting. All modules enabled including " +
			"protocol abuse. Nightmare evasion with forged IPs, encoding tricks, and cache busting. " +
			"WARNING: This profile may crash the target server.",
		Config: scanner.Config{
			Concurrency: 100,
			RateLimit:   0, // unlimited
			Timeout:     30 * time.Second,
			MaxBodyRead: 4 << 20, // 4 MB
			CrawlFirst:  true,
			CrawlDepth:  10,
			Profile:     "nightmare",
			EnabledModules: []string{
				"headers", "tls", "cookies", "cors", "csp",
				"xss", "sqli", "path-traversal", "command-injection",
				"ssti", "ssrf", "open-redirect", "file-upload",
				"xxe", "deserialization", "ldap-injection",
				"nosql-injection", "graphql", "websocket",
				"http-smuggling", "cache-poisoning",
				// Protocol abuse modules specific to nightmare.
				"request-flooding", "slowloris", "header-bomb",
				"body-bomb", "connection-exhaustion",
				// Chaos module for malformed/impossible requests.
				"chaos",
				// Server destruction modules.
				"slowhttp", "tls",
			},
			EvasionMode: "nightmare",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			CustomHeaders: map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate, br",
				"Cache-Control":   "no-cache",
				"Pragma":          "no-cache",
			},
			OutputFormat: "json",
			Verbose:      true,
		},
	}
}
