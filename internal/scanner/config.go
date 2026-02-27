package scanner

import "time"

// Config holds all scanner configuration parameters.
type Config struct {
	Target         string            // target URL (e.g. "http://localhost:8765")
	Concurrency    int               // worker count (default 10)
	RateLimit      int               // requests/sec (default 100)
	Timeout        time.Duration     // per-request timeout (default 10s)
	MaxBodyRead    int64             // max response body to read in bytes (default 1MB)
	CrawlFirst     bool              // crawl the target before running attack modules
	CrawlDepth     int               // max crawl depth (default 3)
	Profile        string            // compliance, aggressive, stealth, nightmare
	EnabledModules []string          // which modules to enable (empty = all)
	EvasionMode    string            // none, basic, advanced, nightmare
	UserAgent      string            // default User-Agent header
	CustomHeaders  map[string]string // extra headers sent on every request
	ProxyURL         string            // HTTP proxy URL (for testing through Glitch Proxy)
	OutputFile       string            // report output file path
	OutputFormat     string            // json, html (default json)
	Verbose          bool              // enable verbose logging
	CrawlConcurrency int              // parallel crawler worker count (default 10)
}

// DefaultConfig returns a balanced configuration suitable for general use.
func DefaultConfig() *Config {
	return &Config{
		Concurrency:      10,
		RateLimit:        100,
		Timeout:          10 * time.Second,
		MaxBodyRead:      1 << 20, // 1 MB
		CrawlFirst:       false,
		CrawlDepth:       3,
		Profile:          "default",
		EnabledModules:   nil,
		EvasionMode:      "none",
		UserAgent:        "GlitchScanner/1.0",
		CustomHeaders:    make(map[string]string),
		OutputFormat:     "json",
		Verbose:          false,
		CrawlConcurrency: 10,
	}
}

// NightmareConfig returns maximum-intensity settings: high concurrency,
// all modules enabled, all evasion techniques, deep crawl.
func NightmareConfig() *Config {
	c := DefaultConfig()
	c.Concurrency = 50
	c.RateLimit = 500
	c.Timeout = 30 * time.Second
	c.MaxBodyRead = 4 << 20 // 4 MB
	c.CrawlFirst = true
	c.CrawlDepth = 5
	c.Profile = "nightmare"
	c.EvasionMode = "nightmare"
	c.CrawlConcurrency = 50
	c.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	return c
}

// StealthConfig returns low-rate settings with evasion enabled and a
// realistic browser User-Agent to avoid triggering bot detection.
func StealthConfig() *Config {
	c := DefaultConfig()
	c.Concurrency = 3
	c.RateLimit = 10
	c.Timeout = 15 * time.Second
	c.CrawlFirst = true
	c.CrawlDepth = 2
	c.Profile = "stealth"
	c.EvasionMode = "advanced"
	c.CrawlConcurrency = 2
	c.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
	return c
}

// AggressiveConfig returns high-concurrency settings with all modules
// and no evasion — designed for maximum speed and coverage.
func AggressiveConfig() *Config {
	c := DefaultConfig()
	c.Concurrency = 30
	c.RateLimit = 300
	c.Timeout = 10 * time.Second
	c.MaxBodyRead = 2 << 20 // 2 MB
	c.CrawlFirst = true
	c.CrawlDepth = 4
	c.Profile = "aggressive"
	c.EvasionMode = "none"
	c.CrawlConcurrency = 20
	c.UserAgent = "GlitchScanner/1.0 (Aggressive)"
	return c
}

// ComplianceConfig returns polite, standards-compliant settings for
// baseline security testing. Low concurrency, respects rate limits.
func ComplianceConfig() *Config {
	c := DefaultConfig()
	c.Concurrency = 5
	c.RateLimit = 20
	c.Timeout = 15 * time.Second
	c.CrawlFirst = true
	c.CrawlDepth = 2
	c.Profile = "compliance"
	c.EvasionMode = "none"
	c.CrawlConcurrency = 5
	c.UserAgent = "GlitchScanner/1.0 (Compliance)"
	return c
}
