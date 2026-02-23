package spider

import (
	"sync"
)

// Config holds all configurable parameters for the spider/crawler resource handler.
// All fields are protected by a mutex for concurrent access.
type Config struct {
	mu                  sync.RWMutex
	SitemapErrorRate    float64  // 0-1, chance of broken sitemap XML
	SitemapGzipErrorRate float64 // 0-1, chance of broken gzip encoding
	SitemapEntryCount   int      // Number of URL entries in sitemap (default 50)
	FaviconErrorRate    float64  // 0-1, chance of serving invalid favicon
	RobotsCrawlDelay    int      // Crawl-delay directive value (0=omit)
	RobotsDisallowPaths []string // Additional disallow paths
	RobotsErrorRate     float64  // 0-1, chance of broken robots.txt
	MetaErrorRate       float64  // 0-1, chance of broken meta files
	EnableSitemapIndex  bool     // Whether to serve sitemap index with sub-sitemaps
	EnableGzipSitemap   bool     // Whether to serve gzip-compressed sitemap
}

// NewConfig returns a Config with sensible defaults.
func NewConfig() *Config {
	return &Config{
		SitemapErrorRate:     0.15,
		SitemapGzipErrorRate: 0.10,
		SitemapEntryCount:    50,
		FaviconErrorRate:     0.20,
		RobotsCrawlDelay:     2,
		RobotsDisallowPaths:  []string{"/admin/", "/internal/", "/api/debug/"},
		RobotsErrorRate:      0.10,
		MetaErrorRate:        0.10,
		EnableSitemapIndex:   true,
		EnableGzipSitemap:    true,
	}
}

// Get retrieves a configuration value by key name. Returns nil if the key is unknown.
func (c *Config) Get(key string) interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	switch key {
	case "sitemap_error_rate":
		return c.SitemapErrorRate
	case "sitemap_gzip_error_rate":
		return c.SitemapGzipErrorRate
	case "sitemap_entry_count":
		return c.SitemapEntryCount
	case "favicon_error_rate":
		return c.FaviconErrorRate
	case "robots_crawl_delay":
		return c.RobotsCrawlDelay
	case "robots_disallow_paths":
		return c.RobotsDisallowPaths
	case "robots_error_rate":
		return c.RobotsErrorRate
	case "meta_error_rate":
		return c.MetaErrorRate
	case "enable_sitemap_index":
		return c.EnableSitemapIndex
	case "enable_gzip_sitemap":
		return c.EnableGzipSitemap
	default:
		return nil
	}
}

// Set updates a configuration value by key name. Returns true if the key was recognized
// and the value was of the correct type; false otherwise.
func (c *Config) Set(key string, value interface{}) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch key {
	case "sitemap_error_rate":
		if v, ok := value.(float64); ok {
			c.SitemapErrorRate = clampFloat(v, 0, 1)
			return true
		}
	case "sitemap_gzip_error_rate":
		if v, ok := value.(float64); ok {
			c.SitemapGzipErrorRate = clampFloat(v, 0, 1)
			return true
		}
	case "sitemap_entry_count":
		if v, ok := value.(int); ok {
			if v < 1 {
				v = 1
			}
			if v > 10000 {
				v = 10000
			}
			c.SitemapEntryCount = v
			return true
		}
	case "favicon_error_rate":
		if v, ok := value.(float64); ok {
			c.FaviconErrorRate = clampFloat(v, 0, 1)
			return true
		}
	case "robots_crawl_delay":
		if v, ok := value.(int); ok {
			if v < 0 {
				v = 0
			}
			c.RobotsCrawlDelay = v
			return true
		}
	case "robots_disallow_paths":
		if v, ok := value.([]string); ok {
			c.RobotsDisallowPaths = v
			return true
		}
	case "robots_error_rate":
		if v, ok := value.(float64); ok {
			c.RobotsErrorRate = clampFloat(v, 0, 1)
			return true
		}
	case "meta_error_rate":
		if v, ok := value.(float64); ok {
			c.MetaErrorRate = clampFloat(v, 0, 1)
			return true
		}
	case "enable_sitemap_index":
		if v, ok := value.(bool); ok {
			c.EnableSitemapIndex = v
			return true
		}
	case "enable_gzip_sitemap":
		if v, ok := value.(bool); ok {
			c.EnableGzipSitemap = v
			return true
		}
	}
	return false
}

// Snapshot returns a copy of all configuration values as a map.
func (c *Config) Snapshot() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	paths := make([]string, len(c.RobotsDisallowPaths))
	copy(paths, c.RobotsDisallowPaths)

	return map[string]interface{}{
		"sitemap_error_rate":      c.SitemapErrorRate,
		"sitemap_gzip_error_rate": c.SitemapGzipErrorRate,
		"sitemap_entry_count":     c.SitemapEntryCount,
		"favicon_error_rate":      c.FaviconErrorRate,
		"robots_crawl_delay":      c.RobotsCrawlDelay,
		"robots_disallow_paths":   paths,
		"robots_error_rate":       c.RobotsErrorRate,
		"meta_error_rate":         c.MetaErrorRate,
		"enable_sitemap_index":    c.EnableSitemapIndex,
		"enable_gzip_sitemap":     c.EnableGzipSitemap,
	}
}

func clampFloat(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
