package spider

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

// Handler serves spider/crawler-related resources: robots.txt, sitemaps,
// favicons, and various metadata files that crawlers and browsers request.
// Each endpoint supports configurable error injection to test crawler resilience.
type Handler struct {
	cfg *Config
}

// NewHandler creates a Handler with the given configuration.
func NewHandler(cfg *Config) *Handler {
	if cfg == nil {
		cfg = NewConfig()
	}
	return &Handler{cfg: cfg}
}

// ShouldHandle returns true if the given path is a spider/crawler resource
// that this handler serves.
func (h *Handler) ShouldHandle(path string) bool {
	switch path {
	case "/robots.txt",
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/favicon.ico",
		"/apple-touch-icon.png",
		"/apple-touch-icon-precomposed.png",
		"/manifest.json",
		"/browserconfig.xml",
		"/humans.txt",
		"/ads.txt",
		"/.well-known/security.txt":
		return true
	}

	// Sub-sitemaps: /sitemap-1.xml, /sitemap-2.xml, etc.
	if strings.HasPrefix(path, "/sitemap-") && strings.HasSuffix(path, ".xml") {
		middle := path[len("/sitemap-") : len(path)-len(".xml")]
		if _, err := strconv.Atoi(middle); err == nil {
			return true
		}
	}

	return false
}

// ServeHTTP dispatches the request to the appropriate endpoint handler
// and returns the HTTP status code written.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch path {
	case "/robots.txt":
		return h.serveRobots(w, r)
	case "/sitemap.xml":
		return h.serveSitemap(w, r)
	case "/sitemap_index.xml":
		return h.serveSitemapIndex(w, r)
	case "/favicon.ico":
		return h.serveFavicon(w, r)
	case "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png":
		return h.serveAppleTouchIcon(w, r)
	case "/manifest.json":
		return h.serveManifest(w, r)
	case "/browserconfig.xml":
		return h.serveBrowserconfig(w, r)
	case "/humans.txt":
		return h.serveHumans(w, r)
	case "/ads.txt":
		return h.serveAds(w, r)
	case "/.well-known/security.txt":
		return h.serveSecurity(w, r)
	}

	// Sub-sitemaps
	if strings.HasPrefix(path, "/sitemap-") && strings.HasSuffix(path, ".xml") {
		middle := path[len("/sitemap-") : len(path)-len(".xml")]
		if n, err := strconv.Atoi(middle); err == nil {
			return h.serveSitemapN(w, r, n)
		}
	}

	http.NotFound(w, r)
	return 404
}

// GetConfig returns the handler's configuration for external inspection.
func (h *Handler) GetConfig() *Config {
	return h.cfg
}

// seedRand returns a deterministic random source seeded from the given path string.
// This ensures the same URL always produces the same "random" behavior.
func seedRand(path string) *rand.Rand {
	h := sha256.Sum256([]byte(path))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

// shouldError returns true if error injection should trigger, based on the given
// error rate. Uses a deterministic seed derived from the path and a salt so that
// the same URL consistently errors or succeeds (but different error types vary).
func shouldError(path string, salt string, rate float64) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 1.0 {
		return true
	}
	rng := seedRand(path + salt)
	return rng.Float64() < rate
}
