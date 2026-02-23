package spider

import (
	"fmt"
	"net/http"
	"strings"
)

// serveRobots serves a "real" robots.txt (as opposed to the honeypot trap version).
// It includes standard directives: User-agent, Disallow, Crawl-delay, and Sitemap.
// With configurable probability, it returns broken content (truncated, wrong content-type, or empty).
func (h *Handler) serveRobots(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.RobotsErrorRate
	crawlDelay := h.cfg.RobotsCrawlDelay
	disallowPaths := make([]string, len(h.cfg.RobotsDisallowPaths))
	copy(disallowPaths, h.cfg.RobotsDisallowPaths)
	enableSitemapIndex := h.cfg.EnableSitemapIndex
	h.cfg.mu.RUnlock()

	// Error injection
	if shouldError(r.URL.Path, "robots_error", errorRate) {
		rng := seedRand(r.URL.Path + "robots_mode")
		mode := rng.Intn(4)
		switch mode {
		case 0:
			// Truncated response — partial content
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte("User-agent: *\nDis"))
			return 200
		case 1:
			// Wrong content type — serve HTML instead of text
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			w.Write([]byte("<html><body>Not a robots file</body></html>"))
			return 200
		case 2:
			// Empty response
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(200)
			return 200
		case 3:
			// 500 error
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(500)
			w.Write([]byte("Internal Server Error"))
			return 500
		}
	}

	// Build valid robots.txt
	var b strings.Builder

	b.WriteString("# robots.txt - Glitch Web Server\n")
	b.WriteString("# This file tells web crawlers which pages to avoid.\n\n")

	b.WriteString("User-agent: *\n")
	for _, p := range disallowPaths {
		fmt.Fprintf(&b, "Disallow: %s\n", p)
	}

	// Standard disallow paths always present
	standardDisallows := []string{
		"/cgi-bin/",
		"/tmp/",
		"/private/",
	}
	for _, p := range standardDisallows {
		fmt.Fprintf(&b, "Disallow: %s\n", p)
	}

	if crawlDelay > 0 {
		fmt.Fprintf(&b, "Crawl-delay: %d\n", crawlDelay)
	}

	b.WriteString("\n")

	// Googlebot-specific rules
	b.WriteString("User-agent: Googlebot\n")
	b.WriteString("Allow: /\n")
	b.WriteString("Disallow: /admin/\n")
	if crawlDelay > 0 {
		fmt.Fprintf(&b, "Crawl-delay: %d\n", crawlDelay/2+1)
	}
	b.WriteString("\n")

	// Bingbot-specific rules
	b.WriteString("User-agent: Bingbot\n")
	b.WriteString("Allow: /\n")
	b.WriteString("Disallow: /admin/\n")
	b.WriteString("Disallow: /internal/\n")
	b.WriteString("\n")

	// Sitemap reference
	host := r.Host
	if host == "" {
		host = "localhost:8765"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if enableSitemapIndex {
		fmt.Fprintf(&b, "Sitemap: %s://%s/sitemap_index.xml\n", scheme, host)
	} else {
		fmt.Fprintf(&b, "Sitemap: %s://%s/sitemap.xml\n", scheme, host)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	w.Write([]byte(b.String()))
	return 200
}
