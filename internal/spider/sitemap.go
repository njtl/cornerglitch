package spider

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// sitemapPaths are realistic URL paths that appear in sitemap entries.
var sitemapPaths = []string{
	"/",
	"/about",
	"/contact",
	"/products",
	"/services",
	"/blog",
	"/blog/latest",
	"/blog/archive",
	"/faq",
	"/terms",
	"/privacy",
	"/search",
	"/api/v1/users",
	"/api/v1/products",
	"/api/v1/orders",
	"/vuln/a01/",
	"/vuln/a02/",
	"/vuln/a03/",
	"/vuln/a04/",
	"/vuln/a05/",
	"/vuln/a06/",
	"/vuln/a07/",
	"/vuln/a08/",
	"/vuln/a09/",
	"/vuln/a10/",
	"/login",
	"/register",
	"/dashboard",
	"/settings",
	"/profile",
	"/help",
	"/status",
	"/docs",
	"/docs/api",
	"/docs/guides",
	"/pricing",
	"/features",
	"/integrations",
	"/changelog",
	"/security",
	"/careers",
	"/press",
	"/partners",
	"/support",
	"/support/tickets",
	"/community",
	"/events",
	"/webinars",
	"/case-studies",
	"/resources",
	"/downloads",
	"/articles/tech/web-scraping-101",
	"/articles/security/owasp-top-10",
	"/articles/devops/ci-cd-pipelines",
}

// serveSitemap generates and serves /sitemap.xml with URL entries.
// Error injection can produce broken XML, truncated output, or invalid gzip.
func (h *Handler) serveSitemap(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.SitemapErrorRate
	gzipErrorRate := h.cfg.SitemapGzipErrorRate
	entryCount := h.cfg.SitemapEntryCount
	enableGzip := h.cfg.EnableGzipSitemap
	h.cfg.mu.RUnlock()

	// Error injection: broken XML
	if shouldError(r.URL.Path, "sitemap_xml_error", errorRate) {
		return h.serveBrokenSitemap(w, r)
	}

	// Error injection: broken gzip
	if enableGzip && shouldError(r.URL.Path, "sitemap_gzip_error", gzipErrorRate) {
		return h.serveBrokenGzipSitemap(w, r)
	}

	xml := h.buildSitemapXML(r, entryCount, 0)

	// Serve with gzip if enabled and client accepts it
	if enableGzip && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return h.serveGzipContent(w, xml, "application/xml; charset=utf-8")
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write([]byte(xml))
	return 200
}

// serveSitemapIndex serves /sitemap_index.xml referencing sub-sitemaps.
func (h *Handler) serveSitemapIndex(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.SitemapErrorRate
	enableIndex := h.cfg.EnableSitemapIndex
	h.cfg.mu.RUnlock()

	if !enableIndex {
		http.NotFound(w, r)
		return 404
	}

	if shouldError(r.URL.Path, "sitemap_index_error", errorRate) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(200)
		// Truncated XML
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>`))
		return 200
	}

	host := r.Host
	if host == "" {
		host = "localhost:8765"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	now := time.Now().UTC().Format("2006-01-02")

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")

	// Generate 3 sub-sitemap references
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&b, "  <sitemap>\n")
		fmt.Fprintf(&b, "    <loc>%s://%s/sitemap-%d.xml</loc>\n", scheme, host, i)
		fmt.Fprintf(&b, "    <lastmod>%s</lastmod>\n", now)
		fmt.Fprintf(&b, "  </sitemap>\n")
	}

	b.WriteString("</sitemapindex>\n")

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write([]byte(b.String()))
	return 200
}

// serveSitemapN serves individual sub-sitemaps: /sitemap-1.xml, /sitemap-2.xml, etc.
func (h *Handler) serveSitemapN(w http.ResponseWriter, r *http.Request, n int) int {
	if n < 1 || n > 3 {
		http.NotFound(w, r)
		return 404
	}

	h.cfg.mu.RLock()
	errorRate := h.cfg.SitemapErrorRate
	entryCount := h.cfg.SitemapEntryCount
	enableGzip := h.cfg.EnableGzipSitemap
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "sitemap_n_error", errorRate) {
		return h.serveBrokenSitemap(w, r)
	}

	// Each sub-sitemap gets a different slice of paths using an offset
	offset := (n - 1) * entryCount / 3
	count := entryCount / 3
	if count < 5 {
		count = 5
	}

	xml := h.buildSitemapXML(r, count, offset)

	if enableGzip && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return h.serveGzipContent(w, xml, "application/xml; charset=utf-8")
	}

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write([]byte(xml))
	return 200
}

// buildSitemapXML constructs a valid sitemap XML string with the specified number
// of URL entries starting from the given offset into the path list.
func (h *Handler) buildSitemapXML(r *http.Request, count, offset int) string {
	host := r.Host
	if host == "" {
		host = "localhost:8765"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	now := time.Now().UTC().Format("2006-01-02")

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")

	priorities := []string{"1.0", "0.8", "0.6", "0.5", "0.3"}
	frequencies := []string{"daily", "weekly", "monthly", "yearly"}

	for i := 0; i < count; i++ {
		idx := (offset + i) % len(sitemapPaths)
		path := sitemapPaths[idx]

		priority := priorities[i%len(priorities)]
		freq := frequencies[i%len(frequencies)]

		fmt.Fprintf(&b, "  <url>\n")
		fmt.Fprintf(&b, "    <loc>%s://%s%s</loc>\n", scheme, host, path)
		fmt.Fprintf(&b, "    <lastmod>%s</lastmod>\n", now)
		fmt.Fprintf(&b, "    <changefreq>%s</changefreq>\n", freq)
		fmt.Fprintf(&b, "    <priority>%s</priority>\n", priority)
		fmt.Fprintf(&b, "  </url>\n")
	}

	b.WriteString("</urlset>\n")
	return b.String()
}

// serveBrokenSitemap serves intentionally invalid sitemap XML.
func (h *Handler) serveBrokenSitemap(w http.ResponseWriter, r *http.Request) int {
	rng := seedRand(r.URL.Path + "broken_mode")
	mode := rng.Intn(4)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(200)

	switch mode {
	case 0:
		// Unclosed tags
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>http://localhost:8765/</loc>
    <lastmod>2024-01-15</lastmod>
    <priority>1.0
  </url>
  <url>
    <loc>http://localhost:8765/about
`))
	case 1:
		// Invalid XML characters (control characters)
		w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset>\x00\x01\x02<url><loc>\x08broken</loc></url></urlset>"))
	case 2:
		// Truncated mid-tag
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>http://localhos`))
	case 3:
		// Wrong root element / malformed structure
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<notasitemap>
  <entry><link>http://localhost:8765/</link></entry>
  <broken><![CDATA[>>>>]]]]></broken>
</notasitemap>`))
	}

	return 200
}

// serveBrokenGzipSitemap sends a Content-Encoding: gzip header but writes
// invalid gzip data to test crawler decompression error handling.
func (h *Handler) serveBrokenGzipSitemap(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.WriteHeader(200)

	rng := seedRand(r.URL.Path + "gzip_broken")
	mode := rng.Intn(3)

	switch mode {
	case 0:
		// Random bytes that look nothing like gzip
		garbage := make([]byte, 256)
		for i := range garbage {
			garbage[i] = byte(rng.Intn(256))
		}
		w.Write(garbage)
	case 1:
		// Gzip magic bytes followed by garbage (partial gzip header)
		data := []byte{0x1f, 0x8b, 0x08, 0x00}
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(rng.Intn(256))
		}
		w.Write(append(data, garbage...))
	case 2:
		// Truncated valid gzip — compress then cut in half
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>http://localhost/test</loc></url></urlset>`))
		gz.Close()
		full := buf.Bytes()
		w.Write(full[:len(full)/2])
	}

	return 200
}

// serveGzipContent compresses the given content with gzip and writes it to the response.
func (h *Handler) serveGzipContent(w http.ResponseWriter, content string, contentType string) int {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(content)); err != nil {
		w.WriteHeader(500)
		return 500
	}
	if err := gz.Close(); err != nil {
		w.WriteHeader(500)
		return 500
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(200)
	w.Write(buf.Bytes())
	return 200
}
