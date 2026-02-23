package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// CrawlResult holds information discovered for a single crawled URL.
type CrawlResult struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	ContentType  string   `json:"content_type"`
	Links        []string `json:"links,omitempty"`
	Forms        []FormInfo `json:"forms,omitempty"`
	APIEndpoints []string `json:"api_endpoints,omitempty"`
}

// FormInfo describes an HTML form found during crawling.
type FormInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Fields []string `json:"fields"`
}

// Crawler discovers pages and API endpoints by following links in a
// breadth-first manner with configurable depth limiting.
type Crawler struct {
	config  *Config
	client  *http.Client
	visited map[string]bool
	mu      sync.Mutex
	results []CrawlResult
}

// NewCrawler creates a Crawler using the given config and HTTP client.
func NewCrawler(config *Config, client *http.Client) *Crawler {
	return &Crawler{
		config:  config,
		client:  client,
		visited: make(map[string]bool),
		results: make([]CrawlResult, 0, 64),
	}
}

// crawlItem is an internal work item for the BFS queue.
type crawlItem struct {
	url   string
	depth int
}

// Crawl performs a breadth-first crawl starting from startURL.
// It respects the configured crawl depth and context cancellation.
func (c *Crawler) Crawl(ctx context.Context, startURL string) ([]CrawlResult, error) {
	base, err := url.Parse(startURL)
	if err != nil {
		return nil, err
	}

	queue := []crawlItem{{url: startURL, depth: 0}}
	c.markVisited(startURL)

	// Also try to discover paths from robots.txt.
	robotsLinks := c.fetchRobotsTxt(ctx, base)
	for _, link := range robotsLinks {
		norm := c.normalizeURL(base, link)
		if norm != "" && !c.isVisited(norm) {
			c.markVisited(norm)
			queue = append(queue, crawlItem{url: norm, depth: 1})
		}
	}

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return c.getResults(), ctx.Err()
		default:
		}

		item := queue[0]
		queue = queue[1:]

		if item.depth > c.config.CrawlDepth {
			continue
		}

		result, err := c.fetchPage(ctx, item.url)
		if err != nil {
			continue
		}

		c.mu.Lock()
		c.results = append(c.results, *result)
		c.mu.Unlock()

		if item.depth >= c.config.CrawlDepth {
			continue
		}

		// Enqueue newly discovered links.
		for _, link := range result.Links {
			norm := c.normalizeURL(base, link)
			if norm == "" {
				continue
			}
			if !c.isSameHost(base, norm) {
				continue
			}
			if c.isVisited(norm) {
				continue
			}
			c.markVisited(norm)
			queue = append(queue, crawlItem{url: norm, depth: item.depth + 1})
		}

		// Also enqueue form actions.
		for _, form := range result.Forms {
			if form.Action == "" {
				continue
			}
			norm := c.normalizeURL(base, form.Action)
			if norm == "" || !c.isSameHost(base, norm) || c.isVisited(norm) {
				continue
			}
			c.markVisited(norm)
			queue = append(queue, crawlItem{url: norm, depth: item.depth + 1})
		}

		// And discovered API endpoints.
		for _, ep := range result.APIEndpoints {
			norm := c.normalizeURL(base, ep)
			if norm == "" || !c.isSameHost(base, norm) || c.isVisited(norm) {
				continue
			}
			c.markVisited(norm)
			queue = append(queue, crawlItem{url: norm, depth: item.depth + 1})
		}
	}

	return c.getResults(), nil
}

// fetchPage performs an HTTP GET and extracts links, forms, and API
// endpoints from the response body.
func (c *Crawler) fetchPage(ctx context.Context, targetURL string) (*CrawlResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}
	for k, v := range c.config.CustomHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	maxRead := c.config.MaxBodyRead
	if maxRead <= 0 {
		maxRead = 1 << 20
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)

	ct := resp.Header.Get("Content-Type")
	result := &CrawlResult{
		URL:         targetURL,
		StatusCode:  resp.StatusCode,
		ContentType: ct,
	}

	// Only extract links from HTML-like content.
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "text/xml") || ct == "" {
		result.Links = c.extractLinks(body)
		result.Forms = c.extractForms(body)
		result.APIEndpoints = c.extractAPIEndpoints(body)
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// Link extraction
// ---------------------------------------------------------------------------

// Compiled regexps for link extraction.
var (
	reHref     = regexp.MustCompile(`(?i)(?:href|src)\s*=\s*["']([^"'#]+)["']`)
	rePrefetch = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*["']prefetch["'][^>]+href\s*=\s*["']([^"']+)["']`)
	reFetch    = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`)
	reFormTag  = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	reAction   = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	reMethod   = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)
	reInput    = regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']([^"']+)["']`)
	reSelect   = regexp.MustCompile(`(?i)<select[^>]+name\s*=\s*["']([^"']+)["']`)
	reTextarea = regexp.MustCompile(`(?i)<textarea[^>]+name\s*=\s*["']([^"']+)["']`)
)

// extractLinks pulls URLs from href, src, and link-prefetch attributes.
func (c *Crawler) extractLinks(body string) []string {
	seen := make(map[string]bool)
	var links []string

	for _, matches := range reHref.FindAllStringSubmatch(body, -1) {
		link := strings.TrimSpace(matches[1])
		if link != "" && !seen[link] {
			seen[link] = true
			links = append(links, link)
		}
	}

	for _, matches := range rePrefetch.FindAllStringSubmatch(body, -1) {
		link := strings.TrimSpace(matches[1])
		if link != "" && !seen[link] {
			seen[link] = true
			links = append(links, link)
		}
	}

	return links
}

// extractForms finds HTML forms and returns their action, method, and fields.
func (c *Crawler) extractForms(body string) []FormInfo {
	var forms []FormInfo

	for _, m := range reFormTag.FindAllStringSubmatch(body, -1) {
		attrs := m[1]
		inner := m[2]

		action := ""
		if am := reAction.FindStringSubmatch(attrs); am != nil {
			action = am[1]
		}
		method := "GET"
		if mm := reMethod.FindStringSubmatch(attrs); mm != nil {
			method = strings.ToUpper(mm[1])
		}

		var fields []string
		fieldSeen := make(map[string]bool)
		for _, re := range []*regexp.Regexp{reInput, reSelect, reTextarea} {
			for _, fm := range re.FindAllStringSubmatch(inner, -1) {
				name := fm[1]
				if !fieldSeen[name] {
					fieldSeen[name] = true
					fields = append(fields, name)
				}
			}
		}

		forms = append(forms, FormInfo{
			Action: action,
			Method: method,
			Fields: fields,
		})
	}

	return forms
}

// extractAPIEndpoints finds JavaScript fetch() calls pointing to API paths.
func (c *Crawler) extractAPIEndpoints(body string) []string {
	seen := make(map[string]bool)
	var endpoints []string

	for _, matches := range reFetch.FindAllStringSubmatch(body, -1) {
		ep := strings.TrimSpace(matches[1])
		if ep != "" && !seen[ep] {
			seen[ep] = true
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

// fetchRobotsTxt fetches /robots.txt and extracts Allow/Disallow paths
// and Sitemap URLs.
func (c *Crawler) fetchRobotsTxt(ctx context.Context, base *url.URL) []string {
	robotsURL := base.Scheme + "://" + base.Host + "/robots.txt"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return nil
	}
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64 KB max
	if err != nil {
		return nil
	}

	var paths []string
	for _, line := range strings.Split(string(bodyBytes), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "allow:") || strings.HasPrefix(lower, "disallow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if path != "" && path != "/" {
					paths = append(paths, path)
				}
			}
		}
		if strings.HasPrefix(lower, "sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				sm := strings.TrimSpace(parts[1])
				// Sitemap values often include the scheme, re-join if split.
				if !strings.HasPrefix(sm, "http") {
					sm = ":" + sm // was split at "Sitemap: http://..."
				}
				paths = append(paths, sm)
			}
		}
	}

	return paths
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

// normalizeURL resolves a possibly-relative link against the base URL
// and strips the fragment. Returns "" if the URL is unparseable or
// points to a non-HTTP scheme.
func (c *Crawler) normalizeURL(base *url.URL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// Skip data URIs, javascript:, mailto:, tel:, etc.
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"javascript:", "mailto:", "tel:", "data:", "#"} {
		if strings.HasPrefix(lower, prefix) {
			return ""
		}
	}

	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}

	resolved := base.ResolveReference(ref)
	resolved.Fragment = ""

	// Only follow HTTP(S).
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}

	return resolved.String()
}

// isSameHost returns true if the given absolute URL shares a host with base.
func (c *Crawler) isSameHost(base *url.URL, absURL string) bool {
	u, err := url.Parse(absURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
}

// markVisited records a URL as already seen.
func (c *Crawler) markVisited(u string) {
	c.mu.Lock()
	c.visited[u] = true
	c.mu.Unlock()
}

// isVisited checks if a URL has been seen before.
func (c *Crawler) isVisited(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[u]
}

// getResults returns a snapshot of the current crawl results.
func (c *Crawler) getResults() []CrawlResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CrawlResult, len(c.results))
	copy(out, c.results)
	return out
}
