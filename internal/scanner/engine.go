package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Core types (Finding and ScanResult; AttackModule and AttackRequest are
// defined in module.go)
// ---------------------------------------------------------------------------

// Finding represents a single vulnerability or observation discovered
// during a scan.
type Finding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	Evidence    string `json:"evidence"`
	Description string `json:"description"`
}

// ScanResult stores the outcome of executing a single AttackRequest.
type ScanResult struct {
	Request     AttackRequest     `json:"request"`
	StatusCode  int               `json:"status_code"`
	LatencyMs   int64             `json:"latency_ms"`
	BodySize    int64             `json:"body_size"`
	Error       string            `json:"error,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodySnippet string            `json:"body_snippet,omitempty"` // first 512 bytes
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

// Engine is the main scan orchestrator. It manages a pool of workers,
// rate-limits outgoing requests, tracks progress, and collects results.
type Engine struct {
	config   *Config
	client   *http.Client
	crawler  *Crawler
	modules  []AttackModule
	reporter *Reporter

	// Progress tracking (read via atomic).
	completed atomic.Int64
	total     atomic.Int64
	found     atomic.Int64

	// Phase tracking for UI feedback during crawl/generation phases.
	phase atomic.Value // string: "init", "crawling", "generating", "scanning", "done"

	// Detailed progress tracking.
	crawledURLs      atomic.Int64
	generatedAttacks atomic.Int64
	currentURL       atomic.Value // string

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
}

// NewEngine creates an Engine with the given configuration. It sets up
// the HTTP client (with optional proxy) and creates internal subsystems.
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        config.Concurrency * 2,
		MaxIdleConnsPerHost: config.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — intentional for scanner
		TLSHandshakeTimeout: config.Timeout,
	}

	// Configure proxy if specified.
	if config.ProxyURL != "" {
		if proxyURL, err := url.Parse(config.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		// Do not follow redirects automatically; we want to observe them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	e := &Engine{
		config:   config,
		client:   client,
		modules:  make([]AttackModule, 0),
		reporter: NewReporter(),
	}
	e.phase.Store("init")

	e.crawler = NewCrawler(config, client)

	return e
}

// RegisterModule adds an attack module to the engine. Modules are
// invoked during Run to generate attack requests.
func (e *Engine) RegisterModule(m AttackModule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules = append(e.modules, m)
}

// Run executes the full scan: optional crawl, request generation,
// rate-limited parallel execution, and report building.
func (e *Engine) Run(ctx context.Context) (*Report, error) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil, fmt.Errorf("scan is already running")
	}
	e.running = true
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.mu.Unlock()

	defer func() {
		cancel()
		e.mu.Lock()
		e.running = false
		e.cancel = nil
		e.mu.Unlock()
	}()

	startedAt := time.Now()

	// ---- Phase 1: optional crawl ----
	// Give crawl at most 30% of the remaining time so attacks get the rest.
	var crawlResults []CrawlResult
	if e.config.CrawlFirst {
		e.phase.Store("crawling")
		crawlBudget := 15 * time.Second // default
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			crawlFraction := 0.3
			if e.config.Profile == "nightmare" {
				crawlFraction = 0.15
			}
			crawlBudget = time.Duration(float64(remaining) * crawlFraction)
			if crawlBudget < 5*time.Second {
				crawlBudget = 5 * time.Second
			}
		}
		crawlCtx, crawlCancel := context.WithTimeout(ctx, crawlBudget)
		var err error
		crawlResults, err = e.crawler.Crawl(crawlCtx, e.config.Target)
		crawlCancel()
		// Errors during crawl are non-fatal; we continue with whatever we got.
		if err != nil && crawlCtx.Err() == nil {
			e.reporter.AddError("crawl error: " + err.Error())
		}
	}

	e.crawledURLs.Store(int64(len(crawlResults)))

	// Check if the parent context was cancelled (not just crawl budget).
	if ctx.Err() != nil {
		completedAt := time.Now()
		return e.reporter.BuildReport(e.config, startedAt, completedAt), ctx.Err()
	}

	// ---- Phase 2: generate attack requests ----
	e.phase.Store("generating")
	requests := e.generateRequests(crawlResults)
	e.total.Store(int64(len(requests)))
	e.generatedAttacks.Store(int64(len(requests)))
	e.completed.Store(0)
	e.found.Store(0)

	if len(requests) == 0 {
		e.phase.Store("done")
		completedAt := time.Now()
		return e.reporter.BuildReport(e.config, startedAt, completedAt), nil
	}

	// ---- Phase 3: execute via worker pool with rate limiting ----
	e.phase.Store("scanning")
	err := e.executeAll(ctx, requests)
	if err != nil && ctx.Err() != nil {
		// Scan was cancelled or duration expired; build partial report.
		completedAt := time.Now()
		return e.reporter.BuildReport(e.config, startedAt, completedAt), ctx.Err()
	}

	// ---- Phase 4: raw TCP attack modules ----
	if ctx.Err() == nil {
		for _, mod := range e.modules {
			if rawMod, ok := mod.(RawTCPModule); ok {
				// Check if module is enabled.
				if len(e.config.EnabledModules) > 0 {
					enabled := false
					for _, name := range e.config.EnabledModules {
						if strings.EqualFold(name, mod.Name()) {
							enabled = true
							break
						}
					}
					if !enabled {
						continue
					}
				}
				findings := rawMod.RunRawTCP(ctx, e.config.Target, e.config.Concurrency, e.config.Timeout)
				for _, f := range findings {
					e.reporter.AddFinding(f)
					e.found.Add(1)
				}
			}
		}
	}

	// ---- Phase 5: build report ----
	e.phase.Store("done")
	completedAt := time.Now()
	report := e.reporter.BuildReport(e.config, startedAt, completedAt)
	return report, nil
}

// Stop cancels a running scan.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
}

// Progress returns the current scan progress: how many requests have
// been completed, the total count, and how many findings exist so far.
func (e *Engine) Progress() (completed, total int, findings int) {
	return int(e.completed.Load()), int(e.total.Load()), int(e.found.Load())
}

// Phase returns the current scan phase: "init", "crawling", "generating",
// "scanning", or "done".
func (e *Engine) Phase() string {
	v := e.phase.Load()
	if v == nil {
		return "init"
	}
	return v.(string)
}

// ProgressInfo holds detailed scan progress information.
type ProgressInfo struct {
	Phase            string `json:"phase"`
	Completed        int    `json:"completed"`
	Total            int    `json:"total"`
	Findings         int    `json:"findings"`
	CrawledURLs      int    `json:"crawled_urls"`
	GeneratedAttacks int    `json:"generated_attacks"`
	CurrentURL       string `json:"current_url"`
}

// ProgressDetail returns detailed progress information for the current scan.
func (e *Engine) ProgressDetail() ProgressInfo {
	currentURL := ""
	if v := e.currentURL.Load(); v != nil {
		currentURL = v.(string)
	}
	return ProgressInfo{
		Phase:            e.Phase(),
		Completed:        int(e.completed.Load()),
		Total:            int(e.total.Load()),
		Findings:         int(e.found.Load()),
		CrawledURLs:      int(e.crawledURLs.Load()),
		GeneratedAttacks: int(e.generatedAttacks.Load()),
		CurrentURL:       currentURL,
	}
}

// ---------------------------------------------------------------------------
// Request generation
// ---------------------------------------------------------------------------

// generateRequests collects attack requests from all registered modules,
// optionally filtered by EnabledModules, and augments them with any
// crawl-discovered paths.
func (e *Engine) generateRequests(crawlResults []CrawlResult) []AttackRequest {
	var requests []AttackRequest

	enabledSet := make(map[string]bool)
	for _, name := range e.config.EnabledModules {
		enabledSet[strings.ToLower(name)] = true
	}

	for _, mod := range e.modules {
		// If EnabledModules is non-empty, skip modules not in the list.
		if len(enabledSet) > 0 && !enabledSet[strings.ToLower(mod.Name())] {
			continue
		}

		modRequests := mod.GenerateRequests(e.config.Target)
		requests = append(requests, modRequests...)
	}

	// If we crawled, add baseline GET requests for discovered URLs that
	// are not already covered by module-generated requests.
	if len(crawlResults) > 0 {
		coveredPaths := make(map[string]bool)
		for _, r := range requests {
			coveredPaths[r.Path] = true
		}

		for _, cr := range crawlResults {
			if !coveredPaths[cr.URL] {
				requests = append(requests, AttackRequest{
					Method:      "GET",
					Path:        cr.URL,
					Category:    "crawl",
					SubCategory: "baseline",
					Description: "Baseline check for crawled URL",
				})
			}
		}
	}

	// Nightmare mode: generate additional chaotic variants from base requests.
	if e.config.Profile == "nightmare" {
		base := make([]AttackRequest, len(requests))
		copy(base, requests)

		requests = append(requests, e.generateNightmareVariants(requests)...)

		// Ensure nightmare produces at least 500 requests.
		if len(requests) < 500 {
			for len(requests) < 500 {
				idx := len(requests) % len(base)
				req := base[idx]
				requests = append(requests, AttackRequest{
					Method:      req.Method,
					Path:        req.Path + fmt.Sprintf("?nightmare_pad=%d", len(requests)),
					Category:    "chaos",
					SubCategory: "nightmare-padding",
					Description: fmt.Sprintf("Nightmare padding request #%d", len(requests)),
					Headers:     map[string]string{"X-Nightmare": "true"},
				})
			}
		}
	}

	return requests
}

// generateNightmareVariants creates corrupted-header and malformed-body
// variants from the base request set for nightmare mode stress testing.
func (e *Engine) generateNightmareVariants(base []AttackRequest) []AttackRequest {
	var variants []AttackRequest

	// For every 3rd request, create a corrupted-header variant.
	for i := 0; i < len(base); i += 3 {
		req := base[i]
		variant := AttackRequest{
			Method:      req.Method,
			Path:        req.Path,
			Body:        req.Body,
			BodyType:    req.BodyType,
			Category:    req.Category,
			SubCategory: req.SubCategory + "-nightmare-corrupt",
			Description: req.Description + " (nightmare: corrupted headers)",
			Headers:     make(map[string]string),
		}
		for k, v := range req.Headers {
			variant.Headers[k] = v
		}
		variant.Headers["X-Nightmare-Chaos"] = strings.Repeat("CHAOS", 200)
		variant.Headers["X-Forwarded-For"] = "127.0.0.1, 10.0.0.1, 192.168.1.1, ::1, 0.0.0.0"
		variant.Headers["X-Nightmare-ID"] = fmt.Sprintf("nightmare-%d", i)
		variants = append(variants, variant)
	}

	// For every 5th request, create a malformed-body variant.
	for i := 0; i < len(base); i += 5 {
		req := base[i]
		variant := AttackRequest{
			Method:      "POST",
			Path:        req.Path,
			Body:        strings.Repeat("\x00\xff\xfe\x00", 256),
			BodyType:    "application/octet-stream",
			Category:    req.Category,
			SubCategory: req.SubCategory + "-nightmare-malformed",
			Description: req.Description + " (nightmare: malformed body)",
			Headers:     make(map[string]string),
		}
		for k, v := range req.Headers {
			variant.Headers[k] = v
		}
		variant.Headers["Content-Length"] = "99999"
		variants = append(variants, variant)
	}

	return variants
}

// ---------------------------------------------------------------------------
// Worker pool + rate limiter
// ---------------------------------------------------------------------------

// executeAll sends all requests through a fixed-size worker pool with a
// token-bucket rate limiter backed by a time.Ticker.
func (e *Engine) executeAll(ctx context.Context, requests []AttackRequest) error {
	concurrency := e.config.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	// Rate limiter: one token per (1s / RateLimit). 0 means unlimited.
	rateLimit := e.config.RateLimit
	var ticker *time.Ticker
	if rateLimit > 0 {
		interval := time.Second / time.Duration(rateLimit)
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	work := make(chan AttackRequest, concurrency*2)
	var wg sync.WaitGroup

	// Start workers.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range work {
				e.currentURL.Store(req.Path)
				result := e.executeRequest(ctx, req)
				e.reporter.AddResult(result)
				e.completed.Add(1)

				// Update finding count from reporter.
				e.found.Store(int64(e.reporter.FindingCount()))
			}
		}()
	}

	// Feed work channel with rate limiting.
	for _, req := range requests {
		if ticker != nil {
			select {
			case <-ctx.Done():
				close(work)
				wg.Wait()
				return ctx.Err()
			case <-ticker.C:
				// Rate-limit token acquired.
			}
		}

		select {
		case <-ctx.Done():
			close(work)
			wg.Wait()
			return ctx.Err()
		case work <- req:
		}
	}

	close(work)
	wg.Wait()
	return nil
}

// executeRequest performs a single HTTP request and returns the result.
func (e *Engine) executeRequest(ctx context.Context, attackReq AttackRequest) ScanResult {
	result := ScanResult{
		Request: attackReq,
		Headers: make(map[string]string),
	}

	// Build the full URL.
	targetURL := attackReq.Path
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = strings.TrimRight(e.config.Target, "/") + "/" + strings.TrimLeft(attackReq.Path, "/")
	}

	method := attackReq.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if attackReq.Body != "" {
		bodyReader = strings.NewReader(attackReq.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Set default headers.
	if e.config.UserAgent != "" {
		req.Header.Set("User-Agent", e.config.UserAgent)
	}
	for k, v := range e.config.CustomHeaders {
		req.Header.Set(k, v)
	}

	// Set request-specific headers (override defaults).
	for k, v := range attackReq.Headers {
		req.Header.Set(k, v)
	}

	// Set content type for bodies.
	if attackReq.Body != "" && attackReq.BodyType != "" {
		req.Header.Set("Content-Type", attackReq.BodyType)
	}

	// Apply evasion techniques.
	e.applyEvasion(req)

	start := time.Now()
	resp, err := e.client.Do(req)
	result.LatencyMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Read response headers.
	for k := range resp.Header {
		result.Headers[k] = resp.Header.Get(k)
	}

	// Read body (up to MaxBodyRead).
	maxRead := e.config.MaxBodyRead
	if maxRead <= 0 {
		maxRead = 1 << 20
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		result.Error = "body read: " + err.Error()
		return result
	}
	result.BodySize = int64(len(bodyBytes))

	// Store first 512 bytes as snippet for analysis.
	snippetLen := 512
	if len(bodyBytes) < snippetLen {
		snippetLen = len(bodyBytes)
	}
	result.BodySnippet = string(bodyBytes[:snippetLen])

	return result
}

// ---------------------------------------------------------------------------
// Evasion
// ---------------------------------------------------------------------------

// applyEvasion modifies the request based on the configured evasion mode.
func (e *Engine) applyEvasion(req *http.Request) {
	switch e.config.EvasionMode {
	case "basic":
		e.applyBasicEvasion(req)
	case "advanced":
		e.applyBasicEvasion(req)
		e.applyAdvancedEvasion(req)
	case "nightmare":
		e.applyBasicEvasion(req)
		e.applyAdvancedEvasion(req)
		e.applyNightmareEvasion(req)
	}
}

// applyBasicEvasion adds common browser-like headers.
func (e *Engine) applyBasicEvasion(req *http.Request) {
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}
}

// applyAdvancedEvasion adds referer, cache, and connection headers to
// look more like real browser traffic.
func (e *Engine) applyAdvancedEvasion(req *http.Request) {
	if req.Header.Get("Referer") == "" {
		req.Header.Set("Referer", e.config.Target+"/")
	}
	if req.Header.Get("Cache-Control") == "" {
		req.Header.Set("Cache-Control", "max-age=0")
	}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
}

// applyNightmareEvasion adds extra browser-fingerprint-like headers
// and varies the DNT header to create more realistic traffic.
func (e *Engine) applyNightmareEvasion(req *http.Request) {
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
}
