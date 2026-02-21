package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagTarget      = flag.String("target", "http://localhost:8765", "server URL")
	flagConcurrency = flag.Int("concurrency", 5, "number of concurrent workers")
	flagDepth       = flag.Int("depth", 3, "max labyrinth crawl depth")
	flagTimeout     = flag.Int("timeout", 10, "per-request timeout in seconds")
	flagRate        = flag.Int("rate", 50, "max requests/second")
	flagOutput      = flag.String("output", "", "output file for JSON report (default: stdout)")
	flagVerbose     = flag.Bool("verbose", false, "verbose logging")
	flagUA          = flag.String("ua", "GlitchCrawler/1.0", "user agent string")
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// TestCase describes a single request to execute.
type TestCase struct {
	Category string
	Method   string
	Path     string
	Headers  map[string]string
	Body     string // raw body content
	BodyType string // Content-Type for body
}

// Result holds the outcome of a single test case execution.
type Result struct {
	Category  string `json:"category"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	Size      int64  `json:"size"`
	Error     string `json:"error"`
}

// CategorySummary aggregates stats for a category.
type CategorySummary struct {
	Total       int     `json:"total"`
	Success     int     `json:"success"`
	Failed      int     `json:"failed"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// Report is the final JSON output.
type Report struct {
	Target             string                     `json:"target"`
	StartedAt          string                     `json:"started_at"`
	CompletedAt        string                     `json:"completed_at"`
	DurationMs         int64                      `json:"duration_ms"`
	TotalRequests      int                        `json:"total_requests"`
	Categories         map[string]*CategorySummary `json:"categories"`
	StatusDistribution map[string]int             `json:"status_distribution"`
	CoveragePct        float64                    `json:"coverage_pct"`
	Results            []Result                   `json:"results"`
	Errors             []string                   `json:"errors"`
}

// ---------------------------------------------------------------------------
// Test case definitions
// ---------------------------------------------------------------------------

func buildTestCases() []TestCase {
	var cases []TestCase

	// (a) Content pages
	contentPaths := []string{
		"/", "/blog/test-post", "/news/latest", "/products/item-1", "/shop/category",
		"/about", "/team", "/careers", "/services/consulting", "/help/faq",
		"/dashboard/overview", "/account/settings",
	}
	for _, p := range contentPaths {
		cases = append(cases, TestCase{Category: "content", Method: "GET", Path: p})
	}

	// (b) API endpoints
	apiGets := []string{
		"/api/v1/users", "/api/v1/users/1",
		"/api/v1/products", "/api/v1/products/1",
		"/api/v1/orders",
		"/swagger/", "/openapi.json",
		"/graphql?query={__schema{types{name}}}",
	}
	for _, p := range apiGets {
		cases = append(cases, TestCase{Category: "api", Method: "GET", Path: p})
	}
	cases = append(cases, TestCase{
		Category: "api", Method: "POST", Path: "/api/v1/users",
		Body:     `{"name":"test","email":"test@example.com"}`,
		BodyType: "application/json",
	})
	cases = append(cases, TestCase{
		Category: "api", Method: "POST", Path: "/api/v1/orders",
		Body:     `{"product_id":1,"quantity":2}`,
		BodyType: "application/json",
	})

	// (c) Auth/OAuth flows
	cases = append(cases,
		TestCase{Category: "auth", Method: "GET", Path: "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost/callback"},
		TestCase{Category: "auth", Method: "POST", Path: "/oauth/token",
			Body:     "grant_type=authorization_code&code=testcode&redirect_uri=http://localhost/callback&client_id=test",
			BodyType: "application/x-www-form-urlencoded",
		},
		TestCase{Category: "auth", Method: "GET", Path: "/.well-known/openid-configuration"},
		TestCase{Category: "auth", Method: "GET", Path: "/oauth/userinfo"},
		TestCase{Category: "auth", Method: "GET", Path: "/saml/metadata"},
	)

	// (d) Search engine
	cases = append(cases,
		TestCase{Category: "search", Method: "GET", Path: "/search?q=test"},
		TestCase{Category: "search", Method: "GET", Path: "/search/advanced"},
		TestCase{Category: "search", Method: "GET", Path: "/search/images?q=test"},
		TestCase{Category: "search", Method: "GET", Path: "/api/search/suggest?q=test"},
	)

	// (e) Email/webmail
	cases = append(cases,
		TestCase{Category: "email", Method: "GET", Path: "/webmail"},
		TestCase{Category: "email", Method: "POST", Path: "/webmail/login",
			Body:     "username=test&password=test",
			BodyType: "application/x-www-form-urlencoded",
		},
		TestCase{Category: "email", Method: "GET", Path: "/webmail/inbox"},
		TestCase{Category: "email", Method: "GET", Path: "/webmail/message/1"},
		TestCase{Category: "email", Method: "POST", Path: "/api/email/send",
			Body:     `{"to":"user@example.com","subject":"Test","body":"Hello"}`,
			BodyType: "application/json",
		},
		TestCase{Category: "email", Method: "GET", Path: "/verify?token=abc123def"},
		TestCase{Category: "email", Method: "GET", Path: "/forgot-password"},
		TestCase{Category: "email", Method: "GET", Path: "/unsubscribe?email=test@example.com&list=news"},
		TestCase{Category: "email", Method: "GET", Path: "/archive/2024/01/"},
	)

	// (f) Health/status
	healthPaths := []string{
		"/health", "/health/live", "/health/ready", "/health/startup",
		"/status", "/status.json",
		"/ping", "/version",
		"/debug/vars", "/debug/pprof/",
		"/metrics",
		"/.well-known/health",
	}
	for _, p := range healthPaths {
		cases = append(cases, TestCase{Category: "health", Method: "GET", Path: p})
	}

	// (g) Honeypot paths
	honeypotPaths := []string{
		"/wp-admin/", "/wp-login.php", "/.env", "/phpinfo.php",
		"/admin/", "/administrator/", "/backup.sql",
		"/.git/config", "/server-status",
	}
	for _, p := range honeypotPaths {
		cases = append(cases, TestCase{Category: "honeypot", Method: "GET", Path: p})
	}

	// (h) Vulnerability endpoints
	vulnPaths := []string{
		"/vuln/a01/admin", "/vuln/a02/leak", "/vuln/a03/search?q=test",
		"/vuln/a04/reset?email=test@test.com", "/vuln/a05/config",
		"/vuln/a06/version", "/vuln/a07/session",
		"/vuln/a08/jwt", "/vuln/a09/logs", "/vuln/a10/proxy?url=http://example.com",
	}
	for _, p := range vulnPaths {
		cases = append(cases, TestCase{Category: "vulnerability", Method: "GET", Path: p})
	}

	// (i) Privacy/consent
	cases = append(cases,
		TestCase{Category: "privacy", Method: "GET", Path: "/privacy-policy"},
		TestCase{Category: "privacy", Method: "GET", Path: "/terms-of-service"},
		TestCase{Category: "privacy", Method: "GET", Path: "/consent/preferences"},
		TestCase{Category: "privacy", Method: "GET", Path: "/.well-known/gpc"},
	)

	// (j) CDN/static assets
	cases = append(cases,
		TestCase{Category: "cdn", Method: "GET", Path: "/static/js/app.js"},
		TestCase{Category: "cdn", Method: "GET", Path: "/static/css/style.css"},
		TestCase{Category: "cdn", Method: "GET", Path: "/assets/images/logo.png"},
		TestCase{Category: "cdn", Method: "GET", Path: "/_next/static/chunks/main.js"},
	)

	// (k) Analytics
	cases = append(cases,
		TestCase{Category: "analytics", Method: "GET", Path: "/collect?v=1&t=pageview"},
		TestCase{Category: "analytics", Method: "GET", Path: "/tr"},
		TestCase{Category: "analytics", Method: "POST", Path: "/events",
			Body:     `{"event":"page_view","page":"/","timestamp":1700000000}`,
			BodyType: "application/json",
		},
	)

	// (l) CAPTCHA
	cases = append(cases,
		TestCase{Category: "captcha", Method: "POST", Path: "/captcha/verify",
			Body:     `{"token":"test-captcha-token","response":"test"}`,
			BodyType: "application/json",
		},
	)

	// (m) i18n
	cases = append(cases,
		TestCase{Category: "i18n", Method: "GET", Path: "/es/"},
		TestCase{Category: "i18n", Method: "GET", Path: "/fr/about"},
		TestCase{Category: "i18n", Method: "GET", Path: "/ja/blog/test"},
		TestCase{Category: "i18n", Method: "GET", Path: "/api/i18n/languages"},
		TestCase{Category: "i18n", Method: "GET", Path: "/api/i18n/translate?key=home&lang=es"},
	)

	// (o) WebSocket (handled specially but listed as test cases)
	wsPaths := []string{"/ws/feed", "/ws/chat", "/ws/ticker"}
	for _, p := range wsPaths {
		cases = append(cases, TestCase{Category: "websocket", Method: "GET", Path: p,
			Headers: map[string]string{
				"Connection":            "Upgrade",
				"Upgrade":               "websocket",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
			},
		})
	}

	// (p) Recorder
	cases = append(cases,
		TestCase{Category: "recorder", Method: "GET", Path: "/recorder/status"},
	)

	return cases
}

// ---------------------------------------------------------------------------
// Worker pool and execution
// ---------------------------------------------------------------------------

// executeRequest runs a single test case and returns the result.
func executeRequest(ctx context.Context, client *http.Client, target string, tc TestCase) Result {
	result := Result{
		Category: tc.Category,
		Method:   tc.Method,
		Path:     tc.Path,
	}

	fullURL := target + tc.Path

	var bodyReader io.Reader
	if tc.Body != "" {
		bodyReader = bytes.NewBufferString(tc.Body)
	}

	req, err := http.NewRequestWithContext(ctx, tc.Method, fullURL, bodyReader)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	req.Header.Set("User-Agent", *flagUA)

	if tc.BodyType != "" {
		req.Header.Set("Content-Type", tc.BodyType)
	}

	for k, v := range tc.Headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	result.LatencyMs = elapsed.Milliseconds()

	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap at 1 MB
	if err != nil {
		result.Error = fmt.Sprintf("body read failed: %v", err)
		result.Status = resp.StatusCode
		return result
	}

	result.Status = resp.StatusCode
	result.Size = int64(len(body))

	return result
}

// ---------------------------------------------------------------------------
// Labyrinth crawler
// ---------------------------------------------------------------------------

// hrefRegex matches href attributes in HTML.
var hrefRegex = regexp.MustCompile(`href=["']([^"']+)["']`)

// crawlLabyrinth performs a breadth-first crawl of the labyrinth starting from
// the seed path. It follows links found in HTML responses up to maxDepth levels
// and returns results for every page visited.
func crawlLabyrinth(ctx context.Context, client *http.Client, target string, seedPath string, maxDepth int) []Result {
	type queueItem struct {
		path  string
		depth int
	}

	visited := make(map[string]bool)
	var results []Result
	queue := []queueItem{{path: seedPath, depth: 0}}
	visited[seedPath] = true

	for len(queue) > 0 {
		// Check context cancellation.
		select {
		case <-ctx.Done():
			return results
		default:
		}

		item := queue[0]
		queue = queue[1:]

		tc := TestCase{
			Category: "labyrinth",
			Method:   "GET",
			Path:     item.path,
		}

		result := executeRequest(ctx, client, target, tc)
		results = append(results, result)

		if *flagVerbose {
			log.Printf("[labyrinth] depth=%d path=%s status=%d latency=%dms",
				item.depth, item.path, result.Status, result.LatencyMs)
		}

		// Only follow links if we haven't reached max depth and there was no error.
		if item.depth >= maxDepth || result.Error != "" {
			continue
		}

		// Fetch the body again to extract links (we already read it in executeRequest,
		// so we make a lightweight second request). To avoid this, we could refactor
		// executeRequest to return the body, but for simplicity we just re-fetch.
		bodyBytes, err := fetchBody(ctx, client, target+item.path)
		if err != nil {
			continue
		}

		// Extract links from the HTML body.
		matches := hrefRegex.FindAllSubmatch(bodyBytes, -1)
		for _, m := range matches {
			link := string(m[1])
			parsed, err := url.Parse(link)
			if err != nil {
				continue
			}

			// Only follow relative links or links to the same host.
			if parsed.Host != "" {
				targetURL, _ := url.Parse(target)
				if parsed.Host != targetURL.Host {
					continue
				}
			}

			linkPath := parsed.Path
			if linkPath == "" {
				continue
			}

			// Only follow links that look like labyrinth paths.
			if !strings.HasPrefix(linkPath, "/articles/") &&
				!strings.HasPrefix(linkPath, "/blog/") &&
				!strings.HasPrefix(linkPath, "/wiki/") &&
				!strings.HasPrefix(linkPath, "/docs/") &&
				!strings.HasPrefix(linkPath, "/category/") &&
				!strings.HasPrefix(linkPath, "/topic/") {
				continue
			}

			if !visited[linkPath] {
				visited[linkPath] = true
				queue = append(queue, queueItem{path: linkPath, depth: item.depth + 1})
			}
		}
	}

	return results
}

// fetchBody makes a GET request and returns the response body bytes.
func fetchBody(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", *flagUA)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

func buildReport(target string, startedAt time.Time, completedAt time.Time, results []Result) Report {
	report := Report{
		Target:             target,
		StartedAt:          startedAt.UTC().Format(time.RFC3339),
		CompletedAt:        completedAt.UTC().Format(time.RFC3339),
		DurationMs:         completedAt.Sub(startedAt).Milliseconds(),
		TotalRequests:      len(results),
		Categories:         make(map[string]*CategorySummary),
		StatusDistribution: make(map[string]int),
		Results:            results,
		Errors:             []string{},
	}

	// Aggregate by category and status.
	catLatencies := make(map[string][]int64)

	for _, r := range results {
		// Status distribution.
		statusKey := fmt.Sprintf("%d", r.Status)
		if r.Status == 0 {
			statusKey = "error"
		}
		report.StatusDistribution[statusKey]++

		// Category summary.
		if _, ok := report.Categories[r.Category]; !ok {
			report.Categories[r.Category] = &CategorySummary{}
		}
		cat := report.Categories[r.Category]
		cat.Total++
		if r.Error == "" && r.Status > 0 {
			cat.Success++
		} else {
			cat.Failed++
			if r.Error != "" {
				report.Errors = append(report.Errors, fmt.Sprintf("[%s] %s %s: %s", r.Category, r.Method, r.Path, r.Error))
			}
		}

		catLatencies[r.Category] = append(catLatencies[r.Category], r.LatencyMs)
	}

	// Compute average latencies.
	for cat, lats := range catLatencies {
		if len(lats) == 0 {
			continue
		}
		var sum int64
		for _, l := range lats {
			sum += l
		}
		report.Categories[cat].AvgLatencyMs = float64(sum) / float64(len(lats))
	}

	// Coverage: percentage of test cases that got any HTTP response (non-error).
	successCount := 0
	for _, r := range results {
		if r.Error == "" && r.Status > 0 {
			successCount++
		}
	}
	if len(results) > 0 {
		report.CoveragePct = float64(successCount) / float64(len(results)) * 100.0
	}

	return report
}

// ---------------------------------------------------------------------------
// Human-readable summary
// ---------------------------------------------------------------------------

func printSummary(report Report) {
	totalSuccess := 0
	totalFailed := 0
	for _, cat := range report.Categories {
		totalSuccess += cat.Success
		totalFailed += cat.Failed
	}

	fmt.Fprintf(os.Stderr, "\n=== Glitch Server Coverage Report ===\n")
	fmt.Fprintf(os.Stderr, "Target:    %s\n", report.Target)
	fmt.Fprintf(os.Stderr, "Duration:  %.1fs\n", float64(report.DurationMs)/1000.0)
	fmt.Fprintf(os.Stderr, "Requests:  %d total (%d success, %d failed)\n",
		report.TotalRequests, totalSuccess, totalFailed)
	fmt.Fprintf(os.Stderr, "Coverage:  %.1f%%\n", report.CoveragePct)

	// Category breakdown, sorted by name.
	fmt.Fprintf(os.Stderr, "\nCategory Breakdown:\n")
	catNames := make([]string, 0, len(report.Categories))
	for name := range report.Categories {
		catNames = append(catNames, name)
	}
	sort.Strings(catNames)

	for _, name := range catNames {
		cat := report.Categories[name]
		pct := 0.0
		if cat.Total > 0 {
			pct = float64(cat.Success) / float64(cat.Total) * 100.0
		}
		fmt.Fprintf(os.Stderr, "  %-16s %d/%d (%.0f%%)  avg %.0fms\n",
			name+":", cat.Success, cat.Total, pct, cat.AvgLatencyMs)
	}

	// Status distribution grouped by class.
	fmt.Fprintf(os.Stderr, "\nStatus Distribution:\n")
	class2xx, class3xx, class4xx, class5xx, classErr := 0, 0, 0, 0, 0
	for status, count := range report.StatusDistribution {
		if status == "error" {
			classErr += count
			continue
		}
		switch {
		case strings.HasPrefix(status, "2"):
			class2xx += count
		case strings.HasPrefix(status, "3"):
			class3xx += count
		case strings.HasPrefix(status, "4"):
			class4xx += count
		case strings.HasPrefix(status, "5"):
			class5xx += count
		default:
			classErr += count
		}
	}
	fmt.Fprintf(os.Stderr, "  2xx: %d  3xx: %d  4xx: %d  5xx: %d", class2xx, class3xx, class4xx, class5xx)
	if classErr > 0 {
		fmt.Fprintf(os.Stderr, "  errors: %d", classErr)
	}
	fmt.Fprintf(os.Stderr, "\n\n")
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	// Normalize target URL (strip trailing slash).
	target := strings.TrimRight(*flagTarget, "/")

	// Set up logging.
	if !*flagVerbose {
		log.SetOutput(io.Discard)
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Context with cancellation on SIGINT/SIGTERM.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nInterrupted, shutting down gracefully...\n")
		cancel()
	}()

	// HTTP client with timeout and no automatic redirects (to capture redirect status codes).
	client := &http.Client{
		Timeout: time.Duration(*flagTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build the static test cases.
	testCases := buildTestCases()

	fmt.Fprintf(os.Stderr, "Glitch Crawler starting: target=%s concurrency=%d rate=%d/s\n",
		target, *flagConcurrency, *flagRate)
	fmt.Fprintf(os.Stderr, "Static test cases: %d\n", len(testCases))

	startedAt := time.Now()

	// -----------------------------------------------------------------------
	// Execute static test cases via worker pool with rate limiting.
	// -----------------------------------------------------------------------

	type indexedResult struct {
		index  int
		result Result
	}

	taskCh := make(chan int, len(testCases))
	resultCh := make(chan indexedResult, len(testCases))

	// Rate limiter: emit a tick every 1/rate seconds.
	tickInterval := time.Second / time.Duration(*flagRate)
	rateLimiter := time.NewTicker(tickInterval)
	defer rateLimiter.Stop()

	// Atomic counter for verbose progress.
	var completed int64

	// Start workers.
	var wg sync.WaitGroup
	for i := 0; i < *flagConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range taskCh {
				// Check context.
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Wait for rate limiter tick.
				select {
				case <-ctx.Done():
					return
				case <-rateLimiter.C:
				}

				tc := testCases[idx]
				r := executeRequest(ctx, client, target, tc)
				resultCh <- indexedResult{index: idx, result: r}

				n := atomic.AddInt64(&completed, 1)
				if *flagVerbose {
					log.Printf("[%d/%d] %s %s -> %d (%dms)",
						n, len(testCases), tc.Method, tc.Path, r.Status, r.LatencyMs)
				}
			}
		}()
	}

	// Feed tasks.
	go func() {
		for i := range testCases {
			select {
			case <-ctx.Done():
				break
			case taskCh <- i:
			}
		}
		close(taskCh)
	}()

	// Wait for workers to finish, then close results channel.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results in order.
	staticResults := make([]Result, len(testCases))
	for ir := range resultCh {
		staticResults[ir.index] = ir.result
	}

	// -----------------------------------------------------------------------
	// Labyrinth crawl (sequential BFS, still respects context cancellation).
	// -----------------------------------------------------------------------

	fmt.Fprintf(os.Stderr, "Starting labyrinth crawl (depth=%d)...\n", *flagDepth)
	labyrinthResults := crawlLabyrinth(ctx, client, target, "/articles/deep/path/explore", *flagDepth)
	fmt.Fprintf(os.Stderr, "Labyrinth crawl: %d pages visited\n", len(labyrinthResults))

	// -----------------------------------------------------------------------
	// Combine all results and build report.
	// -----------------------------------------------------------------------

	allResults := append(staticResults, labyrinthResults...)
	completedAt := time.Now()

	report := buildReport(target, startedAt, completedAt, allResults)

	// Print human-readable summary to stderr.
	printSummary(report)

	// Write JSON report to output.
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to marshal report: %v\n", err)
		os.Exit(1)
	}

	if *flagOutput != "" {
		err = os.WriteFile(*flagOutput, reportJSON, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to write output file %s: %v\n", *flagOutput, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *flagOutput)
	} else {
		fmt.Println(string(reportJSON))
	}
}
