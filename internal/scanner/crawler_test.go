package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestCrawler_Crawl
// ---------------------------------------------------------------------------

func TestCrawler_Crawl(t *testing.T) {
	// Build a small site with linked pages.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/page1">Page 1</a>
			<a href="/page2">Page 2</a>
		</body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Page 1</h1><a href="/page3">Page 3</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Page 2</h1></body></html>`)
	})
	mux.HandleFunc("/page3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Page 3</h1></body></html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nAllow: /\n")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.CrawlDepth = 3
	cfg.UserAgent = "TestCrawler/1.0"

	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	results, err := crawler.Crawl(context.Background(), ts.URL+"/")
	if err != nil {
		t.Fatalf("Crawl returned error: %v", err)
	}

	if len(results) < 3 {
		t.Errorf("expected at least 3 crawled pages, got %d", len(results))
	}

	// Verify all expected URLs were visited.
	urls := make(map[string]bool)
	for _, r := range results {
		urls[r.URL] = true
	}

	for _, expected := range []string{
		ts.URL + "/",
		ts.URL + "/page1",
		ts.URL + "/page2",
	} {
		if !urls[expected] {
			t.Errorf("expected URL %s to be crawled", expected)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_LinkExtraction
// ---------------------------------------------------------------------------

func TestCrawler_LinkExtraction(t *testing.T) {
	cfg := DefaultConfig()
	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	body := `<html>
		<head><link rel="prefetch" href="/prefetched.js"></head>
		<body>
			<a href="/page-a">Link A</a>
			<a href="/page-b">Link B</a>
			<img src="/image.png">
			<a href="https://external.com/out">External</a>
			<a href="javascript:void(0)">JS Link</a>
			<a href="mailto:test@example.com">Email</a>
			<a href="#section">Anchor</a>
			<a href="/page-a">Duplicate</a>
		</body>
	</html>`

	links := crawler.extractLinks(body)

	// Check that valid links are present.
	linkSet := make(map[string]bool)
	for _, l := range links {
		linkSet[l] = true
	}

	expected := []string{"/page-a", "/page-b", "/image.png", "https://external.com/out", "/prefetched.js"}
	for _, e := range expected {
		if !linkSet[e] {
			t.Errorf("expected link %q in extracted links", e)
		}
	}

	// Verify no duplicates.
	seen := make(map[string]int)
	for _, l := range links {
		seen[l]++
	}
	for link, count := range seen {
		if count > 1 {
			t.Errorf("link %q appears %d times (should be deduplicated)", link, count)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_LoopDetection
// ---------------------------------------------------------------------------

func TestCrawler_LoopDetection(t *testing.T) {
	// Pages that link to each other in a cycle: / -> /a -> /b -> /
	hitCount := make(map[string]int)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		hitCount["/"]++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/a">A</a></body></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		hitCount["/a"]++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/b">B</a></body></html>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		hitCount["/b"]++
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/">Back to root</a></body></html>`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.CrawlDepth = 10 // High depth to exercise loop detection.

	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	results, err := crawler.Crawl(context.Background(), ts.URL+"/")
	if err != nil {
		t.Fatalf("Crawl returned error: %v", err)
	}

	// Each page should only be visited once despite the cycle.
	for path, count := range hitCount {
		if count > 1 {
			t.Errorf("path %s was visited %d times (expected exactly 1)", path, count)
		}
	}

	if len(results) != 3 {
		t.Errorf("expected 3 crawled pages, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_DepthLimit
// ---------------------------------------------------------------------------

func TestCrawler_DepthLimit(t *testing.T) {
	// Build a linear chain: / -> /d1 -> /d2 -> /d3 -> /d4
	mux := http.NewServeMux()
	for depth := 0; depth <= 4; depth++ {
		d := depth
		path := "/"
		if d > 0 {
			path = fmt.Sprintf("/d%d", d)
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			next := fmt.Sprintf("/d%d", d+1)
			fmt.Fprintf(w, `<html><body>Depth %d <a href="%s">Next</a></body></html>`, d, next)
		})
	}
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.CrawlDepth = 2 // Should visit /, /d1, /d2 but not /d3 or /d4.

	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	results, err := crawler.Crawl(context.Background(), ts.URL+"/")
	if err != nil {
		t.Fatalf("Crawl returned error: %v", err)
	}

	urls := make(map[string]bool)
	for _, r := range results {
		urls[r.URL] = true
	}

	// Depth 0: /, Depth 1: /d1, Depth 2: /d2
	for _, expected := range []string{ts.URL + "/", ts.URL + "/d1", ts.URL + "/d2"} {
		if !urls[expected] {
			t.Errorf("expected %s to be crawled at depth <= 2", expected)
		}
	}

	// /d3 should NOT be crawled (discovered at depth 2, would be visited at depth 3).
	if urls[ts.URL+"/d3"] {
		t.Error("/d3 should not be crawled with depth limit 2")
	}
	if urls[ts.URL+"/d4"] {
		t.Error("/d4 should not be crawled with depth limit 2")
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_APIDiscovery
// ---------------------------------------------------------------------------

func TestCrawler_APIDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		// Embed JS with fetch() calls.
		fmt.Fprint(w, `<html>
		<body>
			<script>
				fetch('/api/users')
				fetch("/api/products")
				fetch('/api/settings')
			</script>
		</body>
		</html>`)
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"users": []}`)
	})
	mux.HandleFunc("/api/products", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"products": []}`)
	})
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"settings": {}}`)
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.CrawlDepth = 2

	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	results, err := crawler.Crawl(context.Background(), ts.URL+"/")
	if err != nil {
		t.Fatalf("Crawl returned error: %v", err)
	}

	// Check that API endpoints were discovered from the root page.
	rootResult := findCrawlResult(results, ts.URL+"/")
	if rootResult == nil {
		t.Fatal("root page not found in crawl results")
	}

	if len(rootResult.APIEndpoints) < 3 {
		t.Errorf("expected at least 3 API endpoints from root page, got %d: %v",
			len(rootResult.APIEndpoints), rootResult.APIEndpoints)
	}

	// Verify the API endpoints were also crawled.
	urls := make(map[string]bool)
	for _, r := range results {
		urls[r.URL] = true
	}

	for _, api := range []string{"/api/users", "/api/products", "/api/settings"} {
		found := false
		for u := range urls {
			if strings.HasSuffix(u, api) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected API endpoint %s to be crawled", api)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_FormExtraction
// ---------------------------------------------------------------------------

func TestCrawler_FormExtraction(t *testing.T) {
	cfg := DefaultConfig()
	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	body := `<html><body>
		<form action="/login" method="POST">
			<input name="username" type="text">
			<input name="password" type="password">
			<select name="role"><option>admin</option></select>
			<textarea name="notes"></textarea>
			<button type="submit">Login</button>
		</form>
		<form action="/search" method="GET">
			<input name="q" type="text">
		</form>
	</body></html>`

	forms := crawler.extractForms(body)

	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}

	// First form: login
	login := forms[0]
	if login.Action != "/login" {
		t.Errorf("expected action /login, got %s", login.Action)
	}
	if login.Method != "POST" {
		t.Errorf("expected method POST, got %s", login.Method)
	}
	if len(login.Fields) != 4 {
		t.Errorf("expected 4 fields (username, password, role, notes), got %d: %v", len(login.Fields), login.Fields)
	}

	// Second form: search
	search := forms[1]
	if search.Action != "/search" {
		t.Errorf("expected action /search, got %s", search.Action)
	}
	if search.Method != "GET" {
		t.Errorf("expected method GET, got %s", search.Method)
	}
	if len(search.Fields) != 1 {
		t.Errorf("expected 1 field (q), got %d: %v", len(search.Fields), search.Fields)
	}
}

// ---------------------------------------------------------------------------
// TestCrawler_CancelContext
// ---------------------------------------------------------------------------

func TestCrawler_CancelContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/next">Next</a></body></html>`)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.CrawlDepth = 100

	client := &http.Client{Timeout: 5 * time.Second}
	crawler := NewCrawler(cfg, client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	results, err := crawler.Crawl(ctx, ts.URL+"/")
	// Context was cancelled, so we may get an error or empty results.
	if err != nil && err != context.Canceled {
		t.Logf("got expected error: %v", err)
	}
	// Results should be empty or very small.
	if len(results) > 1 {
		t.Errorf("expected 0-1 results with cancelled context, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func findCrawlResult(results []CrawlResult, url string) *CrawlResult {
	for i := range results {
		if results[i].URL == url {
			return &results[i]
		}
	}
	return nil
}
