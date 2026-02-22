package botdetect

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper to build requests with custom headers
// ---------------------------------------------------------------------------

func newRequest(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func chromeHeaders() map[string]string {
	return map[string]string{
		"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Encoding":    "gzip, deflate, br",
		"Accept-Language":    "en-US,en;q=0.9",
		"Sec-Fetch-Site":     "none",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-Dest":     "document",
		"Sec-Ch-Ua":          `"Chromium";v="131", "Google Chrome";v="131", "Not-A.Brand";v="99"`,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"Windows"`,
	}
}

// ---------------------------------------------------------------------------
// 1. Known bot UA detection
// ---------------------------------------------------------------------------

func TestKnownBotUA(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	botUAs := []string{
		"GPTBot/1.0",
		"Mozilla/5.0 (compatible; ClaudeBot/1.0)",
		"Scrapy/2.11",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"curl/8.4.0",
		"wget/1.21",
		"Firecrawl/1.0",
		"CCBot/2.0",
		"Perplexitybot/1.0",
	}

	for _, ua := range botUAs {
		t.Run(ua, func(t *testing.T) {
			r := newRequest("GET", "/", map[string]string{"User-Agent": ua})
			profile := d.GetProfile("test-bot-" + ua)
			result := d.Score(r, "test-bot-"+ua, profile)

			found := false
			for _, sig := range result.Signals {
				if sig.Name == "known_bot_ua" || sig.Name == "empty_user_agent" {
					found = true
					break
				}
			}
			if !found {
				// Could also be caught by crawler product detection
				for _, sig := range result.Signals {
					if sig.Score >= 80 {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("Expected bot UA detection for %q, got signals: %+v", ua, result.Signals)
			}
		})
	}
}

func TestEmptyUA(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{})
	r.Header.Del("User-Agent")
	result := d.Score(r, "empty-ua-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "empty_user_agent" {
			found = true
			if sig.Score != 30 {
				t.Errorf("Expected empty UA score 30, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected empty_user_agent signal")
	}
}

func TestLegitBrowserUA(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	profile := d.GetProfile("legit-browser")
	result := d.Score(r, "legit-browser", profile)

	for _, sig := range result.Signals {
		if sig.Name == "known_bot_ua" {
			t.Errorf("Legitimate Chrome UA should not trigger known_bot_ua signal")
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Missing Sec-Fetch header detection
// ---------------------------------------------------------------------------

func TestMissingSecFetchHeaders(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Chrome 131 UA without Sec-Fetch headers
	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	})
	result := d.Score(r, "missing-sec-fetch", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "missing_sec_fetch" {
			found = true
			if sig.Score != 30 {
				t.Errorf("Expected missing_sec_fetch score 30, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected missing_sec_fetch signal for Chrome 131 without Sec-Fetch headers")
	}
}

func TestSecFetchNotExpectedForOldChrome(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Chrome 70 UA (before Sec-Fetch was introduced)
	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
	})
	result := d.Score(r, "old-chrome", nil)

	for _, sig := range result.Signals {
		if sig.Name == "missing_sec_fetch" {
			t.Error("Should not flag missing Sec-Fetch for Chrome 70")
		}
	}
}

func TestSecFetchPresentNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, "good-chrome", nil)

	for _, sig := range result.Signals {
		if sig.Name == "missing_sec_fetch" {
			t.Error("Should not flag missing Sec-Fetch when headers are present")
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Client hints validation
// ---------------------------------------------------------------------------

func TestMissingClientHints(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Chrome 131 without sec-ch-ua
	r := newRequest("GET", "/", map[string]string{
		"User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	})
	result := d.Score(r, "no-hints", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "missing_client_hints" {
			found = true
			if sig.Score != 25 {
				t.Errorf("Expected missing_client_hints score 25, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected missing_client_hints signal for Chrome 131 without sec-ch-ua")
	}
}

func TestClientHintsPresentNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, "with-hints", nil)

	for _, sig := range result.Signals {
		if sig.Name == "missing_client_hints" {
			t.Error("Should not flag missing client hints when sec-ch-ua is present")
		}
	}
}

func TestClientHintsNotExpectedForOldChrome(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36",
	})
	result := d.Score(r, "old-chrome-hints", nil)

	for _, sig := range result.Signals {
		if sig.Name == "missing_client_hints" {
			t.Error("Should not flag missing client hints for Chrome 85")
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Scoring calculation
// ---------------------------------------------------------------------------

func TestScoreCappedAt100(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Request that should trigger honeypot (100) plus bot UA (80) = capped to 100
	r := newRequest("GET", "/secret-trap", map[string]string{
		"User-Agent":           "GPTBot/1.0",
		"X-Glitch-Honeypot-Hit": "true",
	})
	result := d.Score(r, "maxscore-client", nil)

	if result.Score > 100 {
		t.Errorf("Score should be capped at 100, got %f", result.Score)
	}
	if result.Score != 100 {
		t.Errorf("Expected score 100, got %f", result.Score)
	}
}

func TestScoreAggregation(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Chrome 131 UA missing both Sec-Fetch and Client Hints = 30 + 25 = 55
	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	})
	result := d.Score(r, "aggregation-test", nil)

	// Should have at least the missing_sec_fetch and missing_client_hints signals
	hasSecFetch := false
	hasHints := false
	for _, sig := range result.Signals {
		if sig.Name == "missing_sec_fetch" {
			hasSecFetch = true
		}
		if sig.Name == "missing_client_hints" {
			hasHints = true
		}
	}

	if !hasSecFetch || !hasHints {
		t.Errorf("Expected both missing_sec_fetch and missing_client_hints, got signals: %+v", result.Signals)
	}

	if result.Score < 55 {
		t.Errorf("Expected score >= 55 (30+25), got %f", result.Score)
	}
}

// ---------------------------------------------------------------------------
// 5. Profile accumulation
// ---------------------------------------------------------------------------

func TestProfileAccumulation(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "profile-test"

	r1 := newRequest("GET", "/page/1", map[string]string{
		"User-Agent": "TestAgent/1.0",
	})
	r2 := newRequest("GET", "/page/2", map[string]string{
		"User-Agent": "TestAgent/1.0",
	})
	r3 := newRequest("GET", "/style.css", map[string]string{
		"User-Agent": "TestAgent/1.0",
		"Accept":     "text/css",
	})

	d.RecordRequest(clientID, r1)
	time.Sleep(10 * time.Millisecond)
	d.RecordRequest(clientID, r2)
	time.Sleep(10 * time.Millisecond)
	d.RecordRequest(clientID, r3)

	profile := d.GetProfile(clientID)
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if profile.RequestCount != 3 {
		t.Errorf("Expected RequestCount=3, got %d", profile.RequestCount)
	}
	if profile.UniquePathCount != 3 {
		t.Errorf("Expected UniquePathCount=3, got %d", profile.UniquePathCount)
	}
	if !profile.AssetLoading {
		t.Error("Expected AssetLoading=true after requesting .css file")
	}
	if len(profile.RequestIntervals) != 2 {
		t.Errorf("Expected 2 RequestIntervals, got %d", len(profile.RequestIntervals))
	}
	if len(profile.UserAgents) != 1 {
		t.Errorf("Expected 1 UserAgent, got %d", len(profile.UserAgents))
	}
}

func TestProfileRecordBeacon(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "beacon-test"
	d.RecordBeacon(clientID, map[string]interface{}{
		"webdriver":     true,
		"pluginCount":   float64(0),
		"webglRenderer": "SwiftShader",
	})

	profile := d.GetProfile(clientID)
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if !profile.ExecutesJS {
		t.Error("Expected ExecutesJS=true after beacon")
	}
	if profile.BeaconData["webdriver"] != true {
		t.Error("Expected webdriver=true in beacon data")
	}
	if profile.BeaconData["pluginCount"] != float64(0) {
		t.Error("Expected pluginCount=0 in beacon data")
	}
}

func TestProfileDuplicatePaths(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "dup-path"
	r := newRequest("GET", "/same-page", map[string]string{
		"User-Agent": "TestAgent/1.0",
	})

	d.RecordRequest(clientID, r)
	d.RecordRequest(clientID, r)
	d.RecordRequest(clientID, r)

	profile := d.GetProfile(clientID)
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if profile.RequestCount != 3 {
		t.Errorf("Expected RequestCount=3, got %d", profile.RequestCount)
	}
	if profile.UniquePathCount != 1 {
		t.Errorf("Expected UniquePathCount=1 for duplicate paths, got %d", profile.UniquePathCount)
	}
}

// ---------------------------------------------------------------------------
// 6. Threshold classifications
// ---------------------------------------------------------------------------

func TestClassificationHuman(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, "human-client", nil)

	if result.Classification != "human" {
		t.Errorf("Expected classification 'human', got %q (score=%f)", result.Classification, result.Score)
	}
	if result.Recommendation != "allow" {
		t.Errorf("Expected recommendation 'allow', got %q", result.Recommendation)
	}
}

func TestClassificationSuspicious(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Chrome 131 UA without Sec-Fetch and Client Hints -> 30 + 25 = 55
	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	})
	result := d.Score(r, "suspicious-client", nil)

	if result.Classification != "suspicious" {
		t.Errorf("Expected classification 'suspicious', got %q (score=%f)", result.Classification, result.Score)
	}
	if result.Recommendation != "challenge" {
		t.Errorf("Expected recommendation 'challenge', got %q", result.Recommendation)
	}
}

func TestClassificationBot(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Known bot UA (80) -> should be "bot"
	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Scrapy/2.11",
	})
	result := d.Score(r, "bot-client", nil)

	if result.Classification != "bot" {
		t.Errorf("Expected classification 'bot', got %q (score=%f)", result.Classification, result.Score)
	}
	if result.Recommendation != "labyrinth" {
		t.Errorf("Expected recommendation 'labyrinth', got %q", result.Recommendation)
	}
}

func TestClassificationCrawlerService(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Honeypot hit (100) -> "crawler_service"
	r := newRequest("GET", "/admin", map[string]string{
		"User-Agent":           "Mozilla/5.0",
		"X-Glitch-Honeypot-Hit": "true",
	})
	result := d.Score(r, "crawler-service-client", nil)

	if result.Classification != "crawler_service" {
		t.Errorf("Expected classification 'crawler_service', got %q (score=%f)", result.Classification, result.Score)
	}
}

// ---------------------------------------------------------------------------
// 7. Crawler product identification
// ---------------------------------------------------------------------------

func TestFirecrawlDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; Firecrawl/1.0)",
	})
	result := d.Score(r, "firecrawl-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_firecrawl" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Firecrawl product detection")
	}
	if result.CrawlerProduct != "Firecrawl" {
		t.Errorf("Expected CrawlerProduct='Firecrawl', got %q", result.CrawlerProduct)
	}
}

func TestBrightDataDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "BrightBot/1.0",
	})
	result := d.Score(r, "brightdata-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_brightdata" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected BrightData product detection")
	}
	if result.CrawlerProduct != "BrightData" {
		t.Errorf("Expected CrawlerProduct='BrightData', got %q", result.CrawlerProduct)
	}
}

func TestCrawl4AIDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.96 Safari/537.36 Crawl4AI",
	})
	result := d.Score(r, "crawl4ai-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_crawl4ai" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Crawl4AI product detection")
	}
}

func TestOxylabsDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// UA says Windows but Sec-CH-UA-Platform says Linux
	r := newRequest("GET", "/", map[string]string{
		"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Sec-Ch-Ua-Platform": `"Linux"`,
		"Sec-Ch-Ua":          `"Chromium";v="131", "Google Chrome";v="131"`,
		"Sec-Fetch-Site":     "none",
		"Sec-Fetch-Mode":     "navigate",
		"Sec-Fetch-Dest":     "document",
	})
	result := d.Score(r, "oxylabs-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_oxylabs" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected Oxylabs product detection via platform mismatch")
	}
}

func TestScrapingBeeDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "scrapingbee-client"
	// Record beacon data with CDP signal
	d.RecordBeacon(clientID, map[string]interface{}{
		"cdp":            true,
		"viewportWidth":  float64(1920),
		"screenWidth":    float64(1080),
		"pluginCount":    float64(0),
	})

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_scrapingbee" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected ScrapingBee product detection via CDP beacon data")
	}
}

func TestGenericHeadlessDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "headless-client"
	d.RecordBeacon(clientID, map[string]interface{}{
		"webdriver":     true,
		"webglRenderer": "Google SwiftShader",
	})

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "crawler_product_genericheadless" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected GenericHeadless product detection via webdriver+SwiftShader")
	}
}

// ---------------------------------------------------------------------------
// 8. Thread safety
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	var wg sync.WaitGroup
	const goroutines = 50
	const iterations = 100

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			clientID := "concurrent-" + string(rune('A'+id%26))
			for j := 0; j < iterations; j++ {
				r := newRequest("GET", "/page/"+string(rune('0'+j%10)), map[string]string{
					"User-Agent": "TestBot/1.0",
				})
				d.RecordRequest(clientID, r)
				d.Score(r, clientID, nil)
				d.GetProfile(clientID)
				if j%10 == 0 {
					d.RecordBeacon(clientID, map[string]interface{}{
						"webdriver": false,
					})
				}
			}
		}(i)
	}

	wg.Wait()
	// If we get here without panic or race, the test passes
}

func TestConcurrentScoring(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	var wg sync.WaitGroup
	const goroutines = 20

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r := newRequest("GET", "/", map[string]string{
				"User-Agent": "GPTBot/1.0",
			})
			result := d.Score(r, "concurrent-score", nil)
			if result.Score < 80 {
				t.Errorf("Expected score >= 80 for GPTBot, got %f", result.Score)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 9. IP detection (datacenter vs residential)
// ---------------------------------------------------------------------------

func TestDatacenterIPDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	datacenterIPs := []struct {
		ip      string
		desc    string
	}{
		{"52.1.2.3", "AWS"},
		{"20.50.100.200", "Azure"},
		{"34.100.50.25", "GCP"},
		{"159.65.100.50", "DigitalOcean"},
		{"136.243.100.50", "Hetzner"},
		{"108.61.50.25", "Vultr"},
	}

	for _, tc := range datacenterIPs {
		t.Run(tc.desc+"_"+tc.ip, func(t *testing.T) {
			r := newRequest("GET", "/", map[string]string{
				"User-Agent": "Mozilla/5.0",
			})
			r.RemoteAddr = net.JoinHostPort(tc.ip, "12345")

			result := d.Score(r, "dc-ip-"+tc.ip, nil)

			found := false
			for _, sig := range result.Signals {
				if sig.Name == "datacenter_ip" {
					found = true
					if sig.Score != 15 {
						t.Errorf("Expected datacenter_ip score 15, got %f", sig.Score)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected datacenter_ip signal for %s IP %s", tc.desc, tc.ip)
			}
		})
	}
}

func TestResidentialIPNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	residentialIPs := []string{
		"73.162.45.10",   // Comcast
		"71.95.200.100",  // Cox
		"98.100.50.25",   // Charter
		"24.150.75.30",   // Rogers
		"192.168.1.100",  // private
		"10.0.0.1",       // private
	}

	for _, ip := range residentialIPs {
		t.Run(ip, func(t *testing.T) {
			r := newRequest("GET", "/", map[string]string{
				"User-Agent": "Mozilla/5.0",
			})
			r.RemoteAddr = net.JoinHostPort(ip, "12345")

			result := d.Score(r, "res-ip-"+ip, nil)

			for _, sig := range result.Signals {
				if sig.Name == "datacenter_ip" {
					t.Errorf("Residential IP %s should not trigger datacenter_ip signal", ip)
				}
			}
		})
	}
}

func TestXForwardedForIPDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent":      "Mozilla/5.0",
		"X-Forwarded-For": "52.1.2.3, 10.0.0.1",
	})
	r.RemoteAddr = "10.0.0.1:12345"

	result := d.Score(r, "xff-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "datacenter_ip" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected datacenter_ip signal from X-Forwarded-For header")
	}
}

// ---------------------------------------------------------------------------
// 10. Version mismatch
// ---------------------------------------------------------------------------

func TestVersionMismatch(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Sec-Ch-Ua":      `"Chromium";v="120", "Google Chrome";v="120"`,
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	})
	result := d.Score(r, "version-mismatch-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "version_mismatch" {
			found = true
			if sig.Score != 30 {
				t.Errorf("Expected version_mismatch score 30, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected version_mismatch signal when Chrome/131 UA but sec-ch-ua reports 120")
	}
}

func TestVersionMatchNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, "version-match-client", nil)

	for _, sig := range result.Signals {
		if sig.Name == "version_mismatch" {
			t.Error("Should not flag version mismatch when versions match")
		}
	}
}

// ---------------------------------------------------------------------------
// 11. Multiple User-Agents
// ---------------------------------------------------------------------------

func TestMultipleUserAgents(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "multi-ua-client"

	r1 := newRequest("GET", "/page/1", map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/131",
	})
	r2 := newRequest("GET", "/page/2", map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/130",
	})
	r3 := newRequest("GET", "/page/3", map[string]string{
		"User-Agent": "Mozilla/5.0 Firefox/120",
	})

	d.RecordRequest(clientID, r1)
	d.RecordRequest(clientID, r2)
	d.RecordRequest(clientID, r3)

	result := d.Score(r3, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "multiple_user_agents" {
			found = true
			if sig.Score != 40 {
				t.Errorf("Expected multiple_user_agents score 40, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected multiple_user_agents signal when 3 different UAs used")
	}
}

// ---------------------------------------------------------------------------
// 12. Timing regularity
// ---------------------------------------------------------------------------

func TestTimingRegularity(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "timing-regular"
	profile := d.GetProfile(clientID)

	// Simulate very regular timing (machine-like)
	profile.mu.Lock()
	profile.RequestCount = 10
	base := 100 * time.Millisecond
	for i := 0; i < 10; i++ {
		// All intervals exactly the same = CV of 0
		profile.RequestIntervals = append(profile.RequestIntervals, base)
	}
	profile.mu.Unlock()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	result := d.Score(r, clientID, profile)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "timing_regularity" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected timing_regularity signal for perfectly regular intervals")
	}
}

func TestTimingIrregularNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "timing-irregular"
	profile := d.GetProfile(clientID)

	// Simulate highly variable timing (human-like)
	profile.mu.Lock()
	profile.RequestCount = 10
	intervals := []time.Duration{
		50 * time.Millisecond,
		200 * time.Millisecond,
		30 * time.Millisecond,
		500 * time.Millisecond,
		150 * time.Millisecond,
		1000 * time.Millisecond,
		75 * time.Millisecond,
		300 * time.Millisecond,
		2000 * time.Millisecond,
		100 * time.Millisecond,
	}
	profile.RequestIntervals = intervals
	profile.mu.Unlock()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	result := d.Score(r, clientID, profile)

	for _, sig := range result.Signals {
		if sig.Name == "timing_regularity" {
			t.Error("Should not flag timing regularity for highly variable intervals")
		}
	}
}

// ---------------------------------------------------------------------------
// 13. Honeypot interaction
// ---------------------------------------------------------------------------

func TestHoneypotInteraction(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	r := newRequest("GET", "/.env", map[string]string{
		"User-Agent":           "Mozilla/5.0",
		"X-Glitch-Honeypot-Hit": "true",
	})
	result := d.Score(r, "honeypot-client", nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "honeypot_interaction" {
			found = true
			if sig.Score != 100 {
				t.Errorf("Expected honeypot_interaction score 100, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected honeypot_interaction signal")
	}

	if result.Score < 90 {
		t.Errorf("Expected score >= 90 for honeypot hit, got %f", result.Score)
	}
}

// ---------------------------------------------------------------------------
// 14. Cookie non-compliance
// ---------------------------------------------------------------------------

func TestCookieNoncompliance(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "no-cookies"
	profile := d.GetProfile(clientID)
	profile.mu.Lock()
	profile.RequestCount = 10
	profile.HasCookies = false
	profile.AcceptsCookies = false
	profile.mu.Unlock()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	result := d.Score(r, clientID, profile)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "cookie_noncompliance" {
			found = true
			if sig.Score != 15 {
				t.Errorf("Expected cookie_noncompliance score 15, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected cookie_noncompliance signal for client that never sends cookies")
	}
}

func TestCookieCompliantNoSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "with-cookies"
	profile := d.GetProfile(clientID)
	profile.mu.Lock()
	profile.RequestCount = 10
	profile.HasCookies = true
	profile.mu.Unlock()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0",
		"Cookie":     "session=abc123",
	})
	result := d.Score(r, clientID, profile)

	for _, sig := range result.Signals {
		if sig.Name == "cookie_noncompliance" {
			t.Error("Should not flag cookie noncompliance when client sends cookies")
		}
	}
}

// ---------------------------------------------------------------------------
// 15. Zero asset loading
// ---------------------------------------------------------------------------

func TestZeroAssetLoading(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "no-assets"
	profile := d.GetProfile(clientID)
	profile.mu.Lock()
	profile.RequestCount = 10
	profile.AssetLoading = false
	profile.mu.Unlock()

	r := newRequest("GET", "/", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	result := d.Score(r, clientID, profile)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "zero_asset_loading" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected zero_asset_loading signal")
	}
}

// ---------------------------------------------------------------------------
// 16. JS execution beacon signals
// ---------------------------------------------------------------------------

func TestJSWebdriverSignal(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "js-webdriver"
	d.RecordBeacon(clientID, map[string]interface{}{
		"webdriver": true,
	})

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "js_webdriver" {
			found = true
			if sig.Score != 40 {
				t.Errorf("Expected js_webdriver score 40, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected js_webdriver signal when webdriver=true in beacon data")
	}
}

func TestJSViewportExceedsScreen(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "js-viewport"
	d.RecordBeacon(clientID, map[string]interface{}{
		"viewportWidth": float64(1920),
		"screenWidth":   float64(1080),
	})

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "js_viewport_exceeds_screen" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected js_viewport_exceeds_screen signal")
	}
}

func TestJSHeadlessGPU(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "js-headless-gpu"
	d.RecordBeacon(clientID, map[string]interface{}{
		"webglRenderer": "Google SwiftShader",
	})

	headers := chromeHeaders()
	r := newRequest("GET", "/", headers)
	result := d.Score(r, clientID, nil)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "js_headless_gpu" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected js_headless_gpu signal for SwiftShader renderer")
	}
}

// ---------------------------------------------------------------------------
// 17. Utility function tests
// ---------------------------------------------------------------------------

func TestExtractChromeVersion(t *testing.T) {
	tests := []struct {
		ua      string
		version int
	}{
		{"Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36", 131},
		{"Mozilla/5.0 Chrome/80.0.3987.149 Safari/537.36", 80},
		{"Mozilla/5.0 Chromium/116.0.5845.96 Safari/537.36", 116},
		{"Mozilla/5.0 Firefox/120.0", 0},
		{"curl/8.4.0", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.ua, func(t *testing.T) {
			ver := extractChromeVersion(tc.ua)
			if ver != tc.version {
				t.Errorf("extractChromeVersion(%q) = %d, want %d", tc.ua, ver, tc.version)
			}
		})
	}
}

func TestExtractSecChUAVersion(t *testing.T) {
	tests := []struct {
		header  string
		version int
	}{
		{`"Chromium";v="131", "Google Chrome";v="131", "Not-A.Brand";v="99"`, 131},
		{`"Chromium";v="120"`, 120},
		{`"Not-A.Brand";v="99"`, 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			ver := extractSecChUAVersion(tc.header)
			if ver != tc.version {
				t.Errorf("extractSecChUAVersion(%q) = %d, want %d", tc.header, ver, tc.version)
			}
		})
	}
}

func TestExtractTrailingNumber(t *testing.T) {
	tests := []struct {
		path string
		num  int
	}{
		{"/page/3", 3},
		{"/article-5", 5},
		{"/posts/123", 123},
		{"/no-number", -1},
		{"", -1},
		{"/page/0", 0},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			n := extractTrailingNumber(tc.path)
			if n != tc.num {
				t.Errorf("extractTrailingNumber(%q) = %d, want %d", tc.path, n, tc.num)
			}
		})
	}
}

func TestCoefficientOfVariation(t *testing.T) {
	// All same -> CV = 0
	same := []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond}
	cv := coefficientOfVariation(same)
	if cv != 0 {
		t.Errorf("Expected CV=0 for identical intervals, got %f", cv)
	}

	// Single value -> CV = 1.0 (default for insufficient data)
	single := []time.Duration{100 * time.Millisecond}
	cv = coefficientOfVariation(single)
	if cv != 1.0 {
		t.Errorf("Expected CV=1.0 for single interval, got %f", cv)
	}

	// Empty -> CV = 1.0
	cv = coefficientOfVariation(nil)
	if cv != 1.0 {
		t.Errorf("Expected CV=1.0 for nil intervals, got %f", cv)
	}
}

func TestIsAssetRequest(t *testing.T) {
	tests := []struct {
		path    string
		accept  string
		isAsset bool
	}{
		{"/style.css", "", true},
		{"/app.js", "", true},
		{"/logo.png", "", true},
		{"/font.woff2", "", true},
		{"/photo.jpg", "", true},
		{"/page", "text/html", false},
		{"/api/data", "application/json", false},
		{"/image", "image/png", true},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			headers := map[string]string{}
			if tc.accept != "" {
				headers["Accept"] = tc.accept
			}
			r := newRequest("GET", tc.path, headers)
			got := isAssetRequest(r)
			if got != tc.isAsset {
				t.Errorf("isAssetRequest(%q, accept=%q) = %v, want %v", tc.path, tc.accept, got, tc.isAsset)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 18. Profile cleanup
// ---------------------------------------------------------------------------

func TestProfileCleanup(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	// Create a profile that's "old"
	clientID := "old-client"
	profile := d.getOrCreateProfile(clientID)
	profile.mu.Lock()
	profile.LastSeen = time.Now().Add(-2 * time.Hour) // 2 hours ago
	profile.mu.Unlock()

	// Create a profile that's "recent"
	recentID := "recent-client"
	d.getOrCreateProfile(recentID)

	r := newRequest("GET", "/", map[string]string{"User-Agent": "Test"})
	d.RecordRequest(recentID, r)

	// Run cleanup
	d.cleanupProfiles()

	d.mu.RLock()
	_, oldExists := d.profiles[clientID]
	_, recentExists := d.profiles[recentID]
	d.mu.RUnlock()

	if oldExists {
		t.Error("Expected old profile to be cleaned up")
	}
	if !recentExists {
		t.Error("Expected recent profile to still exist")
	}
}

// ---------------------------------------------------------------------------
// 19. Sequential crawl pattern
// ---------------------------------------------------------------------------

func TestSequentialCrawlDetection(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "sequential-crawler"
	profile := d.GetProfile(clientID)

	profile.mu.Lock()
	profile.RequestCount = 20
	profile.paths = make(map[string]bool)
	// Create sequential paths: /page/1 through /page/20
	for i := 1; i <= 20; i++ {
		path := "/page/" + strconv.Itoa(i)
		profile.paths[path] = true
	}
	profile.UniquePathCount = 20
	profile.mu.Unlock()

	r := newRequest("GET", "/page/21", map[string]string{
		"User-Agent": "Mozilla/5.0",
	})
	result := d.Score(r, clientID, profile)

	found := false
	for _, sig := range result.Signals {
		if sig.Name == "sequential_crawl" {
			found = true
			if sig.Score != 15 {
				t.Errorf("Expected sequential_crawl score 15, got %f", sig.Score)
			}
			break
		}
	}
	if !found {
		t.Error("Expected sequential_crawl signal for sequential page visits")
	}
}

// ---------------------------------------------------------------------------
// 20. Integration: full bot scenario
// ---------------------------------------------------------------------------

func TestFullBotScenario(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "full-bot"

	// Simulate a bot making requests
	for i := 0; i < 10; i++ {
		r := newRequest("GET", "/page/"+strconv.Itoa(i), map[string]string{
			"User-Agent": "python-requests/2.31.0",
		})
		r.RemoteAddr = "52.1.2.3:12345" // AWS IP
		d.RecordRequest(clientID, r)
		time.Sleep(1 * time.Millisecond)
	}

	// Final score
	r := newRequest("GET", "/page/10", map[string]string{
		"User-Agent": "python-requests/2.31.0",
	})
	r.RemoteAddr = "52.1.2.3:12345"
	result := d.Score(r, clientID, nil)

	// Should have: known_bot_ua (80) + datacenter_ip (15) + cookie_noncompliance (15) + zero_asset_loading (20) = at least 100 (capped)
	if result.Score < 60 {
		t.Errorf("Full bot scenario should score >= 60, got %f", result.Score)
	}
	if result.Classification == "human" {
		t.Errorf("Full bot scenario should not be classified as human, got %q", result.Classification)
	}
	t.Logf("Full bot scenario: score=%f, classification=%q, recommendation=%q, signals=%d",
		result.Score, result.Classification, result.Recommendation, len(result.Signals))
	for _, sig := range result.Signals {
		t.Logf("  Signal: %s (%.0f) - %s", sig.Name, sig.Score, sig.Details)
	}
}

func TestFullHumanScenario(t *testing.T) {
	d := NewDetector()
	defer d.Stop()

	clientID := "full-human"

	// Simulate a real human browser
	headers := chromeHeaders()

	// Record some page views with assets — use variable delays to look human
	pages := []string{"/", "/about", "/contact", "/style.css", "/app.js", "/logo.png"}
	delays := []time.Duration{12, 45, 8, 3, 25, 18} // varied ms, like a real browser
	for i, page := range pages {
		r := newRequest("GET", page, headers)
		r.RemoteAddr = "73.162.45.10:54321" // Residential IP
		r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
		d.RecordRequest(clientID, r)
		time.Sleep(delays[i] * time.Millisecond)
	}

	// Final score
	r := newRequest("GET", "/products", headers)
	r.RemoteAddr = "73.162.45.10:54321"
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
	result := d.Score(r, clientID, nil)

	if result.Classification != "human" {
		t.Errorf("Full human scenario should be classified as 'human', got %q (score=%f)", result.Classification, result.Score)
		for _, sig := range result.Signals {
			t.Logf("  Signal: %s (%.0f) - %s", sig.Name, sig.Score, sig.Details)
		}
	}
	if result.Recommendation != "allow" {
		t.Errorf("Full human scenario should recommend 'allow', got %q", result.Recommendation)
	}
}
