package botdetect

import (
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// Signal represents an individual detection signal that contributed to the score.
type Signal struct {
	Name    string
	Score   float64
	Details string
}

// DetectionResult is the output of scoring a single request.
type DetectionResult struct {
	Score          float64  // 0-100, higher = more likely bot
	Signals        []Signal // individual signals that contributed
	Classification string   // "human", "suspicious", "bot", "crawler_service"
	CrawlerProduct string   // identified product if any
	Recommendation string   // "allow", "challenge", "throttle", "block", "labyrinth"
}

// ClientProfile accumulates per-client data used for behavioral analysis.
type ClientProfile struct {
	mu               sync.RWMutex
	RequestCount     int
	UniquePathCount  int
	paths            map[string]bool
	RequestIntervals []time.Duration        // time between requests
	HeaderOrders     []string               // recorded header orderings
	HasCookies       bool                   // has ever sent cookies
	AcceptsCookies   bool                   // returned Set-Cookie on subsequent request
	ExecutesJS       bool                   // JS beacon received
	BeaconData       map[string]interface{} // from JS detection
	AssetLoading     bool                   // loads CSS/JS/images?
	FirstSeen        time.Time
	LastSeen         time.Time
	UserAgents       map[string]int // multiple UAs = rotating proxy
	CrawlerProduct   string         // identified product (firecrawl, oxylabs, etc.)
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

// Detector uses multiple signals to score how likely a client is to be a bot.
type Detector struct {
	mu       sync.RWMutex
	profiles map[string]*ClientProfile

	// Pre-compiled patterns
	botUAPatterns       []*regexp.Regexp
	crawlerProductRules []crawlerProductRule
	datacenterCIDRs     []*net.IPNet
	chromeHeaderOrder   []string

	// Cleanup
	cleanupTicker *time.Ticker
	done          chan struct{}
}

type crawlerProductRule struct {
	Name    string
	Detect  func(ua string, headers http.Header, profile *ClientProfile) bool
	Score   float64
	Details string
}

// NewDetector creates a Detector and starts background profile cleanup.
func NewDetector() *Detector {
	d := &Detector{
		profiles: make(map[string]*ClientProfile),
		done:     make(chan struct{}),
	}
	d.initBotUAPatterns()
	d.initCrawlerProductRules()
	d.initDatacenterCIDRs()
	d.initChromeHeaderOrder()

	d.cleanupTicker = time.NewTicker(5 * time.Minute)
	go d.cleanupLoop()

	return d
}

// Stop shuts down the background cleanup goroutine.
func (d *Detector) Stop() {
	d.cleanupTicker.Stop()
	close(d.done)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Score evaluates a single request and returns a detection result.
func (d *Detector) Score(r *http.Request, clientID string, profile *ClientProfile) *DetectionResult {
	if profile == nil {
		profile = d.GetProfile(clientID)
	}

	var signals []Signal

	// 1. Known bot UA
	if sig := d.checkBotUA(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 2. API crawler product detection
	if sig := d.checkCrawlerProduct(r, profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 3. Missing Sec-Fetch headers
	if sig := d.checkSecFetchHeaders(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 4. Missing Client Hints
	if sig := d.checkClientHints(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 5. Header order analysis
	if sig := d.checkHeaderOrder(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 6. sec-ch-ua version mismatch
	if sig := d.checkVersionMismatch(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 7. Zero asset loading (behavioral)
	if sig := d.checkAssetLoading(profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 8. Timing regularity (behavioral)
	if sig := d.checkTimingRegularity(profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 9. Sequential crawl pattern (behavioral)
	if sig := d.checkSequentialCrawl(profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 10. Cookie non-compliance (behavioral)
	if sig := d.checkCookieCompliance(profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 11. Honeypot interaction
	if sig := d.checkHoneypot(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 12. Datacenter IP
	if sig := d.checkDatacenterIP(r); sig != nil {
		signals = append(signals, *sig)
	}

	// 13. Multiple User-Agents
	if sig := d.checkMultipleUserAgents(profile); sig != nil {
		signals = append(signals, *sig)
	}

	// 14. JS execution results (from beacon)
	if sigs := d.checkJSExecution(profile); len(sigs) > 0 {
		signals = append(signals, sigs...)
	}

	// Calculate total score (capped at 100)
	totalScore := 0.0
	for _, s := range signals {
		totalScore += s.Score
	}
	if totalScore > 100 {
		totalScore = 100
	}

	// Determine crawler product from profile or signals
	crawlerProduct := ""
	profile.mu.RLock()
	crawlerProduct = profile.CrawlerProduct
	profile.mu.RUnlock()

	result := &DetectionResult{
		Score:          totalScore,
		Signals:        signals,
		CrawlerProduct: crawlerProduct,
	}

	// Classify and recommend
	switch {
	case totalScore >= 90:
		result.Classification = "crawler_service"
		if crawlerProduct != "" {
			result.Recommendation = "labyrinth"
		} else {
			result.Recommendation = "block"
		}
	case totalScore >= 60:
		result.Classification = "bot"
		result.Recommendation = "labyrinth"
	case totalScore >= 30:
		result.Classification = "suspicious"
		result.Recommendation = "challenge"
	default:
		result.Classification = "human"
		result.Recommendation = "allow"
	}

	return result
}

// RecordBeacon records JS beacon data sent back from the client.
func (d *Detector) RecordBeacon(clientID string, signals map[string]interface{}) {
	profile := d.getOrCreateProfile(clientID)
	profile.mu.Lock()
	defer profile.mu.Unlock()

	profile.ExecutesJS = true
	if profile.BeaconData == nil {
		profile.BeaconData = make(map[string]interface{})
	}
	for k, v := range signals {
		profile.BeaconData[k] = v
	}
}

// GetProfile returns the accumulated profile for a client. If none exists,
// a new empty profile is created and returned.
func (d *Detector) GetProfile(clientID string) *ClientProfile {
	return d.getOrCreateProfile(clientID)
}

// RecordRequest records request metadata for behavioral analysis.
func (d *Detector) RecordRequest(clientID string, r *http.Request) {
	profile := d.getOrCreateProfile(clientID)
	profile.mu.Lock()
	defer profile.mu.Unlock()

	now := time.Now()

	// Record inter-request interval
	if !profile.LastSeen.IsZero() {
		interval := now.Sub(profile.LastSeen)
		profile.RequestIntervals = append(profile.RequestIntervals, interval)
		// Keep only last 100 intervals
		if len(profile.RequestIntervals) > 100 {
			profile.RequestIntervals = profile.RequestIntervals[len(profile.RequestIntervals)-100:]
		}
	}

	if profile.FirstSeen.IsZero() {
		profile.FirstSeen = now
	}
	profile.LastSeen = now
	profile.RequestCount++

	// Track unique paths
	path := r.URL.Path
	if profile.paths == nil {
		profile.paths = make(map[string]bool)
	}
	if !profile.paths[path] {
		profile.paths[path] = true
		profile.UniquePathCount++
	}

	// Track user agents
	ua := r.UserAgent()
	if ua != "" {
		if profile.UserAgents == nil {
			profile.UserAgents = make(map[string]int)
		}
		profile.UserAgents[ua]++
	}

	// Track header order
	headerOrder := buildHeaderOrderString(r)
	profile.HeaderOrders = append(profile.HeaderOrders, headerOrder)
	if len(profile.HeaderOrders) > 20 {
		profile.HeaderOrders = profile.HeaderOrders[len(profile.HeaderOrders)-20:]
	}

	// Track cookies
	if len(r.Cookies()) > 0 {
		profile.HasCookies = true
	}

	// Track asset loading (CSS, JS, images, fonts)
	if isAssetRequest(r) {
		profile.AssetLoading = true
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (d *Detector) getOrCreateProfile(clientID string) *ClientProfile {
	d.mu.RLock()
	p, ok := d.profiles[clientID]
	d.mu.RUnlock()
	if ok {
		return p
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Double-check after acquiring write lock
	if p, ok := d.profiles[clientID]; ok {
		return p
	}
	p = &ClientProfile{
		paths:      make(map[string]bool),
		UserAgents: make(map[string]int),
		BeaconData: make(map[string]interface{}),
		FirstSeen:  time.Now(),
	}
	d.profiles[clientID] = p
	return p
}

func (d *Detector) cleanupLoop() {
	for {
		select {
		case <-d.cleanupTicker.C:
			d.cleanupProfiles()
		case <-d.done:
			return
		}
	}
}

func (d *Detector) cleanupProfiles() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, p := range d.profiles {
		p.mu.RLock()
		lastSeen := p.LastSeen
		p.mu.RUnlock()
		if !lastSeen.IsZero() && lastSeen.Before(cutoff) {
			delete(d.profiles, id)
		}
	}
}

// ---------------------------------------------------------------------------
// Signal checks
// ---------------------------------------------------------------------------

// 1. Known bot User-Agent
func (d *Detector) checkBotUA(r *http.Request) *Signal {
	ua := r.UserAgent()
	if ua == "" {
		return &Signal{
			Name:    "empty_user_agent",
			Score:   30,
			Details: "Request has no User-Agent header",
		}
	}
	uaLower := strings.ToLower(ua)
	for _, pat := range d.botUAPatterns {
		if pat.MatchString(uaLower) {
			return &Signal{
				Name:    "known_bot_ua",
				Score:   80,
				Details: "User-Agent matches known bot pattern: " + pat.String(),
			}
		}
	}
	return nil
}

// 2. API crawler product detection
func (d *Detector) checkCrawlerProduct(r *http.Request, profile *ClientProfile) *Signal {
	ua := strings.ToLower(r.UserAgent())
	for _, rule := range d.crawlerProductRules {
		if rule.Detect(ua, r.Header, profile) {
			profile.mu.Lock()
			profile.CrawlerProduct = rule.Name
			profile.mu.Unlock()
			return &Signal{
				Name:    "crawler_product_" + strings.ToLower(rule.Name),
				Score:   rule.Score,
				Details: rule.Details,
			}
		}
	}
	return nil
}

// 3. Missing Sec-Fetch headers
func (d *Detector) checkSecFetchHeaders(r *http.Request) *Signal {
	ua := r.UserAgent()
	chromeVer := extractChromeVersion(ua)
	if chromeVer < 80 {
		return nil // Sec-Fetch not expected
	}

	missing := []string{}
	for _, h := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
		if r.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	return &Signal{
		Name:    "missing_sec_fetch",
		Score:   30,
		Details: "Chrome " + strconv.Itoa(chromeVer) + " UA but missing: " + strings.Join(missing, ", "),
	}
}

// 4. Missing Client Hints
func (d *Detector) checkClientHints(r *http.Request) *Signal {
	ua := r.UserAgent()
	chromeVer := extractChromeVersion(ua)
	if chromeVer < 89 {
		return nil // Client hints not expected
	}

	if r.Header.Get("Sec-Ch-Ua") == "" && r.Header.Get("sec-ch-ua") == "" {
		return &Signal{
			Name:    "missing_client_hints",
			Score:   25,
			Details: "Chrome " + strconv.Itoa(chromeVer) + " UA but no sec-ch-ua headers",
		}
	}
	return nil
}

// 5. Header order analysis
func (d *Detector) checkHeaderOrder(r *http.Request) *Signal {
	ua := r.UserAgent()
	if !strings.Contains(strings.ToLower(ua), "chrome") {
		return nil // Only check Chrome for now
	}

	order := getHeaderKeys(r)
	if len(order) < 3 {
		return nil
	}

	// Chrome typically sends Host first, then high-priority headers
	// Check for a set of anomalies rather than an exact match
	score := d.headerOrderScore(order)
	if score > 0 {
		return &Signal{
			Name:    "header_order_anomaly",
			Score:   score,
			Details: "Header order deviates from expected Chrome pattern",
		}
	}
	return nil
}

// 6. sec-ch-ua version mismatch
func (d *Detector) checkVersionMismatch(r *http.Request) *Signal {
	ua := r.UserAgent()
	chromeVer := extractChromeVersion(ua)
	if chromeVer == 0 {
		return nil
	}

	// Check sec-ch-ua header
	secChUA := r.Header.Get("Sec-Ch-Ua")
	if secChUA == "" {
		secChUA = r.Header.Get("sec-ch-ua")
	}
	if secChUA == "" {
		return nil
	}

	// Parse sec-ch-ua for Chromium version
	chVer := extractSecChUAVersion(secChUA)
	if chVer == 0 {
		return nil
	}

	if chromeVer != chVer {
		return &Signal{
			Name:    "version_mismatch",
			Score:   30,
			Details: "UA Chrome/" + strconv.Itoa(chromeVer) + " but sec-ch-ua reports " + strconv.Itoa(chVer),
		}
	}
	return nil
}

// 7. Zero asset loading
func (d *Detector) checkAssetLoading(profile *ClientProfile) *Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if profile.RequestCount < 5 {
		return nil // Need enough data
	}
	if profile.AssetLoading {
		return nil // Client loads assets
	}

	return &Signal{
		Name:    "zero_asset_loading",
		Score:   20,
		Details: "Client has made " + strconv.Itoa(profile.RequestCount) + " requests but never loaded CSS/JS/images/fonts",
	}
}

// 8. Timing regularity
func (d *Detector) checkTimingRegularity(profile *ClientProfile) *Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.RequestIntervals) < 5 {
		return nil
	}

	cv := coefficientOfVariation(profile.RequestIntervals)
	if cv < 0.15 {
		return &Signal{
			Name:    "timing_regularity",
			Score:   20,
			Details: "Inter-request timing CV=" + strconv.FormatFloat(cv, 'f', 3, 64) + " (very regular, machine-like)",
		}
	}
	return nil
}

// 9. Sequential crawl pattern
func (d *Detector) checkSequentialCrawl(profile *ClientProfile) *Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if profile.UniquePathCount < 10 {
		return nil
	}

	paths := make([]string, 0, len(profile.paths))
	for p := range profile.paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	// Check for sequential numeric patterns in paths
	sequentialCount := 0
	for i := 1; i < len(paths); i++ {
		numA := extractTrailingNumber(paths[i-1])
		numB := extractTrailingNumber(paths[i])
		if numA >= 0 && numB >= 0 && numB == numA+1 {
			sequentialCount++
		}
	}

	// If more than 40% of paths are sequential, flag it
	ratio := float64(sequentialCount) / float64(len(paths))
	if ratio > 0.4 {
		return &Signal{
			Name:    "sequential_crawl",
			Score:   15,
			Details: "Sequential path pattern detected (" + strconv.Itoa(int(ratio*100)) + "% sequential)",
		}
	}
	return nil
}

// 10. Cookie non-compliance
func (d *Detector) checkCookieCompliance(profile *ClientProfile) *Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if profile.RequestCount < 3 {
		return nil
	}
	if profile.HasCookies {
		return nil // Client sends cookies, compliant
	}
	if profile.AcceptsCookies {
		return nil
	}

	return &Signal{
		Name:    "cookie_noncompliance",
		Score:   15,
		Details: "Client has made " + strconv.Itoa(profile.RequestCount) + " requests without returning cookies",
	}
}

// 11. Honeypot interaction
func (d *Detector) checkHoneypot(r *http.Request) *Signal {
	// Check for honeypot header set by the honeypot handler
	if r.Header.Get("X-Glitch-Honeypot-Hit") == "true" {
		return &Signal{
			Name:    "honeypot_interaction",
			Score:   100,
			Details: "Client visited honeypot path: " + r.URL.Path,
		}
	}
	return nil
}

// 12. Datacenter IP
func (d *Detector) checkDatacenterIP(r *http.Request) *Signal {
	ipStr := extractIP(r)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	for _, cidr := range d.datacenterCIDRs {
		if cidr.Contains(ip) {
			return &Signal{
				Name:    "datacenter_ip",
				Score:   15,
				Details: "IP " + ipStr + " is in datacenter range " + cidr.String(),
			}
		}
	}
	return nil
}

// 13. Multiple User-Agents
func (d *Detector) checkMultipleUserAgents(profile *ClientProfile) *Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.UserAgents) <= 1 {
		return nil
	}

	return &Signal{
		Name:    "multiple_user_agents",
		Score:   40,
		Details: "Client used " + strconv.Itoa(len(profile.UserAgents)) + " different User-Agent strings",
	}
}

// 14. JS execution results (from beacon data)
func (d *Detector) checkJSExecution(profile *ClientProfile) []Signal {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	if len(profile.BeaconData) == 0 {
		return nil
	}

	var signals []Signal

	// webdriver flag
	if wd, ok := profile.BeaconData["webdriver"]; ok {
		if wdBool, isBool := wd.(bool); isBool && wdBool {
			signals = append(signals, Signal{
				Name:    "js_webdriver",
				Score:   40,
				Details: "navigator.webdriver is true (automation detected)",
			})
		}
	}

	// Plugin count
	if pc, ok := profile.BeaconData["pluginCount"]; ok {
		if pcFloat, isFloat := pc.(float64); isFloat && pcFloat == 0 {
			signals = append(signals, Signal{
				Name:    "js_zero_plugins",
				Score:   15,
				Details: "Browser reports zero plugins",
			})
		}
	}

	// Viewport vs screen consistency
	if vw, ok := profile.BeaconData["viewportWidth"]; ok {
		if sw, ok2 := profile.BeaconData["screenWidth"]; ok2 {
			vwF, vwOK := vw.(float64)
			swF, swOK := sw.(float64)
			if vwOK && swOK && vwF > swF {
				signals = append(signals, Signal{
					Name:    "js_viewport_exceeds_screen",
					Score:   25,
					Details: "Viewport width (" + strconv.FormatFloat(vwF, 'f', 0, 64) + ") exceeds screen width (" + strconv.FormatFloat(swF, 'f', 0, 64) + ")",
				})
			}
		}
	}

	// WebGL renderer check for headless
	if renderer, ok := profile.BeaconData["webglRenderer"]; ok {
		if rendererStr, isStr := renderer.(string); isStr {
			rLower := strings.ToLower(rendererStr)
			if strings.Contains(rLower, "swiftshader") || strings.Contains(rLower, "llvmpipe") {
				signals = append(signals, Signal{
					Name:    "js_headless_gpu",
					Score:   35,
					Details: "WebGL renderer indicates headless browser: " + rendererStr,
				})
			}
		}
	}

	return signals
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

func (d *Detector) initBotUAPatterns() {
	patterns := []string{
		`gptbot`,
		`chatgpt`,
		`claudebot`,
		`claude-web`,
		`anthropic`,
		`ccbot`,
		`scrapy`,
		`python-requests`,
		`python-urllib`,
		`go-http-client`,
		`\bcurl\b`,
		`\bwget\b`,
		`firecrawl`,
		`brightbot`,
		`crawl4ai`,
		`perplexitybot`,
		`bytespider`,
		`amazonbot`,
		`applebot`,
		`facebookexternalhit`,
		`twitterbot`,
		`slackbot`,
		`telegrambot`,
		`whatsapp`,
		`discordbot`,
		`linkedinbot`,
		`ahrefsbot`,
		`semrushbot`,
		`mj12bot`,
		`dotbot`,
		`rogerbot`,
		`seznambot`,
		`yandexbot`,
		`baiduspider`,
		`sogou`,
		`exabot`,
		`ia_archiver`,
		`archive\.org_bot`,
		`headlesschrome`,
		`phantomjs`,
		`selenium`,
		`puppeteer`,
		`playwright`,
		`httpx`,
		`axios`,
		`node-fetch`,
		`undici`,
		`java/`,
		`okhttp`,
		`apache-httpclient`,
		`libwww-perl`,
		`mechanize`,
		`colly`,
	}

	d.botUAPatterns = make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		d.botUAPatterns = append(d.botUAPatterns, regexp.MustCompile(p))
	}
}

func (d *Detector) initCrawlerProductRules() {
	d.crawlerProductRules = []crawlerProductRule{
		{
			Name:  "Firecrawl",
			Score: 90,
			Details: "Firecrawl crawler detected via UA or header patterns",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				if strings.Contains(ua, "firecrawl") || strings.Contains(ua, "firecrawlagent") {
					return true
				}
				// Playwright-like header patterns: Sec-CH-UA containing "HeadlessChrome"
				// combined with specific connection patterns
				secCHUA := strings.ToLower(headers.Get("Sec-Ch-Ua"))
				if strings.Contains(secCHUA, "headlesschrome") &&
					(strings.Contains(ua, "chrome") && headers.Get("Sec-Fetch-Site") == "same-origin") {
					return true
				}
				return false
			},
		},
		{
			Name:  "Oxylabs",
			Score: 90,
			Details: "Oxylabs proxy detected via platform mismatch",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				// Platform mismatch: UA says Windows but Sec-CH-UA-Platform says Linux (or vice versa)
				platform := strings.ToLower(headers.Get("Sec-Ch-Ua-Platform"))
				if platform == "" {
					return false
				}
				platform = strings.Trim(platform, `"`)
				uaHasWindows := strings.Contains(ua, "windows")
				uaHasLinux := strings.Contains(ua, "linux")
				uaHasMac := strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os")

				platformIsWindows := strings.Contains(platform, "windows")
				platformIsLinux := strings.Contains(platform, "linux")
				platformIsMac := strings.Contains(platform, "macos") || strings.Contains(platform, "mac")

				if uaHasWindows && !platformIsWindows {
					return true
				}
				if uaHasLinux && !platformIsLinux && !uaHasWindows && !uaHasMac {
					return true
				}
				if uaHasMac && !platformIsMac {
					return true
				}
				return false
			},
		},
		{
			Name:  "ScrapingBee",
			Score: 90,
			Details: "ScrapingBee detected via CDP signals in beacon data",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				profile.mu.RLock()
				defer profile.mu.RUnlock()
				if len(profile.BeaconData) == 0 {
					return false
				}

				// CDP signal in beacon data
				if cdp, ok := profile.BeaconData["cdp"]; ok {
					if cdpBool, isBool := cdp.(bool); isBool && cdpBool {
						return true
					}
				}

				// Viewport > screen + zero plugins
				vw, hasVW := profile.BeaconData["viewportWidth"]
				sw, hasSW := profile.BeaconData["screenWidth"]
				pc, hasPC := profile.BeaconData["pluginCount"]
				if hasVW && hasSW && hasPC {
					vwF, vwOK := vw.(float64)
					swF, swOK := sw.(float64)
					pcF, pcOK := pc.(float64)
					if vwOK && swOK && pcOK && vwF > swF && pcF == 0 {
						return true
					}
				}
				return false
			},
		},
		{
			Name:  "BrightData",
			Score: 90,
			Details: "Bright Data detected via UA or behavioral pattern",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				if strings.Contains(ua, "brightbot") {
					return true
				}
				return false
			},
		},
		{
			Name:  "Crawl4AI",
			Score: 90,
			Details: "Crawl4AI detected via outdated Chrome version and Linux platform",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				if strings.Contains(ua, "crawl4ai") {
					return true
				}
				// Outdated Chrome version (116.x) on Linux x86_64
				chromeVer := extractChromeVersion(strings.ToUpper(ua))
				if chromeVer == 0 {
					// Try case-insensitive extract
					chromeVer = extractChromeVersion(ua)
				}
				if chromeVer >= 110 && chromeVer <= 120 &&
					strings.Contains(ua, "linux") && strings.Contains(ua, "x86_64") {
					// Current Chrome is 140+, version 116 is very outdated
					return true
				}
				return false
			},
		},
		{
			Name:  "GenericHeadless",
			Score: 90,
			Details: "Headless browser detected via WebGL renderer or webdriver flag",
			Detect: func(ua string, headers http.Header, profile *ClientProfile) bool {
				profile.mu.RLock()
				defer profile.mu.RUnlock()

				if len(profile.BeaconData) == 0 {
					return false
				}

				// SwiftShader/llvmpipe in WebGL renderer
				if renderer, ok := profile.BeaconData["webglRenderer"]; ok {
					if rendererStr, isStr := renderer.(string); isStr {
						rLower := strings.ToLower(rendererStr)
						if strings.Contains(rLower, "swiftshader") || strings.Contains(rLower, "llvmpipe") {
							return true
						}
					}
				}

				// navigator.webdriver=true
				if wd, ok := profile.BeaconData["webdriver"]; ok {
					if wdBool, isBool := wd.(bool); isBool && wdBool {
						return true
					}
				}

				return false
			},
		},
	}
}

func (d *Detector) initDatacenterCIDRs() {
	// More specific datacenter CIDR blocks for major cloud providers
	cidrs := []string{
		// AWS
		"3.0.0.0/9",
		"3.128.0.0/9",
		"13.32.0.0/11",
		"13.64.0.0/11",
		"13.208.0.0/12",
		"13.224.0.0/12",
		"13.248.0.0/13",
		"18.0.0.0/10",
		"18.64.0.0/10",
		"18.128.0.0/9",
		"34.192.0.0/10",
		"34.224.0.0/12",
		"34.240.0.0/13",
		"35.152.0.0/13",
		"35.160.0.0/11",
		"52.0.0.0/11",
		"52.32.0.0/11",
		"52.64.0.0/12",
		"52.80.0.0/12",
		"52.94.0.0/15",
		"52.192.0.0/11",
		"54.64.0.0/11",
		"54.144.0.0/12",
		"54.160.0.0/11",
		"54.192.0.0/12",
		"54.208.0.0/13",
		"54.216.0.0/13",
		"54.224.0.0/12",
		"54.240.0.0/12",
		// GCP
		"34.64.0.0/11",
		"34.96.0.0/12",
		"34.112.0.0/12",
		"34.128.0.0/10",
		"35.184.0.0/12",
		"35.192.0.0/11",
		"35.224.0.0/12",
		"35.236.0.0/14",
		"35.240.0.0/13",
		// Azure
		"13.64.0.0/11",
		"13.96.0.0/13",
		"13.104.0.0/14",
		"20.0.0.0/11",
		"20.32.0.0/11",
		"20.64.0.0/10",
		"20.128.0.0/10",
		"20.192.0.0/10",
		"40.64.0.0/10",
		"40.112.0.0/12",
		"40.128.0.0/12",
		"51.104.0.0/13",
		"51.112.0.0/12",
		"51.128.0.0/12",
		"52.96.0.0/12",
		"52.112.0.0/12",
		"52.136.0.0/13",
		"52.148.0.0/14",
		"52.152.0.0/13",
		"52.160.0.0/11",
		// DigitalOcean
		"64.225.0.0/16",
		"104.131.0.0/16",
		"104.236.0.0/16",
		"138.68.0.0/16",
		"138.197.0.0/16",
		"139.59.0.0/16",
		"159.65.0.0/16",
		"159.89.0.0/16",
		"159.203.0.0/16",
		"161.35.0.0/16",
		"167.71.0.0/16",
		"167.172.0.0/16",
		"178.128.0.0/16",
		// Hetzner
		"5.9.0.0/16",
		"5.75.0.0/16",
		"46.4.0.0/16",
		"78.46.0.0/15",
		"78.47.0.0/16",
		"88.198.0.0/16",
		"88.99.0.0/16",
		"136.243.0.0/16",
		"138.201.0.0/16",
		"144.76.0.0/16",
		"148.251.0.0/16",
		"157.90.0.0/16",
		"159.69.0.0/16",
		"162.55.0.0/16",
		"168.119.0.0/16",
		"176.9.0.0/16",
		"178.63.0.0/16",
		"185.12.64.0/22",
		"188.40.0.0/16",
		"195.201.0.0/16",
		"213.133.0.0/16",
		"213.239.0.0/16",
		// OVH
		"51.68.0.0/16",
		"51.75.0.0/16",
		"51.77.0.0/16",
		"51.79.0.0/16",
		"51.83.0.0/16",
		"51.89.0.0/16",
		"51.91.0.0/16",
		"51.161.0.0/16",
		"51.178.0.0/16",
		"51.195.0.0/16",
		"51.210.0.0/16",
		"51.222.0.0/16",
		"54.36.0.0/14",
		// Linode
		"45.33.0.0/16",
		"45.56.0.0/16",
		"45.79.0.0/16",
		"50.116.0.0/16",
		"66.175.208.0/20",
		"69.164.192.0/20",
		"72.14.176.0/20",
		"74.207.224.0/20",
		"96.126.96.0/19",
		"139.144.0.0/16",
		"139.162.0.0/16",
		"172.104.0.0/15",
		"172.232.0.0/14",
		"173.255.192.0/18",
		"178.79.128.0/17",
		"194.195.208.0/21",
		// Vultr
		"45.32.0.0/16",
		"45.63.0.0/16",
		"45.76.0.0/16",
		"45.77.0.0/16",
		"64.176.0.0/16",
		"64.237.32.0/19",
		"66.42.0.0/16",
		"78.141.192.0/18",
		"95.179.128.0/17",
		"104.156.224.0/19",
		"104.238.128.0/17",
		"108.61.0.0/16",
		"136.244.64.0/18",
		"140.82.0.0/16",
		"149.28.0.0/16",
		"155.138.128.0/17",
		"207.148.0.0/16",
		"209.250.224.0/19",
		"216.128.128.0/17",
	}

	d.datacenterCIDRs = make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			d.datacenterCIDRs = append(d.datacenterCIDRs, ipNet)
		}
	}
}

func (d *Detector) initChromeHeaderOrder() {
	// Real Chrome typically sends headers in this approximate order
	d.chromeHeaderOrder = []string{
		"host",
		"connection",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
		"cookie",
	}
}

// headerOrderScore returns a score (0-25) based on how much the header order
// deviates from a known Chrome browser pattern.
func (d *Detector) headerOrderScore(order []string) float64 {
	if len(order) < 3 {
		return 0
	}

	// Normalize to lowercase
	normalized := make([]string, len(order))
	for i, h := range order {
		normalized[i] = strings.ToLower(h)
	}

	// Build position maps
	expectedPos := make(map[string]int)
	for i, h := range d.chromeHeaderOrder {
		expectedPos[h] = i
	}

	actualPos := make(map[string]int)
	for i, h := range normalized {
		actualPos[h] = i
	}

	// Count inversions among headers that appear in both orders
	inversions := 0
	matches := 0
	for i := 0; i < len(d.chromeHeaderOrder); i++ {
		for j := i + 1; j < len(d.chromeHeaderOrder); j++ {
			hA := d.chromeHeaderOrder[i]
			hB := d.chromeHeaderOrder[j]
			posA, okA := actualPos[hA]
			posB, okB := actualPos[hB]
			if okA && okB {
				matches++
				if posA > posB {
					inversions++
				}
			}
		}
	}

	if matches == 0 {
		return 0
	}

	// Inversion ratio > 0.3 is suspicious
	inversionRatio := float64(inversions) / float64(matches)
	if inversionRatio > 0.3 {
		// Scale 0-25 based on ratio (0.3 -> 0, 1.0 -> 25)
		score := (inversionRatio - 0.3) / 0.7 * 25.0
		if score > 25 {
			score = 25
		}
		return score
	}
	return 0
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// extractChromeVersion parses the Chrome major version from a User-Agent string.
// Returns 0 if Chrome is not found.
func extractChromeVersion(ua string) int {
	// Match Chrome/NNN or Chromium/NNN
	idx := strings.Index(ua, "Chrome/")
	if idx == -1 {
		idx = strings.Index(ua, "chrome/")
	}
	if idx == -1 {
		idx = strings.Index(ua, "Chromium/")
	}
	if idx == -1 {
		idx = strings.Index(ua, "chromium/")
	}
	if idx == -1 {
		return 0
	}

	// Advance past "Chrome/"
	start := idx + strings.Index(ua[idx:], "/") + 1
	if start >= len(ua) {
		return 0
	}

	// Read digits
	end := start
	for end < len(ua) && ua[end] >= '0' && ua[end] <= '9' {
		end++
	}
	if end == start {
		return 0
	}

	ver, err := strconv.Atoi(ua[start:end])
	if err != nil {
		return 0
	}
	return ver
}

// extractSecChUAVersion parses the Chromium version from a sec-ch-ua header value.
// Example: `"Chromium";v="131", "Google Chrome";v="131"` -> 131
func extractSecChUAVersion(header string) int {
	// Look for "Chromium";v="NNN" or "Google Chrome";v="NNN"
	for _, brand := range []string{"Chromium", "Google Chrome"} {
		idx := strings.Index(header, brand)
		if idx == -1 {
			continue
		}
		// Find v="NNN" after the brand
		rest := header[idx:]
		vIdx := strings.Index(rest, `v="`)
		if vIdx == -1 {
			continue
		}
		start := vIdx + 3
		end := start
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == start {
			continue
		}
		ver, err := strconv.Atoi(rest[start:end])
		if err == nil {
			return ver
		}
	}
	return 0
}

// extractIP pulls the client IP from the request, checking X-Forwarded-For
// and X-Real-IP before falling back to RemoteAddr.
func extractIP(r *http.Request) string {
	// Check forwarding headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Strip port from RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// getHeaderKeys returns the header keys in the order they appear in the request.
func getHeaderKeys(r *http.Request) []string {
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	return keys
}

// buildHeaderOrderString creates a deterministic string representation of header
// order for storage in profiles.
func buildHeaderOrderString(r *http.Request) string {
	keys := getHeaderKeys(r)
	return strings.Join(keys, ",")
}

// isAssetRequest returns true if the request is for a typical web asset.
func isAssetRequest(r *http.Request) bool {
	path := strings.ToLower(r.URL.Path)
	assetExts := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".webp", ".avif", ".map",
	}
	for _, ext := range assetExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	// Also check Accept header for asset types
	accept := r.Header.Get("Accept")
	assetAccepts := []string{
		"text/css",
		"application/javascript",
		"image/",
		"font/",
	}
	for _, a := range assetAccepts {
		if strings.Contains(accept, a) {
			return true
		}
	}
	return false
}

// coefficientOfVariation computes CV = stddev / mean for a slice of durations.
// Returns 1.0 if there are fewer than 2 values.
func coefficientOfVariation(intervals []time.Duration) float64 {
	n := len(intervals)
	if n < 2 {
		return 1.0
	}

	// Calculate mean
	var sum float64
	for _, d := range intervals {
		sum += float64(d)
	}
	mean := sum / float64(n)
	if mean == 0 {
		return 0
	}

	// Calculate standard deviation
	var variance float64
	for _, d := range intervals {
		diff := float64(d) - mean
		variance += diff * diff
	}
	variance /= float64(n)
	stddev := math.Sqrt(variance)

	return stddev / mean
}

// extractTrailingNumber returns the trailing numeric value from a path segment,
// or -1 if none is found. E.g. "/page/3" -> 3, "/article-5" -> 5.
func extractTrailingNumber(path string) int {
	// Find trailing digits
	end := len(path)
	start := end
	for start > 0 && path[start-1] >= '0' && path[start-1] <= '9' {
		start--
	}
	if start == end {
		return -1
	}
	n, err := strconv.Atoi(path[start:end])
	if err != nil {
		return -1
	}
	return n
}
