package evasion

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
)

// HeaderManipulator modifies HTTP request headers to evade bot detection,
// fingerprinting, and WAF classification. The Mode controls how aggressive
// the manipulation is:
//
//   - "none": no header changes
//   - "basic": rotate User-Agent only
//   - "advanced": rotate UA, add decoy headers, randomize order
//   - "nightmare": all of the above plus cache-busting, forged IPs, and protocol tricks
type HeaderManipulator struct {
	Mode       string
	UserAgents []string
	currentUA  int
	mu         sync.Mutex
}

// Realistic user agent strings covering major browsers and platforms.
var defaultUserAgents = []string{
	// Chrome on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",

	// Chrome on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

	// Chrome on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",

	// Firefox on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",

	// Firefox on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:122.0) Gecko/20100101 Firefox/122.0",

	// Firefox on Linux
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",

	// Safari on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",

	// Edge on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

	// Mobile - Chrome on Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",

	// Mobile - Safari on iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",

	// Mobile - Firefox on Android
	"Mozilla/5.0 (Android 14; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",

	// Opera
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",

	// Brave (reports as Chrome)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
}

// Common Accept header values from real browsers.
var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
}

// Common Accept-Language values.
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"en-US,en;q=0.9,de;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8",
	"en-US,en;q=0.9,es;q=0.8,pt;q=0.7",
	"en,en-US;q=0.9,ja;q=0.8",
}

// Common Referer values to make requests look organic.
var referers = []string{
	"https://www.google.com/",
	"https://www.google.com/search?q=site",
	"https://www.bing.com/search?q=test",
	"https://duckduckgo.com/?q=search",
	"https://www.google.com/search?q=web+application",
	"",
}

// Forged IP headers used in nightmare mode to confuse IP-based tracking.
var forgedIPHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Client-IP",
	"X-Originating-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	"Forwarded",
}

// NewHeaderManipulator creates a HeaderManipulator with the given mode and the
// default set of user agents. Valid modes: "none", "basic", "advanced", "nightmare".
func NewHeaderManipulator(mode string) *HeaderManipulator {
	switch mode {
	case "none", "basic", "advanced", "nightmare":
		// valid
	default:
		mode = "none"
	}

	agents := make([]string, len(defaultUserAgents))
	copy(agents, defaultUserAgents)

	return &HeaderManipulator{
		Mode:       mode,
		UserAgents: agents,
		currentUA:  0,
	}
}

// Apply modifies the request headers according to the manipulator's mode.
// In "none" mode, headers are untouched. In "basic", only the User-Agent
// rotates. In "advanced" and "nightmare", progressively more evasion
// techniques are applied.
func (h *HeaderManipulator) Apply(req *http.Request) {
	switch h.Mode {
	case "none":
		return

	case "basic":
		req.Header.Set("User-Agent", h.RotateUserAgent())

	case "advanced":
		req.Header.Set("User-Agent", h.RotateUserAgent())
		h.AddDecoyHeaders(req)
		h.RandomizeHeaders(req)

	case "nightmare":
		req.Header.Set("User-Agent", h.RotateUserAgent())
		h.AddDecoyHeaders(req)
		h.addForgedIPHeaders(req)
		h.addCacheBusters(req)
		h.RandomizeHeaders(req)
	}
}

// RotateUserAgent returns the next user agent in the rotation list. It cycles
// through all available UAs sequentially to maintain a consistent pattern
// that mimics a returning user.
func (h *HeaderManipulator) RotateUserAgent() string {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.UserAgents) == 0 {
		return "Mozilla/5.0"
	}

	ua := h.UserAgents[h.currentUA%len(h.UserAgents)]
	h.currentUA++
	return ua
}

// RandomizeHeaders reorders the existing headers on the request. HTTP does not
// require a specific header order, and varying it can bypass fingerprinting
// that relies on header order.
func (h *HeaderManipulator) RandomizeHeaders(req *http.Request) {
	// Go's map iteration is already randomized in Go 1.12+, and http.Header
	// is a map, so the wire order is effectively randomized by the runtime.
	// To provide additional shuffling, we reconstruct the header map.
	original := make(http.Header, len(req.Header))
	keys := make([]string, 0, len(req.Header))
	for k, v := range req.Header {
		original[k] = v
		keys = append(keys, k)
	}

	// Fisher-Yates shuffle.
	for i := len(keys) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		keys[i], keys[j] = keys[j], keys[i]
	}

	// Rebuild the header map in shuffled order.
	req.Header = make(http.Header, len(keys))
	for _, k := range keys {
		req.Header[k] = original[k]
	}
}

// AddDecoyHeaders adds headers that make the request look like it originates
// from a real browser session. This includes Accept, Accept-Language, and
// Referer headers with realistic values.
func (h *HeaderManipulator) AddDecoyHeaders(req *http.Request) {
	// Only set headers that aren't already present.
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", pickRandom(acceptHeaders))
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", pickRandom(acceptLanguages))
	}
	if req.Header.Get("Accept-Encoding") == "" {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	if req.Header.Get("Referer") == "" {
		ref := pickRandom(referers)
		if ref != "" {
			req.Header.Set("Referer", ref)
		}
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}
	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	// DNT (Do Not Track) is common in real browser traffic.
	if req.Header.Get("DNT") == "" {
		req.Header.Set("DNT", "1")
	}
	// Sec-Fetch headers (Chromium browsers).
	if req.Header.Get("Sec-Fetch-Dest") == "" {
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
	}
}

// addForgedIPHeaders adds fake IP address headers to confuse server-side
// IP-based tracking and rate limiting. Only used in nightmare mode.
func (h *HeaderManipulator) addForgedIPHeaders(req *http.Request) {
	ip := randomIP()
	for _, header := range forgedIPHeaders {
		if header == "Forwarded" {
			req.Header.Set(header, fmt.Sprintf("for=%s", ip))
		} else {
			req.Header.Set(header, ip)
		}
	}
}

// addCacheBusters adds headers that prevent caching and force the server to
// generate a fresh response on every request.
func (h *HeaderManipulator) addCacheBusters(req *http.Request) {
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")
}

// pickRandom returns a random element from the slice.
func pickRandom(options []string) string {
	if len(options) == 0 {
		return ""
	}
	return options[rand.Intn(len(options))]
}

// randomIP generates a random non-reserved IPv4 address string.
func randomIP() string {
	// Avoid reserved ranges (0.x, 10.x, 127.x, 172.16-31.x, 192.168.x).
	for {
		a := rand.Intn(223) + 1 // 1-223
		if a == 10 || a == 127 {
			continue
		}
		b := rand.Intn(256)
		if a == 172 && b >= 16 && b <= 31 {
			continue
		}
		if a == 192 && b == 168 {
			continue
		}
		c := rand.Intn(256)
		d := rand.Intn(254) + 1 // 1-254
		return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
	}
}
