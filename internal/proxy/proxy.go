package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cornerglitch/internal/errors"
	"github.com/cornerglitch/internal/labyrinth"
	"github.com/cornerglitch/internal/pages"
)

// Options configures the reverse proxy behavior.
type Options struct {
	Target           string   // Backend URL (e.g., "http://localhost:3000")
	ScoreThreshold   float64  // Bot score above which to intercept (default: 50)
	PassthroughPaths []string // Paths to always pass through (e.g., "/api/health")
	InterceptMode    string   // "block", "challenge", "labyrinth", "glitch" (default: "glitch")
	DashboardPort    int      // Port for proxy dashboard (default: 8766)
	EnableLogging    bool     // Enable request logging
}

// ProxyStats tracks proxy operation statistics.
type ProxyStats struct {
	TotalRequests    int64
	PassedThrough    int64
	Intercepted      int64
	Challenged       int64
	Blocked          int64
	LabyrinthTrapped int64
}

// clientState tracks per-client scoring state.
type clientState struct {
	mu            sync.Mutex
	id            string
	score         float64
	firstSeen     time.Time
	lastSeen      time.Time
	requestTimes  []time.Time // ring buffer of last N request timestamps
	cookieSet     bool        // whether we set the tracking cookie
	cookieReturned bool       // whether the client returned our cookie
	totalRequests int64
}

// MirrorSettings holds server behavior settings that the proxy mirrors.
// When set, the proxy applies these settings instead of its default profiles.
type MirrorSettings struct {
	ErrorWeights         map[string]float64
	ErrorRateMultiplier  float64
	PageTypeWeights      map[string]float64
	HeaderCorruptLevel   int
	ProtocolGlitchEnabled bool
	ProtocolGlitchLevel  int
	DelayMinMs           int
	DelayMaxMs           int
	ContentTheme         string
}

// ReverseProxy is the main proxy handler that sits in front of a real backend,
// selectively intercepting suspicious traffic and applying glitch defenses.
type ReverseProxy struct {
	target         *url.URL
	reverseProxy   *httputil.ReverseProxy
	opts           Options
	scoreThreshold atomic.Value // float64

	// Interception pipeline (configured by modes package)
	Pipeline *Pipeline

	// Per-client state
	clients sync.Map // map[string]*clientState

	// Glitch subsystems (used for interception)
	lab     *labyrinth.Labyrinth
	errGen  *errors.Generator
	pageGen *pages.Generator

	// Mirror mode: when set, applyGlitchTreatment uses these server settings
	mirrorMu       sync.RWMutex
	mirrorSettings *MirrorSettings

	// Statistics
	totalRequests    atomic.Int64
	passedThrough    atomic.Int64
	intercepted      atomic.Int64
	challenged       atomic.Int64
	blocked          atomic.Int64
	labyrinthTrapped atomic.Int64

	// Cleanup
	stopCleanup chan struct{}
}

// Known bot User-Agent patterns.
var botPatterns = []string{
	"googlebot", "bingbot", "yandex", "baiduspider",
	"gptbot", "chatgpt", "anthropic", "claude", "ccbot", "perplexity",
	"python", "httpx", "requests", "urllib",
	"go-http", "java/", "curl", "wget",
	"postman", "insomnia",
	"ab/", "wrk", "siege", "vegeta", "hey/", "bombardier",
	"k6", "locust", "jmeter", "gatling",
	"scrapy", "httpclient", "mechanize", "phantom", "headless",
	"semrush", "ahrefs", "mj12bot", "dotbot", "rogerbot",
	"bytespider", "petalbot", "amazonbot",
}

// challengeCookieName is the cookie used to track challenge compliance.
const challengeCookieName = "_glitch_proxy_ck"

// NewReverseProxy creates a new reverse proxy with the given target and options.
func NewReverseProxy(target string, opts Options) *ReverseProxy {
	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("invalid target URL %q: %v", target, err)
	}

	if opts.ScoreThreshold == 0 {
		opts.ScoreThreshold = 50
	}
	if opts.InterceptMode == "" {
		opts.InterceptMode = "glitch"
	}
	if opts.DashboardPort == 0 {
		opts.DashboardPort = 8766
	}

	rp := &ReverseProxy{
		target:      targetURL,
		opts:        opts,
		lab:         labyrinth.NewLabyrinth(),
		errGen:      errors.NewGenerator(),
		pageGen:     pages.NewGenerator(),
		stopCleanup: make(chan struct{}),
	}

	rp.scoreThreshold.Store(opts.ScoreThreshold)

	// Configure the stdlib reverse proxy
	rp.reverseProxy = &httputil.ReverseProxy{
		Director: rp.director,
		ModifyResponse: func(resp *http.Response) error {
			if rp.Pipeline != nil {
				processed, err := rp.Pipeline.ProcessResponse(resp)
				if err != nil {
					return err
				}
				// Copy modified fields back into the original response
				*resp = *processed
			}
			return nil
		},
	}

	// Start background cleanup of expired client state
	go rp.cleanupLoop()

	return rp
}

// SetScoreThreshold updates the bot score threshold for interception.
func (rp *ReverseProxy) SetScoreThreshold(threshold float64) {
	rp.scoreThreshold.Store(threshold)
}

// SetMirrorSettings sets (or clears) the mirror settings. When non-nil,
// applyGlitchTreatment uses these server-mirrored settings.
func (rp *ReverseProxy) SetMirrorSettings(ms *MirrorSettings) {
	rp.mirrorMu.Lock()
	defer rp.mirrorMu.Unlock()
	rp.mirrorSettings = ms
}

// GetMirrorSettings returns the current mirror settings (may be nil).
func (rp *ReverseProxy) GetMirrorSettings() *MirrorSettings {
	rp.mirrorMu.RLock()
	defer rp.mirrorMu.RUnlock()
	return rp.mirrorSettings
}

// Stats returns current proxy statistics.
func (rp *ReverseProxy) Stats() *ProxyStats {
	return &ProxyStats{
		TotalRequests:    rp.totalRequests.Load(),
		PassedThrough:    rp.passedThrough.Load(),
		Intercepted:      rp.intercepted.Load(),
		Challenged:       rp.challenged.Load(),
		Blocked:          rp.blocked.Load(),
		LabyrinthTrapped: rp.labyrinthTrapped.Load(),
	}
}

// Shutdown stops the background cleanup goroutine.
func (rp *ReverseProxy) Shutdown() {
	close(rp.stopCleanup)
}

// ServeHTTP is the main handler: fingerprint, score, decide pass/intercept.
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.totalRequests.Add(1)

	// Run requests through the pipeline before any other processing.
	// The pipeline may modify headers, inject latency, or block requests entirely.
	if rp.Pipeline != nil {
		processed, err := rp.Pipeline.ProcessRequest(r)
		if err != nil {
			// Pipeline blocked the request (e.g., WAF signature match)
			rp.blocked.Add(1)
			if rp.opts.EnableLogging {
				log.Printf("[proxy] PIPELINE_BLOCK %s %s error=%v", r.Method, r.URL.Path, err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `{"error":"Forbidden","message":%q}`, err.Error())
			return
		}
		if processed == nil {
			// Interceptor signaled silent block
			rp.blocked.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		r = processed
	}

	// Check passthrough paths first (fast path)
	for _, p := range rp.opts.PassthroughPaths {
		if strings.HasPrefix(r.URL.Path, p) {
			rp.passedThrough.Add(1)
			rp.proxyPass(w, r, 0)
			return
		}
	}

	// Fingerprint and score the client
	cs := rp.getOrCreateClient(r)
	score := rp.scoreClient(cs, r)
	cs.mu.Lock()
	cs.score = score
	cs.mu.Unlock()

	threshold := rp.scoreThreshold.Load().(float64)

	if score < threshold {
		// Legitimate traffic: pass through
		rp.passedThrough.Add(1)
		rp.proxyPass(w, r, score)
		if rp.opts.EnableLogging {
			log.Printf("[proxy] PASS  %s %s score=%.1f client=%s",
				r.Method, r.URL.Path, score, cs.id[:16])
		}
		return
	}

	// Suspicious traffic: intercept
	rp.intercepted.Add(1)
	if rp.opts.EnableLogging {
		log.Printf("[proxy] INTERCEPT %s %s score=%.1f mode=%s client=%s",
			r.Method, r.URL.Path, score, rp.opts.InterceptMode, cs.id[:16])
	}

	rp.intercept(w, r, cs, score)
}

// director rewrites the request to point at the backend target.
func (rp *ReverseProxy) director(req *http.Request) {
	req.URL.Scheme = rp.target.Scheme
	req.URL.Host = rp.target.Host
	req.Host = rp.target.Host

	// Preserve the original path
	if rp.target.Path != "" && rp.target.Path != "/" {
		req.URL.Path = singleJoiningSlash(rp.target.Path, req.URL.Path)
	}
}

// proxyPass forwards the request to the backend with appropriate headers.
func (rp *ReverseProxy) proxyPass(w http.ResponseWriter, r *http.Request, score float64) {
	// Add forwarding headers
	clientIP := extractIP(r)
	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		clientIP = prior + ", " + clientIP
	}
	r.Header.Set("X-Forwarded-For", clientIP)
	r.Header.Set("X-Real-IP", extractIP(r))
	r.Header.Set("X-Glitch-Score", fmt.Sprintf("%.1f", score))

	// Check for websocket upgrade
	if isWebSocketUpgrade(r) {
		rp.reverseProxy.ServeHTTP(w, r)
		return
	}

	rp.reverseProxy.ServeHTTP(w, r)
}

// intercept handles a request that scored above the threshold.
func (rp *ReverseProxy) intercept(w http.ResponseWriter, r *http.Request, cs *clientState, score float64) {
	switch rp.opts.InterceptMode {
	case "block":
		rp.blocked.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Glitch-Score", fmt.Sprintf("%.1f", score))
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"Forbidden","message":"Access denied","score":%.1f}`, score)

	case "challenge":
		rp.challenged.Add(1)
		rp.serveChallenge(w, r, cs, score)

	case "labyrinth":
		rp.labyrinthTrapped.Add(1)
		rp.lab.Serve(w, r)

	case "glitch":
		// Full glitch treatment: randomly pick between errors, labyrinth, and page generation
		rp.applyGlitchTreatment(w, r, score)

	default:
		// Unknown mode, block
		rp.blocked.Add(1)
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// serveChallenge serves a JavaScript challenge page. If the client has already
// solved it (proven by returning a valid cookie), pass through instead.
func (rp *ReverseProxy) serveChallenge(w http.ResponseWriter, r *http.Request, cs *clientState, score float64) {
	// Check if the client has already passed the challenge
	cookie, err := r.Cookie(challengeCookieName)
	if err == nil && cookie.Value != "" {
		// Validate the cookie: it should be a hash of the client fingerprint
		expected := rp.challengeToken(cs.id)
		if cookie.Value == expected {
			// Challenge passed, forward to backend
			rp.passedThrough.Add(1)
			rp.proxyPass(w, r, score)
			return
		}
	}

	// Serve the JS challenge page
	token := rp.challengeToken(cs.id)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Glitch-Score", fmt.Sprintf("%.1f", score))
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Verifying your browser</title></head>
<body>
<h1>Checking your browser...</h1>
<p>Please wait while we verify you are not a bot.</p>
<noscript><p>JavaScript is required to continue.</p></noscript>
<script>
(function(){
  var t = "%s";
  document.cookie = "%s=" + t + "; path=/; max-age=1800; SameSite=Lax";
  setTimeout(function(){ window.location.reload(); }, 1500);
})();
</script>
</body>
</html>`, token, challengeCookieName)
}

// applyGlitchTreatment applies the full glitch server experience to a request.
// When mirror settings are active, it uses the server's error weights and
// parameters instead of the default profiles.
func (rp *ReverseProxy) applyGlitchTreatment(w http.ResponseWriter, r *http.Request, score float64) {
	w.Header().Set("X-Glitch-Score", fmt.Sprintf("%.1f", score))

	ms := rp.GetMirrorSettings()

	// If mirror mode is active, apply server-mirrored delay
	if ms != nil && ms.DelayMaxMs > 0 {
		h := sha256.Sum256([]byte(fmt.Sprintf("delay-%s-%d", r.URL.Path, time.Now().UnixNano())))
		delayRoll := float64(h[1]) / 255.0
		delayRange := ms.DelayMaxMs - ms.DelayMinMs
		if delayRange > 0 {
			delay := ms.DelayMinMs + int(delayRoll*float64(delayRange))
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	// Higher scores get more aggressive treatment
	aggressiveness := (score - rp.scoreThreshold.Load().(float64)) / 50.0
	if aggressiveness > 1.0 {
		aggressiveness = 1.0
	}
	if aggressiveness < 0.1 {
		aggressiveness = 0.1
	}

	// In mirror mode, scale aggressiveness by the error rate multiplier
	if ms != nil && ms.ErrorRateMultiplier > 0 {
		aggressiveness *= ms.ErrorRateMultiplier
		if aggressiveness > 1.0 {
			aggressiveness = 1.0
		}
	}

	// 30% chance of labyrinth
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", r.URL.Path, time.Now().UnixNano())))
	roll := float64(h[0]) / 255.0

	if roll < 0.3*aggressiveness {
		rp.labyrinthTrapped.Add(1)
		rp.lab.Serve(w, r)
		return
	}

	// 40% chance of error injection
	if roll < 0.7*aggressiveness {
		var profile errors.ErrorProfile
		if ms != nil && len(ms.ErrorWeights) > 0 {
			// Use mirrored server error weights
			weights := make(map[errors.ErrorType]float64, len(ms.ErrorWeights))
			for k, v := range ms.ErrorWeights {
				weights[errors.ErrorType(k)] = v
			}
			profile = errors.ErrorProfile{Weights: weights}
		} else if aggressiveness > 0.5 {
			profile = errors.AggressiveProfile()
		} else {
			profile = errors.DefaultProfile()
		}
		// Force an error (skip ErrNone)
		for i := 0; i < 10; i++ {
			errType := rp.errGen.Pick(profile)
			if errType != errors.ErrNone {
				rp.errGen.Apply(w, r, errType)
				return
			}
		}
		// Fallback: serve a 500
		http.Error(w, `{"error":"Internal Server Error"}`, http.StatusInternalServerError)
		return
	}

	// Otherwise serve a fake page
	rp.pageGen.Generate(w, r, rp.pageGen.PickType())
}

// getOrCreateClient returns the clientState for a request, creating one if needed.
func (rp *ReverseProxy) getOrCreateClient(r *http.Request) *clientState {
	id := rp.fingerprintRequest(r)
	now := time.Now()

	if val, ok := rp.clients.Load(id); ok {
		cs := val.(*clientState)
		cs.mu.Lock()
		cs.lastSeen = now
		cs.totalRequests++
		cs.requestTimes = append(cs.requestTimes, now)
		// Keep only last 200 timestamps
		if len(cs.requestTimes) > 200 {
			cs.requestTimes = cs.requestTimes[len(cs.requestTimes)-200:]
		}
		cs.mu.Unlock()
		return cs
	}

	cs := &clientState{
		id:           id,
		firstSeen:    now,
		lastSeen:     now,
		requestTimes: []time.Time{now},
		totalRequests: 1,
	}
	actual, _ := rp.clients.LoadOrStore(id, cs)
	return actual.(*clientState)
}

// fingerprintRequest produces a stable client ID from request characteristics.
func (rp *ReverseProxy) fingerprintRequest(r *http.Request) string {
	var parts []string
	parts = append(parts, "ua:"+r.UserAgent())
	parts = append(parts, "ip:"+extractIP(r))
	parts = append(parts, "al:"+r.Header.Get("Accept-Language"))
	parts = append(parts, "ae:"+r.Header.Get("Accept-Encoding"))
	parts = append(parts, "conn:"+r.Header.Get("Connection"))

	sig := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(sig))
	return fmt.Sprintf("proxy_%x", hash[:8])
}

// scoreClient computes a bot suspicion score (0-100) for the client.
func (rp *ReverseProxy) scoreClient(cs *clientState, r *http.Request) float64 {
	var score float64
	ua := strings.ToLower(r.UserAgent())

	// 1. Known bot User-Agent patterns (high signal)
	for _, pattern := range botPatterns {
		if strings.Contains(ua, pattern) {
			score += 40
			break
		}
	}

	// 2. Empty User-Agent
	if ua == "" {
		score += 25
	}

	// 3. Missing Accept-Language header (browsers always send this)
	if r.Header.Get("Accept-Language") == "" {
		score += 15
	}

	// 4. Missing Accept-Encoding header
	if r.Header.Get("Accept-Encoding") == "" {
		score += 10
	}

	// 5. Sec-Fetch headers consistency
	// Real browsers send Sec-Fetch-* headers; their absence with a browser-like UA is suspicious
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	secFetchMode := r.Header.Get("Sec-Fetch-Mode")
	hasBrowserUA := strings.Contains(ua, "mozilla") || strings.Contains(ua, "chrome") || strings.Contains(ua, "safari")
	if hasBrowserUA && secFetchSite == "" && secFetchMode == "" {
		score += 10
	}

	// 6. Rate limiting: >30 req/s from same client
	cs.mu.Lock()
	rps := rp.calculateRPS(cs)
	cookieSet := cs.cookieSet
	cookieReturned := cs.cookieReturned
	totalReqs := cs.totalRequests
	cs.mu.Unlock()

	if rps > 30 {
		score += 20
	} else if rps > 10 {
		score += 10
	} else if rps > 5 {
		score += 5
	}

	// 7. Cookie compliance: we set a tracking cookie, check if it was returned
	_, hasCookie := lookupCookie(r, challengeCookieName)
	if cookieSet && !cookieReturned && !hasCookie && totalReqs > 3 {
		// Client ignores cookies -- suspicious
		score += 15
	}
	if hasCookie {
		cs.mu.Lock()
		cs.cookieReturned = true
		cs.mu.Unlock()
		// Reduce score for cookie compliance
		score -= 10
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// calculateRPS computes requests per second over the last 10 seconds.
// Must be called with cs.mu held.
func (rp *ReverseProxy) calculateRPS(cs *clientState) float64 {
	now := time.Now()
	cutoff := now.Add(-10 * time.Second)
	count := 0
	for i := len(cs.requestTimes) - 1; i >= 0; i-- {
		if cs.requestTimes[i].Before(cutoff) {
			break
		}
		count++
	}
	return float64(count) / 10.0
}

// challengeToken generates a deterministic token for a client ID.
func (rp *ReverseProxy) challengeToken(clientID string) string {
	h := sha256.Sum256([]byte("glitch-challenge-" + clientID))
	return fmt.Sprintf("%x", h[:16])
}

// cleanupLoop periodically removes expired client state (inactive > 30 minutes).
func (rp *ReverseProxy) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-30 * time.Minute)
			rp.clients.Range(func(key, value interface{}) bool {
				cs := value.(*clientState)
				cs.mu.Lock()
				expired := cs.lastSeen.Before(cutoff)
				cs.mu.Unlock()
				if expired {
					rp.clients.Delete(key)
				}
				return true
			})
		case <-rp.stopCleanup:
			return
		}
	}
}

// extractIP extracts the client IP from the request.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// lookupCookie looks for a cookie by name, returning its value and whether it was found.
func lookupCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	return c.Value, true
}

// singleJoiningSlash joins two URL path segments with exactly one slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// DashboardHandler returns an HTTP handler for the proxy dashboard.
func (rp *ReverseProxy) DashboardHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", rp.dashboardPage)
	mux.HandleFunc("/api/stats", rp.apiStats)
	mux.HandleFunc("/api/clients", rp.apiClients)
	return mux
}

func (rp *ReverseProxy) dashboardPage(w http.ResponseWriter, r *http.Request) {
	stats := rp.Stats()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Glitch Proxy Dashboard</title>
<style>
body { font-family: monospace; background: #0a0a0a; color: #00ff88; padding: 20px; }
h1 { color: #00ffcc; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }
.card { background: #111; border: 1px solid #00ff8844; border-radius: 8px; padding: 15px; }
.label { color: #888; font-size: 0.8em; text-transform: uppercase; }
.value { font-size: 1.6em; font-weight: bold; margin-top: 5px; }
</style></head><body>
<h1>// GLITCH PROXY DASHBOARD</h1>
<p>Target: %s | Mode: %s | Threshold: %.0f</p>
<div class="grid">
<div class="card"><div class="label">Total</div><div class="value">%d</div></div>
<div class="card"><div class="label">Passed</div><div class="value">%d</div></div>
<div class="card"><div class="label">Intercepted</div><div class="value">%d</div></div>
<div class="card"><div class="label">Blocked</div><div class="value">%d</div></div>
<div class="card"><div class="label">Challenged</div><div class="value">%d</div></div>
<div class="card"><div class="label">Labyrinth</div><div class="value">%d</div></div>
</div>
<script>setTimeout(function(){location.reload()},5000);</script>
</body></html>`,
		rp.target.String(), rp.opts.InterceptMode, rp.scoreThreshold.Load().(float64),
		stats.TotalRequests, stats.PassedThrough, stats.Intercepted,
		stats.Blocked, stats.Challenged, stats.LabyrinthTrapped)
}

func (rp *ReverseProxy) apiStats(w http.ResponseWriter, r *http.Request) {
	stats := rp.Stats()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprintf(w, `{"total_requests":%d,"passed_through":%d,"intercepted":%d,"challenged":%d,"blocked":%d,"labyrinth_trapped":%d,"target":%q,"mode":%q,"threshold":%.1f}`,
		stats.TotalRequests, stats.PassedThrough, stats.Intercepted,
		stats.Challenged, stats.Blocked, stats.LabyrinthTrapped,
		rp.target.String(), rp.opts.InterceptMode, rp.scoreThreshold.Load().(float64))
}

func (rp *ReverseProxy) apiClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	type clientInfo struct {
		ID       string  `json:"id"`
		Score    float64 `json:"score"`
		Requests int64   `json:"requests"`
		RPS      float64 `json:"rps"`
		LastSeen string  `json:"last_seen"`
	}

	var clients []clientInfo
	rp.clients.Range(func(key, value interface{}) bool {
		cs := value.(*clientState)
		cs.mu.Lock()
		ci := clientInfo{
			ID:       cs.id,
			Score:    cs.score,
			Requests: cs.totalRequests,
			RPS:      rp.calculateRPS(cs),
			LastSeen: cs.lastSeen.Format(time.RFC3339),
		}
		cs.mu.Unlock()
		clients = append(clients, ci)
		return true
	})

	// Manual JSON encoding to avoid encoding/json import dependency for the struct
	// (though we use it — stdlib only is fine)
	fmt.Fprint(w, `{"clients":[`)
	for i, c := range clients {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `{"id":%q,"score":%.1f,"requests":%d,"rps":%.1f,"last_seen":%q}`,
			c.ID, c.Score, c.Requests, c.RPS, c.LastSeen)
	}
	fmt.Fprintf(w, `],"count":%d}`, len(clients))
}

// StartDashboard starts the dashboard server in a separate goroutine.
// Returns the http.Server for shutdown coordination.
func (rp *ReverseProxy) StartDashboard(port int) *http.Server {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: rp.DashboardHandler(),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[proxy-dashboard] error: %v", err)
		}
	}()
	return srv
}

// ShutdownDashboard gracefully shuts down the dashboard server.
func ShutdownDashboard(srv *http.Server, ctx context.Context) {
	if srv != nil {
		srv.Shutdown(ctx)
	}
}
