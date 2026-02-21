package jstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Engine generates JavaScript-based traps that detect headless browsers,
// automation tools, and scrapers that execute JS. It produces inline detection
// scripts, invisible honeypot links, JS-rendered content, timing traps,
// canvas fingerprinting, and JS challenge pages.
type Engine struct {
	mu         sync.RWMutex
	challenges map[string]challengeRecord // clientID -> expected challenge answer
}

type challengeRecord struct {
	answer    string
	expiresAt time.Time
}

// NewEngine creates a new JS trap engine.
func NewEngine() *Engine {
	return &Engine{
		challenges: make(map[string]challengeRecord),
	}
}

// seedFromClient produces a deterministic int64 seed from a clientID using SHA-256.
func seedFromClient(clientID string) int64 {
	h := sha256.Sum256([]byte(clientID))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

// hashString returns a short hex hash of the input.
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// GenerateTraps returns <script> blocks with detection code for the given client.
// This includes automation detection, timing traps, and canvas fingerprinting.
func (e *Engine) GenerateTraps(clientID string) string {
	rng := rand.New(rand.NewSource(seedFromClient(clientID)))
	var sb strings.Builder

	// 1. Automation detection script
	sb.WriteString(e.automationDetectionScript(clientID))

	// 2. Timing trap
	sb.WriteString(e.timingTrapScript(clientID))

	// 3. Canvas fingerprinting
	sb.WriteString(e.canvasFingerprintScript(clientID, rng))

	return sb.String()
}

// automationDetectionScript generates the main headless/automation detection script.
func (e *Engine) automationDetectionScript(clientID string) string {
	beaconPath := "/api/beacon"
	return fmt.Sprintf(`<script>
(function(){
    var signals = {};
    signals.webdriver = navigator.webdriver;
    signals.plugins = navigator.plugins.length;
    signals.languages = navigator.languages ? navigator.languages.length : 0;
    signals.platform = navigator.platform;
    signals.hardwareConcurrency = navigator.hardwareConcurrency;
    signals.deviceMemory = navigator.deviceMemory;
    // Check for Playwright
    signals.playwright = !!window.__playwright_binding__;
    // Check for Puppeteer
    signals.puppeteer = !!window.__puppeteer_evaluation_script__;
    // Check CDP
    signals.cdp = !!window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    // Client hints
    signals.userAgentData = !!navigator.userAgentData;
    // Canvas fingerprint
    var c = document.createElement('canvas');
    var ctx = c.getContext('2d');
    ctx.fillStyle = '#f60';
    ctx.fillRect(125,1,62,20);
    ctx.fillStyle = '#069';
    ctx.font = '11pt Arial';
    ctx.fillText('GlitchTrap',2,15);
    signals.canvas = c.toDataURL().length;
    // WebGL renderer
    var gl = c.getContext('webgl');
    if(gl) {
        var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        signals.gpuVendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : '';
        signals.gpuRenderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : '';
    }
    // Screen vs viewport consistency
    signals.screenW = screen.width;
    signals.screenH = screen.height;
    signals.innerW = window.innerWidth;
    signals.innerH = window.innerHeight;
    // Viewport should never exceed screen
    signals.viewportExceedsScreen = (window.innerWidth > screen.width || window.innerHeight > screen.height);
    signals.clientID = %q;
    // Send to beacon endpoint
    var img = new Image();
    img.src = '%s?d=' + btoa(JSON.stringify(signals));
})();
</script>
`, clientID, beaconPath)
}

// timingTrapScript generates a script that measures time between page load
// and first interaction. Bots typically interact in <100ms or not at all.
func (e *Engine) timingTrapScript(clientID string) string {
	return fmt.Sprintf(`<script>
(function(){
    var loadTime = Date.now();
    var reported = false;
    function reportTiming(eventType) {
        if (reported) return;
        reported = true;
        var delta = Date.now() - loadTime;
        var img = new Image();
        img.src = '/api/beacon?d=' + btoa(JSON.stringify({
            type: 'timing',
            clientID: %q,
            event: eventType,
            deltaMs: delta,
            suspicious: delta < 100
        }));
    }
    document.addEventListener('mousemove', function(){ reportTiming('mousemove'); }, {once: true});
    document.addEventListener('click', function(){ reportTiming('click'); }, {once: true});
    document.addEventListener('keydown', function(){ reportTiming('keydown'); }, {once: true});
    document.addEventListener('scroll', function(){ reportTiming('scroll'); }, {once: true});
    // If no interaction within 30s, report that too
    setTimeout(function(){
        if (!reported) reportTiming('timeout');
    }, 30000);
})();
</script>
`, clientID)
}

// canvasFingerprintScript generates unique canvas content per client for
// tracking across sessions.
func (e *Engine) canvasFingerprintScript(clientID string, rng *rand.Rand) string {
	// Generate deterministic colors and text per client
	r1, g1, b1 := rng.Intn(256), rng.Intn(256), rng.Intn(256)
	r2, g2, b2 := rng.Intn(256), rng.Intn(256), rng.Intn(256)
	words := []string{"glitch", "trap", "web", "net", "signal", "probe", "echo", "pulse"}
	word := words[rng.Intn(len(words))]

	return fmt.Sprintf(`<script>
(function(){
    var c = document.createElement('canvas');
    c.width = 200; c.height = 50;
    var ctx = c.getContext('2d');
    ctx.fillStyle = 'rgb(%d,%d,%d)';
    ctx.fillRect(0,0,200,50);
    ctx.fillStyle = 'rgb(%d,%d,%d)';
    ctx.font = '18px Georgia';
    ctx.fillText('%s-%s',10,30);
    ctx.strokeStyle = 'rgba(100,200,50,0.7)';
    ctx.beginPath();
    ctx.arc(100,25,20,0,Math.PI*2);
    ctx.stroke();
    var fp = c.toDataURL();
    var img = new Image();
    img.src = '/api/beacon?d=' + btoa(JSON.stringify({
        type: 'canvas_fp',
        clientID: %q,
        hash: fp.length + '-' + fp.charCodeAt(100) + '-' + fp.charCodeAt(200)
    }));
})();
</script>
`, r1, g1, b1, r2, g2, b2, word, hashString(clientID)[:8], clientID)
}

// GenerateJSRenderedContent returns an HTML page where the actual content is
// loaded via JavaScript. The HTML shell contains only "Loading..." and a script
// that fills in the real content from a base64-encoded data attribute. Scrapers
// that do not execute JS see only the loading placeholder.
func (e *Engine) GenerateJSRenderedContent(clientID, path string) string {
	rng := rand.New(rand.NewSource(seedFromClient(clientID + path)))

	// Generate the actual content that will only be visible after JS runs
	title := generateTitle(rng)
	var paragraphs strings.Builder
	numParagraphs := rng.Intn(5) + 3
	for i := 0; i < numParagraphs; i++ {
		paragraphs.WriteString(fmt.Sprintf("<p>%s</p>", generateParagraph(rng)))
	}

	realContent := fmt.Sprintf(`<h1>%s</h1><div class="article-body">%s</div><footer><p>Published %s</p></footer>`,
		title, paragraphs.String(),
		time.Now().Add(-time.Duration(rng.Intn(365*24))*time.Hour).Format("January 2, 2006"))

	encodedContent := base64.StdEncoding.EncodeToString([]byte(realContent))

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Loading...</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
    .loading { text-align: center; padding: 40px; color: #666; }
    .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #333; border-radius: 50%%;
               width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
    @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div id="app" data-content="%s">
    <div class="loading">
      <div class="spinner"></div>
      <p>Loading...</p>
      <noscript><p>This page requires JavaScript to display content.</p></noscript>
    </div>
  </div>
  %s
  <script>
  (function(){
    var app = document.getElementById('app');
    var encoded = app.getAttribute('data-content');
    if (encoded) {
      try {
        app.innerHTML = atob(encoded);
        document.title = app.querySelector('h1') ? app.querySelector('h1').textContent : 'Article';
      } catch(e) {
        app.innerHTML = '<p>Content failed to load.</p>';
      }
    }
  })();
  </script>
</body>
</html>`, encodedContent, e.GenerateTraps(clientID))
}

// GenerateInvisibleLinks returns HTML with CSS-hidden links that only bots follow.
// The links point to honeypot paths in the labyrinth style that will flag the client
// when visited.
func (e *Engine) GenerateInvisibleLinks(clientID, path string) string {
	rng := rand.New(rand.NewSource(seedFromClient(clientID + path)))

	var sb strings.Builder

	// Generate 5 different styles of hidden links
	hiddenStyles := []struct {
		css   string
		class string
	}{
		{`display:none`, "dn"},
		{`visibility:hidden`, "vh"},
		{`position:absolute;left:-9999px`, "oa"},
		{`opacity:0;height:0;overflow:hidden`, "oh"},
		{`font-size:0;color:transparent`, "ft"},
	}

	for _, style := range hiddenStyles {
		trapHash := hashString(fmt.Sprintf("%s-%s-%d", clientID, style.class, rng.Int63()))
		linkPath := fmt.Sprintf("/articles/hidden-trap-%s", trapHash[:12])
		linkText := generateLinkText(rng)

		sb.WriteString(fmt.Sprintf(`<a href="%s" class="nav-%s" style="%s" tabindex="-1" aria-hidden="true">%s</a>
`, linkPath, style.class, style.css, linkText))
	}

	return sb.String()
}

// ShouldHandle returns true if the path matches JS-trap specific endpoints.
func (e *Engine) ShouldHandle(path string) bool {
	switch {
	case path == "/js/challenge":
		return true
	case path == "/api/beacon":
		return true
	default:
		return false
	}
}

// ServeHTTP handles JS trap endpoints and returns the HTTP status code.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	switch r.URL.Path {
	case "/js/challenge":
		return e.serveChallengePage(w, r)
	case "/api/beacon":
		return e.serveBeacon(w, r)
	default:
		http.NotFound(w, r)
		return http.StatusNotFound
	}
}

// serveChallengePage serves a page that requires JavaScript execution to proceed.
// It sets a cookie with a computed value that the server verifies on subsequent requests.
func (e *Engine) serveChallengePage(w http.ResponseWriter, r *http.Request) int {
	// Generate a unique challenge per client+time window
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		// Fallback: derive from request properties
		h := sha256.Sum256([]byte(r.RemoteAddr + r.UserAgent()))
		clientID = fmt.Sprintf("anon_%s", hex.EncodeToString(h[:8]))
	}

	challengeSeed := hashString(clientID + time.Now().Truncate(5*time.Minute).String())

	// The challenge: compute a specific value from the seed
	// The answer is SHA-256(seed + "glitch-verified") truncated to 16 hex chars
	answer := computeChallengeAnswer(challengeSeed)

	// Store the expected answer
	e.mu.Lock()
	e.challenges[clientID] = challengeRecord{
		answer:    answer,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
	e.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Check</title>
  <style>
    body { font-family: system-ui, sans-serif; display: flex; justify-content: center;
           align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
    .challenge-box { background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
    .spinner { border: 4px solid #e0e0e0; border-top: 4px solid #333; border-radius: 50%%;
               width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }
    @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
    .success { color: #2e7d32; }
    .error { color: #c62828; }
    noscript p { color: #c62828; font-weight: bold; }
  </style>
</head>
<body>
  <div class="challenge-box">
    <h2>Verifying your browser...</h2>
    <div class="spinner" id="spinner"></div>
    <p id="status">Please wait while we verify your browser.</p>
    <noscript><p>JavaScript is required to access this page.</p></noscript>
  </div>
  <script>
  (function(){
    var seed = %q;
    // Simulate a computational challenge
    function sha256hex(str) {
      var buf = new TextEncoder().encode(str);
      return crypto.subtle.digest('SHA-256', buf).then(function(hash) {
        return Array.from(new Uint8Array(hash)).map(function(b) {
          return b.toString(16).padStart(2, '0');
        }).join('');
      });
    }
    sha256hex(seed + 'glitch-verified').then(function(hash) {
      var answer = hash.substring(0, 16);
      // Set the verification cookie
      document.cookie = 'glitch_js_verified=' + answer + '; path=/; max-age=3600; SameSite=Strict';
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('status').className = 'success';
      document.getElementById('status').textContent = 'Verified! Redirecting...';
      // Redirect back to the original page after a short delay
      setTimeout(function() {
        var dest = new URLSearchParams(window.location.search).get('redirect') || '/';
        window.location.href = dest;
      }, 1000);
    }).catch(function() {
      // Fallback for browsers without crypto.subtle (non-HTTPS)
      var answer = simpleHash(seed + 'glitch-verified');
      document.cookie = 'glitch_js_verified=' + answer + '; path=/; max-age=3600; SameSite=Strict';
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('status').className = 'success';
      document.getElementById('status').textContent = 'Verified! Redirecting...';
      setTimeout(function() {
        var dest = new URLSearchParams(window.location.search).get('redirect') || '/';
        window.location.href = dest;
      }, 1000);
    });
    // Simple hash fallback for non-HTTPS contexts
    function simpleHash(str) {
      var hash = 0;
      for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + c;
        hash = hash & hash; // Convert to 32-bit integer
      }
      return Math.abs(hash).toString(16).padStart(16, '0').substring(0, 16);
    }
  })();
  </script>
</body>
</html>`, challengeSeed)

	w.Write([]byte(html))
	return http.StatusOK
}

// serveBeacon receives detection signals sent by the trap scripts.
// It accepts GET requests with a base64-encoded JSON payload in the 'd' parameter.
func (e *Engine) serveBeacon(w http.ResponseWriter, r *http.Request) int {
	// Accept the beacon data — in a real system we'd parse and store it
	// For now, return a 1x1 transparent GIF
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// 1x1 transparent GIF
	gif := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
		0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
		0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
		0x01, 0x00, 0x3b,
	}
	w.Write(gif)
	return http.StatusOK
}

// VerifyChallenge checks whether the request carries a valid JS challenge cookie.
// Returns true if the cookie is present and matches the expected answer.
func (e *Engine) VerifyChallenge(r *http.Request) bool {
	cookie, err := r.Cookie("glitch_js_verified")
	if err != nil || cookie.Value == "" {
		return false
	}

	// Derive clientID the same way the challenge page does
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		h := sha256.Sum256([]byte(r.RemoteAddr + r.UserAgent()))
		clientID = fmt.Sprintf("anon_%s", hex.EncodeToString(h[:8]))
	}

	e.mu.RLock()
	record, exists := e.challenges[clientID]
	e.mu.RUnlock()

	if !exists {
		// No stored challenge — the cookie might still be valid if it matches
		// the current time window's expected answer
		challengeSeed := hashString(clientID + time.Now().Truncate(5*time.Minute).String())
		expected := computeChallengeAnswer(challengeSeed)
		return cookie.Value == expected
	}

	// Check expiration
	if time.Now().After(record.expiresAt) {
		e.mu.Lock()
		delete(e.challenges, clientID)
		e.mu.Unlock()
		return false
	}

	return cookie.Value == record.answer
}

// computeChallengeAnswer computes the expected answer for a given challenge seed.
// This uses SHA-256(seed + "glitch-verified") truncated to 16 hex chars.
func computeChallengeAnswer(seed string) string {
	h := sha256.Sum256([]byte(seed + "glitch-verified"))
	return hex.EncodeToString(h[:])[:16]
}

// --- Content generation helpers ---

var titleAdjectives = []string{
	"Advanced", "Comprehensive", "Essential", "Practical", "Complete",
	"Definitive", "Modern", "Ultimate", "Expert", "Interactive",
}

var titleNouns = []string{
	"Systems", "Networks", "Protocols", "Algorithms", "Frameworks",
	"Architectures", "Databases", "Interfaces", "Pipelines", "Services",
}

var topics = []string{
	"machine learning", "distributed computing", "cloud infrastructure",
	"data engineering", "security operations", "microservices design",
	"API development", "performance tuning", "container orchestration",
}

func generateTitle(rng *rand.Rand) string {
	adj := titleAdjectives[rng.Intn(len(titleAdjectives))]
	noun := titleNouns[rng.Intn(len(titleNouns))]
	topic := topics[rng.Intn(len(topics))]
	patterns := []string{
		fmt.Sprintf("The %s Guide to %s", adj, noun),
		fmt.Sprintf("%s %s in %s", adj, noun, topic),
		fmt.Sprintf("Understanding %s for %s", noun, topic),
	}
	return patterns[rng.Intn(len(patterns))]
}

func generateParagraph(rng *rand.Rand) string {
	templates := []string{
		"When building %s %s, it is critical to understand the underlying principles of %s. Organizations that invest in proper tooling see significant improvements across all metrics.",
		"The evolution of %s has fundamentally changed how teams approach %s. Modern architectures leverage %s to achieve unprecedented reliability.",
		"Consider the trade-offs between %s and %s when designing your next system. A thoughtful approach to %s reduces complexity while maintaining performance.",
		"Industry leaders consistently recommend %s for mission-critical %s. Combined with %s, this methodology delivers measurable outcomes.",
	}
	t := templates[rng.Intn(len(templates))]
	result := t
	for strings.Contains(result, "%s") {
		choices := []string{
			titleAdjectives[rng.Intn(len(titleAdjectives))],
			titleNouns[rng.Intn(len(titleNouns))],
			topics[rng.Intn(len(topics))],
		}
		result = strings.Replace(result, "%s", strings.ToLower(choices[rng.Intn(len(choices))]), 1)
	}
	return result
}

func generateLinkText(rng *rand.Rand) string {
	adj := titleAdjectives[rng.Intn(len(titleAdjectives))]
	noun := titleNouns[rng.Intn(len(titleNouns))]
	return fmt.Sprintf("Learn about %s %s", adj, noun)
}
