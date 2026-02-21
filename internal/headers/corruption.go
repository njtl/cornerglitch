package headers

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// CorruptionLevel controls how aggressively headers are corrupted.
type CorruptionLevel string

const (
	LevelNone       CorruptionLevel = "none"
	LevelSubtle     CorruptionLevel = "subtle"
	LevelModerate   CorruptionLevel = "moderate"
	LevelAggressive CorruptionLevel = "aggressive"
	LevelChaos      CorruptionLevel = "chaos"
)

// Engine applies HTTP header corruption techniques to confuse web scrapers
// while keeping responses mostly functional for real browsers.
// The engine is stateless per request and safe for concurrent use.
type Engine struct{}

// NewEngine creates a new header corruption engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ShouldCorrupt returns true if headers should be corrupted for the given
// client class. Browsers are spared; everything else is fair game.
func (e *Engine) ShouldCorrupt(clientClass string) bool {
	switch clientClass {
	case "browser":
		return false
	case "search_bot":
		// Search bots get subtle corruption only (handled by level selection)
		return true
	case "ai_scraper", "script_bot", "load_tester", "api_tester", "unknown":
		return true
	default:
		return true
	}
}

// Apply applies header corruption techniques to the response based on the
// given corruption level. Techniques are selected deterministically using
// the clientID and request path for consistency across identical requests.
//
// This method must be called BEFORE the response body is written, except
// for hijack-based techniques which take over the connection.
func (e *Engine) Apply(w http.ResponseWriter, r *http.Request, clientID string, level CorruptionLevel) {
	if level == LevelNone {
		return
	}

	seed := e.deterministicSeed(clientID, r.URL.Path)

	switch level {
	case LevelSubtle:
		e.applySubtle(w, r, seed)
	case LevelModerate:
		e.applySubtle(w, r, seed)
		e.applyModerate(w, r, seed)
	case LevelAggressive:
		e.applySubtle(w, r, seed)
		e.applyModerate(w, r, seed)
		e.applyAggressive(w, r, seed)
	case LevelChaos:
		e.applySubtle(w, r, seed)
		e.applyModerate(w, r, seed)
		e.applyAggressive(w, r, seed)
		e.applyChaos(w, r, seed)
	}
}

// deterministicSeed produces a uint64 from clientID + path for repeatable
// pseudo-random decisions within a single request.
func (e *Engine) deterministicSeed(clientID, path string) uint64 {
	h := sha256.Sum256([]byte(clientID + "|" + path))
	return binary.BigEndian.Uint64(h[:8])
}

// nth returns the n-th derived value from a seed. This gives us multiple
// independent-looking pseudo-random values from one seed.
func nth(seed uint64, n int) uint64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", seed, n)))
	return binary.BigEndian.Uint64(h[:8])
}

// bit returns true roughly pct% of the time for the given seed slot.
func bit(seed uint64, slot int, pct float64) bool {
	v := nth(seed, slot)
	return float64(v%10000)/10000.0 < pct
}

// --------------------------------------------------------------------------
// Subtle techniques  (browsers unaffected)
// --------------------------------------------------------------------------

func (e *Engine) applySubtle(w http.ResponseWriter, r *http.Request, seed uint64) {
	// 1. Duplicate Set-Cookie: one legitimate session cookie, one trap cookie
	//    with Max-Age=0 and a future Expires. Browsers handle Max-Age taking
	//    precedence, but naive parsers may keep the trap cookie.
	if bit(seed, 10, 0.8) {
		sessionVal := fmt.Sprintf("sid=%x; Path=/; HttpOnly; SameSite=Lax", nth(seed, 11)%math.MaxUint32)
		trapExpires := time.Now().Add(365 * 24 * time.Hour).UTC().Format(http.TimeFormat)
		trapVal := fmt.Sprintf("_track=%x; Max-Age=0; Expires=%s; Path=/", nth(seed, 12)%math.MaxUint32, trapExpires)
		w.Header()["Set-Cookie"] = append(w.Header()["Set-Cookie"], sessionVal, trapVal)
	}

	// 2. Add misleading framework headers
	if bit(seed, 20, 0.7) {
		frameworks := []struct{ key, val string }{
			{"X-Powered-By", "PHP/8.2.12"},
			{"X-Powered-By", "ASP.NET"},
			{"X-AspNet-Version", "4.0.30319"},
			{"X-Powered-By", "Express"},
			{"Server", "Apache/2.4.58 (Ubuntu)"},
			{"X-Generator", "WordPress 6.4"},
			{"X-Drupal-Cache", "HIT"},
		}
		pick := frameworks[nth(seed, 21)%uint64(len(frameworks))]
		w.Header().Set(pick.key, pick.val)
	}

	// 3. Vary with many fields to break caching
	if bit(seed, 30, 0.6) {
		w.Header().Set("Vary", "Accept, Accept-Encoding, Accept-Language, User-Agent, Cookie, X-Forwarded-For, X-Requested-With, Origin, Referer")
	}

	// 4. X-Robots-Tag to discourage indexing
	if bit(seed, 40, 0.9) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
	}

	// 5. Content-Security-Policy that blocks connect-src (breaks injected JS)
	if bit(seed, 50, 0.5) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
	}
}

// --------------------------------------------------------------------------
// Moderate techniques  (some scrapers break)
// --------------------------------------------------------------------------

func (e *Engine) applyModerate(w http.ResponseWriter, r *http.Request, seed uint64) {
	// 1. Duplicate Content-Type headers: first=application/json, last=text/html.
	//    Browsers use the last value; Go's http client uses the first.
	if bit(seed, 100, 0.6) {
		w.Header()["Content-Type"] = []string{"application/json; charset=utf-8", "text/html; charset=utf-8"}
	}

	// 2. Duplicate Location headers on redirects: first is real, last is honeypot.
	//    Browsers follow the first Location; some scrapers follow the last.
	if bit(seed, 110, 0.5) {
		if r.URL.Path != "/honeypot-trap" {
			w.Header()["X-Redirect-Hint"] = []string{r.URL.Path, "/honeypot-trap?src=header-dup"}
		}
	}

	// 3. Long X-Trace headers to consume parser memory
	if bit(seed, 120, 0.5) {
		traceBase := fmt.Sprintf("trace-%x", nth(seed, 121))
		for i := 0; i < 20; i++ {
			key := fmt.Sprintf("X-Trace-%d", i)
			val := fmt.Sprintf("%s-%d-%s", traceBase, i, strings.Repeat("abcdef0123456789", 64))
			// Each value is ~1KB
			w.Header().Add(key, val[:1024])
		}
	}

	// 4. Conflicting Cache-Control directives
	if bit(seed, 130, 0.7) {
		w.Header()["Cache-Control"] = []string{
			"public, max-age=31536000, immutable",
			"no-cache, no-store, must-revalidate, max-age=0",
		}
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
	}

	// 5. ETag that changes every request (prevents conditional requests)
	if bit(seed, 140, 0.8) {
		etag := fmt.Sprintf(`W/"%x-%d"`, nth(seed, 141), time.Now().UnixNano())
		w.Header().Set("ETag", etag)
	}

	// 6. Cookie with wrong domain (browsers reject, scrapers may accept)
	if bit(seed, 150, 0.5) {
		trapCookie := fmt.Sprintf("_detect=%x; Domain=.different-domain.com; Path=/; Secure; HttpOnly", nth(seed, 151)%math.MaxUint32)
		w.Header().Add("Set-Cookie", trapCookie)
	}
}

// --------------------------------------------------------------------------
// Aggressive techniques  (most scrapers break)
// --------------------------------------------------------------------------

func (e *Engine) applyAggressive(w http.ResponseWriter, r *http.Request, seed uint64) {
	// 1. Content-Length mismatch: claim more bytes than will be sent.
	//    Scrapers that trust Content-Length will hang waiting for the rest.
	if bit(seed, 200, 0.5) {
		// Claim 10KB more than reality. The actual body writer doesn't know
		// about this header so the connection will appear truncated.
		w.Header().Set("Content-Length", fmt.Sprintf("%d", 10240+int(nth(seed, 201)%5120)))
	}

	// 2. Content-Encoding: gzip with non-gzipped body
	//    Crashes naive auto-decompressors.
	if bit(seed, 210, 0.4) {
		w.Header().Set("Content-Encoding", "gzip")
	}

	// 3. 50+ garbage padding headers to bloat response
	if bit(seed, 220, 0.5) {
		for i := 0; i < 55; i++ {
			key := fmt.Sprintf("X-Pad-%03d", i)
			val := strings.Repeat(fmt.Sprintf("%02x", (nth(seed, 220+i))%256), 128)
			w.Header().Set(key, val)
		}
	}

	// 4. Transfer-Encoding: chunked with chunk extensions.
	//    Chunk extensions are legal per RFC 7230 but many parsers choke on them.
	if bit(seed, 230, 0.3) {
		w.Header()["Transfer-Encoding"] = []string{"chunked"}
		// The actual chunked encoding with extensions is handled via Hijack
		// in applyChaos; here we just set the header to confuse parsers that
		// see both Content-Length and Transfer-Encoding.
	}

	// 5. Keep-Alive promise then plan for immediate close.
	//    Sets Connection: keep-alive but the server may close after response,
	//    breaking connection pools.
	if bit(seed, 240, 0.6) {
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Keep-Alive", "timeout=300, max=1000")
	}
}

// --------------------------------------------------------------------------
// Chaos techniques  (breaks almost everything)
// --------------------------------------------------------------------------

func (e *Engine) applyChaos(w http.ResponseWriter, r *http.Request, seed uint64) {
	// 1. Extra contradictory headers — always applied before any early-return
	//    techniques so they are present regardless of which chaos path fires.
	w.Header().Set("Content-Disposition", "attachment; filename=\"response.html\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header()["Www-Authenticate"] = []string{"Basic realm=\"fake\"", "Bearer realm=\"also-fake\""}
	w.Header().Set("Age", fmt.Sprintf("%d", nth(seed, 330)%999999))
	w.Header().Set("Warning", "299 - \"Chaos mode active\"")

	// 2. HTTP/1.0 response with chunked encoding (protocol violation).
	if bit(seed, 310, 0.5) {
		w.Header().Set("X-Protocol-Hint", "HTTP/1.0")
		w.Header()["Transfer-Encoding"] = []string{"chunked"}
		// Also add a contradicting Content-Length
		w.Header().Set("Content-Length", "42")
	}

	// 3. Attempt to send 1xx informational responses before the final response.
	//    This uses http.Hijacker to push raw status lines.
	if bit(seed, 300, 0.4) {
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				// Write a 100 Continue, then a 102 Processing, then the real
				// response with a mix of everything.
				buf.WriteString("HTTP/1.1 100 Continue\r\n\r\n")
				buf.WriteString("HTTP/1.1 102 Processing\r\n\r\n")
				// Now write a final response that mixes HTTP/1.0 with chunked
				buf.WriteString("HTTP/1.0 200 OK\r\n")
				buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
				buf.WriteString("Transfer-Encoding: chunked\r\n")
				// Add null bytes in a header value
				buf.WriteString("X-Chaos: before\x00after\r\n")
				buf.WriteString(fmt.Sprintf("X-Chaos-ID: %x\r\n", nth(seed, 301)))
				buf.WriteString("\r\n")
				// Write a chunked body with extensions
				body := "<html><body><h1>Chaos Response</h1><p>This response violates multiple HTTP specifications simultaneously.</p></body></html>"
				chunk := fmt.Sprintf("%x;ext=glitch;seed=%x\r\n%s\r\n", len(body), seed, body)
				buf.WriteString(chunk)
				buf.WriteString("0;final=true\r\n\r\n")
				buf.Flush()
				conn.Close()
				return
			}
		}
	}

	// 4. Drip-feed with interleaved garbage via Flusher
	if bit(seed, 320, 0.3) {
		if flusher, ok := w.(http.Flusher); ok {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Chaos-Drip", "true")
			w.WriteHeader(http.StatusOK)
			parts := []string{
				"<html>",
				"<head><title>",
				"Loading...",
				"</title></head>",
				"<body>",
				"<!-- " + strings.Repeat("padding ", 128) + " -->",
				"<h1>Content</h1>",
				"</body></html>",
			}
			for _, part := range parts {
				w.Write([]byte(part))
				flusher.Flush()
				// Tiny delay between flushes to mess with streaming parsers
				time.Sleep(time.Duration(nth(seed, 325)%50+10) * time.Millisecond)
			}
			return
		}
	}
}
