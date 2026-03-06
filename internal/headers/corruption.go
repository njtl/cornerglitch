package headers

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
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
type Engine struct {
	mu    sync.RWMutex
	level int // 0-4 (none/subtle/moderate/aggressive/chaos)
}

// NewEngine creates a new header corruption engine.
func NewEngine() *Engine {
	return &Engine{
		level: 1, // default subtle
	}
}

// SetCorruptionLevel sets the corruption level, clamped to [0, 4].
func (e *Engine) SetCorruptionLevel(level int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if level < 0 {
		level = 0
	}
	if level > 4 {
		level = 4
	}
	e.level = level
}

// GetCorruptionLevel returns the current corruption level as an int.
func (e *Engine) GetCorruptionLevel() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.level
}

// GetLevel returns the current corruption level as a CorruptionLevel constant.
func (e *Engine) GetLevel() CorruptionLevel {
	e.mu.RLock()
	defer e.mu.RUnlock()
	switch e.level {
	case 0:
		return LevelNone
	case 1:
		return LevelSubtle
	case 2:
		return LevelModerate
	case 3:
		return LevelAggressive
	case 4:
		return LevelChaos
	default:
		return LevelSubtle
	}
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
				// Null bytes in header values
				buf.WriteString("X-Chaos: before\x00after\r\n")
				// Emoji in header name (completely illegal but crashes parsers)
				buf.WriteString("X-\xF0\x9F\x94\xA5: fire\r\n")
				// Control chars in status line extension
				buf.WriteString("X-Escape: \x1b[31mRED\x1b[0m\r\n")
				// ANSI bell character (audible beep in terminals reading logs)
				buf.WriteString("X-Bell: \x07\x07\x07\r\n")
				// Zero-width joiners and spaces
				buf.WriteString("X-Zero: a\xe2\x80\x8b\xe2\x80\x8bb\r\n")
				// Bare CR without LF (confuses line-based parsers)
				buf.WriteString("X-BareCR: value1\rvalue2\r\n")
				// Header continuation (obs-fold) with tab
				buf.WriteString("X-Folded: start\r\n\tcontinued\r\n\t more\r\n")
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

	// 4. Emoji and Unicode in headers — crashes parsers that expect ASCII-only
	//    RFC 7230 restricts header values to visible ASCII + obs-text (0x80-0xFF).
	//    Emoji (multi-byte UTF-8 starting with 0xF0) and other Unicode in header
	//    names/values crashes many HTTP parsers.
	if bit(seed, 340, 0.6) {
		emojiHeaders := []struct{ key, val string }{
			// Emoji in header values
			{"Server", "Apache/2.4 \xF0\x9F\x94\xA5\xF0\x9F\x92\x80"}, // 🔥💀
			{"X-Powered-By", "Go \xF0\x9F\x90\xBF"},                     // 🐿
			{"X-Status", "\xF0\x9F\x9A\x80 Running"},                    // 🚀
			{"X-Mood", "\xF0\x9F\x98\x88\xF0\x9F\x91\xBB\xF0\x9F\x92\xA3"}, // 😈👻💣
			// CJK characters
			{"X-Lang", "\xe4\xb8\xad\xe6\x96\x87\xe6\xb5\x8b\xe8\xaf\x95"},
			// Arabic (RTL override can mess up log viewers)
			{"X-RTL", "\xd8\xa7\xd9\x84\xd8\xb9\xd8\xb1\xd8\xa8\xd9\x8a\xd8\xa9"},
			// Zero-width chars (invisible but break string comparison)
			{"X-Invisible", "normal\xe2\x80\x8b\xe2\x80\x8b\xe2\x80\x8btext"},
			// Combining diacritics (Zalgo-style)
			{"X-Zalgo", "h\xcc\xa8\xcc\xa9\xcc\xaee\xcc\xa8\xcc\xa9l\xcc\xa8\xcc\xa9p"},
		}
		picked := emojiHeaders[nth(seed, 341)%uint64(len(emojiHeaders))]
		w.Header().Set(picked.key, picked.val)
	}

	// 5. High bytes and control characters in headers
	if bit(seed, 350, 0.5) {
		// Control characters (0x01-0x1F, 0x7F) are illegal in header values
		controlVals := []string{
			"value\x01with\x02control\x03chars",
			"bell\x07tab\x0bvertical",
			"escape\x1b[31mred\x1b[0m", // ANSI escape — crashes log viewers
			"del\x7fchar",
			"backspace\x08\x08\x08overwrite",
			// Mix of high bytes (0x80-0xFF) — obs-text but many parsers reject
			"high\x80\x81\x82\xff\xfebytes",
			"latin1\xe9\xe8\xf1\xfc", // é è ñ ü in Latin-1 (not UTF-8)
		}
		val := controlVals[nth(seed, 351)%uint64(len(controlVals))]
		w.Header().Set("X-Data", val)
	}

	// 6. Wrong encoding indicators — Content-Type claims one charset, body is another
	if bit(seed, 360, 0.4) {
		wrongEncodings := []string{
			"text/html; charset=utf-32",
			"text/html; charset=iso-2022-jp",
			"text/html; charset=ebcdic-us",
			"text/html; charset=utf-7",
			"text/html; charset=windows-31j",
			"application/json; charset=utf-16le",
			"text/html; charset=\xF0\x9F\x92\xA9", // 💩 as charset name
		}
		w.Header().Set("Content-Type", wrongEncodings[nth(seed, 361)%uint64(len(wrongEncodings))])
	}

	// 7. Overlong UTF-8 sequences in headers (security bypass technique)
	//    Overlong encodings of '/' and '.' can bypass path validation
	if bit(seed, 370, 0.3) {
		// Overlong UTF-8 for ASCII chars — illegal but parsed by some
		w.Header().Set("X-Path", "/admin\xc0\xaf..%c0%af../../etc/passwd")
		w.Header().Set("X-Overlong", "A\xc1\x81B\xc0\xafC") // Overlong 'A', overlong '/'
	}

	// 8. CVE-inspired header attacks — patterns from real parser crashes
	if bit(seed, 380, 0.4) {
		cveHeaders := []struct{ key, val string }{
			// CVE-2019-9740 (Python urllib) — CRLF injection in URL
			{"Location", "http://evil.com\r\nInjected: yes"},
			// CVE-2020-8945 (gpgme) — double-free via large header
			{"X-Large", strings.Repeat("A", 65536)},
			// CVE-2023-44487 (HTTP/2 rapid reset) — via header hint
			{"X-HTTP2-Hint", "RST_STREAM"},
			// CVE-2021-22901 (curl) — TLS session reuse confusion
			{"Alt-Svc", `h2="evil.com:443"; ma=2592000; persist=1`},
			// Apache mod_proxy CVE-2021-40438 — SSRF via crafted URI
			{"X-Forwarded-Host", "evil.com:@internal:8080"},
			// Node.js HTTP request smuggling via Unicode
			{"Transfer-Encoding", "chunked\xc0\xae"},
			// Nginx CVE-2013-4547 — null byte in URI
			{"X-Original-URL", "/admin\x00.html"},
			// Header name with whitespace (RFC violation, crashes strict parsers)
			{"X Header", "space in name"},
			// Duplicate content-length (request smuggling classic)
			{"Content-Length", "0"},
			// Empty header name
			{"", "empty-name-value"},
		}
		picked := cveHeaders[nth(seed, 381)%uint64(len(cveHeaders))]
		if picked.key != "" {
			w.Header().Set(picked.key, picked.val)
		}
	}

	// 9. Drip-feed with interleaved garbage via Flusher
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
