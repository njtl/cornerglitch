package cdn

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CDN personality types
type cdnPersonality int

const (
	cdnCloudflare cdnPersonality = iota
	cdnCloudFront
	cdnAkamai
	cdnFastly
	cdnVarnish
)

const numPersonalities = 5

// cacheEntry tracks per-path, per-client cache state.
type cacheEntry struct {
	hits    int
	firstAt time.Time
}

// Engine emulates CDN behavior in responses, assigning per-client CDN personalities
// and tracking cache hit/miss state for realistic headers.
type Engine struct {
	mu    sync.RWMutex
	cache map[string]*cacheEntry // key: "clientID:path"
}

// NewEngine creates a new CDN emulation engine.
func NewEngine() *Engine {
	return &Engine{
		cache: make(map[string]*cacheEntry),
	}
}

// ShouldHandle returns true if the path looks like a static asset that a CDN would serve.
func (e *Engine) ShouldHandle(path string) bool {
	// Check prefix-based static paths
	staticPrefixes := []string{
		"/static/",
		"/assets/",
		"/cdn/",
		"/_next/",
		"/dist/",
		"/build/",
	}
	for _, prefix := range staticPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check for static file extensions under any path
	staticExts := []string{
		".js", ".css", ".woff", ".woff2", ".ttf", ".eot",
		".svg", ".png", ".jpg", ".gif", ".ico", ".map", ".json",
	}
	lower := strings.ToLower(path)
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			// Only match extension-based assets if they are under a static-like path
			for _, prefix := range staticPrefixes {
				if strings.HasPrefix(path, prefix) {
					return true
				}
			}
		}
	}

	return false
}

// ServeHTTP serves a fake static asset with full CDN headers. Returns the HTTP status code.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = "unknown"
	}

	// Compute deterministic ETag from path
	etag := computeETag(path)

	// Conditional request: If-None-Match
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm == etag || inm == `W/`+etag {
			e.ApplyHeaders(w, path, clientID)
			w.WriteHeader(http.StatusNotModified)
			return http.StatusNotModified
		}
	}

	// Generate the response body
	body := generateAssetBody(path)

	// Range request support
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		return e.serveRange(w, r, path, clientID, etag, body, rangeHeader)
	}

	// Apply CDN headers
	e.ApplyHeaders(w, path, clientID)
	setContentType(w, path)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return http.StatusOK
}

// serveRange handles HTTP Range requests and returns 206 Partial Content.
func (e *Engine) serveRange(w http.ResponseWriter, r *http.Request, path, clientID, etag string, body []byte, rangeHeader string) int {
	totalSize := len(body)

	// Parse a simple "bytes=start-end" range
	start, end, ok := parseRange(rangeHeader, totalSize)
	if !ok {
		e.ApplyHeaders(w, path, clientID)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return http.StatusRequestedRangeNotSatisfiable
	}

	partial := body[start : end+1]

	e.ApplyHeaders(w, path, clientID)
	setContentType(w, path)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(partial)))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
	w.WriteHeader(http.StatusPartialContent)
	w.Write(partial)
	return http.StatusPartialContent
}

// ApplyHeaders adds CDN personality headers and cache-related headers to any response.
func (e *Engine) ApplyHeaders(w http.ResponseWriter, path string, clientID string) {
	personality := selectPersonality(clientID)
	cacheStatus := e.getCacheStatus(clientID, path)

	// Common CDN headers
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Vary", "Accept-Encoding")

	etag := computeETag(path)
	if w.Header().Get("ETag") == "" {
		w.Header().Set("ETag", etag)
	}

	// Personality-specific headers
	switch personality {
	case cdnCloudflare:
		e.applyCloudflare(w, path, clientID, cacheStatus)
	case cdnCloudFront:
		e.applyCloudFront(w, path, clientID, cacheStatus)
	case cdnAkamai:
		e.applyAkamai(w, path, clientID, cacheStatus)
	case cdnFastly:
		e.applyFastly(w, path, clientID, cacheStatus)
	case cdnVarnish:
		e.applyVarnish(w, path, clientID, cacheStatus)
	}
}

// selectPersonality deterministically picks a CDN personality for a client using SHA-256.
func selectPersonality(clientID string) cdnPersonality {
	h := sha256.Sum256([]byte("cdn-personality:" + clientID))
	idx := binary.BigEndian.Uint32(h[:4]) % uint32(numPersonalities)
	return cdnPersonality(idx)
}

// getCacheStatus returns "HIT" or "MISS" and updates cache tracking.
func (e *Engine) getCacheStatus(clientID, path string) string {
	key := clientID + ":" + path

	e.mu.Lock()
	defer e.mu.Unlock()

	entry, exists := e.cache[key]
	if !exists {
		e.cache[key] = &cacheEntry{
			hits:    1,
			firstAt: time.Now(),
		}
		return "MISS"
	}

	entry.hits++
	return "HIT"
}

// getCacheEntry returns the current cache entry for read-only access (used for hit counts and age).
func (e *Engine) getCacheEntry(clientID, path string) *cacheEntry {
	key := clientID + ":" + path

	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.cache[key]
}

// --- CDN personality header generators ---

func (e *Engine) applyCloudflare(w http.ResponseWriter, path, clientID, cacheStatus string) {
	ray := deterministicHex(clientID+path+"cf-ray", 16)
	reqID := deterministicHex(clientID+path+"cf-req", 32)
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("CF-Ray", ray+"-IAD")
	w.Header().Set("CF-Cache-Status", cacheStatus)
	w.Header().Set("CF-Request-ID", reqID)
}

func (e *Engine) applyCloudFront(w http.ResponseWriter, path, clientID, cacheStatus string) {
	cfID := deterministicHex(clientID+path+"amz-cf-id", 24)
	status := "Miss from cloudfront"
	if cacheStatus == "HIT" {
		status = "Hit from cloudfront"
	}
	w.Header().Set("X-Cache", status)
	w.Header().Set("X-Amz-Cf-Id", cfID)
	w.Header().Set("X-Amz-Cf-Pop", "IAD50-C1")
	w.Header().Set("Via", "1.1 "+deterministicHex(clientID+"via", 13)+".cloudfront.net (CloudFront)")
}

func (e *Engine) applyAkamai(w http.ResponseWriter, path, clientID, cacheStatus string) {
	tcpStatus := "TCP_MISS"
	if cacheStatus == "HIT" {
		tcpStatus = "TCP_HIT"
	}
	cacheKey := "/L/" + deterministicHex(clientID+path+"akamai-key", 8) + "/" + path
	w.Header().Set("Server", "AkamaiGHost")
	w.Header().Set("X-Cache", tcpStatus)
	w.Header().Set("X-Cache-Key", cacheKey)
	w.Header().Set("X-Akamai-Transformed", "9 - 0 pmb=mRUM,3")
}

func (e *Engine) applyFastly(w http.ResponseWriter, path, clientID, cacheStatus string) {
	entry := e.getCacheEntry(clientID, path)
	hitCount := 0
	if entry != nil {
		hitCount = entry.hits
	}

	timerVal := fmt.Sprintf("S%d.%06d,VS0,VE%d",
		time.Now().Unix(),
		deterministicInt(clientID+path+"timer", 999999),
		deterministicInt(clientID+path+"ve", 50))
	digest := deterministicHex(clientID+path+"fastly-digest", 32)

	w.Header().Set("X-Cache", cacheStatus)
	w.Header().Set("X-Cache-Hits", strconv.Itoa(hitCount))
	w.Header().Set("X-Served-By", "cache-iad-kiad"+deterministicHex(clientID+"served", 6))
	w.Header().Set("X-Timer", timerVal)
	w.Header().Set("Fastly-Debug-Digest", digest)
}

func (e *Engine) applyVarnish(w http.ResponseWriter, path, clientID, cacheStatus string) {
	entry := e.getCacheEntry(clientID, path)
	age := 0
	if entry != nil && cacheStatus == "HIT" {
		age = int(time.Since(entry.firstAt).Seconds())
		if age < 1 {
			age = 1
		}
	}

	varnishID1 := deterministicInt(clientID+path+"varnish1", 999999) + 100000
	varnishID2 := deterministicInt(clientID+path+"varnish2", 999999) + 100000

	w.Header().Set("X-Varnish", fmt.Sprintf("%d %d", varnishID1, varnishID2))
	w.Header().Set("X-Cache", cacheStatus)
	w.Header().Set("Age", strconv.Itoa(age))
	w.Header().Set("Via", "1.1 varnish (Varnish/6.0)")
}

// --- Fake asset body generators ---

// generateAssetBody produces a deterministic fake asset body based on the path.
func generateAssetBody(path string) []byte {
	lower := strings.ToLower(path)

	switch {
	case strings.HasSuffix(lower, ".js"):
		return generateJS(path)
	case strings.HasSuffix(lower, ".css"):
		return generateCSS(path)
	case strings.HasSuffix(lower, ".woff"), strings.HasSuffix(lower, ".woff2"):
		return generateFont(path, "woff")
	case strings.HasSuffix(lower, ".ttf"):
		return generateFont(path, "ttf")
	case strings.HasSuffix(lower, ".eot"):
		return generateFont(path, "eot")
	case strings.HasSuffix(lower, ".png"):
		return generatePNG()
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return generateJPEG()
	case strings.HasSuffix(lower, ".gif"):
		return generateGIF()
	case strings.HasSuffix(lower, ".ico"):
		return generateICO()
	case strings.HasSuffix(lower, ".svg"):
		return generateSVG(path)
	case strings.HasSuffix(lower, ".map"):
		return generateSourceMap(path)
	case strings.HasSuffix(lower, ".json"):
		return generateJSONAsset(path)
	default:
		return generateDirectoryListing(path)
	}
}

// generateJS produces realistic-looking minified JavaScript (webpack boilerplate).
// Size: 5KB-50KB, deterministic per path.
func generateJS(path string) []byte {
	size := deterministicRange(path, 5*1024, 50*1024)
	rng := deterministicRng(path)

	var b strings.Builder
	b.Grow(size)

	// Webpack-style IIFE opening
	b.WriteString("!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}")
	b.WriteString("n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},")
	b.WriteString("n.r=function(e){\"undefined\"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:\"Module\"}),Object.defineProperty(e,\"__esModule\",{value:!0})},")
	b.WriteString("n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&\"object\"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);")
	b.WriteString("if(n.r(r),Object.defineProperty(r,\"default\",{enumerable:!0,value:e}),2&t&&\"string\"!=typeof e)for(var o in e)n.d(r,o,function(t){return e[t]}.bind(null,o));return r},")
	b.WriteString("n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,\"a\",t),t},")
	b.WriteString("n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p=\"/\";")

	// Variable names for reuse
	varNames := []string{"a", "b", "c", "d", "f", "g", "h", "i", "j", "k", "l", "m", "p", "q", "s", "u", "v", "w", "x", "y", "z"}
	funcNames := []string{
		"init", "render", "update", "destroy", "create", "mount", "patch",
		"diff", "schedule", "flush", "dispatch", "subscribe", "notify",
		"validate", "transform", "serialize", "parse", "emit", "resolve",
		"reject", "connect", "disconnect", "configure", "bootstrap",
	}
	propNames := []string{
		"props", "state", "context", "children", "key", "ref", "type",
		"value", "label", "id", "className", "style", "onClick", "onChange",
		"data", "config", "options", "handler", "callback", "listeners",
	}

	// Generate module chunks
	moduleID := 0
	for b.Len() < size {
		moduleID++
		// Module function
		v1 := varNames[rng.Intn(len(varNames))]
		v2 := varNames[rng.Intn(len(varNames))]
		fn := funcNames[rng.Intn(len(funcNames))]
		prop := propNames[rng.Intn(len(propNames))]

		b.WriteString(fmt.Sprintf("var %s%d=n(%d);", v1, moduleID, rng.Intn(500)))

		// Random code patterns
		switch rng.Intn(8) {
		case 0:
			b.WriteString(fmt.Sprintf("function %s%d(%s){return %s.%s||null}", fn, moduleID, v1, v2, prop))
		case 1:
			b.WriteString(fmt.Sprintf("%s%d.prototype.%s=function(){var %s=this.%s;return %s?%s.call(this):%s}",
				v1, moduleID, fn, v2, prop, v2, v2, "void 0"))
		case 2:
			b.WriteString(fmt.Sprintf("Object.defineProperty(%s%d,\"%s\",{get:function(){return this._%s},set:function(%s){this._%s=%s}})",
				v1, moduleID, prop, prop, v2, prop, v2))
		case 3:
			b.WriteString(fmt.Sprintf("var %s%d=[%d,%d,%d,%d,%d,%d,%d,%d]",
				v2, moduleID, rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256),
				rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)))
		case 4:
			b.WriteString(fmt.Sprintf("if(%s%d&&%s%d.%s){%s%d.%s(%s%d)}",
				v1, moduleID, v1, moduleID, prop, v1, moduleID, fn, v2, moduleID))
		case 5:
			b.WriteString(fmt.Sprintf("for(var %s%d=0;%s%d<%d;%s%d++){%s%d.push(%s%d[%s%d])}",
				v1, moduleID, v1, moduleID, rng.Intn(100)+1, v1, moduleID,
				v2, moduleID, v1, moduleID, v1, moduleID))
		case 6:
			b.WriteString(fmt.Sprintf("try{%s%d=%s%d.%s()}catch(%s){console.error(%s)}",
				v1, moduleID, v2, moduleID, fn, v1, v1))
		case 7:
			hash := deterministicHex(path+strconv.Itoa(moduleID), 8)
			b.WriteString(fmt.Sprintf("\"%s\"===typeof %s%d&&(%s%d=\"%s\")",
				"undefined", v1, moduleID, v1, moduleID, hash))
		}

		b.WriteByte(';')
	}

	// Closing IIFE
	b.WriteString("}([]);")

	// Add source map reference
	jsFile := path
	if idx := strings.LastIndex(jsFile, "/"); idx >= 0 {
		jsFile = jsFile[idx+1:]
	}
	b.WriteString(fmt.Sprintf("\n//# sourceMappingURL=%s.map", jsFile))

	result := b.String()
	if len(result) > size {
		result = result[:size]
	}
	return []byte(result)
}

// generateCSS produces realistic-looking minified CSS.
// Size: 2KB-20KB, deterministic per path.
func generateCSS(path string) []byte {
	size := deterministicRange(path, 2*1024, 20*1024)
	rng := deterministicRng(path)

	var b strings.Builder
	b.Grow(size)

	selectors := []string{
		".header", ".footer", ".nav", ".nav-link", ".sidebar", ".content",
		".container", ".wrapper", ".main", ".section", ".article", ".card",
		".btn", ".btn-primary", ".btn-secondary", ".form-group", ".input",
		".modal", ".dropdown", ".tooltip", ".alert", ".badge", ".table",
		".row", ".col", ".grid", ".flex", ".hero", ".banner", ".panel",
		".list-item", ".avatar", ".icon", ".spinner", ".progress", ".tab",
		".breadcrumb", ".pagination", ".menu", ".overlay", ".dialog",
	}
	pseudos := []string{"", ":hover", ":focus", ":active", "::before", "::after", ":first-child", ":last-child"}
	properties := [][]string{
		{"display", "flex", "block", "inline-block", "grid", "none", "inline-flex"},
		{"align-items", "center", "flex-start", "flex-end", "stretch", "baseline"},
		{"justify-content", "center", "space-between", "space-around", "flex-start", "flex-end"},
		{"color", "#333", "#666", "#999", "#000", "#fff", "#1a73e8", "#dc3545", "#28a745"},
		{"background-color", "#fff", "#f8f9fa", "#e9ecef", "#dee2e6", "#212529", "transparent"},
		{"font-size", "12px", "14px", "16px", "18px", "24px", "32px", "0.875rem", "1rem", "1.25rem"},
		{"padding", "0", "4px", "8px", "12px", "16px", "24px", "8px 16px", "12px 24px"},
		{"margin", "0", "4px", "8px", "16px", "24px", "0 auto", "8px 0"},
		{"border", "none", "1px solid #ddd", "1px solid #e0e0e0", "2px solid #1a73e8"},
		{"border-radius", "0", "2px", "4px", "8px", "50%", "9999px"},
		{"font-weight", "400", "500", "600", "700", "normal", "bold"},
		{"text-decoration", "none", "underline"},
		{"position", "relative", "absolute", "fixed", "sticky"},
		{"overflow", "hidden", "auto", "scroll", "visible"},
		{"transition", "all .2s ease", "color .15s", "opacity .3s", "transform .2s ease-in-out"},
		{"box-shadow", "none", "0 2px 4px rgba(0,0,0,.1)", "0 4px 6px rgba(0,0,0,.07)"},
		{"opacity", "0", "0.5", "0.7", "1"},
		{"cursor", "pointer", "default", "not-allowed"},
		{"width", "100%", "auto", "50%", "320px", "fit-content"},
		{"max-width", "1200px", "960px", "768px", "100%"},
		{"height", "auto", "100%", "48px", "64px", "100vh"},
		{"line-height", "1", "1.4", "1.5", "1.6", "1.75", "2"},
		{"z-index", "1", "10", "100", "999", "9999"},
		{"text-align", "left", "center", "right"},
		{"white-space", "nowrap", "normal", "pre-wrap"},
		{"text-overflow", "ellipsis"},
	}

	// CSS reset snippet
	b.WriteString("*,*::before,*::after{box-sizing:border-box}")
	b.WriteString("body{margin:0;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Oxygen-Sans,Ubuntu,Cantarell,sans-serif;-webkit-font-smoothing:antialiased}")

	for b.Len() < size {
		sel := selectors[rng.Intn(len(selectors))]
		pseudo := pseudos[rng.Intn(len(pseudos))]
		b.WriteString(sel + pseudo + "{")

		// 2-6 properties per rule
		numProps := rng.Intn(5) + 2
		for j := 0; j < numProps && b.Len() < size; j++ {
			propSet := properties[rng.Intn(len(properties))]
			prop := propSet[0]
			val := propSet[1+rng.Intn(len(propSet)-1)]
			b.WriteString(prop + ":" + val)
			if j < numProps-1 {
				b.WriteByte(';')
			}
		}
		b.WriteByte('}')

		// Occasionally insert a media query
		if rng.Intn(8) == 0 {
			breakpoints := []string{"768px", "992px", "1200px", "576px", "480px"}
			bp := breakpoints[rng.Intn(len(breakpoints))]
			innerSel := selectors[rng.Intn(len(selectors))]
			propSet := properties[rng.Intn(len(properties))]
			prop := propSet[0]
			val := propSet[1+rng.Intn(len(propSet)-1)]
			b.WriteString(fmt.Sprintf("@media(max-width:%s){%s{%s:%s}}", bp, innerSel, prop, val))
		}
	}

	// Source map reference
	cssFile := path
	if idx := strings.LastIndex(cssFile, "/"); idx >= 0 {
		cssFile = cssFile[idx+1:]
	}
	b.WriteString(fmt.Sprintf("\n/*# sourceMappingURL=%s.map */", cssFile))

	result := b.String()
	if len(result) > size {
		result = result[:size]
	}
	return []byte(result)
}

// generateFont produces deterministic random bytes that look like font data.
// Size: 20KB-100KB.
func generateFont(path, fontType string) []byte {
	size := deterministicRange(path, 20*1024, 100*1024)
	rng := deterministicRng(path)

	data := make([]byte, size)
	// Font file magic bytes
	switch fontType {
	case "woff":
		copy(data, []byte("wOFF"))
	case "woff2":
		copy(data, []byte("wOF2"))
	case "ttf":
		copy(data, []byte{0x00, 0x01, 0x00, 0x00})
	case "eot":
		// EOT starts with file size as little-endian uint32
		binary.LittleEndian.PutUint32(data[:4], uint32(size))
	}

	// Fill with deterministic random bytes after the header
	for i := 4; i < size; i += 4 {
		val := rng.Uint32()
		remaining := size - i
		if remaining >= 4 {
			binary.LittleEndian.PutUint32(data[i:i+4], val)
		} else {
			for j := 0; j < remaining; j++ {
				data[i+j] = byte(val >> (8 * j))
			}
		}
	}

	return data
}

// generatePNG returns a minimal valid 1x1 transparent PNG.
func generatePNG() []byte {
	// 1x1 transparent PNG
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, // RGBA, 8-bit
		0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, // IDAT chunk
		0x78, 0x9c, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe5,
		0x27, 0xde, 0xfc,
		0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, // IEND chunk
		0xae, 0x42, 0x60, 0x82,
	}
}

// generateJPEG returns a minimal valid 1x1 white JPEG.
func generateJPEG() []byte {
	// Minimal 1x1 white JPEG
	return []byte{
		0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01,
		0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43,
		0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
		0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12,
		0x13, 0x0f, 0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c, 0x1c, 0x20,
		0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29,
		0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32,
		0x3c, 0x2e, 0x33, 0x34, 0x32, 0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01,
		0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x1f, 0x00, 0x00,
		0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0xff, 0xc4, 0x00, 0xb5, 0x10, 0x00, 0x02, 0x01, 0x03,
		0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7d,
		0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
		0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08,
		0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72,
		0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45,
		0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75,
		0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
		0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3,
		0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
		0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
		0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
		0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4,
		0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01,
		0x00, 0x00, 0x3f, 0x00, 0x7b, 0x94, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd9,
	}
}

// generateGIF returns a minimal valid 1x1 transparent GIF89a.
func generateGIF() []byte {
	return []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, // GIF89a
		0x01, 0x00, 0x01, 0x00, // 1x1
		0x80, 0x00, 0x00, // GCT flag, 1 color
		0xff, 0xff, 0xff, // white
		0x00, 0x00, 0x00, // black (transparent)
		0x21, 0xf9, 0x04, // graphic control extension
		0x01, 0x00, 0x00, 0x00, 0x00, // transparent index 1
		0x2c, 0x00, 0x00, 0x00, 0x00, // image descriptor
		0x01, 0x00, 0x01, 0x00, 0x00, // 1x1, no local CT
		0x02, 0x02, 0x44, 0x01, 0x00, // LZW min code size 2, data
		0x3b, // trailer
	}
}

// generateICO returns a minimal valid .ico file (1x1 pixel).
func generateICO() []byte {
	// ICO header + single 1x1 32-bit BMP entry
	ico := []byte{
		0x00, 0x00, // reserved
		0x01, 0x00, // type: icon
		0x01, 0x00, // 1 image
		// Directory entry
		0x01,       // width 1
		0x01,       // height 1
		0x00,       // no palette
		0x00,       // reserved
		0x01, 0x00, // 1 color plane
		0x20, 0x00, // 32 bits per pixel
		0x28, 0x00, 0x00, 0x00, // size of image data (40 bytes BMP header + 4 pixel + 4 mask)
		0x16, 0x00, 0x00, 0x00, // offset to image data (22)
	}
	// BMP info header
	bmpHeader := []byte{
		0x28, 0x00, 0x00, 0x00, // header size (40)
		0x01, 0x00, 0x00, 0x00, // width 1
		0x02, 0x00, 0x00, 0x00, // height 2 (doubled for ICO)
		0x01, 0x00, // 1 plane
		0x20, 0x00, // 32 bpp
		0x00, 0x00, 0x00, 0x00, // no compression
		0x00, 0x00, 0x00, 0x00, // image size (can be 0)
		0x00, 0x00, 0x00, 0x00, // X ppm
		0x00, 0x00, 0x00, 0x00, // Y ppm
		0x00, 0x00, 0x00, 0x00, // colors used
		0x00, 0x00, 0x00, 0x00, // important colors
	}
	ico = append(ico, bmpHeader...)
	// Pixel data: 1 white pixel (BGRA) + 4 bytes AND mask
	ico = append(ico, 0xff, 0xff, 0xff, 0xff)
	ico = append(ico, 0x00, 0x00, 0x00, 0x00)
	return ico
}

// generateSVG produces a minimal SVG with deterministic content.
func generateSVG(path string) []byte {
	rng := deterministicRng(path)
	colors := []string{"#1a73e8", "#dc3545", "#28a745", "#ffc107", "#6f42c1", "#17a2b8", "#343a40"}
	color := colors[rng.Intn(len(colors))]
	size := 24 + rng.Intn(232) // 24-256

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">`+
		`<rect width="%d" height="%d" fill="%s" rx="%d"/>`+
		`</svg>`,
		size, size, size, size, size, size, color, rng.Intn(size/4+1))
	return []byte(svg)
}

// generateSourceMap produces a fake source map JSON.
func generateSourceMap(path string) []byte {
	// Strip .map from the path to get the "source" file
	source := strings.TrimSuffix(path, ".map")
	if idx := strings.LastIndex(source, "/"); idx >= 0 {
		source = source[idx+1:]
	}

	rng := deterministicRng(path)
	// Generate fake mappings (valid base64-VLQ-like characters)
	mappingChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/;,"
	var mappings strings.Builder
	mappingLen := 200 + rng.Intn(800)
	for i := 0; i < mappingLen; i++ {
		mappings.WriteByte(mappingChars[rng.Intn(len(mappingChars))])
	}

	sm := fmt.Sprintf(`{"version":3,"file":"%s","sourceRoot":"","sources":["webpack:///%s","webpack:///./src/index.js","webpack:///./src/App.js"],"names":["module","exports","require","__webpack_require__"],"mappings":"%s"}`,
		source, source, mappings.String())
	return []byte(sm)
}

// generateJSONAsset produces a fake JSON asset (manifest, config, etc.).
func generateJSONAsset(path string) []byte {
	lower := strings.ToLower(path)

	// Detect common JSON asset types
	if strings.Contains(lower, "manifest") {
		return []byte(`{"name":"Glitch App","short_name":"Glitch","start_url":"/","display":"standalone","background_color":"#ffffff","theme_color":"#1a73e8","icons":[{"src":"/static/icon-192.png","sizes":"192x192","type":"image/png"},{"src":"/static/icon-512.png","sizes":"512x512","type":"image/png"}]}`)
	}
	if strings.Contains(lower, "package") {
		return []byte(`{"name":"@glitch/frontend","version":"3.14.159","private":true,"dependencies":{"react":"^18.2.0","react-dom":"^18.2.0"},"scripts":{"start":"react-scripts start","build":"react-scripts build"}}`)
	}

	// Generic asset JSON
	rng := deterministicRng(path)
	hash := deterministicHex(path, 8)
	version := fmt.Sprintf("%d.%d.%d", rng.Intn(10), rng.Intn(20), rng.Intn(100))
	return []byte(fmt.Sprintf(`{"version":"%s","hash":"%s","generated":true,"chunks":["%s.js","%s.css"],"assets":{"main":"/static/main.%s.js","styles":"/static/main.%s.css"}}`,
		version, hash,
		deterministicHex(path+"chunk-js", 8),
		deterministicHex(path+"chunk-css", 8),
		deterministicHex(path+"asset-js", 8),
		deterministicHex(path+"asset-css", 8)))
}

// generateDirectoryListing produces an HTML page listing "CDN contents".
func generateDirectoryListing(path string) []byte {
	rng := deterministicRng(path)
	files := []string{
		"main.js", "vendor.js", "runtime.js", "polyfills.js",
		"styles.css", "vendor.css", "theme.css",
		"logo.svg", "favicon.ico", "manifest.json",
		"roboto-v30-latin-regular.woff2", "material-icons.woff2",
	}

	var b strings.Builder
	b.WriteString("<!DOCTYPE html><html><head><title>Index of " + path + "</title>")
	b.WriteString("<style>body{font-family:monospace;margin:2em}table{border-collapse:collapse}td,th{padding:4px 16px;text-align:left}tr:hover{background:#f5f5f5}a{color:#1a73e8;text-decoration:none}a:hover{text-decoration:underline}</style></head>")
	b.WriteString("<body><h1>Index of " + path + "</h1><hr><table><tr><th>Name</th><th>Size</th><th>Modified</th></tr>")
	b.WriteString("<tr><td><a href=\"../\">../</a></td><td>-</td><td>-</td></tr>")

	for _, f := range files {
		size := rng.Intn(500) + 1
		unit := "KB"
		if size > 200 {
			unit = "KB"
		}
		days := rng.Intn(90) + 1
		modified := time.Now().AddDate(0, 0, -days).Format("02-Jan-2006 15:04")
		b.WriteString(fmt.Sprintf("<tr><td><a href=\"%s/%s\">%s</a></td><td>%d%s</td><td>%s</td></tr>",
			strings.TrimSuffix(path, "/"), f, f, size, unit, modified))
	}

	b.WriteString("</table><hr><address>Glitch CDN Server</address></body></html>")
	return []byte(b.String())
}

// --- Content-Type helper ---

func setContentType(w http.ResponseWriter, path string) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(lower, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(lower, ".woff"):
		w.Header().Set("Content-Type", "font/woff")
	case strings.HasSuffix(lower, ".woff2"):
		w.Header().Set("Content-Type", "font/woff2")
	case strings.HasSuffix(lower, ".ttf"):
		w.Header().Set("Content-Type", "font/ttf")
	case strings.HasSuffix(lower, ".eot"):
		w.Header().Set("Content-Type", "application/vnd.ms-fontobject")
	case strings.HasSuffix(lower, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(lower, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		w.Header().Set("Content-Type", "image/jpeg")
	case strings.HasSuffix(lower, ".gif"):
		w.Header().Set("Content-Type", "image/gif")
	case strings.HasSuffix(lower, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	case strings.HasSuffix(lower, ".map"):
		w.Header().Set("Content-Type", "application/json")
	case strings.HasSuffix(lower, ".json"):
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
}

// --- Deterministic helpers ---

// computeETag generates a deterministic ETag from a path using SHA-256.
func computeETag(path string) string {
	h := sha256.Sum256([]byte("etag:" + path))
	return `"` + hex.EncodeToString(h[:16]) + `"`
}

// deterministicHex returns a deterministic hex string of the given length derived from a seed.
func deterministicHex(seed string, length int) string {
	h := sha256.Sum256([]byte(seed))
	hexStr := hex.EncodeToString(h[:])
	if length > len(hexStr) {
		length = len(hexStr)
	}
	return hexStr[:length]
}

// deterministicInt returns a deterministic int in [0, max) derived from a seed.
func deterministicInt(seed string, max int) int {
	h := sha256.Sum256([]byte(seed))
	val := binary.BigEndian.Uint32(h[:4])
	return int(val % uint32(max))
}

// deterministicRange returns a deterministic int in [min, max] derived from a path.
func deterministicRange(path string, min, max int) int {
	h := sha256.Sum256([]byte("size:" + path))
	val := binary.BigEndian.Uint32(h[:4])
	return min + int(val%uint32(max-min+1))
}

// deterministicRng returns a deterministic *rand.Rand seeded from a path.
func deterministicRng(path string) *rand.Rand {
	h := sha256.Sum256([]byte("rng:" + path))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

// parseRange parses a simple "bytes=start-end" Range header.
// Returns start, end (inclusive), and whether the parse succeeded.
func parseRange(rangeHeader string, totalSize int) (int, int, bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(rangeHeader, "bytes=")

	// Only handle a single range (not multi-range)
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}

	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}

	start := 0
	end := totalSize - 1

	if parts[0] != "" {
		s, err := strconv.Atoi(parts[0])
		if err != nil || s < 0 {
			return 0, 0, false
		}
		start = s
	} else {
		// Suffix range: "-N" means last N bytes
		if parts[1] == "" {
			return 0, 0, false
		}
		suffix, err := strconv.Atoi(parts[1])
		if err != nil || suffix <= 0 {
			return 0, 0, false
		}
		start = totalSize - suffix
		if start < 0 {
			start = 0
		}
		return start, end, true
	}

	if parts[1] != "" {
		e, err := strconv.Atoi(parts[1])
		if err != nil || e < start {
			return 0, 0, false
		}
		end = e
	}

	if start >= totalSize {
		return 0, 0, false
	}
	if end >= totalSize {
		end = totalSize - 1
	}

	return start, end, true
}
