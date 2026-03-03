package mediachaos

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ChaosCategory identifies a media chaos behavior category.
type ChaosCategory string

const (
	// FormatCorruption corrupts the raw bytes of the media payload.
	FormatCorruption ChaosCategory = "format_corruption"

	// ContentLengthChaos sends incorrect Content-Length values.
	ContentLengthChaos ChaosCategory = "content_length_chaos"

	// ContentTypeChaos sends an incorrect or missing Content-Type.
	ContentTypeChaos ChaosCategory = "content_type_chaos"

	// RangeRequestChaos responds incorrectly to Range requests.
	RangeRequestChaos ChaosCategory = "range_request_chaos"

	// ChunkedChaos uses malformed chunked transfer encoding.
	ChunkedChaos ChaosCategory = "chunked_chaos"

	// SlowDelivery delivers the media content very slowly.
	SlowDelivery ChaosCategory = "slow_delivery"

	// InfiniteContent appends garbage after the valid media data.
	InfiniteContent ChaosCategory = "infinite_content"

	// StreamSwitching switches format mid-stream.
	StreamSwitching ChaosCategory = "stream_switching"

	// CachePoisoning adds conflicting cache-related headers.
	CachePoisoning ChaosCategory = "cache_poisoning"

	// StreamingChaos corrupts HLS/DASH playlist responses.
	StreamingChaos ChaosCategory = "streaming_chaos"
)

// allCategories defines canonical ordering for consistent selection.
var allCategories = []ChaosCategory{
	FormatCorruption,
	ContentLengthChaos,
	ContentTypeChaos,
	RangeRequestChaos,
	ChunkedChaos,
	SlowDelivery,
	InfiniteContent,
	StreamSwitching,
	CachePoisoning,
	StreamingChaos,
}

// Engine applies media-level chaos to HTTP responses carrying media content.
// It is safe for concurrent use from multiple goroutines.
type Engine struct {
	mu                  sync.RWMutex
	probability         float64
	categories          map[ChaosCategory]bool
	corruptionIntensity float64 // 0.0–1.0
	slowMinMs           int
	slowMaxMs           int
	infiniteMaxBytes    int64
}

// New creates an Engine with all categories enabled, default probability 0.3,
// corruption intensity 0.5, slow delivery range 10–1000 ms, and infinite max 100 MB.
func New() *Engine {
	cats := make(map[ChaosCategory]bool, len(allCategories))
	for _, c := range allCategories {
		cats[c] = true
	}
	return &Engine{
		probability:         0.3,
		categories:          cats,
		corruptionIntensity: 0.5,
		slowMinMs:           10,
		slowMaxMs:           1000,
		infiniteMaxBytes:    100 * 1024 * 1024, // 100 MB
	}
}

// SetProbability sets the probability (0.0–1.0) that chaos is applied on each request.
// Values outside [0,1] are clamped.
func (e *Engine) SetProbability(p float64) {
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	e.mu.Lock()
	e.probability = p
	e.mu.Unlock()
}

// GetProbability returns the current chaos probability.
func (e *Engine) GetProbability() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.probability
}

// SetCategoryEnabled enables or disables a specific chaos category.
func (e *Engine) SetCategoryEnabled(cat ChaosCategory, enabled bool) {
	e.mu.Lock()
	e.categories[cat] = enabled
	e.mu.Unlock()
}

// IsCategoryEnabled reports whether a category is currently enabled.
func (e *Engine) IsCategoryEnabled(cat ChaosCategory) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.categories[cat]
}

// Categories returns a snapshot copy of the category enable/disable map.
func (e *Engine) Categories() map[ChaosCategory]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[ChaosCategory]bool, len(e.categories))
	for k, v := range e.categories {
		out[k] = v
	}
	return out
}

// ShouldApply returns true if chaos should be applied this request.
func (e *Engine) ShouldApply() bool {
	e.mu.RLock()
	p := e.probability
	e.mu.RUnlock()
	return rand.Float64() < p
}

// SetCorruptionIntensity sets the corruption intensity (0.0–1.0).
// Values outside [0,1] are clamped.
func (e *Engine) SetCorruptionIntensity(v float64) {
	if v < 0 {
		v = 0
	}
	if v > 1 {
		v = 1
	}
	e.mu.Lock()
	e.corruptionIntensity = v
	e.mu.Unlock()
}

// GetCorruptionIntensity returns the current corruption intensity.
func (e *Engine) GetCorruptionIntensity() float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.corruptionIntensity
}

// SetSlowMinMs sets the minimum delay in milliseconds for slow delivery.
func (e *Engine) SetSlowMinMs(v int) {
	e.mu.Lock()
	e.slowMinMs = v
	e.mu.Unlock()
}

// SetSlowMaxMs sets the maximum delay in milliseconds for slow delivery.
func (e *Engine) SetSlowMaxMs(v int) {
	e.mu.Lock()
	e.slowMaxMs = v
	e.mu.Unlock()
}

// SetInfiniteMaxBytes sets the maximum number of extra bytes appended in InfiniteContent mode.
func (e *Engine) SetInfiniteMaxBytes(v int64) {
	e.mu.Lock()
	e.infiniteMaxBytes = v
	e.mu.Unlock()
}

// Snapshot returns a serializable config snapshot for export/import.
func (e *Engine) Snapshot() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cats := make(map[string]bool, len(e.categories))
	for k, v := range e.categories {
		cats[string(k)] = v
	}
	return map[string]interface{}{
		"probability":          e.probability,
		"categories":           cats,
		"corruptionIntensity":  e.corruptionIntensity,
		"slowMinMs":            e.slowMinMs,
		"slowMaxMs":            e.slowMaxMs,
		"infiniteMaxBytes":     e.infiniteMaxBytes,
	}
}

// Restore loads config from a snapshot produced by Snapshot().
// Unknown keys are ignored. Partial snapshots are applied incrementally.
func (e *Engine) Restore(cfg map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := cfg["probability"].(float64); ok {
		if p < 0 {
			p = 0
		}
		if p > 1 {
			p = 1
		}
		e.probability = p
	}
	if raw, ok := cfg["categories"]; ok {
		switch cats := raw.(type) {
		case map[string]bool:
			for k, v := range cats {
				e.categories[ChaosCategory(k)] = v
			}
		case map[string]interface{}:
			for k, v := range cats {
				if enabled, ok := v.(bool); ok {
					e.categories[ChaosCategory(k)] = enabled
				}
			}
		}
	}
	if v, ok := cfg["corruptionIntensity"].(float64); ok {
		if v < 0 {
			v = 0
		}
		if v > 1 {
			v = 1
		}
		e.corruptionIntensity = v
	}
	if v, ok := cfg["slowMinMs"].(float64); ok {
		e.slowMinMs = int(v)
	}
	if v, ok := cfg["slowMaxMs"].(float64); ok {
		e.slowMaxMs = int(v)
	}
	if v, ok := cfg["infiniteMaxBytes"].(float64); ok {
		e.infiniteMaxBytes = int64(v)
	}
}

// Apply applies chaos to the given media content and writes the response.
// mediaData is the original media payload; contentType is its MIME type.
// A random enabled category is selected and its handler is invoked.
func (e *Engine) Apply(w http.ResponseWriter, r *http.Request, mediaData []byte, contentType string) {
	e.mu.RLock()
	var enabled []ChaosCategory
	for _, c := range allCategories {
		if e.categories[c] {
			enabled = append(enabled, c)
		}
	}
	intensity := e.corruptionIntensity
	slowMin := e.slowMinMs
	slowMax := e.slowMaxMs
	infiniteMax := e.infiniteMaxBytes
	e.mu.RUnlock()

	if len(enabled) == 0 {
		// No categories enabled — serve content normally.
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(mediaData)
		return
	}

	cat := enabled[rand.Intn(len(enabled))]
	switch cat {
	case FormatCorruption:
		e.applyFormatCorruption(w, r, mediaData, contentType, intensity)
	case ContentLengthChaos:
		e.applyContentLengthChaos(w, r, mediaData, contentType)
	case ContentTypeChaos:
		e.applyContentTypeChaos(w, r, mediaData, contentType)
	case RangeRequestChaos:
		e.applyRangeRequestChaos(w, r, mediaData, contentType)
	case ChunkedChaos:
		e.applyChunkedChaos(w, r, mediaData, contentType)
	case SlowDelivery:
		e.applySlowDelivery(w, r, mediaData, contentType, slowMin, slowMax)
	case InfiniteContent:
		e.applyInfiniteContent(w, r, mediaData, contentType, infiniteMax)
	case StreamSwitching:
		e.applyStreamSwitching(w, r, mediaData, contentType)
	case CachePoisoning:
		e.applyCachePoisoning(w, r, mediaData, contentType)
	case StreamingChaos:
		e.applyStreamingChaos(w, r, mediaData, contentType)
	}
}

// --- Category implementations ---

// applyFormatCorruption corrupts the raw bytes of the media payload.
// The corruption strategy is selected based on the content type and the engine's intensity.
func (e *Engine) applyFormatCorruption(w http.ResponseWriter, r *http.Request, data []byte, contentType string, intensity float64) {
	rng := rand.New(rand.NewSource(rand.Int63()))
	var corrupted []byte
	switch {
	// Image formats
	case strings.Contains(contentType, "image/png"):
		corrupted = corruptPNG(data, intensity, rng)
	case strings.Contains(contentType, "image/jpeg") || strings.Contains(contentType, "image/jpg"):
		corrupted = corruptJPEG(data, intensity, rng)
	case strings.Contains(contentType, "image/gif"):
		corrupted = corruptGIF(data, intensity, rng)
	case strings.Contains(contentType, "image/webp"):
		corrupted = corruptWebP(data, intensity, rng)
	case strings.Contains(contentType, "image/bmp") || strings.Contains(contentType, "image/x-bmp"):
		corrupted = corruptBMP(data, intensity, rng)
	case strings.Contains(contentType, "image/svg+xml"):
		corrupted = corruptSVG(data, intensity, rng)
	case strings.Contains(contentType, "image/x-icon") || strings.Contains(contentType, "image/vnd.microsoft.icon"):
		corrupted = corruptICO(data, intensity, rng)
	case strings.Contains(contentType, "image/tiff"):
		corrupted = corruptTIFF(data, intensity, rng)

	// Audio formats
	case strings.Contains(contentType, "audio/wav") || strings.Contains(contentType, "audio/x-wav"):
		corrupted = corruptWAV(data, intensity, rng)
	case strings.Contains(contentType, "audio/mpeg") || strings.Contains(contentType, "audio/mp3"):
		corrupted = corruptMP3(data, intensity, rng)
	case strings.Contains(contentType, "audio/ogg"):
		corrupted = corruptOGG(data, intensity, rng)
	case strings.Contains(contentType, "audio/flac"):
		corrupted = corruptFLAC(data, intensity, rng)

	// Video formats
	case strings.Contains(contentType, "video/mp4"):
		corrupted = corruptMP4(data, intensity, rng)
	case strings.Contains(contentType, "video/webm"):
		corrupted = corruptWebM(data, intensity, rng)
	case strings.Contains(contentType, "video/x-msvideo") || strings.Contains(contentType, "video/avi"):
		corrupted = corruptAVI(data, intensity, rng)
	case strings.Contains(contentType, "video/mp2t"):
		corrupted = corruptTS(data, intensity, rng)

	// Container formats that may use content-type detection by extension
	case strings.HasSuffix(r.URL.Path, ".webp"):
		corrupted = corruptWebP(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".bmp"):
		corrupted = corruptBMP(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".svg"):
		corrupted = corruptSVG(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".ico"):
		corrupted = corruptICO(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".tif") || strings.HasSuffix(r.URL.Path, ".tiff"):
		corrupted = corruptTIFF(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".mp3"):
		corrupted = corruptMP3(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".ogg") || strings.HasSuffix(r.URL.Path, ".oga"):
		corrupted = corruptOGG(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".flac"):
		corrupted = corruptFLAC(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".mp4") || strings.HasSuffix(r.URL.Path, ".m4v") || strings.HasSuffix(r.URL.Path, ".m4a"):
		corrupted = corruptMP4(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".webm"):
		corrupted = corruptWebM(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".avi"):
		corrupted = corruptAVI(data, intensity, rng)
	case strings.HasSuffix(r.URL.Path, ".ts"):
		corrupted = corruptTS(data, intensity, rng)

	default:
		corrupted = corruptGeneric(data, intensity, rng)
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(corrupted)
}

// applyContentLengthChaos sends an incorrect Content-Length header.
// Variants: too large, too small, zero, negative, duplicate.
func (e *Engine) applyContentLengthChaos(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	variant := rand.Intn(5)
	w.Header().Set("Content-Type", contentType)
	switch variant {
	case 0:
		// Content-Length larger than body — client waits for more data.
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)+99999))
	case 1:
		// Content-Length smaller than body — client truncates.
		cl := len(data) / 2
		if cl < 1 {
			cl = 1
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", cl))
	case 2:
		// Content-Length: 0 but body is present.
		w.Header().Set("Content-Length", "0")
	case 3:
		// Content-Length: -1 (invalid).
		w.Header().Set("Content-Length", "-1")
	case 4:
		// Multiple Content-Length headers with conflicting values.
		w.Header().Add("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Add("Content-Length", fmt.Sprintf("%d", len(data)+1))
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// applyContentTypeChaos sends an incorrect or missing Content-Type header.
// Variants: wrong type, empty, invalid, duplicate, none, conflicting charset.
func (e *Engine) applyContentTypeChaos(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	variant := rand.Intn(6)
	switch variant {
	case 0:
		// Serve with a wrong Content-Type (cross-media swap).
		wrong := wrongContentType(contentType)
		w.Header().Set("Content-Type", wrong)
	case 1:
		// Empty Content-Type.
		w.Header().Set("Content-Type", "")
	case 2:
		// Invalid Content-Type value.
		w.Header().Set("Content-Type", "not-a-type")
	case 3:
		// Duplicate Content-Type headers with different values.
		wrong := wrongContentType(contentType)
		w.Header().Add("Content-Type", contentType)
		w.Header().Add("Content-Type", wrong)
	case 4:
		// No Content-Type at all — force MIME sniffing.
		// Do not set Content-Type.
	case 5:
		// Content-Type with conflicting charset (binary media + text charset).
		w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// applyRangeRequestChaos misbehaves in response to a Range header.
// If the request has no Range header this falls back to a normal response.
// Variants: ignore range / 200, wrong Content-Range total, 206 with less data,
// 206 without Content-Range, multipart without boundary.
func (e *Engine) applyRangeRequestChaos(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	rangeHdr := r.Header.Get("Range")
	if rangeHdr == "" {
		// No Range header — serve normally.
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}
	variant := rand.Intn(5)
	switch variant {
	case 0:
		// Ignore range — serve full content with 200 instead of 206.
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(data)

	case 1:
		// 206 with a wrong total size in Content-Range.
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(data)-1, len(data)*2+999))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data)

	case 2:
		// 206 but deliver less data than the Content-Range claims.
		half := len(data) / 2
		if half < 1 {
			half = 1
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(data)-1, len(data)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data[:half]) // send only half

	case 3:
		// 206 without a Content-Range header.
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data)

	case 4:
		// Multipart byteranges without a boundary parameter.
		w.Header().Set("Content-Type", "multipart/byteranges")
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data)
	}
}

// applyChunkedChaos uses malformed chunked transfer encoding.
// If the ResponseWriter does not implement http.Hijacker, falls back to ContentLengthChaos.
func (e *Engine) applyChunkedChaos(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		e.applyContentLengthChaos(w, r, data, contentType)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		e.applyContentLengthChaos(w, r, data, contentType)
		return
	}
	defer conn.Close()

	variant := rand.Intn(4)
	switch variant {
	case 0:
		// Chunk size claims more bytes than the actual chunk data.
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Content-Type: " + contentType + "\r\n")
		buf.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		// Write first chunk with inflated size.
		realLen := len(data)
		fakeLen := realLen + 500
		buf.WriteString(fmt.Sprintf("%x\r\n", fakeLen))
		buf.Write(data)
		buf.WriteString("\r\n0\r\n\r\n")

	case 1:
		// Chunked encoding without the terminating 0\r\n\r\n.
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Content-Type: " + contentType + "\r\n")
		buf.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		buf.WriteString(fmt.Sprintf("%x\r\n", len(data)))
		buf.Write(data)
		buf.WriteString("\r\n")
		// Intentionally omit: 0\r\n\r\n

	case 2:
		// Invalid hex in the chunk size field.
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Content-Type: " + contentType + "\r\n")
		buf.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		buf.WriteString("ZZZZ\r\n") // invalid hex
		buf.Write(data)
		buf.WriteString("\r\n0\r\n\r\n")

	case 3:
		// Extra whitespace and tabs in chunk size lines.
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Content-Type: " + contentType + "\r\n")
		buf.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		buf.WriteString(fmt.Sprintf(" \t%x \t\r\n", len(data)))
		buf.Write(data)
		buf.WriteString("\r\n 0 \r\n\r\n")
	}
	buf.Flush()
}

// applySlowDelivery delivers the media content very slowly.
// Variants: byte-at-a-time, fast start then slow, random pauses, stall mid-stream.
func (e *Engine) applySlowDelivery(w http.ResponseWriter, r *http.Request, data []byte, contentType string, slowMin, slowMax int) {
	flusher, hasFlusher := w.(http.Flusher)
	variant := rand.Intn(4)
	delayRange := slowMax - slowMin
	if delayRange <= 0 {
		delayRange = 1
	}

	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)

	flush := func() {
		if hasFlusher {
			flusher.Flush()
		}
	}

	randomDelay := func() time.Duration {
		return time.Duration(slowMin+rand.Intn(delayRange)) * time.Millisecond
	}

	switch variant {
	case 0:
		// Byte at a time with random delays.
		for i := 0; i < len(data); i++ {
			w.Write(data[i : i+1])
			flush()
			time.Sleep(randomDelay())
		}

	case 1:
		// Fast start (first 10%), then very slow byte-by-byte.
		fastEnd := len(data) / 10
		if fastEnd < 1 {
			fastEnd = 1
		}
		w.Write(data[:fastEnd])
		flush()
		for i := fastEnd; i < len(data); i++ {
			w.Write(data[i : i+1])
			flush()
			time.Sleep(randomDelay())
		}

	case 2:
		// Send in ~10 chunks with random pauses between them.
		chunkSize := len(data) / 10
		if chunkSize < 1 {
			chunkSize = 1
		}
		for off := 0; off < len(data); off += chunkSize {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			w.Write(data[off:end])
			flush()
			time.Sleep(randomDelay())
		}

	case 3:
		// Write first half, then stall for a long time.
		half := len(data) / 2
		if half < 1 {
			half = 1
		}
		w.Write(data[:half])
		flush()
		stallMs := slowMax * 3
		if stallMs < 500 {
			stallMs = 500
		}
		time.Sleep(time.Duration(stallMs) * time.Millisecond)
		w.Write(data[half:])
	}
}

// applyInfiniteContent appends random garbage bytes after the valid media data,
// up to infiniteMaxBytes total extra bytes.
func (e *Engine) applyInfiniteContent(w http.ResponseWriter, r *http.Request, data []byte, contentType string, maxBytes int64) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	// Write the valid data first.
	w.Write(data)

	flusher, hasFlusher := w.(http.Flusher)

	// Stream garbage in 4 KB chunks up to maxBytes.
	const chunkSize = 4096
	var written int64
	chunk := make([]byte, chunkSize)
	for written < maxBytes {
		remaining := maxBytes - written
		size := int64(chunkSize)
		if remaining < size {
			size = remaining
		}
		rand.Read(chunk[:size])
		w.Write(chunk[:size])
		if hasFlusher {
			flusher.Flush()
		}
		written += size
	}
}

// applyStreamSwitching writes the first half of the media data then switches
// to a different format or injects HTML/script content mid-stream.
func (e *Engine) applyStreamSwitching(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	half := len(data) / 2
	if half < 1 {
		half = 1
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)

	// Write first half of original data.
	w.Write(data[:half])

	variant := rand.Intn(3)
	switch variant {
	case 0:
		// Switch to a different media format signature.
		switched := switchedFormatData(contentType)
		w.Write(switched)

	case 1:
		// Inject HTML mid-stream.
		w.Write([]byte(`<!DOCTYPE html><html><head><title>Error</title></head><body><h1>503 Service Unavailable</h1><p>The media stream was interrupted.</p></body></html>`))

	case 2:
		// Inject a script tag mid-stream (XSS-style injection).
		w.Write([]byte(`<script>console.error("stream interrupted")</script>`))
		// Then append the second half of the original data.
		w.Write(data[half:])
	}
}

// applyCachePoisoning writes the media body but with conflicting cache headers.
// Variants: stale ETag + Last-Modified, public+no-cache+no-store, Vary: *,
// Age > max-age, Expires past + max-age future.
func (e *Engine) applyCachePoisoning(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	variant := rand.Intn(5)
	w.Header().Set("Content-Type", contentType)
	switch variant {
	case 0:
		// ETag present but stale Last-Modified in the distant past.
		w.Header().Set("ETag", fmt.Sprintf(`"stale-%d"`, rand.Int63()))
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2000 00:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=3600")

	case 1:
		// Contradictory: public AND no-cache AND no-store simultaneously.
		w.Header().Add("Cache-Control", "public")
		w.Header().Add("Cache-Control", "no-cache")
		w.Header().Add("Cache-Control", "no-store")
		w.Header().Add("Cache-Control", "max-age=86400")

	case 2:
		// Vary: * makes every request uncacheable per RFC 7234.
		w.Header().Set("Vary", "*")
		w.Header().Set("Cache-Control", "public, max-age=3600")

	case 3:
		// Age greater than max-age — cached copy is already stale on delivery.
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Age", "99999")

	case 4:
		// Expires in the past combined with a future max-age — contradictory.
		w.Header().Set("Expires", "Thu, 01 Jan 1970 00:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=86400, public")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// applyStreamingChaos corrupts HLS or DASH playlist content.
// For other content types it falls back to format corruption.
func (e *Engine) applyStreamingChaos(w http.ResponseWriter, r *http.Request, data []byte, contentType string) {
	switch {
	case strings.Contains(contentType, "application/vnd.apple.mpegurl") ||
		strings.Contains(contentType, "application/x-mpegurl") ||
		strings.HasSuffix(r.URL.Path, ".m3u8"):
		// HLS playlist corruption.
		corrupted := corruptHLS(data)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(corrupted)

	case strings.Contains(contentType, "application/dash+xml") ||
		strings.HasSuffix(r.URL.Path, ".mpd"):
		// DASH manifest corruption.
		corrupted := corruptDASH(data)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(corrupted)

	default:
		// Not a recognized streaming format — fall back to format corruption.
		rng := rand.New(rand.NewSource(rand.Int63()))
		intensity := e.GetCorruptionIntensity()
		corrupted := corruptGeneric(data, intensity, rng)
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(corrupted)
	}
}

// --- Utility functions ---

// wrongContentType returns a MIME type that is incorrect for the given content type.
// Used by ContentTypeChaos to serve media with a mismatched Content-Type.
func wrongContentType(original string) string {
	swaps := map[string]string{
		"image/png":                      "video/mp4",
		"image/jpeg":                     "audio/mpeg",
		"image/gif":                      "application/pdf",
		"image/webp":                     "image/png",
		"audio/mpeg":                     "image/jpeg",
		"audio/wav":                      "video/webm",
		"audio/x-wav":                    "video/webm",
		"video/mp4":                      "image/png",
		"video/webm":                     "audio/ogg",
		"application/pdf":                "image/gif",
		"application/vnd.apple.mpegurl": "text/plain",
		"application/dash+xml":           "text/html",
	}
	for prefix, wrong := range swaps {
		if strings.HasPrefix(original, prefix) {
			return wrong
		}
	}
	// Generic fallback: serve as application/octet-stream.
	return "application/octet-stream"
}

// switchedFormatData returns a small byte slice that looks like the beginning of
// a different media format, used by StreamSwitching.
func switchedFormatData(originalContentType string) []byte {
	switch {
	case strings.Contains(originalContentType, "image/png"):
		// Return JPEG SOI marker followed by garbage.
		return []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}
	case strings.Contains(originalContentType, "image/jpeg"):
		// Return PNG magic bytes.
		return []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	case strings.Contains(originalContentType, "video/mp4"):
		// Return WebM EBML magic.
		return []byte{0x1A, 0x45, 0xDF, 0xA3}
	case strings.Contains(originalContentType, "audio/mpeg"):
		// Return WAV RIFF header fragment.
		return []byte("RIFF\x00\x00\x00\x00WAVE")
	default:
		// Return PDF magic bytes.
		return []byte("%PDF-1.7\n%corrupt")
	}
}
