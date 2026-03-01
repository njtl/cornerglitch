package errors

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrorType defines the kind of glitch to inject.
type ErrorType string

const (
	ErrNone              ErrorType = "none"
	Err500               ErrorType = "500_internal"
	Err502               ErrorType = "502_bad_gateway"
	Err503               ErrorType = "503_unavailable"
	Err504               ErrorType = "504_timeout"
	Err404               ErrorType = "404_not_found"
	Err403               ErrorType = "403_forbidden"
	Err429               ErrorType = "429_rate_limit"
	Err408               ErrorType = "408_timeout"
	ErrSlowDrip          ErrorType = "slow_drip"          // send bytes very slowly
	ErrConnectionReset   ErrorType = "connection_reset"    // close mid-response
	ErrPartialBody       ErrorType = "partial_body"        // truncated JSON/HTML
	ErrWrongContentType  ErrorType = "wrong_content_type"  // lie about content-type
	ErrGarbageBody       ErrorType = "garbage_body"        // random bytes
	ErrEmptyBody         ErrorType = "empty_body"          // 200 with no body
	ErrHugeHeaders       ErrorType = "huge_headers"        // bloated response headers
	ErrDelayed1s         ErrorType = "delay_1s"
	ErrDelayed3s         ErrorType = "delay_3s"
	ErrDelayed10s        ErrorType = "delay_10s"
	ErrDelayedRandom     ErrorType = "delay_random"
	ErrRedirectLoop      ErrorType = "redirect_loop"
	ErrDoubleEncoding    ErrorType = "double_encoding"     // double gzip
	ErrFlipFlop          ErrorType = "flip_flop"           // alternate 200/500
	ErrPacketDrop        ErrorType = "packet_drop"         // accept connection, hold 30-60s, never respond
	ErrTCPReset          ErrorType = "tcp_reset"           // hijack + SetLinger(0) to send RST
	ErrStreamCorrupt     ErrorType = "stream_corrupt"      // valid HTTP start, then random garbage bytes mid-stream
	ErrSessionTimeout    ErrorType = "session_timeout"     // respond at 1 byte/second
	ErrKeepaliveAbuse    ErrorType = "keepalive_abuse"     // send Connection: keep-alive timeout=999, hold forever
	ErrTLSHalfClose      ErrorType = "tls_half_close"      // partial response, CloseWrite(), hold read open
	ErrSlowHeaders       ErrorType = "slow_headers"        // send headers byte-by-byte with 200-500ms gaps
	ErrAcceptThenFIN     ErrorType = "accept_then_fin"     // hijack and immediately close

	// Protocol-level glitches — HTTP version violations
	ErrHTTP10Chunked     ErrorType = "http10_chunked"      // HTTP/1.0 with Transfer-Encoding: chunked
	ErrHTTP11NoLength    ErrorType = "http11_no_length"    // HTTP/1.1 with no Content-Length and no chunked
	ErrProtocolDowngrade ErrorType = "protocol_downgrade"  // send HTTP/1.0 response to HTTP/1.1 client
	ErrMixedVersions     ErrorType = "mixed_versions"      // send 100 Continue then HTTP/1.0 200
	ErrInfoNoFinal       ErrorType = "info_no_final"       // send 1xx responses then close without final

	// Protocol-level glitches — HTTP/2 mock violations
	ErrH2UpgradeReject   ErrorType = "h2_upgrade_reject"   // offer h2c upgrade but respond HTTP/1.1
	ErrFalseH2Preface    ErrorType = "false_h2_preface"    // send H2 preface bytes then HTTP/1.1 content
	ErrH2BadStreamID     ErrorType = "h2_bad_stream_id"    // invalid H2 stream ID headers
	ErrH2PriorityLoop    ErrorType = "h2_priority_loop"    // circular priority dependency header
	ErrFalseServerPush   ErrorType = "false_server_push"   // Link preload for nonexistent resources

	// Protocol-level glitches — header protocol violations
	ErrDuplicateStatus   ErrorType = "duplicate_status"    // write status line twice
	ErrHeaderNullBytes   ErrorType = "header_null_bytes"   // embed \x00 in header values
	ErrMissingCRLF       ErrorType = "missing_crlf"        // use LF-only instead of CRLF
	ErrHeaderObsFold     ErrorType = "header_obs_fold"     // obsolete header folding

	// Protocol-level glitches — content encoding violations
	ErrBothCLAndTE       ErrorType = "both_cl_and_te"      // set both Content-Length and Transfer-Encoding
	ErrFalseCompression  ErrorType = "false_compression"   // claim br but send uncompressed
	ErrMultiEncodings    ErrorType = "multi_encodings"     // conflicting Content-Encoding values

	// Protocol-level glitches — connection violations
	ErrKeepAliveUpgrade  ErrorType = "keepalive_upgrade"   // both Connection: keep-alive and Upgrade: websocket
)

// ErrorProfile defines probabilities for each error type.
type ErrorProfile struct {
	Weights map[ErrorType]float64
}

// DefaultProfile is the baseline error distribution.
func DefaultProfile() ErrorProfile {
	return ErrorProfile{
		Weights: map[ErrorType]float64{
			ErrNone:              0.594,
			Err500:               0.03,
			Err502:               0.02,
			Err503:               0.02,
			Err504:               0.01,
			Err404:               0.03,
			Err403:               0.01,
			Err429:               0.02,
			Err408:               0.01,
			ErrSlowDrip:          0.02,
			ErrConnectionReset:   0.01,
			ErrPartialBody:       0.02,
			ErrWrongContentType:  0.02,
			ErrGarbageBody:       0.01,
			ErrEmptyBody:         0.01,
			ErrHugeHeaders:       0.01,
			ErrDelayed1s:         0.03,
			ErrDelayed3s:         0.02,
			ErrDelayed10s:        0.01,
			ErrDelayedRandom:     0.01,
			ErrRedirectLoop:      0.01,
			ErrDoubleEncoding:    0.005,
			ErrFlipFlop:          0.005,
			ErrPacketDrop:        0.004,
			ErrTCPReset:          0.004,
			ErrStreamCorrupt:     0.004,
			ErrSessionTimeout:    0.004,
			ErrKeepaliveAbuse:    0.003,
			ErrTLSHalfClose:      0.003,
			ErrSlowHeaders:       0.004,
			ErrAcceptThenFIN:     0.004,
			// Protocol-level glitches
			ErrHTTP10Chunked:     0.002,
			ErrHTTP11NoLength:    0.002,
			ErrProtocolDowngrade: 0.002,
			ErrMixedVersions:    0.002,
			ErrInfoNoFinal:      0.002,
			ErrH2UpgradeReject:  0.002,
			ErrFalseH2Preface:   0.002,
			ErrH2BadStreamID:    0.002,
			ErrH2PriorityLoop:   0.002,
			ErrFalseServerPush:  0.002,
			ErrDuplicateStatus:  0.002,
			ErrHeaderNullBytes:  0.002,
			ErrMissingCRLF:      0.002,
			ErrHeaderObsFold:    0.002,
			ErrBothCLAndTE:      0.002,
			ErrFalseCompression: 0.002,
			ErrMultiEncodings:   0.002,
			ErrKeepAliveUpgrade: 0.002,
		},
	}
}

// AggressiveProfile ramps up error rates for identified bots/testers.
func AggressiveProfile() ErrorProfile {
	return ErrorProfile{
		Weights: map[ErrorType]float64{
			ErrNone:             0.056,
			Err500:              0.06,
			Err502:              0.05,
			Err503:              0.05,
			Err504:              0.03,
			Err404:              0.05,
			Err403:              0.03,
			Err429:              0.05,
			Err408:              0.03,
			ErrSlowDrip:         0.04,
			ErrConnectionReset:  0.03,
			ErrPartialBody:      0.04,
			ErrWrongContentType: 0.04,
			ErrGarbageBody:      0.03,
			ErrEmptyBody:        0.02,
			ErrHugeHeaders:      0.02,
			ErrDelayed1s:        0.04,
			ErrDelayed3s:        0.03,
			ErrDelayed10s:       0.02,
			ErrDelayedRandom:    0.02,
			ErrRedirectLoop:     0.02,
			ErrDoubleEncoding:   0.01,
			ErrFlipFlop:         0.01,
			ErrPacketDrop:       0.01,
			ErrTCPReset:         0.01,
			ErrStreamCorrupt:    0.01,
			ErrSessionTimeout:   0.01,
			ErrKeepaliveAbuse:   0.01,
			ErrTLSHalfClose:     0.01,
			ErrSlowHeaders:      0.01,
			ErrAcceptThenFIN:    0.01,
			// Protocol-level glitches
			ErrHTTP10Chunked:     0.008,
			ErrHTTP11NoLength:    0.008,
			ErrProtocolDowngrade: 0.008,
			ErrMixedVersions:    0.008,
			ErrInfoNoFinal:      0.008,
			ErrH2UpgradeReject:  0.008,
			ErrFalseH2Preface:   0.008,
			ErrH2BadStreamID:    0.008,
			ErrH2PriorityLoop:   0.008,
			ErrFalseServerPush:  0.008,
			ErrDuplicateStatus:  0.008,
			ErrHeaderNullBytes:  0.008,
			ErrMissingCRLF:      0.008,
			ErrHeaderObsFold:    0.008,
			ErrBothCLAndTE:      0.008,
			ErrFalseCompression: 0.008,
			ErrMultiEncodings:   0.008,
			ErrKeepAliveUpgrade: 0.008,
		},
	}
}

// Generator picks and applies error types.
type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

// Pick selects an error type using the given profile's weighted distribution.
func (g *Generator) Pick(profile ErrorProfile) ErrorType {
	r := rand.Float64()
	cumulative := 0.0
	for errType, weight := range profile.Weights {
		cumulative += weight
		if r < cumulative {
			return errType
		}
	}
	return ErrNone
}

// Apply writes the error response. Returns true if the response was fully handled.
// Returns false if the caller should write a normal response.
func (g *Generator) Apply(w http.ResponseWriter, r *http.Request, errType ErrorType) bool {
	switch errType {
	case ErrNone:
		return false

	case Err500:
		http.Error(w, `{"error":"Internal Server Error","code":500}`, http.StatusInternalServerError)
		return true

	case Err502:
		http.Error(w, `<html><body><h1>502 Bad Gateway</h1><p>The server received an invalid response.</p></body></html>`, http.StatusBadGateway)
		return true

	case Err503:
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rand.Intn(60)+5))
		http.Error(w, `{"error":"Service Unavailable","retry_after_seconds":30}`, http.StatusServiceUnavailable)
		return true

	case Err504:
		time.Sleep(time.Duration(rand.Intn(3)+1) * time.Second)
		http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
		return true

	case Err404:
		http.Error(w, `{"error":"Not Found","path":"`+r.URL.Path+`"}`, http.StatusNotFound)
		return true

	case Err403:
		http.Error(w, `{"error":"Forbidden","message":"Access denied"}`, http.StatusForbidden)
		return true

	case Err429:
		w.Header().Set("Retry-After", fmt.Sprintf("%d", rand.Intn(30)+1))
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
		http.Error(w, `{"error":"Too Many Requests","message":"Rate limit exceeded"}`, http.StatusTooManyRequests)
		return true

	case Err408:
		time.Sleep(5 * time.Second)
		http.Error(w, "Request Timeout", http.StatusRequestTimeout)
		return true

	case ErrSlowDrip:
		g.slowDrip(w)
		return true

	case ErrConnectionReset:
		// Hijack and close the connection abruptly
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
			}
		}
		return true

	case ErrPartialBody:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "500") // lie about length
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"this response is truncated and the JSON is incomple`))
		return true

	case ErrWrongContentType:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>This is actually HTML despite the content-type header</body></html>`))
		return true

	case ErrGarbageBody:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		garbage := make([]byte, rand.Intn(1024)+256)
		crand.Read(garbage)
		w.Write(garbage)
		return true

	case ErrEmptyBody:
		w.WriteHeader(http.StatusOK)
		return true

	case ErrHugeHeaders:
		for i := 0; i < 50; i++ {
			w.Header().Set(fmt.Sprintf("X-Glitch-Padding-%d", i), strings.Repeat("x", 512))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return true

	case ErrDelayed1s:
		time.Sleep(1 * time.Second)
		return false

	case ErrDelayed3s:
		time.Sleep(3 * time.Second)
		return false

	case ErrDelayed10s:
		time.Sleep(10 * time.Second)
		return false

	case ErrDelayedRandom:
		time.Sleep(time.Duration(rand.Intn(15)+1) * time.Second)
		return false

	case ErrRedirectLoop:
		target := fmt.Sprintf("/redirect-loop/%d?t=%d", rand.Intn(10), time.Now().UnixNano())
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return true

	case ErrDoubleEncoding:
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Write non-gzipped data with gzip header — decoders will choke
		w.Write([]byte("<html><body>This claims to be gzipped but isn't</body></html>"))
		return true

	case ErrFlipFlop:
		if time.Now().UnixNano()%2 == 0 {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}
		return true

	case ErrPacketDrop:
		// Accept connection, hold 30-60s, never respond
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				delay := time.Duration(rand.Intn(31)+30) * time.Second
				time.Sleep(delay)
				conn.Close()
			}
		}
		return true

	case ErrTCPReset:
		// Hijack + SetLinger(0) to send RST
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetLinger(0)
					tc.Close()
				} else {
					conn.Close()
				}
			}
		}
		return true

	case ErrStreamCorrupt:
		// Write valid HTTP start, then inject random garbage bytes
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>")
				buf.Flush()
				garbage := make([]byte, rand.Intn(512)+128)
				crand.Read(garbage)
				conn.Write(garbage)
				conn.Close()
			}
		}
		return true

	case ErrSessionTimeout:
		// Hijack, write response headers, then send body at 1 byte/second
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
				buf.Flush()
				msg := "This response is timing out slowly..."
				for i := 0; i < len(msg); i++ {
					conn.Write([]byte{msg[i]})
					time.Sleep(1 * time.Second)
				}
				conn.Close()
			}
		}
		return true

	case ErrKeepaliveAbuse:
		// Set keepalive headers, write 200 OK, then hijack and hold open
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				buf.WriteString("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=999\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK")
				buf.Flush()
				// Hold the connection open for a long time
				time.Sleep(time.Duration(rand.Intn(60)+60) * time.Second)
				conn.Close()
			}
		}
		return true

	case ErrTLSHalfClose:
		// Hijack, write partial response, CloseWrite(), hold read side open
		if hj, ok := w.(http.Hijacker); ok {
			conn, buf, err := hj.Hijack()
			if err == nil {
				buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 500\r\n\r\n<html><body>partial content...")
				buf.Flush()
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.CloseWrite()
					// Hold read side open
					time.Sleep(time.Duration(rand.Intn(30)+15) * time.Second)
					tc.Close()
				} else {
					conn.Close()
				}
			}
		}
		return true

	case ErrSlowHeaders:
		// Send HTTP headers byte-by-byte with 200-500ms gaps
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				header := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
				for i := 0; i < len(header); i++ {
					conn.Write([]byte{header[i]})
					time.Sleep(time.Duration(rand.Intn(301)+200) * time.Millisecond)
				}
				conn.Write([]byte("<html><body>Slow headers complete</body></html>"))
				conn.Close()
			}
		}
		return true

	case ErrAcceptThenFIN:
		// Hijack and immediately close — never writes anything
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close()
			}
		}
		return true

	// ---- Protocol-level glitches: HTTP Version ----

	case ErrHTTP10Chunked:
		// HTTP/1.0 response with Transfer-Encoding: chunked (illegal combo)
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
		buf.Flush()
		return true

	case ErrHTTP11NoLength:
		// HTTP/1.1 with no Content-Length and no chunked, just body then close
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>No content-length, no chunked encoding. Just data.</body></html>")
		buf.Flush()
		return true

	case ErrProtocolDowngrade:
		// Send HTTP/1.0 200 OK + Connection: close to HTTP/1.1 client
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 22\r\n\r\nProtocol downgrade OK.")
		buf.Flush()
		return true

	case ErrMixedVersions:
		// Send HTTP/1.1 100 Continue then HTTP/1.0 200 OK
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\nMixed hello.")
		buf.Flush()
		return true

	case ErrInfoNoFinal:
		// Send 100 Continue, 102 Processing, then close without final response
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n")
		buf.Flush()
		// Close without sending a final 2xx/3xx/4xx/5xx response
		return true

	// ---- Protocol-level glitches: HTTP/2 Mock ----

	case ErrH2UpgradeReject:
		// Offer h2c upgrade but respond with HTTP/1.1 normally
		w.Header().Set("Upgrade", "h2c")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Offered h2c upgrade but serving HTTP/1.1</body></html>"))
		return true

	case ErrFalseH2Preface:
		// Send HTTP/2 connection preface bytes followed by HTTP/1.1 content
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		// HTTP/2 client connection preface magic
		buf.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		// Then switch to HTTP/1.1 content
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 28\r\n\r\nFalse H2 preface, then H1.1.")
		buf.Flush()
		return true

	case ErrH2BadStreamID:
		// Add invalid H2 stream ID headers
		w.Header().Set("X-H2-Stream-ID", "-1")
		w.Header().Add("X-H2-Stream-ID", "0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Bad H2 stream IDs in headers</body></html>"))
		return true

	case ErrH2PriorityLoop:
		// Circular priority dependency
		w.Header().Set("X-H2-Priority", "parent=self")
		w.Header().Set("X-H2-Stream-Weight", "256")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Circular H2 priority dependency</body></html>"))
		return true

	case ErrFalseServerPush:
		// Link preload headers for nonexistent resources
		w.Header().Add("Link", "</fake-bundle.js>; rel=preload; as=script")
		w.Header().Add("Link", "</nonexistent.css>; rel=preload; as=style")
		w.Header().Add("Link", "</ghost-image.webp>; rel=preload; as=image")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head></head><body>False server push preload hints</body></html>"))
		return true

	// ---- Protocol-level glitches: Header Protocol ----

	case ErrDuplicateStatus:
		// Write the status line twice before headers
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\n\r\nDuplicate status.")
		buf.Flush()
		return true

	case ErrHeaderNullBytes:
		// Embed \x00 in header values
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Glitch: before\x00after\r\nX-Data: null\x00byte\x00header\r\nContent-Length: 20\r\n\r\nNull bytes in header.")
		buf.Flush()
		return true

	case ErrMissingCRLF:
		// Use LF-only instead of CRLF in headers
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: 15\n\n<html>LF only.</html>")
		buf.Flush()
		return true

	case ErrHeaderObsFold:
		// Obsolete header folding: continue header value on next line with space prefix
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return true
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return true
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Long-Header: start of value\r\n continued on next line\r\n and another continuation\r\nContent-Length: 22\r\n\r\nObs-fold header value.")
		buf.Flush()
		return true

	// ---- Protocol-level glitches: Content Encoding ----

	case ErrBothCLAndTE:
		// Set both Content-Length AND Transfer-Encoding: chunked (ambiguous per RFC 7230)
		w.Header().Set("Content-Length", "5")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
		return true

	case ErrFalseCompression:
		// Claim Content-Encoding: br but send uncompressed body
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Claims to be Brotli-compressed but is plain text</body></html>"))
		return true

	case ErrMultiEncodings:
		// Set conflicting Content-Encoding values
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Content-Encoding", "deflate")
		w.Header().Add("Content-Encoding", "identity")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Multiple conflicting encodings</body></html>"))
		return true

	// ---- Protocol-level glitches: Connection ----

	case ErrKeepAliveUpgrade:
		// Set both Connection: keep-alive and Upgrade: websocket (conflicting signals)
		w.Header().Set("Connection", "keep-alive")
		w.Header().Add("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Keep-alive + Upgrade conflict</body></html>"))
		return true
	}

	return false
}

func (g *Generator) slowDrip(w http.ResponseWriter) {
	flusher, ok := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	msg := "This response is being sent very slowly, one character at a time..."
	for _, ch := range msg {
		w.Write([]byte(string(ch)))
		if ok {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rand.Intn(300)+100) * time.Millisecond)
	}
}

// IsError returns true if the error type represents a failure.
func IsError(et ErrorType) bool {
	switch et {
	case ErrNone, ErrDelayed1s, ErrDelayed3s, ErrDelayed10s, ErrDelayedRandom:
		return false
	default:
		return true
	}
}

// IsProtocolGlitch returns true if the error type is a protocol-level glitch.
func IsProtocolGlitch(et ErrorType) bool {
	switch et {
	case ErrHTTP10Chunked, ErrHTTP11NoLength, ErrProtocolDowngrade, ErrMixedVersions, ErrInfoNoFinal,
		ErrH2UpgradeReject, ErrFalseH2Preface, ErrH2BadStreamID, ErrH2PriorityLoop, ErrFalseServerPush,
		ErrDuplicateStatus, ErrHeaderNullBytes, ErrMissingCRLF, ErrHeaderObsFold,
		ErrBothCLAndTE, ErrFalseCompression, ErrMultiEncodings,
		ErrKeepAliveUpgrade:
		return true
	default:
		return false
	}
}

// IsDelay returns true if the error type is a delay (but eventual success).
func IsDelay(et ErrorType) bool {
	switch et {
	case ErrDelayed1s, ErrDelayed3s, ErrDelayed10s, ErrDelayedRandom:
		return true
	default:
		return false
	}
}
