// Package crashtest sends raw TCP malformed HTTP requests to target servers
// to discover parser crashes, hangs, and unexpected behavior.
// Run with: go test ./tests/crashtest/ -v -timeout 300s -run TestCrash
package crashtest

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// target is the server to attack. Override with -target flag if needed.
var targets = map[string]string{
	"express": "localhost:9001",
	"flask":   "localhost:9002",
	"django":  "localhost:9003",
	"gohttp":  "localhost:9004",
	"nginx":   "localhost:9005",
	"apache":  "localhost:9006",
	"puma":    "localhost:9007",
}

// attack defines a raw TCP attack payload
type attack struct {
	name    string
	payload []byte
	// If true, wait for response; if false, just send and close
	expectResponse bool
	// If true, keep connection open and send payload slowly
	slow bool
	// Whether to check server health after this attack
	checkHealth bool
}

func sendRaw(t *testing.T, addr string, atk attack) (response string, err error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = conn.Write(atk.payload)
	if err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	if atk.expectResponse {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read: %w", err)
		}
		return string(buf[:n]), nil
	}

	return "", nil
}

func checkServerAlive(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Send a valid HTTP request
	fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return n > 0 && strings.Contains(string(buf[:n]), "HTTP/")
}

// ============================================================================
// Attack payloads — each one targets a specific parser edge case
// ============================================================================

func allAttacks() []attack {
	return []attack{
		// --- Malformed Request Line ---
		{
			name:           "no_crlf_just_lf",
			payload:        []byte("GET / HTTP/1.1\nHost: localhost\n\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "bare_cr_no_lf",
			payload:        []byte("GET / HTTP/1.1\rHost: localhost\r\r"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "null_in_method",
			payload:        []byte("G\x00ET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "null_in_uri",
			payload:        []byte("GET /\x00path HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "null_in_version",
			payload:        []byte("GET / HTTP/1.\x001\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "tab_separator",
			payload:        []byte("GET\t/\tHTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "http_09_no_headers",
			payload:        []byte("GET /\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "http_version_99",
			payload:        []byte("GET / HTTP/9.9\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "http_version_110",
			payload:        []byte("GET / HTTP/1.10\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "no_space_after_method",
			payload:        []byte("GET/ HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "double_space_separator",
			payload:        []byte("GET  /  HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "missing_uri",
			payload:        []byte("GET HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "missing_version",
			payload:        []byte("GET /\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "method_too_long",
			payload:        []byte(strings.Repeat("A", 65536) + " / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "uri_too_long",
			payload:        []byte("GET /" + strings.Repeat("A", 65536) + " HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Malformed Headers ---
		{
			name:           "header_null_in_name",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-\x00Test: value\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_null_in_value",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: val\x00ue\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_no_colon",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test value\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_space_before_colon",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test : value\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_obs_fold",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: line1\r\n line2\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_obs_fold_tab",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: line1\r\n\tline2\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "duplicate_content_length",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 999\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "duplicate_host",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil.com\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_64kb_value",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: " + strings.Repeat("A", 65536) + "\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_64kb_name",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n" + strings.Repeat("X", 65536) + ": value\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "100_headers",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n" + strings.Repeat("X-H: v\r\n", 100) + "\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "1000_headers",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n" + strings.Repeat("X-H: v\r\n", 1000) + "\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_empty_name",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n: value\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_just_colon",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n:\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "header_crlf_injection",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Inject: val\r\nInjected: yes\r\n\r\n"),
			expectResponse: true,
		},
		{
			name:           "no_host_header",
			payload:        []byte("GET / HTTP/1.1\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "transfer_encoding_and_content_length",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Chunked Encoding Abuse ---
		{
			name:           "chunk_negative_size",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\ndata\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_non_hex_size",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\ndata\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_overflow_size",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_missing_final_crlf",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_size_mismatch_more",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nABCDEF\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_size_mismatch_less",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\na\r\nAB\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "chunk_extension_overflow",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;" + strings.Repeat("ext=val;", 8192) + "\r\nhello\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "double_transfer_encoding",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "transfer_encoding_unknown",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Content-Length Abuse ---
		{
			name:           "content_length_negative",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_overflow",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999999999999\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_nan",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_hex",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0x10\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_leading_zero",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 00004\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_plus_sign",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: +4\r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "content_length_whitespace",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length:  4 \r\n\r\ndata"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Request Smuggling (CL/TE and TE/CL) ---
		{
			name: "smuggle_cl_te",
			payload: []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /x HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name: "smuggle_te_cl",
			payload: []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGET /smuggled HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name: "smuggle_te_te_obfuscation",
			payload: []byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Connection & Pipeline Abuse ---
		{
			name:           "pipeline_two_requests",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "pipeline_post_get",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloGET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "garbage_after_request",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n\x00\x01\x02\x03\xff\xfe\xfd"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "h2_preface_on_http1",
			payload:        []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "pure_garbage",
			payload:        []byte("\x00\x01\x02\x03\x04\x05\xff\xfe\xfd\xfc\xfb\xfa"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "empty_request",
			payload:        []byte("\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "just_crlf",
			payload:        []byte("\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "incomplete_request_line",
			payload:        []byte("GET"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Encoding/Charset Tricks ---
		{
			name:           "utf8_bom_before_method",
			payload:        []byte("\xef\xbb\xbfGET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "backspace_in_header",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: val\x08ue\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "vertical_tab_in_header",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: val\x0bue\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "form_feed_in_header",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: val\x0cue\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "del_char_in_header",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: val\x7fue\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name:           "high_bytes_in_method",
			payload:        []byte("G\xc0\xafET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Multipart Edge Cases ---
		{
			name: "multipart_no_boundary",
			payload: []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data\r\nContent-Length: 10\r\n\r\n1234567890"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name: "multipart_empty_boundary",
			payload: []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=\r\nContent-Length: 10\r\n\r\n1234567890"),
			expectResponse: true,
			checkHealth:    true,
		},
		{
			name: "multipart_nested_infinite",
			payload: func() []byte {
				body := "--outer\r\nContent-Type: multipart/form-data; boundary=inner\r\n\r\n"
				for i := 0; i < 100; i++ {
					body += fmt.Sprintf("--inner\r\nContent-Disposition: form-data; name=\"f%d\"\r\n\r\ndata\r\n", i)
				}
				body += "--inner--\r\n--outer--\r\n"
				return []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=outer\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			}(),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- WebSocket Upgrade Tricks ---
		{
			name:           "websocket_upgrade_then_garbage",
			payload:        []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n\x00\x01\x02\x03"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Request body larger than Content-Length ---
		{
			name:           "body_larger_than_cl",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhelloEXTRA_DATA_THAT_SHOULD_NOT_BE_READ"),
			expectResponse: true,
			checkHealth:    true,
		},

		// --- Expect: 100-continue abuse ---
		{
			name:           "expect_100_no_body",
			payload:        []byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"),
			expectResponse: true,
			checkHealth:    true,
		},
	}
}

// TestCrash_AllTargets runs all attacks against all targets
func TestCrash_AllTargets(t *testing.T) {
	attacks := allAttacks()

	for targetName, addr := range targets {
		// Check if target is alive first
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s (not reachable at %s)", targetName, addr)
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			for _, atk := range attacks {
				t.Run(atk.name, func(t *testing.T) {
					resp, err := sendRaw(t, addr, atk)
					if err != nil {
						t.Logf("  %s: ERROR: %v", atk.name, err)
					} else if resp != "" {
						// Get just the status line
						line := strings.SplitN(resp, "\r\n", 2)[0]
						if line == "" {
							line = strings.SplitN(resp, "\n", 2)[0]
						}
						if len(line) > 120 {
							line = line[:120] + "..."
						}
						t.Logf("  %s: %s", atk.name, line)
					} else {
						t.Logf("  %s: (no response)", atk.name)
					}

					if atk.checkHealth {
						if !checkServerAlive(addr) {
							t.Errorf("SERVER CRASHED after attack %q on %s!", atk.name, targetName)
						}
					}
				})
			}
		})
	}
}

// TestCrash_Rapid fires attacks rapidly to test for race conditions
func TestCrash_Rapid(t *testing.T) {
	attacks := allAttacks()

	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s", targetName)
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			// Send 50 attacks concurrently
			var wg sync.WaitGroup
			for i := 0; i < 50; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					atk := attacks[idx%len(attacks)]
					sendRaw(t, addr, atk)
				}(i)
			}
			wg.Wait()

			// Check server health after concurrent barrage
			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after rapid concurrent attacks on %s!", targetName)
			}
		})
	}
}

// TestCrash_ConnectionReuse tests pipeline and connection reuse attacks
func TestCrash_ConnectionReuse(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s", targetName)
			continue
		}

		t.Run(targetName+"/pipeline_100", func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Skipf("cannot connect: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))

			// Send 100 pipelined requests
			for i := 0; i < 100; i++ {
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
			}

			// Read responses
			scanner := bufio.NewScanner(conn)
			responses := 0
			for scanner.Scan() {
				if strings.HasPrefix(scanner.Text(), "HTTP/") {
					responses++
				}
				if responses >= 100 {
					break
				}
			}
			t.Logf("Got %d responses to 100 pipelined requests", responses)

			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after 100 pipelined requests on %s!", targetName)
			}
		})

		t.Run(targetName+"/mixed_valid_invalid", func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Skipf("cannot connect: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))

			// Send valid request, then garbage, then valid request
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
			time.Sleep(100 * time.Millisecond)
			conn.Write([]byte("\x00\x01\x02\xff\xfe\xfd"))
			time.Sleep(100 * time.Millisecond)
			fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

			buf := make([]byte, 8192)
			n, _ := conn.Read(buf)
			t.Logf("Response after valid+garbage+valid: %d bytes", n)

			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after mixed valid/invalid on %s!", targetName)
			}
		})

		t.Run(targetName+"/half_close", func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Skipf("cannot connect: %v", err)
			}

			// Send request, half-close write side
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.CloseWrite()
			}

			// Try to read response
			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := conn.Read(buf)
			conn.Close()
			t.Logf("Response after half-close: %d bytes", n)

			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after half-close on %s!", targetName)
			}
		})
	}
}

// TestCrash_TLS_Attacks tests TLS-level attacks against HTTPS targets
func TestCrash_TLS_Attacks(t *testing.T) {
	// Test against any HTTPS targets we might have
	// For now, test raw TCP to HTTPS port (sending HTTP to HTTPS)
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName+"/http_to_possible_https", func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				t.Skipf("cannot connect: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			// Try TLS ClientHello to an HTTP port
			// This is a minimal TLS ClientHello that might confuse HTTP parsers
			clientHello := []byte{
				0x16, 0x03, 0x01, // TLS record: handshake, TLS 1.0
				0x00, 0x05, // length 5
				0x01,             // ClientHello
				0x00, 0x00, 0x01, // length 1
				0x03, // "body"
			}
			conn.Write(clientHello)

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 {
				t.Logf("Got %d bytes response to TLS ClientHello on HTTP port", n)
			}

			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after TLS ClientHello on HTTP port %s!", targetName)
			}
		})

		// Test with actual broken TLS handshake
		t.Run(targetName+"/broken_tls_handshake", func(t *testing.T) {
			// Try connecting with TLS but send garbage after handshake start
			tlsConn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: 3 * time.Second},
				"tcp", addr,
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				// Expected — HTTP ports won't do TLS handshake
				t.Logf("TLS handshake failed (expected on HTTP): %v", err)
				return
			}
			defer tlsConn.Close()
			// If TLS succeeded, send garbage
			tlsConn.Write([]byte("\x00\x01\x02\x03"))
			t.Logf("TLS handshake succeeded — server supports HTTPS")
		})
	}
}
