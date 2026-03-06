package crashtest

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTargeted_Puma_500s hammers the attacks that caused Puma 500s
// with many concurrent connections to try to crash it
func TestTargeted_Puma_500s(t *testing.T) {
	addr := targets["puma"]
	if !checkServerAlive(addr) {
		t.Skip("puma not reachable")
	}

	// Attacks that caused 500s in Puma
	crashPayloads := [][]byte{
		[]byte("GET / HTTP/1.1\rHost: localhost\r\r"),            // bare_cr_no_lf
		[]byte("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n"), // chunk_overflow
		[]byte("\r\n\r\n"), // empty_request
	}

	t.Log("Sending 500 concurrent 500-triggering requests to Puma...")
	var wg sync.WaitGroup
	errors500 := 0
	var mu sync.Mutex

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := crashPayloads[idx%len(crashPayloads)]
			resp, err := quickSend(addr, payload)
			if err == nil && strings.Contains(resp, "500") {
				mu.Lock()
				errors500++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	t.Logf("Got %d/500 HTTP 500 responses from Puma", errors500)

	time.Sleep(1 * time.Second)
	if !checkServerAlive(addr) {
		t.Errorf("*** PUMA CRASHED after 500 concurrent 500-triggering requests! ***")
	} else {
		t.Log("Puma survived")
	}
}

// TestTargeted_Flask_NonHTTP tests Flask's non-HTTP response behavior
// These are real protocol violations — Flask returns HTML without HTTP status line
func TestTargeted_Flask_NonHTTP(t *testing.T) {
	addr := targets["flask"]
	if !checkServerAlive(addr) {
		t.Skip("flask not reachable")
	}

	// Payloads that made Flask return non-HTTP responses
	payloads := []struct {
		name    string
		payload []byte
	}{
		{"null_in_version", []byte("GET / HTTP/1.\x001\r\nHost: localhost\r\n\r\n")},
		{"http_99", []byte("GET / HTTP/9.9\r\nHost: localhost\r\n\r\n")},
		{"no_space", []byte("GET/ HTTP/1.1\r\nHost: localhost\r\n\r\n")},
		{"h2_preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")},
	}

	for _, p := range payloads {
		resp, err := quickSend(addr, p.payload)
		if err != nil {
			t.Logf("  %s: error=%v", p.name, err)
		} else {
			isHTTP := strings.HasPrefix(resp, "HTTP/")
			t.Logf("  %s: isHTTP=%v response=%s", p.name, isHTTP, resp)
			if !isHTTP {
				t.Logf("  *** FINDING: Flask returns non-HTTP response for %s ***", p.name)
			}
		}
	}
}

// TestTargeted_ConnectionHold holds many connections open without completing
// the request to test connection pool exhaustion
func TestTargeted_ConnectionHold(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			// Open 200 connections and send partial headers, never complete
			conns := make([]net.Conn, 0, 200)
			var mu sync.Mutex

			for i := 0; i < 200; i++ {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					t.Logf("  Failed to open connection %d: %v", i, err)
					break
				}
				conn.SetDeadline(time.Now().Add(60 * time.Second))
				// Send partial request — never send final \r\n\r\n
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nX-Hold: %d\r\n", i)
				mu.Lock()
				conns = append(conns, conn)
				mu.Unlock()
			}

			t.Logf("  Opened %d partial-request connections", len(conns))

			// Now try to make a normal request — is the server still accepting?
			time.Sleep(1 * time.Second)
			normalConn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				t.Logf("  *** FINDING: Server refuses new connections while %d partial requests are held open ***", len(conns))
			} else {
				normalConn.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(normalConn, "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				buf := make([]byte, 1024)
				n, _ := normalConn.Read(buf)
				normalConn.Close()
				if n > 0 && strings.Contains(string(buf[:n]), "200") {
					t.Logf("  Server still responds normally with %d held connections", len(conns))
				} else if n > 0 {
					t.Logf("  Server responds but not 200: %s", string(buf[:n])[:80])
				} else {
					t.Logf("  *** FINDING: Server accepts connection but doesn't respond with %d held ***", len(conns))
				}
			}

			// Clean up
			for _, c := range conns {
				c.Close()
			}

			// Check if server recovers
			time.Sleep(2 * time.Second)
			if !checkServerAlive(addr) {
				t.Errorf("*** %s CRASHED or HUNG after connection hold attack ***", targetName)
			} else {
				t.Logf("  Server recovered after releasing connections")
			}
		})
	}
}

// TestTargeted_ChunkedHang sends an incomplete chunked request that never finishes
// and checks if this ties up server resources
func TestTargeted_ChunkedHang(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			// Open 100 connections with incomplete chunked encoding
			conns := make([]net.Conn, 0, 100)
			for i := 0; i < 100; i++ {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					break
				}
				conn.SetDeadline(time.Now().Add(60 * time.Second))
				// Start chunked request, send first chunk, never finish
				fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n")
				conns = append(conns, conn)
			}

			t.Logf("  Opened %d incomplete chunked connections", len(conns))

			// Can we still make a normal request?
			time.Sleep(1 * time.Second)
			alive := checkServerAlive(addr)
			if !alive {
				t.Logf("  *** FINDING: Server unresponsive with %d incomplete chunked requests ***", len(conns))
			} else {
				t.Logf("  Server still responds with %d hanging chunked requests", len(conns))
			}

			for _, c := range conns {
				c.Close()
			}
			time.Sleep(2 * time.Second)
			if !checkServerAlive(addr) {
				t.Errorf("*** %s CRASHED after chunked hang attack ***", targetName)
			}
		})
	}
}

// TestTargeted_HeaderBomb sends a request with an extremely large number of headers
func TestTargeted_HeaderBomb(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			// Test with increasing header counts
			for _, count := range []int{100, 500, 1000, 5000, 10000} {
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					t.Logf("  %d headers: cannot connect: %v", count, err)
					break
				}
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				// Build request with many headers
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n")
				for i := 0; i < count; i++ {
					fmt.Fprintf(conn, "X-H%d: value%d\r\n", i, i)
				}
				fmt.Fprintf(conn, "\r\n")

				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				conn.Close()

				if n > 0 {
					line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
					t.Logf("  %d headers: %s", count, line)
					if strings.Contains(line, "500") {
						t.Logf("  *** FINDING: %s returns 500 with %d headers ***", targetName, count)
					}
				} else if err != nil {
					t.Logf("  %d headers: %v", count, err)
				}

				if !checkServerAlive(addr) {
					t.Errorf("*** %s CRASHED after %d headers ***", targetName, count)
					return
				}
			}
		})
	}
}

// TestTargeted_URIBomb sends requests with extremely long URIs
func TestTargeted_URIBomb(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			for _, size := range []int{1024, 4096, 8192, 16384, 32768, 65536, 131072} {
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					t.Logf("  %d-byte URI: cannot connect", size)
					break
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				uri := "/" + strings.Repeat("A", size)
				fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", uri)

				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				conn.Close()

				if n > 0 {
					line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
					if len(line) > 100 {
						line = line[:100]
					}
					t.Logf("  %d-byte URI: %s", size, line)
				} else {
					t.Logf("  %d-byte URI: no response", size)
				}

				if !checkServerAlive(addr) {
					t.Errorf("*** %s CRASHED after %d-byte URI ***", targetName, size)
					return
				}
			}
		})
	}
}

// TestTargeted_BodySizeConfusion sends body larger/smaller than Content-Length
func TestTargeted_BodySizeConfusion(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			tests := []struct {
				name string
				cl   int
				body string
			}{
				{"cl=0_body=1MB", 0, strings.Repeat("X", 1<<20)},
				{"cl=1MB_body=0", 1 << 20, ""},
				{"cl=5_body=1MB", 5, strings.Repeat("X", 1<<20)},
				{"cl=100_body=5", 100, "hello"},
			}

			for _, tt := range tests {
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					continue
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))

				fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", tt.cl, tt.body)

				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				conn.Close()

				if n > 0 {
					line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
					t.Logf("  %s: %s", tt.name, line)
					if strings.Contains(line, "500") {
						t.Logf("  *** FINDING: %s returns 500 for %s ***", targetName, tt.name)
					}
				}

				if !checkServerAlive(addr) {
					t.Errorf("*** %s CRASHED after %s ***", targetName, tt.name)
					return
				}
			}
		})
	}
}
