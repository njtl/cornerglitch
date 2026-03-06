package crashtest

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// result tracks what happened with each attack
type result struct {
	target   string
	attack   string
	response string // first line of response
	err      string
	crashed  bool
}

func quickSend(addr string, payload []byte) (statusLine string, err error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	_, err = conn.Write(payload)
	if err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if n > 0 {
		line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		if line == string(buf[:n]) {
			line = strings.SplitN(string(buf[:n]), "\n", 2)[0]
		}
		if len(line) > 100 {
			line = line[:100]
		}
		return line, nil
	}
	if readErr != nil {
		return "", readErr
	}
	return "(empty)", nil
}

// TestQuickCrash runs all attacks with short timeouts and reports interesting findings
func TestQuickCrash(t *testing.T) {
	attacks := allAttacks()

	// Track interesting findings
	type finding struct {
		target, attack, detail string
	}
	var interesting []finding
	var crashes []finding

	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s (not reachable)", targetName)
			continue
		}

		t.Logf("\n=== %s (%s) ===", targetName, addr)
		crashed := false

		for _, atk := range attacks {
			resp, err := quickSend(addr, atk.payload)

			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "i/o timeout") {
					// Server held connection open — could be waiting for more data
					continue
				}
				if strings.Contains(errStr, "connection reset") {
					// Server actively rejected — interesting
					interesting = append(interesting, finding{targetName, atk.name, "connection reset"})
					t.Logf("  [RESET] %s", atk.name)
					continue
				}
				if strings.Contains(errStr, "EOF") {
					// Server closed connection — could be interesting
					interesting = append(interesting, finding{targetName, atk.name, "EOF (server closed)"})
					continue
				}
				if strings.Contains(errStr, "connection refused") {
					// Server might be down!
					t.Logf("  [REFUSED] %s — %v", atk.name, err)
					if !checkServerAlive(addr) {
						crashed = true
						crashes = append(crashes, finding{targetName, atk.name, "SERVER DOWN after attack"})
						t.Errorf("  *** SERVER CRASHED *** after %s on %s!", atk.name, targetName)
						break
					}
					continue
				}
				// Other errors
				t.Logf("  [ERR] %s: %v", atk.name, err)
				continue
			}

			// Got a response — check if it's unexpected
			if strings.Contains(resp, "500") {
				interesting = append(interesting, finding{targetName, atk.name, "HTTP 500: " + resp})
				t.Logf("  [500!] %s: %s", atk.name, resp)
			} else if strings.Contains(resp, "502") || strings.Contains(resp, "503") {
				interesting = append(interesting, finding{targetName, atk.name, resp})
				t.Logf("  [5xx!] %s: %s", atk.name, resp)
			} else if !strings.Contains(resp, "HTTP/") {
				// Non-HTTP response — very interesting
				interesting = append(interesting, finding{targetName, atk.name, "non-HTTP: " + resp})
				t.Logf("  [WEIRD] %s: %s", atk.name, resp)
			}
		}

		// Post-barrage health check
		if !crashed {
			time.Sleep(500 * time.Millisecond)
			if !checkServerAlive(addr) {
				crashes = append(crashes, finding{targetName, "all_attacks", "SERVER DOWN after full barrage"})
				t.Errorf("  *** SERVER CRASHED *** after full barrage on %s!", targetName)
			}
		}
	}

	// Summary
	t.Logf("\n\n========== SUMMARY ==========")
	t.Logf("Crashes: %d", len(crashes))
	for _, c := range crashes {
		t.Logf("  *** %s: %s — %s", c.target, c.attack, c.detail)
	}
	t.Logf("\nInteresting findings: %d", len(interesting))
	for _, f := range interesting {
		t.Logf("  %s/%s: %s", f.target, f.attack, f.detail)
	}
}

// TestQuickCrash_ConnectionStorm opens many connections with different malformed requests simultaneously
func TestQuickCrash_ConnectionStorm(t *testing.T) {
	for targetName, addr := range targets {
		if !checkServerAlive(addr) {
			continue
		}

		t.Run(targetName, func(t *testing.T) {
			attacks := allAttacks()

			// Open 100 connections simultaneously with different attacks
			type connResult struct {
				attack string
				err    error
			}
			results := make(chan connResult, 100)

			for i := 0; i < 100; i++ {
				go func(idx int) {
					atk := attacks[idx%len(attacks)]
					conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
					if err != nil {
						results <- connResult{atk.name, err}
						return
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					conn.Write(atk.payload)
					buf := make([]byte, 1024)
					conn.Read(buf)
					conn.Close()
					results <- connResult{atk.name, nil}
				}(i)
			}

			// Collect results
			refused := 0
			for i := 0; i < 100; i++ {
				r := <-results
				if r.err != nil && strings.Contains(r.err.Error(), "connection refused") {
					refused++
				}
			}

			if refused > 10 {
				t.Logf("  %d/100 connections refused (possible exhaustion)", refused)
			}

			time.Sleep(1 * time.Second)
			if !checkServerAlive(addr) {
				t.Errorf("SERVER CRASHED after 100 concurrent malformed connections on %s!", targetName)
			} else {
				t.Logf("  Server survived 100 concurrent malformed connections")
			}
		})
	}
}
