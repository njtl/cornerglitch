package crashtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitchWebServer/internal/proxy"
	"github.com/glitchWebServer/internal/proxy/chaos"
	"github.com/glitchWebServer/internal/proxy/modes"
)

// TestProxyClientKiller_Modes verifies that the killer mode is properly configured.
func TestProxyClientKiller_Modes(t *testing.T) {
	mode, err := modes.Get("killer")
	if err != nil {
		t.Fatalf("killer mode not found: %v", err)
	}
	if mode.Name != "killer" {
		t.Errorf("expected name 'killer', got %q", mode.Name)
	}

	// Verify it configures with client killer
	pipeline := proxy.NewPipeline()
	chaosCfg := &modes.ChaosConfig{}
	wafCfg := &modes.WAFConfig{}
	mode.Configure(pipeline, chaosCfg, wafCfg)

	// Pipeline should have interceptors (client killer + corruption + latency)
	stats := pipeline.Stats()
	t.Logf("Pipeline stats after configure: %+v", stats)
}

// TestProxyClientKiller_DirectAttacks runs the ClientKiller directly against
// a simple echo backend and verifies the responses are destructive.
func TestProxyClientKiller_DirectAttacks(t *testing.T) {
	ck := chaos.NewClientKiller(1.0) // 100% attack probability

	attackTypes := map[string]int{}
	errors := 0
	total := 100

	for i := 0; i < total; i++ {
		resp := &http.Response{
			StatusCode:    200,
			Status:        "200 OK",
			Body:          io.NopCloser(strings.NewReader(`{"status":"ok","data":"test"}`)),
			ContentLength: 28,
			Header:        make(http.Header),
		}
		resp.Header.Set("Content-Type", "application/json")

		result, err := ck.InterceptResponse(resp)
		if err != nil {
			errors++
			continue
		}

		// Read limited body
		body, _ := io.ReadAll(io.LimitReader(result.Body, 8192))
		result.Body.Close()

		// Classify the attack
		if result.Header.Get("Content-Encoding") == "gzip" && len(body) > 1000 {
			attackTypes["gzip_bomb"]++
		} else if result.Header.Get("Content-Encoding") == "br" {
			attackTypes["false_compression"]++
		} else if result.Header.Get("Content-Type") == "application/xml" && strings.Contains(string(body), "ENTITY") {
			attackTypes["xml_bomb"]++
		} else if result.Header.Get("Content-Type") == "application/json" && strings.HasPrefix(string(body), `{"a":`) {
			attackTypes["json_depth_bomb"]++
		} else if result.Header.Get("X-Glitch") != "" {
			attackTypes["header_null_bytes"]++
		} else if result.Header.Get("X-Flood-0000") != "" {
			attackTypes["header_flood"]++
		} else if result.Header.Get("Transfer-Encoding") == "chunked" {
			attackTypes["encoding_confusion"]++
		} else if result.ContentLength > 28 || result.ContentLength < 0 {
			attackTypes["cl_mismatch"]++
		} else {
			attackTypes["other"]++
		}
	}

	t.Logf("Attack distribution over %d responses:", total)
	for name, count := range attackTypes {
		t.Logf("  %-25s %d (%.0f%%)", name, count, float64(count)/float64(total)*100)
	}
	t.Logf("  errors: %d", errors)

	// Should have variety
	if len(attackTypes) < 3 {
		t.Errorf("expected at least 3 different attack types, got %d", len(attackTypes))
	}
}

// TestProxyClientKiller_AgainstTargets runs a proxy in killer mode against
// real Docker targets and sends client requests through it.
func TestProxyClientKiller_AgainstTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	for name, addr := range targets {
		if !checkServerAlive(addr) {
			t.Logf("SKIP %s (not reachable)", name)
			continue
		}

		t.Run(name, func(t *testing.T) {
			// Start proxy in killer mode pointing at the target
			rp := proxy.NewReverseProxy("http://"+addr, proxy.Options{
				ScoreThreshold: 0, // intercept everything
				InterceptMode:  "glitch",
			})
			defer rp.Shutdown()

			// Configure killer pipeline
			pipeline := proxy.NewPipeline()
			pipeline.Add(chaos.NewClientKiller(1.0))
			rp.Pipeline = pipeline

			// Start proxy on a random port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start listener: %v", err)
			}
			defer listener.Close()
			proxyAddr := listener.Addr().String()

			srv := &http.Server{Handler: rp}
			go srv.Serve(listener)
			defer srv.Shutdown(context.Background())

			// Send requests through the proxy and count failures
			client := &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			var (
				totalReqs    int64
				parseErrors  int64
				timeouts     int64
				bodyCorrupt  int64
				headerWeird  int64
				successful   int64
				wg           sync.WaitGroup
				concurrency  = 20
			)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			for c := 0; c < concurrency; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-ctx.Done():
							return
						default:
						}

						atomic.AddInt64(&totalReqs, 1)
						reqNum := atomic.LoadInt64(&totalReqs)
						if reqNum > 200 {
							return
						}

						req, _ := http.NewRequestWithContext(ctx, "GET",
							fmt.Sprintf("http://%s/path-%d", proxyAddr, reqNum), nil)

						resp, err := client.Do(req)
						if err != nil {
							if strings.Contains(err.Error(), "timeout") ||
								strings.Contains(err.Error(), "deadline") {
								atomic.AddInt64(&timeouts, 1)
							} else {
								atomic.AddInt64(&parseErrors, 1)
							}
							continue
						}

						// Read limited body
						body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65536))
						resp.Body.Close()

						if readErr != nil {
							atomic.AddInt64(&parseErrors, 1)
							continue
						}

						// Check for signs of corruption
						ct := resp.Header.Get("Content-Type")
						ce := resp.Header.Get("Content-Encoding")
						weirdHeaders := resp.Header.Get("X-Glitch") != "" ||
							resp.Header.Get("X-Flood-0000") != "" ||
							resp.Header.Get("X-Folded") != ""

						if weirdHeaders {
							atomic.AddInt64(&headerWeird, 1)
						} else if ce == "br" || ce == "gzip" {
							// False compression or gzip bomb
							atomic.AddInt64(&bodyCorrupt, 1)
						} else if ct == "application/xml" && strings.Contains(string(body), "ENTITY") {
							atomic.AddInt64(&bodyCorrupt, 1)
						} else if resp.ContentLength < 0 {
							atomic.AddInt64(&bodyCorrupt, 1)
						} else {
							atomic.AddInt64(&successful, 1)
						}
					}
				}()
			}

			wg.Wait()

			total := atomic.LoadInt64(&totalReqs)
			pe := atomic.LoadInt64(&parseErrors)
			to := atomic.LoadInt64(&timeouts)
			bc := atomic.LoadInt64(&bodyCorrupt)
			hw := atomic.LoadInt64(&headerWeird)
			ok := atomic.LoadInt64(&successful)

			t.Logf("Results for %s through killer proxy:", name)
			t.Logf("  Total requests:  %d", total)
			t.Logf("  Parse errors:    %d (%.0f%%)", pe, pct(pe, total))
			t.Logf("  Timeouts:        %d (%.0f%%)", to, pct(to, total))
			t.Logf("  Body corrupt:    %d (%.0f%%)", bc, pct(bc, total))
			t.Logf("  Header weird:    %d (%.0f%%)", hw, pct(hw, total))
			t.Logf("  Successful:      %d (%.0f%%)", ok, pct(ok, total))
			t.Logf("  Disruption rate: %.0f%%", pct(pe+to+bc+hw, total))
		})
	}
}

func pct(n, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}
