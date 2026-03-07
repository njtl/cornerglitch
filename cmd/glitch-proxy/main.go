package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cornerglitch/internal/proxy"
	"github.com/cornerglitch/internal/proxy/modes"
)

func main() {
	target := flag.String("target", "", "Backend server URL (required)")
	listen := flag.String("listen", ":8080", "Listen address")
	threshold := flag.Float64("threshold", 50, "Bot score threshold for interception (0-100)")
	mode := flag.String("mode", "transparent", "Proxy mode: "+strings.Join(modes.List(), "|"))
	dashboard := flag.Int("dashboard", 8766, "Dashboard port")
	passthrough := flag.String("passthrough", "", "Comma-separated paths to always pass through")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	chaosProb := flag.Float64("chaos-prob", 0, "Override chaos injection probability (0.0-1.0); 0 uses mode default")
	wafAction := flag.String("waf-action", "", "Override WAF action: block|log; empty uses mode default")
	rateLimit := flag.Int("rate-limit", 0, "Override rate limit (requests/sec); 0 uses mode default")
	flag.Parse()

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Error: -target is required\n\n")
		fmt.Fprintf(os.Stderr, "Usage: glitch-proxy -target <backend-url> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -threshold 30\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -mode chaos\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -mode nightmare -chaos-prob 0.5\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -mode waf -waf-action log -rate-limit 200\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate intercept mode using the modes registry
	selectedMode, err := modes.Get(*mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Validate waf-action if provided
	if *wafAction != "" && *wafAction != "block" && *wafAction != "log" {
		fmt.Fprintf(os.Stderr, "Error: invalid -waf-action %q. Must be one of: block, log\n", *wafAction)
		os.Exit(1)
	}

	// Parse passthrough paths
	var passthroughPaths []string
	if *passthrough != "" {
		for _, p := range strings.Split(*passthrough, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				passthroughPaths = append(passthroughPaths, p)
			}
		}
	}

	opts := proxy.Options{
		Target:           *target,
		ScoreThreshold:   *threshold,
		PassthroughPaths: passthroughPaths,
		InterceptMode:    *mode,
		DashboardPort:    *dashboard,
		EnableLogging:    *verbose,
	}

	rp := proxy.NewReverseProxy(*target, opts)

	// Create and configure the pipeline based on the selected mode
	pipeline := proxy.NewPipeline()
	chaosCfg := modes.ChaosConfig{}
	wafCfg := modes.WAFConfig{}
	selectedMode.Configure(pipeline, &chaosCfg, &wafCfg)

	// Apply CLI overrides to chaos probability
	if *chaosProb > 0 {
		chaosCfg.LatencyProb = *chaosProb
		chaosCfg.CorruptProb = *chaosProb * 0.3 // scale corruption to 30% of latency prob
	}

	// Apply CLI overrides to WAF action
	if *wafAction != "" {
		wafCfg.BlockAction = *wafAction
	}

	// Apply CLI overrides to rate limit
	if *rateLimit > 0 {
		wafCfg.RateLimitRPS = *rateLimit
	}

	// Attach the configured pipeline to the proxy
	rp.Pipeline = pipeline

	// Start the dashboard
	dashSrv := rp.StartDashboard(*dashboard)

	// Start the proxy server
	srv := &http.Server{
		Addr:         *listen,
		Handler:      rp,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("\033[36m[glitch-proxy]\033[0m Proxying %s -> %s", *listen, *target)
		log.Printf("\033[36m[glitch-proxy]\033[0m Mode: %s | Threshold: %.0f | Dashboard: :%d", *mode, *threshold, *dashboard)
		if *chaosProb > 0 {
			log.Printf("\033[36m[glitch-proxy]\033[0m Chaos probability override: %.2f", *chaosProb)
		}
		if *wafAction != "" {
			log.Printf("\033[36m[glitch-proxy]\033[0m WAF action override: %s", *wafAction)
		}
		if *rateLimit > 0 {
			log.Printf("\033[36m[glitch-proxy]\033[0m Rate limit override: %d req/s", *rateLimit)
		}
		if len(passthroughPaths) > 0 {
			log.Printf("\033[36m[glitch-proxy]\033[0m Passthrough paths: %s", strings.Join(passthroughPaths, ", "))
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("\033[33m[glitch-proxy]\033[0m Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv.Shutdown(ctx)
	proxy.ShutdownDashboard(dashSrv, ctx)
	rp.Shutdown()

	log.Println("\033[32m[glitch-proxy]\033[0m Stopped.")
}
