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

	"github.com/glitchWebServer/internal/proxy"
)

func main() {
	target := flag.String("target", "", "Backend server URL (required)")
	listen := flag.String("listen", ":8080", "Listen address")
	threshold := flag.Float64("threshold", 50, "Bot score threshold for interception (0-100)")
	mode := flag.String("mode", "glitch", "Intercept mode: block|challenge|labyrinth|glitch")
	dashboard := flag.Int("dashboard", 8766, "Dashboard port")
	passthrough := flag.String("passthrough", "", "Comma-separated paths to always pass through")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	flag.Parse()

	if *target == "" {
		fmt.Fprintf(os.Stderr, "Error: -target is required\n\n")
		fmt.Fprintf(os.Stderr, "Usage: glitch-proxy -target <backend-url> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -threshold 30\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -mode block\n")
		fmt.Fprintf(os.Stderr, "  glitch-proxy -target http://localhost:3000 -mode labyrinth -threshold 40\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate intercept mode
	validModes := map[string]bool{"block": true, "challenge": true, "labyrinth": true, "glitch": true}
	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "Error: invalid mode %q. Must be one of: block, challenge, labyrinth, glitch\n", *mode)
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
