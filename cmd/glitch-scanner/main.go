package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
	"github.com/glitchWebServer/internal/scanner/profiles"
)

func main() {
	// CLI flags.
	target := flag.String("target", "", "Target URL (required)")
	profile := flag.String("profile", "aggressive", "Scan profile: compliance, aggressive, stealth, nightmare, destroyer")
	concurrency := flag.Int("concurrency", 0, "Number of concurrent workers (default from profile)")
	rate := flag.Int("rate", 0, "Max requests/second (default from profile)")
	timeout := flag.Int("timeout", 10, "Per-request timeout in seconds")
	modules := flag.String("modules", "", "Comma-separated module list (default: all)")
	evasion := flag.String("evasion", "", "Evasion mode: none, basic, advanced, nightmare (default from profile)")
	crawl := flag.Bool("crawl", true, "Crawl target before attacking")
	crawlDepth := flag.Int("crawl-depth", 3, "Max crawl depth")
	proxyURL := flag.String("proxy", "", "HTTP proxy URL (for testing through Glitch Proxy)")
	output := flag.String("output", "", "Output file for report (default: stdout)")
	format := flag.String("format", "json", "Report format: json, html")
	ua := flag.String("ua", "", "User agent string (default from profile)")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	listModules := flag.Bool("list-modules", false, "List available attack modules and exit")
	listProfiles := flag.Bool("list-profiles", false, "List available scan profiles and exit")

	flag.Parse()

	// Handle list commands first.
	if *listModules {
		printModules()
		return
	}
	if *listProfiles {
		printProfiles()
		return
	}

	// Validate target.
	if *target == "" {
		fmt.Fprintf(os.Stderr, "Error: -target is required\n\n")
		fmt.Fprintf(os.Stderr, "Usage: glitch-scanner -target <url> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  glitch-scanner -target http://localhost:8765\n")
		fmt.Fprintf(os.Stderr, "  glitch-scanner -target http://localhost:8765 -profile stealth\n")
		fmt.Fprintf(os.Stderr, "  glitch-scanner -target http://localhost:8765 -modules owasp,injection -output report.json\n")
		fmt.Fprintf(os.Stderr, "\nUse -list-modules to see available modules.\n")
		fmt.Fprintf(os.Stderr, "Use -list-profiles to see available profiles.\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Normalize target URL.
	normalizedTarget := strings.TrimRight(*target, "/")

	// Load profile.
	prof, err := profiles.Get(*profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Start with profile config and override with explicit flags.
	config := &prof.Config
	config.Target = normalizedTarget
	config.Verbose = *verbose

	// Override concurrency if explicitly set.
	if *concurrency > 0 {
		config.Concurrency = *concurrency
	}

	// Override rate limit if explicitly set.
	if *rate > 0 {
		config.RateLimit = *rate
	}

	// Override timeout if explicitly set (default flag value is 10, but
	// we check if it was explicitly provided by comparing to the flag's default).
	if isFlagSet("timeout") {
		config.Timeout = time.Duration(*timeout) * time.Second
	}

	// Override evasion if explicitly set.
	if *evasion != "" {
		config.EvasionMode = *evasion
	}

	// Override crawl settings.
	if isFlagSet("crawl") {
		config.CrawlFirst = *crawl
	}
	if isFlagSet("crawl-depth") {
		config.CrawlDepth = *crawlDepth
	}

	// Override user agent if explicitly set.
	if *ua != "" {
		config.UserAgent = *ua
	}

	// Override proxy if set.
	if *proxyURL != "" {
		config.ProxyURL = *proxyURL
	}

	// Override output format.
	if isFlagSet("format") {
		config.OutputFormat = *format
	}

	// Parse module list.
	var moduleNames []string
	if *modules != "" {
		for _, m := range strings.Split(*modules, ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				moduleNames = append(moduleNames, m)
			}
		}
		config.EnabledModules = moduleNames
	}

	// Create engine.
	engine := scanner.NewEngine(config)

	// Register attack modules (filtered if -modules was specified).
	allMods := attacks.FilterModules(moduleNames)
	for _, m := range allMods {
		engine.RegisterModule(m)
	}

	fmt.Fprintf(os.Stderr, "Glitch Scanner starting\n")
	fmt.Fprintf(os.Stderr, "  Target:      %s\n", normalizedTarget)
	fmt.Fprintf(os.Stderr, "  Profile:     %s\n", prof.Name)
	fmt.Fprintf(os.Stderr, "  Concurrency: %d\n", config.Concurrency)
	fmt.Fprintf(os.Stderr, "  Rate limit:  %d req/s\n", config.RateLimit)
	fmt.Fprintf(os.Stderr, "  Evasion:     %s\n", config.EvasionMode)
	fmt.Fprintf(os.Stderr, "  Modules:     %d\n", len(allMods))
	fmt.Fprintf(os.Stderr, "  Crawl:       %v (depth=%d)\n", config.CrawlFirst, config.CrawlDepth)
	if config.ProxyURL != "" {
		fmt.Fprintf(os.Stderr, "  Proxy:       %s\n", config.ProxyURL)
	}
	fmt.Fprintf(os.Stderr, "\n")

	// Handle SIGINT/SIGTERM for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nInterrupted, shutting down gracefully...\n")
		cancel()
	}()

	// Run the scan.
	report, err := engine.Run(ctx)
	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "Error: scan failed: %v\n", err)
		os.Exit(1)
	}

	if report == nil {
		fmt.Fprintf(os.Stderr, "Error: no report generated\n")
		os.Exit(1)
	}

	// Print human-readable summary to stderr.
	printSummary(report, prof.Name)

	// Write report to output.
	var reportBytes []byte
	switch strings.ToLower(*format) {
	case "html":
		reportBytes, err = writeHTMLReport(report)
	default:
		reportBytes, err = writeJSONReport(report)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate report: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, reportBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to write output file %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *output)
	} else {
		fmt.Print(string(reportBytes))
	}
}

// isFlagSet returns true if the named flag was explicitly set on the command line.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// printModules lists all available attack modules.
func printModules() {
	fmt.Println("Available attack modules:")
	fmt.Println()
	for _, info := range attacks.ListModules() {
		fmt.Printf("  %-20s  category=%-20s  requests=~%d\n", info.Name, info.Category, info.Requests)
	}
	fmt.Println()
}

// printProfiles lists all available scan profiles.
func printProfiles() {
	fmt.Println("Available scan profiles:")
	fmt.Println()
	for _, prof := range profiles.All() {
		fmt.Printf("  %s\n", prof.Name)
		fmt.Printf("    %s\n", prof.Description)
		fmt.Printf("    concurrency=%d  rate=%d/s  evasion=%s  crawl-depth=%d\n",
			prof.Config.Concurrency, prof.Config.RateLimit,
			prof.Config.EvasionMode, prof.Config.CrawlDepth)
		fmt.Println()
	}
}

// printSummary writes a human-readable summary to stderr.
func printSummary(report *scanner.Report, profileName string) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "=== Glitch Scanner Report ===\n")
	fmt.Fprintf(os.Stderr, "Target:    %s\n", report.Target)
	fmt.Fprintf(os.Stderr, "Profile:   %s\n", profileName)
	fmt.Fprintf(os.Stderr, "Duration:  %dms\n", report.DurationMs)
	fmt.Fprintf(os.Stderr, "\n")

	// Requests.
	total := report.TotalRequests
	errCount := 0
	for _, e := range report.Errors {
		if e != "" {
			errCount++
		}
	}
	fmt.Fprintf(os.Stderr, "Requests:  %d total, %d errors\n", total, errCount)

	// Findings by severity.
	if report.Summary != nil {
		fmt.Fprintf(os.Stderr, "\nFindings:  %d total\n", report.Summary.TotalFindings)
		if report.Summary.Critical > 0 {
			fmt.Fprintf(os.Stderr, "  CRITICAL:  %d\n", report.Summary.Critical)
		}
		if report.Summary.High > 0 {
			fmt.Fprintf(os.Stderr, "  HIGH:      %d\n", report.Summary.High)
		}
		if report.Summary.Medium > 0 {
			fmt.Fprintf(os.Stderr, "  MEDIUM:    %d\n", report.Summary.Medium)
		}
		if report.Summary.Low > 0 {
			fmt.Fprintf(os.Stderr, "  LOW:       %d\n", report.Summary.Low)
		}
		if report.Summary.Info > 0 {
			fmt.Fprintf(os.Stderr, "  INFO:      %d\n", report.Summary.Info)
		}
	}

	// Coverage by category.
	if len(report.Coverage) > 0 {
		fmt.Fprintf(os.Stderr, "\nCoverage by Category:\n")
		for cat, ci := range report.Coverage {
			fmt.Fprintf(os.Stderr, "  %-30s  tested=%d  detected=%d  coverage=%.1f%%\n",
				cat, ci.Tested, ci.Detected, ci.CoveragePct)
		}
	}

	// Overall coverage and resilience.
	if report.Summary != nil {
		fmt.Fprintf(os.Stderr, "\nOverall Coverage:    %.1f%%\n", report.Summary.OverallCoverage)
		fmt.Fprintf(os.Stderr, "Overall Resilience:  %.1f%%\n", report.Summary.OverallResilience)
	}

	// Top errors.
	if len(report.Errors) > 0 {
		fmt.Fprintf(os.Stderr, "\nTop Errors:\n")
		limit := len(report.Errors)
		if limit > 10 {
			limit = 10
		}
		for _, e := range report.Errors[:limit] {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		if len(report.Errors) > 10 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(report.Errors)-10)
		}
	}

	fmt.Fprintf(os.Stderr, "\n")
}

// writeJSONReport serializes the report as indented JSON.
func writeJSONReport(report *scanner.Report) ([]byte, error) {
	reporter := scanner.NewReporter()
	var buf strings.Builder
	if err := reporter.WriteJSON(&buf, report); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// writeHTMLReport serializes the report as an HTML document.
func writeHTMLReport(report *scanner.Report) ([]byte, error) {
	reporter := scanner.NewReporter()
	var buf strings.Builder
	if err := reporter.WriteHTML(&buf, report); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
