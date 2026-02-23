package selftest

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// RunCLI parses selftest-specific flags and runs the pipeline.
// It is intended to be called from the main glitch binary when the user runs
// "glitch selftest [flags]".
func RunCLI(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)

	mode := fs.String("mode", "baseline", "Test mode: baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare")
	duration := fs.Duration("duration", 30*time.Second, "Test duration (e.g. 30s, 2m, 5m)")
	reportFile := fs.String("report", "", "Output file for JSON report (default: stdout)")
	verbose := fs.Bool("verbose", false, "Verbose output from subprocesses")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: glitch selftest [options]\n\n")
		fmt.Fprintf(os.Stderr, "Run a self-test pipeline that starts the Glitch Server, optionally the\n")
		fmt.Fprintf(os.Stderr, "Glitch Proxy, and runs the scanner against them.\n\n")
		fmt.Fprintf(os.Stderr, "Modes:\n")
		fmt.Fprintf(os.Stderr, "  baseline       Low-intensity scan to verify basic functionality (default)\n")
		fmt.Fprintf(os.Stderr, "  scanner-stress  High-throughput scan to stress-test the scanner\n")
		fmt.Fprintf(os.Stderr, "  proxy-stress    Route traffic through the proxy under load\n")
		fmt.Fprintf(os.Stderr, "  server-stress   Maximum request rate against the server\n")
		fmt.Fprintf(os.Stderr, "  chaos           All components with evasion and proxy\n")
		fmt.Fprintf(os.Stderr, "  nightmare       Maximum intensity across all components\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate mode.
	validModes := map[string]bool{
		"baseline":       true,
		"scanner-stress": true,
		"proxy-stress":   true,
		"server-stress":  true,
		"chaos":          true,
		"nightmare":      true,
	}
	if !validModes[*mode] {
		return fmt.Errorf("unknown mode %q; valid modes: baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare", *mode)
	}

	pipeline := NewPipeline(*mode, *duration)
	pipeline.ReportFile = *reportFile
	pipeline.Verbose = *verbose

	// Handle SIGINT/SIGTERM for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nInterrupted, shutting down self-test...\n")
		cancel()
	}()

	// Run the pipeline.
	report, err := pipeline.Run(ctx)
	if err != nil {
		return fmt.Errorf("self-test failed: %w", err)
	}

	// Print summary to stderr.
	PrintSummary(report)

	// Write JSON report.
	reportJSON, err := FormatReport(report)
	if err != nil {
		return fmt.Errorf("formatting report: %w", err)
	}

	if *reportFile != "" {
		if err := os.WriteFile(*reportFile, reportJSON, 0644); err != nil {
			return fmt.Errorf("writing report to %s: %w", *reportFile, err)
		}
		fmt.Fprintf(os.Stderr, "Report written to %s\n", *reportFile)
	} else {
		fmt.Println(string(reportJSON))
	}

	// Exit with non-zero status on failure.
	if report.Verdict == "FAIL" {
		return fmt.Errorf("self-test verdict: FAIL")
	}

	return nil
}
