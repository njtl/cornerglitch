// Package selftest provides a self-test pipeline that orchestrates the Glitch
// Server, Glitch Proxy, and Glitch Scanner as subprocesses to validate the
// entire system end-to-end.
package selftest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
	"github.com/glitchWebServer/internal/scanner/profiles"
)

// Pipeline orchestrates a full self-test: start server, optionally start proxy,
// run scanner, collect metrics, and produce a verdict.
type Pipeline struct {
	Mode       string // baseline, scanner-stress, proxy-stress, server-stress, chaos, nightmare
	Duration   time.Duration
	ReportFile string
	Verbose    bool

	serverPort int
	proxyPort  int
	dashPort   int

	serverCmd *exec.Cmd
	proxyCmd  *exec.Cmd

	logger *log.Logger
}

// PipelineReport is the final output of a self-test run.
type PipelineReport struct {
	Mode           string          `json:"mode"`
	Duration       string          `json:"duration"`
	StartedAt      string          `json:"started_at"`
	CompletedAt    string          `json:"completed_at"`
	Scanner        *ScannerMetrics `json:"scanner"`
	Proxy          *ProxyMetrics   `json:"proxy,omitempty"`
	Server         *ServerMetrics  `json:"server"`
	Verdict        string          `json:"verdict"` // PASS or FAIL
	FailureReasons []string        `json:"failure_reasons,omitempty"`
}

// ScannerMetrics summarizes the scanner's performance during a self-test.
type ScannerMetrics struct {
	RequestsSent int     `json:"requests_sent"`
	Findings     int     `json:"findings"`
	Errors       int     `json:"errors"`
	CoveragePct  float64 `json:"coverage_pct"`
}

// ProxyMetrics summarizes the proxy's performance during a self-test.
type ProxyMetrics struct {
	RequestsProxied  int `json:"requests_proxied"`
	RequestsBlocked  int `json:"requests_blocked"`
	RequestsModified int `json:"requests_modified"`
}

// ServerMetrics summarizes the server's behavior during a self-test.
type ServerMetrics struct {
	RequestsReceived int `json:"requests_received"`
	ErrorsInjected   int `json:"errors_injected"`
}

// NewPipeline creates a Pipeline with the given mode and duration.
func NewPipeline(mode string, duration time.Duration) *Pipeline {
	return &Pipeline{
		Mode:     mode,
		Duration: duration,
		logger:   log.New(os.Stderr, "[selftest] ", log.Ltime),
	}
}

// Run executes the full self-test pipeline: build binaries, start server,
// optionally start proxy, run scanner, collect metrics, and produce a verdict.
func (p *Pipeline) Run(ctx context.Context) (*PipelineReport, error) {
	startedAt := time.Now()
	report := &PipelineReport{
		Mode:      p.Mode,
		StartedAt: startedAt.UTC().Format(time.RFC3339),
	}

	defer p.shutdown()

	// Step 1: Find free ports.
	var err error
	p.serverPort, err = findFreePort()
	if err != nil {
		return nil, fmt.Errorf("finding server port: %w", err)
	}
	p.dashPort, err = findFreePort()
	if err != nil {
		return nil, fmt.Errorf("finding dashboard port: %w", err)
	}
	if p.usesProxy() {
		p.proxyPort, err = findFreePort()
		if err != nil {
			return nil, fmt.Errorf("finding proxy port: %w", err)
		}
	}

	p.logger.Printf("ports: server=%d dashboard=%d proxy=%d", p.serverPort, p.dashPort, p.proxyPort)

	// Step 2: Build binaries if needed.
	if err := p.buildBinaries(ctx); err != nil {
		return nil, fmt.Errorf("building binaries: %w", err)
	}

	// Step 3: Start server.
	if err := p.startServer(ctx); err != nil {
		return nil, fmt.Errorf("starting server: %w", err)
	}

	// Step 4: Wait for server health.
	serverURL := fmt.Sprintf("http://localhost:%d", p.serverPort)
	if err := p.waitForHealth(ctx, serverURL+"/health/live", 15*time.Second); err != nil {
		return nil, fmt.Errorf("server health check: %w", err)
	}
	p.logger.Printf("server is healthy at %s", serverURL)

	// Step 5: Start proxy if mode requires it.
	scanTarget := serverURL
	if p.usesProxy() {
		if err := p.startProxy(ctx); err != nil {
			return nil, fmt.Errorf("starting proxy: %w", err)
		}
		proxyURL := fmt.Sprintf("http://localhost:%d", p.proxyPort)
		if err := p.waitForHealth(ctx, proxyURL+"/health", 10*time.Second); err != nil {
			// Proxy might not have /health. Try the root.
			if err2 := p.waitForReachable(ctx, proxyURL+"/", 10*time.Second); err2 != nil {
				return nil, fmt.Errorf("proxy health check: %w (also tried root: %v)", err, err2)
			}
		}
		scanTarget = proxyURL
		p.logger.Printf("proxy is healthy at %s", proxyURL)
	}

	// Step 6: Run scanner.
	p.logger.Printf("running scanner against %s (mode=%s, duration=%s)", scanTarget, p.Mode, p.Duration)
	scanReport, err := p.runScanner(ctx, scanTarget)
	if err != nil && ctx.Err() == nil && !errors.Is(err, context.DeadlineExceeded) {
		// Only treat as fatal if it's not the expected duration timeout.
		// context.DeadlineExceeded is normal — it means the scan duration elapsed.
		return nil, fmt.Errorf("scanner: %w", err)
	}

	// Step 7: Collect server metrics.
	serverMetrics, err := p.collectServerMetrics()
	if err != nil {
		p.logger.Printf("warning: could not collect server metrics: %v", err)
		serverMetrics = &ServerMetrics{}
	}

	// Step 8: Build report.
	completedAt := time.Now()
	report.CompletedAt = completedAt.UTC().Format(time.RFC3339)
	report.Duration = completedAt.Sub(startedAt).String()
	report.Server = serverMetrics

	if scanReport != nil {
		report.Scanner = &ScannerMetrics{
			RequestsSent: scanReport.TotalRequests,
			Findings:     len(scanReport.Findings),
			Errors:       len(scanReport.Errors),
			CoveragePct:  p.computeCoverage(scanReport),
		}
	} else {
		report.Scanner = &ScannerMetrics{}
	}

	if p.usesProxy() {
		report.Proxy = &ProxyMetrics{}
	}

	// Step 9: Determine verdict.
	report.Verdict, report.FailureReasons = p.evaluate(report)

	return report, nil
}

// usesProxy returns true if the mode involves the proxy.
func (p *Pipeline) usesProxy() bool {
	switch p.Mode {
	case "proxy-stress", "chaos", "nightmare":
		return true
	default:
		return false
	}
}

// buildBinaries ensures the glitch server and proxy binaries exist.
func (p *Pipeline) buildBinaries(ctx context.Context) error {
	binDir := p.binDir()

	targets := []struct {
		name string
		pkg  string
	}{
		{"glitch", "./cmd/glitch"},
		{"glitch-proxy", "./cmd/glitch-proxy"},
	}

	for _, t := range targets {
		binPath := filepath.Join(binDir, t.name)
		if runtime.GOOS == "windows" {
			binPath += ".exe"
		}

		// Check if binary already exists and is recent enough.
		if info, err := os.Stat(binPath); err == nil {
			if time.Since(info.ModTime()) < 5*time.Minute {
				p.logger.Printf("binary %s is recent, skipping build", t.name)
				continue
			}
		}

		p.logger.Printf("building %s...", t.name)
		cmd := exec.CommandContext(ctx, "go", "build", "-o", binPath, t.pkg)
		cmd.Dir = p.projectRoot()
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("building %s: %w", t.name, err)
		}
	}

	return nil
}

// startServer starts the Glitch Server as a subprocess.
func (p *Pipeline) startServer(ctx context.Context) error {
	binPath := filepath.Join(p.binDir(), "glitch")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	args := []string{
		fmt.Sprintf("-port=%d", p.serverPort),
		fmt.Sprintf("-dash-port=%d", p.dashPort),
	}

	p.serverCmd = exec.CommandContext(ctx, binPath, args...)
	p.serverCmd.Dir = p.projectRoot()

	if p.Verbose {
		p.serverCmd.Stdout = os.Stderr
		p.serverCmd.Stderr = os.Stderr
	} else {
		p.serverCmd.Stdout = io.Discard
		p.serverCmd.Stderr = io.Discard
	}

	if err := p.serverCmd.Start(); err != nil {
		return fmt.Errorf("starting server process: %w", err)
	}

	p.logger.Printf("server started (pid=%d, port=%d)", p.serverCmd.Process.Pid, p.serverPort)
	return nil
}

// startProxy starts the Glitch Proxy as a subprocess pointing at the server.
func (p *Pipeline) startProxy(ctx context.Context) error {
	binPath := filepath.Join(p.binDir(), "glitch-proxy")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}

	serverTarget := fmt.Sprintf("http://localhost:%d", p.serverPort)
	listenAddr := fmt.Sprintf(":%d", p.proxyPort)

	proxyMode := "transparent"
	switch p.Mode {
	case "proxy-stress", "chaos":
		proxyMode = "chaos"
	case "nightmare":
		proxyMode = "nightmare"
	}

	args := []string{
		fmt.Sprintf("-target=%s", serverTarget),
		fmt.Sprintf("-listen=%s", listenAddr),
		fmt.Sprintf("-mode=%s", proxyMode),
		fmt.Sprintf("-dashboard=%d", p.dashPort+1000), // offset to avoid conflicts
	}

	p.proxyCmd = exec.CommandContext(ctx, binPath, args...)
	p.proxyCmd.Dir = p.projectRoot()

	if p.Verbose {
		p.proxyCmd.Stdout = os.Stderr
		p.proxyCmd.Stderr = os.Stderr
	} else {
		p.proxyCmd.Stdout = io.Discard
		p.proxyCmd.Stderr = io.Discard
	}

	if err := p.proxyCmd.Start(); err != nil {
		return fmt.Errorf("starting proxy process: %w", err)
	}

	p.logger.Printf("proxy started (pid=%d, port=%d)", p.proxyCmd.Process.Pid, p.proxyPort)
	return nil
}

// runScanner runs the scanner in-process against the target URL.
func (p *Pipeline) runScanner(ctx context.Context, targetURL string) (*scanner.Report, error) {
	// Get profile based on mode.
	profileName := p.scannerProfile()
	prof, err := profiles.Get(profileName)
	if err != nil {
		// Fall back to aggressive.
		prof, _ = profiles.Get("aggressive")
	}

	config := &prof.Config
	config.Target = targetURL
	config.Verbose = p.Verbose

	// Apply mode-specific overrides.
	switch p.Mode {
	case "baseline":
		config.Concurrency = 5
		config.RateLimit = 20
		config.CrawlFirst = true
		config.CrawlDepth = 2
	case "scanner-stress":
		config.Concurrency = 50
		config.RateLimit = 500
		config.CrawlFirst = true
		config.CrawlDepth = 4
	case "server-stress":
		config.Concurrency = 100
		config.RateLimit = 1000
		config.CrawlFirst = false
	case "chaos", "nightmare":
		config.Concurrency = 100
		config.RateLimit = 0 // unlimited
		config.CrawlFirst = true
		config.CrawlDepth = 5
		config.EvasionMode = "nightmare"
	}

	engine := scanner.NewEngine(config)

	// Register all modules.
	for _, m := range attacks.AllModules() {
		engine.RegisterModule(m)
	}

	// Create a context with the pipeline's duration as a deadline.
	scanCtx, scanCancel := context.WithTimeout(ctx, p.Duration)
	defer scanCancel()

	report, err := engine.Run(scanCtx)
	return report, err
}

// collectServerMetrics fetches metrics from the server's dashboard API.
func (p *Pipeline) collectServerMetrics() (*ServerMetrics, error) {
	url := fmt.Sprintf("http://localhost:%d/api/metrics", p.dashPort)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// The metrics API returns a JSON object; we extract what we can.
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing metrics: %w", err)
	}

	metrics := &ServerMetrics{}

	if total, ok := raw["total_requests"]; ok {
		switch v := total.(type) {
		case float64:
			metrics.RequestsReceived = int(v)
		}
	}

	if errCount, ok := raw["errors_injected"]; ok {
		switch v := errCount.(type) {
		case float64:
			metrics.ErrorsInjected = int(v)
		}
	}

	// Alternative field names for compatibility.
	if metrics.RequestsReceived == 0 {
		if total, ok := raw["total"]; ok {
			if v, ok := total.(float64); ok {
				metrics.RequestsReceived = int(v)
			}
		}
	}

	return metrics, nil
}

// shutdown stops all subprocesses.
func (p *Pipeline) shutdown() {
	if p.proxyCmd != nil && p.proxyCmd.Process != nil {
		p.logger.Printf("stopping proxy (pid=%d)", p.proxyCmd.Process.Pid)
		_ = p.proxyCmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = p.proxyCmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.proxyCmd.Process.Kill()
		}
	}

	if p.serverCmd != nil && p.serverCmd.Process != nil {
		p.logger.Printf("stopping server (pid=%d)", p.serverCmd.Process.Pid)
		_ = p.serverCmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = p.serverCmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.serverCmd.Process.Kill()
		}
	}
}

// waitForHealth polls the given URL until it returns a 200 or the timeout expires.
func (p *Pipeline) waitForHealth(ctx context.Context, url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return nil
			}
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("health check timed out after %s for %s", timeout, url)
}

// waitForReachable polls the given URL until it gets any response.
func (p *Pipeline) waitForReachable(ctx context.Context, url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}

		time.Sleep(250 * time.Millisecond)
	}

	return fmt.Errorf("reachability check timed out after %s for %s", timeout, url)
}

// scannerProfile maps the pipeline mode to a scanner profile name.
func (p *Pipeline) scannerProfile() string {
	switch p.Mode {
	case "baseline":
		return "compliance"
	case "stealth":
		return "stealth"
	case "nightmare", "chaos":
		return "nightmare"
	default:
		return "aggressive"
	}
}

// computeCoverage extracts the overall coverage percentage from a scan report.
func (p *Pipeline) computeCoverage(report *scanner.Report) float64 {
	if report.Summary != nil && report.Summary.OverallCoverage > 0 {
		return report.Summary.OverallCoverage
	}
	// Fallback: if category-based coverage is zero but findings exist,
	// compute coverage as the finding-to-request ratio (capped at 100%).
	if report.TotalRequests > 0 && len(report.Findings) > 0 {
		cov := float64(len(report.Findings)) / float64(report.TotalRequests) * 100
		if cov > 100 {
			cov = 100
		}
		return cov
	}
	return 0
}

// evaluate determines whether the self-test passed or failed.
func (p *Pipeline) evaluate(report *PipelineReport) (string, []string) {
	var reasons []string

	// The scanner must have sent at least some requests.
	if report.Scanner.RequestsSent == 0 {
		reasons = append(reasons, "scanner sent zero requests")
	}

	// The server must have received some requests.
	if report.Server.RequestsReceived == 0 {
		// Not a hard failure if we couldn't collect metrics.
		p.logger.Printf("warning: server reported zero requests received (metrics may not be available)")
	}

	// For baseline mode, we want reasonable coverage.
	if p.Mode == "baseline" && report.Scanner.CoveragePct < 10 {
		reasons = append(reasons, fmt.Sprintf("coverage too low: %.1f%%", report.Scanner.CoveragePct))
	}

	// Scanner errors should not be the majority of requests.
	if report.Scanner.RequestsSent > 0 {
		errorRate := float64(report.Scanner.Errors) / float64(report.Scanner.RequestsSent) * 100
		if errorRate > 80 {
			reasons = append(reasons, fmt.Sprintf("error rate too high: %.1f%%", errorRate))
		}
	}

	if len(reasons) > 0 {
		return "FAIL", reasons
	}
	return "PASS", nil
}

// binDir returns the directory where built binaries are placed.
func (p *Pipeline) binDir() string {
	root := p.projectRoot()
	dir := filepath.Join(root, ".build")
	_ = os.MkdirAll(dir, 0755)
	return dir
}

// projectRoot returns the project root directory by looking for go.mod.
func (p *Pipeline) projectRoot() string {
	// Try working directory first.
	wd, _ := os.Getwd()

	// Walk up looking for go.mod.
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Fallback: try to find the project via the module path.
	// Look for common indicators.
	for _, candidate := range []string{
		wd,
		filepath.Join(os.Getenv("HOME"), "glitchWebServer"),
	} {
		if _, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil {
			return candidate
		}
	}

	return wd
}

// findFreePort finds an available TCP port on localhost.
func findFreePort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

// FormatReport serializes a PipelineReport as indented JSON.
func FormatReport(report *PipelineReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// PrintSummary writes a human-readable summary of the pipeline report to stderr.
func PrintSummary(report *PipelineReport) {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "=== Glitch Self-Test Results ===\n")
	fmt.Fprintf(os.Stderr, "Mode:      %s\n", report.Mode)
	fmt.Fprintf(os.Stderr, "Duration:  %s\n", report.Duration)
	fmt.Fprintf(os.Stderr, "Verdict:   %s\n", report.Verdict)

	if report.Scanner != nil {
		fmt.Fprintf(os.Stderr, "\nScanner:\n")
		fmt.Fprintf(os.Stderr, "  Requests sent: %d\n", report.Scanner.RequestsSent)
		fmt.Fprintf(os.Stderr, "  Findings:      %d\n", report.Scanner.Findings)
		fmt.Fprintf(os.Stderr, "  Errors:        %d\n", report.Scanner.Errors)
		fmt.Fprintf(os.Stderr, "  Coverage:      %.1f%%\n", report.Scanner.CoveragePct)
	}

	if report.Proxy != nil {
		fmt.Fprintf(os.Stderr, "\nProxy:\n")
		fmt.Fprintf(os.Stderr, "  Proxied:  %d\n", report.Proxy.RequestsProxied)
		fmt.Fprintf(os.Stderr, "  Blocked:  %d\n", report.Proxy.RequestsBlocked)
		fmt.Fprintf(os.Stderr, "  Modified: %d\n", report.Proxy.RequestsModified)
	}

	if report.Server != nil {
		fmt.Fprintf(os.Stderr, "\nServer:\n")
		fmt.Fprintf(os.Stderr, "  Requests received: %d\n", report.Server.RequestsReceived)
		fmt.Fprintf(os.Stderr, "  Errors injected:   %d\n", report.Server.ErrorsInjected)
	}

	if len(report.FailureReasons) > 0 {
		fmt.Fprintf(os.Stderr, "\nFailure Reasons:\n")
		for _, r := range report.FailureReasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
	}

	fmt.Fprintf(os.Stderr, "\n")
}
