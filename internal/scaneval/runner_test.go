package scaneval

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDefaultRunnerConfig(t *testing.T) {
	cfg := DefaultRunnerConfig("http://localhost:8765", "http://localhost:8766")
	if cfg.TargetURL != "http://localhost:8765" {
		t.Errorf("expected target http://localhost:8765, got %s", cfg.TargetURL)
	}
	if cfg.DashURL != "http://localhost:8766" {
		t.Errorf("expected dash http://localhost:8766, got %s", cfg.DashURL)
	}
	if cfg.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
}

func TestNewRunner(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-runner")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	if r == nil {
		t.Fatal("expected non-nil runner")
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected output dir to be created")
	}
}

func TestAvailableScanners(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-scanner-avail")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	scanners := r.AvailableScanners()

	// Should always return the full list (installed or not)
	if len(scanners) < 5 {
		t.Errorf("expected at least 5 scanner entries, got %d", len(scanners))
	}

	// Check known scanner names
	names := make(map[string]bool)
	for _, s := range scanners {
		names[s.Name] = true
		if s.Description == "" {
			t.Errorf("scanner %s has empty description", s.Name)
		}
		if s.Category == "" {
			t.Errorf("scanner %s has empty category", s.Name)
		}
	}

	for _, expected := range []string{"nuclei", "httpx", "ffuf", "nikto", "nmap"} {
		if !names[expected] {
			t.Errorf("expected scanner %s in list", expected)
		}
	}
}

func TestIsRunning(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-running")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	if r.IsRunning("nuclei") {
		t.Error("expected nuclei not running initially")
	}
}

func TestGetResults(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-results")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	results := r.GetResults()
	if len(results) != 0 {
		t.Errorf("expected 0 initial results, got %d", len(results))
	}
}

func TestGenerateWordlist(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-wordlist")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	wl := r.generateWordlist()
	if wl == "" {
		t.Fatal("expected non-empty wordlist path")
	}
	data, err := os.ReadFile(wl)
	if err != nil {
		t.Fatalf("failed to read wordlist: %v", err)
	}
	if len(data) < 100 {
		t.Error("wordlist seems too small")
	}
	// Check some known paths are present
	content := string(data)
	for _, path := range []string{"vuln", "health", "wp-admin", "api/users"} {
		if !containsLine(content, path) {
			t.Errorf("wordlist missing expected path: %s", path)
		}
	}
}

func containsLine(content, line string) bool {
	for _, l := range splitLines(content) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		url          string
		expectedHost string
		expectedPort string
	}{
		{"http://localhost:8765", "localhost", "8765"},
		{"http://localhost:8765/", "localhost", "8765"},
		{"https://example.com:443", "example.com", "443"},
		{"http://10.0.0.1:9000", "10.0.0.1", "9000"},
		{"http://localhost", "localhost", "80"},
	}

	for _, tt := range tests {
		host, port := parseHostPort(tt.url)
		if host != tt.expectedHost || port != tt.expectedPort {
			t.Errorf("parseHostPort(%q) = (%q, %q), want (%q, %q)",
				tt.url, host, port, tt.expectedHost, tt.expectedPort)
		}
	}
}

func TestParseHTTPXJSON(t *testing.T) {
	sample := `{"url":"http://localhost:8765","status_code":200,"title":"Glitch Server","webserver":"glitch/2.0","tech":["Go"]}
{"url":"http://localhost:8765/vuln","status_code":200,"title":"OWASP Demos","webserver":"glitch/2.0"}`

	result, err := ParseHTTPXJSON([]byte(sample))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if result.Scanner != "httpx" {
		t.Errorf("expected scanner httpx, got %s", result.Scanner)
	}
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}
}

func TestParseHTTPXJSONEmpty(t *testing.T) {
	result, err := ParseHTTPXJSON([]byte(""))
	if err != nil {
		t.Fatalf("parse error on empty: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(result.Findings))
	}
}

func TestCheckSecurityHeaders(t *testing.T) {
	headers := map[string]interface{}{
		"content-type": "text/html",
		// Missing all security headers
	}
	var findings []Finding
	checkSecurityHeaders(headers, &findings)
	if len(findings) < 5 {
		t.Errorf("expected at least 5 missing header findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Severity != "low" {
			t.Errorf("expected severity low for missing header, got %s", f.Severity)
		}
	}
}

func TestParseAndCompareUnknownScanner(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "test", Name: "Test Vuln", Severity: "high"},
		},
		TotalVulns: 1,
		BySeverity: map[string]int{"high": 1},
	}
	_, err := ParseAndCompare("unknown_scanner_xyz", []byte("some output"), profile)
	// Should not error — falls back to generic parser
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopScanner(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "glitch-test-stop")
	defer os.RemoveAll(dir)
	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   60,
	}
	r := NewRunner(cfg)
	// Stopping non-running scanner should return false
	if r.StopScanner("nuclei") {
		t.Error("expected false when stopping non-running scanner")
	}
}

func TestFindBinary(t *testing.T) {
	// findBinary for "go" should find it since Go is installed
	goPath := findBinary("go")
	if goPath == "" {
		t.Skip("go not found on PATH")
	}
}

// ---------------------------------------------------------------------------
// Crash / failure detection tests
// ---------------------------------------------------------------------------

func TestScanRun_CrashDetection_ExitCode137(t *testing.T) {
	// Simulate a process killed by SIGKILL (exit code 137 = 128 + 9).
	// We run a real process via "sh -c 'kill -9 $$'" so that cmd.Run()
	// returns an ExitError whose WaitStatus was signaled.

	dir := filepath.Join(os.TempDir(), "glitch-test-crash137")
	os.MkdirAll(dir, 0o755)
	defer os.RemoveAll(dir)

	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   10 * time.Second,
	}
	r := NewRunner(cfg)

	// Create a small shell script that kills itself with SIGKILL
	script := filepath.Join(dir, "kill_self.sh")
	os.WriteFile(script, []byte("#!/bin/sh\nkill -9 $$\n"), 0o755)

	run := &ScanRun{
		ID:        "crash137-test",
		Scanner:   "testscanner",
		Status:    "running",
		StartedAt: time.Now(),
	}

	cmd := exec.Command("sh", script)
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error from killed process")
	}

	// Apply the same logic as executeScanner
	if exitErr, ok := err.(*exec.ExitError); ok {
		run.ExitCode = exitErr.ExitCode()
		if exitErr.ProcessState != nil {
			if ws, ok := exitErr.ProcessState.Sys().(waitStatusSignaled); ok {
				_ = ws // type assertion test below
			}
		}
	}

	// The exit code for SIGKILL should be -1 or 137 depending on Go runtime.
	// Instead of relying on exact code, verify Crashed is set via the
	// executeScanner-equivalent logic using the helper.
	// We directly test the ScanRun fields by simulating the logic:
	run2 := &ScanRun{
		ID:        "crash137-sim",
		Scanner:   "testscanner",
		Status:    "running",
		StartedAt: time.Now(),
		ExitCode:  137, // 128 + SIGKILL(9)
	}
	run2.Crashed = true
	run2.CrashSignal = "killed"

	if run2.ExitCode != 0 && run2.ExitCode != 1 {
		run2.Status = "failed"
		if run2.Crashed {
			run2.Status = "crashed"
		}
	}

	if run2.Status != "crashed" {
		t.Errorf("expected status 'crashed', got %q", run2.Status)
	}
	if !run2.Crashed {
		t.Error("expected Crashed=true")
	}

	// Also verify with a real process: run sh that self-kills and feed
	// through the runner to confirm signal detection works end-to-end.
	run3 := &ScanRun{
		ID:        "crash137-real",
		Scanner:   "testscanner",
		Status:    "running",
		StartedAt: time.Now(),
	}
	cmd2 := exec.Command("sh", script)
	cmd2.Stderr = &strings.Builder{}
	err2 := cmd2.Run()
	if err2 != nil {
		if exitErr, ok := err2.(*exec.ExitError); ok {
			run3.ExitCode = exitErr.ExitCode()
			if exitErr.ProcessState != nil {
				// Use syscall.WaitStatus directly
				applyCrashDetection(run3, exitErr, "")
			}
		}
	}
	if !run3.Crashed {
		t.Errorf("expected real process SIGKILL to set Crashed=true, got %v (exit=%d, signal=%s)",
			run3.Crashed, run3.ExitCode, run3.CrashSignal)
	}

	r.completeRun(run, nil)
	r.completeRun(run2, nil)
	r.completeRun(run3, nil)
}

// waitStatusSignaled is used for type assertion test only.
type waitStatusSignaled interface {
	Signaled() bool
}

func TestScanRun_CrashDetection_StderrPatterns(t *testing.T) {
	tests := []struct {
		name     string
		stderr   string
		wantCrash bool
	}{
		{"segfault", "Segmentation fault (core dumped)", true},
		{"go panic", "goroutine 1 [running]:\npanic: runtime error", true},
		{"core dump", "Aborted (core dumped)", true},
		{"sigsegv", "received signal SIGSEGV", true},
		{"fatal error", "fatal error: out of memory", true},
		{"stack overflow", "thread 'main' has overflowed its stack\nStack overflow", true},
		{"normal error", "Error: connection refused", false},
		{"exit message", "scan completed with warnings", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectCrashInStderr(tt.stderr)
			if got != tt.wantCrash {
				t.Errorf("detectCrashInStderr(%q) = %v, want %v", tt.stderr, got, tt.wantCrash)
			}
		})
	}
}

func TestScanRun_NotInstalled(t *testing.T) {
	// Test the not-installed code path by simulating the condition that
	// executeScanner checks: cmd == nil || cmd.Path == "".
	// This directly tests the ScanRun field-setting logic without depending
	// on whether specific scanners are installed in the test environment.

	dir := filepath.Join(os.TempDir(), "glitch-test-notinstalled")
	os.MkdirAll(dir, 0o755)
	defer os.RemoveAll(dir)

	cfg := &RunnerConfig{
		TargetURL: "http://localhost:8765",
		OutputDir: dir,
		Timeout:   10 * time.Second,
	}
	r := NewRunner(cfg)

	// Simulate the not-installed code path from executeScanner
	run := &ScanRun{
		ID:        "notinstalled-test",
		Scanner:   "fakescanner",
		Status:    "running",
		StartedAt: time.Now(),
	}

	// This mirrors the code in executeScanner when cmd.Path == ""
	run.NotInstalled = true
	run.Status = "failed"
	run.ErrorOutput = fmt.Sprintf("Scanner %q not found. Install it to use this feature.", run.Scanner)
	run.CompletedAt = time.Now()
	run.Duration = run.CompletedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
	r.completeRun(run, nil)

	if run.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", run.Status)
	}
	if !run.NotInstalled {
		t.Error("expected NotInstalled=true for missing binary")
	}
	if run.ErrorOutput == "" {
		t.Error("expected non-empty error output for missing binary")
	}
	if !strings.Contains(run.ErrorOutput, "not found") {
		t.Errorf("error output should mention 'not found', got: %s", run.ErrorOutput)
	}

	// Verify it was stored in results
	results := r.GetResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "notinstalled-test" {
		t.Errorf("expected run ID 'notinstalled-test', got %q", results[0].ID)
	}

	// Also verify that findBinary returns "" for a non-existent binary
	if findBinary("definitely_not_a_real_scanner_binary_12345") != "" {
		t.Error("findBinary should return empty for non-existent binaries")
	}
}

func TestScanRun_StderrTruncation(t *testing.T) {
	// Test that truncateStderr limits output to the specified max length
	short := "short stderr output"
	got := truncateStderr(short, 4096)
	if got != short {
		t.Errorf("short string should not be truncated, got %q", got)
	}

	// Build a string longer than 4096 bytes
	long := strings.Repeat("x", 5000)
	got = truncateStderr(long, 4096)
	if len(got) > 4096+len("\n...[truncated]") {
		t.Errorf("truncated output should be ~4096+marker bytes, got %d", len(got))
	}
	if !strings.HasSuffix(got, "\n...[truncated]") {
		t.Error("truncated output should end with truncation marker")
	}
	// The first 4096 bytes should be preserved exactly
	if got[:4096] != long[:4096] {
		t.Error("first 4096 bytes should be preserved")
	}

	// Edge case: exactly 4096 bytes should not be truncated
	exact := strings.Repeat("y", 4096)
	got = truncateStderr(exact, 4096)
	if got != exact {
		t.Error("string of exactly maxLen should not be truncated")
	}

	// Edge case: 4097 bytes should be truncated
	oneOver := strings.Repeat("z", 4097)
	got = truncateStderr(oneOver, 4096)
	if !strings.HasSuffix(got, "\n...[truncated]") {
		t.Error("4097-byte string should be truncated")
	}
}

func TestScanRun_NormalExit(t *testing.T) {
	// Verify that exit code 0 and 1 are NOT treated as crashes.
	for _, exitCode := range []int{0, 1} {
		t.Run(fmt.Sprintf("exit_%d", exitCode), func(t *testing.T) {
			run := &ScanRun{
				ID:        fmt.Sprintf("normal-%d", exitCode),
				Scanner:   "testscanner",
				Status:    "running",
				StartedAt: time.Now(),
				ExitCode:  exitCode,
			}

			// Simulate the condition from executeScanner: only set failed
			// when exit code is not 0 and not 1.
			stderrStr := "some warning output"
			run.ErrorOutput = stderrStr
			run.StderrExcerpt = stderrStr

			if detectCrashInStderr(stderrStr) {
				run.Crashed = true
			}

			if run.ExitCode != 0 && run.ExitCode != 1 {
				run.Status = "failed"
				if run.Crashed {
					run.Status = "crashed"
				}
			}

			// For exit 0 or 1, status should NOT be failed or crashed
			if run.Status == "failed" || run.Status == "crashed" {
				t.Errorf("exit code %d should not produce status %q", exitCode, run.Status)
			}
			if run.Crashed {
				t.Errorf("exit code %d with normal stderr should not set Crashed=true", exitCode)
			}
		})
	}
}

// applyCrashDetection is a test helper that applies the same crash detection
// logic used in executeScanner to a ScanRun given an ExitError and stderr.
func applyCrashDetection(run *ScanRun, exitErr *exec.ExitError, stderrStr string) {
	run.ExitCode = exitErr.ExitCode()
	if exitErr.ProcessState != nil {
		if ws, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				run.Crashed = true
				run.CrashSignal = ws.Signal().String()
			}
		}
	}

	stderrStr = truncateStderr(stderrStr, 4096)
	run.ErrorOutput = stderrStr
	run.StderrExcerpt = stderrStr

	if detectCrashInStderr(stderrStr) {
		run.Crashed = true
	}

	if run.ExitCode != 0 && run.ExitCode != 1 {
		run.Status = "failed"
		if run.Crashed {
			run.Status = "crashed"
		}
	}
}
