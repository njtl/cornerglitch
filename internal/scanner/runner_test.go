package scanner

import (
	"os"
	"path/filepath"
	"testing"
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
