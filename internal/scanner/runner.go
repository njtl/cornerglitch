package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Scanner runner — executes external security tools and collects output
// ---------------------------------------------------------------------------

// RunnerConfig holds configuration for scanner execution.
type RunnerConfig struct {
	TargetURL   string        // e.g. "http://localhost:8765"
	DashURL     string        // e.g. "http://localhost:8766"
	OutputDir   string        // directory to store raw scanner output
	Timeout     time.Duration // max time per scanner
	Concurrency int           // max parallel scanners
}

// DefaultRunnerConfig returns sensible defaults.
func DefaultRunnerConfig(targetURL, dashURL string) *RunnerConfig {
	return &RunnerConfig{
		TargetURL:   targetURL,
		DashURL:     dashURL,
		OutputDir:   "/tmp/glitch-scanner-results",
		Timeout:     5 * time.Minute,
		Concurrency: 2,
	}
}

// Runner manages scanner execution and result collection.
type Runner struct {
	mu      sync.Mutex
	config  *RunnerConfig
	results []*ScanRun
	running map[string]*ScanRun // scanner name -> active run
}

// ScanRun tracks a single scanner execution.
type ScanRun struct {
	ID          string        `json:"id"`
	Scanner     string        `json:"scanner"`
	Status      string        `json:"status"` // pending, running, completed, failed, timeout
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at,omitempty"`
	Duration    string        `json:"duration,omitempty"`
	ExitCode    int           `json:"exit_code"`
	OutputFile  string        `json:"output_file"`
	ErrorOutput string        `json:"error_output,omitempty"`
	Result      *ScanResult   `json:"result,omitempty"`
	Comparison  *ComparisonReport `json:"comparison,omitempty"`
	cancel      context.CancelFunc
}

// NewRunner creates a new scanner runner.
func NewRunner(config *RunnerConfig) *Runner {
	os.MkdirAll(config.OutputDir, 0o755)
	return &Runner{
		config:  config,
		results: make([]*ScanRun, 0),
		running: make(map[string]*ScanRun),
	}
}

// AvailableScanners returns a list of scanners that are installed and usable.
func (r *Runner) AvailableScanners() []ScannerInfo {
	scanners := []ScannerInfo{
		{Name: "nuclei", Description: "Template-based vulnerability scanner (ProjectDiscovery)", Category: "vuln"},
		{Name: "httpx", Description: "HTTP probing and header analysis", Category: "recon"},
		{Name: "ffuf", Description: "Web fuzzer for directory/endpoint discovery", Category: "fuzzer"},
		{Name: "nikto", Description: "Web server vulnerability scanner", Category: "vuln"},
		{Name: "nmap", Description: "Network/port scanner with NSE scripts", Category: "network"},
	}

	var available []ScannerInfo
	for _, s := range scanners {
		if path := findBinary(s.Name); path != "" {
			s.Installed = true
			s.Path = path
			s.Version = getVersion(s.Name, path)
			available = append(available, s)
		} else {
			s.Installed = false
			available = append(available, s)
		}
	}
	return available
}

// ScannerInfo describes an available scanner tool.
type ScannerInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Installed   bool   `json:"installed"`
	Path        string `json:"path,omitempty"`
	Version     string `json:"version,omitempty"`
}

// RunScanner starts a scanner asynchronously. Returns the run ID.
func (r *Runner) RunScanner(scannerName string, profile *ExpectedProfile) (string, error) {
	r.mu.Lock()
	if _, ok := r.running[scannerName]; ok {
		r.mu.Unlock()
		return "", fmt.Errorf("scanner %q is already running", scannerName)
	}

	runID := fmt.Sprintf("%s-%d", scannerName, time.Now().UnixMilli())
	run := &ScanRun{
		ID:        runID,
		Scanner:   scannerName,
		Status:    "running",
		StartedAt: time.Now(),
	}
	r.running[scannerName] = run
	r.mu.Unlock()

	go r.executeScanner(run, profile)
	return runID, nil
}

// GetResults returns all completed scan runs.
func (r *Runner) GetResults() []*ScanRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*ScanRun, len(r.results))
	copy(out, r.results)
	return out
}

// GetRunning returns currently running scanners.
func (r *Runner) GetRunning() map[string]*ScanRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*ScanRun)
	for k, v := range r.running {
		out[k] = v
	}
	return out
}

// IsRunning checks if a specific scanner is currently executing.
func (r *Runner) IsRunning(scanner string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.running[scanner]
	return ok
}

// StopScanner cancels a running scanner.
func (r *Runner) StopScanner(scanner string) bool {
	r.mu.Lock()
	run, ok := r.running[scanner]
	r.mu.Unlock()
	if ok && run.cancel != nil {
		run.cancel()
		return true
	}
	return false
}

func (r *Runner) executeScanner(run *ScanRun, profile *ExpectedProfile) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	run.cancel = cancel
	defer cancel()

	outputFile := filepath.Join(r.config.OutputDir, run.ID)
	run.OutputFile = outputFile

	var cmd *exec.Cmd
	var parseFunc func([]byte) (*ScanResult, error)

	switch run.Scanner {
	case "nuclei":
		outFile := outputFile + ".json"
		run.OutputFile = outFile
		cmd = exec.CommandContext(ctx, findBinary("nuclei"),
			"-u", r.config.TargetURL,
			"-severity", "critical,high,medium,low,info",
			"-jsonl", "-o", outFile,
			"-silent",
			"-timeout", "10",
			"-retries", "0",
			"-rl", "100",
			"-duc",
		)
		parseFunc = ParseNucleiJSON

	case "httpx":
		outFile := outputFile + ".json"
		run.OutputFile = outFile
		cmd = exec.CommandContext(ctx, findBinary("httpx"),
			"-u", r.config.TargetURL,
			"-json",
			"-o", outFile,
			"-title",
			"-server",
			"-tech-detect",
			"-status-code",
			"-content-length",
			"-include-response-header",
			"-follow-redirects",
			"-silent",
		)
		parseFunc = ParseHTTPXJSON

	case "ffuf":
		outFile := outputFile + ".json"
		run.OutputFile = outFile
		wordlist := r.generateWordlist()
		cmd = exec.CommandContext(ctx, findBinary("ffuf"),
			"-u", r.config.TargetURL+"/FUZZ",
			"-w", wordlist,
			"-mc", "200,301,302,307,401,403,500",
			"-o", outFile,
			"-of", "json",
			"-t", "20",
			"-rate", "100",
			"-s",
		)
		parseFunc = ParseFFufJSON

	case "nikto":
		outFile := outputFile + ".json"
		run.OutputFile = outFile
		niktoPath := findBinary("nikto")
		if niktoPath == "" {
			// Try the cloned git repo
			niktoPath = "/tmp/nikto/program/nikto.pl"
		}
		cmd = exec.CommandContext(ctx, "perl", niktoPath,
			"-h", r.config.TargetURL,
			"-o", outFile,
			"-Format", "json",
			"-maxtime", "300s",
			"-nointeractive",
		)
		parseFunc = ParseNiktoJSON

	case "nmap":
		outFile := outputFile + ".xml"
		run.OutputFile = outFile
		// Extract host and port from URL
		host, port := parseHostPort(r.config.TargetURL)
		cmd = exec.CommandContext(ctx, findBinary("nmap"),
			"-sV", "-sC",
			"-p", port,
			"--script=http-enum,http-headers,http-methods,http-title,http-server-header",
			"-oX", outFile,
			host,
		)
		parseFunc = ParseNmapXML

	default:
		r.finishRun(run, fmt.Errorf("unknown scanner: %s", run.Scanner))
		return
	}

	if cmd == nil || cmd.Path == "" {
		r.finishRun(run, fmt.Errorf("scanner %q not found on PATH", run.Scanner))
		return
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Also capture stdout for scanners that write to stdout
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()

	run.CompletedAt = time.Now()
	run.Duration = run.CompletedAt.Sub(run.StartedAt).Round(time.Millisecond).String()

	if ctx.Err() == context.DeadlineExceeded {
		run.Status = "timeout"
		run.ErrorOutput = "Scanner timed out after " + r.config.Timeout.String()
		r.completeRun(run, nil)
		return
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			run.ExitCode = exitErr.ExitCode()
		}
		run.ErrorOutput = stderr.String()
		if run.ExitCode != 0 && run.ExitCode != 1 {
			// Many scanners exit 1 when they find vulns, that's OK
			run.Status = "failed"
		}
	}

	// Parse the output
	if parseFunc != nil {
		data, readErr := os.ReadFile(run.OutputFile)
		if readErr != nil {
			// Maybe output was on stdout instead
			data = stdout.Bytes()
		}
		if len(data) > 0 {
			result, parseErr := parseFunc(data)
			if parseErr != nil {
				run.ErrorOutput += "\nParse error: " + parseErr.Error()
			} else {
				result.Scanner = run.Scanner
				result.StartedAt = run.StartedAt
				result.CompletedAt = run.CompletedAt
				result.Duration = run.CompletedAt.Sub(run.StartedAt)
				result.ExitCode = run.ExitCode
				if ctx.Err() == context.DeadlineExceeded {
					result.TimedOut = true
				}
				run.Result = result

				// Compare against profile if we have one
				if profile != nil {
					run.Comparison = CompareResults(profile, result)
				}
			}
		}
	}

	if run.Status != "timeout" && run.Status != "failed" {
		run.Status = "completed"
	}

	r.completeRun(run, nil)
}

func (r *Runner) finishRun(run *ScanRun, err error) {
	run.CompletedAt = time.Now()
	run.Duration = run.CompletedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
	if err != nil {
		run.Status = "failed"
		run.ErrorOutput = err.Error()
	}
	r.completeRun(run, nil)
}

func (r *Runner) completeRun(run *ScanRun, _ error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, run.Scanner)
	r.results = append(r.results, run)
}

// generateWordlist creates a wordlist file for ffuf based on known server paths.
func (r *Runner) generateWordlist() string {
	paths := []string{
		// Standard paths
		"", "index.html", "robots.txt", "sitemap.xml", ".env", "favicon.ico",
		// Health
		"health", "status", "ping", "metrics", "debug/vars",
		// API
		"api/users", "api/products", "api/categories", "api/posts",
		"api/search", "api/graphql", "api/swagger.json", "openapi.json",
		// Auth
		"oauth/authorize", "oauth/token", ".well-known/openid-configuration",
		"saml/metadata",
		// OWASP vulns
		"vuln", "vuln/a01", "vuln/a02", "vuln/a03", "vuln/a04", "vuln/a05",
		"vuln/a06", "vuln/a07", "vuln/a08", "vuln/a09", "vuln/a10",
		// Advanced vulns
		"vuln/cors/reflect", "vuln/redirect", "vuln/xxe/parse", "vuln/ssti/render",
		"vuln/crlf/set", "vuln/host/reset", "vuln/verb/admin", "vuln/hpp/transfer",
		"vuln/upload/form", "vuln/cmd/ping", "vuln/graphql/introspection",
		"vuln/jwt/none", "vuln/race/coupon", "vuln/deserialize/java", "vuln/path/traverse",
		// Dashboard vulns
		"vuln/dashboard", "vuln/dashboard/debug", "vuln/dashboard/phpinfo",
		"vuln/dashboard/server-status", "vuln/dashboard/api-keys",
		"vuln/dashboard/users", "vuln/dashboard/users/export",
		"vuln/dashboard/backup/download", "vuln/dashboard/debug/env",
		"vuln/dashboard/debug/routes", "vuln/dashboard/debug/sql",
		"vuln/dashboard/debug/sessions", "vuln/dashboard/debug/cache",
		// Settings vulns
		"vuln/settings", "vuln/settings/database", "vuln/settings/email",
		"vuln/settings/integrations", "vuln/settings/audit",
		"vuln/settings/flags", "vuln/settings/credentials",
		"vuln/settings/certificates", "vuln/settings/tokens",
		// Honeypot
		"wp-admin", "wp-login.php", "administrator", "phpmyadmin",
		".git/HEAD", ".git/config", ".svn/entries", "server-status",
		"wp-content/debug.log", ".htaccess", "web.config",
		"backup.sql", "dump.sql", "db.sql",
		// Common dirs
		"admin", "login", "register", "dashboard", "console",
		"config", "backup", "test", "debug", "internal",
		// Labyrinth
		"articles/tech/deep-learning",
		"docs/api/v2/reference",
		"products/category/featured",
		// Email
		"email/inbox", "email/compose",
		// Search
		"search",
		// CDN
		"static/js/app.js", "static/css/main.css",
		// Captcha
		"captcha/challenge", "captcha/verify",
		// Analytics
		"analytics/beacon", "analytics/pixel.gif",
		// Privacy
		"privacy", "privacy/consent",
		// i18n
		"es/", "fr/", "de/", "ja/",
		// Websocket
		"ws/echo", "ws/chat",
		// Recorder
		"recorder/sessions",
	}

	wordlistFile := filepath.Join(r.config.OutputDir, "glitch-wordlist.txt")
	content := strings.Join(paths, "\n")
	os.WriteFile(wordlistFile, []byte(content), 0o644)
	return wordlistFile
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findBinary(name string) string {
	// Check common locations
	locations := []string{
		filepath.Join(os.Getenv("HOME"), "go", "bin", name),
		filepath.Join("/usr/local/bin", name),
		filepath.Join("/usr/bin", name),
		filepath.Join("/tmp/nikto/program", name+".pl"),
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}
	// Try PATH
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func getVersion(name, path string) string {
	var cmd *exec.Cmd
	switch name {
	case "nuclei":
		cmd = exec.Command(path, "-version")
	case "httpx":
		cmd = exec.Command(path, "-version")
	case "ffuf":
		cmd = exec.Command(path, "-V")
	case "nmap":
		cmd = exec.Command(path, "--version")
	case "nikto":
		cmd = exec.Command("perl", path, "-Version")
	default:
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	// Return first line
	lines := strings.SplitN(string(out), "\n", 2)
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

func parseHostPort(targetURL string) (host, port string) {
	// Strip scheme
	u := targetURL
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	// Split host:port
	parts := strings.SplitN(u, ":", 2)
	host = parts[0]
	if len(parts) > 1 {
		port = strings.TrimRight(parts[1], "/")
	} else {
		port = "80"
	}
	return
}

// ParseHTTPXJSON parses httpx JSON output into a ScanResult.
func ParseHTTPXJSON(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner: "httpx",
	}

	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		url, _ := entry["url"].(string)
		statusCode := 0
		if sc, ok := entry["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		title, _ := entry["title"].(string)
		server, _ := entry["webserver"].(string)
		tech, _ := entry["tech"].([]interface{})

		finding := Finding{
			Title:    fmt.Sprintf("HTTP %d: %s", statusCode, title),
			URL:      url,
			Severity: "info",
		}

		if server != "" {
			finding.Description = "Server: " + server
			finding.Evidence = server
		}

		if len(tech) > 0 {
			techs := make([]string, 0, len(tech))
			for _, t := range tech {
				if s, ok := t.(string); ok {
					techs = append(techs, s)
				}
			}
			finding.Description += " | Tech: " + strings.Join(techs, ", ")
		}

		// Check response headers for security issues
		if headers, ok := entry["header"].(map[string]interface{}); ok {
			checkSecurityHeaders(headers, &result.Findings)
		}

		result.Findings = append(result.Findings, finding)
	}

	return result, nil
}

func checkSecurityHeaders(headers map[string]interface{}, findings *[]Finding) {
	secHeaders := map[string]string{
		"x-frame-options":        "Missing X-Frame-Options header",
		"x-content-type-options": "Missing X-Content-Type-Options header",
		"strict-transport-security": "Missing Strict-Transport-Security header",
		"content-security-policy":   "Missing Content-Security-Policy header",
		"x-xss-protection":         "Missing X-XSS-Protection header",
		"referrer-policy":           "Missing Referrer-Policy header",
		"permissions-policy":        "Missing Permissions-Policy header",
	}

	for header, desc := range secHeaders {
		if _, ok := headers[header]; !ok {
			*findings = append(*findings, Finding{
				Title:       desc,
				Severity:    "low",
				Description: "The response is missing the " + header + " security header",
				CWE:         "CWE-693",
			})
		}
	}
}

// RunAllScanners runs all available scanners sequentially and returns results.
func (r *Runner) RunAllScanners(profile *ExpectedProfile) []*ScanRun {
	scanners := r.AvailableScanners()
	var runs []*ScanRun

	for _, s := range scanners {
		if !s.Installed {
			continue
		}
		runID, err := r.RunScanner(s.Name, profile)
		if err != nil {
			continue
		}
		// Wait for completion
		for {
			time.Sleep(2 * time.Second)
			if !r.IsRunning(s.Name) {
				break
			}
		}
		// Get the result
		for _, result := range r.GetResults() {
			if result.ID == runID {
				runs = append(runs, result)
				break
			}
		}
	}

	return runs
}

// ParseAndCompare takes raw scanner output, parses it, and compares against a profile.
func ParseAndCompare(scannerName string, data []byte, profile *ExpectedProfile) (*ComparisonReport, error) {
	var result *ScanResult
	var err error

	switch scannerName {
	case "nuclei":
		result, err = ParseNucleiJSON(data)
	case "nikto":
		result, err = ParseNiktoJSON(data)
	case "nmap":
		result, err = ParseNmapXML(data)
	case "ffuf":
		result, err = ParseFFufJSON(data)
	case "httpx":
		result, err = ParseHTTPXJSON(data)
	default:
		result, err = ParseGenericText(scannerName, data)
	}

	if err != nil {
		return nil, fmt.Errorf("parse error for %s: %w", scannerName, err)
	}

	report := CompareResults(profile, result)
	return report, nil
}
