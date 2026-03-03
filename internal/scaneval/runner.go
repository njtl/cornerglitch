package scaneval

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
	"syscall"
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
	mu         sync.Mutex
	config     *RunnerConfig
	results    []*ScanRun
	running    map[string]*ScanRun // scanner name -> active run
	OnComplete func(run *ScanRun)  // called after each run completes (for persistence)
}

// ScanRun tracks a single scanner execution.
type ScanRun struct {
	ID            string            `json:"id"`
	Scanner       string            `json:"scanner"`
	Status        string            `json:"status"` // pending, running, completed, failed, timeout, crashed
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   time.Time         `json:"completed_at,omitempty"`
	Duration      string            `json:"duration,omitempty"`
	ExitCode      int               `json:"exit_code"`
	OutputFile    string            `json:"output_file"`
	ErrorOutput   string            `json:"error_output,omitempty"`
	Result        *ScanResult       `json:"result,omitempty"`
	Comparison    *ComparisonReport `json:"comparison,omitempty"`
	Crashed       bool              `json:"crashed,omitempty"`
	CrashSignal   string            `json:"crash_signal,omitempty"`   // "SIGSEGV", "SIGKILL", etc.
	StderrExcerpt string            `json:"stderr_excerpt,omitempty"` // truncated to 4KB
	NotInstalled  bool              `json:"not_installed,omitempty"`  // binary not found
	cancel        context.CancelFunc
}

// NewRunner creates a new scanner runner.
// It eagerly discovers available scanners in the background so the first
// API request doesn't block on subprocess calls (e.g. wapiti --version ~2s).
func NewRunner(config *RunnerConfig) *Runner {
	os.MkdirAll(config.OutputDir, 0o755)
	r := &Runner{
		config:  config,
		results: make([]*ScanRun, 0),
		running: make(map[string]*ScanRun),
	}
	// Warm the scanner cache in a background goroutine.
	go r.AvailableScanners()
	return r
}

// AvailableScanners returns a list of scanners that are installed and usable.
// Results are cached on first call since installed binaries don't change at runtime.
func (r *Runner) AvailableScanners() []ScannerInfo {
	scannerCacheOnce.Do(func() {
		scanners := []ScannerInfo{
			{Name: "nuclei", Description: "Template-based vulnerability scanner (ProjectDiscovery)", Category: "vuln"},
			{Name: "httpx", Description: "HTTP probing and header analysis", Category: "recon"},
			{Name: "ffuf", Description: "Web fuzzer for directory/endpoint discovery", Category: "fuzzer"},
			{Name: "nikto", Description: "Web server vulnerability scanner", Category: "vuln"},
			{Name: "nmap", Description: "Network/port scanner with NSE scripts", Category: "network"},
			{Name: "wapiti", Description: "Web application vulnerability scanner", Category: "vuln"},
		}

		var available []ScannerInfo
		for _, s := range scanners {
			path := findBinary(s.Name)
			// wapiti may be installed as wapiti3
			if path == "" && s.Name == "wapiti" {
				path = findBinary("wapiti3")
			}
			if path != "" {
				s.Installed = true
				s.Path = path
				s.Version = getVersion(s.Name, path)
				available = append(available, s)
			} else {
				s.Installed = false
				available = append(available, s)
			}
		}
		scannerCacheResult = available
	})
	return scannerCacheResult
}

var (
	scannerCacheOnce   sync.Once
	scannerCacheResult []ScannerInfo
)

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

	case "wapiti":
		outFile := outputFile + ".json"
		run.OutputFile = outFile
		wapitiPath := findBinary("wapiti")
		if wapitiPath == "" {
			wapitiPath = findBinary("wapiti3")
		}
		cmd = exec.CommandContext(ctx, wapitiPath,
			"-u", r.config.TargetURL,
			"-f", "json",
			"-o", outFile,
			"--flush-session",
			"-m", "all",
			"--scope", "folder",
			"-t", "10",
		)
		parseFunc = ParseWapitiJSON

	default:
		r.finishRun(run, fmt.Errorf("unknown scanner: %s", run.Scanner))
		return
	}

	if cmd == nil || cmd.Path == "" {
		run.NotInstalled = true
		run.Status = "failed"
		run.ErrorOutput = fmt.Sprintf("Scanner %q not found. Install it to use this feature.", run.Scanner)
		run.CompletedAt = time.Now()
		run.Duration = run.CompletedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
		r.completeRun(run, nil)
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
			// Check for signal kill (SIGSEGV, SIGKILL, etc.)
			if exitErr.ProcessState != nil {
				if ws, ok := exitErr.ProcessState.Sys().(syscall.WaitStatus); ok {
					if ws.Signaled() {
						run.Crashed = true
						run.CrashSignal = ws.Signal().String()
					}
				}
			}
		}
		// Truncate stderr to 4KB
		stderrStr := truncateStderr(stderr.String(), 4096)
		run.ErrorOutput = stderrStr
		run.StderrExcerpt = stderrStr

		// Detect crash patterns in stderr
		if detectCrashInStderr(stderrStr) {
			run.Crashed = true
		}

		if run.ExitCode != 0 && run.ExitCode != 1 {
			// Many scanners exit 1 when they find vulns, that's OK
			run.Status = "failed"
			if run.Crashed {
				run.Status = "crashed"
			}
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
				if run.Crashed {
					result.Crashed = true
					result.CrashSignal = run.CrashSignal
					result.CrashStderr = run.StderrExcerpt
				}
				run.Result = result

				// Compare against profile if we have one
				if profile != nil {
					run.Comparison = CompareResults(profile, result)
				}
			}
		}
	}

	if run.Status != "timeout" && run.Status != "failed" && run.Status != "crashed" {
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
	delete(r.running, run.Scanner)
	r.results = append(r.results, run)
	cb := r.OnComplete
	r.mu.Unlock()
	if cb != nil {
		cb(run)
	}
}

// AddResult adds a previously-completed run (e.g. loaded from DB).
func (r *Runner) AddResult(run *ScanRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, run)
}

// ClearHistory removes all stored scan run results.
func (r *Runner) ClearHistory() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = nil
}

// generateWordlist creates a wordlist file for ffuf based on known server paths.
func (r *Runner) generateWordlist() string {
	paths := []string{
		// Standard paths
		"", "index.html", "index.php", "index.asp", "index.jsp",
		"robots.txt", "sitemap.xml", "sitemap_index.xml", "crossdomain.xml",
		".env", ".env.bak", ".env.local", ".env.production",
		"favicon.ico", "humans.txt", "security.txt", ".well-known/security.txt",

		// Health and status
		"health", "healthz", "health/live", "health/ready",
		"status", "ping", "version", "info",
		"metrics", "metrics/prometheus", "debug/vars", "debug/pprof",

		// API endpoints (versioned)
		"api", "api/v1", "api/v2", "api/v3",
		"api/users", "api/v1/users", "api/v2/users",
		"api/users/1", "api/users/me", "api/users/admin",
		"api/products", "api/v1/products", "api/products/1",
		"api/categories", "api/v1/categories",
		"api/posts", "api/v1/posts", "api/posts/1",
		"api/search", "api/v1/search",
		"api/graphql", "graphql", "graphql/console", "graphiql",
		"api/swagger.json", "api/swagger.yaml", "swagger.json", "swagger-ui",
		"openapi.json", "openapi.yaml", "api-docs", "api/docs",
		"api/config", "api/health", "api/status", "api/info",
		"api/debug", "api/admin", "api/token", "api/auth",
		"api/login", "api/register", "api/logout",
		"api/upload", "api/download", "api/export", "api/import",
		"api/i18n/languages",

		// Auth and OAuth
		"login", "logout", "register", "signup", "signin",
		"oauth/authorize", "oauth/token", "oauth/callback",
		".well-known/openid-configuration", ".well-known/jwks.json",
		"saml/metadata", "saml/login", "saml/acs",
		"auth/login", "auth/callback", "auth/token",
		"sso/login", "sso/callback",

		// OWASP Top 10 vulns (index + sub-paths)
		"vuln", "vuln/",
		"vuln/a01", "vuln/a01/", "vuln/a01/admin", "vuln/a01/idor",
		"vuln/a01/privilege-escalation", "vuln/a01/force-browse",
		"vuln/a02", "vuln/a02/", "vuln/a02/login", "vuln/a02/default-creds",
		"vuln/a02/weak-password", "vuln/a02/hardcoded",
		"vuln/a03", "vuln/a03/", "vuln/a03/sqli", "vuln/a03/xss",
		"vuln/a03/xss/stored", "vuln/a03/xss/reflected", "vuln/a03/xss/dom",
		"vuln/a03/inject", "vuln/a03/ldap", "vuln/a03/nosql",
		"vuln/a04", "vuln/a04/", "vuln/a04/mass-assign", "vuln/a04/insecure-design",
		"vuln/a05", "vuln/a05/", "vuln/a05/misconfig", "vuln/a05/headers",
		"vuln/a05/cors", "vuln/a05/debug", "vuln/a05/default",
		"vuln/a06", "vuln/a06/", "vuln/a06/outdated", "vuln/a06/cve",
		"vuln/a07", "vuln/a07/", "vuln/a07/auth-bypass", "vuln/a07/session",
		"vuln/a07/brute-force",
		"vuln/a08", "vuln/a08/", "vuln/a08/integrity", "vuln/a08/deserialization",
		"vuln/a09", "vuln/a09/", "vuln/a09/logging", "vuln/a09/monitoring",
		"vuln/a10", "vuln/a10/", "vuln/a10/ssrf", "vuln/a10/ssrf/fetch",

		// API Security Top 10
		"vuln/api1", "vuln/api1/", "vuln/api1/bola",
		"vuln/api2", "vuln/api2/", "vuln/api2/auth",
		"vuln/api3", "vuln/api3/", "vuln/api3/property",
		"vuln/api4", "vuln/api4/", "vuln/api4/resource",
		"vuln/api5", "vuln/api5/", "vuln/api5/bfla",
		"vuln/api6", "vuln/api6/", "vuln/api6/mass-assign",
		"vuln/api7", "vuln/api7/", "vuln/api7/misconfig",
		"vuln/api8", "vuln/api8/", "vuln/api8/injection",
		"vuln/api9", "vuln/api9/", "vuln/api9/inventory",
		"vuln/api10", "vuln/api10/", "vuln/api10/consumption",

		// Advanced vuln endpoints
		"vuln/cors/reflect", "vuln/cors/wildcard", "vuln/cors/null",
		"vuln/redirect", "vuln/redirect/open", "vuln/redirect/param",
		"vuln/xxe/parse", "vuln/xxe/upload",
		"vuln/ssti/render", "vuln/ssti/eval",
		"vuln/crlf/set", "vuln/crlf/header",
		"vuln/host/reset", "vuln/host/route",
		"vuln/verb/admin", "vuln/verb/debug",
		"vuln/hpp/transfer", "vuln/hpp/search",
		"vuln/upload/form", "vuln/upload/avatar",
		"vuln/cmd/ping", "vuln/cmd/exec",
		"vuln/graphql/introspection", "vuln/graphql/query",
		"vuln/jwt/none", "vuln/jwt/weak", "vuln/jwt/kid",
		"vuln/race/coupon", "vuln/race/transfer",
		"vuln/deserialize/java", "vuln/deserialize/php",
		"vuln/path/traverse", "vuln/path/read",
		"vuln/cache/poison", "vuln/cache/deception",
		"vuln/prototype/pollution",
		"vuln/clickjack/frame",
		"vuln/websocket/hijack",

		// Dashboard/admin vuln surfaces
		"vuln/dashboard", "vuln/dashboard/",
		"vuln/dashboard/debug", "vuln/dashboard/phpinfo",
		"vuln/dashboard/server-status", "vuln/dashboard/api-keys",
		"vuln/dashboard/users", "vuln/dashboard/users/export",
		"vuln/dashboard/backup/download", "vuln/dashboard/debug/env",
		"vuln/dashboard/debug/routes", "vuln/dashboard/debug/sql",
		"vuln/dashboard/debug/sessions", "vuln/dashboard/debug/cache",
		"vuln/dashboard/debug/config",

		// Settings vuln surfaces
		"vuln/settings", "vuln/settings/",
		"vuln/settings/database", "vuln/settings/email",
		"vuln/settings/integrations", "vuln/settings/audit",
		"vuln/settings/flags", "vuln/settings/credentials",
		"vuln/settings/certificates", "vuln/settings/tokens",
		"vuln/settings/api-keys", "vuln/settings/webhooks",

		// Infrastructure vulns
		"vuln/infra", "vuln/infra/", "vuln/infra/aws",
		"vuln/infra/docker", "vuln/infra/k8s",

		// IoT/Desktop/Mobile vulns
		"vuln/iot", "vuln/iot/", "vuln/mobile", "vuln/mobile/",

		// Modern vulns
		"vuln/modern", "vuln/modern/", "vuln/modern/graphql",
		"vuln/modern/websocket", "vuln/modern/grpc",

		// Specialized vulns
		"vuln/specialized", "vuln/specialized/",

		// Honeypot paths
		"wp-admin", "wp-admin/", "wp-login.php", "wp-content", "wp-includes",
		"wp-content/debug.log", "wp-content/uploads", "wp-config.php",
		"administrator", "administrator/", "phpmyadmin", "phpmyadmin/",
		"adminer", "adminer.php", "phpinfo.php", "info.php",
		".git/HEAD", ".git/config", ".git/objects", ".gitignore",
		".svn/entries", ".svn/wc.db", ".hg/store",
		"server-status", "server-info",
		".htaccess", ".htpasswd", "web.config", "web.xml",
		"backup.sql", "dump.sql", "db.sql", "database.sql",
		"backup.tar.gz", "backup.zip", "site.tar.gz",
		".DS_Store", "Thumbs.db",
		"composer.json", "package.json", "Gemfile", "requirements.txt",
		"Dockerfile", "docker-compose.yml", ".dockerignore",
		"Makefile", "Rakefile", "Gruntfile.js", "Gulpfile.js",
		"id_rsa", "id_rsa.pub", ".ssh/authorized_keys",
		"credentials.json", "service-account.json",

		// Common dirs and admin panels
		"admin", "admin/", "admin/login", "admin/dashboard",
		"login", "register", "dashboard", "console", "portal",
		"config", "config/", "configuration", "settings",
		"backup", "backups", "test", "testing",
		"debug", "debug/", "internal", "internal/",
		"private", "secret", "tmp", "temp",
		"uploads", "upload", "files", "images", "media",
		"static", "assets", "public", "dist", "build",
		"cgi-bin", "cgi-bin/", "bin",

		// Labyrinth (crawler trap)
		"articles/tech/deep-learning",
		"articles/science/quantum",
		"articles/business/startups",
		"docs/api/v2/reference",
		"docs/api/v1/getting-started",
		"docs/tutorials/beginner",
		"products/category/featured",
		"products/category/new",
		"products/sale/clearance",
		"blog/2024/01/hello-world",
		"blog/2024/02/update",
		"news/latest-update",
		"help/getting-started",
		"help/faq",

		// Email
		"email", "email/inbox", "email/compose", "email/sent",
		"webmail", "webmail/",
		"mail", "mail/inbox",

		// Search
		"search", "search/", "search/advanced",
		"search/images", "api/search/suggest",

		// CDN / static assets
		"static/js/app.js", "static/js/main.js", "static/js/vendor.js",
		"static/css/main.css", "static/css/app.css",
		"assets/js/app.js", "assets/css/style.css",
		"dist/bundle.js", "build/static/js/main.js",

		// Captcha
		"captcha", "captcha/challenge", "captcha/verify", "captcha/image",

		// Analytics
		"analytics", "analytics/beacon", "analytics/pixel.gif",
		"analytics/collect", "collect",

		// Privacy
		"privacy", "privacy/", "privacy/consent",
		"privacy-policy", "terms", "terms-of-service",
		"cookie-policy", "gdpr", "ccpa",

		// i18n
		"es/", "fr/", "de/", "ja/", "zh/", "ko/", "pt/", "it/", "ru/",
		"en/", "en-US/", "en-GB/",

		// WebSocket
		"ws", "ws/echo", "ws/chat", "ws/feed", "ws/notifications",
		"websocket", "socket.io",

		// Recorder
		"recorder", "recorder/sessions", "recorder/status",

		// Spider data
		"spider", "spider/links", "spider/sitemap",

		// Framework-specific
		"actuator", "actuator/health", "actuator/info", "actuator/env",
		"actuator/beans", "actuator/mappings", "actuator/configprops",
		"__debug__", "_debug_toolbar",
		"elmah.axd", "trace.axd",
		"rails/info/routes",
		"django-admin",
		"telescope", "horizon",

		// Error pages
		"404", "500", "403", "401",
		"error", "errors", "not-found",

		// Misc discovery paths
		"README.md", "CHANGELOG.md", "LICENSE",
		"release-notes", "changelog",
		"xmlrpc.php", "wp-json", "wp-json/wp/v2/users",
		"feed", "feed/rss", "feed/atom", "rss.xml", "atom.xml",
		"manifest.json", "browserconfig.xml", "service-worker.js",
	}

	wordlistFile := filepath.Join(r.config.OutputDir, "glitch-wordlist.txt")
	content := strings.Join(paths, "\n")
	os.WriteFile(wordlistFile, []byte(content), 0o644)
	return wordlistFile
}

// ---------------------------------------------------------------------------
// Crash detection helpers
// ---------------------------------------------------------------------------

// crashPatterns are stderr substrings (lowercase) that indicate a process crash.
var crashPatterns = []string{
	"segmentation fault", "panic:", "core dumped",
	"sigsegv", "fatal error", "stack overflow",
}

// detectCrashInStderr checks if stderr output contains crash indicators.
func detectCrashInStderr(stderrStr string) bool {
	lower := strings.ToLower(stderrStr)
	for _, pat := range crashPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// truncateStderr truncates stderr output to maxLen bytes, appending a
// truncation marker if the output exceeds that limit.
func truncateStderr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "\n...[truncated]"
	}
	return s
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findBinary(name string) string {
	// Check common locations
	home := os.Getenv("HOME")
	locations := []string{
		filepath.Join(home, "go", "bin", name),
		filepath.Join(home, ".local", "bin", name),
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
	case "wapiti":
		cmd = exec.Command(path, "--version")
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
