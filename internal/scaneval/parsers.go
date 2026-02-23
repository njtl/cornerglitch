package scaneval

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Nuclei JSONL parser
// ---------------------------------------------------------------------------

// nucleiResult represents a single line of nuclei JSONL output.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Classification struct {
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
		Reference []string `json:"reference"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Timestamp string `json:"timestamp"`
}

// ParseNucleiJSON parses nuclei JSONL output (one JSON object per line).
func ParseNucleiJSON(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   "nuclei",
		StartedAt: time.Now(),
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && strings.TrimSpace(lines[0]) == "") {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	parseErrors := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			parseErrors++
			result.Errors = append(result.Errors, "failed to parse line: "+truncate(line, 100))
			continue
		}

		cwe := ""
		if len(nr.Info.Classification.CWEID) > 0 {
			cwe = nr.Info.Classification.CWEID[0]
		}

		ref := ""
		if len(nr.Info.Reference) > 0 {
			ref = nr.Info.Reference[0]
		}

		finding := Finding{
			ID:          nr.TemplateID,
			Title:       nr.Info.Name,
			Severity:    normalizeSeverity(nr.Info.Severity),
			URL:         nr.MatchedAt,
			Description: nr.Info.Description,
			CWE:         cwe,
			Reference:   ref,
		}

		result.Findings = append(result.Findings, finding)
	}

	// If more than half the lines failed to parse, mark as crashed
	if parseErrors > 0 && parseErrors > len(lines)/2 {
		result.Crashed = true
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// ---------------------------------------------------------------------------
// Nikto JSON parser
// ---------------------------------------------------------------------------

// niktoReport represents the top-level nikto JSON output.
type niktoReport struct {
	Host            string          `json:"host"`
	IP              string          `json:"ip"`
	Port            string          `json:"port"`
	Banner          string          `json:"banner"`
	Vulnerabilities []niktoFinding  `json:"vulnerabilities"`
}

type niktoFinding struct {
	ID     string `json:"id"`
	OSVDBID int   `json:"OSVDB"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Msg    string `json:"msg"`
}

// ParseNiktoJSON parses nikto JSON output.
func ParseNiktoJSON(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   "nikto",
		StartedAt: time.Now(),
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	var report niktoReport
	if err := json.Unmarshal(data, &report); err != nil {
		// Try array format (some nikto versions output an array of hosts)
		var reports []niktoReport
		if err2 := json.Unmarshal(data, &reports); err2 != nil {
			result.Crashed = true
			result.Errors = append(result.Errors, "failed to parse nikto JSON: "+err.Error())
			result.CompletedAt = time.Now()
			result.Duration = result.CompletedAt.Sub(result.StartedAt)
			return result, nil
		}
		if len(reports) > 0 {
			report = reports[0]
		}
	}

	for _, v := range report.Vulnerabilities {
		severity := niktoSeverity(v.Msg)
		finding := Finding{
			ID:          v.ID,
			Title:       v.Msg,
			Severity:    severity,
			URL:         v.URL,
			Description: v.Msg,
			Evidence:    v.Method + " " + v.URL,
		}
		result.Findings = append(result.Findings, finding)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// niktoSeverity guesses severity from a nikto message based on keywords.
func niktoSeverity(msg string) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "remote code execution") ||
		strings.Contains(lower, "rce") ||
		strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "command injection"):
		return "critical"
	case strings.Contains(lower, "xss") ||
		strings.Contains(lower, "directory listing") ||
		strings.Contains(lower, "file upload") ||
		strings.Contains(lower, "traversal"):
		return "high"
	case strings.Contains(lower, "header") ||
		strings.Contains(lower, "cookie") ||
		strings.Contains(lower, "disclosure") ||
		strings.Contains(lower, "information"):
		return "medium"
	case strings.Contains(lower, "banner") ||
		strings.Contains(lower, "version") ||
		strings.Contains(lower, "server"):
		return "info"
	default:
		return "medium"
	}
}

// ---------------------------------------------------------------------------
// Nmap XML parser
// ---------------------------------------------------------------------------

// nmapRun is the top-level XML structure for nmap output.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Address nmapAddress `xml:"address"`
	Ports   nmapPorts   `xml:"ports"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapScript struct {
	ID     string       `xml:"id,attr"`
	Output string       `xml:"output,attr"`
	Tables []nmapTable  `xml:"table"`
	Elems  []nmapElem   `xml:"elem"`
}

type nmapTable struct {
	Key   string      `xml:"key,attr"`
	Elems []nmapElem  `xml:"elem"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// ParseNmapXML parses nmap XML output.
func ParseNmapXML(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   "nmap",
		StartedAt: time.Now(),
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		result.Crashed = true
		result.Errors = append(result.Errors, "failed to parse nmap XML: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	for _, host := range run.Hosts {
		for _, port := range host.Ports.Ports {
			// Service detection findings
			if port.Service.Product != "" {
				finding := Finding{
					ID:       "nmap-service-" + port.PortID,
					Title:    "Service detected: " + port.Service.Product,
					Severity: "info",
					URL:      host.Address.Addr + ":" + port.PortID,
					Description: "Service: " + port.Service.Name +
						" Product: " + port.Service.Product +
						" Version: " + port.Service.Version,
					Evidence: port.Service.Product + "/" + port.Service.Version,
				}
				result.Findings = append(result.Findings, finding)
			}

			// NSE script findings
			for _, script := range port.Scripts {
				severity := nmapScriptSeverity(script.ID, script.Output)
				finding := Finding{
					ID:          "nmap-" + script.ID,
					Title:       script.ID,
					Severity:    severity,
					URL:         host.Address.Addr + ":" + port.PortID,
					Description: script.Output,
					Evidence:    script.Output,
				}

				// Extract CWE from script output if present
				if cwe := extractCWEFromText(script.Output); cwe != "" {
					finding.CWE = cwe
				}

				result.Findings = append(result.Findings, finding)
			}
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// nmapScriptSeverity assigns severity based on nmap NSE script type.
func nmapScriptSeverity(scriptID, output string) string {
	lower := strings.ToLower(scriptID + " " + output)
	switch {
	case strings.Contains(lower, "vuln") && strings.Contains(lower, "exploitable"):
		return "critical"
	case strings.Contains(lower, "vuln"):
		return "high"
	case strings.Contains(lower, "ssl") || strings.Contains(lower, "tls"):
		return "medium"
	case strings.Contains(lower, "http-headers") ||
		strings.Contains(lower, "http-server-header") ||
		strings.Contains(lower, "http-title"):
		return "info"
	default:
		return "info"
	}
}

// ---------------------------------------------------------------------------
// FFuf JSON parser
// ---------------------------------------------------------------------------

// ffufReport represents the top-level ffuf JSON output.
type ffufReport struct {
	CommandLine string       `json:"commandline"`
	Results     []ffufResult `json:"results"`
	Config      struct {
		URL string `json:"url"`
	} `json:"config"`
}

type ffufResult struct {
	Input    map[string]string `json:"input"`
	Position int               `json:"position"`
	Status   int               `json:"status"`
	Length   int               `json:"length"`
	Words    int               `json:"words"`
	Lines    int               `json:"lines"`
	URL      string            `json:"url"`
	Host     string            `json:"host"`
}

// ParseFFufJSON parses ffuf JSON output.
func ParseFFufJSON(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   "ffuf",
		StartedAt: time.Now(),
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	var report ffufReport
	if err := json.Unmarshal(data, &report); err != nil {
		result.Crashed = true
		result.Errors = append(result.Errors, "failed to parse ffuf JSON: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	result.RequestCount = len(report.Results)

	for _, r := range report.Results {
		severity := ffufSeverity(r.Status, r.URL)
		finding := Finding{
			ID:       "ffuf-" + strings.TrimPrefix(r.URL, "http://"),
			Title:    "Discovered: " + r.URL,
			Severity: severity,
			URL:      r.URL,
			Description: ffufDescription(r.Status, r.Length, r.URL),
			Evidence: ffufEvidence(r.Status, r.Length, r.Words, r.Lines),
		}
		result.Findings = append(result.Findings, finding)
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// ffufSeverity assigns severity based on HTTP status and path.
func ffufSeverity(status int, url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "admin") ||
		strings.Contains(lower, "backup") ||
		strings.Contains(lower, ".sql") ||
		strings.Contains(lower, ".env"):
		return "high"
	case strings.Contains(lower, "config") ||
		strings.Contains(lower, "debug") ||
		strings.Contains(lower, ".git"):
		return "medium"
	case status == 200:
		return "info"
	case status == 403:
		return "info"
	default:
		return "info"
	}
}

func ffufDescription(status, length int, url string) string {
	parts := []string{"Endpoint discovered via content discovery"}
	if status == 200 {
		parts = append(parts, "returns 200 OK")
	} else if status == 403 {
		parts = append(parts, "returns 403 Forbidden (exists but restricted)")
	} else if status == 301 || status == 302 {
		parts = append(parts, "redirects (may indicate an application path)")
	}
	return strings.Join(parts, ", ")
}

func ffufEvidence(status, length, words, lines int) string {
	return strings.Join([]string{
		"status=" + itoa(status),
		"length=" + itoa(length),
		"words=" + itoa(words),
		"lines=" + itoa(lines),
	}, " ")
}

// ---------------------------------------------------------------------------
// Wapiti JSON parser
// ---------------------------------------------------------------------------

// wapitiReport represents the top-level wapiti JSON report.
type wapitiReport struct {
	Classifications map[string]wapitiClassification `json:"classifications"`
	Vulnerabilities map[string][]wapitiVuln         `json:"vulnerabilities"`
	Anomalies       map[string][]wapitiVuln         `json:"anomalies"`
	Infos           map[string][]wapitiVuln         `json:"infos"`
}

type wapitiClassification struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
	Sol  string `json:"sol"`
	Ref  string `json:"ref"`
}

type wapitiVuln struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Info     string `json:"info"`
	Level    int    `json:"level"`
	Param    string `json:"parameter"`
	HTTP     string `json:"http_request"`
	CurlCmd  string `json:"curl_command"`
	WSTGID   string `json:"wstg"`
	Response string `json:"response"`
}

// ParseWapitiJSON parses wapiti JSON report output.
func ParseWapitiJSON(data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   "wapiti",
		StartedAt: time.Now(),
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	var report wapitiReport
	if err := json.Unmarshal(data, &report); err != nil {
		result.Crashed = true
		result.Errors = append(result.Errors, "failed to parse wapiti JSON: "+err.Error())
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	// Process vulnerabilities
	for category, vulns := range report.Vulnerabilities {
		for _, v := range vulns {
			cwe := extractCWEFromText(category + " " + v.Info)
			finding := Finding{
				ID:          "wapiti-" + sanitizeID(category),
				Title:       category + ": " + truncate(v.Info, 100),
				Severity:    wapitiSeverity(v.Level),
				URL:         v.Path,
				Description: v.Info,
				CWE:         cwe,
				Evidence:    v.Param,
				Reference:   v.WSTGID,
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	// Process anomalies as lower severity findings
	for category, anomalies := range report.Anomalies {
		for _, a := range anomalies {
			finding := Finding{
				ID:          "wapiti-anomaly-" + sanitizeID(category),
				Title:       "Anomaly: " + category,
				Severity:    "low",
				URL:         a.Path,
				Description: a.Info,
				Reference:   a.WSTGID,
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	// Process informational findings
	for category, infos := range report.Infos {
		for _, i := range infos {
			finding := Finding{
				ID:          "wapiti-info-" + sanitizeID(category),
				Title:       "Info: " + category,
				Severity:    "info",
				URL:         i.Path,
				Description: i.Info,
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// wapitiSeverity maps wapiti's numeric level to a severity string.
func wapitiSeverity(level int) string {
	switch {
	case level >= 4:
		return "critical"
	case level == 3:
		return "high"
	case level == 2:
		return "medium"
	case level == 1:
		return "low"
	default:
		return "info"
	}
}

// ---------------------------------------------------------------------------
// Generic text parser (fallback)
// ---------------------------------------------------------------------------

// ParseGenericText provides a best-effort parser for plain text scanner output.
func ParseGenericText(scanner string, data []byte) (*ScanResult, error) {
	result := &ScanResult{
		Scanner:   scanner,
		StartedAt: time.Now(),
	}

	text := string(data)
	if strings.TrimSpace(text) == "" {
		result.CompletedAt = time.Now()
		result.Duration = result.CompletedAt.Sub(result.StartedAt)
		return result, nil
	}

	// Check for crash indicators
	if isCrashedOutput(text) {
		result.Crashed = true
	}

	// Check for timeout indicators
	if isTimedOutOutput(text) {
		result.TimedOut = true
	}

	lines := strings.Split(text, "\n")
	findingIdx := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip informational/progress lines
		if isProgressLine(line) {
			continue
		}

		// Look for lines that indicate findings
		if looksLikeFinding(line) {
			severity := guessSeverityFromText(line)
			url := extractURLFromText(line)
			cwe := extractCWEFromText(line)
			findingIdx++

			finding := Finding{
				ID:          scanner + "-" + itoa(findingIdx),
				Title:       truncate(line, 200),
				Severity:    severity,
				URL:         url,
				Description: line,
				CWE:         cwe,
			}
			result.Findings = append(result.Findings, finding)
		}

		// Collect error lines
		if looksLikeError(line) {
			result.Errors = append(result.Errors, line)
		}
	}

	result.CompletedAt = time.Now()
	result.Duration = result.CompletedAt.Sub(result.StartedAt)
	return result, nil
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return "critical"
	case "high":
		return "high"
	case "medium", "med", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "information", "none":
		return "info"
	default:
		return "info"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func sanitizeID(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	// Collapse multiple dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func extractCWEFromText(text string) string {
	upper := strings.ToUpper(text)
	idx := strings.Index(upper, "CWE-")
	if idx < 0 {
		idx = strings.Index(upper, "CWE ")
		if idx < 0 {
			return ""
		}
		idx += 4 // skip "CWE "
	} else {
		idx += 4 // skip "CWE-"
	}

	// Extract digits
	var digits []byte
	for i := idx; i < len(upper) && i < idx+6; i++ {
		if upper[i] >= '0' && upper[i] <= '9' {
			digits = append(digits, upper[i])
		} else {
			break
		}
	}
	if len(digits) == 0 {
		return ""
	}
	return "CWE-" + string(digits)
}

func extractURLFromText(line string) string {
	// Look for http:// or https:// URLs
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(line, prefix)
		if idx >= 0 {
			end := idx
			for end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != '"' && line[end] != '\'' {
				end++
			}
			return line[idx:end]
		}
	}

	// Look for path-like patterns starting with /
	words := strings.Fields(line)
	for _, w := range words {
		if strings.HasPrefix(w, "/") && len(w) > 1 && !strings.HasPrefix(w, "//") {
			return w
		}
	}

	return ""
}

func isCrashedOutput(text string) bool {
	indicators := []string{
		"panic:", "segfault", "segmentation fault",
		"core dumped", "fatal error", "aborted",
		"killed", "out of memory", "oom",
		"stack overflow", "exception",
	}
	lower := strings.ToLower(text)
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}

	// Check for truncated JSON/XML/HTML
	trimmed := strings.TrimSpace(text)
	if (strings.HasPrefix(trimmed, "{") && !strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && !strings.HasSuffix(trimmed, "]")) {
		return true
	}
	// For HTML/XML: starts with < but doesn't end with a proper closing tag
	if strings.HasPrefix(trimmed, "<") {
		if !strings.HasSuffix(trimmed, ">") {
			return true
		}
		// Check for unclosed HTML — has opening tags but no </html> or similar end tag
		lowerTrimmed := strings.ToLower(trimmed)
		if strings.Contains(lowerTrimmed, "<html") && !strings.Contains(lowerTrimmed, "</html>") {
			return true
		}
		if strings.Contains(lowerTrimmed, "<body") && !strings.Contains(lowerTrimmed, "</body>") {
			return true
		}
	}

	return false
}

func isTimedOutOutput(text string) bool {
	indicators := []string{
		"timed out", "timeout", "deadline exceeded",
		"context deadline", "operation timed out",
	}
	lower := strings.ToLower(text)
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func isProgressLine(line string) bool {
	lower := strings.ToLower(line)
	progressIndicators := []string{
		"progress:", "scanning:", "testing:", "[info]",
		"status:", "elapsed:", "eta:", "requests/sec",
		"started at", "completed at", "duration:",
		"───", "---", "===", "***",
	}
	for _, ind := range progressIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func looksLikeFinding(line string) bool {
	lower := strings.ToLower(line)
	findingIndicators := []string{
		"vuln", "vulnerability", "finding", "issue",
		"warning", "alert", "critical", "high", "medium",
		"cve-", "cwe-", "osvdb", "exploit",
		"injection", "xss", "sqli", "traversal",
		"disclosure", "misconfiguration", "insecure",
		"exposed", "leaked", "sensitive", "unauthorized",
		"open redirect", "ssrf", "csrf", "cors",
		"missing header", "cookie", "ssl", "tls",
	}
	for _, ind := range findingIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func looksLikeError(line string) bool {
	lower := strings.ToLower(line)
	errorIndicators := []string{
		"error:", "err:", "failed:", "failure:",
		"cannot ", "unable to", "exception:",
		"traceback", "errno", "permission denied",
	}
	for _, ind := range errorIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

func guessSeverityFromText(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "critical") ||
		strings.Contains(lower, "rce") ||
		strings.Contains(lower, "remote code") ||
		strings.Contains(lower, "command injection"):
		return "critical"
	case strings.Contains(lower, "high") ||
		strings.Contains(lower, "sql injection") ||
		strings.Contains(lower, "xss") ||
		strings.Contains(lower, "traversal"):
		return "high"
	case strings.Contains(lower, "medium") ||
		strings.Contains(lower, "disclosure") ||
		strings.Contains(lower, "misconfiguration"):
		return "medium"
	case strings.Contains(lower, "low") ||
		strings.Contains(lower, "info") ||
		strings.Contains(lower, "informational"):
		return "low"
	default:
		return "medium"
	}
}
