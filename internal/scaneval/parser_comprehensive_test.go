package scaneval

import (
	"fmt"
	"strings"
	"testing"
)

// ===========================================================================
// Comprehensive parser test suite
//
// Covers: ParseNucleiJSON, ParseFFufJSON, ParseNmapXML, ParseNiktoJSON,
//         ParseHTTPXJSON, ParseWapitiJSON, ParseGenericText, ParseAndCompare,
//         CompareResults
//
// Run:  go test ./internal/scaneval/ -count=1 -v -run Comprehensive
// ===========================================================================

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// nucleiLine builds a single nuclei JSONL line with the given fields.
func nucleiLine(templateID, name, severity, url, cwe, ref string) string {
	cweArr := "[]"
	if cwe != "" {
		cweArr = fmt.Sprintf("[%q]", cwe)
	}
	refArr := "[]"
	if ref != "" {
		refArr = fmt.Sprintf("[%q]", ref)
	}
	return fmt.Sprintf(
		`{"template-id":%q,"info":{"name":%q,"severity":%q,"description":"desc","classification":{"cwe-id":%s},"reference":%s},"matched-at":%q,"timestamp":"2025-01-01T00:00:00Z"}`,
		templateID, name, severity, cweArr, refArr, url,
	)
}

// repeatLine returns n copies of s separated by newlines.
func repeatLine(s string, n int) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = s
	}
	return strings.Join(lines, "\n")
}

// buildMinimalProfile returns a small profile useful for ParseAndCompare tests.
func buildMinimalProfile() *ExpectedProfile {
	return &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{
				ID: "test-xss", Name: "XSS", Severity: "high",
				Endpoints: []string{"/vuln/xss"}, CWE: "CWE-79", Detectable: true,
			},
			{
				ID: "test-sqli", Name: "SQL Injection", Severity: "critical",
				Endpoints: []string{"/vuln/sqli"}, CWE: "CWE-89", Detectable: true,
			},
			{
				ID: "test-info", Name: "Server Banner", Severity: "info",
				Endpoints: []string{"/"}, CWE: "", Detectable: true,
			},
		},
		TotalVulns: 3,
		BySeverity: map[string]int{"critical": 1, "high": 1, "info": 1},
	}
}

// ===========================================================================
// Nuclei JSONL — Comprehensive
// ===========================================================================

func TestComprehensive_Nuclei_FullResults(t *testing.T) {
	lines := []string{
		nucleiLine("cve-2021-44228", "Log4j RCE", "critical", "http://target/api", "CWE-502", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
		nucleiLine("xss-reflected", "Reflected XSS", "medium", "http://target/search", "CWE-79", ""),
		nucleiLine("cors-misconfig", "CORS Misconfiguration", "medium", "http://target/api/cors", "CWE-942", ""),
		nucleiLine("missing-hsts", "Missing HSTS", "info", "http://target/", "", ""),
		nucleiLine("open-redirect", "Open Redirect", "low", "http://target/redirect", "CWE-601", ""),
	}
	data := []byte(strings.Join(lines, "\n"))

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "nuclei" {
		t.Errorf("Scanner = %q, want nuclei", result.Scanner)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("Findings = %d, want 5", len(result.Findings))
	}
	if result.Crashed {
		t.Error("should not be marked crashed")
	}

	// Verify first finding in detail
	f := result.Findings[0]
	if f.ID != "cve-2021-44228" {
		t.Errorf("ID = %q", f.ID)
	}
	if f.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", f.Severity)
	}
	if f.CWE != "CWE-502" {
		t.Errorf("CWE = %q, want CWE-502", f.CWE)
	}
	if f.Reference != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" {
		t.Errorf("Reference = %q", f.Reference)
	}
	if f.URL != "http://target/api" {
		t.Errorf("URL = %q", f.URL)
	}

	// Check severity distribution
	sevCount := map[string]int{}
	for _, finding := range result.Findings {
		sevCount[finding.Severity]++
	}
	if sevCount["critical"] != 1 || sevCount["medium"] != 2 || sevCount["info"] != 1 || sevCount["low"] != 1 {
		t.Errorf("severity distribution = %v", sevCount)
	}
}

func TestComprehensive_Nuclei_SingleFinding(t *testing.T) {
	data := []byte(nucleiLine("single-vuln", "Single", "high", "http://target/one", "", ""))

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].ID != "single-vuln" {
		t.Errorf("ID = %q", result.Findings[0].ID)
	}
}

func TestComprehensive_Nuclei_EmptyOutput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   "), []byte("\n\n\n")} {
		result, err := ParseNucleiJSON(input)
		if err != nil {
			t.Fatalf("unexpected error for input %q: %v", input, err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_Nuclei_PartialTruncated(t *testing.T) {
	// Complete line followed by a truncated JSON line
	good := nucleiLine("valid-1", "Valid", "high", "http://target/x", "", "")
	truncated := `{"template-id":"trunc","info":{"name":"Tru`
	data := []byte(good + "\n" + truncated)

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("Findings = %d, want 1 (only valid line)", len(result.Findings))
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors = %d, want 1 (truncated line)", len(result.Errors))
	}
	// 1 bad out of 2 is exactly half => not crashed
	if result.Crashed {
		t.Error("should not be crashed (1/2 lines bad is not > half)")
	}
}

func TestComprehensive_Nuclei_MalformedBinaryGarbage(t *testing.T) {
	garbage := []byte{0x00, 0x01, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47}
	result, err := ParseNucleiJSON(garbage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for binary garbage", len(result.Findings))
	}
	if !result.Crashed {
		t.Error("binary garbage should mark result as crashed (all lines fail)")
	}
}

func TestComprehensive_Nuclei_MissingFields(t *testing.T) {
	// Missing severity
	line1 := `{"template-id":"no-sev","info":{"name":"No Severity","description":"d","classification":{"cwe-id":[]}},"matched-at":"http://target/a"}`
	// Missing matched-at
	line2 := `{"template-id":"no-url","info":{"name":"No URL","severity":"high","description":"d","classification":{"cwe-id":[]}}}`
	// Missing template-id
	line3 := `{"info":{"name":"No ID","severity":"low","description":"d","classification":{"cwe-id":[]}},"matched-at":"http://target/c"}`

	data := []byte(line1 + "\n" + line2 + "\n" + line3)
	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All three are valid JSON, so all parse
	if len(result.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3", len(result.Findings))
	}
	// Missing severity should normalize to "info"
	if result.Findings[0].Severity != "info" {
		t.Errorf("missing severity normalized to %q, want info", result.Findings[0].Severity)
	}
	// Missing matched-at should be empty
	if result.Findings[1].URL != "" {
		t.Errorf("missing matched-at => URL = %q, want empty", result.Findings[1].URL)
	}
	// Missing template-id => empty ID
	if result.Findings[2].ID != "" {
		t.Errorf("missing template-id => ID = %q, want empty", result.Findings[2].ID)
	}
}

func TestComprehensive_Nuclei_LargeOutput(t *testing.T) {
	line := nucleiLine("bulk-vuln", "Bulk Finding", "medium", "http://target/bulk", "", "")
	data := []byte(repeatLine(line, 1000))
	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1000 {
		t.Errorf("Findings = %d, want 1000", len(result.Findings))
	}
}

func TestComprehensive_Nuclei_Unicode(t *testing.T) {
	line := `{"template-id":"unicode-test","info":{"name":"XSS \u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412","severity":"high","description":"\u2603 snowman","classification":{"cwe-id":["CWE-79"]}},"matched-at":"http://target/\u00e9"}`
	result, err := ParseNucleiJSON([]byte(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].CWE != "CWE-79" {
		t.Errorf("CWE = %q", result.Findings[0].CWE)
	}
}

func TestComprehensive_Nuclei_WhitespaceOnly(t *testing.T) {
	result, err := ParseNucleiJSON([]byte("   \t\n   \n\t  "))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for whitespace-only", len(result.Findings))
	}
}

func TestComprehensive_Nuclei_WrongFormatJSON(t *testing.T) {
	// Valid JSON but wrong structure (an array instead of objects-per-line).
	// json.Unmarshal into nucleiResult (a struct) fails for an array,
	// so this line is treated as malformed.
	data := []byte(`[{"key":"value"},{"key":"value2"}]`)
	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 (array cannot unmarshal into struct)", len(result.Findings))
	}
	if len(result.Errors) != 1 {
		t.Errorf("Errors = %d, want 1 (the single line is malformed for nuclei)", len(result.Errors))
	}
	if !result.Crashed {
		t.Error("should be crashed (all lines failed)")
	}
}

// ===========================================================================
// FFuf JSON — Comprehensive
// ===========================================================================

func TestComprehensive_FFuf_FullResults(t *testing.T) {
	data := []byte(`{
		"commandline": "ffuf -u http://target/FUZZ -w wordlist.txt",
		"results": [
			{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,"words":100,"lines":50,"url":"http://target/admin","host":"target"},
			{"input":{"FUZZ":".env"},"position":2,"status":200,"length":567,"words":30,"lines":15,"url":"http://target/.env","host":"target"},
			{"input":{"FUZZ":"config"},"position":3,"status":403,"length":234,"words":10,"lines":5,"url":"http://target/config","host":"target"},
			{"input":{"FUZZ":"index.html"},"position":4,"status":200,"length":4567,"words":400,"lines":100,"url":"http://target/index.html","host":"target"},
			{"input":{"FUZZ":"backup.sql"},"position":5,"status":200,"length":99999,"words":5000,"lines":1000,"url":"http://target/backup.sql","host":"target"},
			{"input":{"FUZZ":".git/HEAD"},"position":6,"status":200,"length":23,"words":2,"lines":1,"url":"http://target/.git/HEAD","host":"target"},
			{"input":{"FUZZ":"debug"},"position":7,"status":200,"length":890,"words":50,"lines":20,"url":"http://target/debug","host":"target"}
		],
		"config": {"url": "http://target/FUZZ"}
	}`)

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "ffuf" {
		t.Errorf("Scanner = %q, want ffuf", result.Scanner)
	}
	if len(result.Findings) != 7 {
		t.Fatalf("Findings = %d, want 7", len(result.Findings))
	}
	if result.RequestCount != 7 {
		t.Errorf("RequestCount = %d, want 7", result.RequestCount)
	}
	if result.Crashed {
		t.Error("should not be crashed")
	}

	// Check severity assignments
	severities := map[string]string{}
	for _, f := range result.Findings {
		severities[f.URL] = f.Severity
	}
	if severities["http://target/admin"] != "high" {
		t.Errorf("admin severity = %q, want high", severities["http://target/admin"])
	}
	if severities["http://target/.env"] != "high" {
		t.Errorf(".env severity = %q, want high", severities["http://target/.env"])
	}
	if severities["http://target/backup.sql"] != "high" {
		t.Errorf("backup.sql severity = %q, want high", severities["http://target/backup.sql"])
	}
	if severities["http://target/config"] != "medium" {
		t.Errorf("config severity = %q, want medium", severities["http://target/config"])
	}
	if severities["http://target/.git/HEAD"] != "medium" {
		t.Errorf(".git severity = %q, want medium", severities["http://target/.git/HEAD"])
	}
	if severities["http://target/debug"] != "medium" {
		t.Errorf("debug severity = %q, want medium", severities["http://target/debug"])
	}
	if severities["http://target/index.html"] != "info" {
		t.Errorf("index.html severity = %q, want info", severities["http://target/index.html"])
	}
}

func TestComprehensive_FFuf_SingleResult(t *testing.T) {
	data := []byte(`{
		"commandline": "ffuf",
		"results": [
			{"input":{"FUZZ":"test"},"position":1,"status":200,"length":100,"words":10,"lines":5,"url":"http://target/test","host":"target"}
		],
		"config": {"url": "http://target/FUZZ"}
	}`)

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1", result.RequestCount)
	}
}

func TestComprehensive_FFuf_EmptyResults(t *testing.T) {
	data := []byte(`{"commandline":"ffuf","results":[],"config":{"url":"http://target/FUZZ"}}`)
	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for empty results array", len(result.Findings))
	}
	if result.RequestCount != 0 {
		t.Errorf("RequestCount = %d, want 0", result.RequestCount)
	}
}

func TestComprehensive_FFuf_EmptyInput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   ")} {
		result, err := ParseFFufJSON(input)
		if err != nil {
			t.Fatalf("unexpected error for input %q: %v", input, err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_FFuf_TruncatedJSON(t *testing.T) {
	data := []byte(`{"commandline":"ffuf","results":[{"input":{"FUZZ":"admin"},"position":1,"status":200`)
	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be marked crashed for truncated JSON")
	}
	if len(result.Errors) == 0 {
		t.Error("should have parse errors")
	}
}

func TestComprehensive_FFuf_MalformedBinaryGarbage(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be crashed for binary garbage")
	}
}

func TestComprehensive_FFuf_VariousStatusCodes(t *testing.T) {
	data := []byte(`{
		"commandline": "ffuf",
		"results": [
			{"input":{"FUZZ":"ok"},"position":1,"status":200,"length":100,"words":10,"lines":5,"url":"http://target/ok","host":"target"},
			{"input":{"FUZZ":"redirect"},"position":2,"status":301,"length":0,"words":0,"lines":0,"url":"http://target/redirect","host":"target"},
			{"input":{"FUZZ":"forbidden"},"position":3,"status":403,"length":50,"words":5,"lines":2,"url":"http://target/forbidden","host":"target"},
			{"input":{"FUZZ":"error"},"position":4,"status":500,"length":200,"words":20,"lines":10,"url":"http://target/error","host":"target"}
		],
		"config": {"url": "http://target/FUZZ"}
	}`)

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 4 {
		t.Fatalf("Findings = %d, want 4", len(result.Findings))
	}

	// Verify evidence contains status codes
	for _, f := range result.Findings {
		if f.Evidence == "" {
			t.Errorf("finding %q has empty evidence", f.URL)
		}
	}
}

func TestComprehensive_FFuf_LargeOutput(t *testing.T) {
	// Build 500 results programmatically
	var results []string
	for i := 0; i < 500; i++ {
		results = append(results, fmt.Sprintf(
			`{"input":{"FUZZ":"path%d"},"position":%d,"status":200,"length":100,"words":10,"lines":5,"url":"http://target/path%d","host":"target"}`,
			i, i+1, i,
		))
	}
	data := []byte(fmt.Sprintf(`{"commandline":"ffuf","results":[%s],"config":{"url":"http://target/FUZZ"}}`,
		strings.Join(results, ",")))

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 500 {
		t.Errorf("Findings = %d, want 500", len(result.Findings))
	}
}

// ===========================================================================
// Nmap XML — Comprehensive
// ===========================================================================

func TestComprehensive_Nmap_FullResults(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="-sV -sC localhost" start="1234567890">
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="8765">
        <state state="open"/>
        <service name="http" product="Go HTTP Server" version="1.24"/>
        <script id="http-headers" output="X-Debug-Mode: true&#xa;Server: Apache/2.4.29"/>
        <script id="http-title" output="Glitch Web Server"/>
        <script id="http-server-header" output="glitch/2.0"/>
      </port>
      <port protocol="tcp" portid="8766">
        <state state="open"/>
        <service name="http" product="Go HTTP Server" version="1.24"/>
        <script id="http-title" output="Dashboard"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18"/>
        <script id="ssl-cert" output="Subject: CN=localhost"/>
        <script id="ssl-enum-ciphers" output="TLSv1.0 weak ciphers"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "nmap" {
		t.Errorf("Scanner = %q, want nmap", result.Scanner)
	}
	if result.Crashed {
		t.Error("should not be crashed")
	}

	// 3 services with products + 6 scripts = 9 findings
	if len(result.Findings) < 8 {
		t.Errorf("Findings = %d, want >= 8", len(result.Findings))
	}

	// Verify service detection findings exist
	foundService8765 := false
	foundService443 := false
	foundSSL := false
	for _, f := range result.Findings {
		if f.ID == "nmap-service-8765" {
			foundService8765 = true
			if f.Severity != "info" {
				t.Errorf("service-8765 severity = %q, want info", f.Severity)
			}
			if !strings.Contains(f.Description, "Go HTTP Server") {
				t.Errorf("service-8765 description missing product name")
			}
		}
		if f.ID == "nmap-service-443" {
			foundService443 = true
		}
		if f.ID == "nmap-ssl-enum-ciphers" {
			foundSSL = true
			if f.Severity != "medium" {
				t.Errorf("ssl script severity = %q, want medium", f.Severity)
			}
		}
	}
	if !foundService8765 {
		t.Error("missing service detection for port 8765")
	}
	if !foundService443 {
		t.Error("missing service detection for port 443")
	}
	if !foundSSL {
		t.Error("missing ssl-enum-ciphers finding")
	}
}

func TestComprehensive_Nmap_SinglePort(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.51"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].ID != "nmap-service-80" {
		t.Errorf("ID = %q, want nmap-service-80", result.Findings[0].ID)
	}
	if !strings.Contains(result.Findings[0].URL, "10.0.0.1:80") {
		t.Errorf("URL = %q, expected to contain 10.0.0.1:80", result.Findings[0].URL)
	}
}

func TestComprehensive_Nmap_EmptyInput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   ")} {
		result, err := ParseNmapXML(input)
		if err != nil {
			t.Fatalf("unexpected error for input %q: %v", input, err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_Nmap_TruncatedXML(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="8765">
        <state state="open"/>
        <service name="http" product="Go HT`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be marked crashed for truncated XML")
	}
	if len(result.Errors) == 0 {
		t.Error("should have parse errors")
	}
}

func TestComprehensive_Nmap_MalformedBinaryGarbage(t *testing.T) {
	data := []byte{0x00, 0x01, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47}
	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be crashed for binary garbage")
	}
}

func TestComprehensive_Nmap_EmptyHost(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports></ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for empty host", len(result.Findings))
	}
}

func TestComprehensive_Nmap_MultipleHosts(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.20"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2 (one service per host)", len(result.Findings))
	}

	urls := map[string]bool{}
	for _, f := range result.Findings {
		urls[f.URL] = true
	}
	if !urls["10.0.0.1:80"] {
		t.Error("missing finding for host 10.0.0.1:80")
	}
	if !urls["10.0.0.2:443"] {
		t.Error("missing finding for host 10.0.0.2:443")
	}
}

func TestComprehensive_Nmap_VulnExploitable(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="http-vuln-cve2017-5638" output="VULNERABLE: Apache Struts2 RCE exploitable CWE-20"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range result.Findings {
		if f.ID == "nmap-http-vuln-cve2017-5638" {
			found = true
			// "vuln" + "exploitable" => critical
			if f.Severity != "critical" {
				t.Errorf("Severity = %q, want critical", f.Severity)
			}
			if f.CWE != "CWE-20" {
				t.Errorf("CWE = %q, want CWE-20", f.CWE)
			}
		}
	}
	if !found {
		t.Error("missing vuln script finding")
	}
}

func TestComprehensive_Nmap_NoServiceProduct(t *testing.T) {
	// Port with service name but no product => no service-detection finding
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No product means no service detection finding, no scripts either
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 (no product, no scripts)", len(result.Findings))
	}
}

func TestComprehensive_Nmap_LargeOutput(t *testing.T) {
	// Build XML with 200 ports
	var ports strings.Builder
	for i := 1; i <= 200; i++ {
		fmt.Fprintf(&ports, `      <port protocol="tcp" portid="%d">
        <state state="open"/>
        <service name="http" product="Service%d" version="1.0"/>
      </port>
`, i, i)
	}
	data := []byte(fmt.Sprintf(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1"/>
    <ports>
%s
    </ports>
  </host>
</nmaprun>`, ports.String()))

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 200 {
		t.Errorf("Findings = %d, want 200", len(result.Findings))
	}
}

// ===========================================================================
// Nikto JSON — Comprehensive
// ===========================================================================

func TestComprehensive_Nikto_FullResults(t *testing.T) {
	data := []byte(`{
		"host": "localhost",
		"ip": "127.0.0.1",
		"port": "8765",
		"banner": "Go HTTP Server",
		"vulnerabilities": [
			{"id":"999990","OSVDB":0,"method":"GET","url":"/","msg":"Server banner found"},
			{"id":"999991","OSVDB":3092,"method":"GET","url":"/.env","msg":"Environment file disclosure"},
			{"id":"999992","OSVDB":0,"method":"GET","url":"/admin","msg":"Admin page found - possible SQL injection point"},
			{"id":"999993","OSVDB":0,"method":"GET","url":"/debug","msg":"Debug endpoint exposed with directory listing"},
			{"id":"999994","OSVDB":12345,"method":"GET","url":"/wp-admin","msg":"WordPress admin - possible remote code execution via RCE plugin"}
		]
	}`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "nikto" {
		t.Errorf("Scanner = %q, want nikto", result.Scanner)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("Findings = %d, want 5", len(result.Findings))
	}
	if result.Crashed {
		t.Error("should not be crashed")
	}

	// Check severity assignment based on keywords in niktoSeverity
	expected := map[string]string{
		"/":         "info",     // "banner" + "server" => info
		"/.env":     "medium",   // "disclosure" => medium
		"/admin":    "critical", // "sql injection" in msg => critical
		"/debug":    "high",     // "directory listing" => high
		"/wp-admin": "critical", // "remote code execution" + "rce" => critical
	}

	for _, f := range result.Findings {
		want, ok := expected[f.URL]
		if !ok {
			continue
		}
		if f.Severity != want {
			t.Errorf("URL %q severity = %q, want %q (msg: %q)", f.URL, f.Severity, want, f.Title)
		}
	}
}

func TestComprehensive_Nikto_SingleFinding(t *testing.T) {
	data := []byte(`{"host":"localhost","port":"8765","vulnerabilities":[{"id":"1","OSVDB":0,"method":"GET","url":"/test","msg":"Test finding"}]}`)
	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].URL != "/test" {
		t.Errorf("URL = %q", result.Findings[0].URL)
	}
	// Evidence should contain method + url
	if !strings.Contains(result.Findings[0].Evidence, "GET") {
		t.Errorf("Evidence = %q, expected to contain GET", result.Findings[0].Evidence)
	}
}

func TestComprehensive_Nikto_EmptyVulnerabilities(t *testing.T) {
	data := []byte(`{"host":"localhost","port":"8765","vulnerabilities":[]}`)
	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestComprehensive_Nikto_EmptyInput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   ")} {
		result, err := ParseNiktoJSON(input)
		if err != nil {
			t.Fatalf("unexpected error for input %q: %v", input, err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_Nikto_TruncatedJSON(t *testing.T) {
	data := []byte(`{"host":"localhost","port":"8765","vulnerabilities":[{"id":"1","OSVDB":0,"method":"GET","url":"/te`)
	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be marked crashed for truncated JSON")
	}
}

func TestComprehensive_Nikto_MalformedBinaryGarbage(t *testing.T) {
	data := []byte{0x00, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47}
	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Crashed {
		t.Error("should be crashed for binary garbage")
	}
}

func TestComprehensive_Nikto_ArrayFormatMultipleHosts(t *testing.T) {
	data := []byte(`[
		{"host":"host1","port":"8765","vulnerabilities":[
			{"id":"1","OSVDB":0,"method":"GET","url":"/a","msg":"Finding on host1"}
		]},
		{"host":"host2","port":"8766","vulnerabilities":[
			{"id":"2","OSVDB":0,"method":"GET","url":"/b","msg":"Finding on host2"}
		]}
	]`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the first host is parsed
	if len(result.Findings) != 1 {
		t.Errorf("Findings = %d, want 1 (only first host in array)", len(result.Findings))
	}
}

func TestComprehensive_Nikto_SeverityKeywords(t *testing.T) {
	tests := []struct {
		msg      string
		expected string
	}{
		{"Remote code execution possible", "critical"},
		{"RCE via plugin", "critical"},
		{"SQL injection found", "critical"},
		{"Command injection in parameter", "critical"},
		{"XSS vulnerability found", "high"},
		{"Directory listing enabled", "high"},
		{"File upload vulnerability", "high"},
		{"Path traversal possible", "high"},
		{"Missing security header", "medium"},
		{"Cookie without secure flag", "medium"},
		{"Information disclosure", "medium"},
		{"Server banner found", "info"},
		{"Server version exposed", "info"},
		{"Something completely unknown", "medium"}, // default
	}

	for _, tt := range tests {
		got := niktoSeverity(tt.msg)
		if got != tt.expected {
			t.Errorf("niktoSeverity(%q) = %q, want %q", tt.msg, got, tt.expected)
		}
	}
}

func TestComprehensive_Nikto_DifferentOSVDB(t *testing.T) {
	data := []byte(`{"host":"localhost","port":"8765","vulnerabilities":[
		{"id":"1","OSVDB":0,"method":"GET","url":"/a","msg":"Test 1"},
		{"id":"2","OSVDB":3092,"method":"GET","url":"/b","msg":"Test 2"},
		{"id":"3","OSVDB":99999,"method":"POST","url":"/c","msg":"Test 3"}
	]}`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 3 {
		t.Errorf("Findings = %d, want 3", len(result.Findings))
	}
}

func TestComprehensive_Nikto_LargeOutput(t *testing.T) {
	var vulns []string
	for i := 0; i < 500; i++ {
		vulns = append(vulns, fmt.Sprintf(
			`{"id":"%d","OSVDB":0,"method":"GET","url":"/path%d","msg":"Finding %d"}`,
			i, i, i,
		))
	}
	data := []byte(fmt.Sprintf(`{"host":"localhost","port":"8765","vulnerabilities":[%s]}`,
		strings.Join(vulns, ",")))

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 500 {
		t.Errorf("Findings = %d, want 500", len(result.Findings))
	}
}

// ===========================================================================
// HTTPX JSONL — Comprehensive
// ===========================================================================

func TestComprehensive_HTTPX_FullResults(t *testing.T) {
	lines := []string{
		`{"url":"http://localhost:8765","status_code":200,"title":"Glitch Server","webserver":"glitch/2.0","tech":["Go","CustomFramework"]}`,
		`{"url":"http://localhost:8765/vuln","status_code":200,"title":"OWASP Demos","webserver":"glitch/2.0"}`,
		`{"url":"http://localhost:8765/admin","status_code":403,"title":"Forbidden","webserver":"glitch/2.0","header":{"content-type":"text/html"}}`,
	}
	data := []byte(strings.Join(lines, "\n"))

	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "httpx" {
		t.Errorf("Scanner = %q, want httpx", result.Scanner)
	}

	// 3 endpoint findings + security header findings from the entry with headers
	if len(result.Findings) < 3 {
		t.Errorf("Findings = %d, want >= 3", len(result.Findings))
	}

	// Check tech detection
	foundTech := false
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "Go") && strings.Contains(f.Description, "CustomFramework") {
			foundTech = true
		}
	}
	if !foundTech {
		t.Error("tech detection not found in findings")
	}
}

func TestComprehensive_HTTPX_SingleEntry(t *testing.T) {
	data := []byte(`{"url":"http://target:8080","status_code":200,"title":"Test","webserver":"nginx/1.20"}`)
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.URL != "http://target:8080" {
		t.Errorf("URL = %q", f.URL)
	}
	if f.Evidence != "nginx/1.20" {
		t.Errorf("Evidence = %q, want nginx/1.20", f.Evidence)
	}
	if !strings.Contains(f.Title, "200") {
		t.Errorf("Title = %q, expected to contain status code", f.Title)
	}
}

func TestComprehensive_HTTPX_EmptyInput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   \n  ")} {
		result, err := ParseHTTPXJSON(input)
		if err != nil {
			t.Fatalf("unexpected error for input %q: %v", input, err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_HTTPX_MalformedLines(t *testing.T) {
	data := []byte("this is not json\n{also broken\n")
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Malformed lines are silently skipped
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for all-malformed lines", len(result.Findings))
	}
}

func TestComprehensive_HTTPX_MissingFields(t *testing.T) {
	// No webserver, no tech, no title
	data := []byte(`{"url":"http://target/page","status_code":200}`)
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Evidence != "" {
		t.Errorf("Evidence = %q, want empty (no webserver)", f.Evidence)
	}
}

func TestComprehensive_HTTPX_SecurityHeaders(t *testing.T) {
	// Entry with headers object that has some security headers and misses others
	data := []byte(`{"url":"http://target","status_code":200,"header":{"x-frame-options":"DENY","content-type":"text/html"}}`)
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have missing header findings for all headers except x-frame-options
	missingCount := 0
	for _, f := range result.Findings {
		if strings.HasPrefix(f.Title, "Missing") {
			missingCount++
			if f.Severity != "low" {
				t.Errorf("missing header finding severity = %q, want low", f.Severity)
			}
		}
	}
	// 7 security headers checked, 1 present => 6 missing
	if missingCount != 6 {
		t.Errorf("missing header findings = %d, want 6", missingCount)
	}
}

func TestComprehensive_HTTPX_AllSecurityHeadersPresent(t *testing.T) {
	data := []byte(`{"url":"http://target","status_code":200,"header":{
		"x-frame-options":"DENY",
		"x-content-type-options":"nosniff",
		"strict-transport-security":"max-age=31536000",
		"content-security-policy":"default-src 'self'",
		"x-xss-protection":"1; mode=block",
		"referrer-policy":"no-referrer",
		"permissions-policy":"geolocation=()"
	}}`)
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range result.Findings {
		if strings.HasPrefix(f.Title, "Missing") {
			t.Errorf("unexpected missing header finding: %q", f.Title)
		}
	}
}

func TestComprehensive_HTTPX_LargeOutput(t *testing.T) {
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, fmt.Sprintf(
			`{"url":"http://target/path%d","status_code":200,"title":"Page %d"}`, i, i,
		))
	}
	data := []byte(strings.Join(lines, "\n"))
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1000 {
		t.Errorf("Findings = %d, want 1000", len(result.Findings))
	}
}

func TestComprehensive_HTTPX_Unicode(t *testing.T) {
	data := []byte(`{"url":"http://target/\u00e9","status_code":200,"title":"\u4e2d\u6587\u6807\u9898","webserver":"nginx"}`)
	result, err := ParseHTTPXJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
}

// ===========================================================================
// Generic Text Parser — Comprehensive
// ===========================================================================

func TestComprehensive_Generic_FullResults(t *testing.T) {
	// Note: "[INFO]" is matched by isProgressLine ("[info]" indicator) so
	// that line is skipped. The remaining 5 lines with finding keywords
	// should be captured.
	data := []byte(`Custom Scanner v3.0 started
Testing http://localhost:8765/
Progress: 25%
[CRITICAL] Remote code execution via command injection at http://localhost:8765/vuln/cmd/ping
[HIGH] SQL Injection vulnerability found at /vuln/sqli CWE-89
[HIGH] XSS reflected at http://localhost:8765/vuln/xss?q=test
[MEDIUM] Information disclosure at /vuln/a05/verbose-errors
[LOW] Cookie without secure flag on /vuln/a07/session
Server banner disclosure: glitch/2.0
Progress: 100%
Scan complete. Duration: 45s`)

	result, err := ParseGenericText("custom-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "custom-scanner" {
		t.Errorf("Scanner = %q", result.Scanner)
	}
	if len(result.Findings) < 6 {
		t.Errorf("Findings = %d, want >= 6", len(result.Findings))
	}

	// Verify severity detection
	foundCritical := false
	foundHigh := false
	foundMedium := false
	for _, f := range result.Findings {
		switch f.Severity {
		case "critical":
			foundCritical = true
		case "high":
			foundHigh = true
		case "medium":
			foundMedium = true
		}
	}
	if !foundCritical {
		t.Error("missing critical finding")
	}
	if !foundHigh {
		t.Error("missing high finding")
	}
	if !foundMedium {
		t.Error("missing medium finding")
	}
}

func TestComprehensive_Generic_EmptyInput(t *testing.T) {
	for _, input := range [][]byte{nil, {}, []byte(""), []byte("   \n\t  ")} {
		result, err := ParseGenericText("scanner", input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("input %q: Findings = %d, want 0", input, len(result.Findings))
		}
	}
}

func TestComprehensive_Generic_RandomText(t *testing.T) {
	data := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco.
Duis aute irure dolor in reprehenderit in voluptate velit esse.`)

	result, err := ParseGenericText("lorem", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 for random text with no security keywords", len(result.Findings))
	}
}

func TestComprehensive_Generic_CrashIndicators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"panic", "Scanner running...\npanic: runtime error: index out of range\ngoroutine 1 [running]"},
		{"segfault", "Testing...\nSegmentation fault (core dumped)"},
		{"fatal_error", "fatal error: all goroutines are asleep"},
		{"oom", "Out of memory: killed process 12345"},
		{"aborted", "Scanner aborted due to signal"},
		{"truncated_json", `{"started": true, "results": [`},
		{"truncated_array", `[{"finding": 1}, {"finding": 2`},
		{"truncated_html", `<html><body><h1>Results`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseGenericText("crash-test", []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Crashed {
				t.Error("should be marked as crashed")
			}
		})
	}
}

func TestComprehensive_Generic_TimeoutIndicators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"timed_out", "Error: operation timed out after 300s"},
		{"timeout", "Connection timeout after 60 seconds"},
		{"deadline", "context deadline exceeded"},
		{"deadline_2", "Error: deadline exceeded while scanning"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseGenericText("timeout-test", []byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.TimedOut {
				t.Error("should be marked as timed out")
			}
		})
	}
}

func TestComprehensive_Generic_ErrorLines(t *testing.T) {
	data := []byte(`Error: connection refused
Failed: unable to connect to host
cannot resolve hostname target.local
errno 111: connection refused
Permission denied: /etc/shadow
normal line here`)

	result, err := ParseGenericText("error-test", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Errors) < 4 {
		t.Errorf("Errors = %d, want >= 4", len(result.Errors))
	}
}

func TestComprehensive_Generic_CWEExtraction(t *testing.T) {
	data := []byte(`Found vulnerability CWE-79 at /vuln/xss
Detected CWE-89 SQL injection issue
Missing header check CWE 693`)

	result, err := ParseGenericText("cwe-test", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cweFound := map[string]bool{}
	for _, f := range result.Findings {
		if f.CWE != "" {
			cweFound[f.CWE] = true
		}
	}
	for _, want := range []string{"CWE-79", "CWE-89", "CWE-693"} {
		if !cweFound[want] {
			t.Errorf("missing CWE extraction for %s", want)
		}
	}
}

func TestComprehensive_Generic_URLExtraction(t *testing.T) {
	data := []byte(`[ALERT] XSS at http://localhost:8765/vuln/xss
[ALERT] Open redirect at https://example.com/redirect?to=evil
[ALERT] Missing header on /vuln/headers`)

	result, err := ParseGenericText("url-test", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	urls := map[string]bool{}
	for _, f := range result.Findings {
		if f.URL != "" {
			urls[f.URL] = true
		}
	}
	if !urls["http://localhost:8765/vuln/xss"] {
		t.Error("missing http URL extraction")
	}
	if !urls["https://example.com/redirect?to=evil"] {
		t.Error("missing https URL extraction")
	}
	if !urls["/vuln/headers"] {
		t.Error("missing path extraction")
	}
}

func TestComprehensive_Generic_ProgressLinesSkipped(t *testing.T) {
	data := []byte(`Progress: 10%
Scanning: http://localhost/
Testing: endpoints
[info] initialization complete
Status: running
Elapsed: 30s
ETA: 2 minutes
Requests/sec: 100
=== Summary ===
--- Results ---
vulnerability found at /test`)

	result, err := ParseGenericText("progress-test", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the last line should be a finding; progress lines are skipped
	if len(result.Findings) != 1 {
		t.Errorf("Findings = %d, want 1 (only the vulnerability line)", len(result.Findings))
	}
}

func TestComprehensive_Generic_LargeOutput(t *testing.T) {
	var lines []string
	for i := 0; i < 1000; i++ {
		lines = append(lines, fmt.Sprintf("[HIGH] XSS vulnerability %d at http://target/path%d", i, i))
	}
	data := []byte(strings.Join(lines, "\n"))

	result, err := ParseGenericText("large", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1000 {
		t.Errorf("Findings = %d, want 1000", len(result.Findings))
	}
}

func TestComprehensive_Generic_Unicode(t *testing.T) {
	data := []byte("[CRITICAL] XSS vulnerability \u00e9\u00e8\u00ea at http://target/\u00e9")
	result, err := ParseGenericText("unicode", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) < 1 {
		t.Error("should have at least 1 finding for unicode input with keywords")
	}
}

// ===========================================================================
// Wapiti JSON — Comprehensive (additional tests)
// ===========================================================================

func TestComprehensive_Wapiti_FullResults(t *testing.T) {
	data := []byte(`{
		"classifications": {
			"Cross Site Scripting": {"name":"Cross Site Scripting","desc":"XSS","sol":"encode","ref":"https://owasp.org/xss"},
			"SQL Injection": {"name":"SQL Injection","desc":"SQLi","sol":"parameterize","ref":"https://owasp.org/sqli"},
			"CRLF Injection": {"name":"CRLF Injection","desc":"Header injection","sol":"sanitize","ref":"https://owasp.org/crlf"}
		},
		"vulnerabilities": {
			"Cross Site Scripting": [
				{"method":"GET","path":"/vuln/xss?q=test","info":"XSS found CWE-79","level":3,"parameter":"q","wstg":"WSTG-INPV-01"},
				{"method":"POST","path":"/vuln/xss","info":"Stored XSS in body CWE-79","level":3,"parameter":"body","wstg":"WSTG-INPV-01"}
			],
			"SQL Injection": [
				{"method":"GET","path":"/vuln/sqli?id=1","info":"SQL injection CWE-89","level":4,"parameter":"id","wstg":"WSTG-INPV-05"}
			],
			"CRLF Injection": [
				{"method":"GET","path":"/vuln/crlf","info":"CRLF injection in header","level":2,"parameter":"header","wstg":"WSTG-INPV-15"}
			]
		},
		"anomalies": {
			"Server Error": [
				{"method":"GET","path":"/error500","info":"500 Internal Server Error","level":1}
			]
		},
		"infos": {
			"HTTP Methods": [
				{"method":"OPTIONS","path":"/","info":"Allowed: GET, POST, OPTIONS"}
			],
			"Technology": [
				{"method":"GET","path":"/","info":"Go language detected"}
			]
		}
	}`)

	result, err := ParseWapitiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanner != "wapiti" {
		t.Errorf("Scanner = %q, want wapiti", result.Scanner)
	}
	// 2 XSS + 1 SQLi + 1 CRLF + 1 anomaly + 2 infos = 7
	if len(result.Findings) != 7 {
		t.Fatalf("Findings = %d, want 7", len(result.Findings))
	}

	sevCount := map[string]int{}
	for _, f := range result.Findings {
		sevCount[f.Severity]++
	}
	// SQLi level 4 = critical(1), XSS level 3 = high(2), CRLF level 2 = medium(1), anomaly = low(1), info(2)
	if sevCount["critical"] != 1 {
		t.Errorf("critical count = %d, want 1", sevCount["critical"])
	}
	if sevCount["high"] != 2 {
		t.Errorf("high count = %d, want 2", sevCount["high"])
	}
	if sevCount["medium"] != 1 {
		t.Errorf("medium count = %d, want 1", sevCount["medium"])
	}
	if sevCount["low"] != 1 {
		t.Errorf("low count = %d, want 1", sevCount["low"])
	}
	if sevCount["info"] != 2 {
		t.Errorf("info count = %d, want 2", sevCount["info"])
	}
}

func TestComprehensive_Wapiti_EmptyCategories(t *testing.T) {
	data := []byte(`{"classifications":{},"vulnerabilities":{},"anomalies":{},"infos":{}}`)
	result, err := ParseWapitiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestComprehensive_Wapiti_OnlyAnomalies(t *testing.T) {
	data := []byte(`{
		"classifications":{},
		"vulnerabilities":{},
		"anomalies":{
			"Timeout": [{"method":"GET","path":"/slow","info":"Response took 30s","level":1}]
		},
		"infos":{}
	}`)

	result, err := ParseWapitiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Severity != "low" {
		t.Errorf("anomaly severity = %q, want low", result.Findings[0].Severity)
	}
}

// ===========================================================================
// ParseAndCompare — Comprehensive pipeline tests
// ===========================================================================

func TestComprehensive_ParseAndCompare_Nuclei(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte(strings.Join([]string{
		nucleiLine("xss-1", "XSS Found", "high", "http://target/vuln/xss", "CWE-79", ""),
		nucleiLine("info-1", "Server Banner", "info", "http://target/", "", ""),
	}, "\n"))

	report, err := ParseAndCompare("nuclei", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Scanner != "nuclei" {
		t.Errorf("Scanner = %q, want nuclei", report.Scanner)
	}
	if report.Grade == "" {
		t.Error("Grade should not be empty")
	}
	// Should have matched at least the XSS vuln (CWE match)
	if len(report.TruePositives) < 1 {
		t.Errorf("TruePositives = %d, want >= 1", len(report.TruePositives))
	}
	if report.DetectionRate <= 0 {
		t.Errorf("DetectionRate = %f, want > 0", report.DetectionRate)
	}
}

func TestComprehensive_ParseAndCompare_FFuf(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte(`{
		"commandline":"ffuf",
		"results":[
			{"input":{"FUZZ":"vuln/xss"},"position":1,"status":200,"length":100,"words":10,"lines":5,"url":"http://target/vuln/xss","host":"target"},
			{"input":{"FUZZ":"vuln/sqli"},"position":2,"status":200,"length":200,"words":20,"lines":10,"url":"http://target/vuln/sqli","host":"target"}
		],
		"config":{"url":"http://target/FUZZ"}
	}`)

	report, err := ParseAndCompare("ffuf", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Scanner != "ffuf" {
		t.Errorf("Scanner = %q, want ffuf", report.Scanner)
	}
	if report.ExpectedVulns != 3 {
		t.Errorf("ExpectedVulns = %d, want 3", report.ExpectedVulns)
	}
	if report.FoundVulns != 2 {
		t.Errorf("FoundVulns = %d, want 2", report.FoundVulns)
	}
}

func TestComprehensive_ParseAndCompare_Nmap(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="8765">
        <state state="open"/>
        <service name="http" product="glitch" version="2.0"/>
        <script id="http-server-header" output="glitch/2.0"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	report, err := ParseAndCompare("nmap", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Scanner != "nmap" {
		t.Errorf("Scanner = %q, want nmap", report.Scanner)
	}
}

func TestComprehensive_ParseAndCompare_Nikto(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte(`{"host":"localhost","port":"8765","vulnerabilities":[
		{"id":"1","OSVDB":0,"method":"GET","url":"/vuln/xss","msg":"XSS vulnerability found"},
		{"id":"2","OSVDB":0,"method":"GET","url":"/vuln/sqli","msg":"SQL injection possible"}
	]}`)

	report, err := ParseAndCompare("nikto", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Scanner != "nikto" {
		t.Errorf("Scanner = %q, want nikto", report.Scanner)
	}
}

func TestComprehensive_ParseAndCompare_HTTPX(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte(`{"url":"http://localhost:8765","status_code":200,"title":"Glitch","webserver":"glitch/2.0","tech":["Go"]}`)

	report, err := ParseAndCompare("httpx", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	if report.Scanner != "httpx" {
		t.Errorf("Scanner = %q, want httpx", report.Scanner)
	}
}

func TestComprehensive_ParseAndCompare_Unknown(t *testing.T) {
	profile := buildMinimalProfile()
	data := []byte("[HIGH] XSS vulnerability at /vuln/xss CWE-79")

	report, err := ParseAndCompare("custom-scanner-xyz", data, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil")
	}
	// Should have used generic text parser
	if report.Scanner != "custom-scanner-xyz" {
		t.Errorf("Scanner = %q, want custom-scanner-xyz", report.Scanner)
	}
}

func TestComprehensive_ParseAndCompare_EmptyData(t *testing.T) {
	profile := buildMinimalProfile()
	scanners := []string{"nuclei", "nikto", "nmap", "ffuf", "httpx", "unknown"}

	for _, scanner := range scanners {
		t.Run(scanner, func(t *testing.T) {
			report, err := ParseAndCompare(scanner, []byte(""), profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report == nil {
				t.Fatal("report is nil")
			}
			if report.DetectionRate != 0 {
				t.Errorf("DetectionRate = %f, want 0 for empty data", report.DetectionRate)
			}
		})
	}
}

func TestComprehensive_ParseAndCompare_MalformedData(t *testing.T) {
	profile := buildMinimalProfile()
	garbage := []byte{0x00, 0x01, 0xFF, 0xFE}
	scanners := []string{"nuclei", "nikto", "nmap", "ffuf", "httpx"}

	for _, scanner := range scanners {
		t.Run(scanner, func(t *testing.T) {
			report, err := ParseAndCompare(scanner, garbage, profile)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report == nil {
				t.Fatal("report is nil")
			}
		})
	}
}

// ===========================================================================
// CompareResults — grade calculation
// ===========================================================================

func TestComprehensive_CompareResults_GradeCalculation(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
			{ID: "v2", Name: "V2", Endpoints: []string{"/v2"}, CWE: "CWE-2", Detectable: true},
			{ID: "v3", Name: "V3", Endpoints: []string{"/v3"}, CWE: "CWE-3", Detectable: true},
			{ID: "v4", Name: "V4", Endpoints: []string{"/v4"}, CWE: "CWE-4", Detectable: true},
			{ID: "v5", Name: "V5", Endpoints: []string{"/v5"}, CWE: "CWE-5", Detectable: true},
			{ID: "v6", Name: "V6", Endpoints: []string{"/v6"}, CWE: "CWE-6", Detectable: true},
			{ID: "v7", Name: "V7", Endpoints: []string{"/v7"}, CWE: "CWE-7", Detectable: true},
			{ID: "v8", Name: "V8", Endpoints: []string{"/v8"}, CWE: "CWE-8", Detectable: true},
			{ID: "v9", Name: "V9", Endpoints: []string{"/v9"}, CWE: "CWE-9", Detectable: true},
			{ID: "v10", Name: "V10", Endpoints: []string{"/v10"}, CWE: "CWE-10", Detectable: true},
		},
		TotalVulns: 10,
		BySeverity: map[string]int{"high": 10},
	}

	tests := []struct {
		name      string
		findCount int
		wantGrade string
	}{
		{"10/10 found => A", 10, "A"},
		{"9/10 found => A", 9, "A"},
		{"7/10 found => B", 7, "B"},
		{"5/10 found => C", 5, "C"},
		{"3/10 found => D", 3, "D"},
		{"1/10 found => F", 1, "F"},
		{"0/10 found => F", 0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ScanResult{Scanner: "test"}
			for i := 0; i < tt.findCount; i++ {
				v := profile.Vulnerabilities[i]
				result.Findings = append(result.Findings, Finding{
					ID:  "f-" + v.ID,
					URL: v.Endpoints[0],
					CWE: v.CWE,
				})
			}

			report := CompareResults(profile, result)
			if report.Grade != tt.wantGrade {
				t.Errorf("Grade = %q, want %q (detection = %f)",
					report.Grade, tt.wantGrade, report.DetectionRate)
			}
		})
	}
}

func TestComprehensive_CompareResults_FalsePositives(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
		},
		TotalVulns: 1,
		BySeverity: map[string]int{"high": 1},
	}

	// Result with the expected finding plus 5 extra (false positives)
	result := &ScanResult{
		Scanner: "test",
		Findings: []Finding{
			{ID: "f1", URL: "/v1", CWE: "CWE-1"},       // true positive
			{ID: "f2", URL: "/unknown1", CWE: "CWE-99"}, // false positive
			{ID: "f3", URL: "/unknown2", CWE: "CWE-98"}, // false positive
			{ID: "f4", URL: "/unknown3", CWE: "CWE-97"}, // false positive
			{ID: "f5", URL: "/unknown4", CWE: "CWE-96"}, // false positive
			{ID: "f6", URL: "/unknown5", CWE: "CWE-95"}, // false positive
		},
	}

	report := CompareResults(profile, result)
	if len(report.TruePositives) != 1 {
		t.Errorf("TruePositives = %d, want 1", len(report.TruePositives))
	}
	if len(report.FalsePositives) != 5 {
		t.Errorf("FalsePositives = %d, want 5", len(report.FalsePositives))
	}
	if report.FalsePositiveRate <= 0 {
		t.Errorf("FalsePositiveRate = %f, want > 0", report.FalsePositiveRate)
	}
	if report.DetectionRate != 1.0 {
		t.Errorf("DetectionRate = %f, want 1.0", report.DetectionRate)
	}
}

func TestComprehensive_CompareResults_AllFalseNegatives(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
			{ID: "v2", Name: "V2", Endpoints: []string{"/v2"}, CWE: "CWE-2", Detectable: true},
		},
		TotalVulns: 2,
		BySeverity: map[string]int{"high": 2},
	}

	result := &ScanResult{Scanner: "test", Findings: []Finding{}}

	report := CompareResults(profile, result)
	if len(report.FalseNegatives) != 2 {
		t.Errorf("FalseNegatives = %d, want 2", len(report.FalseNegatives))
	}
	if report.DetectionRate != 0 {
		t.Errorf("DetectionRate = %f, want 0", report.DetectionRate)
	}
	if report.Grade != "F" {
		t.Errorf("Grade = %q, want F", report.Grade)
	}
}

func TestComprehensive_CompareResults_CrashedScanner(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
		},
		TotalVulns: 1,
	}

	result := &ScanResult{
		Scanner: "test",
		Crashed: true,
		Errors:  []string{"panic: segfault"},
	}

	report := CompareResults(profile, result)
	if !report.ScannerCrashed {
		t.Error("ScannerCrashed should be true")
	}
	if len(report.ScannerErrors) != 1 {
		t.Errorf("ScannerErrors = %d, want 1", len(report.ScannerErrors))
	}
}

func TestComprehensive_CompareResults_TimedOutScanner(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
		},
		TotalVulns: 1,
	}

	result := &ScanResult{
		Scanner:  "test",
		TimedOut: true,
	}

	report := CompareResults(profile, result)
	if !report.ScannerTimedOut {
		t.Error("ScannerTimedOut should be true")
	}
}

func TestComprehensive_CompareResults_NonDetectableVulns(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "v1", Name: "V1", Endpoints: []string{"/v1"}, CWE: "CWE-1", Detectable: true},
			{ID: "v2", Name: "V2 (not detectable)", Endpoints: []string{"/v2"}, CWE: "CWE-2", Detectable: false},
			{ID: "v3", Name: "V3 (not detectable)", Endpoints: []string{"/v3"}, CWE: "CWE-3", Detectable: false},
		},
		TotalVulns: 3,
	}

	result := &ScanResult{
		Scanner: "test",
		Findings: []Finding{
			{ID: "f1", URL: "/v1", CWE: "CWE-1"},
		},
	}

	report := CompareResults(profile, result)
	// Only 1 detectable vuln, and we found it => 100% detection
	if report.ExpectedVulns != 1 {
		t.Errorf("ExpectedVulns = %d, want 1 (only detectable)", report.ExpectedVulns)
	}
	if report.DetectionRate != 1.0 {
		t.Errorf("DetectionRate = %f, want 1.0", report.DetectionRate)
	}
}

// ===========================================================================
// Edge cases — nil, whitespace, very large
// ===========================================================================

func TestComprehensive_NilByteSlice(t *testing.T) {
	parsers := []struct {
		name  string
		parse func([]byte) (*ScanResult, error)
	}{
		{"nuclei", ParseNucleiJSON},
		{"nikto", ParseNiktoJSON},
		{"nmap", ParseNmapXML},
		{"ffuf", ParseFFufJSON},
		{"httpx", ParseHTTPXJSON},
		{"wapiti", ParseWapitiJSON},
	}

	for _, p := range parsers {
		t.Run(p.name, func(t *testing.T) {
			result, err := p.parse(nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("result should not be nil")
			}
			if len(result.Findings) != 0 {
				t.Errorf("Findings = %d, want 0", len(result.Findings))
			}
		})
	}

	// Generic parser
	result, err := ParseGenericText("test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Generic Findings = %d, want 0", len(result.Findings))
	}
}

func TestComprehensive_OnlyWhitespace(t *testing.T) {
	whitespace := []byte("   \t  \n  \n\t  \n   ")
	parsers := []struct {
		name  string
		parse func([]byte) (*ScanResult, error)
	}{
		{"nuclei", ParseNucleiJSON},
		{"nikto", ParseNiktoJSON},
		{"nmap", ParseNmapXML},
		{"ffuf", ParseFFufJSON},
		{"httpx", ParseHTTPXJSON},
		{"wapiti", ParseWapitiJSON},
	}

	for _, p := range parsers {
		t.Run(p.name, func(t *testing.T) {
			result, err := p.parse(whitespace)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("result should not be nil")
			}
			if len(result.Findings) != 0 {
				t.Errorf("Findings = %d, want 0", len(result.Findings))
			}
		})
	}
}

func TestComprehensive_VeryLargeNucleiOutput(t *testing.T) {
	// Generate 2000 lines
	line := nucleiLine("bulk-vuln", "Bulk", "medium", "http://target/bulk", "CWE-79", "")
	data := []byte(repeatLine(line, 2000))
	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2000 {
		t.Errorf("Findings = %d, want 2000", len(result.Findings))
	}
}

func TestComprehensive_TimestampFields(t *testing.T) {
	// Verify that all parsers set StartedAt and CompletedAt
	data := []byte(nucleiLine("t1", "T1", "info", "http://target/", "", ""))
	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if result.CompletedAt.IsZero() {
		t.Error("CompletedAt should not be zero")
	}
	if result.Duration <= 0 {
		// Duration could be 0 for very fast parses, but should be non-negative
		if result.Duration < 0 {
			t.Errorf("Duration = %v, should be non-negative", result.Duration)
		}
	}
}

// ===========================================================================
// Cross-parser consistency tests
// ===========================================================================

func TestComprehensive_ScannerFieldConsistency(t *testing.T) {
	tests := []struct {
		name     string
		parse    func([]byte) (*ScanResult, error)
		scanner  string
		data     []byte
	}{
		{
			"nuclei",
			ParseNucleiJSON,
			"nuclei",
			[]byte(nucleiLine("t1", "Test", "high", "http://target/", "", "")),
		},
		{
			"nikto",
			ParseNiktoJSON,
			"nikto",
			[]byte(`{"host":"localhost","port":"8765","vulnerabilities":[{"id":"1","OSVDB":0,"method":"GET","url":"/","msg":"Test"}]}`),
		},
		{
			"nmap",
			ParseNmapXML,
			"nmap",
			[]byte(`<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache" version="2.4"/></port></ports></host></nmaprun>`),
		},
		{
			"ffuf",
			ParseFFufJSON,
			"ffuf",
			[]byte(`{"commandline":"ffuf","results":[{"input":{"FUZZ":"test"},"position":1,"status":200,"length":100,"words":10,"lines":5,"url":"http://target/test","host":"target"}],"config":{"url":"http://target/FUZZ"}}`),
		},
		{
			"httpx",
			ParseHTTPXJSON,
			"httpx",
			[]byte(`{"url":"http://target","status_code":200,"title":"Test"}`),
		},
		{
			"wapiti",
			ParseWapitiJSON,
			"wapiti",
			[]byte(`{"classifications":{},"vulnerabilities":{"XSS":[{"method":"GET","path":"/xss","info":"XSS found","level":3}]},"anomalies":{},"infos":{}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.parse(tt.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Scanner != tt.scanner {
				t.Errorf("Scanner = %q, want %q", result.Scanner, tt.scanner)
			}
			if len(result.Findings) == 0 {
				t.Error("expected at least one finding")
			}
			for i, f := range result.Findings {
				if f.Severity == "" {
					t.Errorf("Finding[%d].Severity is empty", i)
				}
			}
		})
	}
}

// ===========================================================================
// ParseAndCompare full pipeline with grade verification
// ===========================================================================

func TestComprehensive_ParseAndCompare_FullPipelineGrade(t *testing.T) {
	profile := &ExpectedProfile{
		Vulnerabilities: []VulnCategory{
			{ID: "xss", Name: "XSS", Severity: "high", Endpoints: []string{"/vuln/xss"}, CWE: "CWE-79", Detectable: true},
			{ID: "sqli", Name: "SQLi", Severity: "critical", Endpoints: []string{"/vuln/sqli"}, CWE: "CWE-89", Detectable: true},
			{ID: "rce", Name: "RCE", Severity: "critical", Endpoints: []string{"/vuln/cmd"}, CWE: "CWE-78", Detectable: true},
			{ID: "cors", Name: "CORS", Severity: "medium", Endpoints: []string{"/vuln/cors"}, CWE: "CWE-942", Detectable: true},
			{ID: "hsts", Name: "HSTS", Severity: "low", Endpoints: []string{"/"}, CWE: "CWE-319", Detectable: true},
		},
		TotalVulns: 5,
		BySeverity: map[string]int{"critical": 2, "high": 1, "medium": 1, "low": 1},
	}

	// Nuclei finds all 5 => should get grade A
	nucleiData := []byte(strings.Join([]string{
		nucleiLine("xss-1", "XSS", "high", "http://target/vuln/xss", "CWE-79", ""),
		nucleiLine("sqli-1", "SQLi", "critical", "http://target/vuln/sqli", "CWE-89", ""),
		nucleiLine("rce-1", "RCE", "critical", "http://target/vuln/cmd", "CWE-78", ""),
		nucleiLine("cors-1", "CORS", "medium", "http://target/vuln/cors", "CWE-942", ""),
		nucleiLine("hsts-1", "HSTS", "info", "http://target/", "CWE-319", ""),
	}, "\n"))

	report, err := ParseAndCompare("nuclei", nucleiData, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.DetectionRate != 1.0 {
		t.Errorf("DetectionRate = %f, want 1.0", report.DetectionRate)
	}
	if report.Grade != "A" {
		t.Errorf("Grade = %q, want A", report.Grade)
	}
	if len(report.FalseNegatives) != 0 {
		t.Errorf("FalseNegatives = %d, want 0", len(report.FalseNegatives))
	}
}
