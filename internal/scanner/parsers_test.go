package scanner

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Nuclei JSONL parser tests
// ---------------------------------------------------------------------------

func TestParseNucleiJSON_ValidOutput(t *testing.T) {
	data := []byte(`{"template-id":"cve-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical","description":"Remote code execution via Log4j","classification":{"cwe-id":["CWE-502"]}},"matched-at":"http://localhost:8765/vuln/a03/","timestamp":"2025-01-01T00:00:00Z"}
{"template-id":"cors-misconfiguration","info":{"name":"CORS Misconfiguration","severity":"medium","description":"Origin reflection in CORS headers","classification":{"cwe-id":["CWE-942"]},"reference":["https://owasp.org/cors"]},"matched-at":"http://localhost:8765/vuln/cors/reflect","timestamp":"2025-01-01T00:00:01Z"}
{"template-id":"missing-hsts","info":{"name":"Missing HSTS Header","severity":"info","description":"Strict-Transport-Security header not set","classification":{"cwe-id":[]}},"matched-at":"http://localhost:8765/","timestamp":"2025-01-01T00:00:02Z"}`)

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Scanner != "nuclei" {
		t.Errorf("Scanner = %q, want nuclei", result.Scanner)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("Findings count = %d, want 3", len(result.Findings))
	}

	// Check first finding
	f0 := result.Findings[0]
	if f0.ID != "cve-2021-44228" {
		t.Errorf("Finding[0].ID = %q, want cve-2021-44228", f0.ID)
	}
	if f0.Severity != "critical" {
		t.Errorf("Finding[0].Severity = %q, want critical", f0.Severity)
	}
	if f0.CWE != "CWE-502" {
		t.Errorf("Finding[0].CWE = %q, want CWE-502", f0.CWE)
	}
	if f0.URL != "http://localhost:8765/vuln/a03/" {
		t.Errorf("Finding[0].URL = %q, want http://localhost:8765/vuln/a03/", f0.URL)
	}

	// Check second finding has reference
	f1 := result.Findings[1]
	if f1.Reference != "https://owasp.org/cors" {
		t.Errorf("Finding[1].Reference = %q, want https://owasp.org/cors", f1.Reference)
	}

	if result.Crashed {
		t.Error("result should not be marked as crashed")
	}
}

func TestParseNucleiJSON_EmptyInput(t *testing.T) {
	result, err := ParseNucleiJSON([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings count = %d, want 0", len(result.Findings))
	}
}

func TestParseNucleiJSON_MalformedLines(t *testing.T) {
	data := []byte(`{"template-id":"valid","info":{"name":"Valid","severity":"high","description":"ok","classification":{"cwe-id":[]}},"matched-at":"http://host/path"}
this is not json
also not json
{"template-id":"valid2","info":{"name":"Valid2","severity":"low","description":"ok2","classification":{"cwe-id":["CWE-200"]}},"matched-at":"http://host/path2"}`)

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 2 {
		t.Errorf("Findings = %d, want 2 (valid lines only)", len(result.Findings))
	}

	if len(result.Errors) != 2 {
		t.Errorf("Errors = %d, want 2 (malformed lines)", len(result.Errors))
	}

	// 2 out of 4 lines are bad, which is exactly half, so not >half => not crashed
	if result.Crashed {
		t.Error("should not be crashed when exactly half are malformed")
	}
}

func TestParseNucleiJSON_MostlyMalformed(t *testing.T) {
	data := []byte(`not json 1
not json 2
not json 3
{"template-id":"valid","info":{"name":"Valid","severity":"info","description":"ok","classification":{"cwe-id":[]}},"matched-at":"http://host/"}`)

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed when more than half lines are malformed")
	}
}

func TestParseNucleiJSON_SeverityNormalization(t *testing.T) {
	data := []byte(`{"template-id":"t1","info":{"name":"T1","severity":"CRITICAL","description":"d","classification":{"cwe-id":[]}},"matched-at":"http://host/"}
{"template-id":"t2","info":{"name":"T2","severity":"Medium","description":"d","classification":{"cwe-id":[]}},"matched-at":"http://host/"}
{"template-id":"t3","info":{"name":"T3","severity":"informational","description":"d","classification":{"cwe-id":[]}},"matched-at":"http://host/"}`)

	result, err := ParseNucleiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := []string{"critical", "medium", "info"}
	for i, want := range expected {
		if result.Findings[i].Severity != want {
			t.Errorf("Finding[%d].Severity = %q, want %q", i, result.Findings[i].Severity, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Nikto JSON parser tests
// ---------------------------------------------------------------------------

func TestParseNiktoJSON_ValidOutput(t *testing.T) {
	data := []byte(`{
		"host": "localhost",
		"ip": "127.0.0.1",
		"port": "8765",
		"banner": "Go HTTP Server",
		"vulnerabilities": [
			{
				"id": "999990",
				"OSVDB": 0,
				"method": "GET",
				"url": "/admin",
				"msg": "Admin login page found"
			},
			{
				"id": "999991",
				"OSVDB": 3092,
				"method": "GET",
				"url": "/.env",
				"msg": "Environment file disclosure - contains sensitive information"
			}
		]
	}`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Scanner != "nikto" {
		t.Errorf("Scanner = %q, want nikto", result.Scanner)
	}

	if len(result.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(result.Findings))
	}

	f0 := result.Findings[0]
	if f0.URL != "/admin" {
		t.Errorf("Finding[0].URL = %q, want /admin", f0.URL)
	}

	f1 := result.Findings[1]
	if f1.URL != "/.env" {
		t.Errorf("Finding[1].URL = %q, want /.env", f1.URL)
	}
	// "disclosure" should give medium severity
	if f1.Severity != "medium" {
		t.Errorf("Finding[1].Severity = %q, want medium", f1.Severity)
	}
}

func TestParseNiktoJSON_EmptyInput(t *testing.T) {
	result, err := ParseNiktoJSON([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestParseNiktoJSON_MalformedInput(t *testing.T) {
	data := []byte(`{"host": "localhost", "port": "8765", "vulnerabilities": [{"id": "1"`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed for truncated JSON")
	}
	if len(result.Errors) == 0 {
		t.Error("should have parse errors")
	}
}

func TestParseNiktoJSON_ArrayFormat(t *testing.T) {
	data := []byte(`[{
		"host": "localhost",
		"port": "8765",
		"vulnerabilities": [
			{
				"id": "1",
				"OSVDB": 0,
				"method": "GET",
				"url": "/test",
				"msg": "Test finding with SQL injection possible"
			}
		]
	}]`)

	result, err := ParseNiktoJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Errorf("Findings = %d, want 1", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// Nmap XML parser tests
// ---------------------------------------------------------------------------

func TestParseNmapXML_ValidOutput(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="-sV --script=http-headers localhost" start="1234567890">
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="8765">
        <state state="open"/>
        <service name="http" product="Go HTTP Server" version="1.24"/>
        <script id="http-headers" output="X-Debug-Mode: true&#xa;Server: Apache/2.4.29 (Ubuntu)&#xa;X-Powered-By: PHP/5.6.40"/>
        <script id="http-server-header" output="Go HTTP Server"/>
      </port>
      <port protocol="tcp" portid="8766">
        <state state="open"/>
        <service name="http" product="Go HTTP Server" version="1.24"/>
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

	// Should have service detection + script findings
	if len(result.Findings) < 2 {
		t.Errorf("Findings = %d, want >= 2", len(result.Findings))
	}

	// Check that service detection produces a finding
	foundService := false
	for _, f := range result.Findings {
		if f.ID == "nmap-service-8765" {
			foundService = true
			if f.Severity != "info" {
				t.Errorf("service finding severity = %q, want info", f.Severity)
			}
		}
	}
	if !foundService {
		t.Error("missing service detection finding for port 8765")
	}
}

func TestParseNmapXML_EmptyInput(t *testing.T) {
	result, err := ParseNmapXML([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestParseNmapXML_MalformedInput(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed for truncated XML")
	}
}

func TestParseNmapXML_VulnScript(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-heartbleed" output="VULNERABLE: The Heartbleed Bug is a serious vulnerability CWE-119"/>
      </port>
    </ports>
  </host>
</nmaprun>`)

	result, err := ParseNmapXML(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Find the vuln script finding
	found := false
	for _, f := range result.Findings {
		if f.ID == "nmap-ssl-heartbleed" {
			found = true
			if f.CWE != "CWE-119" {
				t.Errorf("CWE = %q, want CWE-119", f.CWE)
			}
		}
	}
	if !found {
		t.Error("missing ssl-heartbleed finding")
	}
}

// ---------------------------------------------------------------------------
// FFuf JSON parser tests
// ---------------------------------------------------------------------------

func TestParseFFufJSON_ValidOutput(t *testing.T) {
	data := []byte(`{
		"commandline": "ffuf -u http://localhost:8765/FUZZ -w wordlist.txt",
		"results": [
			{
				"input": {"FUZZ": "admin"},
				"position": 1,
				"status": 200,
				"length": 1234,
				"words": 100,
				"lines": 50,
				"url": "http://localhost:8765/admin",
				"host": "localhost:8765"
			},
			{
				"input": {"FUZZ": ".env"},
				"position": 2,
				"status": 200,
				"length": 567,
				"words": 30,
				"lines": 15,
				"url": "http://localhost:8765/.env",
				"host": "localhost:8765"
			},
			{
				"input": {"FUZZ": "backup.sql"},
				"position": 3,
				"status": 200,
				"length": 89012,
				"words": 5000,
				"lines": 1000,
				"url": "http://localhost:8765/backup.sql",
				"host": "localhost:8765"
			}
		],
		"config": {
			"url": "http://localhost:8765/FUZZ"
		}
	}`)

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Scanner != "ffuf" {
		t.Errorf("Scanner = %q, want ffuf", result.Scanner)
	}

	if len(result.Findings) != 3 {
		t.Fatalf("Findings = %d, want 3", len(result.Findings))
	}

	if result.RequestCount != 3 {
		t.Errorf("RequestCount = %d, want 3", result.RequestCount)
	}

	// Admin should be high severity
	f0 := result.Findings[0]
	if f0.Severity != "high" {
		t.Errorf("admin finding severity = %q, want high", f0.Severity)
	}
}

func TestParseFFufJSON_EmptyInput(t *testing.T) {
	result, err := ParseFFufJSON([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestParseFFufJSON_MalformedInput(t *testing.T) {
	data := []byte(`{"results": [{"url": "http://host/test"`)

	result, err := ParseFFufJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed for truncated JSON")
	}
}

// ---------------------------------------------------------------------------
// Wapiti JSON parser tests
// ---------------------------------------------------------------------------

func TestParseWapitiJSON_ValidOutput(t *testing.T) {
	data := []byte(`{
		"classifications": {
			"Cross Site Scripting": {
				"name": "Cross Site Scripting",
				"desc": "XSS allows injection of client-side scripts",
				"sol": "Use output encoding",
				"ref": "https://owasp.org/xss"
			}
		},
		"vulnerabilities": {
			"Cross Site Scripting": [
				{
					"method": "GET",
					"path": "/vuln/a03/xss?q=test",
					"info": "XSS vulnerability found in parameter q CWE-79",
					"level": 3,
					"parameter": "q",
					"http_request": "GET /vuln/a03/xss?q=<script>",
					"curl_command": "curl http://localhost:8765/vuln/a03/xss?q=test",
					"wstg": "WSTG-INPV-01",
					"response": "200"
				}
			],
			"SQL Injection": [
				{
					"method": "GET",
					"path": "/vuln/a03/sqli?id=1",
					"info": "SQL injection in parameter id",
					"level": 4,
					"parameter": "id",
					"http_request": "GET /vuln/a03/sqli?id=1'",
					"wstg": "WSTG-INPV-05"
				}
			]
		},
		"anomalies": {
			"Internal Server Error": [
				{
					"method": "GET",
					"path": "/vuln/a05/verbose-errors",
					"info": "500 Internal Server Error",
					"level": 1
				}
			]
		},
		"infos": {
			"HTTP Methods": [
				{
					"method": "OPTIONS",
					"path": "/",
					"info": "Supported methods: GET, POST, PUT, DELETE, OPTIONS"
				}
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

	// Should have: 1 XSS + 1 SQLi + 1 anomaly + 1 info = 4 findings
	if len(result.Findings) != 4 {
		t.Fatalf("Findings = %d, want 4", len(result.Findings))
	}

	// Check XSS finding
	xssFound := false
	sqliFound := false
	anomalyFound := false
	infoFound := false
	for _, f := range result.Findings {
		switch {
		case f.Title == "Cross Site Scripting: XSS vulnerability found in parameter q CWE-79":
			xssFound = true
			if f.Severity != "high" { // level 3 = high
				t.Errorf("XSS severity = %q, want high", f.Severity)
			}
			if f.CWE != "CWE-79" {
				t.Errorf("XSS CWE = %q, want CWE-79", f.CWE)
			}
		case f.Severity == "critical" && f.URL == "/vuln/a03/sqli?id=1":
			sqliFound = true
		case f.Severity == "low":
			anomalyFound = true
		case f.Severity == "info":
			infoFound = true
		}
	}

	if !xssFound {
		t.Error("XSS finding not found")
	}
	if !sqliFound {
		t.Error("SQLi finding not found")
	}
	if !anomalyFound {
		t.Error("anomaly finding not found")
	}
	if !infoFound {
		t.Error("info finding not found")
	}
}

func TestParseWapitiJSON_EmptyInput(t *testing.T) {
	result, err := ParseWapitiJSON([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestParseWapitiJSON_MalformedInput(t *testing.T) {
	data := []byte(`{"vulnerabilities": {"XSS": [{"method": "GET"`)

	result, err := ParseWapitiJSON(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed for truncated JSON")
	}
}

// ---------------------------------------------------------------------------
// Generic text parser tests
// ---------------------------------------------------------------------------

func TestParseGenericText_WithFindings(t *testing.T) {
	data := []byte(`Scanner started at 2025-01-01 00:00:00
Testing http://localhost:8765/
Progress: 10%
[HIGH] SQL Injection vulnerability found at /vuln/a03/sqli
[MEDIUM] Missing HSTS header on http://localhost:8765/
[CRITICAL] Remote code execution possible via command injection at /vuln/cmd/ping
Progress: 100%
Scan complete`)

	result, err := ParseGenericText("custom-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Scanner != "custom-scanner" {
		t.Errorf("Scanner = %q, want custom-scanner", result.Scanner)
	}

	// Should find at least the 3 findings (high, medium, critical)
	if len(result.Findings) < 3 {
		t.Errorf("Findings = %d, want >= 3", len(result.Findings))
	}
}

func TestParseGenericText_EmptyInput(t *testing.T) {
	result, err := ParseGenericText("scanner", []byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Findings = %d, want 0", len(result.Findings))
	}
}

func TestParseGenericText_CrashDetection(t *testing.T) {
	data := []byte(`Scanner starting...
Testing endpoints...
panic: runtime error: index out of range
goroutine 1 [running]:
main.main()
	/scanner/main.go:42 +0x123`)

	result, err := ParseGenericText("crashing-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Crashed {
		t.Error("should be marked as crashed when output contains panic")
	}
}

func TestParseGenericText_TimeoutDetection(t *testing.T) {
	data := []byte(`Scanner starting...
Testing http://localhost:8765/
Error: operation timed out after 300 seconds
Partial results saved`)

	result, err := ParseGenericText("slow-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.TimedOut {
		t.Error("should be marked as timed out")
	}
}

func TestParseGenericText_ErrorDetection(t *testing.T) {
	data := []byte(`Error: connection refused to localhost:8765
Failed: unable to connect
vulnerability check skipped`)

	result, err := ParseGenericText("error-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Errors) < 2 {
		t.Errorf("Errors = %d, want >= 2", len(result.Errors))
	}
}

func TestParseGenericText_URLExtraction(t *testing.T) {
	data := []byte(`[HIGH] XSS vulnerability found at http://localhost:8765/vuln/a03/xss
[MEDIUM] Open redirect at /vuln/redirect?url=evil.com`)

	result, err := ParseGenericText("url-scanner", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) < 2 {
		t.Fatalf("Findings = %d, want >= 2", len(result.Findings))
	}

	// Check URL extraction from full URL
	foundFullURL := false
	foundPath := false
	for _, f := range result.Findings {
		if f.URL == "http://localhost:8765/vuln/a03/xss" {
			foundFullURL = true
		}
		if f.URL == "/vuln/redirect?url=evil.com" {
			foundPath = true
		}
	}

	if !foundFullURL {
		t.Error("failed to extract full URL from finding")
	}
	if !foundPath {
		t.Error("failed to extract path from finding")
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		max    int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"this is a very long string", 10, "this is..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Cross Site Scripting", "cross-site-scripting"},
		{"SQL_Injection!!!", "sql-injection"},
		{"test---test", "test-test"},
	}

	for _, tt := range tests {
		got := sanitizeID(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input int
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{1234567, "1234567"},
		{-5, "-5"},
	}

	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractCWEFromText(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"CWE-79 Cross-Site Scripting", "CWE-79"},
		{"vulnerability cwe-502 deserialization", "CWE-502"},
		{"no cwe here", ""},
		{"CWE 200 information disclosure", "CWE-200"},
		{"multiple CWE-79 and CWE-89", "CWE-79"}, // returns first
	}

	for _, tt := range tests {
		got := extractCWEFromText(tt.input)
		if got != tt.want {
			t.Errorf("extractCWEFromText(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractURLFromText(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"found at http://localhost:8765/admin", "http://localhost:8765/admin"},
		{"found at https://example.com/path", "https://example.com/path"},
		{"path is /vuln/a01/idor", "/vuln/a01/idor"},
		{"no url here", ""},
	}

	for _, tt := range tests {
		got := extractURLFromText(tt.input)
		if got != tt.want {
			t.Errorf("extractURLFromText(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"crit", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"medium", "medium"},
		{"med", "medium"},
		{"moderate", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"none", "info"},
		{"unknown", "info"},
	}

	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsCrashedOutput(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"panic: runtime error", true},
		{"Segmentation fault (core dumped)", true},
		{"normal output", false},
		{`{"incomplete": true`, true},  // truncated JSON
		{`<html><body>`, true},          // truncated XML/HTML
		{`{"complete": true}`, false},   // valid JSON
	}

	for _, tt := range tests {
		got := isCrashedOutput(tt.input)
		if got != tt.want {
			t.Errorf("isCrashedOutput(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestIsTimedOutOutput(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"operation timed out", true},
		{"context deadline exceeded", true},
		{"scan completed successfully", false},
	}

	for _, tt := range tests {
		got := isTimedOutOutput(tt.input)
		if got != tt.want {
			t.Errorf("isTimedOutOutput(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestWapitiSeverity(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{4, "critical"},
		{5, "critical"},
		{3, "high"},
		{2, "medium"},
		{1, "low"},
		{0, "info"},
	}

	for _, tt := range tests {
		got := wapitiSeverity(tt.level)
		if got != tt.want {
			t.Errorf("wapitiSeverity(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}
