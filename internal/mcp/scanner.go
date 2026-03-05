package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ScanFinding represents a security issue found during MCP scanning.
type ScanFinding struct {
	Severity    string `json:"severity"` // critical, high, medium, low, info
	Category    string `json:"category"` // injection, credential, traversal, exfiltration, rug_pull
	Title       string `json:"title"`
	Description string `json:"description"`
	Tool        string `json:"tool,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Prompt      string `json:"prompt,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// ScanReport is the structured output of an MCP security scan.
type ScanReport struct {
	Target        string        `json:"target"`
	ScanTime      time.Time     `json:"scan_time"`
	DurationMS    int64         `json:"duration_ms"`
	ServerName    string        `json:"server_name"`
	ServerVersion string        `json:"server_version"`
	ToolCount     int           `json:"tool_count"`
	ResourceCount int           `json:"resource_count"`
	PromptCount   int           `json:"prompt_count"`
	Findings      []ScanFinding `json:"findings"`
	RiskScore     int           `json:"risk_score"` // 0-100
	RugPull       bool          `json:"rug_pull"`   // tool descriptions changed between calls
	Error         string        `json:"error,omitempty"`
}

// Scanner connects to external MCP servers and tests their security.
type Scanner struct {
	client *http.Client
}

// NewScanner creates a new MCP scanner.
func NewScanner() *Scanner {
	return &Scanner{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Scan performs a security scan of an MCP server at the given URL.
func (sc *Scanner) Scan(targetURL string) *ScanReport {
	start := time.Now()
	report := &ScanReport{
		Target:   targetURL,
		ScanTime: start,
	}

	// Step 1: Initialize handshake
	sid, serverInfo, err := sc.initialize(targetURL)
	if err != nil {
		report.Error = fmt.Sprintf("initialize failed: %v", err)
		report.DurationMS = time.Since(start).Milliseconds()
		return report
	}
	if name, ok := serverInfo["name"].(string); ok {
		report.ServerName = name
	}
	if ver, ok := serverInfo["version"].(string); ok {
		report.ServerVersion = ver
	}

	// Step 2: List and analyze tools
	tools, err := sc.listTools(targetURL, sid)
	if err == nil {
		report.ToolCount = len(tools)
		for _, t := range tools {
			findings := analyzeToolDescription(t)
			report.Findings = append(report.Findings, findings...)
		}
	}

	// Step 3: List and analyze resources
	resources, err := sc.listResources(targetURL, sid)
	if err == nil {
		report.ResourceCount = len(resources)
		for _, r := range resources {
			findings := analyzeResource(r)
			report.Findings = append(report.Findings, findings...)
		}
	}

	// Step 4: List and analyze prompts
	prompts, err := sc.listPrompts(targetURL, sid)
	if err == nil {
		report.PromptCount = len(prompts)
		for _, p := range prompts {
			findings := analyzePrompt(p)
			report.Findings = append(report.Findings, findings...)
		}
	}

	// Step 4.5: Canary testing — call tools with canary values
	if len(tools) > 0 {
		canaryFindings := sc.testCanaryPayloads(targetURL, sid, tools)
		report.Findings = append(report.Findings, canaryFindings...)
	}

	// Step 5: Rug pull detection — re-list tools and compare
	if len(tools) > 0 {
		tools2, err := sc.listTools(targetURL, sid)
		if err == nil {
			if detectRugPull(tools, tools2) {
				report.RugPull = true
				report.Findings = append(report.Findings, ScanFinding{
					Severity:    "critical",
					Category:    "rug_pull",
					Title:       "Tool description changed between calls",
					Description: "Tool descriptions differ between first and second listing, indicating a rug pull attack",
				})
			}
		}
	}

	// Step 6: Calculate risk score
	report.RiskScore = calculateRiskScore(report.Findings)
	report.DurationMS = time.Since(start).Milliseconds()

	// Clean up session
	sc.deleteSession(targetURL, sid)

	return report
}

// initialize performs the MCP handshake and returns session ID + server info.
func (sc *Scanner) initialize(url string) (string, map[string]interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"clientInfo": map[string]interface{}{
				"name":    "glitch-mcp-scanner",
				"version": "1.0.0",
			},
		},
	}

	resp, err := sc.rpcCall(url, "", req)
	if err != nil {
		return "", nil, err
	}

	sid, _ := resp["_session_id"].(string)
	result, _ := resp["result"].(map[string]interface{})
	if result == nil {
		return sid, nil, fmt.Errorf("no result in initialize response")
	}

	serverInfo, _ := result["serverInfo"].(map[string]interface{})
	return sid, serverInfo, nil
}

// listTools calls tools/list and returns tool definitions.
func (sc *Scanner) listTools(url, sid string) ([]map[string]interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	resp, err := sc.rpcCall(url, sid, req)
	if err != nil {
		return nil, err
	}
	result, _ := resp["result"].(map[string]interface{})
	if result == nil {
		return nil, nil
	}
	toolsRaw, _ := result["tools"].([]interface{})
	var tools []map[string]interface{}
	for _, t := range toolsRaw {
		if tm, ok := t.(map[string]interface{}); ok {
			tools = append(tools, tm)
		}
	}
	return tools, nil
}

// listResources calls resources/list.
func (sc *Scanner) listResources(url, sid string) ([]map[string]interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "resources/list",
	}
	resp, err := sc.rpcCall(url, sid, req)
	if err != nil {
		return nil, err
	}
	result, _ := resp["result"].(map[string]interface{})
	if result == nil {
		return nil, nil
	}
	resRaw, _ := result["resources"].([]interface{})
	var resources []map[string]interface{}
	for _, r := range resRaw {
		if rm, ok := r.(map[string]interface{}); ok {
			resources = append(resources, rm)
		}
	}
	return resources, nil
}

// listPrompts calls prompts/list.
func (sc *Scanner) listPrompts(url, sid string) ([]map[string]interface{}, error) {
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "prompts/list",
	}
	resp, err := sc.rpcCall(url, sid, req)
	if err != nil {
		return nil, err
	}
	result, _ := resp["result"].(map[string]interface{})
	if result == nil {
		return nil, nil
	}
	promptsRaw, _ := result["prompts"].([]interface{})
	var prompts []map[string]interface{}
	for _, p := range promptsRaw {
		if pm, ok := p.(map[string]interface{}); ok {
			prompts = append(prompts, pm)
		}
	}
	return prompts, nil
}

// testCanaryPayloads calls tools with unique canary values to detect data exfiltration.
func (sc *Scanner) testCanaryPayloads(url, sid string, tools []map[string]interface{}) []ScanFinding {
	var findings []ScanFinding
	canary := "GLITCH_CANARY_" + fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFFFF)

	for _, t := range tools {
		name, _ := t["name"].(string)
		if name == "" {
			continue
		}
		// Only test tools that accept string parameters
		schema, _ := t["inputSchema"].(map[string]interface{})
		if schema == nil {
			continue
		}
		props, _ := schema["properties"].(map[string]interface{})
		if len(props) == 0 {
			continue
		}

		// Build arguments with canary value for first string param
		args := make(map[string]interface{})
		for pName, pDef := range props {
			if pm, ok := pDef.(map[string]interface{}); ok {
				if pm["type"] == "string" {
					args[pName] = canary
					break
				}
			}
		}
		if len(args) == 0 {
			continue
		}

		argsJSON, _ := json.Marshal(args)
		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      100,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      name,
				"arguments": json.RawMessage(argsJSON),
			},
		}

		resp, err := sc.rpcCall(url, sid, req)
		if err != nil {
			continue
		}

		// Check if canary appears in the response (which it shouldn't normally)
		respBytes, _ := json.Marshal(resp)
		if strings.Contains(string(respBytes), canary) {
			findings = append(findings, ScanFinding{
				Severity:    "medium",
				Category:    "exfiltration",
				Title:       fmt.Sprintf("Canary reflected in tool '%s' response", name),
				Description: "Tool echoes back input data, which could be used for data exfiltration verification",
				Tool:        name,
				Evidence:    canary,
			})
		}
	}
	return findings
}

// deleteSession sends DELETE to close the session.
func (sc *Scanner) deleteSession(url, sid string) {
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("Mcp-Session-Id", sid)
	sc.client.Do(req)
}

// rpcCall sends a JSON-RPC request and returns the parsed response.
func (sc *Scanner) rpcCall(url, sid string, payload map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	// Capture session ID from response headers
	if respSID := resp.Header.Get("Mcp-Session-Id"); respSID != "" {
		result["_session_id"] = respSID
	}

	return result, nil
}

// --- Analysis functions ---

// injectionPatterns are strings that indicate tool description injection.
var injectionPatterns = []string{
	"<IMPORTANT>", "</IMPORTANT>",
	"<important>", "</important>",
	"IMPORTANT:", "WARNING:",
	"override", "ignore previous",
	"disregard", "instead of",
	"do not tell", "secretly",
	"before responding", "after completing",
}

// credentialKeywords indicate credential harvesting.
var credentialKeywords = []string{
	"password", "secret", "credential", "api_key", "api key",
	"access_key", "access key", "token", "private_key", "private key",
	"ssh key", "aws", "database connection",
}

func analyzeToolDescription(tool map[string]interface{}) []ScanFinding {
	var findings []ScanFinding
	name, _ := tool["name"].(string)
	desc, _ := tool["description"].(string)
	descLower := strings.ToLower(desc)

	// Check for injection patterns
	for _, pattern := range injectionPatterns {
		if strings.Contains(strings.ToLower(desc), strings.ToLower(pattern)) {
			findings = append(findings, ScanFinding{
				Severity:    "critical",
				Category:    "injection",
				Title:       fmt.Sprintf("Injection pattern in tool '%s'", name),
				Description: fmt.Sprintf("Tool description contains injection pattern: %s", pattern),
				Tool:        name,
				Evidence:    truncateEvidence(desc, 200),
			})
			break // one finding per tool for injection
		}
	}

	// Check for credential harvesting
	for _, kw := range credentialKeywords {
		if strings.Contains(descLower, kw) {
			findings = append(findings, ScanFinding{
				Severity:    "high",
				Category:    "credential",
				Title:       fmt.Sprintf("Credential-related tool '%s'", name),
				Description: fmt.Sprintf("Tool description mentions credentials: %s", kw),
				Tool:        name,
			})
			break
		}
	}

	// Check input schema for suspicious parameters
	if schema, ok := tool["inputSchema"].(map[string]interface{}); ok {
		if props, ok := schema["properties"].(map[string]interface{}); ok {
			for propName := range props {
				propLower := strings.ToLower(propName)
				if strings.Contains(propLower, "password") || strings.Contains(propLower, "secret") ||
					strings.Contains(propLower, "token") || strings.Contains(propLower, "key") ||
					strings.Contains(propLower, "credential") {
					findings = append(findings, ScanFinding{
						Severity:    "high",
						Category:    "exfiltration",
						Title:       fmt.Sprintf("Suspicious parameter '%s' in tool '%s'", propName, name),
						Description: "Tool accepts credential-like parameter that may harvest sensitive data",
						Tool:        name,
					})
				}
			}
		}
	}

	return findings
}

func analyzeResource(resource map[string]interface{}) []ScanFinding {
	var findings []ScanFinding
	uri, _ := resource["uri"].(string)
	name, _ := resource["name"].(string)
	uriLower := strings.ToLower(uri)

	// Check for path traversal
	if strings.Contains(uri, "../") {
		findings = append(findings, ScanFinding{
			Severity:    "critical",
			Category:    "traversal",
			Title:       fmt.Sprintf("Path traversal in resource '%s'", name),
			Description: "Resource URI contains path traversal sequence",
			Resource:    uri,
		})
	}

	// Check for suspicious file types
	suspiciousExts := []string{".env", ".pem", ".key", ".ssh", "credentials", "secrets", "id_rsa", "dump.sql"}
	for _, ext := range suspiciousExts {
		if strings.Contains(uriLower, ext) {
			findings = append(findings, ScanFinding{
				Severity:    "high",
				Category:    "credential",
				Title:       fmt.Sprintf("Suspicious resource '%s'", name),
				Description: fmt.Sprintf("Resource URI contains sensitive file indicator: %s", ext),
				Resource:    uri,
			})
			break
		}
	}

	// Check for absolute paths outside expected scope
	if strings.HasPrefix(uri, "file:///etc/") || strings.HasPrefix(uri, "file:///home/") ||
		strings.HasPrefix(uri, "file:///root/") || strings.HasPrefix(uri, "file:///backups/") {
		findings = append(findings, ScanFinding{
			Severity: "medium",
			Category: "traversal",
			Title:    fmt.Sprintf("System path resource '%s'", name),
			Description: "Resource URI references system paths outside application scope",
			Resource: uri,
		})
	}

	return findings
}

func analyzePrompt(prompt map[string]interface{}) []ScanFinding {
	var findings []ScanFinding
	name, _ := prompt["name"].(string)
	desc, _ := prompt["description"].(string)

	// Check prompt descriptions for injection
	for _, pattern := range injectionPatterns {
		if strings.Contains(strings.ToLower(desc), strings.ToLower(pattern)) {
			findings = append(findings, ScanFinding{
				Severity:    "high",
				Category:    "injection",
				Title:       fmt.Sprintf("Injection pattern in prompt '%s'", name),
				Description: fmt.Sprintf("Prompt description contains injection pattern: %s", pattern),
				Prompt:      name,
				Evidence:    truncateEvidence(desc, 200),
			})
			break
		}
	}

	// Check arguments for injection potential
	if args, ok := prompt["arguments"].([]interface{}); ok {
		for _, arg := range args {
			if am, ok := arg.(map[string]interface{}); ok {
				argDesc, _ := am["description"].(string)
				for _, pattern := range injectionPatterns {
					if strings.Contains(strings.ToLower(argDesc), strings.ToLower(pattern)) {
						findings = append(findings, ScanFinding{
							Severity:    "medium",
							Category:    "injection",
							Title:       fmt.Sprintf("Injection in prompt argument for '%s'", name),
							Description: "Prompt argument description contains injection pattern",
							Prompt:      name,
						})
						break
					}
				}
			}
		}
	}

	return findings
}

// detectRugPull compares two tool listings to detect description changes.
func detectRugPull(first, second []map[string]interface{}) bool {
	hash := func(tools []map[string]interface{}) string {
		h := sha256.New()
		for _, t := range tools {
			name, _ := t["name"].(string)
			desc, _ := t["description"].(string)
			fmt.Fprintf(h, "%s:%s\n", name, desc)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	return hash(first) != hash(second)
}

// calculateRiskScore computes an overall risk score from findings.
func calculateRiskScore(findings []ScanFinding) int {
	score := 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score += 25
		case "high":
			score += 15
		case "medium":
			score += 8
		case "low":
			score += 3
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func truncateEvidence(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
