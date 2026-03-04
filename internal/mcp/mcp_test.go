package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- JSON-RPC tests ---

func TestParseRequest_Valid(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req, err := ParseRequest([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != "initialize" {
		t.Errorf("method = %q, want %q", req.Method, "initialize")
	}
	if req.IsNotification() {
		t.Error("should not be a notification")
	}
}

func TestParseRequest_Notification(t *testing.T) {
	data := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, err := ParseRequest([]byte(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !req.IsNotification() {
		t.Error("should be a notification")
	}
}

func TestParseRequest_InvalidVersion(t *testing.T) {
	data := `{"jsonrpc":"1.0","id":1,"method":"test"}`
	_, err := ParseRequest([]byte(data))
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestParseRequest_MissingMethod(t *testing.T) {
	data := `{"jsonrpc":"2.0","id":1}`
	_, err := ParseRequest([]byte(data))
	if err == nil {
		t.Error("expected error for missing method")
	}
}

// --- Session tests ---

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := NewSessionStore()
	sid := store.Create(map[string]interface{}{"name": "test-client"})
	if sid == "" {
		t.Fatal("empty session ID")
	}

	sess := store.Get(sid)
	if sess == nil {
		t.Fatal("session not found")
	}
	if sess.ClientInfo["name"] != "test-client" {
		t.Errorf("client name = %v, want test-client", sess.ClientInfo["name"])
	}
}

func TestSessionStore_RecordToolCall(t *testing.T) {
	store := NewSessionStore()
	sid := store.Create(nil)
	store.RecordToolCall(sid, "ping")
	store.RecordToolCall(sid, "ping")
	store.RecordToolCall(sid, "get_aws_credentials")

	sess := store.Get(sid)
	if sess.ToolCalls["ping"] != 2 {
		t.Errorf("ping calls = %d, want 2", sess.ToolCalls["ping"])
	}
	if sess.ToolCalls["get_aws_credentials"] != 1 {
		t.Errorf("aws calls = %d, want 1", sess.ToolCalls["get_aws_credentials"])
	}
}

func TestSessionStore_Delete(t *testing.T) {
	store := NewSessionStore()
	sid := store.Create(nil)
	store.Delete(sid)
	if store.Get(sid) != nil {
		t.Error("session should be deleted")
	}
}

// --- Tool registry tests ---

func TestToolRegistry_ListAndGet(t *testing.T) {
	reg := NewToolRegistry()
	tools := reg.List()
	if len(tools) == 0 {
		t.Fatal("no tools registered")
	}

	// Check known tools exist
	for _, name := range []string{"get_aws_credentials", "ping", "get_server_status"} {
		if reg.Get(name) == nil {
			t.Errorf("tool %q not found", name)
		}
	}
}

func TestToolRegistry_ExecuteHoneypot(t *testing.T) {
	reg := NewToolRegistry()

	tests := []struct {
		name string
		args string
	}{
		{"get_aws_credentials", `{"profile":"default"}`},
		{"get_api_keys", `{}`},
		{"get_database_connection", `{"environment":"production"}`},
		{"analyze_codebase", `{"code":"test code"}`},
		{"submit_feedback", `{"feedback":"test"}`},
		{"check_vulnerability", `{"cve_id":"CVE-2024-1234"}`},
		{"generate_report", `{"scope":"quick"}`},
		{"run_diagnostics", `{"target":"localhost"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reg.Execute(tt.name, json.RawMessage(tt.args))
			if result.IsError {
				t.Errorf("unexpected error: %s", result.Content[0].Text)
			}
			if len(result.Content) == 0 || result.Content[0].Text == "" {
				t.Error("empty result")
			}
		})
	}
}

func TestToolRegistry_ExecuteLegit(t *testing.T) {
	reg := NewToolRegistry()

	for _, name := range []string{"get_server_status", "list_endpoints", "ping"} {
		t.Run(name, func(t *testing.T) {
			result := reg.Execute(name, nil)
			if result.IsError {
				t.Errorf("unexpected error: %s", result.Content[0].Text)
			}
		})
	}
}

func TestToolRegistry_ExecuteUnknown(t *testing.T) {
	reg := NewToolRegistry()
	result := reg.Execute("nonexistent_tool", nil)
	if !result.IsError {
		t.Error("expected error for unknown tool")
	}
}

// --- Resource registry tests ---

func TestResourceRegistry_ListAndRead(t *testing.T) {
	reg := NewResourceRegistry()
	resources := reg.List()
	if len(resources) == 0 {
		t.Fatal("no resources registered")
	}

	// Read a honeypot resource
	result := reg.Read("file:///app/.env")
	if len(result.Contents) == 0 {
		t.Fatal("empty result")
	}
	content := result.Contents[0].Text
	if !strings.Contains(content, "DATABASE_URL") {
		t.Error("expected .env to contain DATABASE_URL")
	}
	if !strings.Contains(content, "AWS_ACCESS_KEY_ID") {
		t.Error("expected .env to contain AWS_ACCESS_KEY_ID")
	}
}

func TestResourceRegistry_ReadLegit(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///app/README.md")
	if len(result.Contents) == 0 {
		t.Fatal("empty result")
	}
	if !strings.Contains(result.Contents[0].Text, "Glitch MCP") {
		t.Error("expected README content")
	}
}

func TestResourceRegistry_ReadUnknown(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///nonexistent")
	if len(result.Contents) == 0 {
		t.Fatal("empty result")
	}
	if !strings.Contains(result.Contents[0].Text, "not found") {
		t.Error("expected not found message")
	}
}

// --- Prompt registry tests ---

func TestPromptRegistry_ListAndGet(t *testing.T) {
	reg := NewPromptRegistry()
	prompts := reg.List()
	if len(prompts) == 0 {
		t.Fatal("no prompts registered")
	}

	// Get a honeypot prompt
	result := reg.Get("security_audit", map[string]string{"scope": "full"})
	if len(result.Messages) == 0 {
		t.Fatal("empty messages")
	}
	msg := result.Messages[0].Content.Text
	if !strings.Contains(msg, "get_aws_credentials") {
		t.Error("security_audit should reference credential tools")
	}
}

func TestPromptRegistry_GetLegit(t *testing.T) {
	reg := NewPromptRegistry()
	result := reg.Get("help", nil)
	if len(result.Messages) == 0 {
		t.Fatal("empty messages")
	}
}

func TestPromptRegistry_GetUnknown(t *testing.T) {
	reg := NewPromptRegistry()
	result := reg.Get("nonexistent", nil)
	if len(result.Messages) == 0 {
		t.Fatal("empty messages")
	}
	if !strings.Contains(result.Messages[0].Content.Text, "not found") {
		t.Error("expected not found message")
	}
}

// --- Server integration tests ---

func TestServer_Initialize(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test-client","version":"1.0"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result not a map")
	}
	if result["protocolVersion"] != "2025-03-26" {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}
}

func TestServer_ToolsList(t *testing.T) {
	srv := NewServer()

	// Initialize first to get a session
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test"}}}`
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
	initW := httptest.NewRecorder()
	srv.ServeHTTP(initW, initReq)

	// Now list tools
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("result not a map")
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatal("tools not an array")
	}
	if len(tools) == 0 {
		t.Error("no tools returned")
	}
}

func TestServer_ToolsCall(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestServer_ResourcesList(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}

	result := resp.Result.(map[string]interface{})
	resources := result["resources"].([]interface{})
	if len(resources) == 0 {
		t.Error("no resources returned")
	}
}

func TestServer_ResourcesRead(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///app/.env"}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestServer_PromptsList(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"prompts/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestServer_PromptsGet(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"security_audit","arguments":{"scope":"full"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestServer_Ping(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Message)
	}
}

func TestServer_MethodNotFound(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"nonexistent/method"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("code = %d, want %d", resp.Error.Code, ErrCodeMethodNotFound)
	}
}

func TestServer_Notification(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusAccepted {
		t.Errorf("status = %d, want %d", status, http.StatusAccepted)
	}
}

func TestServer_DeleteSession(t *testing.T) {
	srv := NewServer()

	// Initialize to create session
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test"}}}`
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
	initW := httptest.NewRecorder()
	srv.ServeHTTP(initW, initReq)

	// Get session from response header
	sid := initW.Header().Get("Mcp-Session-Id")

	// Delete session
	delReq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	delReq.Header.Set("Mcp-Session-Id", sid)
	delW := httptest.NewRecorder()

	status := srv.ServeHTTP(delW, delReq)
	if status != http.StatusOK {
		t.Errorf("delete status = %d, want %d", status, http.StatusOK)
	}
}

func TestServer_DeleteNoSession(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestServer_MethodNotAllowed(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest(http.MethodPut, "/mcp", nil)
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", status, http.StatusMethodNotAllowed)
	}
}

func TestServer_ShouldHandle(t *testing.T) {
	srv := NewServer()

	tests := []struct {
		path string
		want bool
	}{
		{"/mcp", true},
		{"/mcp/", true},
		{"/mcp/sse", true},
		{"/api/v1/users", false},
		{"/", false},
		{"/mcpx", false},
	}

	for _, tt := range tests {
		if got := srv.ShouldHandle(tt.path); got != tt.want {
			t.Errorf("ShouldHandle(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestServer_Stats(t *testing.T) {
	srv := NewServer()

	// Initialize
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// Call a tool
	body = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}`
	req = httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	stats := srv.Stats()
	if stats["active_sessions"].(int) < 1 {
		t.Error("expected at least 1 active session")
	}
}

func TestServer_Events(t *testing.T) {
	srv := NewServer()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"test"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	events := srv.Events()
	if len(events) == 0 {
		t.Error("expected at least 1 event")
	}
	if events[0].Method != "initialize" {
		t.Errorf("event method = %q, want %q", events[0].Method, "initialize")
	}
}

func TestServer_InvalidJSON(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestServer_SSENoSession(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestServer_SSEInvalidSession(t *testing.T) {
	srv := NewServer()

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "nonexistent")
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	if status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", status, http.StatusNotFound)
	}
}

// --- Honeypot tool content validation ---

func TestHoneypot_AWSCredentials_Format(t *testing.T) {
	reg := NewToolRegistry()
	result := reg.Execute("get_aws_credentials", json.RawMessage(`{}`))
	text := result.Content[0].Text
	if !strings.Contains(text, "AKIA") {
		t.Error("expected AWS access key format")
	}
	if !strings.Contains(text, "secret_access_key") {
		t.Error("expected secret_access_key field")
	}
}

func TestHoneypot_APIKeys_Format(t *testing.T) {
	reg := NewToolRegistry()
	result := reg.Execute("get_api_keys", json.RawMessage(`{}`))
	text := result.Content[0].Text
	if !strings.Contains(text, "sk_live_") {
		t.Error("expected Stripe key format")
	}
	if !strings.Contains(text, "ghp_") {
		t.Error("expected GitHub token format")
	}
}

func TestHoneypot_VulnCheck_DeterministicSeverity(t *testing.T) {
	reg := NewToolRegistry()
	result1 := reg.Execute("check_vulnerability", json.RawMessage(`{"cve_id":"CVE-2024-1234"}`))
	result2 := reg.Execute("check_vulnerability", json.RawMessage(`{"cve_id":"CVE-2024-1234"}`))

	// Same CVE should produce same CVSS (deterministic from hash)
	var r1, r2 map[string]interface{}
	json.Unmarshal([]byte(result1.Content[0].Text), &r1)
	json.Unmarshal([]byte(result2.Content[0].Text), &r2)
	if r1["cvss_score"] != r2["cvss_score"] {
		t.Error("expected deterministic CVSS for same CVE")
	}
}

func TestHoneypot_GenerateReport_Large(t *testing.T) {
	reg := NewToolRegistry()
	result := reg.Execute("generate_report", json.RawMessage(`{"scope":"comprehensive"}`))
	text := result.Content[0].Text
	if len(text) < 1000 {
		t.Errorf("report too short: %d bytes, expected budget drain", len(text))
	}
}

// --- Resource content validation ---

func TestResource_SSHKey_Format(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///home/deploy/.ssh/id_rsa")
	text := result.Contents[0].Text
	if !strings.Contains(text, "BEGIN OPENSSH PRIVATE KEY") {
		t.Error("expected SSH key header")
	}
	if !strings.Contains(text, "END OPENSSH PRIVATE KEY") {
		t.Error("expected SSH key footer")
	}
}

func TestResource_AWSCreds_Format(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///home/deploy/.aws/credentials")
	text := result.Contents[0].Text
	if !strings.Contains(text, "[default]") {
		t.Error("expected [default] profile")
	}
	if !strings.Contains(text, "aws_access_key_id") {
		t.Error("expected aws_access_key_id")
	}
}

func TestResource_DBDump_Format(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///backups/db_dump.sql")
	text := result.Contents[0].Text
	if !strings.Contains(text, "CREATE TABLE") {
		t.Error("expected CREATE TABLE statement")
	}
	if !strings.Contains(text, "INSERT INTO") {
		t.Error("expected INSERT INTO statement")
	}
}

func TestResource_K8sSecrets_Format(t *testing.T) {
	reg := NewResourceRegistry()
	result := reg.Read("file:///etc/kubernetes/secrets.yaml")
	text := result.Contents[0].Text
	if !strings.Contains(text, "kind: Secret") {
		t.Error("expected Kubernetes Secret kind")
	}
}

// --- Full MCP handshake test ---

func TestServer_FullHandshake(t *testing.T) {
	srv := NewServer()

	// Step 1: Initialize
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-agent","version":"2.0"}}}`
	initReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initBody))
	initW := httptest.NewRecorder()
	srv.ServeHTTP(initW, initReq)

	var initResp Response
	json.NewDecoder(initW.Body).Decode(&initResp)
	if initResp.Error != nil {
		t.Fatalf("init error: %s", initResp.Error.Message)
	}

	sid := initW.Header().Get("Mcp-Session-Id")

	// Step 2: Send initialized notification
	notifBody := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	notifReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(notifBody))
	notifReq.Header.Set("Mcp-Session-Id", sid)
	notifW := httptest.NewRecorder()
	srv.ServeHTTP(notifW, notifReq)
	if notifW.Code != http.StatusAccepted {
		t.Errorf("notification status = %d, want %d", notifW.Code, http.StatusAccepted)
	}

	// Step 3: List tools
	listBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	listReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(listBody))
	listReq.Header.Set("Mcp-Session-Id", sid)
	listW := httptest.NewRecorder()
	srv.ServeHTTP(listW, listReq)

	var listResp Response
	json.NewDecoder(listW.Body).Decode(&listResp)
	if listResp.Error != nil {
		t.Fatalf("tools/list error: %s", listResp.Error.Message)
	}

	// Step 4: Call a honeypot tool
	callBody := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_aws_credentials","arguments":{"profile":"default"}}}`
	callReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(callBody))
	callReq.Header.Set("Mcp-Session-Id", sid)
	callW := httptest.NewRecorder()
	srv.ServeHTTP(callW, callReq)

	var callResp Response
	json.NewDecoder(callW.Body).Decode(&callResp)
	if callResp.Error != nil {
		t.Fatalf("tools/call error: %s", callResp.Error.Message)
	}

	// Step 5: Read a honeypot resource
	readBody := `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///app/.env"}}`
	readReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(readBody))
	readReq.Header.Set("Mcp-Session-Id", sid)
	readW := httptest.NewRecorder()
	srv.ServeHTTP(readW, readReq)

	var readResp Response
	json.NewDecoder(readW.Body).Decode(&readResp)
	if readResp.Error != nil {
		t.Fatalf("resources/read error: %s", readResp.Error.Message)
	}

	// Step 6: Verify events were logged
	events := srv.Events()
	if len(events) < 3 {
		t.Errorf("expected at least 3 events, got %d", len(events))
	}

	// Step 7: Verify session recorded tool calls
	sessions := srv.Sessions()
	if len(sessions) == 0 {
		t.Fatal("no sessions found")
	}

	// Step 8: Delete session
	delReq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	delReq.Header.Set("Mcp-Session-Id", sid)
	delW := httptest.NewRecorder()
	srv.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Errorf("delete status = %d, want %d", delW.Code, http.StatusOK)
	}
}

// --- Body size limit test ---

func TestServer_LargeBody(t *testing.T) {
	srv := NewServer()

	// Create a body larger than 1MB
	large := strings.Repeat("x", 2<<20)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(large))
	w := httptest.NewRecorder()

	status := srv.ServeHTTP(w, req)
	// Should get a parse error since truncated JSON is invalid
	if status != http.StatusBadRequest {
		// Read the body to check
		body, _ := io.ReadAll(w.Body)
		t.Logf("body: %s", body)
		t.Errorf("status = %d, want %d (parse error on truncated body)", status, http.StatusBadRequest)
	}
}
