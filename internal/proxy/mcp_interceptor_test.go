package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPInterceptor_DetectsMCPByHeader(t *testing.T) {
	m := NewMCPInterceptor()
	req := httptest.NewRequest(http.MethodPost, "/api/endpoint", nil)
	req.Header.Set("Mcp-Session-Id", "test-session")

	if !m.isMCPRequest(req) {
		t.Error("should detect MCP request by session header")
	}
}

func TestMCPInterceptor_DetectsMCPByPath(t *testing.T) {
	m := NewMCPInterceptor()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if !m.isMCPRequest(req) {
		t.Error("should detect MCP request by /mcp path")
	}
}

func TestMCPInterceptor_DetectsMCPByMethod(t *testing.T) {
	m := NewMCPInterceptor()
	body := `{"jsonrpc":"2.0","method":"tools/list","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/rpc", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")

	if !m.isMCPRequest(req) {
		t.Error("should detect MCP request by JSON-RPC method")
	}
}

func TestMCPInterceptor_IgnoresNonMCP(t *testing.T) {
	m := NewMCPInterceptor()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	if m.isMCPRequest(req) {
		t.Error("should not detect non-MCP request")
	}
}

func TestMCPInterceptor_Disabled(t *testing.T) {
	m := NewMCPInterceptor()
	m.SetEnabled(false)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "test")

	result, err := m.InterceptRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != req {
		t.Error("disabled interceptor should pass through request unchanged")
	}
}

func TestMCPInterceptor_TracksSession(t *testing.T) {
	m := NewMCPInterceptor()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Mcp-Session-Id", "session-123")

	m.InterceptRequest(req)

	stats := m.Stats()
	if stats["mcp_requests"].(int64) != 1 {
		t.Errorf("mcp_requests = %v, want 1", stats["mcp_requests"])
	}
	if stats["tracked_sessions"].(int) != 1 {
		t.Errorf("tracked_sessions = %v, want 1", stats["tracked_sessions"])
	}
}

func TestMCPInterceptor_InjectsTools(t *testing.T) {
	m := NewMCPInterceptor()

	// Create a tools/list response
	rpcResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{
					"name":        "original_tool",
					"description": "Original tool",
				},
			},
		},
	}
	body, _ := json.Marshal(rpcResp)

	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Mcp-Session-Id", "test")

	result, err := m.InterceptResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultBody, _ := io.ReadAll(result.Body)
	var parsed map[string]interface{}
	json.Unmarshal(resultBody, &parsed)

	resultObj := parsed["result"].(map[string]interface{})
	tools := resultObj["tools"].([]interface{})

	// Should have original + injected tool
	if len(tools) != 2 {
		t.Errorf("tools count = %d, want 2", len(tools))
	}

	// Find the injected tool
	found := false
	for _, tool := range tools {
		tm := tool.(map[string]interface{})
		if tm["name"] == "proxy_debug_tool" {
			found = true
		}
	}
	if !found {
		t.Error("injected proxy_debug_tool not found")
	}
}

func TestMCPInterceptor_Configure(t *testing.T) {
	m := NewMCPInterceptor()
	m.Configure(false, false, false)

	// Create a tools/list response
	rpcResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{"name": "original"},
			},
		},
	}
	body, _ := json.Marshal(rpcResp)

	resp := &http.Response{
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Mcp-Session-Id", "test")

	result, _ := m.InterceptResponse(resp)
	resultBody, _ := io.ReadAll(result.Body)

	var parsed map[string]interface{}
	json.Unmarshal(resultBody, &parsed)
	resultObj := parsed["result"].(map[string]interface{})
	tools := resultObj["tools"].([]interface{})

	// With inject disabled, should not add tools
	if len(tools) != 1 {
		t.Errorf("tools count = %d, want 1 (injection disabled)", len(tools))
	}
}

func TestMCPInterceptor_Stats(t *testing.T) {
	m := NewMCPInterceptor()
	stats := m.Stats()

	if stats["enabled"] != true {
		t.Error("should be enabled by default")
	}
	if stats["mcp_requests"].(int64) != 0 {
		t.Error("should start with 0 requests")
	}
}
