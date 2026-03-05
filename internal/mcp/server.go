package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// timeNow is a package-level function for testability.
var timeNow = time.Now

// sseClient represents a connected SSE listener.
type sseClient struct {
	sessionID string
	events    chan []byte // serialized SSE events
	done      chan struct{}
}

// Server implements a fake MCP (Model Context Protocol) server.
// It exposes honeypot tools, poisoned resources, and trap prompts
// for testing MCP client security behavior.
type Server struct {
	tools     *ToolRegistry
	resources *ResourceRegistry
	prompts   *PromptRegistry
	sessions  *SessionStore

	mu       sync.RWMutex
	eventLog []EventRecord // recent events for dashboard

	sseMu   sync.Mutex
	sseClients map[string][]*sseClient // sessionID -> clients
	lastEventID uint64
}

// EventRecord captures an MCP interaction for monitoring.
type EventRecord struct {
	SessionID  string          `json:"session_id"`
	Method     string          `json:"method"`
	ToolName   string          `json:"tool_name,omitempty"`
	Category   string          `json:"category,omitempty"` // honeypot, legit, unknown
	ClientInfo json.RawMessage `json:"client_info,omitempty"`
	Timestamp  int64           `json:"timestamp"`
}

// NewServer creates a new MCP honeypot server.
func NewServer() *Server {
	return &Server{
		tools:      NewToolRegistry(),
		resources:  NewResourceRegistry(),
		prompts:    NewPromptRegistry(),
		sessions:   NewSessionStore(),
		sseClients: make(map[string][]*sseClient),
	}
}

// ShouldHandle returns true if the path is an MCP endpoint.
func (s *Server) ShouldHandle(path string) bool {
	return path == "/mcp" || strings.HasPrefix(path, "/mcp/")
}

// ServeHTTP handles MCP requests per the Streamable HTTP transport spec.
// POST /mcp — JSON-RPC request/response
// GET  /mcp — SSE event stream
// DELETE /mcp — close session
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	switch r.Method {
	case http.MethodPost:
		return s.handlePost(w, r)
	case http.MethodGet:
		return s.handleSSE(w, r)
	case http.MethodDelete:
		return s.handleDelete(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return http.StatusMethodNotAllowed
	}
}

// handlePost processes a JSON-RPC 2.0 request over HTTP POST.
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) int {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		resp := NewErrorResponse(nil, ErrCodeParse, "failed to read body", nil)
		return s.writeJSON(w, resp, http.StatusBadRequest)
	}

	req, err := ParseRequest(body)
	if err != nil {
		resp := NewErrorResponse(nil, ErrCodeParse, err.Error(), nil)
		return s.writeJSON(w, resp, http.StatusBadRequest)
	}

	// Route to handler based on method
	resp := s.handleMethod(req, r)

	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return http.StatusAccepted
	}

	// Set session header on response if we have one
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		w.Header().Set("Mcp-Session-Id", sid)
	}

	return s.writeJSON(w, resp, http.StatusOK)
}

// handleSSE opens a Server-Sent Events stream for the session.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) int {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid == "" {
		http.Error(w, "Missing Mcp-Session-Id header", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	sess := s.sessions.Get(sid)
	if sess == nil {
		http.Error(w, "Invalid session", http.StatusNotFound)
		return http.StatusNotFound
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sid)
	w.WriteHeader(http.StatusOK)

	// Register this SSE client
	client := &sseClient{
		sessionID: sid,
		events:    make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	s.addSSEClient(sid, client)
	defer s.removeSSEClient(sid, client)

	// Send an initial keepalive event
	s.sseMu.Lock()
	eid := s.lastEventID
	s.sseMu.Unlock()
	fmt.Fprintf(w, "id: %d\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n", eid)
	flusher.Flush()

	// Handle Last-Event-ID for reconnection
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		// Client is reconnecting — send a fresh initialized notification
		fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/reconnected\"}\n\n")
		flusher.Flush()
	}

	// Heartbeat ticker
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// Stream events until client disconnects
	for {
		select {
		case <-r.Context().Done():
			return http.StatusOK
		case <-client.done:
			return http.StatusOK
		case data := <-client.events:
			w.Write(data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// handleDelete closes an MCP session.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) int {
	sid := r.Header.Get("Mcp-Session-Id")
	if sid == "" {
		http.Error(w, "Missing Mcp-Session-Id header", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	s.sessions.Delete(sid)
	w.WriteHeader(http.StatusOK)
	return http.StatusOK
}

// handleMethod dispatches a JSON-RPC method to the appropriate handler.
func (s *Server) handleMethod(req *Request, httpReq *http.Request) *Response {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req, httpReq)
	case "notifications/initialized":
		return nil // notification, no response needed
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req, httpReq)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(req, httpReq)
	case "prompts/list":
		return s.handlePromptsList(req)
	case "prompts/get":
		return s.handlePromptsGet(req, httpReq)
	case "ping":
		return NewResponse(req.ID, map[string]interface{}{})
	default:
		return NewErrorResponse(req.ID, ErrCodeMethodNotFound,
			fmt.Sprintf("method not found: %s", req.Method), nil)
	}
}

// handleInitialize processes the MCP initialize handshake.
func (s *Server) handleInitialize(req *Request, httpReq *http.Request) *Response {
	var params struct {
		ProtocolVersion string                 `json:"protocolVersion"`
		Capabilities    map[string]interface{} `json:"capabilities"`
		ClientInfo      map[string]interface{} `json:"clientInfo"`
	}
	if req.Params != nil {
		json.Unmarshal(req.Params, &params)
	}

	// Create session and record client info for fingerprinting
	sid := s.sessions.Create(params.ClientInfo)

	// Log the initialize event
	clientInfoJSON, _ := json.Marshal(params.ClientInfo)
	s.recordEvent(EventRecord{
		SessionID:  sid,
		Method:     "initialize",
		Category:   "protocol",
		ClientInfo: clientInfoJSON,
	})

	// Build response with server capabilities
	result := map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{"listChanged": true},
			"resources": map[string]interface{}{"subscribe": true, "listChanged": true},
			"prompts":   map[string]interface{}{"listChanged": true},
		},
		"serverInfo": map[string]interface{}{
			"name":    "glitch-mcp",
			"version": "1.0.0",
		},
	}

	resp := NewResponse(req.ID, result)
	// Attach session ID via HTTP header (done in handlePost)
	httpReq.Header.Set("Mcp-Session-Id", sid)
	// Also include in a custom way the caller can read
	return resp
}

// handleToolsList returns all available tools.
func (s *Server) handleToolsList(req *Request) *Response {
	tools := s.tools.List()
	// Build the response matching MCP spec
	toolDefs := make([]map[string]interface{}, 0, len(tools))
	for _, t := range tools {
		toolDefs = append(toolDefs, map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return NewResponse(req.ID, map[string]interface{}{
		"tools": toolDefs,
	})
}

// handleToolsCall executes a tool.
func (s *Server) handleToolsCall(req *Request, httpReq *http.Request) *Response {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return NewErrorResponse(req.ID, ErrCodeInvalidParams, "invalid params", nil)
	}

	tool := s.tools.Get(params.Name)
	category := "unknown"
	if tool != nil {
		category = tool.Category
	}

	// Record the tool call
	sid := httpReq.Header.Get("Mcp-Session-Id")
	s.sessions.RecordToolCall(sid, params.Name)
	s.sessions.RecordFingerprint(sid, func(fp *Fingerprint) { fp.RecordToolCall(params.Name) })
	s.recordEvent(EventRecord{
		SessionID: sid,
		Method:    "tools/call",
		ToolName:  params.Name,
		Category:  category,
	})

	result := s.tools.Execute(params.Name, params.Arguments)
	return NewResponse(req.ID, result)
}

// handleResourcesList returns all available resources.
func (s *Server) handleResourcesList(req *Request) *Response {
	resources := s.resources.List()
	resDefs := make([]map[string]interface{}, 0, len(resources))
	for _, r := range resources {
		rd := map[string]interface{}{
			"uri":      r.URI,
			"name":     r.Name,
			"mimeType": r.MimeType,
		}
		if r.Description != "" {
			rd["description"] = r.Description
		}
		resDefs = append(resDefs, rd)
	}
	return NewResponse(req.ID, map[string]interface{}{
		"resources": resDefs,
	})
}

// handleResourcesRead reads a resource by URI.
func (s *Server) handleResourcesRead(req *Request, httpReq *http.Request) *Response {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return NewErrorResponse(req.ID, ErrCodeInvalidParams, "invalid params", nil)
	}

	sid := httpReq.Header.Get("Mcp-Session-Id")
	s.sessions.RecordFingerprint(sid, func(fp *Fingerprint) { fp.RecordResourceRead(params.URI) })
	s.recordEvent(EventRecord{
		SessionID: sid,
		Method:    "resources/read",
		ToolName:  params.URI,
		Category:  "resource",
	})

	result := s.resources.Read(params.URI)
	return NewResponse(req.ID, result)
}

// handlePromptsList returns all available prompts.
func (s *Server) handlePromptsList(req *Request) *Response {
	prompts := s.prompts.List()
	promptDefs := make([]map[string]interface{}, 0, len(prompts))
	for _, p := range prompts {
		pd := map[string]interface{}{
			"name":        p.Name,
			"description": p.Description,
		}
		if len(p.Arguments) > 0 {
			pd["arguments"] = p.Arguments
		}
		promptDefs = append(promptDefs, pd)
	}
	return NewResponse(req.ID, map[string]interface{}{
		"prompts": promptDefs,
	})
}

// handlePromptsGet retrieves a prompt with arguments applied.
func (s *Server) handlePromptsGet(req *Request, httpReq *http.Request) *Response {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return NewErrorResponse(req.ID, ErrCodeInvalidParams, "invalid params", nil)
	}

	sid := httpReq.Header.Get("Mcp-Session-Id")
	s.recordEvent(EventRecord{
		SessionID: sid,
		Method:    "prompts/get",
		ToolName:  params.Name,
		Category:  "prompt",
	})

	result := s.prompts.Get(params.Name, params.Arguments)
	return NewResponse(req.ID, result)
}

// writeJSON serializes a response and writes it.
func (s *Server) writeJSON(w http.ResponseWriter, resp *Response, statusCode int) int {
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return http.StatusAccepted
	}
	w.Header().Set("Content-Type", "application/json")
	data, err := MarshalResponse(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	w.WriteHeader(statusCode)
	w.Write(data)
	return statusCode
}

// addSSEClient registers a new SSE client for a session.
func (s *Server) addSSEClient(sid string, c *sseClient) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	s.sseClients[sid] = append(s.sseClients[sid], c)
}

// removeSSEClient unregisters an SSE client.
func (s *Server) removeSSEClient(sid string, c *sseClient) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	clients := s.sseClients[sid]
	for i, cl := range clients {
		if cl == c {
			s.sseClients[sid] = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	if len(s.sseClients[sid]) == 0 {
		delete(s.sseClients, sid)
	}
}

// broadcastSSE sends a JSON-RPC notification to all SSE clients for a session.
// If sid is empty, broadcasts to all sessions.
func (s *Server) broadcastSSE(sid string, method string, params interface{}) {
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if params != nil {
		msg["params"] = params
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	s.sseMu.Lock()
	s.lastEventID++
	eid := s.lastEventID
	s.sseMu.Unlock()

	sseData := []byte(fmt.Sprintf("id: %d\nevent: message\ndata: %s\n\n", eid, data))

	s.sseMu.Lock()
	defer s.sseMu.Unlock()

	if sid != "" {
		for _, c := range s.sseClients[sid] {
			select {
			case c.events <- sseData:
			default: // drop if buffer full
			}
		}
	} else {
		for _, clients := range s.sseClients {
			for _, c := range clients {
				select {
				case c.events <- sseData:
				default:
				}
			}
		}
	}
}

// BroadcastToolsChanged sends a tools/listChanged notification to all SSE clients.
func (s *Server) BroadcastToolsChanged() {
	s.broadcastSSE("", "notifications/tools/listChanged", nil)
}

// BroadcastResourcesChanged sends a resources/listChanged notification to all SSE clients.
func (s *Server) BroadcastResourcesChanged() {
	s.broadcastSSE("", "notifications/resources/listChanged", nil)
}

// recordEvent appends an event to the log (capped at 1000).
func (s *Server) recordEvent(ev EventRecord) {
	ev.Timestamp = timeNow().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventLog = append(s.eventLog, ev)
	if len(s.eventLog) > 1000 {
		s.eventLog = s.eventLog[len(s.eventLog)-500:]
	}
}

// Events returns recent MCP events for the dashboard.
func (s *Server) Events() []EventRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]EventRecord, len(s.eventLog))
	copy(result, s.eventLog)
	return result
}

// Sessions returns all active sessions.
func (s *Server) Sessions() []*Session {
	return s.sessions.All()
}

// SessionsAny returns all active sessions as interface{} for dashboard provider.
func (s *Server) SessionsAny() interface{} {
	return s.sessions.All()
}

// EventsAny returns recent events as interface{} for dashboard provider.
func (s *Server) EventsAny() interface{} {
	return s.Events()
}

// Stats returns summary statistics.
func (s *Server) Stats() map[string]interface{} {
	sessions := s.sessions.All()
	totalToolCalls := 0
	honeypotCalls := 0
	for _, sess := range sessions {
		for toolName, count := range sess.ToolCalls {
			totalToolCalls += count
			tool := s.tools.Get(toolName)
			if tool != nil && tool.Category == "honeypot" {
				honeypotCalls += count
			}
		}
	}
	return map[string]interface{}{
		"active_sessions":    len(sessions),
		"total_tool_calls":   totalToolCalls,
		"honeypot_calls":     honeypotCalls,
		"tools_registered":   len(s.tools.tools),
		"resources_exposed":  len(s.resources.resources),
		"prompts_registered": len(s.prompts.prompts),
	}
}
