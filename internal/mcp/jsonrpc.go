// Package mcp implements a fake Model Context Protocol (MCP) server
// that serves as a honeypot for AI agents and MCP clients. It exposes
// deliberately vulnerable tools, poisoned descriptions, and trap resources
// for testing MCP client security.
package mcp

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 message types per MCP specification.

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // string or int; nil = notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// ParseRequest parses a raw JSON message into a Request.
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	if req.JSONRPC != "2.0" {
		return nil, fmt.Errorf("invalid jsonrpc version: %q", req.JSONRPC)
	}
	if req.Method == "" {
		return nil, fmt.Errorf("missing method")
	}
	return &req, nil
}

// IsNotification returns true if the request has no ID (notification).
func (r *Request) IsNotification() bool {
	return r.ID == nil || string(r.ID) == "null"
}

// NewResponse creates a success response.
func NewResponse(id json.RawMessage, result interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse creates an error response.
func NewErrorResponse(id json.RawMessage, code int, message string, data interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// MarshalResponse serializes a response to JSON.
func MarshalResponse(resp *Response) ([]byte, error) {
	return json.Marshal(resp)
}
