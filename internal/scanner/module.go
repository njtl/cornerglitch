package scanner

import (
	"context"
	"time"
)

// AttackModule defines the interface for all scanner attack modules.
// Each module generates a set of AttackRequests targeting a given host.
type AttackModule interface {
	// Name returns a short, unique identifier for this module (e.g. "owasp", "injection").
	Name() string

	// Category returns a broader classification (e.g. "vulnerability", "fuzzing", "protocol").
	Category() string

	// GenerateRequests produces attack requests against the given target base URL.
	// The target includes the scheme and host (e.g. "http://localhost:8765").
	GenerateRequests(target string) []AttackRequest
}

// RawTCPModule is an optional interface that attack modules can implement
// to run raw TCP attacks that bypass Go's net/http client. Modules that
// implement this interface will have RunRawTCP called during the scan
// in addition to (or instead of) GenerateRequests.
type RawTCPModule interface {
	AttackModule
	RunRawTCP(ctx context.Context, target string, concurrency int, timeout time.Duration) []Finding
}

// AttackRequest represents a single HTTP request to send during a scan.
type AttackRequest struct {
	Method      string            `json:"method"`       // HTTP method (GET, POST, PUT, etc.)
	Path        string            `json:"path"`         // URL path (e.g. "/vuln/a03/search?q=payload")
	Headers     map[string]string `json:"headers,omitempty"` // extra headers to include
	Body        string            `json:"body,omitempty"`    // request body (for POST/PUT)
	BodyType    string            `json:"body_type,omitempty"` // Content-Type for the body (e.g. "application/json")
	Category    string            `json:"category"`     // broad attack category (e.g. "OWASP-A03")
	SubCategory string            `json:"sub_category,omitempty"` // specific classification (e.g. "sql-injection")
	Description string            `json:"description"`  // human-readable description of this request's purpose
}
