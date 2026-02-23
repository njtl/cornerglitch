package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// Mock interceptors for testing
// ---------------------------------------------------------------------------

type passthruInterceptor struct {
	name string
}

func (p *passthruInterceptor) Name() string { return p.name }
func (p *passthruInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	return req, nil
}
func (p *passthruInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	return resp, nil
}

type modifyInterceptor struct {
	name      string
	headerKey string
	headerVal string
}

func (m *modifyInterceptor) Name() string { return m.name }
func (m *modifyInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(m.headerKey, m.headerVal)
	return clone, nil
}
func (m *modifyInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	// Modify response by adding a header.
	newResp := *resp
	newResp.Header = resp.Header.Clone()
	newResp.Header.Set(m.headerKey, m.headerVal)
	return &newResp, nil
}

type blockingInterceptor struct {
	name string
}

func (b *blockingInterceptor) Name() string { return b.name }
func (b *blockingInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	return nil, fmt.Errorf("request blocked by %s", b.name)
}
func (b *blockingInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	return resp, nil
}

type nilReturningInterceptor struct {
	name string
}

func (n *nilReturningInterceptor) Name() string { return n.name }
func (n *nilReturningInterceptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	return nil, nil // signals block without error
}
func (n *nilReturningInterceptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	return resp, nil
}

// ---------------------------------------------------------------------------
// TestPipeline_Add
// ---------------------------------------------------------------------------

func TestPipeline_Add(t *testing.T) {
	p := NewPipeline()

	p.Add(&passthruInterceptor{name: "first"})
	p.Add(&passthruInterceptor{name: "second"})
	p.Add(&passthruInterceptor{name: "third"})

	p.mu.RLock()
	count := len(p.interceptors)
	p.mu.RUnlock()

	if count != 3 {
		t.Errorf("expected 3 interceptors, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// TestPipeline_ProcessRequest
// ---------------------------------------------------------------------------

func TestPipeline_ProcessRequest(t *testing.T) {
	t.Run("passthrough", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&passthruInterceptor{name: "pass"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.URL.Path != "/test" {
			t.Errorf("expected path /test, got %s", result.URL.Path)
		}
	})

	t.Run("modify_request", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&modifyInterceptor{name: "mod", headerKey: "X-Modified", headerVal: "true"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.Header.Get("X-Modified") != "true" {
			t.Error("expected X-Modified header to be set")
		}

		stats := p.Stats()
		if stats.RequestsModified != 1 {
			t.Errorf("expected 1 modified request, got %d", stats.RequestsModified)
		}
	})

	t.Run("block_with_error", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&blockingInterceptor{name: "blocker"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err == nil {
			t.Error("expected error from blocking interceptor")
		}
		if result != nil {
			t.Error("expected nil result when blocked with error")
		}

		stats := p.Stats()
		if stats.RequestsBlocked != 1 {
			t.Errorf("expected 1 blocked request, got %d", stats.RequestsBlocked)
		}
		if stats.Errors != 1 {
			t.Errorf("expected 1 error, got %d", stats.Errors)
		}
	})

	t.Run("block_with_nil_return", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&nilReturningInterceptor{name: "nil-blocker"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err != nil {
			t.Errorf("expected nil error for nil-return block, got %v", err)
		}
		if result != nil {
			t.Error("expected nil result when interceptor returns nil")
		}

		stats := p.Stats()
		if stats.RequestsBlocked != 1 {
			t.Errorf("expected 1 blocked request, got %d", stats.RequestsBlocked)
		}
	})

	t.Run("chain_multiple_interceptors", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&modifyInterceptor{name: "first", headerKey: "X-First", headerVal: "1"})
		p.Add(&modifyInterceptor{name: "second", headerKey: "X-Second", headerVal: "2"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		// Both interceptors modified the request, but only one "final" modification is tracked.
		if result.Header.Get("X-Second") != "2" {
			t.Error("expected X-Second header from second interceptor")
		}
	})

	t.Run("blocker_stops_chain", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&blockingInterceptor{name: "blocker"})
		p.Add(&modifyInterceptor{name: "should-not-run", headerKey: "X-After", headerVal: "yes"})

		req := httptest.NewRequest("GET", "/test", nil)
		result, err := p.ProcessRequest(req)

		if err == nil {
			t.Error("expected error from blocker")
		}
		if result != nil {
			t.Error("expected nil result")
		}
	})
}

// ---------------------------------------------------------------------------
// TestPipeline_ProcessResponse
// ---------------------------------------------------------------------------

func TestPipeline_ProcessResponse(t *testing.T) {
	t.Run("passthrough", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&passthruInterceptor{name: "pass"})

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := p.ProcessResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.StatusCode != 200 {
			t.Errorf("expected status 200, got %d", result.StatusCode)
		}
	})

	t.Run("modify_response", func(t *testing.T) {
		p := NewPipeline()
		p.Add(&modifyInterceptor{name: "mod", headerKey: "X-Modified", headerVal: "true"})

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := p.ProcessResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Header.Get("X-Modified") != "true" {
			t.Error("expected X-Modified header on response")
		}

		stats := p.Stats()
		if stats.ResponsesModified != 1 {
			t.Errorf("expected 1 modified response, got %d", stats.ResponsesModified)
		}
	})
}

// ---------------------------------------------------------------------------
// TestPipeline_Stats
// ---------------------------------------------------------------------------

func TestPipeline_Stats(t *testing.T) {
	p := NewPipeline()
	p.Add(&passthruInterceptor{name: "pass"})

	// Process some requests.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/test/%d", i), nil)
		p.ProcessRequest(req)
	}

	// Process some responses.
	for i := 0; i < 3; i++ {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		p.ProcessResponse(resp)
	}

	stats := p.Stats()

	if stats.RequestsProcessed != 5 {
		t.Errorf("expected 5 requests processed, got %d", stats.RequestsProcessed)
	}
	if stats.ResponsesProcessed != 3 {
		t.Errorf("expected 3 responses processed, got %d", stats.ResponsesProcessed)
	}
	if stats.RequestsBlocked != 0 {
		t.Errorf("expected 0 blocked, got %d", stats.RequestsBlocked)
	}
	if stats.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", stats.Errors)
	}
}

func TestPipeline_Stats_WithMixedResults(t *testing.T) {
	p := NewPipeline()
	p.Add(&blockingInterceptor{name: "blocker"})

	// All requests will be blocked.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		p.ProcessRequest(req)
	}

	stats := p.Stats()

	if stats.RequestsProcessed != 3 {
		t.Errorf("expected 3 requests processed, got %d", stats.RequestsProcessed)
	}
	if stats.RequestsBlocked != 3 {
		t.Errorf("expected 3 blocked, got %d", stats.RequestsBlocked)
	}
	if stats.Errors != 3 {
		t.Errorf("expected 3 errors, got %d", stats.Errors)
	}
}

// ---------------------------------------------------------------------------
// TestNewPipeline
// ---------------------------------------------------------------------------

func TestNewPipeline(t *testing.T) {
	p := NewPipeline()
	if p == nil {
		t.Fatal("NewPipeline returned nil")
	}

	stats := p.Stats()
	if stats.RequestsProcessed != 0 {
		t.Error("new pipeline should have 0 requests processed")
	}
	if stats.ResponsesProcessed != 0 {
		t.Error("new pipeline should have 0 responses processed")
	}
}
