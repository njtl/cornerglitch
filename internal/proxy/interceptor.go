package proxy

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// Interceptor defines an interface for request/response modification in the proxy pipeline.
type Interceptor interface {
	Name() string
	InterceptRequest(req *http.Request) (*http.Request, error)
	InterceptResponse(resp *http.Response) (*http.Response, error)
}

// PipelineStats tracks statistics for the interception pipeline.
type PipelineStats struct {
	RequestsProcessed  int64
	ResponsesProcessed int64
	RequestsBlocked    int64
	RequestsModified   int64
	ResponsesModified  int64
	Errors             int64
}

// Pipeline chains multiple interceptors to process requests and responses in order.
type Pipeline struct {
	interceptors []Interceptor
	mu           sync.RWMutex
	stats        struct {
		requestsProcessed  atomic.Int64
		responsesProcessed atomic.Int64
		requestsBlocked    atomic.Int64
		requestsModified   atomic.Int64
		responsesModified  atomic.Int64
		errors             atomic.Int64
	}
}

// NewPipeline creates a new empty interception pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{}
}

// Add appends an interceptor to the pipeline.
func (p *Pipeline) Add(i Interceptor) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.interceptors = append(p.interceptors, i)
}

// ProcessRequest runs the request through all interceptors in order.
// If any interceptor returns an error, the pipeline stops and returns the error.
// A nil return for the request means the request was blocked.
func (p *Pipeline) ProcessRequest(req *http.Request) (*http.Request, error) {
	p.stats.requestsProcessed.Add(1)

	p.mu.RLock()
	interceptors := make([]Interceptor, len(p.interceptors))
	copy(interceptors, p.interceptors)
	p.mu.RUnlock()

	current := req
	modified := false
	for _, interceptor := range interceptors {
		result, err := interceptor.InterceptRequest(current)
		if err != nil {
			p.stats.errors.Add(1)
			p.stats.requestsBlocked.Add(1)
			return nil, err
		}
		if result == nil {
			// Interceptor signaled the request should be blocked
			p.stats.requestsBlocked.Add(1)
			return nil, nil
		}
		if result != current {
			modified = true
			current = result
		}
	}
	if modified {
		p.stats.requestsModified.Add(1)
	}
	return current, nil
}

// ProcessResponse runs the response through all interceptors in order.
// If any interceptor returns an error, the pipeline stops and returns the error.
func (p *Pipeline) ProcessResponse(resp *http.Response) (*http.Response, error) {
	p.stats.responsesProcessed.Add(1)

	p.mu.RLock()
	interceptors := make([]Interceptor, len(p.interceptors))
	copy(interceptors, p.interceptors)
	p.mu.RUnlock()

	current := resp
	modified := false
	for _, interceptor := range interceptors {
		result, err := interceptor.InterceptResponse(current)
		if err != nil {
			p.stats.errors.Add(1)
			return nil, err
		}
		if result != current {
			modified = true
			current = result
		}
	}
	if modified {
		p.stats.responsesModified.Add(1)
	}
	return current, nil
}

// Stats returns a snapshot of the pipeline statistics.
func (p *Pipeline) Stats() PipelineStats {
	return PipelineStats{
		RequestsProcessed:  p.stats.requestsProcessed.Load(),
		ResponsesProcessed: p.stats.responsesProcessed.Load(),
		RequestsBlocked:    p.stats.requestsBlocked.Load(),
		RequestsModified:   p.stats.requestsModified.Load(),
		ResponsesModified:  p.stats.responsesModified.Load(),
		Errors:             p.stats.errors.Load(),
	}
}
