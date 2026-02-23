package resilience

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnectionConfig holds parameters for creating a ConnectionManager.
type ConnectionConfig struct {
	// Timeout is the per-request timeout including connection, TLS handshake,
	// and body read. Default: 10s.
	Timeout time.Duration

	// MaxIdleConns is the maximum number of idle keep-alive connections across
	// all hosts. Default: 100.
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum idle connections per host. Default: 10.
	MaxIdleConnsPerHost int

	// DisableKeepAlives disables HTTP keep-alive connections.
	DisableKeepAlives bool

	// TLSSkipVerify disables TLS certificate verification. Useful for scanning
	// servers with self-signed certificates.
	TLSSkipVerify bool

	// RetryCount is the number of times to retry a failed request. Default: 3.
	RetryCount int

	// RetryDelay is the base delay between retries. Each retry doubles the
	// delay (exponential backoff). Default: 500ms.
	RetryDelay time.Duration

	// CircuitBreakerThreshold is the number of consecutive failures before the
	// circuit breaker opens. Default: 5.
	CircuitBreakerThreshold int

	// CircuitBreakerReset is the time to wait before transitioning from open
	// to half-open. Default: 30s.
	CircuitBreakerReset time.Duration
}

// ConnectionManager wraps an http.Client with retry logic and a circuit breaker.
// It is designed to maintain connectivity to servers that are intentionally
// dropping connections, returning errors, or behaving erratically.
type ConnectionManager struct {
	BaseTransport  *http.Transport
	RetryCount     int
	RetryDelay     time.Duration
	CircuitBreaker *CircuitBreaker
	client         *http.Client
}

// NewConnectionManager creates a ConnectionManager from the given configuration.
// If config fields are zero-valued, sensible defaults are applied.
func NewConnectionManager(config ConnectionConfig) *ConnectionManager {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 500 * time.Millisecond
	}
	if config.CircuitBreakerThreshold == 0 {
		config.CircuitBreakerThreshold = 5
	}
	if config.CircuitBreakerReset == 0 {
		config.CircuitBreakerReset = 30 * time.Second
	}

	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		DisableKeepAlives:   config.DisableKeepAlives,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if config.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for scanning
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		// Do not follow redirects automatically — the scanner needs to see them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return http.ErrUseLastResponse
		},
	}

	return &ConnectionManager{
		BaseTransport:  transport,
		RetryCount:     config.RetryCount,
		RetryDelay:     config.RetryDelay,
		CircuitBreaker: NewCircuitBreaker(config.CircuitBreakerThreshold, config.CircuitBreakerReset),
		client:         client,
	}
}

// Do executes an HTTP request with retry logic and circuit breaker protection.
//
// If the circuit breaker is open, the request is rejected immediately. On
// transient failures (timeouts, connection resets, server errors), the request
// is retried up to RetryCount times with exponential backoff. Successful
// responses close the circuit breaker; failures open it after the threshold.
func (m *ConnectionManager) Do(req *http.Request) (*http.Response, error) {
	if !m.CircuitBreaker.Allow() {
		return nil, fmt.Errorf("circuit breaker open: too many consecutive failures (state=%s)", m.CircuitBreaker.State())
	}

	var lastErr error
	delay := m.RetryDelay

	for attempt := 0; attempt <= m.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(delay)
			delay *= 2 // exponential backoff
		}

		resp, err := m.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("attempt %d/%d: %w", attempt+1, m.RetryCount+1, err)
			if !isRetryable(err) {
				m.CircuitBreaker.RecordFailure()
				return nil, lastErr
			}
			continue
		}

		// Server errors (5xx) are retryable; other responses are returned as-is.
		if resp.StatusCode >= 500 && attempt < m.RetryCount {
			resp.Body.Close()
			lastErr = fmt.Errorf("attempt %d/%d: server returned %d", attempt+1, m.RetryCount+1, resp.StatusCode)
			continue
		}

		m.CircuitBreaker.RecordSuccess()
		return resp, nil
	}

	m.CircuitBreaker.RecordFailure()
	return nil, fmt.Errorf("all %d attempts failed: %w", m.RetryCount+1, lastErr)
}

// isRetryable returns true if the error is transient and the request should be
// retried. Connection resets, timeouts, and DNS temporary failures are retryable.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check net.Error for timeout.
	var netErr net.Error
	if ok := isAs(err, &netErr); ok && netErr.Timeout() {
		return true
	}

	// Check for DNS temporary failures.
	var dnsErr *net.DNSError
	if ok := isAs(err, &dnsErr); ok && dnsErr.Temporary() {
		return true
	}

	// Check for connection-level errors.
	var opErr *net.OpError
	if isAs(err, &opErr) {
		return true
	}

	return false
}

// isAs is a helper wrapping errors.As to avoid importing errors in the switch.
func isAs[T any](err error, target *T) bool {
	return errorAs(err, target)
}

// errorAs wraps the standard library errors.As. We use a package-level function
// so the generic isAs helper can call it without a circular import.
var errorAs = errorsAs

// errorsAs is the concrete implementation using type assertion loop.
func errorsAs(err error, target interface{}) bool {
	if err == nil {
		return false
	}
	type iface interface{ As(interface{}) bool }
	type unwrapper interface{ Unwrap() error }
	type multiUnwrapper interface{ Unwrap() []error }

	for {
		if x, ok := target.(*net.Error); ok {
			if v, vOK := err.(net.Error); vOK {
				*x = v
				return true
			}
		}
		if x, ok := target.(**net.DNSError); ok {
			if v, vOK := err.(*net.DNSError); vOK {
				*x = v
				return true
			}
		}
		if x, ok := target.(**net.OpError); ok {
			if v, vOK := err.(*net.OpError); vOK {
				*x = v
				return true
			}
		}
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			if err == nil {
				return false
			}
			continue
		}
		if mu, ok := err.(multiUnwrapper); ok {
			for _, e := range mu.Unwrap() {
				if errorsAs(e, target) {
					return true
				}
			}
		}
		return false
	}
}

// CircuitBreaker implements the circuit breaker pattern to prevent hammering a
// server that is consistently failing. It has three states:
//
//   - closed: requests pass through normally
//   - open: requests are rejected immediately (server is considered down)
//   - half-open: one probe request is allowed through to test recovery
//
// After threshold consecutive failures, the breaker opens. After resetTimeout,
// it transitions to half-open. A successful request in half-open closes the
// breaker; a failure re-opens it.
type CircuitBreaker struct {
	mu           sync.Mutex
	failures     int
	threshold    int
	resetTimeout time.Duration
	state        string // "closed", "open", "half-open"
	lastFailure  time.Time
}

// Circuit breaker states.
const (
	StateClosed   = "closed"
	StateOpen     = "open"
	StateHalfOpen = "half-open"
)

// NewCircuitBreaker creates a circuit breaker with the given failure threshold
// and reset timeout. The breaker starts in the closed state.
func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold:    threshold,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Allow reports whether a request should be permitted. In the closed state,
// all requests are allowed. In the open state, requests are blocked unless the
// reset timeout has elapsed (transitioning to half-open). In the half-open
// state, one request is allowed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = StateHalfOpen
			return true
		}
		return false
	case StateHalfOpen:
		// In half-open, allow one probe request.
		return true
	default:
		return true
	}
}

// RecordSuccess records a successful request. In any state, this resets the
// failure count and closes the breaker.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = StateClosed
}

// RecordFailure records a failed request. If failures exceed the threshold,
// the breaker opens. In half-open state, any failure immediately re-opens.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()

	if cb.state == StateHalfOpen {
		cb.state = StateOpen
		return
	}

	if cb.failures >= cb.threshold {
		cb.state = StateOpen
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}
