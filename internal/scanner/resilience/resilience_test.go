package resilience

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestErrorHandler_SafeReadBody
// ---------------------------------------------------------------------------

func TestErrorHandler_SafeReadBody(t *testing.T) {
	t.Run("nil_response", func(t *testing.T) {
		h := NewErrorHandler(1<<20, 5*time.Second)
		body, err := h.SafeReadBody(nil)
		if err == nil {
			t.Error("expected error for nil response")
		}
		if body != nil {
			t.Error("expected nil body for nil response")
		}
	})

	t.Run("nil_body", func(t *testing.T) {
		h := NewErrorHandler(1<<20, 5*time.Second)
		resp := &http.Response{
			StatusCode: 200,
			Body:       nil,
			Header:     make(http.Header),
		}
		body, err := h.SafeReadBody(resp)
		if err != nil {
			t.Errorf("unexpected error for nil body: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("expected empty body, got %d bytes", len(body))
		}
	})

	t.Run("normal_body", func(t *testing.T) {
		h := NewErrorHandler(1<<20, 5*time.Second)
		content := "Hello, World!"
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(content)),
			Header:     make(http.Header),
		}
		body, err := h.SafeReadBody(resp)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if string(body) != content {
			t.Errorf("expected body %q, got %q", content, string(body))
		}
	})

	t.Run("body_exceeds_limit", func(t *testing.T) {
		maxSize := int64(100)
		h := NewErrorHandler(maxSize, 5*time.Second)
		content := strings.Repeat("A", 200)
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(content)),
			Header:     make(http.Header),
		}
		body, err := h.SafeReadBody(resp)
		if err == nil {
			t.Error("expected error for body exceeding limit")
		}
		if int64(len(body)) > maxSize {
			t.Errorf("body should be truncated to %d, got %d bytes", maxSize, len(body))
		}

		// Verify the error was recorded.
		stats := h.GetStats()
		if stats.ByType[ErrTypeBodyTooLarge] == 0 {
			t.Error("expected body_too_large error to be recorded")
		}
	})

	t.Run("gzip_declared_but_not_gzip", func(t *testing.T) {
		h := NewErrorHandler(1<<20, 5*time.Second)
		content := "This is not gzip compressed"
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(content)),
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Encoding", "gzip")

		body, err := h.SafeReadBody(resp)
		// Should fall back to reading raw body.
		if err != nil {
			t.Logf("error (expected for malformed gzip): %v", err)
		}
		if len(body) == 0 {
			t.Error("expected non-empty body after gzip fallback")
		}

		stats := h.GetStats()
		if stats.ByType[ErrTypeDecompression] == 0 {
			t.Error("expected decompression_error to be recorded for fake gzip")
		}
	})

	t.Run("garbage_bytes", func(t *testing.T) {
		h := NewErrorHandler(1<<20, 5*time.Second)
		// Create a body with > 30% non-printable bytes.
		garbage := make([]byte, 100)
		for i := range garbage {
			garbage[i] = byte(i % 16) // lots of control chars
		}
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(garbage))),
			Header:     make(http.Header),
		}

		body, err := h.SafeReadBody(resp)
		if err == nil {
			t.Error("expected error for garbage bytes")
		}
		if len(body) == 0 {
			t.Error("expected body to be returned even for garbage")
		}
	})
}

// ---------------------------------------------------------------------------
// TestErrorHandler_ClassifyError
// ---------------------------------------------------------------------------

func TestErrorHandler_ClassifyError(t *testing.T) {
	h := NewErrorHandler(1<<20, 5*time.Second)

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, ""},
		{"timeout string", fmt.Errorf("connection timeout exceeded"), ErrTypeTimeout},
		{"deadline string", fmt.Errorf("context deadline exceeded"), ErrTypeTimeout},
		{"connection reset", fmt.Errorf("connection reset by peer"), ErrTypeConnectionReset},
		{"connection refused", fmt.Errorf("connection refused"), ErrTypeConnectionRefused},
		{"unexpected eof", io.ErrUnexpectedEOF, ErrTypeEOF},
		{"eof", io.EOF, ErrTypeEOF},
		{"tls error", fmt.Errorf("tls handshake failure"), ErrTypeTLS},
		{"certificate error", fmt.Errorf("x509: certificate signed by unknown authority"), ErrTypeTLS},
		{"body truncated", fmt.Errorf("body truncated at 1024"), ErrTypeBodyTooLarge},
		{"decompression", fmt.Errorf("gzip: invalid header"), ErrTypeDecompression},
		{"partial response", fmt.Errorf("partial read (100 bytes)"), ErrTypePartialResponse},
		{"garbage bytes", fmt.Errorf("response body contains garbage bytes"), ErrTypeGarbageBytes},
		{"unknown error", fmt.Errorf("something entirely new"), ErrTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := h.ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError(%v) = %q, expected %q", tt.err, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestErrorHandler_RecordError
// ---------------------------------------------------------------------------

func TestErrorHandler_RecordError(t *testing.T) {
	h := NewErrorHandler(1<<20, 5*time.Second)

	h.RecordError(ErrTypeTimeout)
	h.RecordError(ErrTypeTimeout)
	h.RecordError(ErrTypeConnectionReset)
	h.RecordError(ErrTypeUnknown)

	stats := h.GetStats()

	if stats.TotalErrors != 4 {
		t.Errorf("expected 4 total errors, got %d", stats.TotalErrors)
	}
	if stats.HandledErrors != 3 {
		t.Errorf("expected 3 handled errors, got %d", stats.HandledErrors)
	}
	if stats.UnhandledErrors != 1 {
		t.Errorf("expected 1 unhandled error, got %d", stats.UnhandledErrors)
	}
	if stats.ByType[ErrTypeTimeout] != 2 {
		t.Errorf("expected 2 timeout errors, got %d", stats.ByType[ErrTypeTimeout])
	}
	if stats.ByType[ErrTypeConnectionReset] != 1 {
		t.Errorf("expected 1 connection_reset error, got %d", stats.ByType[ErrTypeConnectionReset])
	}
}

// ---------------------------------------------------------------------------
// TestErrorHandler_GetStats_DeepCopy
// ---------------------------------------------------------------------------

func TestErrorHandler_GetStats_DeepCopy(t *testing.T) {
	h := NewErrorHandler(1<<20, 5*time.Second)
	h.RecordError(ErrTypeTimeout)

	stats1 := h.GetStats()
	stats1.ByType[ErrTypeTimeout] = 999 // mutate the copy

	stats2 := h.GetStats()
	if stats2.ByType[ErrTypeTimeout] != 1 {
		t.Error("GetStats should return a deep copy; original was mutated")
	}
}

// ---------------------------------------------------------------------------
// TestCircuitBreaker_Allow
// ---------------------------------------------------------------------------

func TestCircuitBreaker_Allow(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Second)

	// Closed state: should allow all requests.
	if !cb.Allow() {
		t.Error("expected Allow()=true in closed state")
	}
	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed', got %q", cb.State())
	}

	// Record a success: should remain closed.
	cb.RecordSuccess()
	if !cb.Allow() {
		t.Error("expected Allow()=true after success")
	}
}

// ---------------------------------------------------------------------------
// TestCircuitBreaker_Open
// ---------------------------------------------------------------------------

func TestCircuitBreaker_Open(t *testing.T) {
	threshold := 3
	cb := NewCircuitBreaker(threshold, 1*time.Hour) // long reset so it stays open

	// Record threshold failures to open the breaker.
	for i := 0; i < threshold; i++ {
		cb.RecordFailure()
	}

	if cb.State() != StateOpen {
		t.Errorf("expected state 'open' after %d failures, got %q", threshold, cb.State())
	}

	// Should reject requests in open state (reset timeout not elapsed).
	if cb.Allow() {
		t.Error("expected Allow()=false in open state")
	}
}

// ---------------------------------------------------------------------------
// TestCircuitBreaker_HalfOpen
// ---------------------------------------------------------------------------

func TestCircuitBreaker_HalfOpen(t *testing.T) {
	threshold := 2
	resetTimeout := 50 * time.Millisecond
	cb := NewCircuitBreaker(threshold, resetTimeout)

	// Open the breaker.
	for i := 0; i < threshold; i++ {
		cb.RecordFailure()
	}
	if cb.State() != StateOpen {
		t.Fatalf("expected state 'open', got %q", cb.State())
	}

	// Wait for the reset timeout.
	time.Sleep(resetTimeout + 10*time.Millisecond)

	// Should transition to half-open and allow one probe.
	if !cb.Allow() {
		t.Error("expected Allow()=true after reset timeout (half-open)")
	}
	if cb.State() != StateHalfOpen {
		t.Errorf("expected state 'half-open', got %q", cb.State())
	}

	// Success in half-open should close the breaker.
	cb.RecordSuccess()
	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed' after success in half-open, got %q", cb.State())
	}
}

func TestCircuitBreaker_HalfOpen_FailureReopens(t *testing.T) {
	threshold := 2
	resetTimeout := 50 * time.Millisecond
	cb := NewCircuitBreaker(threshold, resetTimeout)

	// Open the breaker.
	for i := 0; i < threshold; i++ {
		cb.RecordFailure()
	}

	// Wait for reset timeout.
	time.Sleep(resetTimeout + 10*time.Millisecond)

	// Allow one probe (transitions to half-open).
	cb.Allow()
	if cb.State() != StateHalfOpen {
		t.Fatalf("expected state 'half-open', got %q", cb.State())
	}

	// Failure in half-open should re-open.
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Errorf("expected state 'open' after failure in half-open, got %q", cb.State())
	}
}

// ---------------------------------------------------------------------------
// TestCircuitBreaker_SuccessResetsFailures
// ---------------------------------------------------------------------------

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 1*time.Hour)

	// Record 2 failures (below threshold).
	cb.RecordFailure()
	cb.RecordFailure()

	// Success should reset failure count.
	cb.RecordSuccess()
	if cb.State() != StateClosed {
		t.Errorf("expected state 'closed' after success, got %q", cb.State())
	}

	// Now 2 more failures should not open (because count was reset).
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Error("expected state 'closed' because success reset the counter")
	}

	// Third failure should open.
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Error("expected state 'open' after 3 consecutive failures")
	}
}

// ---------------------------------------------------------------------------
// TestConnectionManager_NewConnectionManager
// ---------------------------------------------------------------------------

func TestConnectionManager_NewConnectionManager(t *testing.T) {
	t.Run("defaults_applied", func(t *testing.T) {
		cm := NewConnectionManager(ConnectionConfig{})
		if cm.RetryCount != 3 {
			t.Errorf("expected default RetryCount=3, got %d", cm.RetryCount)
		}
		if cm.RetryDelay != 500*time.Millisecond {
			t.Errorf("expected default RetryDelay=500ms, got %s", cm.RetryDelay)
		}
		if cm.CircuitBreaker == nil {
			t.Error("circuit breaker is nil")
		}
		if cm.CircuitBreaker.threshold != 5 {
			t.Errorf("expected default CB threshold=5, got %d", cm.CircuitBreaker.threshold)
		}
	})

	t.Run("custom_values", func(t *testing.T) {
		cm := NewConnectionManager(ConnectionConfig{
			Timeout:                 30 * time.Second,
			RetryCount:              5,
			RetryDelay:              1 * time.Second,
			CircuitBreakerThreshold: 10,
			CircuitBreakerReset:     1 * time.Minute,
			TLSSkipVerify:           true,
		})
		if cm.RetryCount != 5 {
			t.Errorf("expected RetryCount=5, got %d", cm.RetryCount)
		}
		if cm.RetryDelay != 1*time.Second {
			t.Errorf("expected RetryDelay=1s, got %s", cm.RetryDelay)
		}
		if cm.CircuitBreaker.threshold != 10 {
			t.Errorf("expected CB threshold=10, got %d", cm.CircuitBreaker.threshold)
		}
	})
}

// ---------------------------------------------------------------------------
// TestIsRetryable
// ---------------------------------------------------------------------------

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"generic error", errors.New("something went wrong"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryable(tt.err)
			if result != tt.expected {
				t.Errorf("isRetryable(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}
