// Package resilience provides error handling and connection management for
// scanning servers that produce intentionally broken HTTP responses.
package resilience

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrorHandler safely processes HTTP responses that may be corrupted, truncated,
// excessively large, or otherwise malformed. It records statistics about the
// types of errors encountered during a scan.
type ErrorHandler struct {
	MaxBodySize int64
	ReadTimeout time.Duration
	Stats       ErrorStats
	mu          sync.Mutex
}

// ErrorStats tracks counts of errors encountered during scanning, broken down
// by category.
type ErrorStats struct {
	TotalErrors     int            `json:"total_errors"`
	HandledErrors   int            `json:"handled_errors"`
	UnhandledErrors int            `json:"unhandled_errors"`
	ByType          map[string]int `json:"by_type"`
}

// Error type constants returned by ClassifyError.
const (
	ErrTypeTimeout          = "timeout"
	ErrTypeConnectionReset  = "connection_reset"
	ErrTypeConnectionRefused = "connection_refused"
	ErrTypeEOF              = "unexpected_eof"
	ErrTypeDNS              = "dns_error"
	ErrTypeTLS              = "tls_error"
	ErrTypeBodyTooLarge     = "body_too_large"
	ErrTypeDecompression    = "decompression_error"
	ErrTypeCorruptedBody    = "corrupted_body"
	ErrTypeMalformedHeader  = "malformed_header"
	ErrTypeInvalidStatus    = "invalid_status"
	ErrTypePartialResponse  = "partial_response"
	ErrTypeGarbageBytes     = "garbage_bytes"
	ErrTypeUnknown          = "unknown"
)

// NewErrorHandler creates an ErrorHandler with the given body size limit and
// per-read timeout. The body size limit prevents memory exhaustion from infinite
// or very large response bodies.
func NewErrorHandler(maxBody int64, readTimeout time.Duration) *ErrorHandler {
	return &ErrorHandler{
		MaxBodySize: maxBody,
		ReadTimeout: readTimeout,
		Stats: ErrorStats{
			ByType: make(map[string]int),
		},
	}
}

// SafeReadBody reads the body of an HTTP response safely, applying size limits,
// timeouts, and decompression handling. It will never panic, even on severely
// corrupted responses.
//
// The method handles:
//   - nil response or nil body (returns empty bytes)
//   - gzip-declared bodies that are not actually gzip-compressed
//   - bodies that exceed MaxBodySize (truncated, error returned)
//   - bodies that stall mid-stream (enforced by ReadTimeout)
//   - garbage bytes or binary data (returned as-is)
//   - partial responses truncated mid-stream
func (h *ErrorHandler) SafeReadBody(resp *http.Response) ([]byte, error) {
	if resp == nil {
		h.RecordError(ErrTypePartialResponse)
		return nil, fmt.Errorf("nil response")
	}
	if resp.Body == nil {
		return []byte{}, nil
	}
	defer resp.Body.Close()

	// Validate status code range.
	if resp.StatusCode < 100 || resp.StatusCode > 599 {
		h.RecordError(ErrTypeInvalidStatus)
		// Continue reading body anyway — we still want the content.
	}

	// Check for malformed headers that could cause problems.
	h.checkHeaders(resp)

	// Determine the reader — handle gzip transparently.
	reader, err := h.bodyReader(resp)
	if err != nil {
		return nil, err
	}

	// Wrap in a size-limited reader to prevent memory exhaustion.
	limited := io.LimitReader(reader, h.MaxBodySize+1)

	// Read with a deadline by wrapping in a timed reader.
	buf, err := h.timedRead(limited)
	if err != nil {
		errType := h.ClassifyError(err)
		h.RecordError(errType)
		// Return what we got so far along with the error.
		if len(buf) > 0 {
			return buf, fmt.Errorf("partial read (%d bytes): %w", len(buf), err)
		}
		return nil, err
	}

	// Check if body exceeded the limit.
	if int64(len(buf)) > h.MaxBodySize {
		h.RecordError(ErrTypeBodyTooLarge)
		return buf[:h.MaxBodySize], fmt.Errorf("body truncated at %d bytes (limit %d)", len(buf), h.MaxBodySize)
	}

	// Check for garbage bytes (high proportion of non-printable, non-UTF8).
	if len(buf) > 0 && h.isGarbage(buf) {
		h.RecordError(ErrTypeGarbageBytes)
		return buf, fmt.Errorf("response body contains garbage bytes")
	}

	return buf, nil
}

// bodyReader returns an appropriate reader for the response body, handling
// gzip Content-Encoding. If the server declares gzip but the body is not
// valid gzip, it falls back to reading the raw body.
func (h *ErrorHandler) bodyReader(resp *http.Response) (io.Reader, error) {
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	if encoding != "gzip" {
		return resp.Body, nil
	}

	// Read enough to check the gzip magic number.
	// Gzip files start with bytes 0x1f 0x8b.
	var probe [2]byte
	n, err := io.ReadFull(resp.Body, probe[:])
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			h.RecordError(ErrTypeDecompression)
			return bytes.NewReader(probe[:n]), nil
		}
		return nil, err
	}

	// Reconstruct a reader with the probed bytes prepended.
	combined := io.MultiReader(bytes.NewReader(probe[:n]), resp.Body)

	if probe[0] != 0x1f || probe[1] != 0x8b {
		// Not valid gzip despite Content-Encoding header.
		h.RecordError(ErrTypeDecompression)
		return combined, nil
	}

	gz, err := gzip.NewReader(combined)
	if err != nil {
		h.RecordError(ErrTypeDecompression)
		// Fall back to raw body with probed bytes.
		return io.MultiReader(bytes.NewReader(probe[:n]), resp.Body), nil
	}

	return gz, nil
}

// timedRead reads all available data from r, returning whatever was read even
// if an error occurs. It enforces the ErrorHandler's ReadTimeout.
func (h *ErrorHandler) timedRead(r io.Reader) ([]byte, error) {
	done := make(chan struct{})
	var buf bytes.Buffer
	var readErr error

	go func() {
		defer close(done)
		_, readErr = io.Copy(&buf, r)
	}()

	select {
	case <-done:
		return buf.Bytes(), readErr
	case <-time.After(h.ReadTimeout):
		// Return whatever we managed to read before timeout.
		return buf.Bytes(), fmt.Errorf("read timeout after %s", h.ReadTimeout)
	}
}

// checkHeaders inspects response headers for malformation and records errors.
func (h *ErrorHandler) checkHeaders(resp *http.Response) {
	// Check Content-Length consistency.
	if resp.ContentLength < -1 {
		h.RecordError(ErrTypeMalformedHeader)
	}

	// Check for headers with empty names or obviously corrupted values.
	for name, values := range resp.Header {
		if name == "" {
			h.RecordError(ErrTypeMalformedHeader)
			continue
		}
		for _, v := range values {
			if containsControlChars(v) {
				h.RecordError(ErrTypeMalformedHeader)
			}
		}
	}
}

// containsControlChars reports whether s contains ASCII control characters
// other than \t, \r, \n (which are acceptable in header values per HTTP spec).
func containsControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			return true
		}
		if c == 0x7f {
			return true
		}
	}
	return false
}

// isGarbage returns true if more than 30% of the bytes in data are
// non-printable, non-whitespace bytes outside the ASCII range. This catches
// binary/garbage responses that are not useful text.
func (h *ErrorHandler) isGarbage(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Sample at most 1024 bytes for performance.
	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}
	nonPrintable := 0
	for _, b := range sample {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			nonPrintable++
		}
		if b == 0x7f {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(sample)) > 0.3
}

// ClassifyError examines an error and returns a string constant identifying its
// type. This is used for error statistics and to decide on retry strategy.
func (h *ErrorHandler) ClassifyError(err error) string {
	if err == nil {
		return ""
	}

	errStr := err.Error()

	// Check for timeout errors (net.Error interface).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrTypeTimeout
	}

	// Check for specific network errors.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			if strings.Contains(errStr, "refused") {
				return ErrTypeConnectionRefused
			}
			return ErrTypeDNS
		}
		if strings.Contains(errStr, "reset") {
			return ErrTypeConnectionReset
		}
	}

	// Check for DNS errors.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ErrTypeDNS
	}

	// String-based classification for errors that don't implement typed interfaces.
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF):
		return ErrTypeEOF
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return ErrTypeTimeout
	case strings.Contains(errStr, "connection reset"):
		return ErrTypeConnectionReset
	case strings.Contains(errStr, "connection refused"):
		return ErrTypeConnectionRefused
	case strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509"):
		return ErrTypeTLS
	case strings.Contains(errStr, "body truncated") || strings.Contains(errStr, "body_too_large"):
		return ErrTypeBodyTooLarge
	case strings.Contains(errStr, "gzip") || strings.Contains(errStr, "decompression") || strings.Contains(errStr, "flate"):
		return ErrTypeDecompression
	case strings.Contains(errStr, "partial"):
		return ErrTypePartialResponse
	case strings.Contains(errStr, "garbage"):
		return ErrTypeGarbageBytes
	default:
		return ErrTypeUnknown
	}
}

// RecordError increments the counter for the given error type. It is safe for
// concurrent use.
func (h *ErrorHandler) RecordError(errType string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Stats.TotalErrors++
	if errType != ErrTypeUnknown {
		h.Stats.HandledErrors++
	} else {
		h.Stats.UnhandledErrors++
	}
	h.Stats.ByType[errType]++
}

// GetStats returns a snapshot of the current error statistics. The returned
// value is a copy and safe to use without locking.
func (h *ErrorHandler) GetStats() ErrorStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Return a deep copy so callers can't mutate our state.
	byType := make(map[string]int, len(h.Stats.ByType))
	for k, v := range h.Stats.ByType {
		byType[k] = v
	}
	return ErrorStats{
		TotalErrors:     h.Stats.TotalErrors,
		HandledErrors:   h.Stats.HandledErrors,
		UnhandledErrors: h.Stats.UnhandledErrors,
		ByType:          byType,
	}
}
