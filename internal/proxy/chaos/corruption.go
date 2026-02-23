package chaos

import (
	"bytes"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// ResponseCorruptor corrupts HTTP response bodies by flipping random bytes,
// truncating content, or changing the Content-Type header.
type ResponseCorruptor struct {
	Probability  float64 // overall chance of corrupting a response
	FlipBytePct  float64 // percentage of bytes to flip (0.0-1.0)
	TruncatePct  float64 // chance of truncating (0.0-1.0)
	WrongTypePct float64 // chance of wrong Content-Type (0.0-1.0)
	mu           sync.Mutex
	rng          *rand.Rand
}

// NewResponseCorruptor creates a ResponseCorruptor with the given parameters.
func NewResponseCorruptor(probability, flipBytePct, truncatePct, wrongTypePct float64) *ResponseCorruptor {
	return &ResponseCorruptor{
		Probability:  probability,
		FlipBytePct:  flipBytePct,
		TruncatePct:  truncatePct,
		WrongTypePct: wrongTypePct,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name returns the name of this interceptor.
func (c *ResponseCorruptor) Name() string {
	return "chaos/corruption"
}

// InterceptRequest is a no-op for corruption; corruption only affects responses.
func (c *ResponseCorruptor) InterceptRequest(req *http.Request) (*http.Request, error) {
	return req, nil
}

// InterceptResponse potentially corrupts the response body.
func (c *ResponseCorruptor) InterceptResponse(resp *http.Response) (*http.Response, error) {
	c.mu.Lock()
	shouldCorrupt := c.rng.Float64() < c.Probability
	c.mu.Unlock()

	if !shouldCorrupt {
		return resp, nil
	}

	// Read the entire response body
	if resp.Body == nil {
		return resp, nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, err
	}

	// Decide what kind of corruption to apply
	c.mu.Lock()
	roll := c.rng.Float64()
	c.mu.Unlock()

	if roll < c.TruncatePct && len(body) > 1 {
		body = c.truncateBody(body)
	} else if roll < c.TruncatePct+c.WrongTypePct {
		c.corruptContentType(resp)
	} else {
		body = c.flipBytes(body)
	}

	// Replace the body with the corrupted version
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", "")
	resp.Header.Del("Content-Length")

	return resp, nil
}

// flipBytes flips random bytes in the body according to FlipBytePct.
func (c *ResponseCorruptor) flipBytes(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	corrupted := make([]byte, len(body))
	copy(corrupted, body)

	c.mu.Lock()
	numFlips := int(float64(len(corrupted)) * c.FlipBytePct)
	if numFlips < 1 {
		numFlips = 1
	}
	for i := 0; i < numFlips; i++ {
		idx := c.rng.Intn(len(corrupted))
		corrupted[idx] ^= byte(c.rng.Intn(256))
	}
	c.mu.Unlock()

	return corrupted
}

// truncateBody cuts the body at a random point.
func (c *ResponseCorruptor) truncateBody(body []byte) []byte {
	if len(body) <= 1 {
		return body
	}
	c.mu.Lock()
	// Truncate to 10-90% of original length
	minLen := len(body) / 10
	if minLen < 1 {
		minLen = 1
	}
	maxLen := len(body) * 9 / 10
	if maxLen <= minLen {
		maxLen = minLen + 1
	}
	cutPoint := minLen + c.rng.Intn(maxLen-minLen)
	c.mu.Unlock()

	return body[:cutPoint]
}

// corruptContentType replaces the Content-Type header with a wrong value.
func (c *ResponseCorruptor) corruptContentType(resp *http.Response) {
	wrongTypes := []string{
		"application/octet-stream",
		"text/plain",
		"image/png",
		"application/xml",
		"text/csv",
		"application/pdf",
		"audio/mpeg",
		"video/mp4",
	}
	c.mu.Lock()
	idx := c.rng.Intn(len(wrongTypes))
	c.mu.Unlock()

	resp.Header.Set("Content-Type", wrongTypes[idx])
}
