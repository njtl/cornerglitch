package waf

import (
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter implements a token bucket rate limiter. Tokens are refilled at
// a steady rate up to BurstSize, and each request consumes one token.
type RateLimiter struct {
	RequestsPerSecond int     // refill rate
	BurstSize         int     // maximum tokens (bucket capacity)
	mu                sync.Mutex
	tokens            float64
	lastRefill        time.Time
	limited           atomic.Int64
}

// NewRateLimiter creates a token bucket rate limiter with the given
// requests-per-second rate and burst capacity.
func NewRateLimiter(rps int, burst int) *RateLimiter {
	if burst < 1 {
		burst = 1
	}
	if rps < 1 {
		rps = 1
	}
	return &RateLimiter{
		RequestsPerSecond: rps,
		BurstSize:         burst,
		tokens:            float64(burst),
		lastRefill:        time.Now(),
	}
}

// Allow returns true if the request is permitted under the rate limit.
// It consumes one token from the bucket if available.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now

	// Refill tokens based on elapsed time
	r.tokens += elapsed * float64(r.RequestsPerSecond)
	if r.tokens > float64(r.BurstSize) {
		r.tokens = float64(r.BurstSize)
	}

	if r.tokens >= 1.0 {
		r.tokens -= 1.0
		return true
	}

	// Rate limited
	r.limited.Add(1)
	return false
}

// Limited returns the total number of requests that have been rate limited.
func (r *RateLimiter) Limited() int64 {
	return r.limited.Load()
}
