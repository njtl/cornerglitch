package chaos

import (
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// LatencyInjector adds random delays to requests or responses to simulate
// network latency, slow backends, or congested links.
type LatencyInjector struct {
	MinDelay    time.Duration // minimum injected delay
	MaxDelay    time.Duration // maximum injected delay
	Probability float64       // 0.0-1.0, chance of injecting delay per request
	mu          sync.Mutex
	rng         *rand.Rand
}

// NewLatencyInjector creates a LatencyInjector with the given parameters.
func NewLatencyInjector(minDelay, maxDelay time.Duration, probability float64) *LatencyInjector {
	return &LatencyInjector{
		MinDelay:    minDelay,
		MaxDelay:    maxDelay,
		Probability: probability,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name returns the name of this interceptor.
func (l *LatencyInjector) Name() string {
	return "chaos/latency"
}

// InterceptRequest potentially injects a delay before the request is forwarded.
func (l *LatencyInjector) InterceptRequest(req *http.Request) (*http.Request, error) {
	l.maybeDelay()
	return req, nil
}

// InterceptResponse potentially injects a delay before the response is returned.
func (l *LatencyInjector) InterceptResponse(resp *http.Response) (*http.Response, error) {
	l.maybeDelay()
	return resp, nil
}

// maybeDelay sleeps for a random duration between MinDelay and MaxDelay
// with the configured probability.
func (l *LatencyInjector) maybeDelay() {
	l.mu.Lock()
	roll := l.rng.Float64()
	var delay time.Duration
	if roll < l.Probability {
		spread := l.MaxDelay - l.MinDelay
		if spread <= 0 {
			delay = l.MinDelay
		} else {
			delay = l.MinDelay + time.Duration(l.rng.Int63n(int64(spread)))
		}
	}
	l.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}
}
