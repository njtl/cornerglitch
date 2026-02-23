package chaos

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestLatencyInjector
// ---------------------------------------------------------------------------

func TestLatencyInjector(t *testing.T) {
	t.Run("name", func(t *testing.T) {
		li := NewLatencyInjector(10*time.Millisecond, 50*time.Millisecond, 1.0)
		if li.Name() != "chaos/latency" {
			t.Errorf("expected name 'chaos/latency', got %q", li.Name())
		}
	})

	t.Run("always_inject_adds_delay", func(t *testing.T) {
		minDelay := 50 * time.Millisecond
		maxDelay := 100 * time.Millisecond
		li := NewLatencyInjector(minDelay, maxDelay, 1.0) // probability=1.0: always inject

		req := httptest.NewRequest("GET", "/test", nil)

		start := time.Now()
		result, err := li.InterceptRequest(req)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if elapsed < minDelay {
			t.Errorf("expected delay of at least %s, got %s", minDelay, elapsed)
		}
	})

	t.Run("never_inject_no_delay", func(t *testing.T) {
		li := NewLatencyInjector(1*time.Second, 2*time.Second, 0.0) // probability=0.0: never inject

		req := httptest.NewRequest("GET", "/test", nil)

		start := time.Now()
		result, err := li.InterceptRequest(req)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if elapsed > 100*time.Millisecond {
			t.Errorf("expected no delay with probability=0.0, took %s", elapsed)
		}
	})

	t.Run("response_interception", func(t *testing.T) {
		li := NewLatencyInjector(10*time.Millisecond, 50*time.Millisecond, 1.0)

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		start := time.Now()
		result, err := li.InterceptResponse(resp)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if elapsed < 10*time.Millisecond {
			t.Errorf("expected response delay of at least 10ms, got %s", elapsed)
		}
	})

	t.Run("returns_same_request", func(t *testing.T) {
		li := NewLatencyInjector(0, 0, 0.0)
		req := httptest.NewRequest("GET", "/test", nil)

		result, err := li.InterceptRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != req {
			t.Error("expected same request object returned")
		}
	})
}

// ---------------------------------------------------------------------------
// TestResponseCorruptor
// ---------------------------------------------------------------------------

func TestResponseCorruptor(t *testing.T) {
	t.Run("name", func(t *testing.T) {
		c := NewResponseCorruptor(1.0, 0.1, 0.3, 0.2)
		if c.Name() != "chaos/corruption" {
			t.Errorf("expected name 'chaos/corruption', got %q", c.Name())
		}
	})

	t.Run("request_passthrough", func(t *testing.T) {
		c := NewResponseCorruptor(1.0, 0.1, 0.3, 0.2)
		req := httptest.NewRequest("GET", "/test", nil)

		result, err := c.InterceptRequest(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != req {
			t.Error("InterceptRequest should pass through the request unchanged")
		}
	})

	t.Run("no_corruption_when_probability_zero", func(t *testing.T) {
		c := NewResponseCorruptor(0.0, 0.1, 0.3, 0.2) // probability=0: never corrupt
		originalBody := "This is the original body content"
		resp := &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(originalBody)),
			Header:     make(http.Header),
		}

		result, err := c.InterceptResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// With probability=0, the body should be unchanged (same response).
		if result != resp {
			t.Error("expected same response when probability is 0")
		}
	})

	t.Run("corruption_when_probability_one", func(t *testing.T) {
		c := NewResponseCorruptor(1.0, 0.5, 0.0, 0.0) // always corrupt, flip 50% bytes, no truncate, no wrong type
		originalBody := strings.Repeat("ABCDEFGH", 100)
		resp := &http.Response{
			StatusCode:    200,
			Body:          io.NopCloser(strings.NewReader(originalBody)),
			ContentLength: int64(len(originalBody)),
			Header:        make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/plain")

		result, err := c.InterceptResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}

		// Read the corrupted body.
		body, err := io.ReadAll(result.Body)
		if err != nil {
			t.Fatalf("error reading corrupted body: %v", err)
		}

		// Body should be different from original (with 50% flip rate on a long string).
		if string(body) == originalBody {
			t.Error("expected body to be corrupted, but it matches original")
		}
	})

	t.Run("nil_body_response", func(t *testing.T) {
		c := NewResponseCorruptor(1.0, 0.1, 0.3, 0.2)
		resp := &http.Response{
			StatusCode: 200,
			Body:       nil,
			Header:     make(http.Header),
		}

		result, err := c.InterceptResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != resp {
			t.Error("nil body should return the same response")
		}
	})
}

// ---------------------------------------------------------------------------
// TestConnectionChaos_ShouldDrop
// ---------------------------------------------------------------------------

func TestConnectionChaos_ShouldDrop(t *testing.T) {
	t.Run("always_drop", func(t *testing.T) {
		cc := NewConnectionChaos(1.0, 0.0, 0.0, 1024) // 100% drop
		dropped := false
		for i := 0; i < 10; i++ {
			if cc.ShouldDrop() {
				dropped = true
				break
			}
		}
		if !dropped {
			t.Error("ShouldDrop should return true at least once with probability=1.0")
		}
	})

	t.Run("never_drop", func(t *testing.T) {
		cc := NewConnectionChaos(0.0, 0.0, 0.0, 1024) // 0% drop
		for i := 0; i < 100; i++ {
			if cc.ShouldDrop() {
				t.Error("ShouldDrop should never return true with probability=0.0")
				break
			}
		}
	})

	t.Run("probabilistic", func(t *testing.T) {
		cc := NewConnectionChaos(0.5, 0.0, 0.0, 1024) // 50% drop
		drops := 0
		passes := 0
		for i := 0; i < 1000; i++ {
			if cc.ShouldDrop() {
				drops++
			} else {
				passes++
			}
		}
		// With 50% probability over 1000 trials, we expect roughly 500 drops.
		// Allow a wide margin (300-700) due to randomness.
		if drops < 300 || drops > 700 {
			t.Errorf("expected ~500 drops out of 1000, got %d", drops)
		}
		if passes < 300 || passes > 700 {
			t.Errorf("expected ~500 passes out of 1000, got %d", passes)
		}
	})
}

// ---------------------------------------------------------------------------
// TestConnectionChaos_ShouldReset
// ---------------------------------------------------------------------------

func TestConnectionChaos_ShouldReset(t *testing.T) {
	cc := NewConnectionChaos(0.0, 1.0, 0.0, 1024) // 100% reset
	if !cc.ShouldReset() {
		t.Error("ShouldReset should return true with probability=1.0")
	}

	cc2 := NewConnectionChaos(0.0, 0.0, 0.0, 1024) // 0% reset
	for i := 0; i < 100; i++ {
		if cc2.ShouldReset() {
			t.Error("ShouldReset should never return true with probability=0.0")
			break
		}
	}
}

// ---------------------------------------------------------------------------
// TestConnectionChaos_ShouldSlow
// ---------------------------------------------------------------------------

func TestConnectionChaos_ShouldSlow(t *testing.T) {
	cc := NewConnectionChaos(0.0, 0.0, 1.0, 1024) // 100% slow
	if !cc.ShouldSlow() {
		t.Error("ShouldSlow should return true with probability=1.0")
	}

	cc2 := NewConnectionChaos(0.0, 0.0, 0.0, 1024) // 0% slow
	for i := 0; i < 100; i++ {
		if cc2.ShouldSlow() {
			t.Error("ShouldSlow should never return true with probability=0.0")
			break
		}
	}
}

// ---------------------------------------------------------------------------
// TestConnectionChaos_SlowWriter
// ---------------------------------------------------------------------------

func TestConnectionChaos_SlowWriter(t *testing.T) {
	cc := NewConnectionChaos(0.0, 0.0, 0.0, 100) // 100 bytes/sec
	var buf bytes.Buffer
	sw := cc.SlowWriter(&buf)

	data := []byte("Hello, World!") // 13 bytes
	n, err := sw.Write(data)
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected to write %d bytes, wrote %d", len(data), n)
	}
	if buf.String() != "Hello, World!" {
		t.Errorf("expected 'Hello, World!' in buffer, got %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// TestConnectionChaos_DefaultSlowBPS
// ---------------------------------------------------------------------------

func TestConnectionChaos_DefaultSlowBPS(t *testing.T) {
	cc := NewConnectionChaos(0.0, 0.0, 0.0, 0) // 0 should default to 1024
	if cc.SlowBytesPerSec != 1024 {
		t.Errorf("expected default SlowBytesPerSec=1024, got %d", cc.SlowBytesPerSec)
	}

	cc2 := NewConnectionChaos(0.0, 0.0, 0.0, -1) // negative should default to 1024
	if cc2.SlowBytesPerSec != 1024 {
		t.Errorf("expected default SlowBytesPerSec=1024 for negative input, got %d", cc2.SlowBytesPerSec)
	}
}

// ---------------------------------------------------------------------------
// TestResponseCorruptor_FlipBytes
// ---------------------------------------------------------------------------

func TestResponseCorruptor_FlipBytes(t *testing.T) {
	c := NewResponseCorruptor(1.0, 0.5, 0.0, 0.0)
	original := []byte(strings.Repeat("A", 100))
	corrupted := c.flipBytes(original)

	if len(corrupted) != len(original) {
		t.Errorf("flipBytes should not change length: %d vs %d", len(original), len(corrupted))
	}

	// With 50% flip rate, at least some bytes should be different.
	differences := 0
	for i := range original {
		if original[i] != corrupted[i] {
			differences++
		}
	}
	if differences == 0 {
		t.Error("expected at least some flipped bytes")
	}
}

// ---------------------------------------------------------------------------
// TestResponseCorruptor_TruncateBody
// ---------------------------------------------------------------------------

func TestResponseCorruptor_TruncateBody(t *testing.T) {
	c := NewResponseCorruptor(1.0, 0.0, 1.0, 0.0)
	original := []byte(strings.Repeat("B", 200))
	truncated := c.truncateBody(original)

	if len(truncated) >= len(original) {
		t.Errorf("truncateBody should produce shorter body: %d vs %d", len(truncated), len(original))
	}
	if len(truncated) == 0 {
		t.Error("truncated body should not be empty")
	}
}

// ---------------------------------------------------------------------------
// TestResponseCorruptor_EmptyBody
// ---------------------------------------------------------------------------

func TestResponseCorruptor_EmptyBody(t *testing.T) {
	c := NewResponseCorruptor(1.0, 0.5, 0.5, 0.0)

	// flipBytes with empty body should not panic.
	result := c.flipBytes([]byte{})
	if len(result) != 0 {
		t.Errorf("flipBytes on empty body should return empty, got %d bytes", len(result))
	}

	// truncateBody with very short body.
	shortResult := c.truncateBody([]byte("x"))
	if len(shortResult) != 1 {
		t.Errorf("truncateBody on single byte should return single byte, got %d", len(shortResult))
	}
}
