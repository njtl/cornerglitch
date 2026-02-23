package chaos

import (
	"io"
	"math/rand"
	"sync"
	"time"
)

// ConnectionChaos simulates connection-level problems such as dropped connections,
// TCP resets, and throttled throughput. It does not implement Interceptor directly
// because connection-level chaos requires access to the raw connection/writer.
type ConnectionChaos struct {
	DropProbability  float64 // chance of dropping the connection entirely
	ResetProbability float64 // chance of sending a TCP RST
	SlowProbability  float64 // chance of throttling response speed
	SlowBytesPerSec  int     // bytes per second when in slow mode
	mu               sync.Mutex
	rng              *rand.Rand
}

// NewConnectionChaos creates a ConnectionChaos with the given parameters.
func NewConnectionChaos(dropProb, resetProb, slowProb float64, slowBPS int) *ConnectionChaos {
	if slowBPS <= 0 {
		slowBPS = 1024 // default: 1KB/s
	}
	return &ConnectionChaos{
		DropProbability:  dropProb,
		ResetProbability: resetProb,
		SlowProbability:  slowProb,
		SlowBytesPerSec:  slowBPS,
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ShouldDrop returns true if this connection should be dropped (no response sent).
func (cc *ConnectionChaos) ShouldDrop() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.rng.Float64() < cc.DropProbability
}

// ShouldReset returns true if this connection should receive a RST (abrupt close).
func (cc *ConnectionChaos) ShouldReset() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.rng.Float64() < cc.ResetProbability
}

// ShouldSlow returns true if this connection should be throttled.
func (cc *ConnectionChaos) ShouldSlow() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.rng.Float64() < cc.SlowProbability
}

// SlowWriter returns a writer that throttles output to SlowBytesPerSec.
// Each Write call is broken into small chunks with sleeps between them
// to simulate a very slow connection.
func (cc *ConnectionChaos) SlowWriter(w io.Writer) io.Writer {
	return &throttledWriter{
		underlying:  w,
		bytesPerSec: cc.SlowBytesPerSec,
	}
}

// throttledWriter wraps an io.Writer to limit throughput.
type throttledWriter struct {
	underlying  io.Writer
	bytesPerSec int
}

// Write implements io.Writer with throttling. It writes in small chunks
// with calculated sleeps to achieve the target bytes-per-second rate.
func (tw *throttledWriter) Write(p []byte) (int, error) {
	if tw.bytesPerSec <= 0 {
		return tw.underlying.Write(p)
	}

	totalWritten := 0
	remaining := p

	// Write in chunks, sleeping between each to maintain the target rate.
	// Chunk size is 1/10th of bytes-per-second or the remaining data, whichever is smaller.
	chunkSize := tw.bytesPerSec / 10
	if chunkSize < 1 {
		chunkSize = 1
	}

	for len(remaining) > 0 {
		writeSize := chunkSize
		if writeSize > len(remaining) {
			writeSize = len(remaining)
		}

		n, err := tw.underlying.Write(remaining[:writeSize])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
		remaining = remaining[n:]

		if len(remaining) > 0 {
			// Sleep proportional to bytes written to maintain target rate
			sleepDuration := time.Duration(float64(n) / float64(tw.bytesPerSec) * float64(time.Second))
			if sleepDuration < time.Millisecond {
				sleepDuration = time.Millisecond
			}
			time.Sleep(sleepDuration)
		}
	}

	return totalWritten, nil
}
