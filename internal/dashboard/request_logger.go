package dashboard

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitchWebServer/internal/storage"
)

// RequestLogger samples incoming requests and persists them to the database
// in batches. This populates the request_log table for historical analysis
// (e.g., scanner false-negative classification across restarts).
type RequestLogger struct {
	ch       chan storage.RequestLogEntry
	stopCh   chan struct{}
	done     chan struct{}
	counter  atomic.Int64
	sampleN  int // log 1 in every N requests
}

var (
	globalRequestLogger *RequestLogger
	requestLoggerOnce   sync.Once
)

// StartRequestLogger initializes and starts the background request logger.
// sampleRate controls sampling: 1 = every request, 10 = every 10th, etc.
// Called once from main.go after storage is initialized.
func StartRequestLogger(sampleRate int) func() {
	if GetStore() == nil {
		return func() {} // no DB, no logging
	}
	if sampleRate < 1 {
		sampleRate = 10
	}

	rl := &RequestLogger{
		ch:      make(chan storage.RequestLogEntry, 4096),
		stopCh:  make(chan struct{}),
		done:    make(chan struct{}),
		sampleN: sampleRate,
	}
	requestLoggerOnce.Do(func() {
		globalRequestLogger = rl
	})

	go rl.batchWorker()
	log.Printf("[glitch] Request logger started (sample rate: 1/%d)", sampleRate)

	return func() {
		close(rl.stopCh)
		<-rl.done
	}
}

// LogRequest submits a request for potential logging. Only sampled requests
// are actually persisted. This is non-blocking; if the channel is full the
// entry is silently dropped.
func LogRequest(clientID, method, path string, statusCode int, latencyMs float64, responseType, userAgent string) {
	rl := globalRequestLogger
	if rl == nil {
		return
	}
	// Sample: only log every Nth request.
	n := rl.counter.Add(1)
	if n%int64(rl.sampleN) != 0 {
		return
	}
	entry := storage.RequestLogEntry{
		ClientID:     clientID,
		Method:       method,
		Path:         path,
		StatusCode:   statusCode,
		LatencyMs:    latencyMs,
		ResponseType: responseType,
		UserAgent:    userAgent,
	}
	select {
	case rl.ch <- entry:
	default:
		// Channel full, drop silently.
	}
}

// batchWorker drains the channel and writes batches to the database.
func (rl *RequestLogger) batchWorker() {
	defer close(rl.done)

	batch := make([]storage.RequestLogEntry, 0, 100)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		store := GetStore()
		if store == nil {
			batch = batch[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := store.SaveRequestBatch(ctx, batch)
		cancel()
		if err != nil {
			log.Printf("\033[33m[glitch]\033[0m Request log batch write failed: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case entry := <-rl.ch:
			batch = append(batch, entry)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-rl.stopCh:
			// Drain remaining entries.
			for {
				select {
				case entry := <-rl.ch:
					batch = append(batch, entry)
				default:
					flush()
					return
				}
			}
		}
	}
}
