package websocket

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

// ---------------------------------------------------------------------------
// Endpoint: /ws/live-data, /ws/events, /ws/stream — Budget-draining honeypot
//
// Sends increasingly slow data to keep scanners/scrapers connected as long as
// possible, draining their crawl budget without providing useful content.
//
// Phase 1 (0-30s):   Fast updates every 1-2s — looks like real market data
// Phase 2 (30-120s): Degraded mode, 10-30s intervals, latency warnings
// Phase 3 (120s+):   Near-stalled, 60s intervals, "reconnecting" status
// ---------------------------------------------------------------------------

func (h *Handler) runHoneypot(conn net.Conn, path string) {
	cr := newConnRunner(conn)
	go cr.readLoop()
	go cr.pingLoop()
	defer cr.close()

	rng := rand.New(rand.NewSource(pathSeed(path) ^ time.Now().UnixNano()))
	start := time.Now()
	seq := 0

	symbols := []string{"AAPL", "GOOGL", "MSFT", "AMZN", "TSLA", "NVDA", "META", "NFLX"}
	basePrices := []float64{189.42, 141.80, 417.50, 186.30, 248.90, 885.20, 505.75, 628.40}
	prices := make([]float64, len(symbols))
	copy(prices, basePrices)

	metricNames := []string{"cpu_usage", "memory_pct", "disk_io", "network_rx", "request_latency_ms"}
	chatUsers := []string{"system", "monitor", "ops-bot", "alert-engine", "scheduler"}
	chatMessages := []string{
		"Health check passed",
		"Scaling event triggered",
		"Cache hit ratio: 94.2%",
		"Queue depth nominal",
		"Replication lag within bounds",
		"Failover standby ready",
		"Certificate renewal scheduled",
		"Rate limiter threshold adjusted",
	}

	for {
		elapsed := time.Since(start)
		seq++

		// Determine phase and interval.
		var interval time.Duration
		switch {
		case elapsed < 30*time.Second:
			// Phase 1: fast, 1-2 seconds.
			interval = time.Duration(1000+rng.Intn(1000)) * time.Millisecond
		case elapsed < 120*time.Second:
			// Phase 2: degraded, 10-30 seconds.
			interval = time.Duration(10000+rng.Intn(20000)) * time.Millisecond
		default:
			// Phase 3: near-stalled, ~60 seconds.
			interval = time.Duration(55000+rng.Intn(10000)) * time.Millisecond
		}

		select {
		case <-cr.done:
			return
		case <-time.After(interval):
		}

		now := time.Now().UTC().Format(time.RFC3339)

		// Pick message type.
		var msg string
		kind := rng.Intn(4)
		switch kind {
		case 0: // market update
			idx := rng.Intn(len(symbols))
			drift := (rng.Float64() - 0.5) * 0.04
			prices[idx] *= (1 + drift)
			change := prices[idx] - basePrices[idx]
			volume := rng.Intn(50000000) + 100000
			msg = fmt.Sprintf(`{"type":"market_update","data":{"symbol":"%s","price":%.2f,"change":%.2f,"volume":%d},"timestamp":"%s","seq":%d`,
				symbols[idx], prices[idx], change, volume, now, seq)

		case 1: // system metrics
			metric := metricNames[rng.Intn(len(metricNames))]
			value := rng.Float64() * 100
			msg = fmt.Sprintf(`{"type":"system_metrics","data":{"metric":"%s","value":%.2f,"host":"node-%d"},"timestamp":"%s","seq":%d`,
				metric, value, rng.Intn(8)+1, now, seq)

		case 2: // chat/notification
			user := chatUsers[rng.Intn(len(chatUsers))]
			text := chatMessages[rng.Intn(len(chatMessages))]
			msg = fmt.Sprintf(`{"type":"chat_message","data":{"user":"%s","message":"%s"},"timestamp":"%s","seq":%d`,
				user, text, now, seq)

		case 3: // notification
			msg = fmt.Sprintf(`{"type":"notification","data":{"title":"System Update","body":"Routine maintenance window scheduled","priority":"low"},"timestamp":"%s","seq":%d`,
				now, seq)
		}

		// Add phase-specific fields and close the JSON.
		switch {
		case elapsed < 30*time.Second:
			msg += `}`
		case elapsed < 120*time.Second:
			msg += `,"latency":"degraded"}`
		default:
			msg += `,"latency":"degraded","status":"reconnecting"}`
		}

		if !cr.send([]byte(msg)) {
			return
		}
	}
}
