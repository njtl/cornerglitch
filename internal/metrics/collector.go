package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// RequestRecord captures full detail of a single request for analysis.
type RequestRecord struct {
	Timestamp    time.Time
	ClientID     string
	Method       string
	Path         string
	StatusCode   int
	Latency      time.Duration
	ResponseType string // "ok", "error", "delayed", "labyrinth", "page", etc.
	UserAgent    string
	RemoteAddr   string
	Headers      map[string]string
	RequestBytes  int64
	ResponseBytes int64
}

// ClientProfile tracks aggregate behavior for a single fingerprinted client.
type ClientProfile struct {
	mu              sync.Mutex
	ClientID        string
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalRequests   int64
	RequestsPerSec  float64
	PathsVisited    map[string]int
	StatusCodes     map[int]int
	AvgLatency      time.Duration
	ErrorsReceived  int64
	LabyrinthDepth  int
	UserAgents      map[string]int
	RequestPattern  []time.Time // last N timestamps for rate analysis
	BurstWindows    int         // number of detected burst windows
	IsBot           bool
	BotConfidence   float64
	AdaptiveProfile string // current adaptive behavior profile assigned
}

// Collector is the central metrics aggregator.
type Collector struct {
	mu sync.RWMutex

	// Global counters
	TotalRequests  atomic.Int64
	TotalErrors    atomic.Int64
	Total2xx       atomic.Int64
	Total4xx       atomic.Int64
	Total5xx       atomic.Int64
	TotalDelayed   atomic.Int64
	TotalLabyrinth atomic.Int64
	ActiveConns    atomic.Int64

	// Traffic byte counters (total = accumulated across restarts, session = since startup)
	TotalRequestBytes    atomic.Int64
	TotalResponseBytes   atomic.Int64
	SessionRequestBytes  atomic.Int64
	SessionResponseBytes atomic.Int64

	// Per-client profiles
	clients map[string]*ClientProfile

	// Ring buffer of recent records for dashboard
	records    []RequestRecord
	recordIdx  int
	recordSize int

	// Time-series buckets (per-second counters for the last 5 min)
	buckets    []secondBucket
	bucketIdx  int
	bucketSize int

	startTime time.Time

	// Async recording
	recordCh chan RequestRecord
	stopCh   chan struct{}
	done     chan struct{}
}

type secondBucket struct {
	Timestamp time.Time
	Requests  int
	Errors    int
	AvgMs     float64
	totalMs   float64
}

// CounterSnapshot holds cumulative counter values for persistence.
type CounterSnapshot struct {
	TotalRequests       int64 `json:"total_requests"`
	TotalErrors         int64 `json:"total_errors"`
	Total2xx            int64 `json:"total_2xx"`
	Total4xx            int64 `json:"total_4xx"`
	Total5xx            int64 `json:"total_5xx"`
	TotalDelayed        int64 `json:"total_delayed"`
	TotalLabyrinth      int64 `json:"total_labyrinth"`
	TotalRequestBytes   int64 `json:"total_request_bytes"`
	TotalResponseBytes  int64 `json:"total_response_bytes"`
	SessionRequestBytes  int64 `json:"session_request_bytes"`
	SessionResponseBytes int64 `json:"session_response_bytes"`
}

// GetCounterSnapshot returns current cumulative counter values.
func (c *Collector) GetCounterSnapshot() CounterSnapshot {
	return CounterSnapshot{
		TotalRequests:        c.TotalRequests.Load(),
		TotalErrors:          c.TotalErrors.Load(),
		Total2xx:             c.Total2xx.Load(),
		Total4xx:             c.Total4xx.Load(),
		Total5xx:             c.Total5xx.Load(),
		TotalDelayed:         c.TotalDelayed.Load(),
		TotalLabyrinth:       c.TotalLabyrinth.Load(),
		TotalRequestBytes:    c.TotalRequestBytes.Load(),
		TotalResponseBytes:   c.TotalResponseBytes.Load(),
		SessionRequestBytes:  c.SessionRequestBytes.Load(),
		SessionResponseBytes: c.SessionResponseBytes.Load(),
	}
}

// RestoreCounters sets cumulative counters from a previously saved snapshot.
// This is used on startup to restore metrics from the database.
// Session byte counters are intentionally not restored — they reset to 0 each startup.
func (c *Collector) RestoreCounters(snap CounterSnapshot) {
	c.TotalRequests.Store(snap.TotalRequests)
	c.TotalErrors.Store(snap.TotalErrors)
	c.Total2xx.Store(snap.Total2xx)
	c.Total4xx.Store(snap.Total4xx)
	c.Total5xx.Store(snap.Total5xx)
	c.TotalDelayed.Store(snap.TotalDelayed)
	c.TotalLabyrinth.Store(snap.TotalLabyrinth)
	c.TotalRequestBytes.Store(snap.TotalRequestBytes)
	c.TotalResponseBytes.Store(snap.TotalResponseBytes)
}

func NewCollector() *Collector {
	c := &Collector{
		clients:    make(map[string]*ClientProfile),
		recordSize: 10000,
		records:    make([]RequestRecord, 10000),
		bucketSize: 300, // 5 minutes of per-second data
		buckets:    make([]secondBucket, 300),
		startTime:  time.Now(),
		recordCh:   make(chan RequestRecord, 4096),
		stopCh:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	go c.bucketTicker()
	go c.recordWorker()
	return c
}

func (c *Collector) bucketTicker() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.bucketIdx = (c.bucketIdx + 1) % c.bucketSize
			c.buckets[c.bucketIdx] = secondBucket{Timestamp: time.Now()}
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

// Record updates atomic counters immediately and queues the record
// for async processing of ring buffer, buckets, and client profiles.
func (c *Collector) Record(r RequestRecord) {
	// Atomic counter updates — immediate visibility, no locks
	c.TotalRequests.Add(1)

	switch {
	case r.StatusCode >= 500:
		c.TotalErrors.Add(1)
		c.Total5xx.Add(1)
	case r.StatusCode >= 400:
		c.Total4xx.Add(1)
	default:
		c.Total2xx.Add(1)
	}

	if r.ResponseType == "delayed" {
		c.TotalDelayed.Add(1)
	}
	if r.ResponseType == "labyrinth" {
		c.TotalLabyrinth.Add(1)
	}

	// Byte counters — both total (persisted across restarts) and session (since startup)
	if r.RequestBytes > 0 {
		c.TotalRequestBytes.Add(r.RequestBytes)
		c.SessionRequestBytes.Add(r.RequestBytes)
	}
	if r.ResponseBytes > 0 {
		c.TotalResponseBytes.Add(r.ResponseBytes)
		c.SessionResponseBytes.Add(r.ResponseBytes)
	}

	// Non-blocking send to background worker
	select {
	case c.recordCh <- r:
	default:
		// Channel full, drop record (metrics are best-effort)
	}
}

// recordWorker processes queued records in a single goroutine,
// eliminating write lock contention from concurrent Record() calls.
func (c *Collector) recordWorker() {
	for {
		select {
		case r := <-c.recordCh:
			c.processRecord(r)
		case <-c.stopCh:
			// Drain remaining records before exiting
			for {
				select {
				case r := <-c.recordCh:
					c.processRecord(r)
				default:
					close(c.done)
					return
				}
			}
		}
	}
}

// processRecord handles the mutex-protected work: ring buffer, buckets, client profiles.
func (c *Collector) processRecord(r RequestRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Store record in ring buffer
	c.records[c.recordIdx] = r
	c.recordIdx = (c.recordIdx + 1) % c.recordSize

	// Update per-second bucket
	bucket := &c.buckets[c.bucketIdx]
	bucket.Requests++
	bucket.totalMs += float64(r.Latency.Milliseconds())
	if bucket.Requests > 0 {
		bucket.AvgMs = bucket.totalMs / float64(bucket.Requests)
	}
	if r.StatusCode >= 400 {
		bucket.Errors++
	}

	// Update client profile
	cp, ok := c.clients[r.ClientID]
	if !ok {
		cp = &ClientProfile{
			ClientID:     r.ClientID,
			FirstSeen:    r.Timestamp,
			PathsVisited: make(map[string]int),
			StatusCodes:  make(map[int]int),
			UserAgents:   make(map[string]int),
		}
		c.clients[r.ClientID] = cp
	}
	cp.mu.Lock()
	cp.LastSeen = r.Timestamp
	cp.TotalRequests++
	cp.PathsVisited[r.Path]++
	cp.StatusCodes[r.StatusCode]++
	cp.UserAgents[r.UserAgent]++
	if r.StatusCode >= 400 {
		cp.ErrorsReceived++
	}

	// Keep last 200 timestamps for rate analysis
	cp.RequestPattern = append(cp.RequestPattern, r.Timestamp)
	if len(cp.RequestPattern) > 200 {
		cp.RequestPattern = cp.RequestPattern[len(cp.RequestPattern)-200:]
	}

	// Calculate requests per second over last 10s
	cutoff := r.Timestamp.Add(-10 * time.Second)
	count := 0
	for i := len(cp.RequestPattern) - 1; i >= 0; i-- {
		if cp.RequestPattern[i].Before(cutoff) {
			break
		}
		count++
	}
	cp.RequestsPerSec = float64(count) / 10.0

	// Detect bursts (>50 req/s)
	if cp.RequestsPerSec > 50 {
		cp.BurstWindows++
	}

	cp.mu.Unlock()
}

// Stop gracefully shuts down the record worker, draining any pending records.
func (c *Collector) Stop() {
	close(c.stopCh)
	<-c.done
}

// GetClientProfile returns a copy of the profile for a client.
func (c *Collector) GetClientProfile(clientID string) *ClientProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if cp, ok := c.clients[clientID]; ok {
		return cp
	}
	return nil
}

// GetAllClientProfiles returns all tracked client profiles.
func (c *Collector) GetAllClientProfiles() []*ClientProfile {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*ClientProfile, 0, len(c.clients))
	for _, cp := range c.clients {
		result = append(result, cp)
	}
	return result
}

// RecentRecords returns the last n records.
func (c *Collector) RecentRecords(n int) []RequestRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if n > c.recordSize {
		n = c.recordSize
	}
	result := make([]RequestRecord, 0, n)
	idx := (c.recordIdx - 1 + c.recordSize) % c.recordSize
	for i := 0; i < n; i++ {
		r := c.records[idx]
		if r.Timestamp.IsZero() {
			break
		}
		result = append(result, r)
		idx = (idx - 1 + c.recordSize) % c.recordSize
	}
	return result
}

// TimeSeries returns per-second metrics for the last n seconds.
func (c *Collector) TimeSeries(n int) []secondBucket {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if n > c.bucketSize {
		n = c.bucketSize
	}
	result := make([]secondBucket, 0, n)
	idx := c.bucketIdx
	for i := 0; i < n; i++ {
		b := c.buckets[idx]
		if !b.Timestamp.IsZero() {
			result = append(result, b)
		}
		idx = (idx - 1 + c.bucketSize) % c.bucketSize
	}
	return result
}

// GetPathsInTimeWindow returns a map of paths and their request counts
// for requests that occurred within the given time window [start, end].
func (c *Collector) GetPathsInTimeWindow(start, end time.Time) map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	paths := make(map[string]int)
	for _, rec := range c.records {
		if rec.Timestamp.IsZero() {
			continue
		}
		if !rec.Timestamp.Before(start) && !rec.Timestamp.After(end) {
			paths[rec.Path]++
		}
	}
	return paths
}

// CurrentRPS returns the real-time requests per second averaged over the last 5 buckets.
func (c *Collector) CurrentRPS() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sum int
	var count int
	idx := c.bucketIdx
	for i := 0; i < 5; i++ {
		b := c.buckets[idx]
		if !b.Timestamp.IsZero() {
			sum += b.Requests
			count++
		}
		idx = (idx - 1 + c.bucketSize) % c.bucketSize
	}
	if count == 0 {
		return 0
	}
	return float64(sum) / float64(count)
}

// Uptime returns server uptime.
func (c *Collector) Uptime() time.Duration {
	return time.Since(c.startTime)
}

// SecondBucket is exported read-only access to bucket data for the dashboard.
type SecondBucket = secondBucket

// ClientProfileSnapshot is a thread-safe copy of a ClientProfile.
type ClientProfileSnapshot struct {
	ClientID        string
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalRequests   int64
	RequestsPerSec  float64
	PathsVisited    map[string]int
	StatusCodes     map[int]int
	ErrorsReceived  int64
	LabyrinthDepth  int
	UserAgents      map[string]int
	BurstWindows    int
	AdaptiveProfile string
}

// SetAdaptiveProfile updates the adaptive profile string under the profile's mutex.
func (cp *ClientProfile) SetAdaptiveProfile(profile string) {
	cp.mu.Lock()
	cp.AdaptiveProfile = profile
	cp.mu.Unlock()
}

// Snapshot returns a thread-safe copy of the client profile.
func (cp *ClientProfile) Snapshot() ClientProfileSnapshot {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	paths := make(map[string]int, len(cp.PathsVisited))
	for k, v := range cp.PathsVisited {
		paths[k] = v
	}
	codes := make(map[int]int, len(cp.StatusCodes))
	for k, v := range cp.StatusCodes {
		codes[k] = v
	}
	agents := make(map[string]int, len(cp.UserAgents))
	for k, v := range cp.UserAgents {
		agents[k] = v
	}

	return ClientProfileSnapshot{
		ClientID:        cp.ClientID,
		FirstSeen:       cp.FirstSeen,
		LastSeen:        cp.LastSeen,
		TotalRequests:   cp.TotalRequests,
		RequestsPerSec:  cp.RequestsPerSec,
		PathsVisited:    paths,
		StatusCodes:     codes,
		ErrorsReceived:  cp.ErrorsReceived,
		LabyrinthDepth:  cp.LabyrinthDepth,
		UserAgents:      agents,
		BurstWindows:    cp.BurstWindows,
		AdaptiveProfile: cp.AdaptiveProfile,
	}
}

// RestoreClientProfile adds a client profile from persisted data.
// Used during startup to reload client state from the database.
func (c *Collector) RestoreClientProfile(snap ClientProfileSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()

	paths := snap.PathsVisited
	if paths == nil {
		paths = make(map[string]int)
	}
	codes := snap.StatusCodes
	if codes == nil {
		codes = make(map[int]int)
	}
	agents := snap.UserAgents
	if agents == nil {
		agents = make(map[string]int)
	}

	c.clients[snap.ClientID] = &ClientProfile{
		ClientID:        snap.ClientID,
		FirstSeen:       snap.FirstSeen,
		LastSeen:        snap.LastSeen,
		TotalRequests:   snap.TotalRequests,
		RequestsPerSec:  snap.RequestsPerSec,
		PathsVisited:    paths,
		StatusCodes:     codes,
		ErrorsReceived:  snap.ErrorsReceived,
		LabyrinthDepth:  snap.LabyrinthDepth,
		UserAgents:      agents,
		BurstWindows:    snap.BurstWindows,
		AdaptiveProfile: snap.AdaptiveProfile,
	}
}
