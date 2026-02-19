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
	TotalRequests   atomic.Int64
	TotalErrors     atomic.Int64
	Total2xx        atomic.Int64
	Total4xx        atomic.Int64
	Total5xx        atomic.Int64
	TotalDelayed    atomic.Int64
	TotalLabyrinth  atomic.Int64
	ActiveConns     atomic.Int64

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
}

type secondBucket struct {
	Timestamp time.Time
	Requests  int
	Errors    int
	AvgMs     float64
	totalMs   float64
}

func NewCollector() *Collector {
	c := &Collector{
		clients:    make(map[string]*ClientProfile),
		recordSize: 10000,
		records:    make([]RequestRecord, 10000),
		bucketSize: 300, // 5 minutes of per-second data
		buckets:    make([]secondBucket, 300),
		startTime:  time.Now(),
	}
	go c.bucketTicker()
	return c
}

func (c *Collector) bucketTicker() {
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		c.mu.Lock()
		c.bucketIdx = (c.bucketIdx + 1) % c.bucketSize
		c.buckets[c.bucketIdx] = secondBucket{Timestamp: time.Now()}
		c.mu.Unlock()
	}
}

// Record stores a request record and updates all aggregate metrics.
func (c *Collector) Record(r RequestRecord) {
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
