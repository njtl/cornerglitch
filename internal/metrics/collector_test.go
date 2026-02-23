package metrics

import (
	"fmt"
	"testing"
	"time"
)

func TestRecord_StoresEntry(t *testing.T) {
	c := NewCollector()
	rec := RequestRecord{
		Timestamp:    time.Now(),
		ClientID:     "client_abc",
		Method:       "GET",
		Path:         "/test",
		StatusCode:   200,
		Latency:      50 * time.Millisecond,
		ResponseType: "ok",
	}
	c.Record(rec)
	if c.TotalRequests.Load() != 1 {
		t.Fatalf("expected 1 total request, got %d", c.TotalRequests.Load())
	}
	recent := c.RecentRecords(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent record, got %d", len(recent))
	}
	if recent[0].Path != "/test" {
		t.Fatalf("expected path /test, got %s", recent[0].Path)
	}
}

func TestRecent_ReturnsMostRecent(t *testing.T) {
	c := NewCollector()
	for i := 0; i < 5; i++ {
		c.Record(RequestRecord{
			Timestamp:  time.Now().Add(time.Duration(i) * time.Second),
			ClientID:   "client_1",
			Path:       fmt.Sprintf("/path-%d", i),
			StatusCode: 200,
		})
	}
	recent := c.RecentRecords(3)
	if len(recent) != 3 {
		t.Fatalf("expected 3 records, got %d", len(recent))
	}
	// Most recent should come first
	if recent[0].Path != "/path-4" {
		t.Fatalf("expected most recent path /path-4, got %s", recent[0].Path)
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	c := NewCollector()
	// Fill beyond the 10k ring buffer
	for i := 0; i < 10050; i++ {
		c.Record(RequestRecord{
			Timestamp:  time.Now(),
			ClientID:   "client_1",
			Path:       fmt.Sprintf("/path-%d", i),
			StatusCode: 200,
		})
	}
	if c.TotalRequests.Load() != 10050 {
		t.Fatalf("expected 10050 total requests, got %d", c.TotalRequests.Load())
	}
	// RecentRecords should return at most recordSize entries
	recent := c.RecentRecords(20000)
	if len(recent) > 10000 {
		t.Fatalf("ring buffer should cap at 10000 records, got %d", len(recent))
	}
}

func TestTimeSeries(t *testing.T) {
	c := NewCollector()

	// Wait for the bucket ticker to fire at least once so the current
	// bucket gets a non-zero Timestamp (the ticker sets Timestamp on advance).
	time.Sleep(1100 * time.Millisecond)

	c.Record(RequestRecord{
		Timestamp:  time.Now(),
		ClientID:   "client_1",
		Path:       "/ts",
		StatusCode: 200,
		Latency:    10 * time.Millisecond,
	})

	ts := c.TimeSeries(10)
	// After the ticker has fired and we recorded a request, there should be
	// at least one bucket with a non-zero Timestamp.
	if len(ts) == 0 {
		t.Fatal("expected at least one time series bucket")
	}
}

func TestClientProfile(t *testing.T) {
	c := NewCollector()
	now := time.Now()
	for i := 0; i < 3; i++ {
		c.Record(RequestRecord{
			Timestamp:  now.Add(time.Duration(i) * time.Millisecond),
			ClientID:   "client_xyz",
			Method:     "GET",
			Path:       fmt.Sprintf("/p%d", i),
			StatusCode: 200,
			UserAgent:  "TestAgent/1.0",
		})
	}
	cp := c.GetClientProfile("client_xyz")
	if cp == nil {
		t.Fatal("expected client profile to exist")
	}
	if cp.TotalRequests != 3 {
		t.Fatalf("expected 3 total requests, got %d", cp.TotalRequests)
	}
	if len(cp.PathsVisited) != 3 {
		t.Fatalf("expected 3 unique paths, got %d", len(cp.PathsVisited))
	}
	if cp.UserAgents["TestAgent/1.0"] != 3 {
		t.Fatalf("expected UA count 3, got %d", cp.UserAgents["TestAgent/1.0"])
	}
	// Verify nil for unknown client
	if c.GetClientProfile("nonexistent") != nil {
		t.Fatal("expected nil for unknown client")
	}
}
