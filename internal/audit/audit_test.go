package audit

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// mockStore implements AuditStore for testing.
type mockStore struct {
	mu      sync.Mutex
	batches [][]Entry
}

func (m *mockStore) SaveAuditBatch(entries []Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Entry, len(entries))
	copy(cp, entries)
	m.batches = append(m.batches, cp)
	return nil
}

func (m *mockStore) LoadRecentAuditEntries(limit int) ([]Entry, error) {
	return nil, nil // mock returns empty — no pre-populated entries
}

func (m *mockStore) allEntries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Entry
	for _, b := range m.batches {
		all = append(all, b...)
	}
	return all
}

// resetGlobal tears down any existing global logger and resets state.
func resetGlobal() {
	globalMu.Lock()
	if globalLogger != nil {
		globalLogger.Close()
		globalLogger = nil
	}
	globalMu.Unlock()
}

func TestRingBuffer_Basic(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "test.action", "resource.a", nil, nil, nil)
	Log("admin", "test.action", "resource.b", nil, nil, nil)
	Log("admin", "test.action", "resource.c", nil, nil, nil)

	result := Query(QueryOpts{Limit: 10})
	if result.Total != 3 {
		t.Fatalf("expected 3 entries, got %d", result.Total)
	}
	// Newest first
	if result.Entries[0].Resource != "resource.c" {
		t.Errorf("expected newest entry first, got %s", result.Entries[0].Resource)
	}
	if result.Entries[2].Resource != "resource.a" {
		t.Errorf("expected oldest entry last, got %s", result.Entries[2].Resource)
	}
}

func TestRingBuffer_Overflow(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	// Fill beyond maxEntries
	for i := 0; i < maxEntries+100; i++ {
		Log("admin", "test.overflow", "resource", nil, nil, nil)
	}

	result := Query(QueryOpts{Limit: maxEntries + 1})
	if result.Total != maxEntries {
		t.Fatalf("expected %d entries after overflow, got %d", maxEntries, result.Total)
	}
}

func TestLog_FieldsPopulated(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	details := map[string]interface{}{"key": "value"}
	Log("admin", "config.change", "admin_config.error_rate", 1.0, 2.5, details)

	result := Query(QueryOpts{Limit: 1})
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	e := result.Entries[0]

	if e.Actor != "admin" {
		t.Errorf("actor = %q, want %q", e.Actor, "admin")
	}
	if e.Action != "config.change" {
		t.Errorf("action = %q, want %q", e.Action, "config.change")
	}
	if e.Resource != "admin_config.error_rate" {
		t.Errorf("resource = %q, want %q", e.Resource, "admin_config.error_rate")
	}
	if e.Status != "success" {
		t.Errorf("status = %q, want %q", e.Status, "success")
	}
	if e.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if e.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if e.OldValue != 1.0 {
		t.Errorf("old_value = %v, want 1.0", e.OldValue)
	}
	if e.NewValue != 2.5 {
		t.Errorf("new_value = %v, want 2.5", e.NewValue)
	}
	if e.Details["key"] != "value" {
		t.Errorf("details[key] = %v, want %q", e.Details["key"], "value")
	}
}

func TestLogAction_NoOldNewValues(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	LogAction("admin", "config.export", "config.export", nil)

	result := Query(QueryOpts{Limit: 1})
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	e := result.Entries[0]
	if e.OldValue != nil {
		t.Errorf("expected nil OldValue, got %v", e.OldValue)
	}
	if e.NewValue != nil {
		t.Errorf("expected nil NewValue, got %v", e.NewValue)
	}
}

func TestLogSystem_ActorIsSystem(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	LogSystem("system.start", "system.lifecycle", map[string]interface{}{"port": 8765})

	result := Query(QueryOpts{Limit: 1})
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Actor != "system" {
		t.Errorf("actor = %q, want %q", result.Entries[0].Actor, "system")
	}
}

func TestLogEntry_CustomStatus(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	LogEntry(Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		ClientIP: "192.168.1.100",
		Status:   "error",
	})

	result := Query(QueryOpts{Limit: 1})
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	e := result.Entries[0]
	if e.Status != "error" {
		t.Errorf("status = %q, want %q", e.Status, "error")
	}
	if e.ClientIP != "192.168.1.100" {
		t.Errorf("client_ip = %q, want %q", e.ClientIP, "192.168.1.100")
	}
}

func TestQuery_FilterByActor(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "feature.toggle", "feature_flags.labyrinth", true, false, nil)
	LogSystem("system.start", "system.lifecycle", nil)
	Log("admin", "config.change", "admin_config.error_rate", 1.0, 2.0, nil)

	result := Query(QueryOpts{Actor: "admin", Limit: 10})
	if result.Total != 2 {
		t.Fatalf("expected 2 entries for actor=admin, got %d", result.Total)
	}
	for _, e := range result.Entries {
		if e.Actor != "admin" {
			t.Errorf("expected actor=admin, got %q", e.Actor)
		}
	}

	result = Query(QueryOpts{Actor: "system", Limit: 10})
	if result.Total != 1 {
		t.Fatalf("expected 1 entry for actor=system, got %d", result.Total)
	}
}

func TestQuery_FilterByAction_PrefixMatch(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "config.change", "admin_config.x", nil, nil, nil)
	Log("admin", "config.import", "config.import", nil, nil, nil)
	Log("admin", "feature.toggle", "feature_flags.y", nil, nil, nil)

	// Prefix match: "config" should match "config.change" and "config.import"
	result := Query(QueryOpts{Action: "config", Limit: 10})
	if result.Total != 2 {
		t.Fatalf("expected 2 entries for action prefix 'config', got %d", result.Total)
	}
}

func TestQuery_FilterByResource_SubstringMatch(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "feature.toggle", "feature_flags.labyrinth", nil, nil, nil)
	Log("admin", "feature.toggle", "feature_flags.captcha", nil, nil, nil)
	Log("admin", "config.change", "admin_config.error_rate", nil, nil, nil)

	result := Query(QueryOpts{Resource: "feature_flags", Limit: 10})
	if result.Total != 2 {
		t.Fatalf("expected 2 entries for resource containing 'feature_flags', got %d", result.Total)
	}
}

func TestQuery_FilterByStatus(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "config.change", "admin_config.x", nil, nil, nil) // success by default
	LogEntry(Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		Status:   "error",
	})

	result := Query(QueryOpts{Status: "error", Limit: 10})
	if result.Total != 1 {
		t.Fatalf("expected 1 entry for status=error, got %d", result.Total)
	}
}

func TestQuery_FilterByTimeRange(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "old.action", "resource", nil, nil, nil)
	time.Sleep(10 * time.Millisecond)

	cutoff := time.Now()
	time.Sleep(10 * time.Millisecond)

	Log("admin", "new.action", "resource", nil, nil, nil)

	result := Query(QueryOpts{From: &cutoff, Limit: 10})
	if result.Total != 1 {
		t.Fatalf("expected 1 entry after cutoff, got %d", result.Total)
	}
	if result.Entries[0].Action != "new.action" {
		t.Errorf("expected new.action, got %q", result.Entries[0].Action)
	}
}

func TestQuery_Pagination(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	for i := 0; i < 10; i++ {
		Log("admin", "test.action", "resource", nil, nil, nil)
	}

	// Page 1: limit=3, offset=0
	r1 := Query(QueryOpts{Limit: 3, Offset: 0})
	if r1.Total != 10 {
		t.Fatalf("expected total=10, got %d", r1.Total)
	}
	if len(r1.Entries) != 3 {
		t.Fatalf("expected 3 entries on page 1, got %d", len(r1.Entries))
	}

	// Page 2: limit=3, offset=3
	r2 := Query(QueryOpts{Limit: 3, Offset: 3})
	if len(r2.Entries) != 3 {
		t.Fatalf("expected 3 entries on page 2, got %d", len(r2.Entries))
	}

	// Different entries on different pages
	if r1.Entries[0].ID == r2.Entries[0].ID {
		t.Error("pages should contain different entries")
	}

	// Past end: offset=9, limit=5
	r3 := Query(QueryOpts{Limit: 5, Offset: 9})
	if len(r3.Entries) != 1 {
		t.Fatalf("expected 1 entry at offset 9, got %d", len(r3.Entries))
	}
}

func TestQuery_LimitClamped(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "test.action", "resource", nil, nil, nil)

	// Limit 0 should default to 50
	r := Query(QueryOpts{Limit: 0})
	if r.Total != 1 {
		t.Fatalf("expected total=1, got %d", r.Total)
	}

	// Limit > 200 should clamp to 200
	r = Query(QueryOpts{Limit: 500})
	if r.Total != 1 {
		t.Fatalf("expected total=1, got %d", r.Total)
	}
}

func TestQuery_FilterInfo(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	Log("admin", "config.change", "admin_config.x", nil, nil, nil)
	LogSystem("system.start", "system.lifecycle", nil)
	LogEntry(Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		Status:   "error",
	})

	result := Query(QueryOpts{Limit: 10})
	if len(result.Filters.Actors) < 2 {
		t.Errorf("expected at least 2 distinct actors, got %d", len(result.Filters.Actors))
	}
	if len(result.Filters.Actions) < 2 {
		t.Errorf("expected at least 2 distinct actions, got %d", len(result.Filters.Actions))
	}
	if len(result.Filters.Statuses) < 2 {
		t.Errorf("expected at least 2 distinct statuses, got %d", len(result.Filters.Statuses))
	}
}

func TestConcurrentWrites(t *testing.T) {
	resetGlobal()
	Init(nil)
	defer resetGlobal()

	var wg sync.WaitGroup
	n := 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			Log("admin", "concurrent.test", "resource", idx, idx+1, nil)
		}(i)
	}
	wg.Wait()

	result := Query(QueryOpts{Limit: maxEntries})
	if result.Total != n {
		t.Fatalf("expected %d entries after concurrent writes, got %d", n, result.Total)
	}
}

func TestEntry_JSONRoundTrip(t *testing.T) {
	e := Entry{
		ID:        42,
		Timestamp: time.Now().Truncate(time.Second),
		Actor:     "admin",
		Action:    "config.change",
		Resource:  "admin_config.error_rate",
		OldValue:  1.0,
		NewValue:  2.5,
		Details:   map[string]interface{}{"key": "value"},
		ClientIP:  "10.0.0.1",
		Status:    "success",
	}

	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Entry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != e.ID {
		t.Errorf("ID = %d, want %d", decoded.ID, e.ID)
	}
	if decoded.Actor != e.Actor {
		t.Errorf("actor = %q, want %q", decoded.Actor, e.Actor)
	}
	if decoded.Action != e.Action {
		t.Errorf("action = %q, want %q", decoded.Action, e.Action)
	}
	if decoded.Resource != e.Resource {
		t.Errorf("resource = %q, want %q", decoded.Resource, e.Resource)
	}
	if decoded.Status != e.Status {
		t.Errorf("status = %q, want %q", decoded.Status, e.Status)
	}
	if decoded.ClientIP != e.ClientIP {
		t.Errorf("client_ip = %q, want %q", decoded.ClientIP, e.ClientIP)
	}
}

func TestDBWriter_BatchFlush(t *testing.T) {
	resetGlobal()
	store := &mockStore{}
	Init(store)
	defer resetGlobal()

	// Write enough entries to trigger a batch flush
	for i := 0; i < batchSize+10; i++ {
		Log("admin", "batch.test", "resource", nil, nil, nil)
	}

	// Allow time for async flush
	time.Sleep(200 * time.Millisecond)

	entries := store.allEntries()
	if len(entries) < batchSize {
		t.Fatalf("expected at least %d entries flushed to store, got %d", batchSize, len(entries))
	}
}

func TestDBWriter_TimerFlush(t *testing.T) {
	resetGlobal()
	store := &mockStore{}
	Init(store)
	defer resetGlobal()

	// Write fewer entries than batchSize — should flush on timer
	Log("admin", "timer.test", "resource", nil, nil, nil)

	// Wait for timer flush (batchDelay + buffer)
	time.Sleep(batchDelay + 100*time.Millisecond)

	entries := store.allEntries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry flushed on timer, got %d", len(entries))
	}
}

func TestNilLogger_NoOp(t *testing.T) {
	resetGlobal()
	// Don't call Init — globalLogger should be nil

	// These should not panic
	Log("admin", "test", "resource", nil, nil, nil)
	LogAction("admin", "test", "resource", nil)
	LogSystem("test", "resource", nil)
	LogEntry(Entry{Action: "test"})

	result := Query(QueryOpts{Limit: 10})
	if result.Total != 0 {
		t.Errorf("expected 0 entries with nil logger, got %d", result.Total)
	}
}
