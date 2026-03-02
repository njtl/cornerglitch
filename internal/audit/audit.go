package audit

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuditStore defines the interface for persisting audit entries.
// Implemented by internal/storage.Store (methods added in task #2).
type AuditStore interface {
	SaveAuditBatch(entries []Entry) error
	// LoadRecentAuditEntries returns up to `limit` most recent entries
	// in chronological order (oldest first) for pre-populating the ring buffer.
	LoadRecentAuditEntries(limit int) ([]Entry, error)
}

// Entry represents a single audit log event.
type Entry struct {
	ID        int64                  `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Actor     string                 `json:"actor"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	OldValue  interface{}            `json:"old_value,omitempty"`
	NewValue  interface{}            `json:"new_value,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	ClientIP  string                 `json:"client_ip,omitempty"`
	Status    string                 `json:"status"`
}

// QueryOpts configures a query against the audit log.
type QueryOpts struct {
	Limit    int
	Offset   int
	Actor    string
	Action   string
	Resource string
	Status   string
	From     *time.Time
	To       *time.Time
}

// QueryResult is returned by Query.
type QueryResult struct {
	Entries []Entry    `json:"entries"`
	Total   int        `json:"total"`
	Filters FilterInfo `json:"filters"`
}

// FilterInfo contains distinct values for building filter dropdowns.
type FilterInfo struct {
	Actors   []string `json:"actors"`
	Actions  []string `json:"actions"`
	Statuses []string `json:"statuses"`
}

const (
	maxEntries = 1000
	batchSize  = 50
	batchDelay = 100 * time.Millisecond
	chanSize   = 1000
)

// Logger is the audit log engine with an in-memory ring buffer
// and optional async DB persistence.
type Logger struct {
	mu        sync.RWMutex
	entries   []Entry
	idCounter atomic.Int64
	dbChan    chan *Entry
	store     AuditStore
	done      chan struct{}
	wg        sync.WaitGroup
}

var (
	globalLogger *Logger
	globalMu     sync.Mutex
)

// Init initializes the global audit logger with an optional DB store.
// If store is nil, entries are kept in-memory only.
// When a store is provided, recent entries are loaded from DB to pre-populate
// the in-memory ring buffer so audit history survives server restarts.
func Init(store AuditStore) {
	globalMu.Lock()
	defer globalMu.Unlock()

	if globalLogger != nil {
		globalLogger.Close()
	}

	l := &Logger{
		entries: make([]Entry, 0, maxEntries),
		dbChan:  make(chan *Entry, chanSize),
		store:   store,
		done:    make(chan struct{}),
	}

	// Pre-populate ring buffer from DB if available.
	if store != nil {
		if loaded, err := store.LoadRecentAuditEntries(maxEntries); err == nil && len(loaded) > 0 {
			l.entries = loaded
			// Set ID counter past the highest loaded ID so new entries don't collide.
			var maxID int64
			for i := range loaded {
				if loaded[i].ID > maxID {
					maxID = loaded[i].ID
				}
			}
			l.idCounter.Store(maxID)
		}
	}

	l.wg.Add(1)
	go l.dbWriter()

	globalLogger = l
}

// GetLogger returns the global audit logger.
// Returns nil if Init has not been called.
func GetLogger() *Logger {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalLogger
}

// Log records a state change with old and new values.
func Log(actor, action, resource string, oldVal, newVal interface{}, details map[string]interface{}) {
	l := GetLogger()
	if l == nil {
		return
	}
	l.log(actor, action, resource, oldVal, newVal, details)
}

// LogAction records an action without old/new values.
func LogAction(actor, action, resource string, details map[string]interface{}) {
	Log(actor, action, resource, nil, nil, details)
}

// LogSystem records a system action (actor="system").
func LogSystem(action, resource string, details map[string]interface{}) {
	Log("system", action, resource, nil, nil, details)
}

// log creates an Entry, appends to ring buffer, and sends to dbChan.
func (l *Logger) log(actor, action, resource string, oldVal, newVal interface{}, details map[string]interface{}) {
	e := Entry{
		ID:        l.idCounter.Add(1),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		OldValue:  oldVal,
		NewValue:  newVal,
		Details:   details,
		Status:    "success",
	}

	l.mu.Lock()
	if len(l.entries) >= maxEntries {
		// Drop oldest entry (ring buffer behavior)
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, e)
	l.mu.Unlock()

	// Non-blocking send to DB channel
	select {
	case l.dbChan <- &e:
	default:
		// Channel full — drop the DB write to avoid blocking
	}
}

// LogEntry records a pre-built entry (for callers that need to set Status or ClientIP).
func LogEntry(e Entry) {
	l := GetLogger()
	if l == nil {
		return
	}
	e.ID = l.idCounter.Add(1)
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	if e.Status == "" {
		e.Status = "success"
	}

	l.mu.Lock()
	if len(l.entries) >= maxEntries {
		l.entries = l.entries[1:]
	}
	l.entries = append(l.entries, e)
	l.mu.Unlock()

	select {
	case l.dbChan <- &e:
	default:
	}
}

// Query returns entries matching the given options from the in-memory ring buffer.
func Query(opts QueryOpts) QueryResult {
	l := GetLogger()
	if l == nil {
		return QueryResult{}
	}
	return l.query(opts)
}

func (l *Logger) query(opts QueryOpts) QueryResult {
	if opts.Limit <= 0 {
		opts.Limit = 50
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}

	l.mu.RLock()
	// Snapshot entries in reverse chronological order
	all := make([]Entry, len(l.entries))
	copy(all, l.entries)
	l.mu.RUnlock()

	// Reverse for newest-first
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}

	// Collect distinct values for filters (from all entries, before filtering)
	actorSet := make(map[string]bool)
	actionSet := make(map[string]bool)
	statusSet := make(map[string]bool)
	for i := range all {
		actorSet[all[i].Actor] = true
		actionSet[all[i].Action] = true
		statusSet[all[i].Status] = true
	}

	// Apply filters
	var filtered []Entry
	for i := range all {
		e := &all[i]
		if opts.Actor != "" && e.Actor != opts.Actor {
			continue
		}
		if opts.Action != "" && !strings.HasPrefix(e.Action, opts.Action) {
			continue
		}
		if opts.Resource != "" && !strings.Contains(e.Resource, opts.Resource) {
			continue
		}
		if opts.Status != "" && e.Status != opts.Status {
			continue
		}
		if opts.From != nil && e.Timestamp.Before(*opts.From) {
			continue
		}
		if opts.To != nil && e.Timestamp.After(*opts.To) {
			continue
		}
		filtered = append(filtered, *e)
	}

	total := len(filtered)

	// Apply pagination
	start := opts.Offset
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + opts.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[start:end]

	return QueryResult{
		Entries: page,
		Total:   total,
		Filters: FilterInfo{
			Actors:   setToSlice(actorSet),
			Actions:  setToSlice(actionSet),
			Statuses: setToSlice(statusSet),
		},
	}
}

// Close gracefully shuts down the audit logger, flushing pending DB writes.
func (l *Logger) Close() {
	close(l.done)
	l.wg.Wait()
}

// dbWriter drains the dbChan in batches and writes to the store.
func (l *Logger) dbWriter() {
	defer l.wg.Done()

	batch := make([]Entry, 0, batchSize)
	timer := time.NewTimer(batchDelay)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if l.store != nil {
			// Best-effort write; log errors but don't block
			_ = l.store.SaveAuditBatch(batch)
		}
		batch = batch[:0]
	}

	for {
		select {
		case entry, ok := <-l.dbChan:
			if !ok {
				flush()
				return
			}
			batch = append(batch, *entry)
			if len(batch) >= batchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(batchDelay)
			}
		case <-timer.C:
			flush()
			timer.Reset(batchDelay)
		case <-l.done:
			// Drain remaining entries from channel
			for {
				select {
				case entry, ok := <-l.dbChan:
					if !ok {
						flush()
						return
					}
					batch = append(batch, *entry)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func setToSlice(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	return s
}
