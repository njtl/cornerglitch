package content

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// CacheEntry stores a cached page.
type CacheEntry struct {
	Key       string
	Body      []byte
	Headers   map[string]string
	Status    int
	CreatedAt time.Time
}

// CacheStats reports cache usage counters.
type CacheStats struct {
	Size      int
	MaxSize   int
	Hits      int64
	Misses    int64
	Evictions int64
}

// Cache is a thread-safe LRU cache with TTL.
type Cache struct {
	mu        sync.RWMutex
	entries   map[string]*list.Element
	order     *list.List
	maxSize   int
	ttl       time.Duration
	hits      atomic.Int64
	misses    atomic.Int64
	evictions atomic.Int64
	done      chan struct{}
}

// NewCache creates a new LRU cache with the given maximum size and TTL.
// It starts a background goroutine that purges expired entries every 5 minutes.
// Call Stop() to terminate the cleanup goroutine when the cache is no longer needed.
func NewCache(maxSize int, ttl time.Duration) *Cache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	c := &Cache{
		entries: make(map[string]*list.Element),
		order:   list.New(),
		maxSize: maxSize,
		ttl:     ttl,
		done:    make(chan struct{}),
	}

	go c.cleanupLoop()
	return c
}

// Get returns a cached entry if it exists and has not expired.
// On a hit the entry is promoted to the front of the LRU list.
// Returns nil, false when the key is missing or expired.
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	elem, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()
		c.misses.Add(1)
		return nil, false
	}
	entry := elem.Value.(*CacheEntry)
	if time.Since(entry.CreatedAt) > c.ttl {
		c.mu.RUnlock()
		// Expired — remove under write lock.
		c.Delete(key)
		c.misses.Add(1)
		return nil, false
	}
	c.mu.RUnlock()

	// Promote to front under write lock.
	c.mu.Lock()
	// Re-check presence; another goroutine may have deleted it.
	if elem, ok := c.entries[key]; ok {
		c.order.MoveToFront(elem)
	}
	c.mu.Unlock()

	c.hits.Add(1)
	return entry, true
}

// Set adds or replaces an entry in the cache. CreatedAt is set to time.Now().
// If the cache is at capacity the least recently used entry is evicted first.
func (c *Cache) Set(key string, entry *CacheEntry) {
	entry.Key = key
	entry.CreatedAt = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry.
	if elem, ok := c.entries[key]; ok {
		elem.Value = entry
		c.order.MoveToFront(elem)
		return
	}

	// Evict if at capacity.
	for c.order.Len() >= c.maxSize {
		c.evictOldest()
	}

	elem := c.order.PushFront(entry)
	c.entries[key] = elem
}

// Delete removes a single entry from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		c.removeElement(elem)
	}
}

// Len returns the number of entries currently in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.order.Len()
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*list.Element)
	c.order.Init()
}

// Stats returns a snapshot of cache usage counters.
func (c *Cache) Stats() CacheStats {
	c.mu.RLock()
	size := c.order.Len()
	c.mu.RUnlock()

	return CacheStats{
		Size:      size,
		MaxSize:   c.maxSize,
		Hits:      c.hits.Load(),
		Misses:    c.misses.Load(),
		Evictions: c.evictions.Load(),
	}
}

// SetTTL updates the cache's TTL duration. Thread-safe.
func (c *Cache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	c.ttl = ttl
}

// Stop terminates the background cleanup goroutine.
func (c *Cache) Stop() {
	close(c.done)
}

// cleanupLoop runs every 5 minutes and removes expired entries.
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.removeExpired()
		}
	}
}

// removeExpired walks the list from back (oldest) to front and removes
// every entry whose TTL has elapsed.
func (c *Cache) removeExpired() {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem := c.order.Back()
	for elem != nil {
		prev := elem.Prev()
		entry := elem.Value.(*CacheEntry)
		if now.Sub(entry.CreatedAt) > c.ttl {
			c.removeElement(elem)
			c.evictions.Add(1)
		}
		elem = prev
	}
}

// evictOldest removes the least recently used entry. Must be called with mu held.
func (c *Cache) evictOldest() {
	elem := c.order.Back()
	if elem == nil {
		return
	}
	c.removeElement(elem)
	c.evictions.Add(1)
}

// removeElement removes an element from both the list and the map. Must be called with mu held.
func (c *Cache) removeElement(elem *list.Element) {
	entry := elem.Value.(*CacheEntry)
	delete(c.entries, entry.Key)
	c.order.Remove(elem)
}
