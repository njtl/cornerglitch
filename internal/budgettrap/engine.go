package budgettrap

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Engine decides when and how to drain scanner budgets by applying
// escalating traps based on per-client request volume.
type Engine struct {
	mu        sync.RWMutex
	enabled   bool
	threshold int64 // request count before traps activate
}

// NewEngine creates a budget trap engine with default settings.
func NewEngine() *Engine {
	return &Engine{
		enabled:   false,
		threshold: 10,
	}
}

// SetEnabled toggles budget traps on/off.
func (e *Engine) SetEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = enabled
}

// IsEnabled returns whether budget traps are active.
func (e *Engine) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// SetThreshold sets the minimum request count before traps activate.
func (e *Engine) SetThreshold(t int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if t < 1 {
		t = 1
	}
	e.threshold = t
}

// GetThreshold returns the current activation threshold.
func (e *Engine) GetThreshold() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.threshold
}

// ShouldHandle returns true if the client has exceeded the request threshold
// and budget traps are enabled.
func (e *Engine) ShouldHandle(clientID string, totalRequests int64) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled && totalRequests > e.threshold
}

// Apply picks and executes a trap based on the client's escalation level.
// Returns (statusCode, trapType). trapType is one of: "tarpit", "breadcrumbs",
// "streaming_bait", "pagination_trap", "expansion".
func (e *Engine) Apply(w http.ResponseWriter, r *http.Request, clientID string, totalRequests int64) (int, string) {
	rng := seedRNG(clientID, r.URL.Path)

	e.mu.RLock()
	thresh := e.threshold
	e.mu.RUnlock()

	roll := rng.Float64()

	switch {
	case totalRequests <= thresh*5: // level 1: threshold+1 to threshold*5
		if roll < 0.20 {
			return applyTarpit(w, r, 1, rng)
		}
		InjectBreadcrumbHeaders(w, rng)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(generateNormalPage(rng)))
		return http.StatusOK, "breadcrumbs"

	case totalRequests <= thresh*10: // level 2: threshold*5+1 to threshold*10
		if roll < 0.40 {
			return applyTarpit(w, r, 2, rng)
		}
		if roll < 0.60 {
			return applyStreamingBait(w, r, rng)
		}
		InjectBreadcrumbHeaders(w, rng)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(generateNormalPage(rng)))
		return http.StatusOK, "breadcrumbs"

	default: // level 3: beyond threshold*10
		if roll < 0.30 {
			return applyTarpit(w, r, 3, rng)
		}
		if roll < 0.55 {
			return applyStreamingBait(w, r, rng)
		}
		if roll < 0.75 {
			return applyPaginationTrap(w, r, rng)
		}
		// Expansion: breadcrumbs + extra links to waste crawl budget
		InjectBreadcrumbHeaders(w, rng)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(generateExpansionPage(rng)))
		return http.StatusOK, "expansion"
	}
}

// seedRNG creates a deterministic RNG from clientID + path using SHA-256.
func seedRNG(clientID, path string) *rand.Rand {
	h := sha256.New()
	h.Write([]byte(clientID))
	h.Write([]byte(path))
	sum := h.Sum(nil)
	seed := int64(binary.BigEndian.Uint64(sum[:8]))
	return rand.New(rand.NewSource(seed))
}

// applyStreamingBait sends a chunked response that drips data slowly,
// keeping the connection busy.
func applyStreamingBait(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	flusher, canFlush := w.(http.Flusher)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	chunks := []string{
		"<!DOCTYPE html><html><head><title>Loading...</title></head><body>",
		"<div class=\"content\"><h1>Processing your request</h1>",
		"<p>Please wait while we retrieve the data...</p>",
		"<div class=\"results\"><table><thead><tr><th>ID</th><th>Name</th><th>Status</th></tr></thead><tbody>",
	}

	for _, chunk := range chunks {
		w.Write([]byte(chunk))
		if canFlush {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rng.Intn(1500)+500) * time.Millisecond)
	}

	// Generate fake table rows slowly
	names := []string{"admin", "root", "deploy", "backup", "service", "api-user", "jenkins", "monitoring"}
	statuses := []string{"active", "suspended", "pending", "locked"}
	rows := rng.Intn(15) + 10
	for i := 0; i < rows; i++ {
		name := names[rng.Intn(len(names))]
		status := statuses[rng.Intn(len(statuses))]
		row := fmt.Sprintf("<tr><td>%d</td><td>%s</td><td>%s</td></tr>", i+1, name, status)
		w.Write([]byte(row))
		if canFlush {
			flusher.Flush()
		}
		time.Sleep(time.Duration(rng.Intn(1200)+300) * time.Millisecond)
	}

	w.Write([]byte("</tbody></table></div></div></body></html>"))
	if canFlush {
		flusher.Flush()
	}
	return http.StatusOK, "streaming_bait"
}

// applyPaginationTrap serves a page with links to many "next page" URLs,
// each of which generates more pagination links.
func applyPaginationTrap(w http.ResponseWriter, r *http.Request, rng *rand.Rand) (int, string) {
	InjectBreadcrumbHeaders(w, rng)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	var sb strings.Builder
	page := rng.Intn(9999) + 1
	fmt.Fprintf(&sb, "<!DOCTYPE html><html><head><title>Results - Page %d</title></head><body>", page)
	sb.WriteString("<h1>Search Results</h1><div class=\"results\">")

	for i := 0; i < 20; i++ {
		fmt.Fprintf(&sb, "<div class=\"result\"><h3>Result #%d</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>", page*20+i)
	}

	sb.WriteString("</div><nav class=\"pagination\">")

	// Generate many pagination links to expand the crawl frontier
	base := r.URL.Path
	sorts := []string{"relevance", "date", "rating", "price", "name"}
	for i := 0; i < 50; i++ {
		p := rng.Intn(99999) + 1
		sort := sorts[rng.Intn(len(sorts))]
		fmt.Fprintf(&sb, "<a href=\"%s?page=%d&sort=%s\">Page %d</a> ", base, p, sort, p)
	}

	sb.WriteString("</nav></body></html>")
	w.Write([]byte(sb.String()))
	return http.StatusOK, "pagination_trap"
}

// generateNormalPage produces a realistic HTML page with breadcrumb HTML injected.
func generateNormalPage(rng *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><title>Acme Corp Portal</title></head><body>")
	sb.WriteString("<nav><a href=\"/\">Home</a> | <a href=\"/about\">About</a> | <a href=\"/products\">Products</a></nav>")
	sb.WriteString("<main><h1>Welcome to Acme Corp</h1>")
	sb.WriteString("<p>Your request has been processed successfully.</p>")
	sb.WriteString(GenerateBreadcrumbHTML(rng))
	sb.WriteString("</main></body></html>")
	return sb.String()
}

// generateExpansionPage produces a page with many links to waste crawl budget.
func generateExpansionPage(rng *rand.Rand) string {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><title>Acme Corp - Directory</title></head><body>")
	sb.WriteString("<nav><a href=\"/\">Home</a> | <a href=\"/about\">About</a></nav>")
	sb.WriteString("<main><h1>Site Directory</h1><ul>")

	dirs := []string{
		"/internal/reports/", "/api/v2/admin/", "/backup/archives/",
		"/staff/portal/", "/legacy/app/", "/staging/deploy/",
		"/data/exports/", "/files/private/", "/config/advanced/",
		"/debug/traces/", "/monitoring/alerts/", "/logs/archive/",
	}
	for _, d := range dirs {
		for i := 0; i < 5; i++ {
			n := rng.Intn(9999)
			fmt.Fprintf(&sb, "<li><a href=\"%s%d\">%s%d</a></li>", d, n, d, n)
		}
	}

	sb.WriteString("</ul>")
	sb.WriteString(GenerateBreadcrumbHTML(rng))
	sb.WriteString("</main></body></html>")
	return sb.String()
}
