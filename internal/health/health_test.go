package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

// helper: create a Handler with a known start time.
func newTestHandler() *Handler {
	return NewHandler(time.Now().Add(-5 * time.Minute))
}

// helper: issue a request to the handler and return the recorder + status code.
func doRequest(h *Handler, method, path string) (*httptest.ResponseRecorder, int) {
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	code := h.ServeHTTP(rr, req)
	return rr, code
}

// ---------- NewHandler ----------

func TestNewHandler(t *testing.T) {
	start := time.Now()
	h := NewHandler(start)
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if !h.startTime.Equal(start) {
		t.Fatalf("startTime mismatch: got %v, want %v", h.startTime, start)
	}
}

// ---------- ShouldHandle ----------

func TestShouldHandle_MatchedPaths(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		"/health",
		"/health/live",
		"/health/ready",
		"/health/startup",
		"/status",
		"/status.json",
		"/.well-known/health",
		"/ping",
		"/version",
		"/debug/vars",
		"/metrics",
		"/debug/pprof",
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/some-custom-profile",
	}
	for _, p := range paths {
		if !h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = false, want true", p)
		}
	}
}

func TestShouldHandle_UnmatchedPaths(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		"/",
		"/about",
		"/api/v1/users",
		"/healthz",
		"/health/other",
		"/statuspage",
		"/debug",
		"/debug/",
		"/debug/other",
		"/metricsmore",
		"/pings",
	}
	for _, p := range paths {
		if h.ShouldHandle(p) {
			t.Errorf("ShouldHandle(%q) = true, want false", p)
		}
	}
}

// ---------- /health ----------

func TestHealthEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/health")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %q, want %q", body["status"], "healthy")
	}
	if _, ok := body["timestamp"]; !ok {
		t.Error("missing 'timestamp' key in response")
	}
}

// ---------- /.well-known/health ----------

func TestWellKnownHealthEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/.well-known/health")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %q, want %q", body["status"], "healthy")
	}
}

// ---------- /health/live ----------

func TestLiveEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/health/live")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

// ---------- /health/ready ----------

func TestReadyEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/health/ready")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "ready" {
		t.Errorf("status = %v, want %q", body["status"], "ready")
	}
	checks, ok := body["checks"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'checks' object")
	}
	for _, key := range []string{"database", "cache", "queue"} {
		if checks[key] != "up" {
			t.Errorf("checks[%q] = %v, want %q", key, checks[key], "up")
		}
	}
}

// ---------- /health/startup ----------

func TestStartupEndpoint(t *testing.T) {
	h := NewHandler(time.Now().Add(-2 * time.Minute))
	rr, code := doRequest(h, http.MethodGet, "/health/startup")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["status"] != "started" {
		t.Errorf("status = %v, want %q", body["status"], "started")
	}
	uptimeSec, ok := body["uptime_seconds"].(float64)
	if !ok {
		t.Fatal("missing or invalid 'uptime_seconds'")
	}
	// We set startTime 2 minutes ago; uptime should be >= 119 seconds.
	if uptimeSec < 119 {
		t.Errorf("uptime_seconds = %v, want >= 119", uptimeSec)
	}
}

// ---------- /status (HTML) ----------

func TestStatusHTMLEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/status")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("response body missing <!DOCTYPE html>")
	}
	if !strings.Contains(body, "All Systems Operational") {
		t.Error("response body missing 'All Systems Operational'")
	}
	if !strings.Contains(body, runtime.Version()) {
		t.Errorf("response body missing Go version %q", runtime.Version())
	}
	// All six components should appear.
	for _, comp := range []string{"Database", "Cache", "Queue", "Search", "Email", "Storage"} {
		if !strings.Contains(body, comp) {
			t.Errorf("response body missing component %q", comp)
		}
	}
}

// ---------- /status.json ----------

func TestStatusJSONEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/status.json")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["version"] != "1.0.0" {
		t.Errorf("version = %v, want %q", body["version"], "1.0.0")
	}
	if body["go_version"] != runtime.Version() {
		t.Errorf("go_version = %v, want %q", body["go_version"], runtime.Version())
	}
	components, ok := body["components"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'components' object")
	}
	for _, key := range []string{"database", "cache", "queue", "search", "email", "storage"} {
		if components[key] != "operational" {
			t.Errorf("components[%q] = %v, want %q", key, components[key], "operational")
		}
	}
	metrics, ok := body["metrics"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'metrics' object")
	}
	for _, key := range []string{"goroutines", "gomaxprocs", "heap_alloc", "heap_sys", "num_gc", "uptime_seconds"} {
		if _, ok := metrics[key]; !ok {
			t.Errorf("metrics missing key %q", key)
		}
	}
}

// ---------- /ping ----------

func TestPingEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/ping")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
	if rr.Body.String() != "pong" {
		t.Errorf("body = %q, want %q", rr.Body.String(), "pong")
	}
}

// ---------- /version ----------

func TestVersionEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/version")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if body["version"] != "1.0.0" {
		t.Errorf("version = %q, want %q", body["version"], "1.0.0")
	}
	if body["build"] != "abc123" {
		t.Errorf("build = %q, want %q", body["build"], "abc123")
	}
	if body["go"] != runtime.Version() {
		t.Errorf("go = %q, want %q", body["go"], runtime.Version())
	}
	expectedOS := runtime.GOOS + "/" + runtime.GOARCH
	if body["os"] != expectedOS {
		t.Errorf("os = %q, want %q", body["os"], expectedOS)
	}
}

// ---------- /debug/vars ----------

func TestDebugVarsEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/vars")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	for _, key := range []string{"NumGoroutine", "NumCPU", "GOMAXPROCS"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	memstats, ok := body["memstats"].(map[string]interface{})
	if !ok {
		t.Fatal("missing or invalid 'memstats' object")
	}
	memKeys := []string{
		"Alloc", "TotalAlloc", "Sys", "HeapAlloc", "HeapSys",
		"HeapIdle", "HeapInuse", "HeapReleased", "HeapObjects",
		"StackInuse", "StackSys", "NumGC", "GCCPUFraction",
	}
	for _, key := range memKeys {
		if _, ok := memstats[key]; !ok {
			t.Errorf("memstats missing key %q", key)
		}
	}
}

func TestDebugVarsNumCPUValue(t *testing.T) {
	h := newTestHandler()
	rr, _ := doRequest(h, http.MethodGet, "/debug/vars")

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	numCPU, ok := body["NumCPU"].(float64)
	if !ok {
		t.Fatal("NumCPU not a number")
	}
	if int(numCPU) != runtime.NumCPU() {
		t.Errorf("NumCPU = %v, want %d", numCPU, runtime.NumCPU())
	}
}

// ---------- /debug/pprof/ (index) ----------

func TestPprofIndexEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/debug/pprof/") {
		t.Error("pprof index missing self-reference")
	}
	for _, profile := range []string{"goroutine", "heap", "threadcreate", "block", "mutex", "allocs", "profile", "trace", "symbol", "cmdline"} {
		if !strings.Contains(body, profile) {
			t.Errorf("pprof index missing link to %q", profile)
		}
	}
}

func TestPprofIndexWithoutTrailingSlash(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/debug/pprof/") {
		t.Error("pprof index (no slash) should return the index page")
	}
}

// ---------- /debug/pprof/<profile> individual profiles ----------

func TestPprofGoroutineProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/goroutine")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain prefix", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "goroutine profile: total") {
		t.Error("goroutine profile missing expected header")
	}
	if !strings.Contains(body, "runtime.gopark") {
		t.Error("goroutine profile missing runtime.gopark")
	}
}

func TestPprofHeapProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/heap")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "heap profile:") {
		t.Error("heap profile missing expected header")
	}
	if !strings.Contains(body, "# runtime.MemStats") {
		t.Error("heap profile missing MemStats section")
	}
}

func TestPprofBlockProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/block")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "contention") {
		t.Error("block profile missing 'contention' header")
	}
}

func TestPprofMutexProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/mutex")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "mutex") {
		t.Error("mutex profile missing 'mutex' header")
	}
}

func TestPprofAllocsProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/allocs")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "alloc_objects") {
		t.Error("allocs profile missing 'alloc_objects'")
	}
}

func TestPprofThreadcreateProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/threadcreate")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "threadcreate profile:") {
		t.Error("threadcreate profile missing expected header")
	}
}

func TestPprofCmdlineProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/cmdline")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "glitch") {
		t.Error("cmdline profile missing 'glitch'")
	}
}

func TestPprofSymbolProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/symbol")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "num_symbols") {
		t.Error("symbol profile missing 'num_symbols'")
	}
}

func TestPprofProfileEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/profile")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "binary profile data") {
		t.Error("profile endpoint missing expected message")
	}
}

func TestPprofTraceEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/trace")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "binary trace data") {
		t.Error("trace endpoint missing expected message")
	}
}

func TestPprofUnknownProfile(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/debug/pprof/nonexistent")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "unknown profile: nonexistent") {
		t.Errorf("unexpected body for unknown profile: %q", body)
	}
}

// ---------- /metrics ----------

func TestMetricsEndpoint(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/metrics")

	if code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", code, http.StatusOK)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain included", ct)
	}
	if !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type missing version=0.0.4: %q", ct)
	}

	body := rr.Body.String()
	// Verify HELP/TYPE blocks are present for key metric families.
	expectedMetrics := []string{
		"process_cpu_seconds_total",
		"process_start_time_seconds",
		"process_resident_memory_bytes",
		"process_virtual_memory_bytes",
		"go_goroutines",
		"go_threads",
		"go_gc_duration_seconds",
		"go_memstats_alloc_bytes",
		"go_memstats_sys_bytes",
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_sys_bytes",
		"go_memstats_heap_idle_bytes",
		"go_memstats_heap_inuse_bytes",
		"go_memstats_stack_inuse_bytes",
		"go_info",
		"http_requests_total",
		"http_request_duration_seconds",
		"up",
	}
	for _, name := range expectedMetrics {
		if !strings.Contains(body, name) {
			t.Errorf("metrics output missing %q", name)
		}
	}
}

func TestMetricsContainsHELPAndTYPE(t *testing.T) {
	h := newTestHandler()
	rr, _ := doRequest(h, http.MethodGet, "/metrics")
	body := rr.Body.String()

	// Check a sampling of HELP/TYPE lines.
	helpLines := []string{
		"# HELP go_goroutines",
		"# TYPE go_goroutines gauge",
		"# HELP http_requests_total",
		"# TYPE http_requests_total counter",
		"# HELP http_request_duration_seconds",
		"# TYPE http_request_duration_seconds histogram",
		"# HELP go_gc_duration_seconds",
		"# TYPE go_gc_duration_seconds summary",
		"# HELP up",
		"# TYPE up gauge",
	}
	for _, line := range helpLines {
		if !strings.Contains(body, line) {
			t.Errorf("metrics output missing %q", line)
		}
	}
}

func TestMetricsUpIsOne(t *testing.T) {
	h := newTestHandler()
	rr, _ := doRequest(h, http.MethodGet, "/metrics")
	body := rr.Body.String()
	if !strings.Contains(body, "up 1") {
		t.Error("metrics should contain 'up 1'")
	}
}

func TestMetricsGoInfo(t *testing.T) {
	h := newTestHandler()
	rr, _ := doRequest(h, http.MethodGet, "/metrics")
	body := rr.Body.String()

	expected := `go_info{version="` + runtime.Version() + `"} 1`
	if !strings.Contains(body, expected) {
		t.Errorf("metrics missing go_info line, want %q", expected)
	}
}

func TestMetricsHistogramBuckets(t *testing.T) {
	h := newTestHandler()
	rr, _ := doRequest(h, http.MethodGet, "/metrics")
	body := rr.Body.String()

	// Verify histogram buckets are monotonically increasing.
	bucketLabels := []string{
		`le="0.005"`,
		`le="0.01"`,
		`le="0.025"`,
		`le="0.05"`,
		`le="0.1"`,
		`le="0.25"`,
		`le="0.5"`,
		`le="1"`,
		`le="+Inf"`,
	}
	for _, label := range bucketLabels {
		if !strings.Contains(body, label) {
			t.Errorf("metrics missing histogram bucket %q", label)
		}
	}
}

// ---------- Unknown route ----------

func TestUnknownRoute(t *testing.T) {
	h := newTestHandler()
	rr, code := doRequest(h, http.MethodGet, "/nonexistent")

	if code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", code, http.StatusNotFound)
	}
	if rr.Code != http.StatusNotFound {
		t.Errorf("recorder code = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// ---------- Return code matches recorder ----------

func TestReturnCodeConsistency(t *testing.T) {
	h := newTestHandler()
	paths := []string{
		"/health", "/health/live", "/health/ready", "/health/startup",
		"/status", "/status.json", "/.well-known/health",
		"/ping", "/version", "/debug/vars", "/metrics",
		"/debug/pprof/", "/debug/pprof/heap",
	}
	for _, p := range paths {
		rr, code := doRequest(h, http.MethodGet, p)
		if code != http.StatusOK {
			t.Errorf("%s: return code = %d, want %d", p, code, http.StatusOK)
		}
		if rr.Code != http.StatusOK {
			t.Errorf("%s: recorder code = %d, want %d", p, rr.Code, http.StatusOK)
		}
	}
}

// ---------- formatDuration helper ----------

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{0, "0s"},
		{90 * time.Second, "1m 30s"},
		{3661 * time.Second, "1h 1m 1s"},
		{90061 * time.Second, "1d 1h 1m 1s"},
		{48*time.Hour + 30*time.Minute, "2d 0h 30m 0s"},
	}
	for _, tt := range tests {
		got := formatDuration(tt.d)
		if got != tt.want {
			t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

// ---------- formatBytes helper ----------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		b    uint64
		want string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{1610612736, "1.5 GB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.b)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.b, got, tt.want)
		}
	}
}

// ---------- barColor helper ----------

func TestBarColor(t *testing.T) {
	tests := []struct {
		pct  int
		want string
	}{
		{0, "green"},
		{49, "green"},
		{50, "yellow"},
		{79, "yellow"},
		{80, "red"},
		{100, "red"},
	}
	for _, tt := range tests {
		got := barColor(tt.pct)
		if got != tt.want {
			t.Errorf("barColor(%d) = %q, want %q", tt.pct, got, tt.want)
		}
	}
}

// ---------- Concurrent safety ----------

func TestConcurrentRequests(t *testing.T) {
	h := newTestHandler()
	done := make(chan struct{})
	paths := []string{
		"/health", "/ping", "/version", "/metrics",
		"/debug/vars", "/debug/pprof/heap", "/status.json",
	}

	for i := 0; i < 20; i++ {
		go func(idx int) {
			defer func() { done <- struct{}{} }()
			p := paths[idx%len(paths)]
			_, code := doRequest(h, http.MethodGet, p)
			if code != http.StatusOK {
				t.Errorf("concurrent request %s returned %d", p, code)
			}
		}(i)
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}
