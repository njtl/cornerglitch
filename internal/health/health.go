package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Handler serves health check, status, debug, and metrics endpoints.
type Handler struct {
	startTime time.Time
}

// NewHandler creates a Handler with the given server start time.
func NewHandler(startTime time.Time) *Handler {
	return &Handler{startTime: startTime}
}

// ShouldHandle returns true if the path is a health/status/debug/metrics endpoint.
func (h *Handler) ShouldHandle(path string) bool {
	switch path {
	case "/health", "/health/live", "/health/ready", "/health/startup",
		"/status", "/status.json",
		"/.well-known/health",
		"/ping",
		"/version",
		"/debug/vars",
		"/metrics":
		return true
	}
	if strings.HasPrefix(path, "/debug/pprof/") || path == "/debug/pprof" {
		return true
	}
	return false
}

// ServeHTTP dispatches to the appropriate endpoint handler and returns the HTTP status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	switch r.URL.Path {
	case "/health", "/.well-known/health":
		return h.serveHealth(w)
	case "/health/live":
		return h.serveLive(w)
	case "/health/ready":
		return h.serveReady(w)
	case "/health/startup":
		return h.serveStartup(w)
	case "/status":
		return h.serveStatusHTML(w)
	case "/status.json":
		return h.serveStatusJSON(w)
	case "/ping":
		return h.servePing(w)
	case "/version":
		return h.serveVersion(w)
	case "/debug/vars":
		return h.serveDebugVars(w)
	case "/metrics":
		return h.serveMetrics(w)
	}
	if strings.HasPrefix(r.URL.Path, "/debug/pprof") {
		return h.servePprof(w, r)
	}
	w.WriteHeader(http.StatusNotFound)
	return http.StatusNotFound
}

// --- /health ---

func (h *Handler) serveHealth(w http.ResponseWriter) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	return http.StatusOK
}

// --- /health/live ---

func (h *Handler) serveLive(w http.ResponseWriter) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
	return http.StatusOK
}

// --- /health/ready ---

func (h *Handler) serveReady(w http.ResponseWriter) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ready",
		"checks": map[string]string{
			"database": "up",
			"cache":    "up",
			"queue":    "up",
		},
	})
	return http.StatusOK
}

// --- /health/startup ---

func (h *Handler) serveStartup(w http.ResponseWriter) int {
	uptime := time.Since(h.startTime).Seconds()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "started",
		"uptime_seconds": int(uptime),
	})
	return http.StatusOK
}

// --- /status ---

func (h *Handler) serveStatusHTML(w http.ResponseWriter) int {
	uptime := time.Since(h.startTime)
	uptimeStr := formatDuration(uptime)

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	heapPct := 0
	if mem.HeapSys > 0 {
		heapPct = int(float64(mem.HeapAlloc) / float64(mem.HeapSys) * 100)
	}
	cpuPct := 42 // simulated
	goroutines := runtime.NumGoroutine()
	maxProcs := runtime.GOMAXPROCS(0)

	type component struct {
		Name   string
		Status string
	}
	components := []component{
		{"Database", "Operational"},
		{"Cache", "Operational"},
		{"Queue", "Operational"},
		{"Search", "Operational"},
		{"Email", "Operational"},
		{"Storage", "Operational"},
	}

	var compRows strings.Builder
	for _, c := range components {
		compRows.WriteString(fmt.Sprintf(`        <tr>
          <td>&#x2705; %s</td>
          <td><span class="badge ok">%s</span></td>
        </tr>
`, c.Name, c.Status))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>System Status</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#0f1117;color:#e1e4e8;padding:2rem}
    h1{font-size:1.8rem;margin-bottom:.5rem;color:#58a6ff}
    h2{font-size:1.2rem;margin:1.5rem 0 .8rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.2rem;margin-bottom:1rem}
    table{width:100%%;border-collapse:collapse}
    th,td{text-align:left;padding:.5rem .8rem;border-bottom:1px solid #21262d}
    th{color:#8b949e;font-weight:600;font-size:.85rem}
    .badge{padding:2px 10px;border-radius:12px;font-size:.8rem;font-weight:600}
    .badge.ok{background:#1b4332;color:#2dd4bf}
    .bar-bg{background:#21262d;border-radius:4px;height:18px;overflow:hidden;margin-top:4px}
    .bar-fill{height:100%%;border-radius:4px;transition:width .3s}
    .bar-fill.green{background:#2dd4bf}
    .bar-fill.yellow{background:#e3b341}
    .bar-fill.red{background:#f85149}
    .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:.5rem}
    .info-grid span.label{color:#8b949e;font-size:.85rem}
    .info-grid span.value{font-weight:600}
    .ts{color:#484f58;font-size:.8rem;margin-top:1rem}
  </style>
</head>
<body>
  <h1>&#x1F7E2; All Systems Operational</h1>
  <p class="ts">Last updated: %s</p>

  <h2>Server Info</h2>
  <div class="card">
    <div class="info-grid">
      <span class="label">Version</span><span class="value">1.0.0</span>
      <span class="label">Go Version</span><span class="value">%s</span>
      <span class="label">GOMAXPROCS</span><span class="value">%d</span>
      <span class="label">Goroutines</span><span class="value">%d</span>
      <span class="label">Uptime</span><span class="value">%s</span>
      <span class="label">OS/Arch</span><span class="value">%s/%s</span>
    </div>
  </div>

  <h2>Component Status</h2>
  <div class="card">
    <table>
      <tr><th>Component</th><th>Status</th></tr>
%s    </table>
  </div>

  <h2>Resource Usage</h2>
  <div class="card">
    <p style="margin-bottom:.4rem;font-size:.9rem">CPU Usage (%d%%%%)</p>
    <div class="bar-bg"><div class="bar-fill %s" style="width:%d%%"></div></div>
    <p style="margin:.8rem 0 .4rem;font-size:.9rem">Heap Memory (%d%%%% of %s)</p>
    <div class="bar-bg"><div class="bar-fill %s" style="width:%d%%"></div></div>
  </div>

  <h2>Recent Activity</h2>
  <div class="card">
    <table>
      <tr><th>Time</th><th>Event</th><th>Detail</th></tr>
      <tr><td>%s</td><td>Server started</td><td>PID %d</td></tr>
      <tr><td>%s</td><td>Health check</td><td>All checks passed</td></tr>
      <tr><td>%s</td><td>Status page viewed</td><td>200 OK</td></tr>
    </table>
  </div>
</body>
</html>`,
		time.Now().UTC().Format(time.RFC3339),
		runtime.Version(),
		maxProcs,
		goroutines,
		uptimeStr,
		runtime.GOOS, runtime.GOARCH,
		compRows.String(),
		cpuPct, barColor(cpuPct), cpuPct,
		heapPct, formatBytes(mem.HeapSys), barColor(heapPct), heapPct,
		h.startTime.UTC().Format("15:04:05"), 1,
		time.Now().Add(-30*time.Second).UTC().Format("15:04:05"),
		time.Now().UTC().Format("15:04:05"),
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// --- /status.json ---

func (h *Handler) serveStatusJSON(w http.ResponseWriter) int {
	uptime := time.Since(h.startTime)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]interface{}{
		"version":    "1.0.0",
		"go_version": runtime.Version(),
		"uptime":     formatDuration(uptime),
		"components": map[string]string{
			"database": "operational",
			"cache":    "operational",
			"queue":    "operational",
			"search":   "operational",
			"email":    "operational",
			"storage":  "operational",
		},
		"metrics": map[string]interface{}{
			"goroutines":    runtime.NumGoroutine(),
			"gomaxprocs":    runtime.GOMAXPROCS(0),
			"heap_alloc":    mem.HeapAlloc,
			"heap_sys":      mem.HeapSys,
			"num_gc":        mem.NumGC,
			"uptime_seconds": int(uptime.Seconds()),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
	return http.StatusOK
}

// --- /ping ---

func (h *Handler) servePing(w http.ResponseWriter) int {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
	return http.StatusOK
}

// --- /version ---

func (h *Handler) serveVersion(w http.ResponseWriter) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"version": "1.0.0",
		"build":   "abc123",
		"go":      runtime.Version(),
		"os":      runtime.GOOS + "/" + runtime.GOARCH,
	})
	return http.StatusOK
}

// --- /debug/vars ---

func (h *Handler) serveDebugVars(w http.ResponseWriter) int {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]interface{}{
		"NumGoroutine": runtime.NumGoroutine(),
		"NumCPU":       runtime.NumCPU(),
		"GOMAXPROCS":   runtime.GOMAXPROCS(0),
		"memstats": map[string]interface{}{
			"Alloc":        mem.Alloc,
			"TotalAlloc":   mem.TotalAlloc,
			"Sys":          mem.Sys,
			"Lookups":      mem.Lookups,
			"Mallocs":      mem.Mallocs,
			"Frees":        mem.Frees,
			"HeapAlloc":    mem.HeapAlloc,
			"HeapSys":      mem.HeapSys,
			"HeapIdle":     mem.HeapIdle,
			"HeapInuse":    mem.HeapInuse,
			"HeapReleased": mem.HeapReleased,
			"HeapObjects":  mem.HeapObjects,
			"StackInuse":   mem.StackInuse,
			"StackSys":     mem.StackSys,
			"MSpanInuse":   mem.MSpanInuse,
			"MSpanSys":     mem.MSpanSys,
			"MCacheInuse":  mem.MCacheInuse,
			"MCacheSys":    mem.MCacheSys,
			"BuckHashSys":  mem.BuckHashSys,
			"GCSys":        mem.GCSys,
			"OtherSys":     mem.OtherSys,
			"NextGC":       mem.NextGC,
			"LastGC":       mem.LastGC,
			"NumGC":        mem.NumGC,
			"NumForcedGC":  mem.NumForcedGC,
			"GCCPUFraction": mem.GCCPUFraction,
			"PauseTotalNs": mem.PauseTotalNs,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data)
	return http.StatusOK
}

// --- /debug/pprof/ ---

func (h *Handler) servePprof(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	// Index page
	if path == "/debug/pprof/" || path == "/debug/pprof" {
		return h.servePprofIndex(w)
	}

	// Individual profile endpoints
	profile := strings.TrimPrefix(path, "/debug/pprof/")
	return h.servePprofProfile(w, profile)
}

func (h *Handler) servePprofIndex(w http.ResponseWriter) int {
	html := `<!DOCTYPE html>
<html>
<head><title>/debug/pprof/</title></head>
<body>
<h1>/debug/pprof/</h1>
<table>
<tr><td><a href="/debug/pprof/goroutine">goroutine</a></td></tr>
<tr><td><a href="/debug/pprof/heap">heap</a></td></tr>
<tr><td><a href="/debug/pprof/threadcreate">threadcreate</a></td></tr>
<tr><td><a href="/debug/pprof/block">block</a></td></tr>
<tr><td><a href="/debug/pprof/mutex">mutex</a></td></tr>
<tr><td><a href="/debug/pprof/allocs">allocs</a></td></tr>
<tr><td><a href="/debug/pprof/cmdline">cmdline</a></td></tr>
<tr><td><a href="/debug/pprof/profile">profile</a></td></tr>
<tr><td><a href="/debug/pprof/symbol">symbol</a></td></tr>
<tr><td><a href="/debug/pprof/trace">trace</a></td></tr>
</table>
<p>Profile Descriptions:</p>
<ul>
<li><b>goroutine</b>: stack traces of all current goroutines</li>
<li><b>heap</b>: a sampling of memory allocations of live objects</li>
<li><b>threadcreate</b>: stack traces that led to the creation of new OS threads</li>
<li><b>block</b>: stack traces that led to blocking on synchronization primitives</li>
<li><b>mutex</b>: stack traces of holders of contended mutexes</li>
<li><b>allocs</b>: a sampling of all past memory allocations</li>
</ul>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) servePprofProfile(w http.ResponseWriter, profile string) int {
	goroutines := runtime.NumGoroutine()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var body string
	switch profile {
	case "goroutine":
		body = fmt.Sprintf(`goroutine profile: total %d
%d @ 0x43e1a6 0x44b1c0 0x44b19e 0x46c060 0x4801
# 0x43e1a5    runtime.gopark+0x125          runtime/proc.go:398
# 0x44b1bf    runtime.goparkunlock+0x3f      runtime/proc.go:403
# 0x44b19d    runtime.chanrecv+0x27d         runtime/chan.go:583
# 0x46c05f    main.(*Server).serve+0x1ff     server/handler.go:99

%d @ 0x43e1a6 0x449030 0x488db0 0x4801
# 0x43e1a5    runtime.gopark+0x125          runtime/proc.go:398
# 0x44902f    time.Sleep+0x18f              runtime/time.go:195
# 0x488daf    net/http.(*conn).serve+0x8af  net/http/server.go:1930

1 @ 0x43e1a6 0x44b1c0 0x48a120 0x4801
# 0x43e1a5    runtime.gopark+0x125          runtime/proc.go:398
# 0x44b1bf    runtime.goparkunlock+0x3f      runtime/proc.go:403
# 0x48a11f    net/http.(*Server).Serve+0x3ff net/http/server.go:3056
`, goroutines, goroutines-2, 1)

	case "heap":
		body = fmt.Sprintf(`heap profile: %d: %d [%d: %d] @ heap/%d
%d: %d [%d: %d] @ 0x4a2f00 0x4a3100 0x4801
# 0x4a2eff    bytes.makeSlice+0x6f            bytes/buffer.go:229
# 0x4a30ff    bytes.(*Buffer).grow+0x13f      bytes/buffer.go:142

%d: %d [%d: %d] @ 0x4b1200 0x4b1400 0x4801
# 0x4b11ff    encoding/json.(*encodeState).marshal+0x1af json/encode.go:304
# 0x4b13ff    encoding/json.Marshal+0xaf                 json/encode.go:160

# runtime.MemStats
# Alloc = %d
# TotalAlloc = %d
# Sys = %d
# HeapAlloc = %d
# HeapSys = %d
# HeapIdle = %d
# HeapInuse = %d
# HeapReleased = %d
# HeapObjects = %d
# NumGC = %d
`,
			mem.HeapObjects, mem.HeapAlloc, mem.Mallocs, mem.TotalAlloc, mem.HeapSys,
			128, 32768, 512, 131072,
			64, 16384, 256, 65536,
			mem.Alloc, mem.TotalAlloc, mem.Sys,
			mem.HeapAlloc, mem.HeapSys, mem.HeapIdle,
			mem.HeapInuse, mem.HeapReleased, mem.HeapObjects,
			mem.NumGC)

	case "threadcreate":
		body = fmt.Sprintf(`threadcreate profile: total %d
%d @ 0x43e1a6 0x44b1c0 0x4801
# 0x43e1a5    runtime.gopark+0x125    runtime/proc.go:398
# 0x44b1bf    runtime.allocm+0x3f     runtime/proc.go:1809
`, runtime.GOMAXPROCS(0)+2, runtime.GOMAXPROCS(0)+2)

	case "block":
		body = `--- contention:
cycles/second=1000000000
1000000 1 @ 0x43e1a6 0x44b1c0 0x4801
# 0x43e1a5    runtime.chanrecv1+0x125    runtime/chan.go:442
# 0x44b1bf    main.worker+0x3f           main.go:45

500000 1 @ 0x43e1a6 0x449030 0x4801
# 0x43e1a5    sync.(*Mutex).Lock+0x125   sync/mutex.go:81
# 0x44902f    main.process+0x18f         main.go:72
`

	case "mutex":
		body = `--- mutex:
cycles/second=1000000000
200000 1 @ 0x43e1a6 0x44b1c0 0x4801
# 0x43e1a5    sync.(*Mutex).Unlock+0x125    sync/mutex.go:190
# 0x44b1bf    main.handler+0x3f             server/handler.go:55
`

	case "allocs":
		body = fmt.Sprintf(`alloc_objects: %d
alloc_space: %d
inuse_objects: %d
inuse_space: %d

%d: %d [%d: %d] @ 0x4a2f00 0x4a3100 0x4801
# 0x4a2eff    bytes.makeSlice+0x6f       bytes/buffer.go:229
# 0x4a30ff    bytes.(*Buffer).grow+0x13f bytes/buffer.go:142
`, mem.Mallocs, mem.TotalAlloc, mem.HeapObjects, mem.HeapAlloc,
			mem.Mallocs, mem.TotalAlloc, mem.HeapObjects, mem.HeapAlloc)

	case "cmdline":
		body = "glitch\x00"

	case "symbol":
		body = `num_symbols: 1
0x43e1a6 runtime.gopark
`

	case "profile":
		body = "binary profile data not available in fake pprof endpoint\n"

	case "trace":
		body = "binary trace data not available in fake pprof endpoint\n"

	default:
		body = fmt.Sprintf("unknown profile: %s\n", profile)
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
	return http.StatusOK
}

// --- /metrics ---

func (h *Handler) serveMetrics(w http.ResponseWriter) int {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	uptime := time.Since(h.startTime).Seconds()
	goroutines := runtime.NumGoroutine()

	var sb strings.Builder

	sb.WriteString("# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n")
	sb.WriteString("# TYPE process_cpu_seconds_total counter\n")
	sb.WriteString(fmt.Sprintf("process_cpu_seconds_total %.2f\n", uptime*0.03))
	sb.WriteString("\n")

	sb.WriteString("# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n")
	sb.WriteString("# TYPE process_start_time_seconds gauge\n")
	sb.WriteString(fmt.Sprintf("process_start_time_seconds %.3f\n", float64(h.startTime.Unix())+float64(h.startTime.Nanosecond())/1e9))
	sb.WriteString("\n")

	sb.WriteString("# HELP process_resident_memory_bytes Resident memory size in bytes.\n")
	sb.WriteString("# TYPE process_resident_memory_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("process_resident_memory_bytes %d\n", mem.Sys))
	sb.WriteString("\n")

	sb.WriteString("# HELP process_virtual_memory_bytes Virtual memory size in bytes.\n")
	sb.WriteString("# TYPE process_virtual_memory_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("process_virtual_memory_bytes %d\n", mem.Sys+mem.HeapIdle))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_goroutines Number of goroutines that currently exist.\n")
	sb.WriteString("# TYPE go_goroutines gauge\n")
	sb.WriteString(fmt.Sprintf("go_goroutines %d\n", goroutines))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_threads Number of OS threads created.\n")
	sb.WriteString("# TYPE go_threads gauge\n")
	sb.WriteString(fmt.Sprintf("go_threads %d\n", runtime.GOMAXPROCS(0)+4))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_gc_duration_seconds A summary of pause durations of garbage collection cycles.\n")
	sb.WriteString("# TYPE go_gc_duration_seconds summary\n")
	gcPause := float64(mem.PauseTotalNs) / 1e9
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds{quantile=\"0\"} %.6f\n", gcPause*0.1))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds{quantile=\"0.25\"} %.6f\n", gcPause*0.25))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds{quantile=\"0.5\"} %.6f\n", gcPause*0.5))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds{quantile=\"0.75\"} %.6f\n", gcPause*0.75))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds{quantile=\"1\"} %.6f\n", gcPause))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds_sum %.6f\n", gcPause))
	sb.WriteString(fmt.Sprintf("go_gc_duration_seconds_count %d\n", mem.NumGC))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n")
	sb.WriteString("# TYPE go_memstats_alloc_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_alloc_bytes %d\n", mem.Alloc))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_alloc_bytes_total Total number of bytes allocated, even if freed.\n")
	sb.WriteString("# TYPE go_memstats_alloc_bytes_total counter\n")
	sb.WriteString(fmt.Sprintf("go_memstats_alloc_bytes_total %d\n", mem.TotalAlloc))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_sys_bytes Number of bytes obtained from system.\n")
	sb.WriteString("# TYPE go_memstats_sys_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_sys_bytes %d\n", mem.Sys))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.\n")
	sb.WriteString("# TYPE go_memstats_heap_alloc_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_heap_alloc_bytes %d\n", mem.HeapAlloc))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_heap_sys_bytes Number of heap bytes obtained from system.\n")
	sb.WriteString("# TYPE go_memstats_heap_sys_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_heap_sys_bytes %d\n", mem.HeapSys))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_heap_idle_bytes Number of heap bytes waiting to be used.\n")
	sb.WriteString("# TYPE go_memstats_heap_idle_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_heap_idle_bytes %d\n", mem.HeapIdle))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_heap_inuse_bytes Number of heap bytes that are in use.\n")
	sb.WriteString("# TYPE go_memstats_heap_inuse_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_heap_inuse_bytes %d\n", mem.HeapInuse))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_memstats_stack_inuse_bytes Number of bytes in use by the stack allocator.\n")
	sb.WriteString("# TYPE go_memstats_stack_inuse_bytes gauge\n")
	sb.WriteString(fmt.Sprintf("go_memstats_stack_inuse_bytes %d\n", mem.StackInuse))
	sb.WriteString("\n")

	sb.WriteString("# HELP go_info Information about the Go environment.\n")
	sb.WriteString("# TYPE go_info gauge\n")
	sb.WriteString(fmt.Sprintf("go_info{version=\"%s\"} 1\n", runtime.Version()))
	sb.WriteString("\n")

	sb.WriteString("# HELP http_requests_total Total number of HTTP requests processed.\n")
	sb.WriteString("# TYPE http_requests_total counter\n")
	sb.WriteString(fmt.Sprintf("http_requests_total{method=\"GET\",code=\"200\"} %d\n", int(uptime*2.3)+17))
	sb.WriteString(fmt.Sprintf("http_requests_total{method=\"GET\",code=\"404\"} %d\n", int(uptime*0.1)+2))
	sb.WriteString(fmt.Sprintf("http_requests_total{method=\"GET\",code=\"500\"} %d\n", int(uptime*0.05)+1))
	sb.WriteString(fmt.Sprintf("http_requests_total{method=\"POST\",code=\"200\"} %d\n", int(uptime*0.8)+5))
	sb.WriteString(fmt.Sprintf("http_requests_total{method=\"POST\",code=\"400\"} %d\n", int(uptime*0.02)))
	sb.WriteString("\n")

	sb.WriteString("# HELP http_request_duration_seconds HTTP request latency in seconds.\n")
	sb.WriteString("# TYPE http_request_duration_seconds histogram\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.005\"} 320\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.01\"} 580\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.025\"} 740\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.05\"} 820\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.1\"} 890\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.25\"} 940\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"0.5\"} 970\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"1\"} 990\n")
	sb.WriteString("http_request_duration_seconds_bucket{le=\"+Inf\"} 1000\n")
	sb.WriteString("http_request_duration_seconds_sum 28.7\n")
	sb.WriteString("http_request_duration_seconds_count 1000\n")
	sb.WriteString("\n")

	sb.WriteString("# HELP up 1 if the server is up.\n")
	sb.WriteString("# TYPE up gauge\n")
	sb.WriteString("up 1\n")

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(sb.String()))
	return http.StatusOK
}

// --- helpers ---

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func formatBytes(b uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func barColor(pct int) string {
	switch {
	case pct >= 80:
		return "red"
	case pct >= 50:
		return "yellow"
	default:
		return "green"
	}
}
