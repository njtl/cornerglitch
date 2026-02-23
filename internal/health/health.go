package health

import (
	"crypto/rand"
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
	if path == "/actuator" || path == "/actuator/" || strings.HasPrefix(path, "/actuator/") {
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
	if r.URL.Path == "/actuator" || r.URL.Path == "/actuator/" || strings.HasPrefix(r.URL.Path, "/actuator/") {
		return h.serveActuator(w, r)
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

// --- Spring Boot Actuator emulation ---

func (h *Handler) serveActuator(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	// Strip trailing slash for consistency, but keep root as-is
	if path == "/actuator" || path == "/actuator/" {
		return h.serveActuatorIndex(w)
	}

	// Remove the /actuator/ prefix
	sub := strings.TrimPrefix(path, "/actuator/")

	switch {
	case sub == "health":
		return h.serveActuatorHealth(w)
	case sub == "info":
		return h.serveActuatorInfo(w)
	case sub == "env":
		return h.serveActuatorEnv(w)
	case sub == "beans":
		return h.serveActuatorBeans(w)
	case sub == "mappings":
		return h.serveActuatorMappings(w)
	case sub == "metrics":
		return h.serveActuatorMetrics(w)
	case strings.HasPrefix(sub, "metrics/"):
		metricName := strings.TrimPrefix(sub, "metrics/")
		return h.serveActuatorMetricDetail(w, metricName)
	case sub == "configprops":
		return h.serveActuatorConfigprops(w)
	case sub == "loggers":
		return h.serveActuatorLoggers(w)
	case sub == "threaddump":
		return h.serveActuatorThreaddump(w)
	case sub == "heapdump":
		return h.serveActuatorHeapdump(w)
	case sub == "conditions":
		return h.serveActuatorConditions(w)
	case sub == "scheduledtasks":
		return h.serveActuatorScheduledtasks(w)
	case sub == "httptrace":
		return h.serveActuatorHttptrace(w)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000+00:00"),
			"status":    404,
			"error":     "Not Found",
			"path":      path,
		})
		return http.StatusNotFound
	}
}

func (h *Handler) writeActuatorJSON(w http.ResponseWriter, data interface{}) int {
	w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v3+json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data)
	return http.StatusOK
}

// --- /actuator/ --- Actuator index

func (h *Handler) serveActuatorIndex(w http.ResponseWriter) int {
	type link struct {
		Href      string `json:"href"`
		Templated bool   `json:"templated"`
	}
	data := map[string]interface{}{
		"_links": map[string]interface{}{
			"self":           link{Href: "/actuator", Templated: false},
			"health":         link{Href: "/actuator/health", Templated: false},
			"health-path":    link{Href: "/actuator/health/{*path}", Templated: true},
			"info":           link{Href: "/actuator/info", Templated: false},
			"env":            link{Href: "/actuator/env", Templated: false},
			"env-toMatch":    link{Href: "/actuator/env/{toMatch}", Templated: true},
			"beans":          link{Href: "/actuator/beans", Templated: false},
			"mappings":       link{Href: "/actuator/mappings", Templated: false},
			"metrics":        link{Href: "/actuator/metrics", Templated: false},
			"metrics-requiredMetricName": link{Href: "/actuator/metrics/{requiredMetricName}", Templated: true},
			"configprops":    link{Href: "/actuator/configprops", Templated: false},
			"configprops-prefix": link{Href: "/actuator/configprops/{prefix}", Templated: true},
			"loggers":        link{Href: "/actuator/loggers", Templated: false},
			"loggers-name":   link{Href: "/actuator/loggers/{name}", Templated: true},
			"threaddump":     link{Href: "/actuator/threaddump", Templated: false},
			"heapdump":       link{Href: "/actuator/heapdump", Templated: false},
			"conditions":     link{Href: "/actuator/conditions", Templated: false},
			"scheduledtasks": link{Href: "/actuator/scheduledtasks", Templated: false},
			"httptrace":      link{Href: "/actuator/httptrace", Templated: false},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/health --- Health with component details

func (h *Handler) serveActuatorHealth(w http.ResponseWriter) int {
	uptime := time.Since(h.startTime)
	data := map[string]interface{}{
		"status": "UP",
		"components": map[string]interface{}{
			"db": map[string]interface{}{
				"status": "UP",
				"details": map[string]interface{}{
					"database": "PostgreSQL",
					"validationQuery": "isValid()",
				},
			},
			"diskSpace": map[string]interface{}{
				"status": "UP",
				"details": map[string]interface{}{
					"total":     214748364800,
					"free":      161061273600,
					"threshold":  10485760,
					"path":      "/opt/app/.",
					"exists":    true,
				},
			},
			"ping": map[string]interface{}{
				"status": "UP",
			},
			"redis": map[string]interface{}{
				"status": "UP",
				"details": map[string]interface{}{
					"version":                "7.2.3",
					"cluster_enabled":        false,
					"connected_clients":      12,
					"used_memory_human":      "4.52M",
					"maxmemory_human":        "256M",
				},
			},
			"rabbit": map[string]interface{}{
				"status": "UP",
				"details": map[string]interface{}{
					"version": "3.12.10",
					"nodes":   []string{"rabbit@prod-mq-01"},
				},
			},
			"livenessState": map[string]interface{}{
				"status": "UP",
			},
			"readinessState": map[string]interface{}{
				"status": "UP",
			},
		},
		"groups": []string{"liveness", "readiness"},
		"uptime": int(uptime.Seconds()),
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/info --- Application info

func (h *Handler) serveActuatorInfo(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"app": map[string]interface{}{
			"name":        "acme-application",
			"description": "ACME Enterprise Application Service",
			"version":     "2.4.1",
			"encoding":    "UTF-8",
		},
		"git": map[string]interface{}{
			"branch": "main",
			"commit": map[string]interface{}{
				"id":   "a1b2c3d",
				"time": "2024-12-15T10:30:00Z",
			},
			"build": map[string]interface{}{
				"version": "2.4.1",
				"time":    "2024-12-15T10:35:22Z",
			},
		},
		"java": map[string]interface{}{
			"version": "17.0.9",
			"vendor": map[string]interface{}{
				"name":    "Eclipse Adoptium",
				"version": "Temurin-17.0.9+9",
			},
			"runtime": map[string]interface{}{
				"name":    "OpenJDK Runtime Environment",
				"version": "17.0.9+9",
			},
			"jvm": map[string]interface{}{
				"name":    "OpenJDK 64-Bit Server VM",
				"vendor":  "Eclipse Adoptium",
				"version": "17.0.9+9",
			},
		},
		"os": map[string]interface{}{
			"name":    "Linux",
			"version": "6.1.0-25-amd64",
			"arch":    "amd64",
		},
		"spring-boot": map[string]interface{}{
			"version": "3.2.1",
		},
		"spring": map[string]interface{}{
			"version": "6.1.2",
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/env --- Environment properties

func (h *Handler) serveActuatorEnv(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"activeProfiles": []string{"production", "cloud"},
		"propertySources": []map[string]interface{}{
			{
				"name": "systemProperties",
				"properties": map[string]interface{}{
					"java.runtime.name":    map[string]string{"value": "OpenJDK Runtime Environment"},
					"java.vm.version":      map[string]string{"value": "17.0.9+9"},
					"java.vm.vendor":       map[string]string{"value": "Eclipse Adoptium"},
					"java.home":            map[string]string{"value": "/opt/java/openjdk"},
					"java.version":         map[string]string{"value": "17.0.9"},
					"file.encoding":        map[string]string{"value": "UTF-8"},
					"os.name":              map[string]string{"value": "Linux"},
					"os.version":           map[string]string{"value": "6.1.0-25-amd64"},
					"os.arch":              map[string]string{"value": "amd64"},
					"user.timezone":        map[string]string{"value": "UTC"},
					"PID":                  map[string]string{"value": "1"},
				},
			},
			{
				"name": "systemEnvironment",
				"properties": map[string]interface{}{
					"JAVA_HOME":      map[string]string{"value": "/opt/java/openjdk"},
					"SPRING_PROFILES_ACTIVE": map[string]string{"value": "production,cloud"},
					"SERVER_PORT":    map[string]string{"value": "8080"},
					"LANG":           map[string]string{"value": "en_US.UTF-8"},
					"TZ":             map[string]string{"value": "UTC"},
					"HOSTNAME":       map[string]string{"value": "prod-app-7b9f5d4c6-x2k4m"},
				},
			},
			{
				"name": "Config resource 'class path resource [application.yml]'",
				"properties": map[string]interface{}{
					"spring.application.name":    map[string]string{"value": "acme-application"},
					"spring.datasource.url":      map[string]string{"value": "******"},
					"spring.datasource.username": map[string]string{"value": "******"},
					"spring.redis.host":          map[string]string{"value": "redis-master.default.svc.cluster.local"},
					"spring.redis.port":          map[string]string{"value": "6379"},
					"spring.rabbitmq.host":       map[string]string{"value": "rabbitmq.default.svc.cluster.local"},
					"server.port":                map[string]string{"value": "8080"},
					"management.endpoints.web.exposure.include": map[string]string{"value": "*"},
					"logging.level.root":         map[string]string{"value": "INFO"},
					"logging.level.org.springframework": map[string]string{"value": "WARN"},
				},
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/beans --- Spring beans

func (h *Handler) serveActuatorBeans(w http.ResponseWriter) int {
	type beanDef struct {
		Aliases      []string `json:"aliases"`
		Scope        string   `json:"scope"`
		Type         string   `json:"type"`
		Resource     string   `json:"resource"`
		Dependencies []string `json:"dependencies"`
	}
	data := map[string]interface{}{
		"contexts": map[string]interface{}{
			"acme-application": map[string]interface{}{
				"beans": map[string]beanDef{
					"userController": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.controller.UserController",
						Resource:     "file [/opt/app/classes/com/acme/application/controller/UserController.class]",
						Dependencies: []string{"userService", "authService"},
					},
					"authController": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.controller.AuthController",
						Resource:     "file [/opt/app/classes/com/acme/application/controller/AuthController.class]",
						Dependencies: []string{"authService", "tokenProvider"},
					},
					"productController": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.controller.ProductController",
						Resource:     "file [/opt/app/classes/com/acme/application/controller/ProductController.class]",
						Dependencies: []string{"productService"},
					},
					"userService": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.service.UserServiceImpl",
						Resource:     "file [/opt/app/classes/com/acme/application/service/UserServiceImpl.class]",
						Dependencies: []string{"userRepository", "passwordEncoder", "eventPublisher"},
					},
					"authService": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.service.AuthServiceImpl",
						Resource:     "file [/opt/app/classes/com/acme/application/service/AuthServiceImpl.class]",
						Dependencies: []string{"userRepository", "tokenProvider", "passwordEncoder"},
					},
					"productService": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.service.ProductServiceImpl",
						Resource:     "file [/opt/app/classes/com/acme/application/service/ProductServiceImpl.class]",
						Dependencies: []string{"productRepository", "cacheManager"},
					},
					"orderService": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.service.OrderServiceImpl",
						Resource:     "file [/opt/app/classes/com/acme/application/service/OrderServiceImpl.class]",
						Dependencies: []string{"orderRepository", "productService", "eventPublisher"},
					},
					"tokenProvider": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.security.JwtTokenProvider",
						Resource:     "file [/opt/app/classes/com/acme/application/security/JwtTokenProvider.class]",
						Dependencies: []string{},
					},
					"passwordEncoder": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder",
						Resource:     "class path resource [com/acme/application/config/SecurityConfig.class]",
						Dependencies: []string{},
					},
					"dataSource": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.zaxxer.hikari.HikariDataSource",
						Resource:     "class path resource [org/springframework/boot/autoconfigure/jdbc/DataSourceConfiguration$Hikari.class]",
						Dependencies: []string{},
					},
					"entityManagerFactory": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean",
						Resource:     "class path resource [org/springframework/boot/autoconfigure/orm/jpa/HibernateJpaConfiguration.class]",
						Dependencies: []string{"dataSource"},
					},
					"transactionManager": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.orm.jpa.JpaTransactionManager",
						Resource:     "class path resource [org/springframework/boot/autoconfigure/orm/jpa/HibernateJpaConfiguration.class]",
						Dependencies: []string{"entityManagerFactory"},
					},
					"userRepository": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.repository.UserRepository",
						Resource:     "null",
						Dependencies: []string{"jpaMappingContext", "entityManagerFactory"},
					},
					"productRepository": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.repository.ProductRepository",
						Resource:     "null",
						Dependencies: []string{"jpaMappingContext", "entityManagerFactory"},
					},
					"orderRepository": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.repository.OrderRepository",
						Resource:     "null",
						Dependencies: []string{"jpaMappingContext", "entityManagerFactory"},
					},
					"cacheManager": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.data.redis.cache.RedisCacheManager",
						Resource:     "class path resource [com/acme/application/config/CacheConfig.class]",
						Dependencies: []string{"redisConnectionFactory"},
					},
					"redisConnectionFactory": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory",
						Resource:     "class path resource [org/springframework/boot/autoconfigure/data/redis/LettuceConnectionConfiguration.class]",
						Dependencies: []string{},
					},
					"rabbitTemplate": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "org.springframework.amqp.rabbit.core.RabbitTemplate",
						Resource:     "class path resource [org/springframework/boot/autoconfigure/amqp/RabbitAutoConfiguration$RabbitTemplateConfiguration.class]",
						Dependencies: []string{"rabbitConnectionFactory"},
					},
					"eventPublisher": {
						Aliases:      []string{},
						Scope:        "singleton",
						Type:         "com.acme.application.event.EventPublisherImpl",
						Resource:     "file [/opt/app/classes/com/acme/application/event/EventPublisherImpl.class]",
						Dependencies: []string{"rabbitTemplate"},
					},
				},
				"parentId": nil,
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/mappings --- Request mappings

func (h *Handler) serveActuatorMappings(w http.ResponseWriter) int {
	type handlerMethod struct {
		ClassName  string `json:"className"`
		Name       string `json:"name"`
		Descriptor string `json:"descriptor"`
	}
	type requestMapping struct {
		Handler    string          `json:"handler"`
		Predicate  string          `json:"predicate"`
		Details    map[string]interface{} `json:"details"`
	}
	type dispatcherMapping struct {
		Handler        string `json:"handler"`
		Predicate      string `json:"predicate"`
		HandlerMethod  handlerMethod `json:"handlerMethod,omitempty"`
	}

	mappings := []map[string]interface{}{
		{
			"handler":   "com.acme.application.controller.UserController#getUsers(Pageable)",
			"predicate": "{GET [/api/v1/users], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.UserController",
					"name":       "getUsers",
					"descriptor": "(Lorg/springframework/data/domain/Pageable;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"consumes":  []string{},
					"headers":   []string{},
					"methods":   []string{"GET"},
					"params":    []string{},
					"patterns":  []string{"/api/v1/users"},
					"produces":  []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.UserController#getUserById(Long)",
			"predicate": "{GET [/api/v1/users/{id}], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.UserController",
					"name":       "getUserById",
					"descriptor": "(Ljava/lang/Long;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"GET"},
					"patterns": []string{"/api/v1/users/{id}"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.UserController#createUser(CreateUserRequest)",
			"predicate": "{POST [/api/v1/users], consumes [application/json], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.UserController",
					"name":       "createUser",
					"descriptor": "(Lcom/acme/application/dto/CreateUserRequest;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"POST"},
					"patterns": []string{"/api/v1/users"},
					"consumes": []string{"application/json"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.AuthController#login(LoginRequest)",
			"predicate": "{POST [/api/v1/auth/login], consumes [application/json], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.AuthController",
					"name":       "login",
					"descriptor": "(Lcom/acme/application/dto/LoginRequest;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"POST"},
					"patterns": []string{"/api/v1/auth/login"},
					"consumes": []string{"application/json"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.AuthController#refreshToken(RefreshTokenRequest)",
			"predicate": "{POST [/api/v1/auth/refresh], consumes [application/json], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.AuthController",
					"name":       "refreshToken",
					"descriptor": "(Lcom/acme/application/dto/RefreshTokenRequest;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"POST"},
					"patterns": []string{"/api/v1/auth/refresh"},
					"consumes": []string{"application/json"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.ProductController#getProducts(Pageable, ProductFilter)",
			"predicate": "{GET [/api/v1/products], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.ProductController",
					"name":       "getProducts",
					"descriptor": "(Lorg/springframework/data/domain/Pageable;Lcom/acme/application/dto/ProductFilter;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"GET"},
					"patterns": []string{"/api/v1/products"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "com.acme.application.controller.ProductController#getProductById(Long)",
			"predicate": "{GET [/api/v1/products/{id}], produces [application/json]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className":  "com.acme.application.controller.ProductController",
					"name":       "getProductById",
					"descriptor": "(Ljava/lang/Long;)Lorg/springframework/http/ResponseEntity;",
				},
				"requestMappingConditions": map[string]interface{}{
					"methods":  []string{"GET"},
					"patterns": []string{"/api/v1/products/{id}"},
					"produces": []string{"application/json"},
				},
			},
		},
		{
			"handler":   "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#errorHtml(HttpServletRequest, HttpServletResponse)",
			"predicate": "{GET /error, produces [text/html]}",
			"details": map[string]interface{}{
				"handlerMethod": map[string]string{
					"className": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController",
					"name":      "errorHtml",
				},
			},
		},
	}

	data := map[string]interface{}{
		"contexts": map[string]interface{}{
			"acme-application": map[string]interface{}{
				"mappings": map[string]interface{}{
					"dispatcherServlets": map[string]interface{}{
						"dispatcherServlet": mappings,
					},
				},
				"parentId": nil,
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/metrics --- Available metrics list

func (h *Handler) serveActuatorMetrics(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"names": []string{
			"application.ready.time",
			"application.started.time",
			"disk.free",
			"disk.total",
			"executor.active",
			"executor.completed",
			"executor.pool.core",
			"executor.pool.max",
			"executor.pool.size",
			"executor.queue.remaining",
			"executor.queued",
			"hikaricp.connections",
			"hikaricp.connections.active",
			"hikaricp.connections.idle",
			"hikaricp.connections.max",
			"hikaricp.connections.min",
			"hikaricp.connections.pending",
			"http.server.requests",
			"http.server.requests.active",
			"jvm.buffer.count",
			"jvm.buffer.memory.used",
			"jvm.buffer.total.capacity",
			"jvm.classes.loaded",
			"jvm.classes.unloaded",
			"jvm.compilation.time",
			"jvm.gc.live.data.size",
			"jvm.gc.max.data.size",
			"jvm.gc.memory.allocated",
			"jvm.gc.memory.promoted",
			"jvm.gc.overhead",
			"jvm.gc.pause",
			"jvm.info",
			"jvm.memory.committed",
			"jvm.memory.max",
			"jvm.memory.usage.after.gc",
			"jvm.memory.used",
			"jvm.threads.daemon",
			"jvm.threads.live",
			"jvm.threads.peak",
			"jvm.threads.started",
			"jvm.threads.states",
			"logback.events",
			"process.cpu.usage",
			"process.files.max",
			"process.files.open",
			"process.start.time",
			"process.uptime",
			"spring.data.repository.invocations",
			"system.cpu.count",
			"system.cpu.usage",
			"system.load.average.1m",
			"tomcat.sessions.active.current",
			"tomcat.sessions.active.max",
			"tomcat.sessions.created",
			"tomcat.sessions.expired",
			"tomcat.sessions.rejected",
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/metrics/{name} --- Individual metric value

func (h *Handler) serveActuatorMetricDetail(w http.ResponseWriter, name string) int {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	uptime := time.Since(h.startTime).Seconds()

	knownMetrics := map[string]interface{}{
		"jvm.memory.used": map[string]interface{}{
			"name":        "jvm.memory.used",
			"description": "The amount of used memory",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": mem.HeapAlloc + mem.StackInuse},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "area", "values": []string{"heap", "nonheap"}},
				{"tag": "id", "values": []string{"G1 Eden Space", "G1 Old Gen", "G1 Survivor Space", "Metaspace", "CodeCache", "Compressed Class Space"}},
			},
		},
		"jvm.memory.max": map[string]interface{}{
			"name":        "jvm.memory.max",
			"description": "The maximum amount of memory in bytes that can be used for memory management",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": mem.HeapSys * 4},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "area", "values": []string{"heap", "nonheap"}},
				{"tag": "id", "values": []string{"G1 Eden Space", "G1 Old Gen", "G1 Survivor Space", "Metaspace", "CodeCache"}},
			},
		},
		"jvm.memory.committed": map[string]interface{}{
			"name":        "jvm.memory.committed",
			"description": "The amount of memory in bytes that is committed for the JVM to use",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": mem.HeapSys},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "area", "values": []string{"heap", "nonheap"}},
			},
		},
		"http.server.requests": map[string]interface{}{
			"name":        "http.server.requests",
			"description": "Duration of HTTP server request handling",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "COUNT", "value": int(uptime*2.5) + 42},
				{"statistic": "TOTAL_TIME", "value": uptime * 0.15},
				{"statistic": "MAX", "value": 0.287},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "exception", "values": []string{"None", "RuntimeException", "IOException"}},
				{"tag": "method", "values": []string{"GET", "POST", "PUT", "DELETE"}},
				{"tag": "uri", "values": []string{"/api/v1/users", "/api/v1/users/{id}", "/api/v1/products", "/api/v1/auth/login"}},
				{"tag": "outcome", "values": []string{"SUCCESS", "CLIENT_ERROR", "SERVER_ERROR"}},
				{"tag": "status", "values": []string{"200", "201", "400", "401", "403", "404", "500"}},
			},
		},
		"process.uptime": map[string]interface{}{
			"name":        "process.uptime",
			"description": "The uptime of the Java virtual machine",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": uptime},
			},
			"availableTags": []map[string]interface{}{},
		},
		"process.cpu.usage": map[string]interface{}{
			"name":        "process.cpu.usage",
			"description": "The recent CPU usage for the JVM process",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 0.0342},
			},
			"availableTags": []map[string]interface{}{},
		},
		"system.cpu.usage": map[string]interface{}{
			"name":        "system.cpu.usage",
			"description": "The recent CPU usage of the system the application is running in",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 0.1247},
			},
			"availableTags": []map[string]interface{}{},
		},
		"system.cpu.count": map[string]interface{}{
			"name":        "system.cpu.count",
			"description": "The number of processors available to the JVM",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": runtime.NumCPU()},
			},
			"availableTags": []map[string]interface{}{},
		},
		"jvm.threads.live": map[string]interface{}{
			"name":        "jvm.threads.live",
			"description": "The current number of live threads including both daemon and non-daemon threads",
			"baseUnit":    "threads",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": runtime.NumGoroutine() + 22},
			},
			"availableTags": []map[string]interface{}{},
		},
		"jvm.threads.peak": map[string]interface{}{
			"name":        "jvm.threads.peak",
			"description": "The peak live thread count since the JVM started",
			"baseUnit":    "threads",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": runtime.NumGoroutine() + 35},
			},
			"availableTags": []map[string]interface{}{},
		},
		"jvm.threads.daemon": map[string]interface{}{
			"name":        "jvm.threads.daemon",
			"description": "The current number of live daemon threads",
			"baseUnit":    "threads",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": runtime.NumGoroutine() + 18},
			},
			"availableTags": []map[string]interface{}{},
		},
		"jvm.gc.pause": map[string]interface{}{
			"name":        "jvm.gc.pause",
			"description": "Time spent in GC pause",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "COUNT", "value": mem.NumGC},
				{"statistic": "TOTAL_TIME", "value": float64(mem.PauseTotalNs) / 1e9},
				{"statistic": "MAX", "value": 0.012},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "action", "values": []string{"end of minor GC", "end of major GC"}},
				{"tag": "cause", "values": []string{"G1 Evacuation Pause", "Metadata GC Threshold"}},
			},
		},
		"jvm.gc.live.data.size": map[string]interface{}{
			"name":        "jvm.gc.live.data.size",
			"description": "Size of long-lived heap memory pool after reclamation",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": mem.HeapInuse},
			},
			"availableTags": []map[string]interface{}{},
		},
		"jvm.classes.loaded": map[string]interface{}{
			"name":        "jvm.classes.loaded",
			"description": "The number of classes that are currently loaded in the JVM",
			"baseUnit":    "classes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 14892},
			},
			"availableTags": []map[string]interface{}{},
		},
		"disk.free": map[string]interface{}{
			"name":        "disk.free",
			"description": "Usable space for path",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 161061273600},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "path", "values": []string{"/opt/app/."}},
			},
		},
		"disk.total": map[string]interface{}{
			"name":        "disk.total",
			"description": "Total space for path",
			"baseUnit":    "bytes",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 214748364800},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "path", "values": []string{"/opt/app/."}},
			},
		},
		"process.start.time": map[string]interface{}{
			"name":        "process.start.time",
			"description": "Start time of the process since unix epoch",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": float64(h.startTime.Unix())},
			},
			"availableTags": []map[string]interface{}{},
		},
		"logback.events": map[string]interface{}{
			"name":        "logback.events",
			"description": "Number of events that made it to the logs",
			"baseUnit":    "events",
			"measurements": []map[string]interface{}{
				{"statistic": "COUNT", "value": int(uptime*1.2) + 150},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "level", "values": []string{"trace", "debug", "info", "warn", "error"}},
			},
		},
		"hikaricp.connections.active": map[string]interface{}{
			"name":        "hikaricp.connections.active",
			"description": "Active connections",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 3},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "pool", "values": []string{"HikariPool-1"}},
			},
		},
		"hikaricp.connections.idle": map[string]interface{}{
			"name":        "hikaricp.connections.idle",
			"description": "Idle connections",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 7},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "pool", "values": []string{"HikariPool-1"}},
			},
		},
		"hikaricp.connections.max": map[string]interface{}{
			"name":        "hikaricp.connections.max",
			"description": "Max connections",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 10},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "pool", "values": []string{"HikariPool-1"}},
			},
		},
		"tomcat.sessions.active.current": map[string]interface{}{
			"name":        "tomcat.sessions.active.current",
			"description": "Current active sessions",
			"baseUnit":    "sessions",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 0},
			},
			"availableTags": []map[string]interface{}{},
		},
		"application.ready.time": map[string]interface{}{
			"name":        "application.ready.time",
			"description": "Time taken for the application to be ready to service requests",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 3.847},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "main.application.class", "values": []string{"com.acme.application.AcmeApplication"}},
			},
		},
		"application.started.time": map[string]interface{}{
			"name":        "application.started.time",
			"description": "Time taken to start the application",
			"baseUnit":    "seconds",
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 3.621},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "main.application.class", "values": []string{"com.acme.application.AcmeApplication"}},
			},
		},
		"jvm.info": map[string]interface{}{
			"name":        "jvm.info",
			"description": "JVM version info",
			"baseUnit":    nil,
			"measurements": []map[string]interface{}{
				{"statistic": "VALUE", "value": 1.0},
			},
			"availableTags": []map[string]interface{}{
				{"tag": "version", "values": []string{"17.0.9+9"}},
				{"tag": "vendor", "values": []string{"Eclipse Adoptium"}},
				{"tag": "runtime", "values": []string{"OpenJDK Runtime Environment"}},
			},
		},
	}

	metric, ok := knownMetrics[name]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000+00:00"),
			"status":    404,
			"error":     "Not Found",
			"message":   fmt.Sprintf("No endpoint mapping found for metric '%s'", name),
			"path":      "/actuator/metrics/" + name,
		})
		return http.StatusNotFound
	}

	return h.writeActuatorJSON(w, metric)
}

// --- /actuator/configprops --- Configuration properties

func (h *Handler) serveActuatorConfigprops(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"contexts": map[string]interface{}{
			"acme-application": map[string]interface{}{
				"beans": map[string]interface{}{
					"spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties": map[string]interface{}{
						"prefix": "spring.datasource",
						"properties": map[string]interface{}{
							"url":                 "jdbc:postgresql://db-master.internal:5432/acme_prod",
							"username":            "******",
							"password":            "******",
							"driverClassName":     "org.postgresql.Driver",
							"type":                "com.zaxxer.hikari.HikariDataSource",
							"generateUniqueName":  false,
						},
					},
					"spring.jpa-org.springframework.boot.autoconfigure.orm.jpa.JpaProperties": map[string]interface{}{
						"prefix": "spring.jpa",
						"properties": map[string]interface{}{
							"database":          "POSTGRESQL",
							"openInView":        false,
							"showSql":           false,
							"generateDdl":       false,
							"databasePlatform":  "org.hibernate.dialect.PostgreSQLDialect",
							"properties": map[string]string{
								"hibernate.format_sql":    "true",
								"hibernate.default_schema": "public",
								"hibernate.jdbc.batch_size": "50",
							},
						},
					},
					"spring.data.redis-org.springframework.boot.autoconfigure.data.redis.RedisProperties": map[string]interface{}{
						"prefix": "spring.data.redis",
						"properties": map[string]interface{}{
							"host":     "redis-master.default.svc.cluster.local",
							"port":     6379,
							"database": 0,
							"password": "******",
							"timeout":  "2000ms",
							"lettuce": map[string]interface{}{
								"pool": map[string]interface{}{
									"maxActive": 8,
									"maxIdle":   8,
									"minIdle":   2,
									"maxWait":   "-1ms",
								},
							},
						},
					},
					"spring.rabbitmq-org.springframework.boot.autoconfigure.amqp.RabbitProperties": map[string]interface{}{
						"prefix": "spring.rabbitmq",
						"properties": map[string]interface{}{
							"host":        "rabbitmq.default.svc.cluster.local",
							"port":        5672,
							"username":    "******",
							"password":    "******",
							"virtualHost": "/",
						},
					},
					"management.endpoints.web-org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointProperties": map[string]interface{}{
						"prefix": "management.endpoints.web",
						"properties": map[string]interface{}{
							"basePath": "/actuator",
							"exposure": map[string]interface{}{
								"include": []string{"*"},
								"exclude": []string{},
							},
						},
					},
					"server-org.springframework.boot.autoconfigure.web.ServerProperties": map[string]interface{}{
						"prefix": "server",
						"properties": map[string]interface{}{
							"port":        8080,
							"contextPath": "/",
							"tomcat": map[string]interface{}{
								"maxThreads":         200,
								"minSpareThreads":    10,
								"maxConnections":     8192,
								"acceptCount":        100,
								"connectionTimeout":  "20000ms",
							},
						},
					},
				},
				"parentId": nil,
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/loggers --- Logger levels

func (h *Handler) serveActuatorLoggers(w http.ResponseWriter) int {
	type loggerLevel struct {
		ConfiguredLevel *string `json:"configuredLevel"`
		EffectiveLevel  string  `json:"effectiveLevel"`
	}
	infoLevel := "INFO"
	warnLevel := "WARN"
	debugLevel := "DEBUG"
	errorLevel := "ERROR"

	data := map[string]interface{}{
		"levels": []string{"OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"},
		"loggers": map[string]loggerLevel{
			"ROOT":                                          {ConfiguredLevel: &infoLevel, EffectiveLevel: "INFO"},
			"com.acme":                                      {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application":                          {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application.controller":               {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application.service":                  {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application.repository":               {ConfiguredLevel: &debugLevel, EffectiveLevel: "DEBUG"},
			"com.acme.application.security":                 {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application.config":                   {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"com.acme.application.event":                    {ConfiguredLevel: nil, EffectiveLevel: "INFO"},
			"org.springframework":                           {ConfiguredLevel: &warnLevel, EffectiveLevel: "WARN"},
			"org.springframework.web":                       {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.springframework.security":                  {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.springframework.boot":                      {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.springframework.data":                      {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.springframework.orm.jpa":                   {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.hibernate":                                 {ConfiguredLevel: &warnLevel, EffectiveLevel: "WARN"},
			"org.hibernate.SQL":                             {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.hibernate.type.descriptor.sql.BasicBinder": {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.apache.tomcat":                             {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"org.apache.catalina":                           {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"io.lettuce":                                    {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"com.zaxxer.hikari":                             {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
			"com.zaxxer.hikari.pool":                        {ConfiguredLevel: &errorLevel, EffectiveLevel: "ERROR"},
			"org.springframework.amqp":                      {ConfiguredLevel: nil, EffectiveLevel: "WARN"},
		},
		"groups": map[string]interface{}{
			"web": map[string]interface{}{
				"configuredLevel": nil,
				"members": []string{
					"org.springframework.core.codec",
					"org.springframework.http",
					"org.springframework.web",
					"org.springframework.boot.actuate.endpoint.web",
					"org.springframework.boot.web.servlet.ServletContextInitializerBeans",
				},
			},
			"sql": map[string]interface{}{
				"configuredLevel": nil,
				"members": []string{
					"org.springframework.jdbc.core",
					"org.hibernate.SQL",
					"org.jooq.tools.LoggerListener",
				},
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/threaddump --- Thread dump (Java-style)

func (h *Handler) serveActuatorThreaddump(w http.ResponseWriter) int {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000+00:00")
	goroutines := runtime.NumGoroutine()

	threads := []map[string]interface{}{
		{
			"threadName":   "main",
			"threadId":     1,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  42,
			"lockOwnerId":  -1,
			"daemon":       false,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "RUNNABLE",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "java.lang.Thread", "methodName": "dumpThreads", "fileName": "Thread.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.lang.Thread", "methodName": "getAllStackTraces", "fileName": "Thread.java", "lineNumber": 1610, "nativeMethod": false},
				{"className": "org.springframework.boot.actuate.management.ThreadDumpEndpoint", "methodName": "getFormattedThreadDump", "fileName": "ThreadDumpEndpoint.java", "lineNumber": 51, "nativeMethod": false},
			},
		},
		{
			"threadName":   "http-nio-8080-exec-1",
			"threadId":     23,
			"blockedTime":  -1,
			"blockedCount": 2,
			"waitedTime":   -1,
			"waitedCount":  187,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "WAITING",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.misc.Unsafe", "methodName": "park", "fileName": "Unsafe.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.util.concurrent.locks.LockSupport", "methodName": "park", "fileName": "LockSupport.java", "lineNumber": 175, "nativeMethod": false},
				{"className": "java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject", "methodName": "await", "fileName": "AbstractQueuedSynchronizer.java", "lineNumber": 2039, "nativeMethod": false},
				{"className": "java.util.concurrent.LinkedBlockingQueue", "methodName": "take", "fileName": "LinkedBlockingQueue.java", "lineNumber": 442, "nativeMethod": false},
				{"className": "org.apache.tomcat.util.threads.TaskQueue", "methodName": "take", "fileName": "TaskQueue.java", "lineNumber": 117, "nativeMethod": false},
			},
		},
		{
			"threadName":   "http-nio-8080-exec-2",
			"threadId":     24,
			"blockedTime":  -1,
			"blockedCount": 1,
			"waitedTime":   -1,
			"waitedCount":  134,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "RUNNABLE",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.nio.ch.EPollSelectorImpl", "methodName": "doSelect", "fileName": "EPollSelectorImpl.java", "lineNumber": 120, "nativeMethod": false},
				{"className": "sun.nio.ch.SelectorImpl", "methodName": "lockAndDoSelect", "fileName": "SelectorImpl.java", "lineNumber": 124, "nativeMethod": false},
				{"className": "sun.nio.ch.SelectorImpl", "methodName": "select", "fileName": "SelectorImpl.java", "lineNumber": 136, "nativeMethod": false},
				{"className": "org.apache.tomcat.util.net.NioEndpoint$Poller", "methodName": "run", "fileName": "NioEndpoint.java", "lineNumber": 709, "nativeMethod": false},
			},
		},
		{
			"threadName":   "HikariPool-1 housekeeper",
			"threadId":     30,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  98,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "TIMED_WAITING",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.misc.Unsafe", "methodName": "park", "fileName": "Unsafe.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.util.concurrent.locks.LockSupport", "methodName": "parkNanos", "fileName": "LockSupport.java", "lineNumber": 215, "nativeMethod": false},
				{"className": "java.util.concurrent.ScheduledThreadPoolExecutor$DelayedWorkQueue", "methodName": "take", "fileName": "ScheduledThreadPoolExecutor.java", "lineNumber": 1182, "nativeMethod": false},
				{"className": "com.zaxxer.hikari.pool.HikariPool$HouseKeeper", "methodName": "run", "fileName": "HikariPool.java", "lineNumber": 399, "nativeMethod": false},
			},
		},
		{
			"threadName":   "lettuce-nioEventLoop-1-1",
			"threadId":     35,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  0,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     true,
			"suspended":    false,
			"threadState":  "RUNNABLE",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.nio.ch.EPoll", "methodName": "wait", "fileName": "EPoll.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "sun.nio.ch.EPollSelectorImpl", "methodName": "doSelect", "fileName": "EPollSelectorImpl.java", "lineNumber": 118, "nativeMethod": false},
				{"className": "io.netty.channel.nio.NioEventLoop", "methodName": "run", "fileName": "NioEventLoop.java", "lineNumber": 569, "nativeMethod": false},
			},
		},
		{
			"threadName":   "scheduling-1",
			"threadId":     40,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  56,
			"lockOwnerId":  -1,
			"daemon":       false,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "TIMED_WAITING",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.misc.Unsafe", "methodName": "park", "fileName": "Unsafe.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.util.concurrent.locks.LockSupport", "methodName": "parkNanos", "fileName": "LockSupport.java", "lineNumber": 215, "nativeMethod": false},
				{"className": "java.util.concurrent.ScheduledThreadPoolExecutor$DelayedWorkQueue", "methodName": "take", "fileName": "ScheduledThreadPoolExecutor.java", "lineNumber": 1182, "nativeMethod": false},
				{"className": "org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler", "methodName": "run", "fileName": "ThreadPoolTaskScheduler.java", "lineNumber": 315, "nativeMethod": false},
			},
		},
		{
			"threadName":   "GC Thread#0",
			"threadId":     2,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  0,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "RUNNABLE",
			"priority":     9,
			"stackTrace":   []map[string]interface{}{},
		},
		{
			"threadName":   "Finalizer",
			"threadId":     3,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  12,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "WAITING",
			"priority":     8,
			"stackTrace": []map[string]interface{}{
				{"className": "java.lang.Object", "methodName": "wait", "fileName": "Object.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.lang.ref.ReferenceQueue", "methodName": "remove", "fileName": "ReferenceQueue.java", "lineNumber": 155, "nativeMethod": false},
				{"className": "java.lang.ref.Finalizer$FinalizerThread", "methodName": "run", "fileName": "Finalizer.java", "lineNumber": 216, "nativeMethod": false},
			},
		},
		{
			"threadName":   "Signal Dispatcher",
			"threadId":     4,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  0,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "RUNNABLE",
			"priority":     9,
			"stackTrace":   []map[string]interface{}{},
		},
		{
			"threadName":   "RabbitMQ Consumer-1",
			"threadId":     45,
			"blockedTime":  -1,
			"blockedCount": 0,
			"waitedTime":   -1,
			"waitedCount":  320,
			"lockOwnerId":  -1,
			"daemon":       true,
			"inNative":     false,
			"suspended":    false,
			"threadState":  "WAITING",
			"priority":     5,
			"stackTrace": []map[string]interface{}{
				{"className": "sun.misc.Unsafe", "methodName": "park", "fileName": "Unsafe.java", "lineNumber": -2, "nativeMethod": true},
				{"className": "java.util.concurrent.locks.LockSupport", "methodName": "park", "fileName": "LockSupport.java", "lineNumber": 175, "nativeMethod": false},
				{"className": "com.rabbitmq.client.impl.ConsumerWorkService$WorkPoolRunnable", "methodName": "run", "fileName": "ConsumerWorkService.java", "lineNumber": 104, "nativeMethod": false},
			},
		},
	}

	data := map[string]interface{}{
		"timestamp": now,
		"threads":   threads,
		"threadCount": goroutines + len(threads),
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/heapdump --- Fake binary heap dump

func (h *Handler) serveActuatorHeapdump(w http.ResponseWriter) int {
	// Java heap dump files start with "JAVA PROFILE 1.0.2" header
	header := []byte("JAVA PROFILE 1.0.2\x00")
	// Append some fake binary data to make it look like a real heap dump
	fakeData := make([]byte, 256)
	rand.Read(fakeData)

	// Tag: HPROF_UTF8 (0x01), followed by timestamp and length fields
	fakeData[0] = 0x01 // tag
	fakeData[1] = 0x00 // time high
	fakeData[2] = 0x00
	fakeData[3] = 0x00
	fakeData[4] = 0x00 // time low
	fakeData[5] = 0x00
	fakeData[6] = 0x00
	fakeData[7] = 0x00
	fakeData[8] = 0x10 // length

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"heapdump\"")
	w.WriteHeader(http.StatusOK)
	w.Write(header)
	w.Write(fakeData)
	return http.StatusOK
}

// --- /actuator/conditions --- Auto-configuration conditions report

func (h *Handler) serveActuatorConditions(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"contexts": map[string]interface{}{
			"acme-application": map[string]interface{}{
				"positiveMatches": map[string]interface{}{
					"DataSourceAutoConfiguration": []map[string]interface{}{
						{
							"condition": "DataSourceAvailableCondition",
							"message":   "DataSource available",
						},
					},
					"DataSourceAutoConfiguration.PooledDataSourceConfiguration": []map[string]interface{}{
						{
							"condition": "PooledDataSourceCondition",
							"message":   "AnyNestedCondition 1 matched 1 did not; NestedCondition on DataSourceAutoConfiguration.PooledDataSourceCondition.PooledDataSourceAvailable found supported DataSource",
						},
					},
					"HibernateJpaAutoConfiguration": []map[string]interface{}{
						{
							"condition": "HibernateEntityManagerCondition",
							"message":   "@ConditionalOnClass found required classes 'org.hibernate.engine.spi.SessionImplementor', 'jakarta.persistence.EntityManager'",
						},
					},
					"JpaRepositoriesAutoConfiguration": []map[string]interface{}{
						{
							"condition": "JpaRepositoriesAutoConfiguration.JpaRepositoriesImportSelector$JpaRepositoriesRegistrar$EnableJpaRepositoriesConfiguration",
							"message":   "@ConditionalOnBean (types: javax.sql.DataSource; SearchStrategy: all) found bean 'dataSource'",
						},
					},
					"RedisAutoConfiguration": []map[string]interface{}{
						{
							"condition": "OnClassCondition",
							"message":   "@ConditionalOnClass found required class 'org.springframework.data.redis.core.RedisOperations'",
						},
					},
					"RabbitAutoConfiguration": []map[string]interface{}{
						{
							"condition": "OnClassCondition",
							"message":   "@ConditionalOnClass found required classes 'com.rabbitmq.client.Channel', 'org.springframework.amqp.rabbit.core.RabbitTemplate'",
						},
					},
					"CacheAutoConfiguration": []map[string]interface{}{
						{
							"condition": "CacheCondition",
							"message":   "Cache org.springframework.boot.autoconfigure.cache.CacheCondition matched",
						},
					},
					"WebMvcAutoConfiguration": []map[string]interface{}{
						{
							"condition": "OnWebApplicationCondition",
							"message":   "found 'session' scope",
						},
					},
					"SecurityAutoConfiguration": []map[string]interface{}{
						{
							"condition": "OnClassCondition",
							"message":   "@ConditionalOnClass found required class 'org.springframework.security.authentication.DefaultAuthenticationEventPublisher'",
						},
					},
					"EmbeddedWebServerFactoryCustomizerAutoConfiguration.TomcatWebServerFactoryCustomizerConfiguration": []map[string]interface{}{
						{
							"condition": "OnClassCondition",
							"message":   "@ConditionalOnClass found required classes 'org.apache.catalina.startup.Tomcat', 'org.apache.coyote.UpgradeProtocol'",
						},
					},
				},
				"negativeMatches": map[string]interface{}{
					"MongoAutoConfiguration": map[string]interface{}{
						"notMatched": []map[string]interface{}{
							{
								"condition": "OnClassCondition",
								"message":   "@ConditionalOnClass did not find required class 'com.mongodb.client.MongoClient'",
							},
						},
						"matched": []map[string]interface{}{},
					},
					"CassandraAutoConfiguration": map[string]interface{}{
						"notMatched": []map[string]interface{}{
							{
								"condition": "OnClassCondition",
								"message":   "@ConditionalOnClass did not find required class 'com.datastax.oss.driver.api.core.CqlSession'",
							},
						},
						"matched": []map[string]interface{}{},
					},
					"ElasticsearchRestClientAutoConfiguration": map[string]interface{}{
						"notMatched": []map[string]interface{}{
							{
								"condition": "OnClassCondition",
								"message":   "@ConditionalOnClass did not find required class 'org.elasticsearch.client.RestClient'",
							},
						},
						"matched": []map[string]interface{}{},
					},
					"FlywayAutoConfiguration": map[string]interface{}{
						"notMatched": []map[string]interface{}{
							{
								"condition": "OnClassCondition",
								"message":   "@ConditionalOnClass did not find required class 'org.flywaydb.core.Flyway'",
							},
						},
						"matched": []map[string]interface{}{},
					},
					"ReactiveWebServerFactoryAutoConfiguration": map[string]interface{}{
						"notMatched": []map[string]interface{}{
							{
								"condition": "OnWebApplicationCondition",
								"message":   "not a reactive web application",
							},
						},
						"matched": []map[string]interface{}{},
					},
				},
				"unconditionalClasses": []string{
					"org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration",
					"org.springframework.boot.autoconfigure.context.LifecycleAutoConfiguration",
					"org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration",
					"org.springframework.boot.actuate.autoconfigure.info.InfoContributorAutoConfiguration",
					"org.springframework.boot.actuate.autoconfigure.metrics.MetricsAutoConfiguration",
					"org.springframework.boot.actuate.autoconfigure.endpoint.EndpointAutoConfiguration",
				},
				"parentId": nil,
			},
		},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/scheduledtasks --- Scheduled tasks

func (h *Handler) serveActuatorScheduledtasks(w http.ResponseWriter) int {
	data := map[string]interface{}{
		"cron": []map[string]interface{}{
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.MetricsCollector.collectMetrics",
				},
				"expression": "0 */5 * * * *",
			},
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.CacheWarmer.warmProductCache",
				},
				"expression": "0 0 */1 * * *",
			},
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.SessionCleaner.cleanExpiredSessions",
				},
				"expression": "0 0 2 * * *",
			},
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.ReportGenerator.generateDailyReport",
				},
				"expression": "0 30 6 * * MON-FRI",
			},
		},
		"fixedDelay": []map[string]interface{}{
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.HealthChecker.checkDependencies",
				},
				"initialDelay": 5000,
				"interval":     30000,
			},
		},
		"fixedRate": []map[string]interface{}{
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.EventProcessor.processEvents",
				},
				"initialDelay": 0,
				"interval":     10000,
			},
			{
				"runnable": map[string]string{
					"target": "com.acme.application.scheduler.QueueMonitor.checkQueueDepth",
				},
				"initialDelay": 1000,
				"interval":     60000,
			},
		},
		"custom": []map[string]interface{}{},
	}
	return h.writeActuatorJSON(w, data)
}

// --- /actuator/httptrace --- Recent HTTP traces

func (h *Handler) serveActuatorHttptrace(w http.ResponseWriter) int {
	now := time.Now().UTC()
	traces := make([]map[string]interface{}, 0, 20)

	type traceEntry struct {
		method string
		uri    string
		status int
		ms     int
		ua     string
	}
	sampleTraces := []traceEntry{
		{"GET", "/api/v1/users", 200, 12, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		{"GET", "/api/v1/products?page=0&size=20", 200, 34, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
		{"POST", "/api/v1/auth/login", 200, 87, "okhttp/4.12.0"},
		{"GET", "/api/v1/users/42", 200, 8, "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"},
		{"GET", "/api/v1/products/128", 200, 15, "PostmanRuntime/7.36.0"},
		{"PUT", "/api/v1/users/42", 200, 23, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
		{"GET", "/api/v1/orders?userId=42", 200, 45, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
		{"DELETE", "/api/v1/products/999", 404, 5, "curl/8.4.0"},
		{"POST", "/api/v1/users", 400, 3, "PostmanRuntime/7.36.0"},
		{"GET", "/api/v1/products?category=electronics", 200, 28, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)"},
		{"POST", "/api/v1/auth/refresh", 200, 42, "okhttp/4.12.0"},
		{"GET", "/actuator/health", 200, 2, "kube-probe/1.28"},
		{"GET", "/api/v1/users?role=ADMIN", 403, 6, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
		{"GET", "/api/v1/products", 200, 31, "python-requests/2.31.0"},
		{"POST", "/api/v1/orders", 201, 156, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
		{"GET", "/api/v1/users/99", 404, 4, "curl/8.4.0"},
		{"GET", "/api/v1/products/42/reviews", 200, 19, "Mozilla/5.0 (X11; Linux x86_64)"},
		{"PATCH", "/api/v1/users/42/preferences", 200, 11, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
		{"GET", "/actuator/health", 200, 1, "kube-probe/1.28"},
		{"GET", "/api/v1/products?sort=price,desc&page=2", 200, 38, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
	}

	for i, tr := range sampleTraces {
		ts := now.Add(-time.Duration(len(sampleTraces)-i) * 3 * time.Second)
		traces = append(traces, map[string]interface{}{
			"timestamp": ts.Format("2006-01-02T15:04:05.000+00:00"),
			"principal": nil,
			"session":   nil,
			"request": map[string]interface{}{
				"method":  tr.method,
				"uri":     "http://localhost:8080" + tr.uri,
				"headers": map[string][]string{
					"Accept":     {"application/json"},
					"User-Agent": {tr.ua},
					"Host":       {"localhost:8080"},
				},
			},
			"response": map[string]interface{}{
				"status": tr.status,
				"headers": map[string][]string{
					"Content-Type":           {"application/json"},
					"X-Content-Type-Options": {"nosniff"},
					"X-Frame-Options":        {"DENY"},
					"Cache-Control":          {"no-cache, no-store, max-age=0, must-revalidate"},
				},
			},
			"timeTaken": tr.ms,
		})
	}

	data := map[string]interface{}{
		"traces": traces,
	}
	return h.writeActuatorJSON(w, data)
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
