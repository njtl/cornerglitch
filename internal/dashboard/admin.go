package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Feature Flags — thread-safe toggles for server subsystems
// ---------------------------------------------------------------------------

// FeatureFlags holds boolean toggles for each server subsystem.
type FeatureFlags struct {
	mu sync.RWMutex

	labyrinth    bool
	errorInject  bool
	captcha      bool
	honeypot     bool
	vuln         bool
	analytics    bool
	cdn          bool
	oauth        bool
}

// NewFeatureFlags returns a FeatureFlags with every feature enabled.
func NewFeatureFlags() *FeatureFlags {
	return &FeatureFlags{
		labyrinth:   true,
		errorInject: true,
		captcha:     true,
		honeypot:    true,
		vuln:        true,
		analytics:   true,
		cdn:         true,
		oauth:       true,
	}
}

func (f *FeatureFlags) IsLabyrinthEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.labyrinth
}

func (f *FeatureFlags) IsErrorInjectEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.errorInject
}

func (f *FeatureFlags) IsCaptchaEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.captcha
}

func (f *FeatureFlags) IsHoneypotEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.honeypot
}

func (f *FeatureFlags) IsVulnEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.vuln
}

func (f *FeatureFlags) IsAnalyticsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.analytics
}

func (f *FeatureFlags) IsCDNEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cdn
}

func (f *FeatureFlags) IsOAuthEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.oauth
}

// Set toggles a named feature. Returns false if the name is unknown.
func (f *FeatureFlags) Set(name string, enabled bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.ToLower(name) {
	case "labyrinth":
		f.labyrinth = enabled
	case "error_inject":
		f.errorInject = enabled
	case "captcha":
		f.captcha = enabled
	case "honeypot":
		f.honeypot = enabled
	case "vuln":
		f.vuln = enabled
	case "analytics":
		f.analytics = enabled
	case "cdn":
		f.cdn = enabled
	case "oauth":
		f.oauth = enabled
	default:
		return false
	}
	return true
}

// Snapshot returns a map of feature name -> enabled for serialisation.
func (f *FeatureFlags) Snapshot() map[string]bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return map[string]bool{
		"labyrinth":    f.labyrinth,
		"error_inject": f.errorInject,
		"captcha":      f.captcha,
		"honeypot":     f.honeypot,
		"vuln":         f.vuln,
		"analytics":    f.analytics,
		"cdn":          f.cdn,
		"oauth":        f.oauth,
	}
}

// ---------------------------------------------------------------------------
// Admin Config — tunable numeric parameters
// ---------------------------------------------------------------------------

// AdminConfig holds tunable numeric parameters for the admin panel.
type AdminConfig struct {
	mu sync.RWMutex

	MaxLabyrinthDepth     int     // 1-100
	ErrorRateMultiplier   float64 // 0.0-5.0
	CaptchaTriggerThresh  int     // request count threshold before captcha fires
}

// NewAdminConfig returns an AdminConfig with sensible defaults.
func NewAdminConfig() *AdminConfig {
	return &AdminConfig{
		MaxLabyrinthDepth:    50,
		ErrorRateMultiplier:  1.0,
		CaptchaTriggerThresh: 100,
	}
}

// Get returns the current config values as a map.
func (c *AdminConfig) Get() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"max_labyrinth_depth":    c.MaxLabyrinthDepth,
		"error_rate_multiplier":  c.ErrorRateMultiplier,
		"captcha_trigger_thresh": c.CaptchaTriggerThresh,
	}
}

// Set updates a single config key. Returns false if the key is unknown.
func (c *AdminConfig) Set(key string, value float64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case "max_labyrinth_depth":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 100 {
			v = 100
		}
		c.MaxLabyrinthDepth = v
	case "error_rate_multiplier":
		if value < 0 {
			value = 0
		}
		if value > 5.0 {
			value = 5.0
		}
		c.ErrorRateMultiplier = value
	case "captcha_trigger_thresh":
		v := int(value)
		if v < 0 {
			v = 0
		}
		c.CaptchaTriggerThresh = v
	default:
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Singleton holders — used by the admin API handlers
// ---------------------------------------------------------------------------

var (
	globalFlags  = NewFeatureFlags()
	globalConfig = NewAdminConfig()
)

// GetFeatureFlags returns the global FeatureFlags instance.
func GetFeatureFlags() *FeatureFlags { return globalFlags }

// GetAdminConfig returns the global AdminConfig instance.
func GetAdminConfig() *AdminConfig { return globalConfig }

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

// RegisterAdminRoutes registers all admin-panel routes on the given mux.
func RegisterAdminRoutes(mux *http.ServeMux, s *Server) {
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(adminPage))
	})

	mux.HandleFunc("/admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
		adminAPIOverview(w, r, s)
	})

	mux.HandleFunc("/admin/api/features", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIFeaturesPost(w, r)
		} else {
			adminAPIFeaturesGet(w, r)
		}
	})

	mux.HandleFunc("/admin/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIConfigPost(w, r)
		} else {
			adminAPIConfigGet(w, r)
		}
	})

	mux.HandleFunc("/admin/api/log", func(w http.ResponseWriter, r *http.Request) {
		adminAPILog(w, r, s)
	})
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/overview
// ---------------------------------------------------------------------------

func adminAPIOverview(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	// Aggregate from recent records
	records := s.collector.RecentRecords(1000)

	// Top paths
	pathCounts := map[string]int{}
	uaCounts := map[string]int{}
	typeCounts := map[string]int{}
	statusCounts := map[int]int{}

	for _, rec := range records {
		pathCounts[rec.Path]++
		uaCounts[rec.UserAgent]++
		typeCounts[rec.ResponseType]++
		statusCounts[rec.StatusCode]++
	}

	type kv struct {
		Key   string `json:"key"`
		Count int    `json:"count"`
	}

	topPaths := sortedKV(pathCounts, 10)
	topUA := sortedKV(uaCounts, 10)

	// Status code map -> array for JSON
	statusArr := make([]map[string]interface{}, 0, len(statusCounts))
	for code, cnt := range statusCounts {
		statusArr = append(statusArr, map[string]interface{}{"code": code, "count": cnt})
	}

	// Response type map -> array
	typeArr := make([]kv, 0, len(typeCounts))
	for k, v := range typeCounts {
		typeArr = append(typeArr, kv{k, v})
	}
	sort.Slice(typeArr, func(i, j int) bool { return typeArr[i].Count > typeArr[j].Count })

	// Time series for sparkline
	buckets := s.collector.TimeSeries(60)
	sparkline := make([]map[string]interface{}, 0, len(buckets))
	for _, b := range buckets {
		sparkline = append(sparkline, map[string]interface{}{
			"ts":       b.Timestamp.Format(time.RFC3339),
			"requests": b.Requests,
			"errors":   b.Errors,
		})
	}

	resp := map[string]interface{}{
		"top_paths":      topPaths,
		"top_user_agents": topUA,
		"status_codes":   statusArr,
		"response_types": typeArr,
		"sparkline":      sparkline,
		"total_requests": s.collector.TotalRequests.Load(),
		"total_errors":   s.collector.TotalErrors.Load(),
		"uptime_seconds": int(s.collector.Uptime().Seconds()),
	}

	json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/features
// ---------------------------------------------------------------------------

func adminAPIFeaturesGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalFlags.Snapshot())
}

// ---------------------------------------------------------------------------
// API handler: POST /admin/api/features
// ---------------------------------------------------------------------------

func adminAPIFeaturesPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Feature string `json:"feature"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if !globalFlags.Set(req.Feature, req.Enabled) {
		http.Error(w, `{"error":"unknown feature"}`, http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"feature": req.Feature,
		"enabled": req.Enabled,
	})
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/config
// ---------------------------------------------------------------------------

func adminAPIConfigGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalConfig.Get())
}

// ---------------------------------------------------------------------------
// API handler: POST /admin/api/config
// ---------------------------------------------------------------------------

func adminAPIConfigPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Key   string  `json:"key"`
		Value float64 `json:"value"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if !globalConfig.Set(req.Key, req.Value) {
		http.Error(w, `{"error":"unknown config key"}`, http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"key":   req.Key,
		"value": req.Value,
	})
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/log
// ---------------------------------------------------------------------------

func adminAPILog(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	filter := strings.ToLower(r.URL.Query().Get("filter"))

	records := s.collector.RecentRecords(limit)

	// Clients and behaviors for enrichment
	data := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
		// Server-side pre-filter if filter param is provided
		if filter != "" {
			match := strings.Contains(strings.ToLower(rec.Path), filter) ||
				strings.Contains(strings.ToLower(rec.ClientID), filter) ||
				strings.Contains(strings.ToLower(rec.ResponseType), filter) ||
				strings.Contains(strings.ToLower(rec.UserAgent), filter) ||
				strings.Contains(strconv.Itoa(rec.StatusCode), filter)
			if !match {
				continue
			}
		}

		behavior := s.adapt.GetBehavior(rec.ClientID)
		mode := ""
		if behavior != nil {
			mode = string(behavior.Mode)
		}

		data = append(data, map[string]interface{}{
			"timestamp":     rec.Timestamp.Format(time.RFC3339),
			"client_id":     rec.ClientID,
			"method":        rec.Method,
			"path":          rec.Path,
			"status_code":   rec.StatusCode,
			"latency_ms":    rec.Latency.Milliseconds(),
			"response_type": rec.ResponseType,
			"user_agent":    rec.UserAgent,
			"mode":          mode,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"records": data,
		"count":   len(data),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

type kvPair struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func sortedKV(m map[string]int, top int) []kvPair {
	pairs := make([]kvPair, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kvPair{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Count > pairs[j].Count })
	if len(pairs) > top {
		pairs = pairs[:top]
	}
	return pairs
}

// ---------------------------------------------------------------------------
// Admin HTML page — self-contained, dark hacker theme
// ---------------------------------------------------------------------------

var adminPage = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glitch Server Admin Panel</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Courier New', monospace;
    background: #0a0a0a;
    color: #00ff88;
    padding: 20px;
    min-height: 100vh;
  }
  h1 {
    color: #00ffcc;
    margin-bottom: 6px;
    text-shadow: 0 0 10px #00ffcc44;
    font-size: 1.5em;
  }
  .subtitle {
    color: #666;
    font-size: 0.8em;
    margin-bottom: 20px;
  }
  h2 {
    color: #00ccaa;
    margin: 0 0 12px;
    font-size: 1.05em;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  a { color: #44aaff; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 20px;
    border-bottom: 1px solid #00ff8833;
    padding-bottom: 8px;
  }
  .tab {
    padding: 8px 18px;
    background: #111;
    border: 1px solid #00ff8822;
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    color: #888;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.85em;
    transition: all 0.2s;
  }
  .tab:hover { color: #00ff88; background: #1a1a1a; }
  .tab.active {
    color: #00ffcc;
    background: #1a1a1a;
    border-color: #00ff8844;
  }
  .panel { display: none; }
  .panel.active { display: block; }

  /* Cards */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .card {
    background: #111;
    border: 1px solid #00ff8833;
    border-radius: 8px;
    padding: 14px;
  }
  .card .label {
    color: #888;
    font-size: 0.75em;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .card .value {
    font-size: 1.6em;
    font-weight: bold;
    margin-top: 4px;
  }
  .v-ok { color: #00ff88; }
  .v-warn { color: #ffaa00; }
  .v-err { color: #ff4444; }
  .v-info { color: #4488ff; }

  /* Section */
  .section {
    background: #111;
    border: 1px solid #00ff8822;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 18px;
  }

  /* Tables */
  table { width: 100%%; border-collapse: collapse; margin: 8px 0; }
  th, td {
    padding: 7px 10px;
    text-align: left;
    border-bottom: 1px solid #1a1a1a;
    font-size: 0.82em;
  }
  th {
    color: #00ccaa;
    background: #0d0d0d;
    position: sticky;
    top: 0;
    z-index: 1;
    font-weight: normal;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 0.75em;
  }
  tr:hover { background: #1a1a1a; }

  /* Status colors */
  .s2 { color: #00ff88; }
  .s4 { color: #ffaa00; }
  .s5 { color: #ff4444; }

  /* Mode colors */
  .m-normal { color: #00ff88; }
  .m-aggressive { color: #ff4444; }
  .m-labyrinth { color: #aa44ff; }
  .m-escalating { color: #ffaa00; }
  .m-cooperative { color: #44aaff; }
  .m-intermittent { color: #ff8844; }
  .m-mirror { color: #44ffaa; }

  /* Sparkline */
  .sparkline-wrap {
    width: 100%%;
    height: 80px;
    position: relative;
    background: #0d0d0d;
    border-radius: 4px;
    overflow: hidden;
  }
  .spark-bar {
    position: absolute;
    bottom: 0;
    background: #00ff88;
    min-width: 2px;
    border-radius: 1px 1px 0 0;
    transition: height 0.3s;
  }
  .spark-bar.err { background: #ff4444; }

  /* Pie chart (CSS) */
  .pie-wrap {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .pie-canvas { width: 140px; height: 140px; }
  .pie-legend { font-size: 0.8em; line-height: 1.8; }
  .pie-legend span {
    display: inline-block;
    width: 10px; height: 10px;
    border-radius: 2px;
    margin-right: 6px;
    vertical-align: middle;
  }

  /* Toggle switches */
  .toggle-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
  }
  .toggle-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: #0d0d0d;
    border: 1px solid #222;
    border-radius: 6px;
    padding: 10px 14px;
  }
  .toggle-name {
    font-size: 0.85em;
    color: #ccc;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .toggle-sw {
    position: relative;
    width: 44px;
    height: 24px;
    cursor: pointer;
  }
  .toggle-sw input { display: none; }
  .toggle-track {
    position: absolute;
    inset: 0;
    background: #333;
    border-radius: 12px;
    transition: background 0.25s;
  }
  .toggle-sw input:checked + .toggle-track { background: #00aa66; }
  .toggle-knob {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 18px;
    background: #ccc;
    border-radius: 50%%;
    transition: transform 0.25s;
  }
  .toggle-sw input:checked ~ .toggle-knob { transform: translateX(20px); background: #00ff88; }

  /* Sliders */
  .slider-group { margin-bottom: 16px; }
  .slider-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.82em;
    color: #aaa;
    margin-bottom: 4px;
  }
  .slider-label .val { color: #00ffcc; font-weight: bold; }
  input[type="range"] {
    -webkit-appearance: none;
    width: 100%%;
    height: 6px;
    background: #333;
    border-radius: 3px;
    outline: none;
  }
  input[type="range"]::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 16px;
    height: 16px;
    background: #00ff88;
    border-radius: 50%%;
    cursor: pointer;
  }
  input[type="range"]::-moz-range-thumb {
    width: 16px;
    height: 16px;
    background: #00ff88;
    border-radius: 50%%;
    cursor: pointer;
    border: none;
  }

  /* Search box */
  .search-box {
    width: 100%%;
    padding: 8px 14px;
    background: #0d0d0d;
    border: 1px solid #00ff8833;
    border-radius: 6px;
    color: #00ff88;
    font-family: inherit;
    font-size: 0.85em;
    margin-bottom: 12px;
    outline: none;
  }
  .search-box::placeholder { color: #555; }
  .search-box:focus { border-color: #00ff8866; }

  /* Scrollable table wrapper */
  .tbl-scroll {
    max-height: 420px;
    overflow-y: auto;
  }
  .tbl-scroll::-webkit-scrollbar { width: 6px; }
  .tbl-scroll::-webkit-scrollbar-track { background: #111; }
  .tbl-scroll::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }

  /* Row highlight for log */
  .log-row td { font-size: 0.78em; }

  /* Mini bar chart for distributions */
  .bar-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 4px;
    font-size: 0.82em;
  }
  .bar-label { width: 120px; text-align: right; color: #aaa; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; height: 14px; background: #1a1a1a; border-radius: 3px; overflow: hidden; }
  .bar-fill { height: 100%%; background: #00ff88; border-radius: 3px; transition: width 0.3s; }
  .bar-count { width: 50px; color: #888; font-size: 0.9em; }

  /* Toast */
  .toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #00aa66;
    color: #000;
    padding: 10px 20px;
    border-radius: 6px;
    font-size: 0.85em;
    font-weight: bold;
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.3s;
    z-index: 9999;
    pointer-events: none;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
</style>
</head>
<body>

<h1>// GLITCH ADMIN PANEL</h1>
<div class="subtitle">Control center for the glitch web server &mdash; <a href="/">back to dashboard</a></div>

<div class="tabs">
  <button class="tab active" onclick="showTab('sessions')">Sessions</button>
  <button class="tab" onclick="showTab('traffic')">Traffic</button>
  <button class="tab" onclick="showTab('controls')">Controls</button>
  <button class="tab" onclick="showTab('log')">Request Log</button>
</div>

<!-- ==================== SESSIONS TAB ==================== -->
<div id="panel-sessions" class="panel active">
  <div class="section">
    <h2>// Active Client Sessions</h2>
    <div class="tbl-scroll">
      <table>
        <thead><tr>
          <th>Client ID</th>
          <th>Requests</th>
          <th>Req/s</th>
          <th>Errors</th>
          <th>Paths</th>
          <th>Lab Depth</th>
          <th>Mode</th>
          <th>Last Seen</th>
        </tr></thead>
        <tbody id="sess-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== TRAFFIC TAB ==================== -->
<div id="panel-traffic" class="panel">
  <div class="grid" id="overview-cards"></div>

  <div class="section">
    <h2>// Requests/sec (last 60s)</h2>
    <div class="sparkline-wrap" id="sparkline"></div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Status Code Distribution</h2>
      <div class="pie-wrap">
        <canvas class="pie-canvas" id="pie-status" width="140" height="140"></canvas>
        <div class="pie-legend" id="pie-legend"></div>
      </div>
    </div>
    <div class="section">
      <h2>// Response Type Distribution</h2>
      <div id="resp-type-bars"></div>
    </div>
  </div>

  <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 18px;">
    <div class="section">
      <h2>// Top 10 Paths</h2>
      <div id="top-paths"></div>
    </div>
    <div class="section">
      <h2>// Top 10 User Agents</h2>
      <div id="top-ua"></div>
    </div>
  </div>
</div>

<!-- ==================== CONTROLS TAB ==================== -->
<div id="panel-controls" class="panel">
  <div class="section">
    <h2>// Feature Toggles</h2>
    <div class="toggle-grid" id="toggles"></div>
  </div>

  <div class="section">
    <h2>// Depth &amp; Rate Controls</h2>
    <div id="sliders"></div>
  </div>
</div>

<!-- ==================== REQUEST LOG TAB ==================== -->
<div id="panel-log" class="panel">
  <div class="section">
    <h2>// Request Log (last 200)</h2>
    <input type="text" class="search-box" id="log-filter" placeholder="Filter by status, client, path, type..." oninput="filterLog()">
    <div class="tbl-scroll" style="max-height: 600px;">
      <table>
        <thead><tr>
          <th>Time</th>
          <th>Client</th>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Latency</th>
          <th>Type</th>
          <th>Mode</th>
          <th>User Agent</th>
        </tr></thead>
        <tbody id="log-body"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(function(){
  const API = window.location.protocol + '//' + window.location.hostname + ':' + window.location.port;
  let logData = [];

  // ------ Tabs ------
  window.showTab = function(name) {
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('panel-' + name).classList.add('active');
    document.querySelector('.tab[onclick*="' + name + '"]').classList.add('active');
  };

  // ------ Toast ------
  function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 1800);
  }

  // ------ Helpers ------
  async function api(path, opts) {
    const res = await fetch(API + path, opts);
    return res.json();
  }

  function sClass(code) {
    if (code >= 500) return 's5';
    if (code >= 400) return 's4';
    return 's2';
  }

  function mClass(mode) { return 'm-' + (mode || 'normal'); }

  function shortID(id) { return (id || '').substring(0, 16); }
  function shortUA(ua) { return (ua || '').substring(0, 50); }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ------ Sessions ------
  async function refreshSessions() {
    try {
      const data = await api('/api/clients');
      const clients = (data.clients || []);
      // Sort by last_seen descending
      clients.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
      const tbody = document.getElementById('sess-body');
      tbody.innerHTML = clients.map(c => {
        const ago = timeSince(c.last_seen);
        return '<tr>' +
          '<td>' + escapeHtml(shortID(c.client_id)) + '</td>' +
          '<td>' + c.total_requests + '</td>' +
          '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
          '<td class="' + (c.errors_received > 0 ? 's5' : '') + '">' + c.errors_received + '</td>' +
          '<td>' + c.unique_paths + '</td>' +
          '<td>' + (c.labyrinth_depth||0) + '</td>' +
          '<td class="' + mClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
          '<td style="color:#888">' + ago + '</td>' +
          '</tr>';
      }).join('');
    } catch(e) { console.error('sessions:', e); }
  }

  function timeSince(iso) {
    const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s/60) + 'm ago';
    return Math.floor(s/3600) + 'h ago';
  }

  // ------ Traffic Overview ------
  async function refreshTraffic() {
    try {
      const ov = await api('/admin/api/overview');

      // Cards
      const total = ov.total_requests || 0;
      const errs = ov.total_errors || 0;
      const errPct = total > 0 ? (errs/total*100).toFixed(1) : '0.0';
      document.getElementById('overview-cards').innerHTML =
        card('Total Requests', total.toLocaleString(), 'v-ok') +
        card('Total Errors', errs.toLocaleString(), 'v-err') +
        card('Error Rate', errPct + '%%', parseFloat(errPct) > 10 ? 'v-err' : 'v-ok') +
        card('Uptime', fmtUptime(ov.uptime_seconds), 'v-info');

      // Sparkline
      const spark = ov.sparkline || [];
      const wrap = document.getElementById('sparkline');
      if (spark.length > 0) {
        const maxR = Math.max(...spark.map(s => s.requests), 1);
        const bw = Math.max(2, Math.floor(wrap.clientWidth / spark.length) - 1);
        wrap.innerHTML = spark.map((s, i) => {
          const h = Math.max(2, (s.requests / maxR) * 100);
          const cls = s.errors > 0 ? 'spark-bar err' : 'spark-bar';
          return '<div class="' + cls + '" style="left:' + (i*(bw+1)) + 'px;width:' + bw + 'px;height:' + h + '%%;" title="' + s.requests + ' req"></div>';
        }).join('');
      }

      // Pie chart (canvas)
      drawPie(ov.status_codes || []);

      // Response type bars
      const types = ov.response_types || [];
      const maxT = types.length > 0 ? types[0].count : 1;
      document.getElementById('resp-type-bars').innerHTML = types.map(t =>
        '<div class="bar-row">' +
        '<div class="bar-label">' + escapeHtml(t.key || 'unknown') + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (t.count/maxT*100) + '%%"></div></div>' +
        '<div class="bar-count">' + t.count + '</div>' +
        '</div>'
      ).join('');

      // Top paths
      const paths = ov.top_paths || [];
      const maxP = paths.length > 0 ? paths[0].count : 1;
      document.getElementById('top-paths').innerHTML = paths.map(p =>
        '<div class="bar-row">' +
        '<div class="bar-label" title="' + escapeHtml(p.key) + '">' + escapeHtml(p.key.substring(0, 30)) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxP*100) + '%%"></div></div>' +
        '<div class="bar-count">' + p.count + '</div>' +
        '</div>'
      ).join('') || '<div style="color:#555">No data yet</div>';

      // Top UAs
      const uas = ov.top_user_agents || [];
      const maxU = uas.length > 0 ? uas[0].count : 1;
      document.getElementById('top-ua').innerHTML = uas.map(u =>
        '<div class="bar-row">' +
        '<div class="bar-label" title="' + escapeHtml(u.key) + '">' + escapeHtml(u.key.substring(0, 30)) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (u.count/maxU*100) + '%%"></div></div>' +
        '<div class="bar-count">' + u.count + '</div>' +
        '</div>'
      ).join('') || '<div style="color:#555">No data yet</div>';

    } catch(e) { console.error('traffic:', e); }
  }

  function card(label, value, cls) {
    return '<div class="card"><div class="label">' + label + '</div><div class="value ' + cls + '">' + value + '</div></div>';
  }

  function fmtUptime(sec) {
    if (!sec) return '0s';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec %% 3600) / 60);
    const s = sec %% 60;
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + s + 's';
    return s + 's';
  }

  const PIE_COLORS = ['#00ff88','#ffaa00','#ff4444','#4488ff','#aa44ff','#ff8844','#44ffaa','#ff44aa'];
  function drawPie(codes) {
    const canvas = document.getElementById('pie-status');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 70, cy = 70, r = 60;
    ctx.clearRect(0, 0, 140, 140);

    if (codes.length === 0) {
      ctx.fillStyle = '#222';
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI*2); ctx.fill();
      document.getElementById('pie-legend').innerHTML = '<div style="color:#555">No data</div>';
      return;
    }

    // Sort by code
    codes.sort((a, b) => a.code - b.code);
    const total = codes.reduce((s, c) => s + c.count, 0);
    let angle = -Math.PI / 2;
    let legend = '';

    codes.forEach((c, i) => {
      const slice = (c.count / total) * Math.PI * 2;
      const color = PIE_COLORS[i %% PIE_COLORS.length];
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, angle, angle + slice);
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
      legend += '<div><span style="background:' + color + '"></span>' + c.code + ': ' + c.count + ' (' + (c.count/total*100).toFixed(0) + '%%)</div>';
      angle += slice;
    });

    document.getElementById('pie-legend').innerHTML = legend;
  }

  // ------ Controls ------
  const FEATURE_LABELS = {
    labyrinth: 'Labyrinth',
    error_inject: 'Error Injection',
    captcha: 'CAPTCHA',
    honeypot: 'Honeypot',
    vuln: 'Vulnerability Endpoints',
    analytics: 'Analytics Tracking',
    cdn: 'CDN Emulation',
    oauth: 'OAuth Endpoints'
  };

  async function refreshControls() {
    try {
      const features = await api('/admin/api/features');
      const el = document.getElementById('toggles');
      el.innerHTML = Object.keys(FEATURE_LABELS).map(key => {
        const on = features[key] ? 'checked' : '';
        return '<div class="toggle-row">' +
          '<div class="toggle-name">' + FEATURE_LABELS[key] + '</div>' +
          '<label class="toggle-sw">' +
          '<input type="checkbox" ' + on + ' onchange="toggleFeature(\'' + key + '\', this.checked)">' +
          '<div class="toggle-track"></div>' +
          '<div class="toggle-knob"></div>' +
          '</label></div>';
      }).join('');

      const cfg = await api('/admin/api/config');
      document.getElementById('sliders').innerHTML =
        slider('max_labyrinth_depth', 'Max Labyrinth Depth', cfg.max_labyrinth_depth, 1, 100, 1) +
        slider('error_rate_multiplier', 'Error Rate Multiplier', cfg.error_rate_multiplier, 0, 5, 0.1) +
        slider('captcha_trigger_thresh', 'CAPTCHA Trigger Threshold', cfg.captcha_trigger_thresh, 0, 500, 1);
    } catch(e) { console.error('controls:', e); }
  }

  function slider(key, label, value, min, max, step) {
    const isFloat = step < 1;
    const display = isFloat ? parseFloat(value).toFixed(1) : parseInt(value);
    return '<div class="slider-group">' +
      '<div class="slider-label"><span>' + label + '</span><span class="val" id="sv-' + key + '">' + display + '</span></div>' +
      '<input type="range" min="' + min + '" max="' + max + '" step="' + step + '" value="' + value + '" oninput="sliderChange(\'' + key + '\', this.value, ' + isFloat + ')" onchange="sliderCommit(\'' + key + '\', this.value)">' +
      '</div>';
  }

  let sliderTimer = {};
  window.sliderChange = function(key, val, isFloat) {
    document.getElementById('sv-' + key).textContent = isFloat ? parseFloat(val).toFixed(1) : parseInt(val);
  };

  window.sliderCommit = function(key, val) {
    clearTimeout(sliderTimer[key]);
    sliderTimer[key] = setTimeout(() => {
      api('/admin/api/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({key: key, value: parseFloat(val)})
      }).then(() => toast(key + ' updated'));
    }, 300);
  };

  window.toggleFeature = function(name, enabled) {
    api('/admin/api/features', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({feature: name, enabled: enabled})
    }).then(() => toast(name + (enabled ? ' enabled' : ' disabled')));
  };

  // ------ Request Log ------
  async function refreshLog() {
    try {
      const data = await api('/admin/api/log?limit=200');
      logData = data.records || [];
      renderLog(logData);
    } catch(e) { console.error('log:', e); }
  }

  function renderLog(records) {
    const tbody = document.getElementById('log-body');
    tbody.innerHTML = records.map(r => {
      return '<tr class="log-row" data-search="' + escapeHtml((r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent).toLowerCase()) + '">' +
        '<td>' + new Date(r.timestamp).toLocaleTimeString() + '</td>' +
        '<td>' + escapeHtml(shortID(r.client_id)) + '</td>' +
        '<td>' + r.method + '</td>' +
        '<td title="' + escapeHtml(r.path) + '">' + escapeHtml(r.path.substring(0, 45)) + '</td>' +
        '<td class="' + sClass(r.status_code) + '">' + r.status_code + '</td>' +
        '<td>' + r.latency_ms + 'ms</td>' +
        '<td>' + escapeHtml(r.response_type) + '</td>' +
        '<td class="' + mClass(r.mode) + '">' + (r.mode || '-') + '</td>' +
        '<td title="' + escapeHtml(r.user_agent || '') + '">' + escapeHtml(shortUA(r.user_agent)) + '</td>' +
        '</tr>';
    }).join('');
  }

  window.filterLog = function() {
    const q = document.getElementById('log-filter').value.toLowerCase().trim();
    if (!q) {
      renderLog(logData);
      return;
    }
    const filtered = logData.filter(r => {
      const haystack = (r.status_code + ' ' + r.client_id + ' ' + r.path + ' ' + r.response_type + ' ' + r.user_agent + ' ' + r.mode).toLowerCase();
      return haystack.indexOf(q) !== -1;
    });
    renderLog(filtered);
  };

  // ------ Main loop ------
  async function refresh() {
    const active = document.querySelector('.panel.active');
    if (!active) return;
    const id = active.id;
    if (id === 'panel-sessions') await refreshSessions();
    else if (id === 'panel-traffic') await refreshTraffic();
    else if (id === 'panel-controls') await refreshControls();
    else if (id === 'panel-log') await refreshLog();
  }

  // Initial load for all panels
  (async function init() {
    await refreshSessions();
    refreshTraffic();
    refreshControls();
    refreshLog();
  })();

  setInterval(refresh, 2000);
})();
</script>
</body>
</html>`)
