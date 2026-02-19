package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/metrics"
)

// Server serves the monitoring dashboard and metrics API.
type Server struct {
	collector *metrics.Collector
	fp        *fingerprint.Engine
	adapt     *adaptive.Engine
	httpSrv   *http.Server
}

func NewServer(collector *metrics.Collector, fp *fingerprint.Engine, adapt *adaptive.Engine, port int) *Server {
	s := &Server{
		collector: collector,
		fp:        fp,
		adapt:     adapt,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboardHTML)
	mux.HandleFunc("/api/metrics", s.apiMetrics)
	mux.HandleFunc("/api/clients", s.apiClients)
	mux.HandleFunc("/api/timeseries", s.apiTimeSeries)
	mux.HandleFunc("/api/recent", s.apiRecent)
	mux.HandleFunc("/api/behaviors", s.apiBehaviors)

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	return s
}

func (s *Server) ListenAndServe() error {
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) apiMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	resp := map[string]interface{}{
		"uptime_seconds":     int(s.collector.Uptime().Seconds()),
		"total_requests":     s.collector.TotalRequests.Load(),
		"total_errors":       s.collector.TotalErrors.Load(),
		"total_2xx":          s.collector.Total2xx.Load(),
		"total_4xx":          s.collector.Total4xx.Load(),
		"total_5xx":          s.collector.Total5xx.Load(),
		"total_delayed":      s.collector.TotalDelayed.Load(),
		"total_labyrinth":    s.collector.TotalLabyrinth.Load(),
		"active_connections": s.collector.ActiveConns.Load(),
		"unique_clients":     len(s.collector.GetAllClientProfiles()),
	}

	total := s.collector.TotalRequests.Load()
	if total > 0 {
		resp["error_rate_pct"] = float64(s.collector.TotalErrors.Load()) / float64(total) * 100
		resp["labyrinth_rate_pct"] = float64(s.collector.TotalLabyrinth.Load()) / float64(total) * 100
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	profiles := s.collector.GetAllClientProfiles()
	clients := make([]map[string]interface{}, 0, len(profiles))

	for _, p := range profiles {
		snap := p.Snapshot()
		behavior := s.adapt.GetBehavior(snap.ClientID)
		var mode, reason string
		if behavior != nil {
			mode = string(behavior.Mode)
			reason = behavior.Reason
		}

		// Top paths
		type pathCount struct {
			Path  string
			Count int
		}
		topPaths := make([]pathCount, 0, len(snap.PathsVisited))
		for path, count := range snap.PathsVisited {
			topPaths = append(topPaths, pathCount{path, count})
		}
		sort.Slice(topPaths, func(i, j int) bool { return topPaths[i].Count > topPaths[j].Count })
		if len(topPaths) > 10 {
			topPaths = topPaths[:10]
		}
		pathsMap := make(map[string]int, len(topPaths))
		for _, pc := range topPaths {
			pathsMap[pc.Path] = pc.Count
		}

		clients = append(clients, map[string]interface{}{
			"client_id":        snap.ClientID,
			"first_seen":       snap.FirstSeen.Format(time.RFC3339),
			"last_seen":        snap.LastSeen.Format(time.RFC3339),
			"total_requests":   snap.TotalRequests,
			"requests_per_sec": snap.RequestsPerSec,
			"errors_received":  snap.ErrorsReceived,
			"unique_paths":     len(snap.PathsVisited),
			"top_paths":        pathsMap,
			"status_codes":     snap.StatusCodes,
			"user_agents":      snap.UserAgents,
			"burst_windows":    snap.BurstWindows,
			"adaptive_mode":    mode,
			"adaptive_reason":  reason,
			"labyrinth_depth":  snap.LabyrinthDepth,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

func (s *Server) apiTimeSeries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	buckets := s.collector.TimeSeries(60)
	data := make([]map[string]interface{}, 0, len(buckets))
	for _, b := range buckets {
		data = append(data, map[string]interface{}{
			"timestamp": b.Timestamp.Format(time.RFC3339),
			"requests":  b.Requests,
			"errors":    b.Errors,
			"avg_ms":    b.AvgMs,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"series": data})
}

func (s *Server) apiRecent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	records := s.collector.RecentRecords(100)
	data := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
		data = append(data, map[string]interface{}{
			"timestamp":     rec.Timestamp.Format(time.RFC3339),
			"client_id":     rec.ClientID,
			"method":        rec.Method,
			"path":          rec.Path,
			"status_code":   rec.StatusCode,
			"latency_ms":    rec.Latency.Milliseconds(),
			"response_type": rec.ResponseType,
			"user_agent":    rec.UserAgent,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"records": data})
}

func (s *Server) apiBehaviors(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	behaviors := s.adapt.GetAllBehaviors()
	data := make([]map[string]interface{}, 0, len(behaviors))
	for clientID, b := range behaviors {
		data = append(data, map[string]interface{}{
			"client_id":        clientID,
			"mode":             string(b.Mode),
			"labyrinth_chance": b.LabyrinthChance,
			"page_variety":     b.PageVariety,
			"assigned_at":      b.AssignedAt.Format(time.RFC3339),
			"reason":           b.Reason,
			"escalation_level": b.EscalationLevel,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"behaviors": data})
}

func (s *Server) dashboardHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardPage))
}

var dashboardPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glitch Server Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff88; padding: 20px; }
  h1 { color: #00ffcc; margin-bottom: 20px; text-shadow: 0 0 10px #00ffcc44; }
  h2 { color: #00ccaa; margin: 15px 0 10px; font-size: 1.1em; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }
  .card { background: #111; border: 1px solid #00ff8844; border-radius: 8px; padding: 15px; }
  .card .label { color: #888; font-size: 0.8em; text-transform: uppercase; }
  .card .value { font-size: 1.8em; font-weight: bold; margin-top: 5px; }
  .card .value.error { color: #ff4444; }
  .card .value.warn { color: #ffaa00; }
  .card .value.ok { color: #00ff88; }
  .card .value.info { color: #4488ff; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #222; font-size: 0.85em; }
  th { color: #00ccaa; background: #0d0d0d; position: sticky; top: 0; }
  tr:hover { background: #1a1a1a; }
  .mode-normal { color: #00ff88; }
  .mode-aggressive { color: #ff4444; }
  .mode-labyrinth { color: #aa44ff; }
  .mode-escalating { color: #ffaa00; }
  .mode-cooperative { color: #44aaff; }
  .mode-intermittent { color: #ff8844; }
  .mode-mirror { color: #44ffaa; }
  .section { background: #111; border: 1px solid #00ff8822; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .log-row { font-size: 0.8em; }
  .status-2xx { color: #00ff88; }
  .status-4xx { color: #ffaa00; }
  .status-5xx { color: #ff4444; }
  #chart { width: 100%; height: 120px; position: relative; }
  .chart-bar { position: absolute; bottom: 0; background: #00ff88; min-width: 2px; border-radius: 1px 1px 0 0; transition: height 0.3s; }
  .chart-bar.error { background: #ff4444; }
</style>
</head>
<body>
<h1>// GLITCH SERVER DASHBOARD</h1>

<div class="grid" id="metrics"></div>

<div class="section">
  <h2>// THROUGHPUT (last 60s)</h2>
  <div id="chart"></div>
</div>

<div class="section">
  <h2>// CONNECTED CLIENTS &amp; ADAPTIVE BEHAVIORS</h2>
  <table id="clients-table">
    <thead><tr>
      <th>Client</th><th>Requests</th><th>Req/s</th><th>Errors</th><th>Paths</th><th>Mode</th><th>Reason</th>
    </tr></thead>
    <tbody id="clients-body"></tbody>
  </table>
</div>

<div class="section">
  <h2>// RECENT REQUESTS</h2>
  <table id="recent-table">
    <thead><tr>
      <th>Time</th><th>Client</th><th>Method</th><th>Path</th><th>Status</th><th>Latency</th><th>Type</th>
    </tr></thead>
    <tbody id="recent-body"></tbody>
  </table>
</div>

<script>
const API = window.location.protocol + '//' + window.location.hostname + ':' + window.location.port;

async function fetchJSON(path) {
  const res = await fetch(API + path);
  return res.json();
}

function statusClass(code) {
  if (code >= 500) return 'status-5xx';
  if (code >= 400) return 'status-4xx';
  return 'status-2xx';
}

function modeClass(mode) {
  return 'mode-' + (mode || 'normal');
}

async function updateMetrics() {
  const m = await fetchJSON('/api/metrics');
  document.getElementById('metrics').innerHTML = ` + "`" + `
    <div class="card"><div class="label">Total Requests</div><div class="value ok">${m.total_requests.toLocaleString()}</div></div>
    <div class="card"><div class="label">Active Connections</div><div class="value info">${m.active_connections}</div></div>
    <div class="card"><div class="label">2xx Responses</div><div class="value ok">${m.total_2xx.toLocaleString()}</div></div>
    <div class="card"><div class="label">4xx Responses</div><div class="value warn">${m.total_4xx.toLocaleString()}</div></div>
    <div class="card"><div class="label">5xx Responses</div><div class="value error">${m.total_5xx.toLocaleString()}</div></div>
    <div class="card"><div class="label">Error Rate</div><div class="value ${(m.error_rate_pct||0) > 10 ? 'error' : 'ok'}">${(m.error_rate_pct||0).toFixed(1)}%</div></div>
    <div class="card"><div class="label">Labyrinth Hits</div><div class="value info">${m.total_labyrinth.toLocaleString()}</div></div>
    <div class="card"><div class="label">Unique Clients</div><div class="value info">${m.unique_clients}</div></div>
    <div class="card"><div class="label">Uptime</div><div class="value ok">${Math.floor(m.uptime_seconds/60)}m ${m.uptime_seconds%60}s</div></div>
  ` + "`" + `;
}

async function updateChart() {
  const ts = await fetchJSON('/api/timeseries');
  const chart = document.getElementById('chart');
  const series = ts.series || [];
  if (series.length === 0) return;
  const maxReq = Math.max(...series.map(s => s.requests), 1);
  chart.innerHTML = series.map((s, i) => {
    const h = Math.max(2, (s.requests / maxReq) * 100);
    const w = Math.max(2, Math.floor(chart.clientWidth / series.length) - 1);
    const cls = s.errors > 0 ? 'chart-bar error' : 'chart-bar';
    return '<div class="' + cls + '" style="left:' + (i * (w+1)) + 'px;width:' + w + 'px;height:' + h + '%;" title="' + s.requests + ' req, ' + s.errors + ' err"></div>';
  }).join('');
}

async function updateClients() {
  const data = await fetchJSON('/api/clients');
  const tbody = document.getElementById('clients-body');
  tbody.innerHTML = (data.clients || []).map(c =>
    '<tr>' +
    '<td>' + c.client_id.substring(0, 16) + '</td>' +
    '<td>' + c.total_requests + '</td>' +
    '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
    '<td>' + c.errors_received + '</td>' +
    '<td>' + c.unique_paths + '</td>' +
    '<td class="' + modeClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
    '<td>' + (c.adaptive_reason||'') + '</td>' +
    '</tr>'
  ).join('');
}

async function updateRecent() {
  const data = await fetchJSON('/api/recent');
  const tbody = document.getElementById('recent-body');
  tbody.innerHTML = (data.records || []).slice(0, 50).map(r =>
    '<tr class="log-row">' +
    '<td>' + new Date(r.timestamp).toLocaleTimeString() + '</td>' +
    '<td>' + r.client_id.substring(0, 12) + '</td>' +
    '<td>' + r.method + '</td>' +
    '<td>' + r.path.substring(0, 40) + '</td>' +
    '<td class="' + statusClass(r.status_code) + '">' + r.status_code + '</td>' +
    '<td>' + r.latency_ms + 'ms</td>' +
    '<td>' + r.response_type + '</td>' +
    '</tr>'
  ).join('');
}

async function refresh() {
  try {
    await Promise.all([updateMetrics(), updateChart(), updateClients(), updateRecent()]);
  } catch(e) { console.error('refresh error:', e); }
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>`
