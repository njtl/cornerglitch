package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
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

	// Store global reference and sync any pending blocking config.
	SetAdaptive(adapt)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("/api/metrics", s.apiMetrics)
	mux.HandleFunc("/api/clients", s.apiClients)
	mux.HandleFunc("/api/timeseries", s.apiTimeSeries)
	mux.HandleFunc("/api/recent", s.apiRecent)
	mux.HandleFunc("/api/behaviors", s.apiBehaviors)

	// Register admin panel routes
	RegisterAdminRoutes(mux, s)

	// Register built-in scanner API routes
	RegisterBuiltinScannerRoutes(mux)

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: AuthMiddleware(mux),
	}

	return s
}

// Handler returns the HTTP handler for testing purposes.
func (s *Server) Handler() http.Handler {
	return s.httpSrv.Handler
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
		"uptime_seconds":         int(s.collector.Uptime().Seconds()),
		"total_requests":         s.collector.TotalRequests.Load(),
		"total_errors":           s.collector.TotalErrors.Load(),
		"total_2xx":              s.collector.Total2xx.Load(),
		"total_4xx":              s.collector.Total4xx.Load(),
		"total_5xx":              s.collector.Total5xx.Load(),
		"total_delayed":          s.collector.TotalDelayed.Load(),
		"total_labyrinth":        s.collector.TotalLabyrinth.Load(),
		"active_connections":     s.collector.ActiveConns.Load(),
		"unique_clients":         len(s.collector.GetAllClientProfiles()),
		"current_rps":            s.collector.CurrentRPS(),
		"total_request_bytes":    s.collector.TotalRequestBytes.Load(),
		"total_response_bytes":   s.collector.TotalResponseBytes.Load(),
		"session_request_bytes":  s.collector.SessionRequestBytes.Load(),
		"session_response_bytes": s.collector.SessionResponseBytes.Load(),
	}

	total := s.collector.TotalRequests.Load()
	if total > 0 {
		totalNon2xx := s.collector.Total4xx.Load() + s.collector.Total5xx.Load()
		resp["error_rate_pct"] = float64(totalNon2xx) / float64(total) * 100
		resp["labyrinth_rate_pct"] = float64(s.collector.TotalLabyrinth.Load()) / float64(total) * 100
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *Server) apiClients(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	paginated := hasPaginationParams(r)
	limit, offset := parsePagination(r)
	q := r.URL.Query()
	search := strings.ToLower(q.Get("search"))
	sortField, sortAsc := parseSortParams(r, map[string]bool{
		"requests": true, "rps": true, "errors": true, "paths": true,
		"lab_depth": true, "mode": true, "last_seen": true,
	})

	profiles := s.collector.GetAllClientProfiles()
	allClients := make([]map[string]interface{}, 0, len(profiles))

	for _, p := range profiles {
		snap := p.Snapshot()

		// Search filter: match client ID substring
		if search != "" && !strings.Contains(strings.ToLower(snap.ClientID), search) {
			continue
		}

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
		sort.Slice(topPaths, func(i, j int) bool {
			if topPaths[i].Count != topPaths[j].Count {
				return topPaths[i].Count > topPaths[j].Count
			}
			return topPaths[i].Path < topPaths[j].Path // stable tie-break
		})
		if len(topPaths) > 10 {
			topPaths = topPaths[:10]
		}
		pathsMap := make(map[string]int, len(topPaths))
		for _, pc := range topPaths {
			pathsMap[pc.Path] = pc.Count
		}

		allClients = append(allClients, map[string]interface{}{
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

	// Sort (default: requests desc)
	if sortField != "" {
		sort.Slice(allClients, func(i, j int) bool {
			var less bool
			switch sortField {
			case "requests":
				less = allClients[i]["total_requests"].(int) < allClients[j]["total_requests"].(int)
			case "rps":
				less = allClients[i]["requests_per_sec"].(float64) < allClients[j]["requests_per_sec"].(float64)
			case "errors":
				less = allClients[i]["errors_received"].(int) < allClients[j]["errors_received"].(int)
			case "paths":
				less = allClients[i]["unique_paths"].(int) < allClients[j]["unique_paths"].(int)
			case "lab_depth":
				less = allClients[i]["labyrinth_depth"].(int) < allClients[j]["labyrinth_depth"].(int)
			case "mode":
				less = allClients[i]["adaptive_mode"].(string) < allClients[j]["adaptive_mode"].(string)
			case "last_seen":
				less = allClients[i]["last_seen"].(string) < allClients[j]["last_seen"].(string)
			default:
				return false
			}
			if sortAsc {
				return less
			}
			return !less
		})
	}

	total := len(allClients)

	// Backward compatibility: no pagination params → return legacy format
	if !paginated {
		start, end := paginateSlice(total, limit, offset)
		page := allClients[start:end]
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":    page,
			"clients": page,
			"total":   total,
			"limit":   limit,
			"offset":  offset,
			"count":   len(page),
		})
		return
	}

	start, end := paginateSlice(total, limit, offset)
	page := allClients[start:end]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":  page,
		"total":  total,
		"limit":  limit,
		"offset": offset,
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

	paginated := hasPaginationParams(r)
	q := r.URL.Query()
	statusFilter := q.Get("status")
	methodFilter := strings.ToUpper(q.Get("method"))
	pathFilter := q.Get("path")

	// Default limit for recent: 200
	recentLimit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			recentLimit = n
			if recentLimit > 1000 {
				recentLimit = 1000
			}
		}
	}
	recentOffset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			recentOffset = n
		}
	}

	// Fetch enough records to filter from (use larger window when filtering)
	fetchSize := 200
	if statusFilter != "" || methodFilter != "" || pathFilter != "" || paginated {
		fetchSize = 1000
	}
	records := s.collector.RecentRecords(fetchSize)

	var statusCode int
	if statusFilter != "" {
		statusCode, _ = strconv.Atoi(statusFilter)
	}

	data := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
		// Apply filters
		if statusFilter != "" && rec.StatusCode != statusCode {
			continue
		}
		if methodFilter != "" && rec.Method != methodFilter {
			continue
		}
		if pathFilter != "" && !strings.HasPrefix(rec.Path, pathFilter) {
			continue
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
		})
	}

	// Backward compatibility: no pagination params → return legacy format
	if !paginated {
		json.NewEncoder(w).Encode(map[string]interface{}{"records": data})
		return
	}

	total := len(data)
	start, end := paginateSlice(total, recentLimit, recentOffset)
	page := data[start:end]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":  page,
		"total":  total,
		"limit":  recentLimit,
		"offset": recentOffset,
	})
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

