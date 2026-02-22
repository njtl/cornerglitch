package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/scanner"
)

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

	// Client detail endpoint
	mux.HandleFunc("/admin/api/client/", func(w http.ResponseWriter, r *http.Request) {
		adminAPIClientDetail(w, r, s)
	})

	// Blocking controls
	mux.HandleFunc("/admin/api/blocking", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIBlockingPost(w, r, s)
		} else {
			adminAPIBlockingGet(w, r, s)
		}
	})

	// Per-client behavior override
	mux.HandleFunc("/admin/api/override", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIOverridePost(w, r, s)
		} else {
			adminAPIOverrideGet(w, r, s)
		}
	})

	// Scanner profile
	mux.HandleFunc("/admin/api/scanner/profile", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerProfile(w, r, s)
	})

	// Scanner run
	mux.HandleFunc("/admin/api/scanner/run", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerRun(w, r, s)
	})

	// Scanner compare
	mux.HandleFunc("/admin/api/scanner/compare", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerCompare(w, r, s)
	})

	// Scanner results
	mux.HandleFunc("/admin/api/scanner/results", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerResults(w, r, s)
	})

	// Scanner stop
	mux.HandleFunc("/admin/api/scanner/stop", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerStop(w, r, s)
	})

	// Scanner comparison history
	mux.HandleFunc("/admin/api/scanner/history", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerHistory(w, r, s)
	})

	// Multi-scanner compare
	mux.HandleFunc("/admin/api/scanner/multi-compare", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerMultiCompare(w, r, s)
	})

	// Scanner baseline
	mux.HandleFunc("/admin/api/scanner/baseline", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerBaseline(w, r, s)
	})

	// Vulnerability controls
	mux.HandleFunc("/admin/api/vulns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIVulnsPost(w, r)
		} else {
			adminAPIVulnsGet(w, r)
		}
	})

	mux.HandleFunc("/admin/api/vulns/group", func(w http.ResponseWriter, r *http.Request) {
		adminAPIVulnsGroupPost(w, r)
	})

	// Error weight controls
	mux.HandleFunc("/admin/api/error-weights", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIErrorWeightsPost(w, r)
		} else {
			adminAPIErrorWeightsGet(w, r)
		}
	})

	// Page type weight controls
	mux.HandleFunc("/admin/api/page-type-weights", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPIPageTypeWeightsPost(w, r)
		} else {
			adminAPIPageTypeWeightsGet(w, r)
		}
	})

	// Config export/import
	mux.HandleFunc("/admin/api/config/export", func(w http.ResponseWriter, r *http.Request) {
		adminAPIConfigExport(w, r, s)
	})

	mux.HandleFunc("/admin/api/config/import", func(w http.ResponseWriter, r *http.Request) {
		adminAPIConfigImport(w, r, s)
	})
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/overview
// ---------------------------------------------------------------------------

func adminAPIOverview(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	records := s.collector.RecentRecords(1000)

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

	statusArr := make([]map[string]interface{}, 0, len(statusCounts))
	for code, cnt := range statusCounts {
		statusArr = append(statusArr, map[string]interface{}{"code": code, "count": cnt})
	}

	typeArr := make([]kv, 0, len(typeCounts))
	for k, v := range typeCounts {
		typeArr = append(typeArr, kv{k, v})
	}
	sort.Slice(typeArr, func(i, j int) bool { return typeArr[i].Count > typeArr[j].Count })

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
		"top_paths":       topPaths,
		"top_user_agents": topUA,
		"status_codes":    statusArr,
		"response_types":  typeArr,
		"sparkline":       sparkline,
		"total_requests":  s.collector.TotalRequests.Load(),
		"total_errors":    s.collector.TotalErrors.Load(),
		"uptime_seconds":  int(s.collector.Uptime().Seconds()),
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

	// Try string-value config first
	var strReq struct {
		Key   string `json:"key"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(body, &strReq); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Check if value is a string
	var strVal string
	if json.Unmarshal(strReq.Value, &strVal) == nil {
		if globalConfig.SetString(strReq.Key, strVal) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"key":   strReq.Key,
				"value": strVal,
			})
			return
		}
	}

	// Otherwise treat as numeric
	var numVal float64
	if json.Unmarshal(strReq.Value, &numVal) == nil {
		if globalConfig.Set(strReq.Key, numVal) {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"key":   strReq.Key,
				"value": numVal,
			})
			return
		}
	}

	http.Error(w, `{"error":"unknown config key"}`, http.StatusBadRequest)
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

	data := make([]map[string]interface{}, 0, len(records))
	for _, rec := range records {
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
// API handler: GET /admin/api/client/{id}
// ---------------------------------------------------------------------------

func adminAPIClientDetail(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	clientID := strings.TrimPrefix(r.URL.Path, "/admin/api/client/")
	if clientID == "" {
		http.Error(w, `{"error":"client_id required"}`, http.StatusBadRequest)
		return
	}

	profiles := s.collector.GetAllClientProfiles()
	var matchedProfile interface{}
	var fullClientID string
	for _, p := range profiles {
		snap := p.Snapshot()
		if snap.ClientID == clientID || strings.HasPrefix(snap.ClientID, clientID) {
			fullClientID = snap.ClientID
			behavior := s.adapt.GetBehavior(snap.ClientID)
			var mode, reason string
			var escalation int
			var botScore float64
			if behavior != nil {
				mode = string(behavior.Mode)
				reason = behavior.Reason
				escalation = behavior.EscalationLevel
				botScore = behavior.BotScore
			}

			pathsList := make([]map[string]interface{}, 0, len(snap.PathsVisited))
			for path, count := range snap.PathsVisited {
				pathsList = append(pathsList, map[string]interface{}{
					"path": path, "count": count,
				})
			}
			sort.Slice(pathsList, func(i, j int) bool {
				return pathsList[i]["count"].(int) > pathsList[j]["count"].(int)
			})

			recentRecords := s.collector.RecentRecords(1000)
			clientRecords := make([]map[string]interface{}, 0)
			for _, rec := range recentRecords {
				if rec.ClientID == fullClientID {
					clientRecords = append(clientRecords, map[string]interface{}{
						"timestamp":     rec.Timestamp.Format(time.RFC3339),
						"method":        rec.Method,
						"path":          rec.Path,
						"status_code":   rec.StatusCode,
						"latency_ms":    rec.Latency.Milliseconds(),
						"response_type": rec.ResponseType,
					})
				}
			}

			matchedProfile = map[string]interface{}{
				"client_id":        snap.ClientID,
				"first_seen":       snap.FirstSeen.Format(time.RFC3339),
				"last_seen":        snap.LastSeen.Format(time.RFC3339),
				"total_requests":   snap.TotalRequests,
				"requests_per_sec": snap.RequestsPerSec,
				"errors_received":  snap.ErrorsReceived,
				"unique_paths":     len(snap.PathsVisited),
				"all_paths":        pathsList,
				"status_codes":     snap.StatusCodes,
				"user_agents":      snap.UserAgents,
				"burst_windows":    snap.BurstWindows,
				"labyrinth_depth":  snap.LabyrinthDepth,
				"adaptive_mode":    mode,
				"adaptive_reason":  reason,
				"escalation_level": escalation,
				"bot_score":        botScore,
				"recent_requests":  clientRecords,
			}
			break
		}
	}

	if matchedProfile == nil {
		http.Error(w, `{"error":"client not found"}`, http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(matchedProfile)
}

// ---------------------------------------------------------------------------
// API handler: GET/POST /admin/api/blocking
// ---------------------------------------------------------------------------

func adminAPIBlockingGet(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	chance, duration, enabled := s.adapt.GetBlockConfig()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":      enabled,
		"chance":       chance,
		"duration_sec": int(duration.Seconds()),
	})
}

func adminAPIBlockingPost(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled     *bool    `json:"enabled"`
		Chance      *float64 `json:"chance"`
		DurationSec *int     `json:"duration_sec"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Enabled != nil {
		s.adapt.SetBlockEnabled(*req.Enabled)
	}
	if req.Chance != nil {
		s.adapt.SetBlockChance(*req.Chance)
	}
	if req.DurationSec != nil {
		s.adapt.SetBlockDuration(time.Duration(*req.DurationSec) * time.Second)
	}

	chance, duration, enabled := s.adapt.GetBlockConfig()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":           true,
		"enabled":      enabled,
		"chance":       chance,
		"duration_sec": int(duration.Seconds()),
	})
}

// ---------------------------------------------------------------------------
// API handler: GET/POST /admin/api/override
// ---------------------------------------------------------------------------

func adminAPIOverrideGet(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	overrides := s.adapt.GetOverrides()
	data := make([]map[string]string, 0, len(overrides))
	for clientID, mode := range overrides {
		data = append(data, map[string]string{
			"client_id": clientID,
			"mode":      string(mode),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"overrides": data,
		"count":     len(data),
	})
}

func adminAPIOverridePost(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Mode     string `json:"mode"`
		Clear    bool   `json:"clear"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" {
		http.Error(w, `{"error":"client_id required"}`, http.StatusBadRequest)
		return
	}

	if req.Clear {
		s.adapt.ClearOverride(req.ClientID)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":        true,
			"client_id": req.ClientID,
			"cleared":   true,
		})
		return
	}

	validModes := map[string]bool{
		"normal": true, "cooperative": true, "aggressive": true,
		"labyrinth": true, "mirror": true, "escalating": true,
		"intermittent": true, "blocked": true,
	}
	if !validModes[req.Mode] {
		http.Error(w, `{"error":"invalid mode"}`, http.StatusBadRequest)
		return
	}

	s.adapt.SetOverride(req.ClientID, adaptive.BehaviorMode(req.Mode))
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"client_id": req.ClientID,
		"mode":      req.Mode,
	})
}

// ---------------------------------------------------------------------------
// Scanner API handlers
// ---------------------------------------------------------------------------

func adminAPIScannerProfile(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	profile := buildScannerProfile()

	runner := getScanRunner()
	available := runner.AvailableScanners()

	resp := map[string]interface{}{
		"profile":            profile,
		"available_scanners": available,
	}

	json.NewEncoder(w).Encode(resp)
}

func adminAPIScannerRun(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Scanner string `json:"scanner"`
		Target  string `json:"target"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	runner := getScanRunner()
	profile := buildScannerProfile()

	if runner.IsRunning(req.Scanner) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "already_running",
			"scanner": req.Scanner,
			"message": "Scanner is already running",
		})
		return
	}

	runID, err := runner.RunScanner(req.Scanner, profile)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "error",
			"scanner": req.Scanner,
			"error":   err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "started",
		"scanner": req.Scanner,
		"run_id":  runID,
		"message": "Scanner started. Poll /admin/api/scanner/results for progress.",
	})
}

func adminAPIScannerCompare(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Scanner string `json:"scanner"`
		Data    string `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	profile := buildScannerProfile()
	report, err := scanner.ParseAndCompare(req.Scanner, []byte(req.Data), profile)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"scanner": req.Scanner,
		})
		return
	}

	// Record in comparison history
	comparisonHistory.Add(report)

	json.NewEncoder(w).Encode(report)
}

func adminAPIScannerResults(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	runner := getScanRunner()
	completed := runner.GetResults()
	running := runner.GetRunning()

	runningList := make([]map[string]interface{}, 0, len(running))
	for name, run := range running {
		runningList = append(runningList, map[string]interface{}{
			"scanner":    name,
			"status":     run.Status,
			"started_at": run.StartedAt.Format(time.RFC3339),
			"elapsed":    time.Since(run.StartedAt).Round(time.Second).String(),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"completed": completed,
		"running":   runningList,
		"count":     len(completed),
	})
}

func adminAPIScannerStop(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Scanner string `json:"scanner"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	runner := getScanRunner()
	stopped := runner.StopScanner(req.Scanner)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scanner": req.Scanner,
		"stopped": stopped,
	})
}

// ---------------------------------------------------------------------------
// Vulnerability control handlers
// ---------------------------------------------------------------------------

func adminAPIVulnsGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalVulnConfig.Snapshot())
}

func adminAPIVulnsPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	globalVulnConfig.SetCategory(req.ID, req.Enabled)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"id":      req.ID,
		"enabled": req.Enabled,
	})
}

func adminAPIVulnsGroupPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Group   string `json:"group"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	globalVulnConfig.SetGroup(req.Group, req.Enabled)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"group":   req.Group,
		"enabled": req.Enabled,
	})
}

// ---------------------------------------------------------------------------
// Error weight handlers
// ---------------------------------------------------------------------------

func adminAPIErrorWeightsGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"weights": globalConfig.GetErrorWeights(),
	})
}

func adminAPIErrorWeightsPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		ErrorType string  `json:"error_type"`
		Weight    float64 `json:"weight"`
		Reset     bool    `json:"reset"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Reset {
		globalConfig.ResetErrorWeights()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"reset":   true,
			"weights": globalConfig.GetErrorWeights(),
		})
		return
	}

	globalConfig.SetErrorWeight(req.ErrorType, req.Weight)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":         true,
		"error_type": req.ErrorType,
		"weight":     req.Weight,
	})
}

// ---------------------------------------------------------------------------
// Page type weight handlers
// ---------------------------------------------------------------------------

func adminAPIPageTypeWeightsGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"weights": globalConfig.GetPageTypeWeights(),
	})
}

func adminAPIPageTypeWeightsPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		PageType string  `json:"page_type"`
		Weight   float64 `json:"weight"`
		Reset    bool    `json:"reset"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Reset {
		globalConfig.ResetPageTypeWeights()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"reset":   true,
			"weights": globalConfig.GetPageTypeWeights(),
		})
		return
	}

	globalConfig.SetPageTypeWeight(req.PageType, req.Weight)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"page_type": req.PageType,
		"weight":    req.Weight,
	})
}

// ---------------------------------------------------------------------------
// Config export/import handlers
// ---------------------------------------------------------------------------

func adminAPIConfigExport(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)

	export := ExportConfig()
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=glitch-config.json")
	w.Write(data)
}

func adminAPIConfigImport(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var export ConfigExport
	if err := json.Unmarshal(body, &export); err != nil {
		http.Error(w, `{"error":"invalid JSON: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	ImportConfig(&export)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Configuration imported successfully",
		"version": export.Version,
	})
}

// ---------------------------------------------------------------------------
// Scanner comparison history & multi-compare handlers
// ---------------------------------------------------------------------------

func adminAPIScannerHistory(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	scannerFilter := r.URL.Query().Get("scanner")
	var entries []scanner.HistoryEntry
	if scannerFilter != "" {
		entries = comparisonHistory.GetByScanner(scannerFilter)
	} else {
		entries = comparisonHistory.GetAll()
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

func adminAPIScannerMultiCompare(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Reports map[string]string `json:"reports"` // scanner name -> raw output
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	profile := buildScannerProfile()
	reports := make(map[string]*scanner.ComparisonReport, len(req.Reports))

	for scannerName, rawOutput := range req.Reports {
		report, err := scanner.ParseAndCompare(scannerName, []byte(rawOutput), profile)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   err.Error(),
				"scanner": scannerName,
			})
			return
		}
		reports[scannerName] = report
		// Also record each individual report in history
		comparisonHistory.Add(report)
	}

	mc := scanner.CompareMultiple(reports, profile)
	json.NewEncoder(w).Encode(mc)
}

func adminAPIScannerBaseline(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	scannerName := r.URL.Query().Get("scanner")
	if scannerName == "" {
		http.Error(w, `{"error":"scanner parameter required"}`, http.StatusBadRequest)
		return
	}

	baseline := comparisonHistory.GetBaseline(scannerName)
	if baseline == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scanner":  scannerName,
			"baseline": nil,
			"message":  "no baseline found for this scanner",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"scanner":  scannerName,
		"baseline": baseline,
	})
}
