package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/audit"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/replay"
	"github.com/glitchWebServer/internal/scaneval"
)

// ---------------------------------------------------------------------------
// Pagination helpers
// ---------------------------------------------------------------------------

// parsePagination extracts limit and offset query parameters.
// Defaults: limit=100, offset=0. Max limit=1000.
func parsePagination(r *http.Request) (limit, offset int) {
	limit = 100
	offset = 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 1000 {
				limit = 1000
			}
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

// paginateSlice applies offset and limit to a slice length, returning
// the start and end indices to use for slicing.
func paginateSlice(total, limit, offset int) (start, end int) {
	start = offset
	if start > total {
		start = total
	}
	end = start + limit
	if end > total {
		end = total
	}
	return
}

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

	// Proxy status and mode
	mux.HandleFunc("/admin/api/proxy/status", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalProxyConfig.Snapshot())
	})

	// Proxy runtime lifecycle control
	mux.HandleFunc("/admin/api/proxy/runtime", func(w http.ResponseWriter, r *http.Request) {
		adminAPIProxyRuntime(w, r)
	})

	mux.HandleFunc("/admin/api/proxy/mode", func(w http.ResponseWriter, r *http.Request) {
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
			Mode           string `json:"mode"`
			WAFBlockAction string `json:"waf_block_action"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		oldMode := globalProxyConfig.GetMode()
		if !globalProxyConfig.SetMode(req.Mode) {
			http.Error(w, `{"error":"invalid proxy mode"}`, http.StatusBadRequest)
			return
		}
		audit.Log("admin", "proxy.mode_change", "proxy.mode", oldMode, req.Mode, nil)
		TriggerAutoSave()
		resp := map[string]interface{}{
			"ok":   true,
			"mode": req.Mode,
		}
		if req.Mode == "mirror" {
			resp["mirror"] = globalProxyConfig.GetMirror()
		}
		json.NewEncoder(w).Encode(resp)
	})

	// Mirror refresh — re-snapshot server settings into proxy mirror config
	mux.HandleFunc("/admin/api/proxy/mirror/refresh", func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
			return
		}
		mc := SnapshotMirrorFromServer()
		globalProxyConfig.SetMirror(mc)
		audit.LogAction("admin", "proxy.mirror_refresh", "proxy.mirror", nil)
		TriggerAutoSave()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"mirror": mc,
		})
	})

	// Spider config
	mux.HandleFunc("/admin/api/spider", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPISpiderPost(w, r)
		} else {
			adminAPISpiderGet(w, r)
		}
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

	// Replay endpoints
	mux.HandleFunc("/admin/api/replay/files", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayFiles(w, r)
	})
	mux.HandleFunc("/admin/api/replay/status", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayStatus(w, r)
	})
	mux.HandleFunc("/admin/api/replay/load", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayLoad(w, r)
	})
	mux.HandleFunc("/admin/api/replay/start", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayStart(w, r)
	})
	mux.HandleFunc("/admin/api/replay/stop", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayStop(w, r)
	})
	mux.HandleFunc("/admin/api/replay/upload", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayUpload(w, r)
	})
	mux.HandleFunc("/admin/api/replay/fetch-url", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayFetchURL(w, r)
	})
	mux.HandleFunc("/admin/api/replay/metadata", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayMetadata(w, r)
	})
	mux.HandleFunc("/admin/api/replay/cleanup", func(w http.ResponseWriter, r *http.Request) {
		adminAPIReplayCleanup(w, r)
	})

	// Recorder controls
	mux.HandleFunc("/admin/api/recorder/status", func(w http.ResponseWriter, r *http.Request) {
		adminAPIRecorderStatus(w, r)
	})
	mux.HandleFunc("/admin/api/recorder/start", func(w http.ResponseWriter, r *http.Request) {
		adminAPIRecorderStart(w, r)
	})
	mux.HandleFunc("/admin/api/recorder/stop", func(w http.ResponseWriter, r *http.Request) {
		adminAPIRecorderStop(w, r)
	})
	mux.HandleFunc("/admin/api/recorder/files", func(w http.ResponseWriter, r *http.Request) {
		adminAPIRecorderFiles(w, r)
	})

	// Nightmare mode
	mux.HandleFunc("/admin/api/nightmare", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			adminAPINightmarePost(w, r, s)
		} else {
			adminAPINightmareGet(w, r)
		}
	})

	// Password change
	mux.HandleFunc("/admin/api/password", func(w http.ResponseWriter, r *http.Request) {
		adminAPIPasswordChange(w, r)
	})

	// Audit log
	mux.HandleFunc("/admin/api/audit", func(w http.ResponseWriter, r *http.Request) {
		adminAPIAudit(w, r)
	})

	// API Chaos
	mux.HandleFunc("/admin/api/apichaos/category", func(w http.ResponseWriter, r *http.Request) {
		adminAPIChaosCategory(w, r)
	})
	mux.HandleFunc("/admin/api/apichaos/probability", func(w http.ResponseWriter, r *http.Request) {
		adminAPIChaosProbability(w, r)
	})
	mux.HandleFunc("/admin/api/apichaos/all", func(w http.ResponseWriter, r *http.Request) {
		adminAPIChaosAll(w, r)
	})
	mux.HandleFunc("/admin/api/apichaos", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			adminAPIChaosGet(w, r)
		} else if r.Method == http.MethodPost {
			adminAPIChaosToggle(w, r)
		} else {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	// Media chaos routes
	mux.HandleFunc("/admin/api/mediachaos/category", func(w http.ResponseWriter, r *http.Request) {
		adminMediaChaosCategory(w, r)
	})
	mux.HandleFunc("/admin/api/mediachaos/probability", func(w http.ResponseWriter, r *http.Request) {
		adminMediaChaosProbability(w, r)
	})
	mux.HandleFunc("/admin/api/mediachaos/all", func(w http.ResponseWriter, r *http.Request) {
		adminMediaChaosAll(w, r)
	})
	mux.HandleFunc("/admin/api/mediachaos", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			adminMediaChaosGet(w, r)
		} else if r.Method == http.MethodPost {
			adminMediaChaosToggle(w, r)
		} else {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/audit
// ---------------------------------------------------------------------------

func adminAPIAudit(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()

	limit := 50
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
			if limit > 200 {
				limit = 200
			}
		}
	}

	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	opts := audit.QueryOpts{
		Limit:    limit,
		Offset:   offset,
		Actor:    q.Get("actor"),
		Action:   q.Get("action"),
		Resource: q.Get("resource"),
		Status:   q.Get("status"),
	}

	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.To = &t
		}
	}

	result := audit.Query(opts)

	resp := struct {
		Entries []audit.Entry    `json:"entries"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
		Filters audit.FilterInfo `json:"filters"`
	}{
		Entries: result.Entries,
		Total:   result.Total,
		Limit:   limit,
		Offset:  offset,
		Filters: result.Filters,
	}

	if resp.Entries == nil {
		resp.Entries = []audit.Entry{}
	}

	json.NewEncoder(w).Encode(resp)
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
	sort.Slice(statusArr, func(i, j int) bool {
		return statusArr[i]["code"].(int) < statusArr[j]["code"].(int)
	})

	typeArr := make([]kv, 0, len(typeCounts))
	for k, v := range typeCounts {
		typeArr = append(typeArr, kv{k, v})
	}
	sort.Slice(typeArr, func(i, j int) bool {
		if typeArr[i].Count != typeArr[j].Count {
			return typeArr[i].Count > typeArr[j].Count
		}
		return typeArr[i].Key < typeArr[j].Key // stable tie-break by key
	})

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

	old := globalFlags.Snapshot()[req.Feature]
	if !globalFlags.Set(req.Feature, req.Enabled) {
		http.Error(w, `{"error":"unknown feature"}`, http.StatusBadRequest)
		return
	}

	if old != req.Enabled {
		audit.Log("admin", "feature.toggle", "feature_flags."+req.Feature, old, req.Enabled, nil)
	}
	TriggerAutoSave()
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

	// Capture old config for audit logging
	oldCfg := globalConfig.Get()
	oldVal := oldCfg[strReq.Key]

	// Check if value is a string
	var strVal string
	if json.Unmarshal(strReq.Value, &strVal) == nil {
		if globalConfig.SetString(strReq.Key, strVal) {
			audit.Log("admin", "config.change", "admin_config."+strReq.Key, oldVal, strVal, nil)
			TriggerAutoSave()
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
			audit.Log("admin", "config.change", "admin_config."+strReq.Key, oldVal, numVal, nil)
			TriggerAutoSave()
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

	limit, offset := parsePagination(r)
	filter := strings.ToLower(r.URL.Query().Get("filter"))

	// Fetch a large window of records for filtering
	records := s.collector.RecentRecords(1000)

	all := make([]map[string]interface{}, 0, len(records))
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

		all = append(all, map[string]interface{}{
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

	total := len(all)
	start, end := paginateSlice(total, limit, offset)
	page := all[start:end]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":    page,
		"records": page,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"count":   len(page),
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

			// Check for active override (may not be reflected in behavior yet)
			var overrideMode string
			overrides := s.adapt.GetOverrides()
			if om, ok := overrides[snap.ClientID]; ok {
				overrideMode = string(om)
				if mode == "" {
					mode = overrideMode
					reason = "manual override"
				}
			}

			pathsList := make([]map[string]interface{}, 0, len(snap.PathsVisited))
			for path, count := range snap.PathsVisited {
				pathsList = append(pathsList, map[string]interface{}{
					"path": path, "count": count,
				})
			}
			sort.Slice(pathsList, func(i, j int) bool {
				ci, cj := pathsList[i]["count"].(int), pathsList[j]["count"].(int)
				if ci != cj {
					return ci > cj
				}
				return pathsList[i]["path"].(string) < pathsList[j]["path"].(string) // stable tie-break
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
				"override_mode":    overrideMode,
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

	oldChance, oldDuration, oldEnabled := s.adapt.GetBlockConfig()

	if req.Enabled != nil {
		s.adapt.SetBlockEnabled(*req.Enabled)
		audit.Log("admin", "blocking.config_change", "blocking.enabled", oldEnabled, *req.Enabled, nil)
	}
	if req.Chance != nil {
		s.adapt.SetBlockChance(*req.Chance)
		globalConfig.Set("block_chance", *req.Chance)
		audit.Log("admin", "blocking.config_change", "blocking.chance", oldChance, *req.Chance, nil)
	}
	if req.DurationSec != nil {
		s.adapt.SetBlockDuration(time.Duration(*req.DurationSec) * time.Second)
		globalConfig.Set("block_duration_sec", float64(*req.DurationSec))
		audit.Log("admin", "blocking.config_change", "blocking.duration_sec", int(oldDuration.Seconds()), *req.DurationSec, nil)
	}

	TriggerAutoSave()
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
	sort.Slice(data, func(i, j int) bool {
		return data[i]["client_id"] < data[j]["client_id"]
	})

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

	// Capture old override for audit
	oldOverrides := s.adapt.GetOverrides()
	oldMode := ""
	if om, ok := oldOverrides[req.ClientID]; ok {
		oldMode = string(om)
	}

	if req.Clear {
		s.adapt.ClearOverride(req.ClientID)
		audit.LogAction("admin", "client.override_clear", "client."+req.ClientID, map[string]interface{}{"old_mode": oldMode})
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
	audit.Log("admin", "client.override", "client."+req.ClientID, oldMode, req.Mode, nil)
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

	// Compute summary statistics
	detectable := 0
	for _, v := range profile.Vulnerabilities {
		if v.Detectable {
			detectable++
		}
	}

	vulnSnap := globalVulnConfig.Snapshot()
	enabledGroups := 0
	totalGroups := len(VulnGroups)
	if groups, ok := vulnSnap["groups"].(map[string]bool); ok {
		for _, enabled := range groups {
			if enabled {
				enabledGroups++
			}
		}
	}

	summary := map[string]interface{}{
		"total":           profile.TotalVulns,
		"detectable":      detectable,
		"by_severity":     profile.BySeverity,
		"enabled_groups":  enabledGroups,
		"total_groups":    totalGroups,
		"total_endpoints": profile.TotalEndpoints,
	}

	resp := map[string]interface{}{
		"profile":            profile,
		"summary":            summary,
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

	audit.LogAction("admin", "scanner.run", "scanner.external."+req.Scanner, map[string]interface{}{"target": req.Target, "run_id": runID})
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
		Scanner   string `json:"scanner"`
		Data      string `json:"data"`
		ScanStart string `json:"scan_start"` // optional RFC3339 timestamp
		ScanEnd   string `json:"scan_end"`   // optional RFC3339 timestamp
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	profile := buildScannerProfile()
	report, err := scaneval.ParseAndCompare(req.Scanner, []byte(req.Data), profile)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   err.Error(),
			"scanner": req.Scanner,
		})
		return
	}

	// Classify false negatives using server request logs when time window is provided
	classifyFNFromCollector(report, s, req.ScanStart, req.ScanEnd)

	// Record in comparison history
	comparisonHistory.Add(report)

	// Persist to PostgreSQL
	go PersistComparisonToDB(report, req.Scanner, report.Grade, report.DetectionRate)

	audit.LogAction("admin", "scanner.compare", "scanner.compare", map[string]interface{}{"scanner": req.Scanner})
	json.NewEncoder(w).Encode(report)
}

// classifyFNFromCollector classifies false negatives in a comparison report
// by cross-referencing with the metrics collector's request logs.
// If scanStart/scanEnd are provided (RFC3339), it uses only requests in that
// window. Otherwise it falls back to the last hour of request data.
func classifyFNFromCollector(report *scaneval.ComparisonReport, s *Server, scanStart, scanEnd string) {
	if len(report.FalseNegatives) == 0 {
		return
	}

	var start, end time.Time
	var err error

	if scanStart != "" {
		start, err = time.Parse(time.RFC3339, scanStart)
		if err != nil {
			start = time.Time{}
		}
	}
	if scanEnd != "" {
		end, err = time.Parse(time.RFC3339, scanEnd)
		if err != nil {
			end = time.Time{}
		}
	}

	// Default to last hour if no valid time window provided
	if start.IsZero() || end.IsZero() {
		end = time.Now()
		start = end.Add(-1 * time.Hour)
	}

	accessedPaths := s.collector.GetPathsInTimeWindow(start, end)
	scaneval.ClassifyFalseNegatives(report, accessedPaths)
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
	sort.Slice(runningList, func(i, j int) bool {
		return runningList[i]["scanner"].(string) < runningList[j]["scanner"].(string)
	})

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

	audit.LogAction("admin", "scanner.stop", "scanner.external", map[string]interface{}{"scanner": req.Scanner, "stopped": stopped})
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

	// Capture old state for audit
	oldSnap := globalVulnConfig.Snapshot()
	var oldEnabled interface{}
	if cats, ok := oldSnap["categories"].(map[string]bool); ok {
		oldEnabled = cats[req.ID]
	}

	globalVulnConfig.SetCategory(req.ID, req.Enabled)
	audit.Log("admin", "vuln.category_toggle", "vuln_config.categories."+req.ID, oldEnabled, req.Enabled, nil)
	TriggerAutoSave()
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

	// Validate group name
	validGroup := false
	for _, g := range VulnGroups {
		if g == req.Group {
			validGroup = true
			break
		}
	}
	if !validGroup {
		http.Error(w, `{"error":"unknown vuln group"}`, http.StatusBadRequest)
		return
	}

	// Capture old state for audit
	oldGroupSnap := globalVulnConfig.Snapshot()
	var oldGroupEnabled interface{}
	if groups, ok := oldGroupSnap["groups"].(map[string]bool); ok {
		oldGroupEnabled = groups[req.Group]
	}

	globalVulnConfig.SetGroup(req.Group, req.Enabled)
	audit.Log("admin", "vuln.group_toggle", "vuln_config.groups."+req.Group, oldGroupEnabled, req.Enabled, nil)
	TriggerAutoSave()
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
		oldWeights := globalConfig.GetErrorWeights()
		globalConfig.ResetErrorWeights()
		audit.Log("admin", "config.error_weight", "error_weights.reset", oldWeights, globalConfig.GetErrorWeights(), nil)
		TriggerAutoSave()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"reset":   true,
			"weights": globalConfig.GetErrorWeights(),
		})
		return
	}

	oldWeight := globalConfig.GetErrorWeights()[req.ErrorType]
	globalConfig.SetErrorWeight(req.ErrorType, req.Weight)
	audit.Log("admin", "config.error_weight", "error_weights."+req.ErrorType, oldWeight, req.Weight, nil)
	TriggerAutoSave()
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
		oldPTWeights := globalConfig.GetPageTypeWeights()
		globalConfig.ResetPageTypeWeights()
		audit.Log("admin", "config.page_type_weight", "page_type_weights.reset", oldPTWeights, globalConfig.GetPageTypeWeights(), nil)
		TriggerAutoSave()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":      true,
			"reset":   true,
			"weights": globalConfig.GetPageTypeWeights(),
		})
		return
	}

	oldPTWeight := globalConfig.GetPageTypeWeights()[req.PageType]
	globalConfig.SetPageTypeWeight(req.PageType, req.Weight)
	audit.Log("admin", "config.page_type_weight", "page_type_weights."+req.PageType, oldPTWeight, req.Weight, nil)
	TriggerAutoSave()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"page_type": req.PageType,
		"weight":    req.Weight,
	})
}

// ---------------------------------------------------------------------------
// Spider config handlers
// ---------------------------------------------------------------------------

func adminAPISpiderGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalSpiderConfig.Snapshot())
}

func adminAPISpiderPost(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Key   string      `json:"key"`
		Value interface{} `json:"value"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// JSON numbers decode as float64; convert appropriately for the spider config.
	var typedValue interface{}
	switch v := req.Value.(type) {
	case float64:
		typedValue = v
	case bool:
		typedValue = v
	case string:
		typedValue = v
	default:
		typedValue = req.Value
	}

	oldSpiderSnap := globalSpiderConfig.Snapshot()
	oldSpiderVal := oldSpiderSnap[req.Key]

	if !globalSpiderConfig.Set(req.Key, typedValue) {
		http.Error(w, `{"error":"unknown key or invalid value type"}`, http.StatusBadRequest)
		return
	}

	audit.Log("admin", "spider.config_change", "spider_config."+req.Key, oldSpiderVal, req.Value, nil)
	TriggerAutoSave()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"key":   req.Key,
		"value": req.Value,
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

	audit.LogAction("admin", "config.export", "config.export", nil)
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
	audit.LogAction("admin", "config.import", "config.import", nil)
	TriggerAutoSave()
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

	limit, offset := parsePagination(r)
	scannerFilter := r.URL.Query().Get("scanner")
	var entries []scaneval.HistoryEntry
	if scannerFilter != "" {
		entries = comparisonHistory.GetByScanner(scannerFilter)
	} else {
		entries = comparisonHistory.GetAll()
	}

	total := len(entries)
	start, end := paginateSlice(total, limit, offset)
	page := entries[start:end]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":    page,
		"entries": page,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"count":   len(page),
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
		Reports   map[string]string `json:"reports"`    // scanner name -> raw output
		ScanStart string            `json:"scan_start"` // optional RFC3339 timestamp
		ScanEnd   string            `json:"scan_end"`   // optional RFC3339 timestamp
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	profile := buildScannerProfile()
	reports := make(map[string]*scaneval.ComparisonReport, len(req.Reports))

	for scannerName, rawOutput := range req.Reports {
		report, err := scaneval.ParseAndCompare(scannerName, []byte(rawOutput), profile)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   err.Error(),
				"scanner": scannerName,
			})
			return
		}
		// Classify false negatives using server request logs
		classifyFNFromCollector(report, s, req.ScanStart, req.ScanEnd)
		reports[scannerName] = report
		// Also record each individual report in history
		comparisonHistory.Add(report)
		// Persist to PostgreSQL
		go PersistComparisonToDB(report, scannerName, report.Grade, report.DetectionRate)
	}

	mc := scaneval.CompareMultiple(reports, profile)
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

// ---------------------------------------------------------------------------
// Replay API handlers
// ---------------------------------------------------------------------------

var (
	replayPlayerMu     sync.Mutex
	replayPlayer       *replay.Player
	replayLoadedFile   string
	replayLoadedPkts   []*replay.Packet
	replayCancel       context.CancelFunc
	replayMetadata     map[string]interface{} // Cached metadata for loaded packets
)

func adminAPIReplayFiles(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	type fileInfo struct {
		Name     string `json:"name"`
		Size     string `json:"size"`
		Modified string `json:"modified"`
	}

	var files []fileInfo
	captureDir := "captures"
	entries, err := os.ReadDir(captureDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".pcap" && ext != ".jsonl" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			size := info.Size()
			sizeStr := fmt.Sprintf("%d B", size)
			if size > 1<<20 {
				sizeStr = fmt.Sprintf("%.1f MB", float64(size)/(1<<20))
			} else if size > 1<<10 {
				sizeStr = fmt.Sprintf("%.1f KB", float64(size)/(1<<10))
			}
			files = append(files, fileInfo{
				Name:     e.Name(),
				Size:     sizeStr,
				Modified: info.ModTime().Format("2006-01-02 15:04:05"),
			})
		}
	}

	if files == nil {
		files = []fileInfo{}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
		"count": len(files),
	})
}

func adminAPIReplayStatus(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	replayPlayerMu.Lock()
	defer replayPlayerMu.Unlock()

	resp := map[string]interface{}{
		"playing":        false,
		"loaded_file":    replayLoadedFile,
		"packets_loaded": 0,
		"packets_played": 0,
		"errors":         0,
		"elapsed_ms":     0,
	}

	if replayPlayer != nil {
		stats := replayPlayer.GetStats()
		resp["playing"] = replayPlayer.IsPlaying()
		resp["packets_loaded"] = stats.PacketsLoaded
		resp["packets_played"] = stats.PacketsPlayed
		resp["errors"] = stats.Errors
		resp["elapsed_ms"] = stats.ElapsedMs
	} else if len(replayLoadedPkts) > 0 {
		resp["packets_loaded"] = len(replayLoadedPkts)
	}

	if replayMetadata != nil {
		resp["metadata"] = replayMetadata
	}

	json.NewEncoder(w).Encode(resp)
}

func adminAPIReplayLoad(w http.ResponseWriter, r *http.Request) {
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
		File string `json:"file"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Sanitize filename — no path traversal.
	filename := filepath.Base(req.File)
	path := filepath.Join("captures", filename)

	packets, err := replay.LoadFile(path)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	meta := replay.ParseMetadata(packets)

	replayPlayerMu.Lock()
	// Stop any existing playback.
	if replayPlayer != nil && replayPlayer.IsPlaying() {
		replayPlayer.Stop()
	}
	if replayCancel != nil {
		replayCancel()
	}
	replayLoadedPkts = packets
	replayLoadedFile = filename
	replayMetadata = meta
	replayPlayer = nil
	replayCancel = nil
	replayPlayerMu.Unlock()

	audit.LogAction("admin", "replay.load", "replay."+filename, map[string]interface{}{"packets": len(packets)})
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"file":    filename,
		"packets": len(packets),
	})
}

func adminAPIReplayStart(w http.ResponseWriter, r *http.Request) {
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
		Target     string  `json:"target"`
		Timing     string  `json:"timing"`
		Speed      float64 `json:"speed"`
		FilterPath string  `json:"filter_path"`
		Loop       bool    `json:"loop"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		req.Target = "http://localhost:8765"
	}
	if req.Timing == "" {
		req.Timing = "burst"
	}
	if req.Speed <= 0 {
		req.Speed = 1.0
	}

	replayPlayerMu.Lock()
	if len(replayLoadedPkts) == 0 {
		replayPlayerMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "no packets loaded — load a capture file first",
		})
		return
	}

	if replayPlayer != nil && replayPlayer.IsPlaying() {
		replayPlayerMu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "replay already in progress",
		})
		return
	}

	cfg := replay.Config{
		TimingMode: req.Timing,
		Speed:      req.Speed,
		FilterPath: req.FilterPath,
		Loop:       req.Loop,
	}

	player := replay.NewPlayer(replayLoadedPkts, cfg)
	replayPlayer = player

	ctx, cancel := context.WithCancel(context.Background())
	replayCancel = cancel
	replayPlayerMu.Unlock()

	// Start playback in background.
	go func() {
		player.Play(ctx, req.Target)
	}()

	audit.LogAction("admin", "replay.start", "replay", map[string]interface{}{"timing": req.Timing, "target": req.Target, "speed": req.Speed})
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"target":  req.Target,
		"timing":  req.Timing,
		"speed":   req.Speed,
		"packets": len(replayLoadedPkts),
	})
}

func adminAPIReplayStop(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	replayPlayerMu.Lock()
	if replayPlayer != nil {
		replayPlayer.Stop()
	}
	if replayCancel != nil {
		replayCancel()
		replayCancel = nil
	}
	replayPlayerMu.Unlock()

	audit.LogAction("admin", "replay.stop", "replay", nil)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "replay stopped",
	})
}

// ---------------------------------------------------------------------------
// Replay upload, fetch-url, metadata, cleanup handlers
// ---------------------------------------------------------------------------

// sanitizeFilename strips any path components and dangerous characters.
var reFilenameSafe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = reFilenameSafe.ReplaceAllString(name, "_")
	if name == "" || name == "." || name == ".." {
		name = "upload"
	}
	return name
}

func formatSize(n int64) string {
	if n > 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	if n > 1<<10 {
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

const maxUploadSize = 100 << 20 // 100 MB

func adminAPIReplayUpload(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	// Limit the entire request body to maxUploadSize.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "file too large or invalid multipart form",
		})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "missing 'file' field in upload",
		})
		return
	}
	defer file.Close()

	filename := sanitizeFilename(header.Filename)
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".pcap" && ext != ".jsonl" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "unsupported file type: must be .pcap or .jsonl",
		})
		return
	}

	// Ensure captures directory exists.
	if err := os.MkdirAll("captures", 0o755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "cannot create captures directory",
		})
		return
	}

	destPath := filepath.Join("captures", filename)
	dst, err := os.Create(destPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "cannot create file: " + err.Error(),
		})
		return
	}

	written, err := io.Copy(dst, io.LimitReader(file, maxUploadSize))
	dst.Close()
	if err != nil {
		os.Remove(destPath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "write error: " + err.Error(),
		})
		return
	}

	audit.LogAction("admin", "replay.upload", "replay.upload", map[string]interface{}{"filename": filename, "size": formatSize(written)})
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":   true,
		"file": filename,
		"size": formatSize(written),
	})
}

func adminAPIReplayFetchURL(w http.ResponseWriter, r *http.Request) {
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
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "url is required",
		})
		return
	}

	parsed, err := url.Parse(req.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "invalid URL: must be http or https",
		})
		return
	}

	// Build a sanitized filename from the URL.
	hostPart := sanitizeFilename(parsed.Host)
	basePart := sanitizeFilename(filepath.Base(parsed.Path))
	if basePart == "" || basePart == "." || basePart == "upload" {
		basePart = "capture.pcap"
	}
	filename := hostPart + "_" + basePart
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".pcap" && ext != ".jsonl" {
		filename += ".pcap"
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(req.URL)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "download failed: " + err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("download returned HTTP %d", resp.StatusCode),
		})
		return
	}

	if err := os.MkdirAll("captures", 0o755); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "cannot create captures directory",
		})
		return
	}

	destPath := filepath.Join("captures", filename)
	dst, err := os.Create(destPath)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "cannot create file: " + err.Error(),
		})
		return
	}

	written, err := io.Copy(dst, io.LimitReader(resp.Body, maxUploadSize))
	dst.Close()
	if err != nil {
		os.Remove(destPath)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "write error: " + err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":   true,
		"file": filename,
		"size": formatSize(written),
	})
}

func adminAPIReplayMetadata(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	replayPlayerMu.Lock()
	meta := replayMetadata
	pkts := replayLoadedPkts
	replayPlayerMu.Unlock()

	if meta != nil {
		json.NewEncoder(w).Encode(meta)
		return
	}

	// Compute from loaded packets if available but not cached.
	if len(pkts) > 0 {
		computed := replay.ParseMetadata(pkts)
		replayPlayerMu.Lock()
		replayMetadata = computed
		replayPlayerMu.Unlock()
		json.NewEncoder(w).Encode(computed)
		return
	}

	// Nothing loaded.
	json.NewEncoder(w).Encode(replay.ParseMetadata(nil))
}

func adminAPIReplayCleanup(w http.ResponseWriter, r *http.Request) {
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
		MaxSizeMB float64 `json:"max_size_mb"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.MaxSizeMB <= 0 {
		req.MaxSizeMB = 500
	}

	maxBytes := int64(req.MaxSizeMB * (1 << 20))

	captureDir := "captures"
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": "cannot read captures directory: " + err.Error(),
		})
		return
	}

	type fileEntry struct {
		Name    string
		Size    int64
		ModTime time.Time
	}

	var files []fileEntry
	var totalSize int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".pcap" && ext != ".jsonl" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		totalSize += info.Size()
		files = append(files, fileEntry{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	// Sort oldest first.
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.Before(files[j].ModTime)
	})

	var deletedCount int
	var freedBytes int64

	for _, f := range files {
		if totalSize <= maxBytes {
			break
		}
		path := filepath.Join(captureDir, f.Name)
		if err := os.Remove(path); err != nil {
			continue
		}
		deletedCount++
		freedBytes += f.Size
		totalSize -= f.Size
	}

	audit.LogAction("admin", "replay.cleanup", "replay.cleanup", map[string]interface{}{"deleted": deletedCount, "freed_mb": float64(freedBytes) / (1 << 20)})
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"deleted":  deletedCount,
		"freed_mb": float64(freedBytes) / (1 << 20),
	})
}

// ---------------------------------------------------------------------------
// API handler: GET/POST /admin/api/proxy/runtime
// ---------------------------------------------------------------------------

func adminAPIProxyRuntime(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(globalProxyManager.Status())
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"GET or POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
		Target string `json:"target"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Apply defaults
	if req.Port == 0 {
		req.Port = 8080
	}
	if req.Target == "" {
		req.Target = "http://localhost:8765"
	}

	switch req.Action {
	case "start":
		if err := globalProxyManager.Start(req.Port, req.Target); err != nil {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		audit.LogAction("admin", "proxy.start", "proxy.runtime", map[string]interface{}{"port": req.Port, "target": req.Target})
	case "stop":
		if err := globalProxyManager.Stop(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		audit.LogAction("admin", "proxy.stop", "proxy.runtime", nil)
	case "restart":
		if err := globalProxyManager.Restart(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
			})
			return
		}
		audit.LogAction("admin", "proxy.restart", "proxy.runtime", nil)
	default:
		http.Error(w, `{"error":"invalid action, use: start, stop, restart"}`, http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(globalProxyManager.Status())
}

// ---------------------------------------------------------------------------
// Recorder API handlers
// ---------------------------------------------------------------------------

func adminAPIRecorderStatus(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	rec := globalRecorder
	if rec == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "recorder not initialized",
		})
		return
	}

	json.NewEncoder(w).Encode(rec.GetStatus())
}

func adminAPIRecorderStart(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	rec := globalRecorder
	if rec == nil {
		http.Error(w, `{"error":"recorder not initialized"}`, http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Format         string `json:"format"`
		MaxDurationSec int    `json:"max_duration_sec"`
		MaxRequests    int64  `json:"max_requests"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
	}

	// Set format before starting
	if req.Format == "pcap" || req.Format == "jsonl" {
		rec.SetFormat(req.Format)
	}

	if req.MaxDurationSec > 0 || req.MaxRequests > 0 {
		rec.StartWithLimits(req.MaxDurationSec, req.MaxRequests)
	} else {
		rec.Start()
	}

	audit.LogAction("admin", "recorder.start", "recorder", map[string]interface{}{"format": req.Format})
	status := rec.GetStatus()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"status": status,
	})
}

func adminAPIRecorderStop(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	rec := globalRecorder
	if rec == nil {
		http.Error(w, `{"error":"recorder not initialized"}`, http.StatusInternalServerError)
		return
	}

	rec.Stop()

	audit.LogAction("admin", "recorder.stop", "recorder", nil)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "recording stopped",
	})
}

func adminAPIRecorderFiles(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	rec := globalRecorder
	if rec == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	captures := rec.GetCaptures()
	if captures == nil {
		captures = []recorder.CaptureInfo{}
	}

	json.NewEncoder(w).Encode(captures)
}

// ---------------------------------------------------------------------------
// API handler: GET /admin/api/nightmare
// ---------------------------------------------------------------------------

func adminAPINightmareGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(globalNightmare.Snapshot())
}

// ---------------------------------------------------------------------------
// API handler: POST /admin/api/nightmare
// ---------------------------------------------------------------------------

func adminAPINightmarePost(w http.ResponseWriter, r *http.Request, s *Server) {
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
		Mode    string `json:"mode"`    // "all", "server", "scanner", "proxy"
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	globalNightmare.mu.Lock()
	defer globalNightmare.mu.Unlock()

	switch req.Mode {
	case "all":
		if req.Enabled {
			// Activate all modes
			if !globalNightmare.ServerActive {
				applyServerNightmare()
			}
			globalNightmare.ServerActive = true
			globalNightmare.ScannerActive = true
			globalNightmare.ProxyActive = true
			applyProxyNightmare(s)
			audit.Log("admin", "nightmare.all_enable", "nightmare.all", false, true, nil)
		} else {
			// Deactivate all modes
			if globalNightmare.ServerActive {
				restoreServerNightmare()
			}
			globalNightmare.ServerActive = false
			globalNightmare.ScannerActive = false
			globalNightmare.ProxyActive = false
			restoreProxyNightmare(s)
			audit.Log("admin", "nightmare.all_disable", "nightmare.all", true, false, nil)
		}
	case "server":
		oldServerActive := globalNightmare.ServerActive
		if req.Enabled && !globalNightmare.ServerActive {
			applyServerNightmare()
		} else if !req.Enabled && globalNightmare.ServerActive {
			restoreServerNightmare()
		}
		globalNightmare.ServerActive = req.Enabled
		if req.Enabled {
			audit.Log("admin", "nightmare.server_enable", "nightmare.server", oldServerActive, true, nil)
		} else {
			audit.Log("admin", "nightmare.server_disable", "nightmare.server", oldServerActive, false, nil)
		}
	case "scanner":
		oldScannerActive := globalNightmare.ScannerActive
		globalNightmare.ScannerActive = req.Enabled
		if req.Enabled {
			audit.Log("admin", "nightmare.scanner_enable", "nightmare.scanner", oldScannerActive, true, nil)
		} else {
			audit.Log("admin", "nightmare.scanner_disable", "nightmare.scanner", oldScannerActive, false, nil)
		}
	case "proxy":
		oldProxyActive := globalNightmare.ProxyActive
		if req.Enabled {
			applyProxyNightmare(s)
		} else {
			restoreProxyNightmare(s)
		}
		globalNightmare.ProxyActive = req.Enabled
		if req.Enabled {
			audit.Log("admin", "nightmare.proxy_enable", "nightmare.proxy", oldProxyActive, true, nil)
		} else {
			audit.Log("admin", "nightmare.proxy_disable", "nightmare.proxy", oldProxyActive, false, nil)
		}
	default:
		http.Error(w, `{"error":"invalid mode, use: all, server, scanner, proxy"}`, http.StatusBadRequest)
		return
	}

	TriggerAutoSave()
	state := map[string]bool{
		"server":  globalNightmare.ServerActive,
		"scanner": globalNightmare.ScannerActive,
		"proxy":   globalNightmare.ProxyActive,
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":    true,
		"state": state,
	})
}

// applyServerNightmare snapshots current config and applies extreme values.
// Must be called with globalNightmare.mu held.
func applyServerNightmare() {
	// Snapshot current state
	globalNightmare.PreviousConfig = globalConfig.Get()
	globalNightmare.PreviousFeatures = globalFlags.Snapshot()

	// Enable all features
	globalFlags.SetAll(true)

	// Apply extreme config values
	globalConfig.Set("error_rate_multiplier", 5.0)
	globalConfig.Set("header_corrupt_level", 4)
	globalConfig.Set("block_chance", 0.15)
	globalConfig.Set("delay_min_ms", 500)
	globalConfig.Set("delay_max_ms", 10000)
	globalConfig.Set("max_labyrinth_depth", 100)
	globalConfig.Set("labyrinth_link_density", 20)
	globalConfig.Set("captcha_trigger_thresh", 10)
	globalConfig.Set("cookie_trap_frequency", 15)
	globalConfig.Set("js_trap_difficulty", 5)
	globalConfig.Set("bot_score_threshold", 20)
	globalConfig.Set("adaptive_aggressive_rps", 2)
}

// restoreServerNightmare restores the config snapshot.
// Must be called with globalNightmare.mu held.
func restoreServerNightmare() {
	if globalNightmare.PreviousFeatures != nil {
		for name, enabled := range globalNightmare.PreviousFeatures {
			globalFlags.Set(name, enabled)
		}
	}
	if globalNightmare.PreviousConfig != nil {
		for key, val := range globalNightmare.PreviousConfig {
			switch v := val.(type) {
			case float64:
				globalConfig.Set(key, v)
			case int:
				globalConfig.Set(key, float64(v))
			case string:
				globalConfig.SetString(key, v)
			}
		}
	}
}

// applyProxyNightmare snapshots current proxy mode and sets nightmare mode.
// Must be called with globalNightmare.mu held.
func applyProxyNightmare(s *Server) {
	globalNightmare.PreviousProxyMode = globalProxyConfig.GetMode()
	globalProxyConfig.SetMode("nightmare")
}

// restoreProxyNightmare restores proxy to its previous mode.
// Must be called with globalNightmare.mu held.
func restoreProxyNightmare(s *Server) {
	prev := globalNightmare.PreviousProxyMode
	if prev == "" || prev == "nightmare" {
		prev = "transparent"
	}
	globalProxyConfig.SetMode(prev)
}

// ---------------------------------------------------------------------------
// API handler: POST /admin/api/password
// ---------------------------------------------------------------------------

func adminAPIPasswordChange(w http.ResponseWriter, r *http.Request) {
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
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.New == "" {
		http.Error(w, `{"error":"new password cannot be empty"}`, http.StatusBadRequest)
		return
	}
	if len(req.New) < 4 {
		http.Error(w, `{"error":"password must be at least 4 characters"}`, http.StatusBadRequest)
		return
	}

	if err := ChangePassword(req.Current, req.New); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Password changed successfully",
	})
}

// ---------------------------------------------------------------------------
// API Chaos handlers
// ---------------------------------------------------------------------------

func adminAPIChaosGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	ff := GetFeatureFlags()
	cfg := GetAdminConfig()
	ac := GetAPIChaosConfig()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":     ff.IsAPIChaosEnabled(),
		"probability": cfg.Get()["api_chaos_probability"],
		"categories":  ac.Snapshot(),
	})
}

func adminAPIChaosToggle(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	ff := GetFeatureFlags()
	old := ff.IsAPIChaosEnabled()
	ff.Set("api_chaos", body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "feature.toggle", "feature_flags.api_chaos", old, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "enabled": body.Enabled})
}

func adminAPIChaosProbability(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Value float64 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	cfg := GetAdminConfig()
	old := cfg.Get()["api_chaos_probability"]
	cfg.Set("api_chaos_probability", body.Value)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "admin_config.api_chaos_probability", old, body.Value, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "value": body.Value})
}

func adminAPIChaosCategory(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	ac := GetAPIChaosConfig()
	old := ac.IsEnabled(body.Name)
	ac.SetCategory(body.Name, body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "api_chaos.categories."+body.Name, old, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func adminAPIChaosAll(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	ac := GetAPIChaosConfig()
	ac.SetAll(body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "api_chaos.categories.all", nil, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// ---------------------------------------------------------------------------
// Media Chaos API handlers
// ---------------------------------------------------------------------------

func adminMediaChaosGet(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	ff := GetFeatureFlags()
	cfg := GetAdminConfig()
	mc := GetMediaChaosConfig()
	cfgMap := cfg.Get()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":              ff.IsMediaChaosEnabled(),
		"probability":          cfgMap["media_chaos_probability"],
		"corruption_intensity": cfgMap["media_chaos_corruption_intensity"],
		"slow_min_ms":          cfgMap["media_chaos_slow_min_ms"],
		"slow_max_ms":          cfgMap["media_chaos_slow_max_ms"],
		"infinite_max_bytes":   cfgMap["media_chaos_infinite_max_bytes"],
		"categories":           mc.Snapshot(),
	})
}

func adminMediaChaosToggle(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	ff := GetFeatureFlags()
	old := ff.IsMediaChaosEnabled()
	ff.Set("media_chaos", body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "feature.toggle", "feature_flags.media_chaos", old, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "enabled": body.Enabled})
}

func adminMediaChaosProbability(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Value float64 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	cfg := GetAdminConfig()
	old := cfg.Get()["media_chaos_probability"]
	cfg.Set("media_chaos_probability", body.Value)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "admin_config.media_chaos_probability", old, body.Value, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "value": body.Value})
}

func adminMediaChaosCategory(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	mc := GetMediaChaosConfig()
	old := mc.IsEnabled(body.Name)
	mc.SetCategory(body.Name, body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "media_chaos.categories."+body.Name, old, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func adminMediaChaosAll(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	mc := GetMediaChaosConfig()
	mc.SetAll(body.Enabled)
	TriggerAutoSave()
	audit.Log("admin", "config.change", "media_chaos.categories.all", nil, body.Enabled, nil)

	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}
