package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/audit"
	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
	"github.com/glitchWebServer/internal/storage"
)

// ---------------------------------------------------------------------------
// Built-in scanner state — singleton for admin panel scanner runs
// ---------------------------------------------------------------------------

var (
	builtinMu      sync.RWMutex
	builtinEngine  *scanner.Engine
	builtinReport  *scanner.Report
	builtinCancel  context.CancelFunc
	builtinState   = "idle" // idle, running, completed, error
	builtinError   string
	builtinStart   time.Time
	builtinProfile string
	builtinTarget  string
	builtinModules []string // last-used module selections

	// History of built-in scanner runs (ring buffer, max 50)
	builtinHistory   []builtinHistoryEntry
	builtinHistoryMu sync.RWMutex

	// Full reports keyed by history ID for click-through
	builtinReports   = make(map[string]*scanner.Report)
	builtinReportsMu sync.RWMutex
)

type builtinHistoryEntry struct {
	ID        string  `json:"id"`
	Timestamp string  `json:"timestamp"`
	Profile   string  `json:"profile"`
	Findings  int     `json:"findings"`
	Coverage  float64 `json:"coverage_pct"`
	Resil     float64 `json:"resilience_pct"`
	Duration  int64   `json:"duration_ms"`
	Requests  int     `json:"total_requests"`
}

// LoadBuiltinScanHistory restores built-in scanner history from PostgreSQL on startup.
func LoadBuiltinScanHistory() {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scans, err := store.ListScans(ctx, 50)
	if err != nil {
		log.Printf("\033[33m[glitch]\033[0m Failed to load scan history from DB: %v", err)
		return
	}
	if len(scans) == 0 {
		return
	}

	builtinHistoryMu.Lock()
	builtinReportsMu.Lock()
	defer builtinHistoryMu.Unlock()
	defer builtinReportsMu.Unlock()

	// scans are newest-first from DB, we want oldest-first in our ring buffer
	for i := len(scans) - 1; i >= 0; i-- {
		rec := scans[i]
		// Decode the stored report to extract metadata
		var report scanner.Report
		if err := json.Unmarshal(rec.Report, &report); err != nil {
			continue
		}

		entry := builtinHistoryEntry{
			ID:        generateHistoryID(),
			Timestamp: rec.CreatedAt.UTC().Format(time.RFC3339),
			Profile:   rec.ScannerName,
			Findings:  len(report.Findings),
			Duration:  report.DurationMs,
			Requests:  report.TotalRequests,
		}
		if report.Summary != nil {
			entry.Coverage = report.Summary.OverallCoverage
			entry.Resil = report.Summary.OverallResilience
		}
		if rec.Grade != "" {
			entry.Profile = rec.ScannerName
		}

		builtinHistory = append(builtinHistory, entry)
		// Store full report for click-through
		reportCopy := report
		builtinReports[entry.ID] = &reportCopy
	}

	log.Printf("\033[36m[glitch]\033[0m Restored %d scan history entries from PostgreSQL", len(scans))
}

// ClearBuiltinScanHistory removes all built-in scanner history and reports.
func ClearBuiltinScanHistory() {
	builtinHistoryMu.Lock()
	builtinHistory = nil
	builtinHistoryMu.Unlock()

	builtinReportsMu.Lock()
	builtinReports = make(map[string]*scanner.Report)
	builtinReportsMu.Unlock()
}

// RegisterBuiltinScannerRoutes registers the built-in scanner API endpoints.
func RegisterBuiltinScannerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/api/scanner/builtin/run", adminAPIBuiltinRun)
	mux.HandleFunc("/admin/api/scanner/builtin/status", adminAPIBuiltinStatus)
	mux.HandleFunc("/admin/api/scanner/builtin/stop", adminAPIBuiltinStop)
	mux.HandleFunc("/admin/api/scanner/builtin/results", adminAPIBuiltinResults)
	mux.HandleFunc("/admin/api/scanner/builtin/history", adminAPIBuiltinHistory)
	mux.HandleFunc("/admin/api/scanner/builtin/history/detail", adminAPIBuiltinHistoryDetail)
	mux.HandleFunc("/admin/api/scanner/builtin/modules", adminAPIBuiltinModules)
	mux.HandleFunc("/admin/api/scanner/builtin/config", adminAPIBuiltinConfig)
}

func adminAPIBuiltinModules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	modules := attacks.ListModules()
	json.NewEncoder(w).Encode(modules)
}

func adminAPIBuiltinConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		builtinMu.RLock()
		resp := map[string]interface{}{
			"default_profile": builtinProfile,
			"default_target":  builtinTarget,
			"default_modules": builtinModules,
		}
		builtinMu.RUnlock()
		json.NewEncoder(w).Encode(resp)

	case "POST":
		var req struct {
			Profile string   `json:"default_profile"`
			Target  string   `json:"default_target"`
			Modules []string `json:"default_modules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		builtinMu.Lock()
		if req.Profile != "" {
			builtinProfile = req.Profile
		}
		if req.Target != "" {
			builtinTarget = req.Target
		}
		if req.Modules != nil {
			builtinModules = req.Modules
		}
		builtinMu.Unlock()
		TriggerAutoSave()
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})

	default:
		http.Error(w, `{"error":"GET or POST required"}`, http.StatusMethodNotAllowed)
	}
}

func adminAPIBuiltinRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	builtinMu.Lock()
	if builtinState == "running" {
		builtinMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "scan already running"})
		return
	}

	var req struct {
		Profile string   `json:"profile"`
		Modules []string `json:"modules"`
		Target  string   `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		builtinMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "invalid JSON"})
		return
	}

	// Select config based on profile
	var cfg *scanner.Config
	switch req.Profile {
	case "compliance":
		cfg = scanner.ComplianceConfig()
	case "aggressive":
		cfg = scanner.AggressiveConfig()
	case "stealth":
		cfg = scanner.StealthConfig()
	case "nightmare":
		cfg = scanner.NightmareConfig()
	default:
		cfg = scanner.DefaultConfig()
		cfg.Profile = req.Profile
	}

	if req.Target != "" {
		cfg.Target = req.Target
	} else {
		cfg.Target = "http://localhost:8765"
	}

	if len(req.Modules) > 0 {
		cfg.EnabledModules = req.Modules
	}

	eng := scanner.NewEngine(cfg)

	// Register selected modules
	var mods []scanner.AttackModule
	if len(req.Modules) > 0 {
		mods = attacks.FilterModules(req.Modules)
	} else {
		mods = attacks.AllModules()
	}
	for _, m := range mods {
		eng.RegisterModule(m)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	builtinEngine = eng
	builtinCancel = cancel
	builtinState = "running"
	builtinReport = nil
	builtinError = ""
	builtinStart = time.Now()
	builtinProfile = cfg.Profile
	builtinTarget = cfg.Target
	builtinModules = req.Modules
	builtinMu.Unlock()

	// Auto-save scanner settings (profile, target, modules)
	TriggerAutoSave()

	// Run in background goroutine
	go func() {
		report, err := eng.Run(ctx)
		builtinMu.Lock()
		defer builtinMu.Unlock()

		if err != nil {
			builtinState = "error"
			builtinError = err.Error()
		} else {
			builtinState = "completed"
			builtinReport = report

			// Add to history
			entry := builtinHistoryEntry{
				ID:        generateHistoryID(),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Profile:   cfg.Profile,
				Duration:  time.Since(builtinStart).Milliseconds(),
			}
			if report != nil {
				entry.Findings = len(report.Findings)
				entry.Requests = report.TotalRequests
				if report.Summary != nil {
					entry.Coverage = report.Summary.OverallCoverage
					entry.Resil = report.Summary.OverallResilience
				}
			}
			builtinHistoryMu.Lock()
			builtinHistory = append(builtinHistory, entry)
			if len(builtinHistory) > 50 {
				builtinHistory = builtinHistory[len(builtinHistory)-50:]
			}
			builtinHistoryMu.Unlock()

			// Store full report for history click-through
			builtinReportsMu.Lock()
			builtinReports[entry.ID] = report
			// Trim old reports to match history size
			if len(builtinReports) > 50 {
				// Build set of valid IDs
				builtinHistoryMu.RLock()
				validIDs := make(map[string]bool, len(builtinHistory))
				for _, h := range builtinHistory {
					validIDs[h.ID] = true
				}
				builtinHistoryMu.RUnlock()
				for id := range builtinReports {
					if !validIDs[id] {
						delete(builtinReports, id)
					}
				}
			}
			builtinReportsMu.Unlock()

			// Persist to PostgreSQL if available
			if store := GetStore(); store != nil {
				go persistScanToDB(store, cfg.Profile, report)
			}

			// Auto-save state file with latest scanner results
			TriggerAutoSave()
		}

		builtinCancel = nil
		cancel() // release context resources
	}()

	audit.LogAction("admin", "scanner.builtin_run", "scanner.builtin", map[string]interface{}{
		"profile": cfg.Profile,
		"target":  cfg.Target,
		"modules": req.Modules,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "profile": cfg.Profile, "target": cfg.Target})
}

func adminAPIBuiltinStatus(w http.ResponseWriter, r *http.Request) {
	builtinMu.RLock()
	defer builtinMu.RUnlock()

	resp := map[string]interface{}{
		"state": builtinState,
	}

	// Always include profile/target if available
	if builtinProfile != "" {
		resp["profile"] = builtinProfile
		resp["target"] = builtinTarget
	}

	// Include last completed scan info from history
	builtinHistoryMu.RLock()
	if len(builtinHistory) > 0 {
		last := builtinHistory[len(builtinHistory)-1]
		resp["last_profile"] = last.Profile
		resp["last_timestamp"] = last.Timestamp
		resp["last_findings"] = last.Findings
	}
	builtinHistoryMu.RUnlock()

	if builtinState == "running" && builtinEngine != nil {
		completed, total, findings := builtinEngine.Progress()
		phase := builtinEngine.Phase()
		resp["completed"] = completed
		resp["total"] = total
		resp["findings"] = findings
		resp["elapsed_ms"] = time.Since(builtinStart).Milliseconds()
		resp["phase"] = phase
		if total > 0 {
			resp["progress_pct"] = float64(completed) / float64(total) * 100
		}
		detail := builtinEngine.ProgressDetail()
		resp["crawled_urls"] = detail.CrawledURLs
		resp["generated_attacks"] = detail.GeneratedAttacks
		resp["current_url"] = detail.CurrentURL
	}

	if builtinState == "error" {
		resp["error"] = builtinError
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func adminAPIBuiltinStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}

	builtinMu.Lock()
	if builtinCancel != nil {
		builtinCancel()
	}
	if builtinEngine != nil {
		builtinEngine.Stop()
	}
	builtinMu.Unlock()

	audit.LogAction("admin", "scanner.builtin_stop", "scanner.builtin", nil)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func adminAPIBuiltinResults(w http.ResponseWriter, r *http.Request) {
	builtinMu.RLock()
	defer builtinMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if builtinReport == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "no results available"})
		return
	}

	json.NewEncoder(w).Encode(builtinReport)
}

func adminAPIBuiltinHistoryDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "id parameter required"})
		return
	}

	builtinReportsMu.RLock()
	report, ok := builtinReports[id]
	builtinReportsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if !ok || report == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "report not found"})
		return
	}
	json.NewEncoder(w).Encode(report)
}

func adminAPIBuiltinHistory(w http.ResponseWriter, r *http.Request) {
	builtinHistoryMu.RLock()
	defer builtinHistoryMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if builtinHistory == nil {
		// Backward compat: no pagination params → raw array
		if !hasPaginationParams(r) {
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items":  []interface{}{},
			"total":  0,
			"limit":  100,
			"offset": 0,
		})
		return
	}

	// Backward compatibility: no pagination params → return raw array
	if !hasPaginationParams(r) {
		json.NewEncoder(w).Encode(builtinHistory)
		return
	}

	limit, offset := parsePagination(r)
	total := len(builtinHistory)
	start, end := paginateSlice(total, limit, offset)
	page := builtinHistory[start:end]

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":  page,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func persistScanToDB(store *storage.Store, profile string, report *scanner.Report) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := store.SaveScanFromReport(ctx, "builtin:"+profile, "completed", "", 0, report)
	if err != nil {
		log.Printf("\033[33m[glitch]\033[0m Failed to persist scan to DB: %v", err)
	}
}

// generateHistoryID returns a short unique hex ID for history entries.
func generateHistoryID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Scanner config persistence — export/import default profile, target, modules
// ---------------------------------------------------------------------------

// ExportScannerConfig returns the current scanner defaults for config export.
func ExportScannerConfig() map[string]interface{} {
	builtinMu.RLock()
	defer builtinMu.RUnlock()

	cfg := map[string]interface{}{}
	if builtinProfile != "" {
		cfg["default_profile"] = builtinProfile
	}
	if builtinTarget != "" {
		cfg["default_target"] = builtinTarget
	}
	if len(builtinModules) > 0 {
		cfg["default_modules"] = builtinModules
	}
	// Persist last terminal state so the UI shows the right status on restart.
	if builtinState == "completed" || builtinState == "error" {
		cfg["last_state"] = builtinState
		if builtinState == "error" && builtinError != "" {
			cfg["last_error"] = builtinError
		}
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}

// ImportScannerConfig restores scanner defaults from a config export.
func ImportScannerConfig(cfg map[string]interface{}) {
	builtinMu.Lock()
	defer builtinMu.Unlock()

	if profile, ok := cfg["default_profile"].(string); ok {
		builtinProfile = profile
	}
	if target, ok := cfg["default_target"].(string); ok {
		builtinTarget = target
	}
	// Modules may be []interface{} (from JSON) or []string (direct).
	switch v := cfg["default_modules"].(type) {
	case []interface{}:
		mods := make([]string, 0, len(v))
		for _, m := range v {
			if s, ok := m.(string); ok {
				mods = append(mods, s)
			}
		}
		builtinModules = mods
	case []string:
		builtinModules = v
	}
	// Restore last terminal state (completed/error) so the UI can display it.
	if state, ok := cfg["last_state"].(string); ok {
		if state == "completed" || state == "error" {
			builtinState = state
		}
	}
	if errMsg, ok := cfg["last_error"].(string); ok {
		builtinError = errMsg
	}
}

// ---------------------------------------------------------------------------
// External scanner comparison history persistence
// ---------------------------------------------------------------------------

// PersistComparisonToDB saves an external scanner comparison report to the DB.
func PersistComparisonToDB(report interface{}, scannerName, grade string, detectionRate float64) {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := store.SaveScanFromReport(ctx, "external:"+scannerName, "completed", grade, detectionRate, report)
	if err != nil {
		log.Printf("\033[33m[glitch]\033[0m Failed to persist external scan to DB: %v", err)
	}
}
