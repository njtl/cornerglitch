package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/scanner"
	"github.com/glitchWebServer/internal/scanner/attacks"
)

// ---------------------------------------------------------------------------
// Built-in scanner state — singleton for admin panel scanner runs
// ---------------------------------------------------------------------------

var (
	builtinMu     sync.RWMutex
	builtinEngine *scanner.Engine
	builtinReport *scanner.Report
	builtinCancel context.CancelFunc
	builtinState  = "idle" // idle, running, completed, error
	builtinError  string
	builtinStart  time.Time

	// History of built-in scanner runs (ring buffer, max 50)
	builtinHistory   []builtinHistoryEntry
	builtinHistoryMu sync.RWMutex
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

// RegisterBuiltinScannerRoutes registers the built-in scanner API endpoints.
func RegisterBuiltinScannerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/api/scanner/builtin/run", adminAPIBuiltinRun)
	mux.HandleFunc("/admin/api/scanner/builtin/status", adminAPIBuiltinStatus)
	mux.HandleFunc("/admin/api/scanner/builtin/stop", adminAPIBuiltinStop)
	mux.HandleFunc("/admin/api/scanner/builtin/results", adminAPIBuiltinResults)
	mux.HandleFunc("/admin/api/scanner/builtin/history", adminAPIBuiltinHistory)
	mux.HandleFunc("/admin/api/scanner/builtin/modules", adminAPIBuiltinModules)
}

func adminAPIBuiltinModules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	modules := attacks.ListModules()
	json.NewEncoder(w).Encode(modules)
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
	builtinMu.Unlock()

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
				ID:        time.Now().Format("20060102-150405"),
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
		}

		builtinCancel = nil
		cancel() // release context resources
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "profile": cfg.Profile, "target": cfg.Target})
}

func adminAPIBuiltinStatus(w http.ResponseWriter, r *http.Request) {
	builtinMu.RLock()
	defer builtinMu.RUnlock()

	resp := map[string]interface{}{
		"state": builtinState,
	}

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

func adminAPIBuiltinHistory(w http.ResponseWriter, r *http.Request) {
	builtinHistoryMu.RLock()
	defer builtinHistoryMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if builtinHistory == nil {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	json.NewEncoder(w).Encode(builtinHistory)
}
