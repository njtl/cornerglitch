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

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/scanner"
)

// ---------------------------------------------------------------------------
// Feature Flags — thread-safe toggles for server subsystems
// ---------------------------------------------------------------------------

// FeatureFlags holds boolean toggles for each server subsystem.
type FeatureFlags struct {
	mu sync.RWMutex

	labyrinth       bool
	errorInject     bool
	captcha         bool
	honeypot        bool
	vuln            bool
	analytics       bool
	cdn             bool
	oauth           bool
	headerCorrupt   bool
	cookieTraps     bool
	jsTraps         bool
	botDetection    bool
	randomBlocking  bool
	frameworkEmul   bool
	search          bool
	email           bool
	i18n            bool
	recorder        bool
	websocket       bool
	privacy         bool
	health          bool
}

// NewFeatureFlags returns a FeatureFlags with every feature enabled.
func NewFeatureFlags() *FeatureFlags {
	return &FeatureFlags{
		labyrinth:      true,
		errorInject:    true,
		captcha:        true,
		honeypot:       true,
		vuln:           true,
		analytics:      true,
		cdn:            true,
		oauth:          true,
		headerCorrupt:  true,
		cookieTraps:    true,
		jsTraps:        true,
		botDetection:   true,
		randomBlocking: true,
		frameworkEmul:  true,
		search:         true,
		email:          true,
		i18n:           true,
		recorder:       true,
		websocket:      true,
		privacy:        true,
		health:         true,
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

func (f *FeatureFlags) IsHeaderCorruptEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.headerCorrupt
}

func (f *FeatureFlags) IsCookieTrapsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.cookieTraps
}

func (f *FeatureFlags) IsJSTrapsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.jsTraps
}

func (f *FeatureFlags) IsBotDetectionEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.botDetection
}

func (f *FeatureFlags) IsRandomBlockingEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.randomBlocking
}

func (f *FeatureFlags) IsFrameworkEmulEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.frameworkEmul
}

func (f *FeatureFlags) IsSearchEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.search
}

func (f *FeatureFlags) IsEmailEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.email
}

func (f *FeatureFlags) IsI18nEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.i18n
}

func (f *FeatureFlags) IsRecorderEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.recorder
}

func (f *FeatureFlags) IsWebSocketEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.websocket
}

func (f *FeatureFlags) IsPrivacyEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.privacy
}

func (f *FeatureFlags) IsHealthEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.health
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
	case "header_corrupt":
		f.headerCorrupt = enabled
	case "cookie_traps":
		f.cookieTraps = enabled
	case "js_traps":
		f.jsTraps = enabled
	case "bot_detection":
		f.botDetection = enabled
	case "random_blocking":
		f.randomBlocking = enabled
	case "framework_emul":
		f.frameworkEmul = enabled
	case "search":
		f.search = enabled
	case "email":
		f.email = enabled
	case "i18n":
		f.i18n = enabled
	case "recorder":
		f.recorder = enabled
	case "websocket":
		f.websocket = enabled
	case "privacy":
		f.privacy = enabled
	case "health":
		f.health = enabled
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
		"labyrinth":       f.labyrinth,
		"error_inject":    f.errorInject,
		"captcha":         f.captcha,
		"honeypot":        f.honeypot,
		"vuln":            f.vuln,
		"analytics":       f.analytics,
		"cdn":             f.cdn,
		"oauth":           f.oauth,
		"header_corrupt":  f.headerCorrupt,
		"cookie_traps":    f.cookieTraps,
		"js_traps":        f.jsTraps,
		"bot_detection":   f.botDetection,
		"random_blocking": f.randomBlocking,
		"framework_emul":  f.frameworkEmul,
		"search":          f.search,
		"email":           f.email,
		"i18n":            f.i18n,
		"recorder":        f.recorder,
		"websocket":       f.websocket,
		"privacy":         f.privacy,
		"health":          f.health,
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
	BlockChance           float64 // 0.0-1.0, random block probability
	BlockDurationSec      int     // how long blocks last
	BotScoreThreshold     float64 // 0-100, score above which to flag as bot
	HeaderCorruptLevel    int     // 0-4 (none/subtle/moderate/aggressive/chaos)
	DelayMinMs            int     // minimum added delay (ms)
	DelayMaxMs            int     // maximum added delay (ms)
	LabyrinthLinkDensity  int     // 1-20, links per labyrinth page
	AdaptiveIntervalSec   int     // seconds between adaptive re-evaluation
}

// NewAdminConfig returns an AdminConfig with sensible defaults.
func NewAdminConfig() *AdminConfig {
	return &AdminConfig{
		MaxLabyrinthDepth:    50,
		ErrorRateMultiplier:  1.0,
		CaptchaTriggerThresh: 100,
		BlockChance:          0.02,
		BlockDurationSec:     30,
		BotScoreThreshold:    60,
		HeaderCorruptLevel:   1,
		DelayMinMs:           0,
		DelayMaxMs:           0,
		LabyrinthLinkDensity: 8,
		AdaptiveIntervalSec:  30,
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
		"block_chance":           c.BlockChance,
		"block_duration_sec":     c.BlockDurationSec,
		"bot_score_threshold":    c.BotScoreThreshold,
		"header_corrupt_level":   c.HeaderCorruptLevel,
		"delay_min_ms":           c.DelayMinMs,
		"delay_max_ms":           c.DelayMaxMs,
		"labyrinth_link_density": c.LabyrinthLinkDensity,
		"adaptive_interval_sec":  c.AdaptiveIntervalSec,
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
	case "block_chance":
		if value < 0 {
			value = 0
		}
		if value > 1.0 {
			value = 1.0
		}
		c.BlockChance = value
	case "block_duration_sec":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 3600 {
			v = 3600
		}
		c.BlockDurationSec = v
	case "bot_score_threshold":
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		c.BotScoreThreshold = value
	case "header_corrupt_level":
		v := int(value)
		if v < 0 {
			v = 0
		}
		if v > 4 {
			v = 4
		}
		c.HeaderCorruptLevel = v
	case "delay_min_ms":
		v := int(value)
		if v < 0 {
			v = 0
		}
		c.DelayMinMs = v
	case "delay_max_ms":
		v := int(value)
		if v < 0 {
			v = 0
		}
		c.DelayMaxMs = v
	case "labyrinth_link_density":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 20 {
			v = 20
		}
		c.LabyrinthLinkDensity = v
	case "adaptive_interval_sec":
		v := int(value)
		if v < 5 {
			v = 5
		}
		if v > 300 {
			v = 300
		}
		c.AdaptiveIntervalSec = v
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

	// Scanner runner — uses the real scanner package
	scanRunner   *scanner.Runner
	scanRunnerMu sync.Mutex
)

// GetFeatureFlags returns the global FeatureFlags instance.
func GetFeatureFlags() *FeatureFlags { return globalFlags }

// GetAdminConfig returns the global AdminConfig instance.
func GetAdminConfig() *AdminConfig { return globalConfig }

// getScanRunner returns the singleton scanner.Runner, creating it on first call.
func getScanRunner() *scanner.Runner {
	scanRunnerMu.Lock()
	defer scanRunnerMu.Unlock()
	if scanRunner == nil {
		scanRunner = scanner.NewRunner(scanner.DefaultRunnerConfig(
			"http://localhost:8765",
			"http://localhost:8766",
		))
	}
	return scanRunner
}

// buildScannerProfile computes an expected profile from current feature flags and config.
func buildScannerProfile() *scanner.ExpectedProfile {
	features := globalFlags.Snapshot()
	config := globalConfig.Get()
	return scanner.ComputeProfile(features, config, 8765, 8766)
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

	// Scanner profile — returns vulnerability profile for the current config
	mux.HandleFunc("/admin/api/scanner/profile", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerProfile(w, r, s)
	})

	// Scanner run — kicks off a scanner asynchronously
	mux.HandleFunc("/admin/api/scanner/run", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerRun(w, r, s)
	})

	// Scanner compare — accepts raw scanner output, compares against profile
	mux.HandleFunc("/admin/api/scanner/compare", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerCompare(w, r, s)
	})

	// Scanner results — returns stored scan results
	mux.HandleFunc("/admin/api/scanner/results", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerResults(w, r, s)
	})

	// Scanner stop — stops a running scanner
	mux.HandleFunc("/admin/api/scanner/stop", func(w http.ResponseWriter, r *http.Request) {
		adminAPIScannerStop(w, r, s)
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
// API handler: GET /admin/api/client/{id} — detailed client info
// ---------------------------------------------------------------------------

func adminAPIClientDetail(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	// Extract client ID from path: /admin/api/client/{id}
	clientID := strings.TrimPrefix(r.URL.Path, "/admin/api/client/")
	if clientID == "" {
		http.Error(w, `{"error":"client_id required"}`, http.StatusBadRequest)
		return
	}

	// Find matching client profile
	profiles := s.collector.GetAllClientProfiles()
	var matchedProfile interface{}
	var fullClientID string
	for _, p := range profiles {
		snap := p.Snapshot()
		if snap.ClientID == clientID || strings.HasPrefix(snap.ClientID, clientID) {
			fullClientID = snap.ClientID
			// Build detailed profile
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

			// All paths with counts
			pathsList := make([]map[string]interface{}, 0, len(snap.PathsVisited))
			for path, count := range snap.PathsVisited {
				pathsList = append(pathsList, map[string]interface{}{
					"path": path, "count": count,
				})
			}
			sort.Slice(pathsList, func(i, j int) bool {
				return pathsList[i]["count"].(int) > pathsList[j]["count"].(int)
			})

			// Recent requests for this client
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
// API handler: GET/POST /admin/api/blocking — random blocking controls
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
// API handler: GET/POST /admin/api/override — manual behavior overrides
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

	// Validate mode
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
// Scanner API handlers (stubs — will be backed by internal/scanner later)
// ---------------------------------------------------------------------------

func adminAPIScannerProfile(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	profile := buildScannerProfile()

	// Also include scanner availability info
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

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
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

	json.NewEncoder(w).Encode(report)
}

func adminAPIScannerResults(w http.ResponseWriter, r *http.Request, s *Server) {
	setCORS(w)
	w.Header().Set("Content-Type", "application/json")

	runner := getScanRunner()
	completed := runner.GetResults()
	running := runner.GetRunning()

	// Build running list
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

  /* Severity badges */
  .sev { padding: 2px 8px; border-radius: 10px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
  .sev-critical { background: #ff2244; color: #fff; }
  .sev-high { background: #ff8800; color: #000; }
  .sev-medium { background: #ffcc00; color: #000; }
  .sev-low { background: #4488ff; color: #fff; }
  .sev-info { background: #444; color: #aaa; }

  /* Grade display */
  .grade { font-size: 4em; font-weight: bold; text-align: center; padding: 20px; }
  .grade-a { color: #00ff88; }
  .grade-b { color: #88ff00; }
  .grade-c { color: #ffcc00; }
  .grade-d { color: #ff8800; }
  .grade-f { color: #ff2244; }

  /* Progress bars */
  .prog-bar { height: 20px; background: #1a1a1a; border-radius: 4px; overflow: hidden; margin: 4px 0; }
  .prog-fill { height: 100%%; border-radius: 4px; transition: width 0.5s; }
  .prog-green { background: linear-gradient(90deg, #00aa66, #00ff88); }
  .prog-red { background: linear-gradient(90deg, #aa2200, #ff4444); }
  .prog-yellow { background: linear-gradient(90deg, #aa8800, #ffcc00); }

  /* Scanner controls */
  .scanner-btn { background: #00aa66; color: #000; border: none; padding: 8px 20px; border-radius: 6px; cursor: pointer; font-family: inherit; font-weight: bold; font-size: 0.85em; margin: 4px; }
  .scanner-btn:hover { background: #00cc77; }
  .scanner-btn:disabled { background: #333; color: #666; cursor: not-allowed; }
  .scanner-btn.running { background: #ffaa00; animation: pulse 1s infinite; }
  @keyframes pulse { 0%%,100%% { opacity:1; } 50%% { opacity:0.6; } }

  /* Vuln table */
  .vuln-status-active { color: #00ff88; }
  .vuln-status-disabled { color: #666; }
  .vuln-endpoint { font-size: 0.75em; color: #44aaff; margin: 1px 0; display: block; }
  .vuln-endpoint:hover { color: #88ccff; }

  /* Scanner panels */
  .scanner-panel { background: #0d0d0d; border: 1px solid #222; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .scanner-panel h3 { color: #00ccaa; font-size: 0.9em; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }
  .scanner-select, .scanner-textarea {
    background: #111; color: #00ff88; border: 1px solid #333; border-radius: 4px;
    padding: 8px 12px; font-family: inherit; font-size: 0.85em; width: 100%%;
  }
  .scanner-select { width: auto; min-width: 160px; }
  .scanner-textarea { min-height: 120px; resize: vertical; margin: 8px 0; }

  /* Findings table */
  .findings-tbl { margin-top: 8px; }
  .findings-tbl td { font-size: 0.78em; }
  .findings-tbl .found { color: #00ff88; }
  .findings-tbl .missed { color: #ff4444; }
  .findings-tbl .false-pos { color: #ffaa00; }
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
  <button class="tab" onclick="showTab('vulns')">Vulnerabilities</button>
  <button class="tab" onclick="showTab('scanner')">Scanner</button>
</div>

<!-- ==================== SESSIONS TAB ==================== -->
<div id="panel-sessions" class="panel active">
  <div class="section">
    <h2>// Active Client Sessions</h2>
    <p style="color:#666;font-size:0.8em;margin-bottom:10px">Click a client ID to view details and set behavior overrides.</p>
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
          <th>Actions</th>
        </tr></thead>
        <tbody id="sess-body"></tbody>
      </table>
    </div>
  </div>
  <div class="section" id="client-detail" style="display:none">
    <h2>// Client Detail: <span id="detail-cid" style="color:#00ffcc"></span></h2>
    <div class="grid" id="detail-cards"></div>
    <div style="margin:12px 0">
      <label style="color:#aaa;font-size:0.85em">Override Mode:</label>
      <select id="override-mode" style="background:#0d0d0d;color:#00ff88;border:1px solid #333;padding:6px 10px;border-radius:4px;font-family:inherit;margin:0 8px">
        <option value="">-- auto --</option>
        <option value="normal">Normal</option>
        <option value="cooperative">Cooperative</option>
        <option value="aggressive">Aggressive</option>
        <option value="labyrinth">Labyrinth</option>
        <option value="escalating">Escalating</option>
        <option value="intermittent">Intermittent</option>
        <option value="mirror">Mirror</option>
        <option value="blocked">Blocked</option>
      </select>
      <button onclick="applyOverride()" style="background:#00aa66;color:#000;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;font-weight:bold">Apply</button>
      <button onclick="clearOverride()" style="background:#333;color:#ccc;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-family:inherit;margin-left:4px">Clear</button>
    </div>
    <div id="detail-paths" style="max-height:200px;overflow-y:auto"></div>
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

<!-- ==================== VULNERABILITIES TAB ==================== -->
<div id="panel-vulns" class="panel">
  <div class="section">
    <h2>// Vulnerability Profile Overview</h2>
    <div class="grid" id="vuln-overview-cards">
      <div class="card"><div class="label">Loading...</div><div class="value v-info">--</div></div>
    </div>
  </div>

  <div class="section">
    <h2>// Severity Breakdown</h2>
    <div id="vuln-severity-badges" style="margin-bottom:12px"></div>
  </div>

  <div class="section">
    <h2>// All Vulnerability Endpoints</h2>
    <input type="text" class="search-box" id="vuln-filter" placeholder="Filter by name, severity, CWE, category..." oninput="filterVulns()">
    <div class="tbl-scroll" style="max-height: 600px;">
      <table>
        <thead><tr>
          <th>Name</th>
          <th>Severity</th>
          <th>CWE</th>
          <th>Category</th>
          <th>Endpoints</th>
          <th>Status</th>
        </tr></thead>
        <tbody id="vuln-body"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ==================== SCANNER TAB ==================== -->
<div id="panel-scanner" class="panel">

  <!-- Expected Profile panel -->
  <div class="section">
    <h2>// Expected Profile</h2>
    <button class="scanner-btn" onclick="generateProfile()">Generate Profile</button>
    <div id="scanner-profile-summary" style="margin-top:14px">
      <div style="color:#555">Click "Generate Profile" to load the current vulnerability profile.</div>
    </div>
  </div>

  <!-- Scanner Results panel -->
  <div class="section">
    <h2>// Scanner Results</h2>
    <div class="scanner-panel">
      <h3>Select Scanner</h3>
      <select id="scanner-type" class="scanner-select">
        <option value="nuclei">Nuclei</option>
        <option value="nikto">Nikto</option>
        <option value="nmap">Nmap</option>
        <option value="ffuf">ffuf</option>
        <option value="wapiti">Wapiti</option>
        <option value="generic">Generic</option>
      </select>
    </div>

    <div class="scanner-panel">
      <h3>Upload / Paste Results</h3>
      <textarea id="scanner-output" class="scanner-textarea" placeholder="Paste scanner output here..."></textarea>
      <button class="scanner-btn" onclick="uploadResults()">Upload &amp; Compare</button>
    </div>

    <div class="scanner-panel">
      <h3>Run Scanner</h3>
      <p style="color:#888;font-size:0.82em;margin-bottom:8px">Launch a scanner against this server (requires tool to be installed on host).</p>
      <div id="scanner-run-btns">
        <button class="scanner-btn" onclick="runScanner('nuclei')">nuclei</button>
        <button class="scanner-btn" onclick="runScanner('nikto')">nikto</button>
        <button class="scanner-btn" onclick="runScanner('nmap')">nmap</button>
        <button class="scanner-btn" onclick="runScanner('ffuf')">ffuf</button>
        <button class="scanner-btn" onclick="runScanner('wapiti')">wapiti</button>
      </div>
      <div id="scanner-run-status" style="margin-top:8px;color:#555;font-size:0.82em"></div>
    </div>
  </div>

  <!-- Comparison Report panel -->
  <div class="section">
    <h2>// Comparison Report</h2>
    <div id="scanner-comparison">
      <div style="color:#555">No comparison data yet. Upload scanner results or run a scan.</div>
    </div>
  </div>

  <!-- History panel -->
  <div class="section">
    <h2>// Scan History</h2>
    <div class="tbl-scroll" style="max-height:300px">
      <table>
        <thead><tr>
          <th>Timestamp</th>
          <th>Scanner</th>
          <th>Grade</th>
          <th>Detection</th>
          <th>Status</th>
        </tr></thead>
        <tbody id="scanner-history-body"></tbody>
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
  let selectedClient = null;
  async function refreshSessions() {
    try {
      const data = await api('/api/clients');
      const clients = (data.clients || []);
      // Sort by last_seen descending
      clients.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
      const tbody = document.getElementById('sess-body');
      tbody.innerHTML = clients.map(c => {
        const ago = timeSince(c.last_seen);
        const cid = escapeHtml(c.client_id);
        const short = escapeHtml(shortID(c.client_id));
        return '<tr>' +
          '<td><a href="#" onclick="viewClient(\'' + cid + '\');return false" style="color:#44aaff">' + short + '</a></td>' +
          '<td>' + c.total_requests + '</td>' +
          '<td>' + (c.requests_per_sec||0).toFixed(1) + '</td>' +
          '<td class="' + (c.errors_received > 0 ? 's5' : '') + '">' + c.errors_received + '</td>' +
          '<td>' + c.unique_paths + '</td>' +
          '<td>' + (c.labyrinth_depth||0) + '</td>' +
          '<td class="' + mClass(c.adaptive_mode) + '">' + (c.adaptive_mode||'pending') + '</td>' +
          '<td style="color:#888">' + ago + '</td>' +
          '<td><a href="#" onclick="viewClient(\'' + cid + '\');return false" style="color:#888;font-size:0.8em">details</a></td>' +
          '</tr>';
      }).join('');
    } catch(e) { console.error('sessions:', e); }
  }

  window.viewClient = async function(clientID) {
    selectedClient = clientID;
    try {
      const detail = await api('/admin/api/client/' + encodeURIComponent(clientID));
      document.getElementById('client-detail').style.display = 'block';
      document.getElementById('detail-cid').textContent = shortID(clientID);
      document.getElementById('detail-cards').innerHTML =
        card('Total Requests', detail.total_requests, 'v-ok') +
        card('Req/s', (detail.requests_per_sec||0).toFixed(1), 'v-info') +
        card('Errors', detail.errors_received, detail.errors_received > 0 ? 'v-err' : 'v-ok') +
        card('Unique Paths', detail.unique_paths, 'v-info') +
        card('Mode', detail.adaptive_mode || 'pending', 'v-warn') +
        card('Bot Score', (detail.bot_score||0).toFixed(1), detail.bot_score > 60 ? 'v-err' : 'v-ok') +
        card('Escalation', detail.escalation_level, 'v-warn') +
        card('Lab Depth', detail.labyrinth_depth, 'v-info');

      // Show top paths
      const paths = (detail.all_paths || []).slice(0, 20);
      if (paths.length > 0) {
        const maxC = paths[0].count || 1;
        document.getElementById('detail-paths').innerHTML = '<h2 style="margin-top:12px">// Top Paths</h2>' +
          paths.map(p =>
            '<div class="bar-row">' +
            '<div class="bar-label" title="' + escapeHtml(p.path) + '">' + escapeHtml(p.path.substring(0,40)) + '</div>' +
            '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/maxC*100) + '%%"></div></div>' +
            '<div class="bar-count">' + p.count + '</div></div>'
          ).join('');
      }

      // Show reason
      if (detail.adaptive_reason) {
        document.getElementById('detail-paths').innerHTML +=
          '<div style="margin-top:10px;color:#888;font-size:0.85em">Reason: ' + escapeHtml(detail.adaptive_reason) + '</div>';
      }
    } catch(e) { console.error('viewClient:', e); toast('Client not found'); }
  };

  window.applyOverride = async function() {
    if (!selectedClient) return;
    const mode = document.getElementById('override-mode').value;
    if (!mode) { toast('Select a mode first'); return; }
    await api('/admin/api/override', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({client_id: selectedClient, mode: mode})
    });
    toast('Override applied: ' + mode);
    viewClient(selectedClient);
  };

  window.clearOverride = async function() {
    if (!selectedClient) return;
    await api('/admin/api/override', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({client_id: selectedClient, clear: true})
    });
    toast('Override cleared');
    viewClient(selectedClient);
  };

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
    oauth: 'OAuth Endpoints',
    header_corrupt: 'Header Corruption',
    cookie_traps: 'Cookie Traps',
    js_traps: 'JS Traps',
    bot_detection: 'Bot Detection',
    random_blocking: 'Random Blocking',
    framework_emul: 'Framework Emulation',
    search: 'Search Engine',
    email: 'Email/Webmail',
    i18n: 'Internationalization',
    recorder: 'Traffic Recorder',
    websocket: 'WebSocket',
    privacy: 'Privacy/Consent',
    health: 'Health Endpoints'
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
        slider('captcha_trigger_thresh', 'CAPTCHA Trigger Threshold', cfg.captcha_trigger_thresh, 0, 500, 1) +
        slider('block_chance', 'Random Block Chance', cfg.block_chance, 0, 1, 0.01) +
        slider('block_duration_sec', 'Block Duration (sec)', cfg.block_duration_sec, 1, 3600, 1) +
        slider('bot_score_threshold', 'Bot Score Threshold', cfg.bot_score_threshold, 0, 100, 1) +
        slider('header_corrupt_level', 'Header Corruption Level (0-4)', cfg.header_corrupt_level, 0, 4, 1) +
        slider('delay_min_ms', 'Delay Min (ms)', cfg.delay_min_ms, 0, 10000, 100) +
        slider('delay_max_ms', 'Delay Max (ms)', cfg.delay_max_ms, 0, 30000, 100) +
        slider('labyrinth_link_density', 'Labyrinth Links/Page', cfg.labyrinth_link_density, 1, 20, 1) +
        slider('adaptive_interval_sec', 'Adaptive Re-eval Interval (sec)', cfg.adaptive_interval_sec, 5, 300, 5);
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

  // ------ Vulnerabilities Tab ------
  let vulnData = [];
  let vulnProfile = null;

  async function refreshVulns() {
    try {
      const profile = await api('/admin/api/scanner/profile');
      vulnProfile = profile;
      vulnData = profile.vulns || [];

      // Overview cards
      const cats = profile.category_counts || {};
      const sev = profile.severity_counts || {};
      document.getElementById('vuln-overview-cards').innerHTML =
        card('OWASP Top 10', cats.owasp || 0, 'v-err') +
        card('Advanced Vulns', cats.advanced || 0, 'v-warn') +
        card('Dashboard Vulns', cats.dashboard || 0, 'v-info') +
        card('Total Vulns', profile.total_vulns || 0, 'v-ok') +
        card('Total Endpoints', profile.total_endpoints || 0, 'v-info');

      // Severity badges
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      document.getElementById('vuln-severity-badges').innerHTML = sevOrder.map(function(s) {
        return '<span class="sev sev-' + s + '" style="margin-right:10px">' + s + ': ' + (sev[s] || 0) + '</span>';
      }).join('');

      // Render table
      renderVulnTable(vulnData);
    } catch(e) { console.error('vulns:', e); }
  }

  function renderVulnTable(vulns) {
    var mainPort = 8765;
    var tbody = document.getElementById('vuln-body');
    tbody.innerHTML = vulns.map(function(v) {
      var endpoints = (v.endpoints || []).map(function(ep) {
        return '<a class="vuln-endpoint" href="http://' + window.location.hostname + ':' + mainPort + ep + '" target="_blank" title="' + escapeHtml(ep) + '">' + escapeHtml(ep.length > 60 ? ep.substring(0, 57) + '...' : ep) + '</a>';
      }).join('');
      var statusClass = v.active ? 'vuln-status-active' : 'vuln-status-disabled';
      var statusText = v.active ? 'ACTIVE' : 'DISABLED';
      return '<tr>' +
        '<td>' + escapeHtml(v.name) + '</td>' +
        '<td><span class="sev sev-' + v.severity + '">' + v.severity + '</span></td>' +
        '<td style="color:#888">' + escapeHtml(v.cwe) + '</td>' +
        '<td>' + escapeHtml(v.category) + '</td>' +
        '<td>' + endpoints + '</td>' +
        '<td class="' + statusClass + '">' + statusText + '</td>' +
        '</tr>';
    }).join('');
  }

  window.filterVulns = function() {
    var q = document.getElementById('vuln-filter').value.toLowerCase().trim();
    if (!q) {
      renderVulnTable(vulnData);
      return;
    }
    var filtered = vulnData.filter(function(v) {
      var haystack = (v.name + ' ' + v.severity + ' ' + v.cwe + ' ' + v.category + ' ' + (v.endpoints || []).join(' ')).toLowerCase();
      return haystack.indexOf(q) !== -1;
    });
    renderVulnTable(filtered);
  };

  // ------ Scanner Tab ------
  let scannerRunning = false;
  let scanHistory = [];

  window.generateProfile = async function() {
    try {
      var profile = await api('/admin/api/scanner/profile');
      vulnProfile = profile;
      var sev = profile.severity_counts || {};
      var metrics = profile.expected_metrics || {};

      var sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      var sevHtml = sevOrder.map(function(s) {
        return '<span class="sev sev-' + s + '" style="margin-right:10px">' + s + ': ' + (sev[s] || 0) + '</span>';
      }).join('');

      var html = '<div class="grid">' +
        card('Total Vulns', profile.total_vulns || 0, 'v-ok') +
        card('Total Endpoints', profile.total_endpoints || 0, 'v-info') +
        card('OWASP', (profile.category_counts || {}).owasp || 0, 'v-err') +
        card('Advanced', (profile.category_counts || {}).advanced || 0, 'v-warn') +
        card('Dashboard', (profile.category_counts || {}).dashboard || 0, 'v-info') +
        '</div>' +
        '<div style="margin:12px 0">' + sevHtml + '</div>' +
        '<div style="margin-top:14px">' +
        '<h3 style="color:#00ccaa;font-size:0.85em;margin-bottom:8px">EXPECTED BEHAVIOR METRICS</h3>' +
        metricBar('Error Rate', metrics.error_rate || 0, 'prog-red') +
        metricBar('Labyrinth Rate', metrics.labyrinth_rate || 0, 'prog-yellow') +
        metricBar('Block Rate', metrics.block_rate || 0, 'prog-red') +
        metricBar('CAPTCHA Rate', metrics.captcha_rate || 0, 'prog-yellow') +
        '</div>';

      document.getElementById('scanner-profile-summary').innerHTML = html;
      toast('Profile generated');
    } catch(e) { console.error('generateProfile:', e); toast('Failed to generate profile'); }
  };

  function metricBar(label, value, cls) {
    var pct = Math.min(value * 100, 100).toFixed(1);
    return '<div style="margin:6px 0">' +
      '<div style="display:flex;justify-content:space-between;font-size:0.82em;color:#aaa"><span>' + label + '</span><span style="color:#00ffcc">' + pct + '%%</span></div>' +
      '<div class="prog-bar"><div class="prog-fill ' + cls + '" style="width:' + pct + '%%"></div></div>' +
      '</div>';
  }

  window.runScanner = async function(name) {
    if (scannerRunning) { toast('A scan is already running'); return; }
    scannerRunning = true;
    var btn = event.target;
    btn.classList.add('running');
    btn.disabled = true;
    document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ffaa00">Running ' + escapeHtml(name) + '...</span>';

    try {
      var result = await api('/admin/api/scanner/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scanner: name, target: 'http://' + window.location.hostname + ':8765'})
      });
      document.getElementById('scanner-run-status').innerHTML = '<span style="color:#00ff88">Status: ' + escapeHtml(result.status || 'unknown') + '</span>' +
        (result.message ? '<br><span style="color:#888;font-size:0.9em">' + escapeHtml(result.message) + '</span>' : '');

      scanHistory.push({timestamp: new Date().toISOString(), scanner: name, grade: '-', detection: '-', status: result.status || 'queued'});
      renderScanHistory();
      toast(name + ' scan ' + (result.status || 'queued'));
    } catch(e) {
      document.getElementById('scanner-run-status').innerHTML = '<span style="color:#ff4444">Error running scanner</span>';
      console.error('runScanner:', e);
    } finally {
      scannerRunning = false;
      btn.classList.remove('running');
      btn.disabled = false;
    }
  };

  window.uploadResults = async function() {
    var scanner = document.getElementById('scanner-type').value;
    var data = document.getElementById('scanner-output').value;
    if (!data.trim()) { toast('Paste scanner output first'); return; }

    try {
      var report = await api('/admin/api/scanner/compare', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({scanner: scanner, data: data})
      });
      renderComparison(report);
      scanHistory.push({
        timestamp: report.timestamp || new Date().toISOString(),
        scanner: scanner,
        grade: report.grade || '?',
        detection: ((report.detection_rate || 0) * 100).toFixed(0) + '%%',
        status: 'completed'
      });
      renderScanHistory();
      toast('Comparison complete: grade ' + (report.grade || '?'));
    } catch(e) {
      console.error('uploadResults:', e);
      toast('Comparison failed');
    }
  };

  function renderComparison(report) {
    var grade = (report.grade || '?').toUpperCase();
    var gradeClass = 'grade-' + grade.toLowerCase();
    var detPct = ((report.detection_rate || 0) * 100).toFixed(1);
    var fpPct = ((report.false_pos_rate || 0) * 100).toFixed(1);
    var accPct = ((report.accuracy || 0) * 100).toFixed(1);

    var html = '<div style="display:grid;grid-template-columns:200px 1fr;gap:20px">' +
      '<div>' +
        '<div class="grade ' + gradeClass + '">' + escapeHtml(grade) + '</div>' +
        '<div style="text-align:center;color:#888;font-size:0.85em">Scanner Grade</div>' +
      '</div>' +
      '<div>' +
        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">Detection Rate</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-green" style="width:' + detPct + '%%"></div></div>' +
        '<span style="color:#00ff88;font-size:0.85em">' + detPct + '%%</span></div>' +

        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">False Positive Rate</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-red" style="width:' + fpPct + '%%"></div></div>' +
        '<span style="color:#ff4444;font-size:0.85em">' + fpPct + '%%</span></div>' +

        '<div style="margin:8px 0"><span style="color:#aaa;font-size:0.85em">Accuracy</span>' +
        '<div class="prog-bar"><div class="prog-fill prog-yellow" style="width:' + accPct + '%%"></div></div>' +
        '<span style="color:#ffcc00;font-size:0.85em">' + accPct + '%%</span></div>' +
      '</div></div>';

    // Scanner health
    var health = report.scanner_health || {};
    html += '<div style="margin-top:14px;font-size:0.85em;color:#888">' +
      'Crashed: <span style="color:' + (health.crashed ? '#ff4444' : '#00ff88') + '">' + (health.crashed ? 'YES' : 'no') + '</span> | ' +
      'Timed out: <span style="color:' + (health.timed_out ? '#ff4444' : '#00ff88') + '">' + (health.timed_out ? 'YES' : 'no') + '</span> | ' +
      'Errors: <span style="color:' + (health.errors > 0 ? '#ff4444' : '#00ff88') + '">' + (health.errors || 0) + '</span>' +
      '</div>';

    // True positives table
    var tp = report.true_positives || [];
    if (tp.length > 0) {
      html += '<h3 style="color:#00ff88;font-size:0.85em;margin-top:16px">TRUE POSITIVES (' + tp.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      tp.forEach(function(item) {
        html += '<tr><td class="found">' + escapeHtml(item.name || '') + '</td><td>' + escapeHtml(item.endpoint || '') + '</td><td>' + escapeHtml(item.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    // False negatives table
    var fn = report.false_negatives || [];
    if (fn.length > 0) {
      html += '<h3 style="color:#ff4444;font-size:0.85em;margin-top:16px">FALSE NEGATIVES - MISSED (' + fn.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      fn.forEach(function(item) {
        html += '<tr><td class="missed">' + escapeHtml(item.name || '') + '</td><td>' + escapeHtml(item.endpoint || '') + '</td><td>' + escapeHtml(item.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    // False positives table
    var fp = report.false_positives || [];
    if (fp.length > 0) {
      html += '<h3 style="color:#ffaa00;font-size:0.85em;margin-top:16px">FALSE POSITIVES (' + fp.length + ')</h3>';
      html += '<table class="findings-tbl"><thead><tr><th>Reported Vulnerability</th><th>Endpoint</th><th>Severity</th></tr></thead><tbody>';
      fp.forEach(function(item) {
        html += '<tr><td class="false-pos">' + escapeHtml(item.name || '') + '</td><td>' + escapeHtml(item.endpoint || '') + '</td><td>' + escapeHtml(item.severity || '') + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    if (report.message) {
      html += '<div style="margin-top:12px;color:#555;font-size:0.82em">' + escapeHtml(report.message) + '</div>';
    }

    document.getElementById('scanner-comparison').innerHTML = html;
  }

  function renderScanHistory() {
    var tbody = document.getElementById('scanner-history-body');
    tbody.innerHTML = scanHistory.slice().reverse().map(function(h) {
      var gradeClass = h.grade && h.grade !== '-' && h.grade !== '?' ? 'grade-' + h.grade.toLowerCase() : '';
      return '<tr>' +
        '<td style="color:#888">' + (h.timestamp ? new Date(h.timestamp).toLocaleString() : '-') + '</td>' +
        '<td>' + escapeHtml(h.scanner || '') + '</td>' +
        '<td' + (gradeClass ? ' class="' + gradeClass + '"' : '') + ' style="font-weight:bold;font-size:1.2em">' + escapeHtml(h.grade || '-') + '</td>' +
        '<td>' + escapeHtml(String(h.detection || '-')) + '</td>' +
        '<td>' + escapeHtml(h.status || '-') + '</td>' +
        '</tr>';
    }).join('');
  }

  async function refreshScannerHistory() {
    try {
      var data = await api('/admin/api/scanner/results');
      var results = data.results || [];
      // Merge server results into scanHistory if not already present
      results.forEach(function(r) {
        var exists = scanHistory.some(function(h) { return h.timestamp === r.timestamp && h.scanner === r.scanner; });
        if (!exists) {
          scanHistory.push({
            timestamp: r.timestamp,
            scanner: r.scanner || '',
            grade: r.grade || '-',
            detection: r.detection_rate ? ((r.detection_rate * 100).toFixed(0) + '%%') : '-',
            status: r.status || '-'
          });
        }
      });
      renderScanHistory();
    } catch(e) { console.error('scannerHistory:', e); }
  }

  // ------ Main loop ------
  async function refresh() {
    const active = document.querySelector('.panel.active');
    if (!active) return;
    const id = active.id;
    if (id === 'panel-sessions') await refreshSessions();
    else if (id === 'panel-traffic') await refreshTraffic();
    else if (id === 'panel-controls') await refreshControls();
    else if (id === 'panel-log') await refreshLog();
    else if (id === 'panel-vulns') await refreshVulns();
    else if (id === 'panel-scanner') await refreshScannerHistory();
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
