package dashboard

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/scanner"
)

// ---------------------------------------------------------------------------
// Feature Flags — thread-safe toggles for server subsystems
// ---------------------------------------------------------------------------

// FeatureFlags holds boolean toggles for each server subsystem.
type FeatureFlags struct {
	mu sync.RWMutex

	labyrinth      bool
	errorInject    bool
	captcha        bool
	honeypot       bool
	vuln           bool
	analytics      bool
	cdn            bool
	oauth          bool
	headerCorrupt  bool
	cookieTraps    bool
	jsTraps        bool
	botDetection   bool
	randomBlocking bool
	frameworkEmul  bool
	search         bool
	email          bool
	i18n           bool
	recorder       bool
	websocket      bool
	privacy        bool
	health         bool
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
	switch name {
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
// Admin Config — tunable numeric and string parameters
// ---------------------------------------------------------------------------

// AdminConfig holds tunable parameters for the admin panel.
type AdminConfig struct {
	mu sync.RWMutex

	MaxLabyrinthDepth    int     // 1-100
	ErrorRateMultiplier  float64 // 0.0-5.0
	CaptchaTriggerThresh int     // request count threshold before captcha fires
	BlockChance          float64 // 0.0-1.0, random block probability
	BlockDurationSec     int     // how long blocks last
	BotScoreThreshold    float64 // 0-100, score above which to flag as bot
	HeaderCorruptLevel   int     // 0-4 (none/subtle/moderate/aggressive/chaos)
	DelayMinMs           int     // minimum added delay (ms)
	DelayMaxMs           int     // maximum added delay (ms)
	LabyrinthLinkDensity int     // 1-20, links per labyrinth page
	AdaptiveIntervalSec  int     // seconds between adaptive re-evaluation

	// Extended controllability fields
	ErrorWeights           map[string]float64
	HoneypotResponseStyle  string
	PageTypeWeights        map[string]float64
	CookieTrapFrequency    int
	JSTrapDifficulty       int
	ActiveFramework        string
	ContentTheme           string
	ContentCacheTTLSec     int
	AdaptiveAggressiveRPS  float64
	AdaptiveLabyrinthPaths int
	RecorderFormat         string // "jsonl" or "pcap"
}

// NewAdminConfig returns an AdminConfig with sensible defaults.
func NewAdminConfig() *AdminConfig {
	return &AdminConfig{
		MaxLabyrinthDepth:      50,
		ErrorRateMultiplier:    1.0,
		CaptchaTriggerThresh:   100,
		BlockChance:            0.02,
		BlockDurationSec:       30,
		BotScoreThreshold:      60,
		HeaderCorruptLevel:     1,
		DelayMinMs:             0,
		DelayMaxMs:             0,
		LabyrinthLinkDensity:   8,
		AdaptiveIntervalSec:    30,
		ErrorWeights:           make(map[string]float64),
		HoneypotResponseStyle:  "realistic",
		PageTypeWeights:        make(map[string]float64),
		CookieTrapFrequency:    3,
		JSTrapDifficulty:       2,
		ActiveFramework:        "auto",
		ContentTheme:           "default",
		ContentCacheTTLSec:     60,
		AdaptiveAggressiveRPS:  10,
		AdaptiveLabyrinthPaths: 5,
		RecorderFormat:         "jsonl",
	}
}

// Get returns the current config values as a map.
func (c *AdminConfig) Get() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"max_labyrinth_depth":      c.MaxLabyrinthDepth,
		"error_rate_multiplier":    c.ErrorRateMultiplier,
		"captcha_trigger_thresh":   c.CaptchaTriggerThresh,
		"block_chance":             c.BlockChance,
		"block_duration_sec":       c.BlockDurationSec,
		"bot_score_threshold":      c.BotScoreThreshold,
		"header_corrupt_level":     c.HeaderCorruptLevel,
		"delay_min_ms":             c.DelayMinMs,
		"delay_max_ms":             c.DelayMaxMs,
		"labyrinth_link_density":   c.LabyrinthLinkDensity,
		"adaptive_interval_sec":    c.AdaptiveIntervalSec,
		"honeypot_response_style":  c.HoneypotResponseStyle,
		"cookie_trap_frequency":    c.CookieTrapFrequency,
		"js_trap_difficulty":       c.JSTrapDifficulty,
		"active_framework":         c.ActiveFramework,
		"content_theme":            c.ContentTheme,
		"content_cache_ttl_sec":    c.ContentCacheTTLSec,
		"adaptive_aggressive_rps":  c.AdaptiveAggressiveRPS,
		"adaptive_labyrinth_paths": c.AdaptiveLabyrinthPaths,
		"recorder_format":          c.RecorderFormat,
	}
}

// Set updates a single numeric config key. Returns false if the key is unknown.
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
	case "cookie_trap_frequency":
		v := int(value)
		if v < 0 {
			v = 0
		}
		if v > 20 {
			v = 20
		}
		c.CookieTrapFrequency = v
	case "js_trap_difficulty":
		v := int(value)
		if v < 0 {
			v = 0
		}
		if v > 5 {
			v = 5
		}
		c.JSTrapDifficulty = v
	case "content_cache_ttl_sec":
		v := int(value)
		if v < 0 {
			v = 0
		}
		if v > 3600 {
			v = 3600
		}
		c.ContentCacheTTLSec = v
	case "adaptive_aggressive_rps":
		if value < 1 {
			value = 1
		}
		if value > 100 {
			value = 100
		}
		c.AdaptiveAggressiveRPS = value
	case "adaptive_labyrinth_paths":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 50 {
			v = 50
		}
		c.AdaptiveLabyrinthPaths = v
	default:
		return false
	}
	return true
}

// SetString updates a string config key. Returns false if the key is unknown.
func (c *AdminConfig) SetString(key, value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch key {
	case "honeypot_response_style":
		c.HoneypotResponseStyle = value
	case "active_framework":
		c.ActiveFramework = value
	case "content_theme":
		c.ContentTheme = value
	case "recorder_format":
		if value == "jsonl" || value == "pcap" {
			c.RecorderFormat = value
		}
	default:
		return false
	}
	return true
}

// GetErrorWeights returns a copy of the current error weights map.
func (c *AdminConfig) GetErrorWeights() map[string]float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]float64, len(c.ErrorWeights))
	for k, v := range c.ErrorWeights {
		result[k] = v
	}
	return result
}

// SetErrorWeight sets a single error type weight.
func (c *AdminConfig) SetErrorWeight(errType string, weight float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if weight < 0 {
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	c.ErrorWeights[errType] = weight
}

// ResetErrorWeights clears all custom error weights (reverts to defaults).
func (c *AdminConfig) ResetErrorWeights() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ErrorWeights = make(map[string]float64)
}

// GetPageTypeWeights returns a copy of the current page type weights map.
func (c *AdminConfig) GetPageTypeWeights() map[string]float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]float64, len(c.PageTypeWeights))
	for k, v := range c.PageTypeWeights {
		result[k] = v
	}
	return result
}

// SetPageTypeWeight sets a single page type weight.
func (c *AdminConfig) SetPageTypeWeight(pageType string, weight float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if weight < 0 {
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	c.PageTypeWeights[pageType] = weight
}

// ResetPageTypeWeights clears all custom page type weights.
func (c *AdminConfig) ResetPageTypeWeights() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.PageTypeWeights = make(map[string]float64)
}

// ---------------------------------------------------------------------------
// Vulnerability Config — controls which vuln groups/categories are active
// ---------------------------------------------------------------------------

// VulnConfig controls vulnerability endpoint toggling.
type VulnConfig struct {
	mu               sync.RWMutex
	owaspEnabled     bool
	advancedEnabled  bool
	dashboardEnabled bool
	categories       map[string]bool
}

// NewVulnConfig returns a VulnConfig with all groups enabled.
func NewVulnConfig() *VulnConfig {
	return &VulnConfig{
		owaspEnabled:     true,
		advancedEnabled:  true,
		dashboardEnabled: true,
		categories:       make(map[string]bool),
	}
}

// IsGroupEnabled returns whether a group is enabled.
func (vc *VulnConfig) IsGroupEnabled(group string) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	switch group {
	case "owasp":
		return vc.owaspEnabled
	case "advanced":
		return vc.advancedEnabled
	case "dashboard":
		return vc.dashboardEnabled
	}
	return true
}

// SetGroup toggles a vulnerability group.
func (vc *VulnConfig) SetGroup(group string, enabled bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	switch group {
	case "owasp":
		vc.owaspEnabled = enabled
	case "advanced":
		vc.advancedEnabled = enabled
	case "dashboard":
		vc.dashboardEnabled = enabled
	}
}

// IsCategoryEnabled returns whether a specific category ID is enabled.
func (vc *VulnConfig) IsCategoryEnabled(id string) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	if enabled, ok := vc.categories[id]; ok {
		return enabled
	}
	return true // enabled by default
}

// SetCategory toggles a specific vulnerability category.
func (vc *VulnConfig) SetCategory(id string, enabled bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.categories[id] = enabled
}

// Snapshot returns the current vuln config state.
func (vc *VulnConfig) Snapshot() map[string]interface{} {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	cats := make(map[string]bool, len(vc.categories))
	for k, v := range vc.categories {
		cats[k] = v
	}
	return map[string]interface{}{
		"groups": map[string]bool{
			"owasp":     vc.owaspEnabled,
			"advanced":  vc.advancedEnabled,
			"dashboard": vc.dashboardEnabled,
		},
		"categories": cats,
	}
}

// ---------------------------------------------------------------------------
// Config Export/Import structs
// ---------------------------------------------------------------------------

// ConfigExport represents a full configuration snapshot for export/import.
type ConfigExport struct {
	Version         string                 `json:"version"`
	ExportedAt      string                 `json:"exported_at"`
	Description     string                 `json:"description,omitempty"`
	Features        map[string]bool        `json:"features"`
	Config          map[string]interface{} `json:"config"`
	VulnConfig      map[string]interface{} `json:"vuln_config"`
	ErrorWeights    map[string]float64     `json:"error_weights,omitempty"`
	PageTypeWeights map[string]float64     `json:"page_type_weights,omitempty"`
	Blocking        map[string]interface{} `json:"blocking,omitempty"`
}

// ExportConfig builds a ConfigExport from the current global state.
func ExportConfig() *ConfigExport {
	return &ConfigExport{
		Version:         "1.0",
		ExportedAt:      time.Now().UTC().Format(time.RFC3339),
		Features:        globalFlags.Snapshot(),
		Config:          globalConfig.Get(),
		VulnConfig:      globalVulnConfig.Snapshot(),
		ErrorWeights:    globalConfig.GetErrorWeights(),
		PageTypeWeights: globalConfig.GetPageTypeWeights(),
	}
}

// ImportConfig applies a ConfigExport to the global state.
func ImportConfig(export *ConfigExport) {
	// Import features
	if export.Features != nil {
		for name, enabled := range export.Features {
			globalFlags.Set(name, enabled)
		}
	}

	// Import numeric config
	if export.Config != nil {
		for key, val := range export.Config {
			switch v := val.(type) {
			case float64:
				globalConfig.Set(key, v)
			case string:
				globalConfig.SetString(key, v)
			}
		}
	}

	// Import vuln config
	if export.VulnConfig != nil {
		if groups, ok := export.VulnConfig["groups"]; ok {
			if gmap, ok := groups.(map[string]interface{}); ok {
				for group, enabled := range gmap {
					if b, ok := enabled.(bool); ok {
						globalVulnConfig.SetGroup(group, b)
					}
				}
			}
		}
		if cats, ok := export.VulnConfig["categories"]; ok {
			if cmap, ok := cats.(map[string]interface{}); ok {
				for id, enabled := range cmap {
					if b, ok := enabled.(bool); ok {
						globalVulnConfig.SetCategory(id, b)
					}
				}
			}
		}
	}

	// Import error weights
	if export.ErrorWeights != nil {
		globalConfig.ResetErrorWeights()
		for errType, weight := range export.ErrorWeights {
			globalConfig.SetErrorWeight(errType, weight)
		}
	}

	// Import page type weights
	if export.PageTypeWeights != nil {
		globalConfig.ResetPageTypeWeights()
		for pageType, weight := range export.PageTypeWeights {
			globalConfig.SetPageTypeWeight(pageType, weight)
		}
	}
}

// ---------------------------------------------------------------------------
// Singleton holders — used by the admin API handlers
// ---------------------------------------------------------------------------

var (
	globalFlags      = NewFeatureFlags()
	globalConfig     = NewAdminConfig()
	globalVulnConfig = NewVulnConfig()

	// Scanner runner — uses the real scanner package
	scanRunner   *scanner.Runner
	scanRunnerMu sync.Mutex

	// Comparison history for scanner trend tracking
	comparisonHistory = scanner.NewComparisonHistory(100)
)

// GetFeatureFlags returns the global FeatureFlags instance.
func GetFeatureFlags() *FeatureFlags { return globalFlags }

// GetAdminConfig returns the global AdminConfig instance.
func GetAdminConfig() *AdminConfig { return globalConfig }

// GetVulnConfig returns the global VulnConfig instance.
func GetVulnConfig() *VulnConfig { return globalVulnConfig }

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
