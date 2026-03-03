package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/audit"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/scaneval"
	"github.com/glitchWebServer/internal/spider"
	"github.com/glitchWebServer/internal/storage"
)

// ---------------------------------------------------------------------------
// Auto-save — debounced state persistence to disk
// ---------------------------------------------------------------------------

var (
	stateFilePath string
	autoSaveMu    sync.Mutex
	autoSaveTimer *time.Timer
	globalStore   *storage.Store

	// configVersion is incremented on every config change so the request
	// handler can skip syncConfigToSubsystems when nothing changed.
	configVersion atomic.Int64
)

// BumpConfigVersion increments the global config version counter.
// Called whenever any config value changes (feature flags, admin config, etc.).
func BumpConfigVersion() {
	configVersion.Add(1)
}

// GetConfigVersion returns the current config version counter.
func GetConfigVersion() int64 {
	return configVersion.Load()
}

// SetStateFile configures the path for auto-saving config state.
func SetStateFile(path string) {
	autoSaveMu.Lock()
	defer autoSaveMu.Unlock()
	stateFilePath = path
}

// InitStorage initializes the PostgreSQL storage backend.
// If dbURL is empty, storage is disabled (file-only mode).
func InitStorage(dbURL string) error {
	if dbURL == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := storage.NewWithDSN(ctx, dbURL)
	if err != nil {
		log.Printf("\033[33m[glitch]\033[0m Warning: DB connection failed, using file-only mode: %v", err)
		return nil // graceful degradation, not fatal
	}
	globalStore = store
	log.Printf("\033[36m[glitch]\033[0m PostgreSQL storage initialized")
	return nil
}

// GetStore returns the global storage instance (may be nil if DB disabled).
func GetStore() *storage.Store { return globalStore }

// TriggerAutoSave schedules a debounced write of the current config to disk.
// Multiple rapid changes are coalesced into a single write after 500ms of quiet.
func TriggerAutoSave() {
	BumpConfigVersion()
	autoSaveMu.Lock()
	defer autoSaveMu.Unlock()
	if stateFilePath == "" {
		return
	}
	if autoSaveTimer != nil {
		autoSaveTimer.Stop()
	}
	autoSaveTimer = time.AfterFunc(500*time.Millisecond, func() {
		export := ExportConfig()
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			log.Printf("\033[31m[glitch]\033[0m Auto-save marshal error: %v", err)
			return
		}
		if err := os.WriteFile(stateFilePath, data, 0644); err != nil {
			log.Printf("\033[31m[glitch]\033[0m Auto-save write error: %v", err)
			return
		}

		audit.LogSystem("config.save", "config.autosave", map[string]interface{}{"file": stateFilePath})

		// Also persist to DB if available.
		if globalStore != nil {
			dbExport := &storage.FullConfigExport{
				Features:          export.Features,
				Config:            export.Config,
				VulnConfig:        export.VulnConfig,
				ErrorWeights:      export.ErrorWeights,
				PageTypeWeights:   export.PageTypeWeights,
				Blocking:          export.Blocking,
				APIChaosConfig:    export.APIChaosConfig,
				MediaChaosConfig:  export.MediaChaosConfig,
				ProxyConfig:       export.ProxyConfig,
				ScannerConfig:     export.ScannerConfig,
				NightmareConfig:   export.NightmareConfig,
				SpiderConfig:      export.SpiderConfig,
				Overrides:         export.Overrides,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := globalStore.SaveFullConfig(ctx, dbExport); err != nil {
				log.Printf("\033[33m[glitch]\033[0m DB auto-save warning: %v", err)
			}
		}
	})
}

// LoadStateFile loads config from DB (if available) or state file.
// Returns true if state was loaded from either source.
func LoadStateFile() bool {
	// Try DB first if available.
	if globalStore != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		dbExport, err := globalStore.LoadFullConfig(ctx)
		if err != nil {
			log.Printf("\033[33m[glitch]\033[0m DB load warning: %v", err)
		} else if dbExport != nil {
			export := &ConfigExport{
				Version:          "1.0",
				ExportedAt:       time.Now().UTC().Format(time.RFC3339),
				Features:         dbExport.Features,
				Config:           dbExport.Config,
				VulnConfig:       dbExport.VulnConfig,
				ErrorWeights:     dbExport.ErrorWeights,
				PageTypeWeights:  dbExport.PageTypeWeights,
				Blocking:         dbExport.Blocking,
				APIChaosConfig:   dbExport.APIChaosConfig,
				MediaChaosConfig: dbExport.MediaChaosConfig,
				ProxyConfig:      dbExport.ProxyConfig,
				ScannerConfig:    dbExport.ScannerConfig,
				NightmareConfig:  dbExport.NightmareConfig,
				SpiderConfig:     dbExport.SpiderConfig,
				Overrides:        dbExport.Overrides,
			}
			ImportConfig(export)
			audit.LogSystem("config.load", "config.load", map[string]interface{}{"source": "postgresql"})
			log.Printf("\033[36m[glitch]\033[0m Restored settings from PostgreSQL")
			return true
		}
	}

	// Fall back to state file.
	autoSaveMu.Lock()
	path := stateFilePath
	autoSaveMu.Unlock()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var export ConfigExport
	if err := json.Unmarshal(data, &export); err != nil {
		log.Printf("\033[31m[glitch]\033[0m Failed to parse state file %s: %v", path, err)
		return false
	}
	ImportConfig(&export)
	audit.LogSystem("config.load", "config.load", map[string]interface{}{"source": "file", "path": path})
	log.Printf("\033[36m[glitch]\033[0m Restored settings from %s", path)
	return true
}

// ---------------------------------------------------------------------------
// Feature Flags — thread-safe toggles for server subsystems
// ---------------------------------------------------------------------------

// flagValues holds the actual boolean state for all feature flags.
// Stored inside an atomic.Value for lock-free reads on the hot path.
type flagValues struct {
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
	spider         bool
	apiChaos       bool
	mediaChaos     bool
}

// FeatureFlags holds boolean toggles for each server subsystem.
// Uses atomic.Value for lock-free reads (hot path) and sync.Mutex
// for copy-on-write updates (admin panel changes, infrequent).
type FeatureFlags struct {
	mu sync.Mutex   // write-only lock
	v  atomic.Value // stores *flagValues
}

// NewFeatureFlags returns a FeatureFlags with every feature enabled.
func NewFeatureFlags() *FeatureFlags {
	f := &FeatureFlags{}
	f.v.Store(&flagValues{
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
		spider:         true,
		apiChaos:       true,
		mediaChaos:     true,
	})
	return f
}

func (f *FeatureFlags) IsLabyrinthEnabled() bool {
	return f.v.Load().(*flagValues).labyrinth
}

func (f *FeatureFlags) IsErrorInjectEnabled() bool {
	return f.v.Load().(*flagValues).errorInject
}

func (f *FeatureFlags) IsCaptchaEnabled() bool {
	return f.v.Load().(*flagValues).captcha
}

func (f *FeatureFlags) IsHoneypotEnabled() bool {
	return f.v.Load().(*flagValues).honeypot
}

func (f *FeatureFlags) IsVulnEnabled() bool {
	return f.v.Load().(*flagValues).vuln
}

func (f *FeatureFlags) IsAnalyticsEnabled() bool {
	return f.v.Load().(*flagValues).analytics
}

func (f *FeatureFlags) IsCDNEnabled() bool {
	return f.v.Load().(*flagValues).cdn
}

func (f *FeatureFlags) IsOAuthEnabled() bool {
	return f.v.Load().(*flagValues).oauth
}

func (f *FeatureFlags) IsHeaderCorruptEnabled() bool {
	return f.v.Load().(*flagValues).headerCorrupt
}

func (f *FeatureFlags) IsCookieTrapsEnabled() bool {
	return f.v.Load().(*flagValues).cookieTraps
}

func (f *FeatureFlags) IsJSTrapsEnabled() bool {
	return f.v.Load().(*flagValues).jsTraps
}

func (f *FeatureFlags) IsBotDetectionEnabled() bool {
	return f.v.Load().(*flagValues).botDetection
}

func (f *FeatureFlags) IsRandomBlockingEnabled() bool {
	return f.v.Load().(*flagValues).randomBlocking
}

func (f *FeatureFlags) IsFrameworkEmulEnabled() bool {
	return f.v.Load().(*flagValues).frameworkEmul
}

func (f *FeatureFlags) IsSearchEnabled() bool {
	return f.v.Load().(*flagValues).search
}

func (f *FeatureFlags) IsEmailEnabled() bool {
	return f.v.Load().(*flagValues).email
}

func (f *FeatureFlags) IsI18nEnabled() bool {
	return f.v.Load().(*flagValues).i18n
}

func (f *FeatureFlags) IsRecorderEnabled() bool {
	return f.v.Load().(*flagValues).recorder
}

func (f *FeatureFlags) IsWebSocketEnabled() bool {
	return f.v.Load().(*flagValues).websocket
}

func (f *FeatureFlags) IsPrivacyEnabled() bool {
	return f.v.Load().(*flagValues).privacy
}

func (f *FeatureFlags) IsHealthEnabled() bool {
	return f.v.Load().(*flagValues).health
}

func (f *FeatureFlags) IsSpiderEnabled() bool {
	return f.v.Load().(*flagValues).spider
}

func (f *FeatureFlags) IsAPIChaosEnabled() bool {
	return f.v.Load().(*flagValues).apiChaos
}

func (f *FeatureFlags) IsMediaChaosEnabled() bool {
	return f.v.Load().(*flagValues).mediaChaos
}

// Set toggles a named feature. Returns false if the name is unknown.
// Uses copy-on-write: copies the current flagValues, modifies, then stores atomically.
func (f *FeatureFlags) Set(name string, enabled bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.v.Load().(*flagValues)
	nv := *old // copy
	switch name {
	case "labyrinth":
		nv.labyrinth = enabled
	case "error_inject":
		nv.errorInject = enabled
	case "captcha":
		nv.captcha = enabled
	case "honeypot":
		nv.honeypot = enabled
	case "vuln":
		nv.vuln = enabled
	case "analytics":
		nv.analytics = enabled
	case "cdn":
		nv.cdn = enabled
	case "oauth":
		nv.oauth = enabled
	case "header_corrupt":
		nv.headerCorrupt = enabled
	case "cookie_traps":
		nv.cookieTraps = enabled
	case "js_traps":
		nv.jsTraps = enabled
	case "bot_detection":
		nv.botDetection = enabled
	case "random_blocking":
		nv.randomBlocking = enabled
	case "framework_emul":
		nv.frameworkEmul = enabled
	case "search":
		nv.search = enabled
	case "email":
		nv.email = enabled
	case "i18n":
		nv.i18n = enabled
	case "recorder":
		nv.recorder = enabled
	case "websocket":
		nv.websocket = enabled
	case "privacy":
		nv.privacy = enabled
	case "health":
		nv.health = enabled
	case "spider":
		nv.spider = enabled
	case "api_chaos":
		nv.apiChaos = enabled
	case "media_chaos":
		nv.mediaChaos = enabled
	default:
		return false
	}
	f.v.Store(&nv)
	BumpConfigVersion()
	return true
}

// Snapshot returns a map of feature name -> enabled for serialisation.
func (f *FeatureFlags) Snapshot() map[string]bool {
	v := f.v.Load().(*flagValues)
	return map[string]bool{
		"labyrinth":       v.labyrinth,
		"error_inject":    v.errorInject,
		"captcha":         v.captcha,
		"honeypot":        v.honeypot,
		"vuln":            v.vuln,
		"analytics":       v.analytics,
		"cdn":             v.cdn,
		"oauth":           v.oauth,
		"header_corrupt":  v.headerCorrupt,
		"cookie_traps":    v.cookieTraps,
		"js_traps":        v.jsTraps,
		"bot_detection":   v.botDetection,
		"random_blocking": v.randomBlocking,
		"framework_emul":  v.frameworkEmul,
		"search":          v.search,
		"email":           v.email,
		"i18n":            v.i18n,
		"recorder":        v.recorder,
		"websocket":       v.websocket,
		"privacy":         v.privacy,
		"health":          v.health,
		"spider":          v.spider,
		"api_chaos":       v.apiChaos,
		"media_chaos":     v.mediaChaos,
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

	// Protocol glitch controls
	ProtocolGlitchEnabled bool // whether protocol-level glitches are active
	ProtocolGlitchLevel   int  // 0=disabled, 1=subtle, 2=moderate, 3=aggressive, 4=chaos

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

	// API Chaos controls
	APIChaosProb float64 // 0-100, probability percentage for API chaos responses

	// Media Chaos controls
	MediaChaosProb              float64 // 0-100, probability percentage
	MediaChaosCorruptIntensity  float64 // 0-100, corruption aggressiveness
	MediaChaosSlowMinMs         int     // min delay for slow delivery (ms)
	MediaChaosSlowMaxMs         int     // max delay for slow delivery (ms)
	MediaChaosInfiniteMaxBytes  int64   // safety cap for infinite streams
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
		ProtocolGlitchEnabled: true,
		ProtocolGlitchLevel:   2,
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
		APIChaosProb:                30,
		MediaChaosProb:              30,
		MediaChaosCorruptIntensity:  50,
		MediaChaosSlowMinMs:         10,
		MediaChaosSlowMaxMs:         1000,
		MediaChaosInfiniteMaxBytes:  104857600, // 100MB
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
		"protocol_glitch_enabled":  c.ProtocolGlitchEnabled,
		"protocol_glitch_level":    c.ProtocolGlitchLevel,
		"honeypot_response_style":  c.HoneypotResponseStyle,
		"cookie_trap_frequency":    c.CookieTrapFrequency,
		"js_trap_difficulty":       c.JSTrapDifficulty,
		"active_framework":         c.ActiveFramework,
		"content_theme":            c.ContentTheme,
		"content_cache_ttl_sec":    c.ContentCacheTTLSec,
		"adaptive_aggressive_rps":  c.AdaptiveAggressiveRPS,
		"adaptive_labyrinth_paths": c.AdaptiveLabyrinthPaths,
		"recorder_format":          c.RecorderFormat,
		"api_chaos_probability":             c.APIChaosProb,
		"media_chaos_probability":           c.MediaChaosProb,
		"media_chaos_corruption_intensity":  c.MediaChaosCorruptIntensity,
		"media_chaos_slow_min_ms":           c.MediaChaosSlowMinMs,
		"media_chaos_slow_max_ms":           c.MediaChaosSlowMaxMs,
		"media_chaos_infinite_max_bytes":    c.MediaChaosInfiniteMaxBytes,
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
	case "protocol_glitch_enabled":
		c.ProtocolGlitchEnabled = value != 0
	case "protocol_glitch_level":
		v := int(value)
		if v < 0 {
			v = 0
		}
		if v > 4 {
			v = 4
		}
		c.ProtocolGlitchLevel = v
	case "api_chaos_probability":
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		c.APIChaosProb = value
	case "media_chaos_probability":
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		c.MediaChaosProb = value
	case "media_chaos_corruption_intensity":
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		c.MediaChaosCorruptIntensity = value
	case "media_chaos_slow_min_ms":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 60000 {
			v = 60000
		}
		c.MediaChaosSlowMinMs = v
	case "media_chaos_slow_max_ms":
		v := int(value)
		if v < 1 {
			v = 1
		}
		if v > 60000 {
			v = 60000
		}
		c.MediaChaosSlowMaxMs = v
	case "media_chaos_infinite_max_bytes":
		v := int64(value)
		if v < 0 {
			v = 0
		}
		if v > 10737418240 { // 10GB
			v = 10737418240
		}
		c.MediaChaosInfiniteMaxBytes = v
	default:
		return false
	}
	BumpConfigVersion()
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
	BumpConfigVersion()
	return true
}

// GetErrorWeights returns a copy of the current error weights map.
// Empty keys are excluded.
func (c *AdminConfig) GetErrorWeights() map[string]float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]float64, len(c.ErrorWeights))
	for k, v := range c.ErrorWeights {
		if k != "" {
			result[k] = v
		}
	}
	return result
}

// SetErrorWeight sets a single error type weight.
// Empty error type keys are silently ignored.
func (c *AdminConfig) SetErrorWeight(errType string, weight float64) {
	if errType == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if weight < 0 {
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	c.ErrorWeights[errType] = weight
	BumpConfigVersion()
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
// SetPageTypeWeight sets a single page type weight.
// Empty page type keys are silently ignored.
func (c *AdminConfig) SetPageTypeWeight(pageType string, weight float64) {
	if pageType == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if weight < 0 {
		weight = 0
	}
	if weight > 1 {
		weight = 1
	}
	c.PageTypeWeights[pageType] = weight
	BumpConfigVersion()
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

// VulnGroups lists all supported vulnerability group names.
var VulnGroups = []string{
	"owasp", "api_security", "advanced", "modern",
	"infrastructure", "iot_desktop", "mobile_privacy",
	"specialized", "dashboard",
}

// VulnConfig controls vulnerability endpoint toggling.
type VulnConfig struct {
	mu         sync.RWMutex
	groups     map[string]bool // group name -> enabled (true = enabled)
	categories map[string]bool
}

// NewVulnConfig returns a VulnConfig with all groups enabled.
func NewVulnConfig() *VulnConfig {
	groups := make(map[string]bool, len(VulnGroups))
	for _, g := range VulnGroups {
		groups[g] = true
	}
	return &VulnConfig{
		groups:     groups,
		categories: make(map[string]bool),
	}
}

// IsGroupEnabled returns whether a group is enabled.
func (vc *VulnConfig) IsGroupEnabled(group string) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	if enabled, ok := vc.groups[group]; ok {
		return enabled
	}
	return true // unknown groups are enabled by default
}

// SetGroup toggles a vulnerability group.
func (vc *VulnConfig) SetGroup(group string, enabled bool) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.groups[group] = enabled
	BumpConfigVersion()
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
	groups := make(map[string]bool, len(vc.groups))
	for k, v := range vc.groups {
		groups[k] = v
	}
	return map[string]interface{}{
		"groups":     groups,
		"categories": cats,
	}
}

// ---------------------------------------------------------------------------
// API Chaos Config — controls which API chaos categories are active
// ---------------------------------------------------------------------------

// APIChaosCategories lists all supported API chaos category names.
var APIChaosCategories = []string{
	"malformed_json", "wrong_format", "wrong_status", "wrong_headers",
	"redirect_chaos", "error_formats", "slow_partial", "data_edge_cases",
	"encoding_chaos", "auth_chaos",
}

// APIChaosConfig controls per-category API chaos toggles.
type APIChaosConfig struct {
	mu         sync.RWMutex
	categories map[string]bool // category -> enabled
}

// NewAPIChaosConfig returns an APIChaosConfig with all categories enabled.
func NewAPIChaosConfig() *APIChaosConfig {
	cats := make(map[string]bool, len(APIChaosCategories))
	for _, c := range APIChaosCategories {
		cats[c] = true
	}
	return &APIChaosConfig{categories: cats}
}

// IsEnabled returns whether a category is enabled.
func (ac *APIChaosConfig) IsEnabled(cat string) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	if enabled, ok := ac.categories[cat]; ok {
		return enabled
	}
	return true
}

// SetCategory toggles a category.
func (ac *APIChaosConfig) SetCategory(cat string, enabled bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.categories[cat] = enabled
	BumpConfigVersion()
}

// SetAll enables or disables all categories.
func (ac *APIChaosConfig) SetAll(enabled bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	for _, cat := range APIChaosCategories {
		ac.categories[cat] = enabled
	}
	BumpConfigVersion()
}

// Snapshot returns a copy of the current category states.
func (ac *APIChaosConfig) Snapshot() map[string]bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	result := make(map[string]bool, len(ac.categories))
	for k, v := range ac.categories {
		result[k] = v
	}
	return result
}

// ---------------------------------------------------------------------------
// Media Chaos Config — controls which media chaos categories are active
// ---------------------------------------------------------------------------

// MediaChaosCategories lists all supported media chaos category names.
var MediaChaosCategories = []string{
	"format_corruption", "content_length_chaos", "content_type_chaos",
	"range_request_chaos", "chunked_chaos", "slow_delivery",
	"infinite_content", "stream_switching", "cache_poisoning",
	"streaming_chaos",
}

// MediaChaosConfig controls per-category media chaos toggles.
type MediaChaosConfig struct {
	mu         sync.RWMutex
	categories map[string]bool // category -> enabled
}

// NewMediaChaosConfig returns a MediaChaosConfig with all categories enabled.
func NewMediaChaosConfig() *MediaChaosConfig {
	cats := make(map[string]bool, len(MediaChaosCategories))
	for _, c := range MediaChaosCategories {
		cats[c] = true
	}
	return &MediaChaosConfig{categories: cats}
}

// IsEnabled returns whether a media chaos category is enabled.
func (mc *MediaChaosConfig) IsEnabled(cat string) bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	if enabled, ok := mc.categories[cat]; ok {
		return enabled
	}
	return true
}

// SetCategory toggles a media chaos category.
func (mc *MediaChaosConfig) SetCategory(cat string, enabled bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.categories[cat] = enabled
	BumpConfigVersion()
}

// SetAll enables or disables all media chaos categories.
func (mc *MediaChaosConfig) SetAll(enabled bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	for _, cat := range MediaChaosCategories {
		mc.categories[cat] = enabled
	}
	BumpConfigVersion()
}

// Snapshot returns a copy of the current category states.
func (mc *MediaChaosConfig) Snapshot() map[string]bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	result := make(map[string]bool, len(mc.categories))
	for k, v := range mc.categories {
		result[k] = v
	}
	return result
}

// ---------------------------------------------------------------------------
// Config Export/Import structs
// ---------------------------------------------------------------------------

// ConfigExport represents a full configuration snapshot for export/import.
type ConfigExport struct {
	Version          string                 `json:"version"`
	ExportedAt       string                 `json:"exported_at"`
	Description      string                 `json:"description,omitempty"`
	Features         map[string]bool        `json:"features"`
	Config           map[string]interface{} `json:"config"`
	VulnConfig       map[string]interface{} `json:"vuln_config"`
	ErrorWeights     map[string]float64     `json:"error_weights,omitempty"`
	PageTypeWeights  map[string]float64     `json:"page_type_weights,omitempty"`
	Blocking         map[string]interface{} `json:"blocking,omitempty"`
	APIChaosConfig     map[string]bool        `json:"api_chaos_config,omitempty"`
	MediaChaosConfig   map[string]bool        `json:"media_chaos_config,omitempty"`
	ProxyConfig        map[string]interface{} `json:"proxy_config,omitempty"`
	ScannerConfig      map[string]interface{} `json:"scanner_config,omitempty"`
	NightmareConfig    map[string]interface{} `json:"nightmare_config,omitempty"`
	SpiderConfig       map[string]interface{} `json:"spider_config,omitempty"`
	Overrides          map[string]string      `json:"overrides,omitempty"`
}

// ExportConfig builds a ConfigExport from the current global state.
func ExportConfig() *ConfigExport {
	return &ConfigExport{
		Version:          "1.0",
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		Features:         globalFlags.Snapshot(),
		Config:           globalConfig.Get(),
		VulnConfig:       globalVulnConfig.Snapshot(),
		ErrorWeights:     globalConfig.GetErrorWeights(),
		PageTypeWeights:  globalConfig.GetPageTypeWeights(),
		Blocking:         ExportBlocking(),
		APIChaosConfig:   globalAPIChaosConfig.Snapshot(),
		MediaChaosConfig: globalMediaChaosConfig.Snapshot(),
		ProxyConfig:      globalProxyConfig.SnapshotForExport(),
		ScannerConfig:    ExportScannerConfig(),
		NightmareConfig:  ExportNightmareConfig(),
		SpiderConfig:     exportSpiderConfig(),
		Overrides:        ExportOverrides(),
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
			case int:
				globalConfig.Set(key, float64(v))
			case int64:
				globalConfig.Set(key, float64(v))
			case bool:
				if v {
					globalConfig.Set(key, 1)
				} else {
					globalConfig.Set(key, 0)
				}
			case string:
				globalConfig.SetString(key, v)
			}
		}
	}

	// Import vuln config
	if export.VulnConfig != nil {
		if groups, ok := export.VulnConfig["groups"]; ok {
			switch gmap := groups.(type) {
			case map[string]interface{}:
				for group, enabled := range gmap {
					if b, ok := enabled.(bool); ok {
						globalVulnConfig.SetGroup(group, b)
					}
				}
			case map[string]bool:
				for group, enabled := range gmap {
					globalVulnConfig.SetGroup(group, enabled)
				}
			}
		}
		if cats, ok := export.VulnConfig["categories"]; ok {
			switch cmap := cats.(type) {
			case map[string]interface{}:
				for id, enabled := range cmap {
					if b, ok := enabled.(bool); ok {
						globalVulnConfig.SetCategory(id, b)
					}
				}
			case map[string]bool:
				for id, enabled := range cmap {
					globalVulnConfig.SetCategory(id, enabled)
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

	// Import API chaos config
	if export.APIChaosConfig != nil {
		for cat, enabled := range export.APIChaosConfig {
			globalAPIChaosConfig.SetCategory(cat, enabled)
		}
	}

	// Import media chaos config
	if export.MediaChaosConfig != nil {
		for cat, enabled := range export.MediaChaosConfig {
			globalMediaChaosConfig.SetCategory(cat, enabled)
		}
	}

	// Import proxy config
	if export.ProxyConfig != nil {
		globalProxyConfig.Restore(export.ProxyConfig)
	}

	// Import blocking config — apply to adaptive engine if available,
	// otherwise store as pending for when the engine is created.
	if export.Blocking != nil {
		if globalAdaptive != nil {
			applyBlockingToAdaptive(export.Blocking, globalAdaptive)
		} else {
			pendingBlockingMu.Lock()
			pendingBlocking = export.Blocking
			pendingBlockingMu.Unlock()
		}
	}

	// Import scanner config (default profile, target, modules)
	if export.ScannerConfig != nil {
		ImportScannerConfig(export.ScannerConfig)
	}

	// Import nightmare state
	if export.NightmareConfig != nil {
		importNightmareConfig(export.NightmareConfig)
	}

	// Import spider config
	if export.SpiderConfig != nil {
		importSpiderConfig(export.SpiderConfig)
	}

	// Import per-client overrides
	if export.Overrides != nil {
		importOverrides(export.Overrides)
	}
}

// ---------------------------------------------------------------------------
// Proxy Config — stateful proxy mode and settings
// ---------------------------------------------------------------------------

// ProxyModes lists all valid proxy modes.
var ProxyModes = []string{"transparent", "waf", "chaos", "gateway", "nightmare", "mirror"}

// MirrorConfig holds a snapshot of server settings that the proxy mirrors.
type MirrorConfig struct {
	ErrorWeights         map[string]float64 `json:"error_weights"`
	ErrorRateMultiplier  float64            `json:"error_rate_multiplier"`
	PageTypeWeights      map[string]float64 `json:"page_type_weights"`
	HeaderCorruptLevel   int                `json:"header_corrupt_level"`
	ProtocolGlitchEnabled bool              `json:"protocol_glitch_enabled"`
	ProtocolGlitchLevel  int                `json:"protocol_glitch_level"`
	DelayMinMs           int                `json:"delay_min_ms"`
	DelayMaxMs           int                `json:"delay_max_ms"`
	ContentTheme         string             `json:"content_theme"`
	SnapshotTime         string             `json:"snapshot_time"`
}

// ProxyConfig holds the current proxy configuration.
type ProxyConfig struct {
	mu             sync.RWMutex
	Mode           string  `json:"mode"`
	WAFEnabled     bool    `json:"waf_enabled"`
	WAFBlockAction string  `json:"waf_block_action"`
	LatencyProb    float64 `json:"latency_prob"`
	CorruptProb    float64 `json:"corrupt_prob"`
	DropProb       float64 `json:"drop_prob"`
	ResetProb      float64 `json:"reset_prob"`
	Mirror         *MirrorConfig `json:"mirror,omitempty"`
}

// NewProxyConfig returns a ProxyConfig with transparent defaults.
func NewProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		Mode:           "transparent",
		WAFBlockAction: "reject",
	}
}

// GetMode returns the current proxy mode.
func (pc *ProxyConfig) GetMode() string {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.Mode
}

// SetMode sets the proxy mode if valid.
func (pc *ProxyConfig) SetMode(mode string) bool {
	for _, m := range ProxyModes {
		if m == mode {
			pc.mu.Lock()
			defer pc.mu.Unlock()
			pc.Mode = mode
			// Auto-configure WAF for waf/gateway/nightmare modes
			switch mode {
			case "waf", "gateway", "nightmare":
				pc.WAFEnabled = true
			case "mirror":
				pc.WAFEnabled = false
				// Snapshot server settings when entering mirror mode
				if pc.Mirror == nil {
					pc.mu.Unlock()
					mc := SnapshotMirrorFromServer()
					pc.mu.Lock()
					pc.Mirror = mc
				}
			default:
				pc.WAFEnabled = false
			}
			return true
		}
	}
	return false
}

// Snapshot returns a copy of proxy state for JSON serialization.
func (pc *ProxyConfig) Snapshot() map[string]interface{} {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	result := map[string]interface{}{
		"mode": pc.Mode,
		"pipeline_stats": map[string]int64{
			"requests_processed":  0,
			"responses_processed": 0,
			"requests_blocked":    0,
			"responses_modified":  0,
		},
		"waf_enabled": pc.WAFEnabled,
		"waf_stats": map[string]interface{}{
			"detections":   0,
			"rate_limited": 0,
			"block_action": pc.WAFBlockAction,
		},
		"chaos_config": map[string]float64{
			"latency_prob": pc.LatencyProb,
			"corrupt_prob": pc.CorruptProb,
			"drop_prob":    pc.DropProb,
			"reset_prob":   pc.ResetProb,
		},
		"interceptors": []interface{}{},
	}
	if pc.Mirror != nil {
		result["mirror"] = pc.Mirror
	}
	return result
}

// SnapshotForExport returns a minimal snapshot of proxy state suitable for persistence.
// Unlike Snapshot() (which includes runtime stats), this only captures restorable config.
func (pc *ProxyConfig) SnapshotForExport() map[string]interface{} {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	result := map[string]interface{}{
		"mode":             pc.Mode,
		"waf_enabled":      pc.WAFEnabled,
		"waf_block_action": pc.WAFBlockAction,
		"latency_prob":     pc.LatencyProb,
		"corrupt_prob":     pc.CorruptProb,
		"drop_prob":        pc.DropProb,
		"reset_prob":       pc.ResetProb,
	}
	if pc.Mirror != nil {
		result["mirror"] = pc.Mirror
	}
	return result
}

// Restore applies a snapshot produced by SnapshotForExport.
// Unknown keys are ignored; partial snapshots are applied incrementally.
func (pc *ProxyConfig) Restore(cfg map[string]interface{}) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if v, ok := cfg["mode"].(string); ok {
		valid := false
		for _, m := range ProxyModes {
			if m == v {
				valid = true
				break
			}
		}
		if valid {
			pc.Mode = v
		}
	}
	if v, ok := cfg["waf_enabled"].(bool); ok {
		pc.WAFEnabled = v
	}
	if v, ok := cfg["waf_block_action"].(string); ok {
		pc.WAFBlockAction = v
	}
	if v, ok := cfg["latency_prob"].(float64); ok {
		pc.LatencyProb = v
	}
	if v, ok := cfg["corrupt_prob"].(float64); ok {
		pc.CorruptProb = v
	}
	if v, ok := cfg["drop_prob"].(float64); ok {
		pc.DropProb = v
	}
	if v, ok := cfg["reset_prob"].(float64); ok {
		pc.ResetProb = v
	}
	if raw, ok := cfg["mirror"]; ok && raw != nil {
		switch m := raw.(type) {
		case map[string]interface{}:
			mc := &MirrorConfig{}
			if v, ok := m["error_rate_multiplier"].(float64); ok {
				mc.ErrorRateMultiplier = v
			}
			if v, ok := m["header_corrupt_level"].(float64); ok {
				mc.HeaderCorruptLevel = int(v)
			}
			if v, ok := m["protocol_glitch_enabled"].(bool); ok {
				mc.ProtocolGlitchEnabled = v
			}
			if v, ok := m["protocol_glitch_level"].(float64); ok {
				mc.ProtocolGlitchLevel = int(v)
			}
			if v, ok := m["delay_min_ms"].(float64); ok {
				mc.DelayMinMs = int(v)
			}
			if v, ok := m["delay_max_ms"].(float64); ok {
				mc.DelayMaxMs = int(v)
			}
			if v, ok := m["content_theme"].(string); ok {
				mc.ContentTheme = v
			}
			if v, ok := m["snapshot_time"].(string); ok {
				mc.SnapshotTime = v
			}
			if ew, ok := m["error_weights"].(map[string]interface{}); ok {
				mc.ErrorWeights = make(map[string]float64, len(ew))
				for k, v := range ew {
					if f, ok := v.(float64); ok {
						mc.ErrorWeights[k] = f
					}
				}
			}
			if pw, ok := m["page_type_weights"].(map[string]interface{}); ok {
				mc.PageTypeWeights = make(map[string]float64, len(pw))
				for k, v := range pw {
					if f, ok := v.(float64); ok {
						mc.PageTypeWeights[k] = f
					}
				}
			}
			pc.Mirror = mc
		}
	}
}

// SnapshotMirrorFromServer creates a MirrorConfig by reading current server settings.
func SnapshotMirrorFromServer() *MirrorConfig {
	cfg := globalConfig
	cfg.mu.RLock()
	ew := make(map[string]float64, len(cfg.ErrorWeights))
	for k, v := range cfg.ErrorWeights {
		ew[k] = v
	}
	pw := make(map[string]float64, len(cfg.PageTypeWeights))
	for k, v := range cfg.PageTypeWeights {
		pw[k] = v
	}
	mc := &MirrorConfig{
		ErrorWeights:          ew,
		ErrorRateMultiplier:   cfg.ErrorRateMultiplier,
		PageTypeWeights:       pw,
		HeaderCorruptLevel:    cfg.HeaderCorruptLevel,
		ProtocolGlitchEnabled: cfg.ProtocolGlitchEnabled,
		ProtocolGlitchLevel:   cfg.ProtocolGlitchLevel,
		DelayMinMs:            cfg.DelayMinMs,
		DelayMaxMs:            cfg.DelayMaxMs,
		ContentTheme:          cfg.ContentTheme,
		SnapshotTime:          time.Now().UTC().Format(time.RFC3339),
	}
	cfg.mu.RUnlock()
	return mc
}

// GetMirror returns a copy of the current mirror config (nil if not set).
func (pc *ProxyConfig) GetMirror() *MirrorConfig {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	if pc.Mirror == nil {
		return nil
	}
	// Return a copy
	ew := make(map[string]float64, len(pc.Mirror.ErrorWeights))
	for k, v := range pc.Mirror.ErrorWeights {
		ew[k] = v
	}
	pw := make(map[string]float64, len(pc.Mirror.PageTypeWeights))
	for k, v := range pc.Mirror.PageTypeWeights {
		pw[k] = v
	}
	return &MirrorConfig{
		ErrorWeights:          ew,
		ErrorRateMultiplier:   pc.Mirror.ErrorRateMultiplier,
		PageTypeWeights:       pw,
		HeaderCorruptLevel:    pc.Mirror.HeaderCorruptLevel,
		ProtocolGlitchEnabled: pc.Mirror.ProtocolGlitchEnabled,
		ProtocolGlitchLevel:   pc.Mirror.ProtocolGlitchLevel,
		DelayMinMs:            pc.Mirror.DelayMinMs,
		DelayMaxMs:            pc.Mirror.DelayMaxMs,
		ContentTheme:          pc.Mirror.ContentTheme,
		SnapshotTime:          pc.Mirror.SnapshotTime,
	}
}

// SetMirror sets the mirror config.
func (pc *ProxyConfig) SetMirror(mc *MirrorConfig) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.Mirror = mc
}

// ---------------------------------------------------------------------------
// Singleton holders — used by the admin API handlers
// ---------------------------------------------------------------------------

var (
	globalFlags          = NewFeatureFlags()
	globalConfig         = NewAdminConfig()
	globalVulnConfig     = NewVulnConfig()
	globalAPIChaosConfig   = NewAPIChaosConfig()
	globalMediaChaosConfig = NewMediaChaosConfig()
	globalProxyConfig      = NewProxyConfig()
	globalSpiderConfig = spider.NewConfig()
	globalProxyManager = NewProxyManager()
	globalRecorder     *recorder.Recorder
	globalAdaptive     *adaptive.Engine

	// Pending blocking/overrides config — stored by ImportConfig before adaptive engine exists.
	pendingBlocking   map[string]interface{}
	pendingOverrides  map[string]string
	pendingBlockingMu sync.Mutex

	// Scanner runner — uses the real scanner package
	scanRunner   *scaneval.Runner
	scanRunnerMu sync.Mutex

	// Comparison history for scanner trend tracking
	comparisonHistory = scaneval.NewComparisonHistory(100)
)

// GetFeatureFlags returns the global FeatureFlags instance.
func GetFeatureFlags() *FeatureFlags { return globalFlags }

// GetAdminConfig returns the global AdminConfig instance.
func GetAdminConfig() *AdminConfig { return globalConfig }

// GetVulnConfig returns the global VulnConfig instance.
func GetVulnConfig() *VulnConfig { return globalVulnConfig }

// GetAPIChaosConfig returns the global APIChaosConfig instance.
func GetAPIChaosConfig() *APIChaosConfig { return globalAPIChaosConfig }

// GetMediaChaosConfig returns the global MediaChaosConfig instance.
func GetMediaChaosConfig() *MediaChaosConfig { return globalMediaChaosConfig }

// GetProxyConfig returns the global ProxyConfig instance.
func GetProxyConfig() *ProxyConfig { return globalProxyConfig }

// GetProxyManager returns the global ProxyManager instance.
func GetProxyManager() *ProxyManager { return globalProxyManager }

// GetSpiderConfig returns the global spider Config instance.
func GetSpiderConfig() *spider.Config { return globalSpiderConfig }

// SetSpiderConfig replaces the global spider Config singleton. This allows
// the main function to share the same Config instance with the spider handler.
func SetSpiderConfig(cfg *spider.Config) {
	if cfg != nil {
		globalSpiderConfig = cfg
	}
}

// SetAdaptive stores the global adaptive engine reference and syncs any
// pending blocking config that was loaded before the engine existed.
func SetAdaptive(a *adaptive.Engine) {
	globalAdaptive = a
	SyncBlockingToAdaptive()
	syncOverridesToAdaptive()
}

// SyncBlockingToAdaptive applies any pending blocking config to the adaptive engine.
// Called from SetAdaptive after the engine is created.
func SyncBlockingToAdaptive() {
	if globalAdaptive == nil {
		return
	}
	pendingBlockingMu.Lock()
	cfg := pendingBlocking
	pendingBlocking = nil
	pendingBlockingMu.Unlock()

	if cfg == nil {
		return
	}
	applyBlockingToAdaptive(cfg, globalAdaptive)
}

// syncOverridesToAdaptive applies any pending per-client overrides to the adaptive engine.
func syncOverridesToAdaptive() {
	if globalAdaptive == nil {
		return
	}
	pendingBlockingMu.Lock()
	overrides := pendingOverrides
	pendingOverrides = nil
	pendingBlockingMu.Unlock()

	if overrides == nil {
		return
	}
	for clientID, mode := range overrides {
		globalAdaptive.SetOverride(clientID, adaptive.BehaviorMode(mode))
	}
}

// applyBlockingToAdaptive pushes a blocking config map to the adaptive engine.
func applyBlockingToAdaptive(cfg map[string]interface{}, a *adaptive.Engine) {
	if enabled, ok := cfg["enabled"].(bool); ok {
		a.SetBlockEnabled(enabled)
	}
	if chance, ok := cfg["chance"].(float64); ok {
		a.SetBlockChance(chance)
	}
	// duration_sec may be int (direct round-trip) or float64 (JSON round-trip).
	switch v := cfg["duration_sec"].(type) {
	case float64:
		a.SetBlockDuration(time.Duration(int(v)) * time.Second)
	case int:
		a.SetBlockDuration(time.Duration(v) * time.Second)
	}
}

// ExportBlocking returns the current blocking config from the adaptive engine.
func ExportBlocking() map[string]interface{} {
	if globalAdaptive == nil {
		return nil
	}
	chance, duration, enabled := globalAdaptive.GetBlockConfig()
	return map[string]interface{}{
		"enabled":      enabled,
		"chance":       chance,
		"duration_sec": int(duration.Seconds()),
	}
}

// ---------------------------------------------------------------------------
// Nightmare config export/import
// ---------------------------------------------------------------------------

// ExportNightmareConfig returns the current nightmare state for config export.
func ExportNightmareConfig() map[string]interface{} {
	globalNightmare.mu.RLock()
	defer globalNightmare.mu.RUnlock()

	if !globalNightmare.ServerActive && !globalNightmare.ScannerActive && !globalNightmare.ProxyActive {
		return nil // not active, nothing to persist
	}
	cfg := map[string]interface{}{
		"server_active":  globalNightmare.ServerActive,
		"scanner_active": globalNightmare.ScannerActive,
		"proxy_active":   globalNightmare.ProxyActive,
	}
	if globalNightmare.PreviousConfig != nil {
		cfg["previous_config"] = globalNightmare.PreviousConfig
	}
	if globalNightmare.PreviousFeatures != nil {
		cfg["previous_features"] = globalNightmare.PreviousFeatures
	}
	if globalNightmare.PreviousProxyMode != "" {
		cfg["previous_proxy_mode"] = globalNightmare.PreviousProxyMode
	}
	return cfg
}

// importNightmareConfig restores nightmare state from a config export.
func importNightmareConfig(cfg map[string]interface{}) {
	globalNightmare.mu.Lock()
	defer globalNightmare.mu.Unlock()

	if v, ok := cfg["server_active"].(bool); ok {
		globalNightmare.ServerActive = v
	}
	if v, ok := cfg["scanner_active"].(bool); ok {
		globalNightmare.ScannerActive = v
	}
	if v, ok := cfg["proxy_active"].(bool); ok {
		globalNightmare.ProxyActive = v
	}
	if v, ok := cfg["previous_proxy_mode"].(string); ok {
		globalNightmare.PreviousProxyMode = v
	}

	// Restore previous config snapshot (map[string]interface{})
	switch v := cfg["previous_config"].(type) {
	case map[string]interface{}:
		globalNightmare.PreviousConfig = v
	}

	// Restore previous features (may be map[string]interface{} from JSON)
	switch v := cfg["previous_features"].(type) {
	case map[string]bool:
		globalNightmare.PreviousFeatures = v
	case map[string]interface{}:
		m := make(map[string]bool, len(v))
		for k, val := range v {
			if b, ok := val.(bool); ok {
				m[k] = b
			}
		}
		globalNightmare.PreviousFeatures = m
	}
}

// ---------------------------------------------------------------------------
// Spider config export/import
// ---------------------------------------------------------------------------

// exportSpiderConfig returns the current spider config for config export.
func exportSpiderConfig() map[string]interface{} {
	if globalSpiderConfig == nil {
		return nil
	}
	return globalSpiderConfig.Snapshot()
}

// importSpiderConfig restores spider config from a config export.
func importSpiderConfig(cfg map[string]interface{}) {
	if globalSpiderConfig == nil {
		return
	}
	for key, val := range cfg {
		// JSON round-trip converts int to float64, so handle type coercion.
		switch key {
		case "sitemap_entry_count":
			switch v := val.(type) {
			case float64:
				globalSpiderConfig.Set(key, int(v))
			case int:
				globalSpiderConfig.Set(key, v)
			}
		case "robots_crawl_delay":
			switch v := val.(type) {
			case float64:
				globalSpiderConfig.Set(key, int(v))
			case int:
				globalSpiderConfig.Set(key, v)
			}
		case "robots_disallow_paths":
			switch v := val.(type) {
			case []string:
				globalSpiderConfig.Set(key, v)
			case []interface{}:
				paths := make([]string, 0, len(v))
				for _, p := range v {
					if s, ok := p.(string); ok {
						paths = append(paths, s)
					}
				}
				globalSpiderConfig.Set(key, paths)
			}
		default:
			// Float64 and bool values can be passed through directly.
			globalSpiderConfig.Set(key, val)
		}
	}
}

// ---------------------------------------------------------------------------
// Per-client overrides export/import
// ---------------------------------------------------------------------------

// ExportOverrides returns the current per-client behavior overrides.
func ExportOverrides() map[string]string {
	if globalAdaptive == nil {
		return nil
	}
	overrides := globalAdaptive.GetOverrides()
	if len(overrides) == 0 {
		return nil
	}
	result := make(map[string]string, len(overrides))
	for clientID, mode := range overrides {
		result[clientID] = string(mode)
	}
	return result
}

// importOverrides restores per-client behavior overrides.
func importOverrides(overrides map[string]string) {
	if globalAdaptive == nil {
		// Store as pending for when the engine is created
		pendingBlockingMu.Lock()
		pendingOverrides = overrides
		pendingBlockingMu.Unlock()
		return
	}
	for clientID, mode := range overrides {
		globalAdaptive.SetOverride(clientID, adaptive.BehaviorMode(mode))
	}
}

// SetRecorder sets the global recorder instance for admin API access.
func SetRecorder(rec *recorder.Recorder) {
	globalRecorder = rec
}

// GetRecorder returns the global recorder instance.
func GetRecorder() *recorder.Recorder {
	return globalRecorder
}

// InitScanRunner eagerly creates the scanner runner so available-scanner
// discovery (subprocess calls) happens at startup rather than on first request.
func InitScanRunner(serverPort, dashPort int) {
	scanRunnerMu.Lock()
	defer scanRunnerMu.Unlock()
	if scanRunner == nil {
		scanRunner = scaneval.NewRunner(scaneval.DefaultRunnerConfig(
			fmt.Sprintf("http://localhost:%d", serverPort),
			fmt.Sprintf("http://localhost:%d", dashPort),
		))
		scanRunner.OnComplete = persistExternalScanRun
	}
}

// persistExternalScanRun saves an external scanner run to PostgreSQL.
func persistExternalScanRun(run *scaneval.ScanRun) {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := store.SaveScanFromReport(ctx, "external:"+run.Scanner, run.Status, "", 0, run)
	if err != nil {
		log.Printf("[glitch] Failed to persist external scan run: %v", err)
	}
}

// LoadExternalScanHistory restores external scanner runs and comparison history
// from PostgreSQL on startup.
func LoadExternalScanHistory() {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scans, err := store.ListScans(ctx, 200)
	if err != nil {
		log.Printf("[glitch] Failed to load external scan history: %v", err)
		return
	}
	runner := getScanRunner()
	loadedRuns := 0
	loadedComparisons := 0
	for i := len(scans) - 1; i >= 0; i-- {
		rec := scans[i]
		if !strings.HasPrefix(rec.ScannerName, "external:") {
			continue
		}
		scannerName := rec.ScannerName[9:] // strip "external:"

		// Try restoring as a ScanRun (external scanner run data).
		var run scaneval.ScanRun
		if err := json.Unmarshal(rec.Report, &run); err == nil && run.Scanner != "" {
			runner.AddResult(&run)
			loadedRuns++
		}

		// Also restore as a comparison history entry for the history tab.
		entry := scaneval.HistoryEntry{
			ID:        fmt.Sprintf("db-%d", rec.ID),
			Timestamp: rec.CreatedAt.UTC().Format(time.RFC3339),
			Scanner:   scannerName,
			Grade:     rec.Grade,
			Detection: rec.DetectionRate,
		}
		// Try to extract additional details from the report JSON.
		var reportMeta struct {
			TruePositives []json.RawMessage `json:"true_positives"`
			ExpectedVulns int               `json:"expected_vulns"`
			FPRate        float64           `json:"false_positive_rate"`
		}
		if err := json.Unmarshal(rec.Report, &reportMeta); err == nil {
			entry.VulnsFound = len(reportMeta.TruePositives)
			entry.VulnsTotal = reportMeta.ExpectedVulns
			entry.FPRate = reportMeta.FPRate
		}
		comparisonHistory.AddEntry(entry)
		loadedComparisons++
	}
	if loadedRuns > 0 {
		log.Printf("[glitch] Restored %d external scan runs from DB", loadedRuns)
	}
	if loadedComparisons > 0 {
		log.Printf("[glitch] Restored %d external scan comparison entries from DB", loadedComparisons)
	}
}

// RestoreMetrics loads the latest metrics snapshot from PostgreSQL and restores
// cumulative counters on the collector so the dashboard doesn't start from zero.
func RestoreMetrics(collector *metrics.Collector) {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshots, err := store.ListMetricsSnapshots(ctx, 1)
	if err != nil {
		log.Printf("[glitch] Failed to load metrics snapshot: %v", err)
		return
	}
	if len(snapshots) == 0 {
		return
	}
	snap := snapshots[0]
	cs := metrics.CounterSnapshot{
		TotalRequests: snap.TotalRequests,
		TotalErrors:   snap.TotalErrors,
		Total2xx:      snap.Total2xx,
		Total4xx:      snap.Total4xx,
		Total5xx:      snap.Total5xx,
	}
	// Restore extended counters from snapshot_data if available.
	if len(snap.SnapshotData) > 0 {
		var extra struct {
			TotalDelayed       int64 `json:"total_delayed"`
			TotalLabyrinth     int64 `json:"total_labyrinth"`
			TotalRequestBytes  int64 `json:"total_request_bytes"`
			TotalResponseBytes int64 `json:"total_response_bytes"`
		}
		if json.Unmarshal(snap.SnapshotData, &extra) == nil {
			cs.TotalDelayed = extra.TotalDelayed
			cs.TotalLabyrinth = extra.TotalLabyrinth
			cs.TotalRequestBytes = extra.TotalRequestBytes
			cs.TotalResponseBytes = extra.TotalResponseBytes
		}
	}
	collector.RestoreCounters(cs)
	log.Printf("[glitch] Restored metrics from DB (total_requests=%d, last snapshot: %s)",
		cs.TotalRequests, snap.CreatedAt.Format(time.RFC3339))
}

// StartMetricsSnapshotter launches a background goroutine that periodically
// saves metrics to PostgreSQL. Returns a stop function.
func StartMetricsSnapshotter(collector *metrics.Collector) func() {
	store := GetStore()
	if store == nil {
		return func() {}
	}
	stopCh := make(chan struct{})
	go func() {
		metricsTicker := time.NewTicker(30 * time.Second)
		profileTicker := time.NewTicker(5 * time.Minute)
		defer metricsTicker.Stop()
		defer profileTicker.Stop()
		for {
			select {
			case <-metricsTicker.C:
				cs := collector.GetCounterSnapshot()
				extraData, _ := json.Marshal(map[string]int64{
					"total_delayed":        cs.TotalDelayed,
					"total_labyrinth":      cs.TotalLabyrinth,
					"total_request_bytes":  cs.TotalRequestBytes,
					"total_response_bytes": cs.TotalResponseBytes,
				})
				snap := &storage.MetricsSnapshot{
					TotalRequests:     cs.TotalRequests,
					TotalErrors:       cs.TotalErrors,
					Total2xx:          cs.Total2xx,
					Total4xx:          cs.Total4xx,
					Total5xx:          cs.Total5xx,
					ActiveConnections: int(collector.ActiveConns.Load()),
					UniqueClients:     len(collector.GetAllClientProfiles()),
					SnapshotData:      extraData,
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				store.SaveMetricsSnapshot(ctx, snap)
				cancel()
			case <-profileTicker.C:
				SaveClientProfiles(collector)
			case <-stopCh:
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// SaveMetricsNow immediately saves a metrics snapshot to the database.
// Called during graceful shutdown to ensure no data is lost.
func SaveMetricsNow(collector *metrics.Collector) {
	store := GetStore()
	if store == nil {
		return
	}
	cs := collector.GetCounterSnapshot()
	extraData, _ := json.Marshal(map[string]int64{
		"total_delayed":        cs.TotalDelayed,
		"total_labyrinth":      cs.TotalLabyrinth,
		"total_request_bytes":  cs.TotalRequestBytes,
		"total_response_bytes": cs.TotalResponseBytes,
	})
	snap := &storage.MetricsSnapshot{
		TotalRequests:     cs.TotalRequests,
		TotalErrors:       cs.TotalErrors,
		Total2xx:          cs.Total2xx,
		Total4xx:          cs.Total4xx,
		Total5xx:          cs.Total5xx,
		ActiveConnections: int(collector.ActiveConns.Load()),
		UniqueClients:     len(collector.GetAllClientProfiles()),
		SnapshotData:      extraData,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.SaveMetricsSnapshot(ctx, snap); err != nil {
		log.Printf("[glitch] Failed to save final metrics snapshot: %v", err)
	}
}

// SaveClientProfiles saves active client profiles to the database.
// Called periodically by the metrics snapshotter and during shutdown.
func SaveClientProfiles(collector *metrics.Collector) {
	store := GetStore()
	if store == nil {
		return
	}
	profiles := collector.GetAllClientProfiles()
	if len(profiles) == 0 {
		return
	}
	// Sort by total requests descending, keep top 100.
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].TotalRequests > profiles[j].TotalRequests
	})
	limit := 100
	if len(profiles) < limit {
		limit = len(profiles)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	saved := 0
	for _, cp := range profiles[:limit] {
		snap := cp.Snapshot()
		profileData, err := json.Marshal(snap)
		if err != nil {
			continue
		}
		rec := &storage.ClientProfileRecord{
			ClientID:      snap.ClientID,
			TotalRequests: snap.TotalRequests,
			AdaptiveMode:  snap.AdaptiveProfile,
			ProfileData:   profileData,
		}
		if err := store.SaveClientProfile(ctx, rec); err != nil {
			log.Printf("[glitch] Failed to save client profile %s: %v", snap.ClientID, err)
			continue
		}
		saved++
	}
	if saved > 0 {
		log.Printf("[glitch] Saved %d client profiles to DB", saved)
	}
}

// RestoreClientProfiles loads client profiles from the database into the collector.
func RestoreClientProfiles(collector *metrics.Collector) {
	store := GetStore()
	if store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, err := store.ListClientProfiles(ctx, 100)
	if err != nil {
		log.Printf("[glitch] Failed to load client profiles: %v", err)
		return
	}
	if len(records) == 0 {
		return
	}
	restored := 0
	for _, rec := range records {
		if len(rec.ProfileData) == 0 {
			continue
		}
		var snap metrics.ClientProfileSnapshot
		if err := json.Unmarshal(rec.ProfileData, &snap); err != nil {
			log.Printf("[glitch] Failed to unmarshal client profile %s: %v", rec.ClientID, err)
			continue
		}
		if snap.ClientID == "" {
			snap.ClientID = rec.ClientID
		}
		collector.RestoreClientProfile(snap)
		restored++
	}
	log.Printf("[glitch] Restored %d client profiles from DB", restored)
}

// getScanRunner returns the singleton scaneval.Runner, creating it on first call.
func getScanRunner() *scaneval.Runner {
	scanRunnerMu.Lock()
	defer scanRunnerMu.Unlock()
	if scanRunner == nil {
		scanRunner = scaneval.NewRunner(scaneval.DefaultRunnerConfig(
			"http://localhost:8765",
			"http://localhost:8766",
		))
	}
	return scanRunner
}

// buildScannerProfile computes an expected profile from current feature flags and config.
func buildScannerProfile() *scaneval.ExpectedProfile {
	features := globalFlags.Snapshot()
	config := globalConfig.Get()
	return scaneval.ComputeProfile(features, config, 8765, 8766)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		return pairs[i].Key < pairs[j].Key // stable tie-break by key
	})
	if len(pairs) > top {
		pairs = pairs[:top]
	}
	return pairs
}

// SetAll sets all feature flags to the given value.
// Note: recorder is excluded because it is an operational setting (traffic
// capture), not a chaos feature. Nightmare mode should not start/stop recording.
func (f *FeatureFlags) SetAll(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.v.Load().(*flagValues)
	nv := *old // copy
	nv.labyrinth = enabled
	nv.errorInject = enabled
	nv.captcha = enabled
	nv.honeypot = enabled
	nv.vuln = enabled
	nv.analytics = enabled
	nv.cdn = enabled
	nv.oauth = enabled
	nv.headerCorrupt = enabled
	nv.cookieTraps = enabled
	nv.jsTraps = enabled
	nv.botDetection = enabled
	nv.randomBlocking = enabled
	nv.frameworkEmul = enabled
	nv.search = enabled
	nv.email = enabled
	nv.i18n = enabled
	// nv.recorder deliberately excluded — operational, not chaos
	nv.websocket = enabled
	nv.privacy = enabled
	nv.health = enabled
	nv.spider = enabled
	nv.apiChaos = enabled
	nv.mediaChaos = enabled
	f.v.Store(&nv)
}

// ---------------------------------------------------------------------------
// Nightmare Mode — cross-mode extreme chaos state
// ---------------------------------------------------------------------------

// NightmareState tracks the activation of nightmare mode across subsystems.
type NightmareState struct {
	mu               sync.RWMutex
	ServerActive     bool
	ScannerActive    bool
	ProxyActive      bool
	PreviousConfig    map[string]interface{} // snapshot before server nightmare
	PreviousFeatures  map[string]bool        // snapshot before server nightmare
	PreviousProxyMode string                 // snapshot before proxy nightmare
}

var globalNightmare = &NightmareState{}

// GetNightmareState returns the global NightmareState instance.
func GetNightmareState() *NightmareState {
	return globalNightmare
}

// Snapshot returns a map of nightmare subsystem -> active status.
func (n *NightmareState) Snapshot() map[string]bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return map[string]bool{
		"server":  n.ServerActive,
		"scanner": n.ScannerActive,
		"proxy":   n.ProxyActive,
	}
}

// Reset deactivates all nightmare subsystems and clears snapshots.
func (n *NightmareState) Reset() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ServerActive = false
	n.ScannerActive = false
	n.ProxyActive = false
	n.PreviousConfig = nil
	n.PreviousFeatures = nil
	n.PreviousProxyMode = ""
}

// IsAnyActive returns true if any nightmare subsystem is active.
func (n *NightmareState) IsAnyActive() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.ServerActive || n.ScannerActive || n.ProxyActive
}

// ActiveModes returns a list of active nightmare subsystem names.
func (n *NightmareState) ActiveModes() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var modes []string
	if n.ServerActive {
		modes = append(modes, "Server")
	}
	if n.ScannerActive {
		modes = append(modes, "Scanner")
	}
	if n.ProxyActive {
		modes = append(modes, "Proxy")
	}
	return modes
}
