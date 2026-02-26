package adaptive

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/metrics"
)

// BehaviorMode defines how the server treats a specific client.
type BehaviorMode string

const (
	ModeNormal       BehaviorMode = "normal"       // default error rates
	ModeCooperative  BehaviorMode = "cooperative"   // reduced errors, fast responses
	ModeAggressive   BehaviorMode = "aggressive"    // elevated errors, more glitches
	ModeLabyrinth    BehaviorMode = "labyrinth"     // redirect into infinite pages
	ModeMirror       BehaviorMode = "mirror"        // mirror their request patterns back
	ModeEscalating   BehaviorMode = "escalating"    // gets worse over time
	ModeIntermittent BehaviorMode = "intermittent"  // random bursts of failure
	ModeBlocked      BehaviorMode = "blocked"       // client is temporarily blocked
)

// ClientBehavior holds the adaptive state for a single client.
type ClientBehavior struct {
	Mode            BehaviorMode
	ErrorProfile    errors.ErrorProfile
	LabyrinthChance float64 // probability of redirecting to labyrinth
	PageVariety     float64 // 0-1, how many page types to use
	AssignedAt      time.Time
	Reason          string
	EscalationLevel int // for ModeEscalating
	BlockedUntil    time.Time // for ModeBlocked
	BotScore        float64   // 0-100, detection score from botdetect
}

// Engine decides how to behave toward each client based on their observed patterns.
type Engine struct {
	mu        sync.RWMutex
	behaviors map[string]*ClientBehavior
	collector *metrics.Collector
	fp        *fingerprint.Engine

	// Random blocking configuration
	blockChance    float64       // probability of random block per evaluation (default 0.02)
	blockDuration  time.Duration // how long a block lasts (default 30s)
	blockEnabled   bool          // whether random blocking is active

	// Manual overrides (set via admin panel)
	overrides map[string]BehaviorMode

	// Configurable thresholds
	aggressiveRPSThreshold  float64 // RPS above which bots get aggressive treatment (default 10.0)
	labyrinthPathsThreshold int     // unique paths above which clients get labyrinth mode (default 50)
}

func NewEngine(collector *metrics.Collector, fp *fingerprint.Engine) *Engine {
	return &Engine{
		behaviors:     make(map[string]*ClientBehavior),
		collector:     collector,
		fp:            fp,
		blockChance:             0.02,
		blockDuration:           30 * time.Second,
		blockEnabled:            true,
		overrides:               make(map[string]BehaviorMode),
		aggressiveRPSThreshold:  10.0,
		labyrinthPathsThreshold: 50,
	}
}

// SetBlockChance updates the random block probability (0.0-1.0).
func (e *Engine) SetBlockChance(chance float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if chance < 0 {
		chance = 0
	}
	if chance > 1 {
		chance = 1
	}
	e.blockChance = chance
}

// SetBlockDuration updates how long random blocks last.
func (e *Engine) SetBlockDuration(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockDuration = d
}

// SetBlockEnabled toggles random blocking.
func (e *Engine) SetBlockEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockEnabled = enabled
}

// GetBlockConfig returns the current blocking configuration.
func (e *Engine) GetBlockConfig() (chance float64, duration time.Duration, enabled bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.blockChance, e.blockDuration, e.blockEnabled
}

// SetAggressiveRPSThreshold sets the RPS threshold above which bots get aggressive treatment.
func (e *Engine) SetAggressiveRPSThreshold(rps float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if rps < 1 {
		rps = 1
	}
	if rps > 100 {
		rps = 100
	}
	e.aggressiveRPSThreshold = rps
}

// SetLabyrinthPathsThreshold sets the unique-paths threshold above which clients get labyrinth mode.
func (e *Engine) SetLabyrinthPathsThreshold(paths int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if paths < 1 {
		paths = 1
	}
	if paths > 1000 {
		paths = 1000
	}
	e.labyrinthPathsThreshold = paths
}

// SetOverride forces a specific mode for a client (used by admin panel).
func (e *Engine) SetOverride(clientID string, mode BehaviorMode) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.overrides[clientID] = mode
	// Clear cached behavior so next Decide picks up the override
	delete(e.behaviors, clientID)
}

// ClearOverride removes a manual override for a client.
func (e *Engine) ClearOverride(clientID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.overrides, clientID)
	delete(e.behaviors, clientID)
}

// GetOverrides returns all active manual overrides.
func (e *Engine) GetOverrides() map[string]BehaviorMode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]BehaviorMode, len(e.overrides))
	for k, v := range e.overrides {
		result[k] = v
	}
	return result
}

// Decide returns the behavior for a client, evaluating their profile and updating adaptively.
func (e *Engine) Decide(clientID string, clientClass fingerprint.ClientClass) *ClientBehavior {
	// Phase 1: Read state under RLock
	e.mu.RLock()
	existing, ok := e.behaviors[clientID]

	// Check for active block
	if ok && existing.Mode == ModeBlocked {
		if time.Now().Before(existing.BlockedUntil) {
			e.mu.RUnlock()
			return existing // still blocked
		}
		// Block expired, fall through to re-evaluate
	}

	// Check for manual override from admin panel
	if mode, hasOverride := e.overrides[clientID]; hasOverride {
		e.mu.RUnlock()
		behavior := e.buildOverrideBehavior(mode, clientID)
		e.mu.Lock()
		e.behaviors[clientID] = behavior
		e.mu.Unlock()
		return behavior
	}

	if ok && time.Since(existing.AssignedAt) < 30*time.Second {
		// Re-evaluate every 30 seconds
		e.mu.RUnlock()
		return existing
	}

	// Capture config values needed for evaluation
	blockEnabled := e.blockEnabled
	blockChance := e.blockChance
	blockDuration := e.blockDuration
	aggressiveThreshold := e.aggressiveRPSThreshold
	labThreshold := e.labyrinthPathsThreshold
	e.mu.RUnlock()

	// Phase 2: External calls WITHOUT holding any lock
	profile := e.collector.GetClientProfile(clientID)

	// Phase 3: Evaluate using captured config values (no lock needed)
	behavior := e.evaluateWithConfig(clientID, clientClass, profile, aggressiveThreshold, labThreshold)

	// Random blocking chance (only for non-browser, non-new clients)
	if blockEnabled && profile != nil && profile.TotalRequests > 10 &&
		clientClass != fingerprint.ClassBrowser && rand.Float64() < blockChance {
		behavior = &ClientBehavior{
			Mode:         ModeBlocked,
			ErrorProfile: errors.DefaultProfile(),
			AssignedAt:   time.Now(),
			BlockedUntil: time.Now().Add(blockDuration),
			Reason:       "random block — temporary denial of service",
		}
	}

	// Phase 4: Store result under write lock
	e.mu.Lock()
	e.behaviors[clientID] = behavior
	e.mu.Unlock()

	if profile != nil {
		profile.AdaptiveProfile = string(behavior.Mode)
	}

	return behavior
}

func (e *Engine) evaluateWithConfig(clientID string, class fingerprint.ClientClass, profile *metrics.ClientProfile, aggressiveThreshold float64, labThreshold int) *ClientBehavior {
	// New clients get normal behavior
	if profile == nil || profile.TotalRequests < 5 {
		return &ClientBehavior{
			Mode:            ModeNormal,
			ErrorProfile:    errors.DefaultProfile(),
			LabyrinthChance: 0.05,
			PageVariety:     0.5,
			AssignedAt:      time.Now(),
			Reason:          "new client, insufficient data",
		}
	}

	rps := profile.RequestsPerSec

	// === Classification-based initial decision ===
	switch class {
	case fingerprint.ClassAIScraper:
		return e.aiScraperBehavior(profile)
	case fingerprint.ClassLoadTester:
		return e.loadTesterBehavior(profile, rps)
	case fingerprint.ClassScriptBot:
		return e.scriptBotBehavior(profile, rps, aggressiveThreshold)
	case fingerprint.ClassSearchBot:
		return e.searchBotBehavior(profile)
	case fingerprint.ClassBrowser:
		return e.browserBehavior(profile)
	case fingerprint.ClassAPITester:
		return e.apiTesterBehavior(profile)
	}

	// Unknown clients: analyze behavior patterns
	return e.unknownBehavior(profile, rps, aggressiveThreshold, labThreshold)
}

func (e *Engine) aiScraperBehavior(p *metrics.ClientProfile) *ClientBehavior {
	// AI scrapers get the labyrinth treatment
	labChance := 0.6
	// The deeper they go, the more labyrinth they get
	if p.LabyrinthDepth > 5 {
		labChance = 0.8
	}
	if p.LabyrinthDepth > 20 {
		labChance = 0.95
	}

	return &ClientBehavior{
		Mode:            ModeLabyrinth,
		ErrorProfile:    errors.DefaultProfile(),
		LabyrinthChance: labChance,
		PageVariety:     1.0, // all page types to make scraping harder
		AssignedAt:      time.Now(),
		Reason:          "AI scraper detected, labyrinth mode activated",
	}
}

func (e *Engine) loadTesterBehavior(p *metrics.ClientProfile, rps float64) *ClientBehavior {
	// Load testers get escalating difficulty
	level := int(math.Log2(float64(p.TotalRequests)/100)) + 1
	if level < 1 {
		level = 1
	}
	if level > 10 {
		level = 10
	}

	// Build a profile that gets worse with escalation
	profile := errors.DefaultProfile()
	scale := 1.0 + float64(level)*0.3
	for k, v := range profile.Weights {
		if k != errors.ErrNone {
			profile.Weights[k] = v * scale
		}
	}
	// Reduce "none" proportionally
	totalNonNone := 0.0
	for k, v := range profile.Weights {
		if k != errors.ErrNone {
			totalNonNone += v
		}
	}
	if totalNonNone > 0.95 {
		totalNonNone = 0.95
	}
	profile.Weights[errors.ErrNone] = 1.0 - totalNonNone

	return &ClientBehavior{
		Mode:            ModeEscalating,
		ErrorProfile:    profile,
		LabyrinthChance: 0.01,
		PageVariety:     0.3,
		AssignedAt:      time.Now(),
		Reason:          reasonf("load tester at %.1f req/s, escalation level %d", rps, level),
		EscalationLevel: level,
	}
}

func (e *Engine) scriptBotBehavior(p *metrics.ClientProfile, rps float64, aggressiveThreshold float64) *ClientBehavior {
	if rps > aggressiveThreshold {
		// High-rate script bots get aggressive treatment
		return &ClientBehavior{
			Mode:            ModeAggressive,
			ErrorProfile:    errors.AggressiveProfile(),
			LabyrinthChance: 0.2,
			PageVariety:     0.8,
			AssignedAt:      time.Now(),
			Reason:          reasonf("high-rate script bot at %.1f req/s", rps),
		}
	}

	// Low-rate bots get intermittent failures
	return &ClientBehavior{
		Mode:            ModeIntermittent,
		ErrorProfile:    errors.DefaultProfile(),
		LabyrinthChance: 0.1,
		PageVariety:     0.6,
		AssignedAt:      time.Now(),
		Reason:          "script bot, intermittent mode",
	}
}

func (e *Engine) searchBotBehavior(p *metrics.ClientProfile) *ClientBehavior {
	// Be somewhat cooperative with search bots, but still glitchy
	profile := errors.DefaultProfile()
	// Halve all error rates
	for k, v := range profile.Weights {
		if k != errors.ErrNone {
			profile.Weights[k] = v * 0.5
		}
	}
	profile.Weights[errors.ErrNone] = 0.82

	return &ClientBehavior{
		Mode:            ModeCooperative,
		ErrorProfile:    profile,
		LabyrinthChance: 0.3, // still some labyrinth for search bots
		PageVariety:     0.7,
		AssignedAt:      time.Now(),
		Reason:          "search bot, cooperative but glitchy",
	}
}

func (e *Engine) browserBehavior(p *metrics.ClientProfile) *ClientBehavior {
	return &ClientBehavior{
		Mode:            ModeNormal,
		ErrorProfile:    errors.DefaultProfile(),
		LabyrinthChance: 0.02,
		PageVariety:     0.5,
		AssignedAt:      time.Now(),
		Reason:          "browser user, standard behavior",
	}
}

func (e *Engine) apiTesterBehavior(p *metrics.ClientProfile) *ClientBehavior {
	// Mirror their patterns — if they test specific paths, respond in kind
	return &ClientBehavior{
		Mode:            ModeMirror,
		ErrorProfile:    errors.DefaultProfile(),
		LabyrinthChance: 0.05,
		PageVariety:     1.0, // show all page types so they see the full API surface
		AssignedAt:      time.Now(),
		Reason:          "API tester, mirror mode",
	}
}

func (e *Engine) unknownBehavior(p *metrics.ClientProfile, rps float64, aggressiveThreshold float64, labThreshold int) *ClientBehavior {
	// Heuristic: high request rate + few user agents = bot
	if rps > aggressiveThreshold*2 && len(p.UserAgents) <= 1 {
		return &ClientBehavior{
			Mode:            ModeAggressive,
			ErrorProfile:    errors.AggressiveProfile(),
			LabyrinthChance: 0.3,
			PageVariety:     0.8,
			AssignedAt:      time.Now(),
			Reason:          reasonf("unknown high-rate client (%.1f req/s), aggressive mode", rps),
		}
	}

	// Many unique paths = likely exploration/scanning
	if len(p.PathsVisited) > labThreshold {
		return &ClientBehavior{
			Mode:            ModeLabyrinth,
			ErrorProfile:    errors.DefaultProfile(),
			LabyrinthChance: 0.5,
			PageVariety:     1.0,
			AssignedAt:      time.Now(),
			Reason:          reasonf("scanner detected (%d unique paths), labyrinth mode", len(p.PathsVisited)),
		}
	}

	return &ClientBehavior{
		Mode:            ModeNormal,
		ErrorProfile:    errors.DefaultProfile(),
		LabyrinthChance: 0.05,
		PageVariety:     0.5,
		AssignedAt:      time.Now(),
		Reason:          "unknown client, default behavior",
	}
}

// GetBehavior returns the current behavior for a client (read-only).
func (e *Engine) GetBehavior(clientID string) *ClientBehavior {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.behaviors[clientID]
}

// GetAllBehaviors returns all active behaviors.
func (e *Engine) GetAllBehaviors() map[string]*ClientBehavior {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]*ClientBehavior, len(e.behaviors))
	for k, v := range e.behaviors {
		result[k] = v
	}
	return result
}

func (e *Engine) buildOverrideBehavior(mode BehaviorMode, clientID string) *ClientBehavior {
	b := &ClientBehavior{
		Mode:       mode,
		AssignedAt: time.Now(),
		Reason:     "manual override via admin panel",
	}
	switch mode {
	case ModeBlocked:
		b.ErrorProfile = errors.DefaultProfile()
		b.BlockedUntil = time.Now().Add(24 * time.Hour) // manual blocks last 24h
	case ModeAggressive:
		b.ErrorProfile = errors.AggressiveProfile()
		b.LabyrinthChance = 0.3
		b.PageVariety = 0.8
	case ModeLabyrinth:
		b.ErrorProfile = errors.DefaultProfile()
		b.LabyrinthChance = 0.9
		b.PageVariety = 1.0
	case ModeCooperative:
		profile := errors.DefaultProfile()
		for k, v := range profile.Weights {
			if k != errors.ErrNone {
				profile.Weights[k] = v * 0.3
			}
		}
		profile.Weights[errors.ErrNone] = 0.9
		b.ErrorProfile = profile
		b.LabyrinthChance = 0.0
		b.PageVariety = 0.3
	default:
		b.ErrorProfile = errors.DefaultProfile()
		b.LabyrinthChance = 0.05
		b.PageVariety = 0.5
	}
	return b
}

// IsBlocked returns true if the client is currently blocked.
func (e *Engine) IsBlocked(clientID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, ok := e.behaviors[clientID]
	return ok && b.Mode == ModeBlocked && time.Now().Before(b.BlockedUntil)
}

func reasonf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
