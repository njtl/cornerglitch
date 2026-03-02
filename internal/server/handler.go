package server

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/analytics"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/apichaos"
	"github.com/glitchWebServer/internal/botdetect"
	"github.com/glitchWebServer/internal/captcha"
	"github.com/glitchWebServer/internal/cdn"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/cookies"
	"github.com/glitchWebServer/internal/dashboard"
	"github.com/glitchWebServer/internal/email"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/framework"
	"github.com/glitchWebServer/internal/headers"
	"github.com/glitchWebServer/internal/health"
	"github.com/glitchWebServer/internal/honeypot"
	"github.com/glitchWebServer/internal/i18n"
	"github.com/glitchWebServer/internal/jstrap"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/oauth"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/privacy"
	"github.com/glitchWebServer/internal/recorder"
	"github.com/glitchWebServer/internal/search"
	"github.com/glitchWebServer/internal/spider"
	"github.com/glitchWebServer/internal/vuln"
	"github.com/glitchWebServer/internal/websocket"
)

// ANSI color codes for logging
const (
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	purple = "\033[35m"
	reset  = "\033[0m"
)

// metricsResponseWriter wraps http.ResponseWriter to track bytes written.
// It also implements http.Flusher and http.Hijacker by delegating to the
// underlying writer when those interfaces are supported.
type metricsResponseWriter struct {
	http.ResponseWriter
	bytesWritten int64
	statusCode   int
}

func (m *metricsResponseWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.bytesWritten += int64(n)
	return n, err
}

func (m *metricsResponseWriter) WriteHeader(code int) {
	m.statusCode = code
	m.ResponseWriter.WriteHeader(code)
}

func (m *metricsResponseWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (m *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := m.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// Handler is the main request handler that orchestrates all subsystems.
type Handler struct {
	collector *metrics.Collector
	fp        *fingerprint.Engine
	adapt     *adaptive.Engine
	errGen    *errors.Generator
	pageGen   *pages.Generator
	lab       *labyrinth.Labyrinth
	content   *content.Engine
	apiRouter *api.Router
	honey     *honeypot.Honeypot
	fw        *framework.Emulator
	captcha   *captcha.Engine
	vulnH     *vuln.Handler
	analytix  *analytics.Engine
	cdnEng    *cdn.Engine
	oauthH    *oauth.Handler
	privacyH  *privacy.Handler
	wsH       *websocket.Handler
	rec       *recorder.Recorder
	searchH   *search.Handler
	emailH    *email.Handler
	healthH   *health.Handler
	i18nH     *i18n.Handler
	headerEng *headers.Engine
	cookieT   *cookies.Tracker
	jsEng     *jstrap.Engine
	botDet    *botdetect.Detector
	spiderH            *spider.Handler
	apiChaosEng        *apichaos.Engine
	flags              *dashboard.FeatureFlags
	config             *dashboard.AdminConfig
	apiChaosConfig     *dashboard.APIChaosConfig
	lastConfigVersion  atomic.Int64
}

func NewHandler(
	collector *metrics.Collector,
	fp *fingerprint.Engine,
	adapt *adaptive.Engine,
	errGen *errors.Generator,
	pageGen *pages.Generator,
	lab *labyrinth.Labyrinth,
	contentEng *content.Engine,
	apiRouter *api.Router,
	honey *honeypot.Honeypot,
	fw *framework.Emulator,
	captchaEng *captcha.Engine,
	vulnH *vuln.Handler,
	analytix *analytics.Engine,
	cdnEng *cdn.Engine,
	oauthH *oauth.Handler,
	privacyH *privacy.Handler,
	wsH *websocket.Handler,
	rec *recorder.Recorder,
	searchH *search.Handler,
	emailH *email.Handler,
	healthH *health.Handler,
	i18nH *i18n.Handler,
	headerEng *headers.Engine,
	cookieT *cookies.Tracker,
	jsEng *jstrap.Engine,
	botDet *botdetect.Detector,
	spiderH *spider.Handler,
	apiChaosEng *apichaos.Engine,
) *Handler {
	return &Handler{
		collector:      collector,
		fp:             fp,
		adapt:          adapt,
		errGen:         errGen,
		pageGen:        pageGen,
		lab:            lab,
		content:        contentEng,
		apiRouter:      apiRouter,
		honey:          honey,
		fw:             fw,
		captcha:        captchaEng,
		vulnH:          vulnH,
		analytix:       analytix,
		cdnEng:         cdnEng,
		oauthH:         oauthH,
		privacyH:       privacyH,
		wsH:            wsH,
		rec:            rec,
		searchH:        searchH,
		emailH:         emailH,
		healthH:        healthH,
		i18nH:          i18nH,
		headerEng:      headerEng,
		cookieT:        cookieT,
		jsEng:          jsEng,
		botDet:         botDet,
		spiderH:        spiderH,
		apiChaosEng:    apiChaosEng,
		flags:          dashboard.GetFeatureFlags(),
		config:         dashboard.GetAdminConfig(),
		apiChaosConfig: dashboard.GetAPIChaosConfig(),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.collector.ActiveConns.Add(1)
	defer h.collector.ActiveConns.Add(-1)

	// Wrap the response writer to track bytes written
	mrw := &metricsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Estimate request bytes from Content-Length header (0 if unknown)
	var reqBytes int64
	if r.ContentLength > 0 {
		reqBytes = r.ContentLength
	}

	// Step 0: Apply configured delay (delay_min_ms / delay_max_ms)
	h.applyConfiguredDelay()

	// Step 0.5: Sync admin config to subsystems (lightweight reads)
	h.syncConfigToSubsystems()

	// Step 1: Fingerprint the client
	clientID := h.fp.Identify(r)
	clientClass := h.fp.ClassifyClient(r)

	// Step 1.5: Bot detection — record request and score
	if h.botDet != nil && h.flags.IsBotDetectionEnabled() {
		h.botDet.RecordRequest(clientID, r)
	}

	// Step 2: Apply framework emulation headers/cookies for this client+path
	if h.fw != nil && h.flags.IsFrameworkEmulEnabled() {
		fwProfile := h.fw.ForRequest(clientID, r.URL.Path)
		h.fw.Apply(mrw, fwProfile, clientID)
	}

	// Step 2.5: Apply CDN headers for this client
	if h.cdnEng != nil && h.flags.IsCDNEnabled() {
		h.cdnEng.ApplyHeaders(mrw, r.URL.Path, clientID)
	}

	// Step 2.7: Cookie traps — set tracking cookies
	if h.cookieT != nil && h.flags.IsCookieTrapsEnabled() {
		h.cookieT.SetTraps(mrw, r, clientID)
	}

	// Step 2.8: Header corruption — apply before body is written
	if h.headerEng != nil && h.flags.IsHeaderCorruptEnabled() {
		if h.headerEng.ShouldCorrupt(string(clientClass)) {
			level := h.headerEng.GetLevel()
			h.headerEng.Apply(mrw, r, clientID, level)
		}
	}

	// Step 3: Get adaptive behavior for this client
	behavior := h.adapt.Decide(clientID, clientClass)

	// Step 3.5: Check if client is blocked
	if behavior.Mode == adaptive.ModeBlocked {
		statusCode := 403
		mrw.Header().Set("Content-Type", "text/plain")
		mrw.Header().Set("Retry-After", "30")
		http.Error(mrw, "Access Denied", statusCode)
		latency := time.Since(start)
		h.collector.Record(metrics.RequestRecord{
			Timestamp: start, ClientID: clientID, Method: r.Method,
			Path: r.URL.Path, StatusCode: statusCode, Latency: latency,
			ResponseType: "blocked", UserAgent: r.UserAgent(), RemoteAddr: r.RemoteAddr,
			RequestBytes: reqBytes, ResponseBytes: mrw.bytesWritten,
		})
		log.Printf("%s[blocked]%s %s %s %d %s (client=%s class=%s)",
			red, reset, r.Method, r.URL.Path, statusCode, latency, clientID[:16], clientClass)
		return
	}

	// Step 4: Decide what to do with this request
	statusCode, responseType := h.dispatch(mrw, r, behavior, clientID, string(clientClass))

	// Step 5: Record metrics
	latency := time.Since(start)
	reqHeaders := make(map[string]string)
	for k := range r.Header {
		reqHeaders[k] = r.Header.Get(k)
	}

	h.collector.Record(metrics.RequestRecord{
		Timestamp:     start,
		ClientID:      clientID,
		Method:        r.Method,
		Path:          r.URL.Path,
		StatusCode:    statusCode,
		Latency:       latency,
		ResponseType:  responseType,
		UserAgent:     r.UserAgent(),
		RemoteAddr:    r.RemoteAddr,
		Headers:       reqHeaders,
		RequestBytes:  reqBytes,
		ResponseBytes: mrw.bytesWritten,
	})

	// Step 5.5: Record to traffic capture (if recording)
	if h.rec != nil && h.flags.IsRecorderEnabled() && h.rec.IsRecording() {
		h.rec.RecordFull(r.Method, r.URL.Path, clientID, reqHeaders, nil,
			statusCode, nil, 0, float64(latency.Milliseconds()))
	}

	// Step 6: Log with colors
	color := green
	switch {
	case statusCode >= 500:
		color = red
	case statusCode >= 400:
		color = yellow
	case responseType == "labyrinth":
		color = purple
	case responseType == "delayed":
		color = yellow
	case responseType == "api":
		color = cyan
	case responseType == "honeypot":
		color = red
	case responseType == "captcha":
		color = yellow
	case responseType == "vuln":
		color = red
	case responseType == "i18n":
		color = cyan
	case responseType == "jstrap":
		color = purple
	case responseType == "blocked":
		color = red
	case responseType == "spider":
		color = cyan
	case responseType == "api_chaos":
		color = purple
	}

	log.Printf("%s[%s]%s %s %s %d %s (client=%s class=%s mode=%s)",
		color, responseType, reset,
		r.Method, r.URL.Path, statusCode, latency,
		clientID[:16], clientClass, behavior.Mode)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, behavior *adaptive.ClientBehavior, clientID, clientClass string) (int, string) {
	// WebSocket endpoints (must check early — upgrade needs raw connection)
	if h.wsH != nil && h.flags.IsWebSocketEnabled() && h.wsH.ShouldHandle(r.URL.Path) {
		status := h.wsH.ServeHTTP(w, r)
		return status, "websocket"
	}

	// Health/status/debug endpoints
	if h.healthH != nil && h.flags.IsHealthEnabled() && h.healthH.ShouldHandle(r.URL.Path) {
		status := h.healthH.ServeHTTP(w, r)
		return status, "health"
	}

	// Spider/crawler resource files (robots.txt, sitemap.xml, favicon.ico, etc.)
	if h.spiderH != nil && h.flags.IsSpiderEnabled() && h.spiderH.ShouldHandle(r.URL.Path) {
		status := h.spiderH.ServeHTTP(w, r)
		return status, "spider"
	}

	// JS trap challenge/beacon endpoints
	if h.jsEng != nil && h.flags.IsJSTrapsEnabled() && h.jsEng.ShouldHandle(r.URL.Path) {
		status := h.jsEng.ServeHTTP(w, r)
		return status, "jstrap"
	}

	// API requests bypass error injection and go straight to the API router.
	// Honeypot lure paths under /api/ (like /api/internal/config) get intercepted,
	// but explicit API router endpoints (graphql, swagger, etc.) always go to the router.
	if h.apiRouter != nil && h.apiRouter.ShouldHandle(r.URL.Path) {
		if strings.HasPrefix(r.URL.Path, "/api/") && h.honey != nil && h.flags.IsHoneypotEnabled() && h.honey.ShouldHandle(r.URL.Path) {
			status := h.honey.ServeHTTP(w, r)
			return status, "honeypot"
		}
		// API chaos: inject chaotic responses into API endpoints
		if h.apiChaosEng != nil && h.flags.IsAPIChaosEnabled() && h.apiChaosEng.ShouldApply() {
			h.apiChaosEng.Apply(w, r)
			return 0, "api_chaos"
		}
		status := h.apiRouter.ServeHTTP(w, r)
		return status, "api"
	}

	// OAuth2/SSO/SAML endpoints
	if h.oauthH != nil && h.flags.IsOAuthEnabled() && h.oauthH.ShouldHandle(r.URL.Path) {
		status := h.oauthH.ServeHTTP(w, r)
		return status, "oauth"
	}

	// Privacy/consent endpoints
	if h.privacyH != nil && h.flags.IsPrivacyEnabled() && h.privacyH.ShouldHandle(r.URL.Path) {
		status := h.privacyH.ServeHTTP(w, r)
		return status, "privacy"
	}

	// Analytics beacon/tracking endpoints
	if h.analytix != nil && h.flags.IsAnalyticsEnabled() && h.analytix.ShouldHandle(r.URL.Path) {
		status := h.analytix.ServeHTTP(w, r)
		return status, "analytics"
	}

	// Traffic recorder management endpoints
	if h.rec != nil && h.flags.IsRecorderEnabled() && h.rec.ShouldHandle(r.URL.Path) {
		status := h.rec.ServeHTTP(w, r)
		return status, "recorder"
	}

	// Email/webmail endpoints
	if h.emailH != nil && h.flags.IsEmailEnabled() && h.emailH.ShouldHandle(r.URL.Path) {
		status := h.emailH.ServeHTTP(w, r)
		return status, "email"
	}

	// Search engine endpoints
	if h.searchH != nil && h.flags.IsSearchEnabled() && h.searchH.ShouldHandle(r.URL.Path) {
		status := h.searchH.ServeHTTP(w, r)
		return status, "search"
	}

	// i18n / multi-language endpoints
	if h.i18nH != nil && h.flags.IsI18nEnabled() && h.i18nH.ShouldHandle(r.URL.Path) {
		status := h.i18nH.ServeHTTP(w, r)
		return status, "i18n"
	}

	// Captcha verification endpoint
	if h.captcha != nil && h.flags.IsCaptchaEnabled() && r.URL.Path == "/captcha/verify" && r.Method == "POST" {
		status := h.captcha.HandleVerify(w, r)
		return status, "captcha"
	}

	// CDN static asset serving
	if h.cdnEng != nil && h.flags.IsCDNEnabled() && h.cdnEng.ShouldHandle(r.URL.Path) {
		status := h.cdnEng.ServeHTTP(w, r)
		return status, "cdn"
	}

	// OWASP vulnerability emulation
	if h.vulnH != nil && h.flags.IsVulnEnabled() && h.vulnH.ShouldHandle(r.URL.Path) {
		// Check VulnConfig group/category toggles
		vc := dashboard.GetVulnConfig()
		if h.isVulnDisabled(r.URL.Path, vc) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>404 Not Found</h1><p>The requested page could not be found.</p></body></html>`))
			return 404, "vuln_disabled"
		}
		status := h.vulnH.ServeHTTP(w, r)
		return status, "vuln"
	}

	// Honeypot: catch scanner probes on known vuln paths
	if h.honey != nil && h.flags.IsHoneypotEnabled() && h.honey.ShouldHandle(r.URL.Path) {
		status := h.honey.ServeHTTP(w, r)
		return status, "honeypot"
	}

	// Captcha challenge: intercept requests that should be challenged
	if h.captcha != nil && h.flags.IsCaptchaEnabled() {
		var reqCount int
		if cp := h.collector.GetClientProfile(clientID); cp != nil {
			snap := cp.Snapshot()
			reqCount = int(snap.TotalRequests)
		}
		if h.captcha.ShouldChallenge(r.URL.Path, clientClass, reqCount) {
			ct := h.captcha.SelectChallenge(clientID)
			status := h.captcha.ServeChallenge(w, r, ct)
			return status, "captcha"
		}
	}

	// Check if this should go to the labyrinth
	if h.flags.IsLabyrinthEnabled() && h.shouldLabyrinth(r, behavior) {
		status := h.lab.Serve(w, r)
		return status, "labyrinth"
	}

	// Roll for error injection
	if h.flags.IsErrorInjectEnabled() {
		profile := behavior.ErrorProfile
		// Check for custom error weights from admin config
		customWeights := h.config.GetErrorWeights()
		if len(customWeights) > 0 {
			profile = errors.ErrorProfile{Weights: make(map[errors.ErrorType]float64)}
			for k, v := range customWeights {
				profile.Weights[errors.ErrorType(k)] = v
			}
		}
		// Apply error rate multiplier from admin config
		cfg := h.config.Get()
		if mult, ok := cfg["error_rate_multiplier"].(float64); ok && mult != 1.0 {
			scaled := errors.ErrorProfile{Weights: make(map[errors.ErrorType]float64)}
			var totalNonNone float64
			for k, v := range profile.Weights {
				if k == errors.ErrNone {
					continue
				}
				w := v * mult
				if w > 1 {
					w = 1
				}
				scaled.Weights[k] = w
				totalNonNone += w
			}
			if totalNonNone > 0.99 {
				totalNonNone = 0.99
			}
			scaled.Weights[errors.ErrNone] = 1.0 - totalNonNone
			profile = scaled
		}
		errType := h.errGen.Pick(profile)

		// Check protocol glitch admin config — re-roll if disabled
		if errors.IsProtocolGlitch(errType) {
			pgCfg := h.config.Get()
			pgEnabled, _ := pgCfg["protocol_glitch_enabled"].(bool)
			if !pgEnabled {
				// Protocol glitches disabled: re-roll up to 5 times for a non-protocol type
				for i := 0; i < 5; i++ {
					errType = h.errGen.Pick(profile)
					if !errors.IsProtocolGlitch(errType) {
						break
					}
				}
				if errors.IsProtocolGlitch(errType) {
					errType = errors.ErrNone
				}
			}
		}

		// Apply error — if it fully handled the response, we're done
		if h.errGen.Apply(w, r, errType) {
			statusCode := h.errTypeToStatus(errType)
			return statusCode, string(errType)
		}

		// If it was a delay (but not terminal), we still serve a page
		if errors.IsDelay(errType) {
			return h.servePage(w, r, behavior, clientID), "delayed"
		}
	}

	return h.servePage(w, r, behavior, clientID), "ok"
}

// servePage renders the appropriate page content.
func (h *Handler) servePage(w http.ResponseWriter, r *http.Request, behavior *adaptive.ClientBehavior, clientID string) int {
	// Try content engine first for rich HTML pages
	if h.content != nil && h.content.ShouldHandle(r.URL.Path) {
		accept := r.Header.Get("Accept")
		if accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*") {
			return h.content.Serve(w, r)
		}
	}

	// Serve a page based on the path and behavior settings
	pageType := h.selectPageType(r, behavior)
	h.pageGen.Generate(w, r, pageType)

	return http.StatusOK
}

func (h *Handler) shouldLabyrinth(r *http.Request, behavior *adaptive.ClientBehavior) bool {
	// Always labyrinth if the path is deep enough and looks like crawler exploration
	if h.lab.IsLabyrinthPath(r.URL.Path) {
		return true
	}

	// Random chance based on behavior
	return rand.Float64() < behavior.LabyrinthChance
}

func (h *Handler) selectPageType(r *http.Request, behavior *adaptive.ClientBehavior) pages.PageType {
	// Check Accept header preferences
	accept := r.Header.Get("Accept")
	switch {
	case strings.Contains(accept, "application/json"):
		return pages.PageJSON
	case strings.Contains(accept, "application/xml"):
		return pages.PageXML
	case strings.Contains(accept, "text/event-stream"):
		return pages.PageSSE
	case strings.Contains(accept, "text/csv"):
		return pages.PageCSV
	case strings.Contains(accept, "text/markdown"):
		return pages.PageMarkdown
	}

	// If high page variety, pick randomly (weighted if configured)
	if rand.Float64() < behavior.PageVariety {
		if weights := h.config.GetPageTypeWeights(); len(weights) > 0 {
			return h.pageGen.PickTypeWeighted(weights)
		}
		return h.pageGen.PickType()
	}

	return pages.PageHTML
}

func (h *Handler) errTypeToStatus(errType errors.ErrorType) int {
	switch errType {
	case errors.Err500:
		return 500
	case errors.Err502:
		return 502
	case errors.Err503:
		return 503
	case errors.Err504:
		return 504
	case errors.Err404:
		return 404
	case errors.Err403:
		return 403
	case errors.Err429:
		return 429
	case errors.Err408:
		return 408
	case errors.ErrRedirectLoop:
		return 307
	case errors.ErrPacketDrop, errors.ErrTCPReset, errors.ErrStreamCorrupt,
		errors.ErrSessionTimeout, errors.ErrKeepaliveAbuse, errors.ErrTLSHalfClose,
		errors.ErrSlowHeaders, errors.ErrAcceptThenFIN:
		return 0
	// Protocol glitches — hijacker-based return 0, header-based return 200
	case errors.ErrHTTP10Chunked, errors.ErrHTTP11NoLength, errors.ErrProtocolDowngrade,
		errors.ErrMixedVersions, errors.ErrInfoNoFinal, errors.ErrFalseH2Preface,
		errors.ErrDuplicateStatus, errors.ErrHeaderNullBytes, errors.ErrMissingCRLF,
		errors.ErrHeaderObsFold:
		return 0
	case errors.ErrH2UpgradeReject, errors.ErrH2BadStreamID, errors.ErrH2PriorityLoop,
		errors.ErrFalseServerPush, errors.ErrBothCLAndTE, errors.ErrFalseCompression,
		errors.ErrMultiEncodings, errors.ErrKeepAliveUpgrade:
		return 200
	default:
		return 200
	}
}

// applyConfiguredDelay adds an artificial delay based on delay_min_ms / delay_max_ms config.
func (h *Handler) applyConfiguredDelay() {
	cfg := h.config.Get()
	minMs, _ := cfg["delay_min_ms"].(int)
	maxMs, _ := cfg["delay_max_ms"].(int)
	if maxMs <= 0 {
		return
	}
	if minMs > maxMs {
		minMs = maxMs
	}
	delay := minMs
	if maxMs > minMs {
		delay = minMs + rand.Intn(maxMs-minMs)
	}
	if delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
}

// syncConfigToSubsystems pushes admin config values to subsystems that need them.
// This is called on every request but only performs lightweight reads and
// conditional writes (subsystems ignore no-op updates internally).
func (h *Handler) syncConfigToSubsystems() {
	v := dashboard.GetConfigVersion()
	if v == h.lastConfigVersion.Load() {
		return // config unchanged, skip sync
	}
	h.lastConfigVersion.Store(v)

	cfg := h.config.Get()

	// Sync active framework to framework emulator
	if h.fw != nil {
		if af, ok := cfg["active_framework"].(string); ok {
			if h.fw.GetActiveFramework() != af {
				h.fw.SetActiveFramework(af)
			}
		}
	}

	// Sync adaptive engine thresholds
	if agRPS, ok := cfg["adaptive_aggressive_rps"].(float64); ok {
		h.adapt.SetAggressiveRPSThreshold(agRPS)
	}
	if labPaths, ok := cfg["adaptive_labyrinth_paths"].(int); ok {
		h.adapt.SetLabyrinthPathsThreshold(labPaths)
	}

	// Sync block config
	if bc, ok := cfg["block_chance"].(float64); ok {
		h.adapt.SetBlockChance(bc)
	}
	if bd, ok := cfg["block_duration_sec"].(int); ok {
		h.adapt.SetBlockDuration(time.Duration(bd) * time.Second)
	}

	// Sync JS trap difficulty
	if h.jsEng != nil {
		if diff, ok := cfg["js_trap_difficulty"].(int); ok {
			h.jsEng.SetDifficulty(diff)
		}
	}

	// Sync cookie trap frequency
	if h.cookieT != nil {
		if freq, ok := cfg["cookie_trap_frequency"].(int); ok {
			h.cookieT.SetFrequency(freq)
		}
	}

	// Sync honeypot response style
	if h.honey != nil {
		if style, ok := cfg["honeypot_response_style"].(string); ok {
			h.honey.SetResponseStyle(style)
		}
	}

	// Sync recorder format
	if h.rec != nil {
		if fmtStr, ok := cfg["recorder_format"].(string); ok && fmtStr != "" {
			h.rec.SetFormat(fmtStr)
		}
	}

	// Sync content engine theme and cache TTL
	if h.content != nil {
		if theme, ok := cfg["content_theme"].(string); ok {
			h.content.SetTheme(theme)
		}
		if ttlSec, ok := cfg["content_cache_ttl_sec"].(int); ok && ttlSec > 0 {
			h.content.SetCacheTTL(time.Duration(ttlSec) * time.Second)
		}
	}

	// Sync labyrinth settings
	if h.lab != nil {
		if depth, ok := cfg["max_labyrinth_depth"].(int); ok {
			h.lab.SetMaxDepth(depth)
		}
		if density, ok := cfg["labyrinth_link_density"].(int); ok {
			h.lab.SetLinkDensity(density)
		}
	}

	// Sync header corruption level
	if h.headerEng != nil {
		if level, ok := cfg["header_corrupt_level"].(int); ok {
			h.headerEng.SetCorruptionLevel(level)
		}
	}

	// Sync captcha trigger threshold
	if h.captcha != nil {
		if thresh, ok := cfg["captcha_trigger_thresh"].(int); ok {
			h.captcha.SetTriggerThreshold(thresh)
		}
	}

	// Sync bot detection score threshold
	if h.botDet != nil {
		if thresh, ok := cfg["bot_score_threshold"].(float64); ok {
			h.botDet.SetScoreThreshold(thresh)
		}
	}

	// Sync API chaos engine probability and per-category toggles
	if h.apiChaosEng != nil {
		if prob, ok := cfg["api_chaos_probability"].(float64); ok {
			h.apiChaosEng.SetProbability(prob / 100.0) // config is 0-100, engine wants 0-1
		}
		if h.apiChaosConfig != nil {
			snap := h.apiChaosConfig.Snapshot()
			for cat, enabled := range snap {
				h.apiChaosEng.SetCategoryEnabled(apichaos.ChaosCategory(cat), enabled)
			}
		}
	}
}

// isVulnDisabled checks if a vuln path is disabled via VulnConfig group/category toggles.
func (h *Handler) isVulnDisabled(path string, vc *dashboard.VulnConfig) bool {
	// Determine group and category from path
	if strings.HasPrefix(path, "/vuln/a") {
		// OWASP category (a01-a10)
		if !vc.IsGroupEnabled("owasp") {
			return true
		}
		// Extract category ID like "owasp-a01"
		parts := strings.SplitN(strings.TrimPrefix(path, "/vuln/"), "/", 2)
		if len(parts) > 0 && len(parts[0]) >= 3 {
			catID := "owasp-" + parts[0][:3]
			if !vc.IsCategoryEnabled(catID) {
				return true
			}
		}
	} else if strings.HasPrefix(path, "/vuln/dashboard") || strings.HasPrefix(path, "/vuln/settings") {
		if !vc.IsGroupEnabled("dashboard") {
			return true
		}
	} else if strings.HasPrefix(path, "/vuln/") {
		// Advanced vulns (cors, redirect, xxe, ssti, etc.)
		if !vc.IsGroupEnabled("advanced") {
			return true
		}
	}
	return false
}
