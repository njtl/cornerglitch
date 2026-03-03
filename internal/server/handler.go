package server

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
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
	"github.com/glitchWebServer/internal/media"
	"github.com/glitchWebServer/internal/mediachaos"
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
	apiChaosEng          *apichaos.Engine
	mediaGen             *media.Generator
	mediaChaosEng        *mediachaos.Engine
	flags                *dashboard.FeatureFlags
	config               *dashboard.AdminConfig
	apiChaosConfig       *dashboard.APIChaosConfig
	mediaChaosConfig     *dashboard.MediaChaosConfig
	lastConfigVersion    atomic.Int64
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
	mediaGen *media.Generator,
	mediaChaosEng *mediachaos.Engine,
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
		apiChaosEng:      apiChaosEng,
		mediaGen:         mediaGen,
		mediaChaosEng:    mediaChaosEng,
		flags:            dashboard.GetFeatureFlags(),
		config:           dashboard.GetAdminConfig(),
		apiChaosConfig:   dashboard.GetAPIChaosConfig(),
		mediaChaosConfig: dashboard.GetMediaChaosConfig(),
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

	// Media content serving (with optional chaos)
	// Serves on /media/*, /assets/media/*, /uploads/*, /content/media/*, /stream/*
	if h.mediaGen != nil && h.flags.IsMediaChaosEnabled() && h.isMediaPath(r.URL.Path) {
		return h.serveMedia(w, r)
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

	// Sync media chaos engine probability, intensity, and per-category toggles
	if h.mediaChaosEng != nil {
		if prob, ok := cfg["media_chaos_probability"].(float64); ok {
			h.mediaChaosEng.SetProbability(prob / 100.0)
		}
		if intensity, ok := cfg["media_chaos_corruption_intensity"].(float64); ok {
			h.mediaChaosEng.SetCorruptionIntensity(intensity / 100.0)
		}
		if v, ok := cfg["media_chaos_slow_min_ms"].(int); ok {
			h.mediaChaosEng.SetSlowMinMs(v)
		}
		if v, ok := cfg["media_chaos_slow_max_ms"].(int); ok {
			h.mediaChaosEng.SetSlowMaxMs(v)
		}
		if v, ok := cfg["media_chaos_infinite_max_bytes"].(int64); ok {
			h.mediaChaosEng.SetInfiniteMaxBytes(v)
		}
		if h.mediaChaosConfig != nil {
			snap := h.mediaChaosConfig.Snapshot()
			for cat, enabled := range snap {
				h.mediaChaosEng.SetCategoryEnabled(mediachaos.ChaosCategory(cat), enabled)
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

// isMediaPath checks if the URL path should be handled by the media subsystem.
func (h *Handler) isMediaPath(path string) bool {
	// Direct media paths
	if strings.HasPrefix(path, "/media/") {
		return true
	}
	// Upload/content paths with media extensions
	if strings.HasPrefix(path, "/uploads/") || strings.HasPrefix(path, "/content/media/") ||
		strings.HasPrefix(path, "/assets/media/") || strings.HasPrefix(path, "/stream/") ||
		strings.HasPrefix(path, "/live/") {
		return true
	}
	// Any path with a known media extension
	format := media.FormatFromPath(path)
	if format != "" {
		// Only match if it's under a media-like prefix or has explicit media query
		if strings.Contains(path, "/img/") || strings.Contains(path, "/images/") ||
			strings.Contains(path, "/video/") || strings.Contains(path, "/audio/") ||
			strings.Contains(path, "/files/") || strings.Contains(path, "/download/") {
			return true
		}
	}
	return false
}

// serveMedia generates media content and optionally applies chaos.
// Supports: direct serving, streaming (infinite), range requests, CDN headers,
// and content negotiation via Accept header.
func (h *Handler) serveMedia(w http.ResponseWriter, r *http.Request) (int, string) {
	path := r.URL.Path

	// Determine format from path extension
	format := media.FormatFromPath(path)
	if format == "" {
		// Check for directory-style media paths (e.g., /media/stream/video)
		format = h.inferMediaFormat(path, r)
		if format == "" {
			http.Error(w, "Unknown media format", http.StatusNotFound)
			return 404, "media"
		}
	}

	// Check for streaming request (infinite content / live streams)
	isStream := strings.Contains(path, "/stream/") || strings.Contains(path, "/live/") ||
		r.URL.Query().Get("stream") == "true"

	// Apply CDN headers if CDN emulation is enabled
	if h.cdnEng != nil && h.flags.IsCDNEnabled() {
		clientID := r.Header.Get("X-Client-ID")
		if clientID == "" {
			clientID = r.RemoteAddr
		}
		h.cdnEng.ApplyHeaders(w, path, clientID)
	}

	// Streaming path: use InfiniteReader for unbounded content delivery
	if isStream && (format == media.FormatWAV || format == media.FormatMP3 ||
		format == media.FormatOGG || format == media.FormatFLAC ||
		format == media.FormatMP4 || format == media.FormatWebM ||
		format == media.FormatAVI || format == media.FormatTS ||
		format == media.FormatPNG || format == media.FormatGIF ||
		format == media.FormatHLS || format == media.FormatDASH) {
		return h.serveMediaStream(w, r, format, path)
	}

	// Generate deterministic media content
	data, contentType := h.mediaGen.Generate(format, path)
	if data == nil {
		http.Error(w, "Failed to generate media", http.StatusInternalServerError)
		return 500, "media"
	}

	// Apply media chaos if engine is available and probability triggers
	if h.mediaChaosEng != nil && h.mediaChaosEng.ShouldApply() {
		h.mediaChaosEng.Apply(w, r, data, contentType)
		return 200, "media_chaos"
	}

	// Handle Range requests for non-streaming content
	if rangeHdr := r.Header.Get("Range"); rangeHdr != "" {
		return h.serveMediaRange(w, r, data, contentType, rangeHdr)
	}

	// Serve clean media with proper headers
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Accept-Ranges", "bytes")
	// Deterministic ETag from path
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(path)))[:18] + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Conditional request support
	if match := r.Header.Get("If-None-Match"); match != "" {
		if match == etag || match == "*" {
			w.WriteHeader(http.StatusNotModified)
			return 304, "media"
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write(data)
	return 200, "media"
}

// serveMediaStream serves unbounded streaming content using InfiniteReader.
func (h *Handler) serveMediaStream(w http.ResponseWriter, r *http.Request, format media.Format, path string) (int, string) {
	// Determine max bytes: query param, or default based on config
	maxBytes := int64(10 * 1024 * 1024) // 10MB default
	if mb := r.URL.Query().Get("max_bytes"); mb != "" {
		if v, err := strconv.ParseInt(mb, 10, 64); err == nil && v > 0 {
			maxBytes = v
		}
	}
	// Cap at configured infinite_max_bytes from media chaos snapshot
	if h.mediaChaosEng != nil {
		snap := h.mediaChaosEng.Snapshot()
		if v, ok := snap["infiniteMaxBytes"].(int64); ok && v > 0 && maxBytes > v {
			maxBytes = v
		} else if v, ok := snap["infiniteMaxBytes"].(float64); ok && int64(v) > 0 && maxBytes > int64(v) {
			maxBytes = int64(v)
		}
	}

	reader := h.mediaGen.GenerateStream(format, path, maxBytes)
	contentType := format.ContentType()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("X-Content-Stream", "true")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)

	flusher, hasFlusher := w.(http.Flusher)
	buf := make([]byte, 8192)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if hasFlusher {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	return 200, "media_stream"
}

// serveMediaRange handles HTTP Range requests for media content.
func (h *Handler) serveMediaRange(w http.ResponseWriter, r *http.Request, data []byte, contentType, rangeHdr string) (int, string) {
	total := len(data)
	// Parse "bytes=start-end" format
	if !strings.HasPrefix(rangeHdr, "bytes=") {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return 200, "media"
	}
	spec := strings.TrimPrefix(rangeHdr, "bytes=")
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return 416, "media"
	}

	var start, end int
	if parts[0] == "" {
		// Suffix range: bytes=-N
		suffix, err := strconv.Atoi(parts[1])
		if err != nil || suffix <= 0 {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return 416, "media"
		}
		start = total - suffix
		if start < 0 {
			start = 0
		}
		end = total - 1
	} else {
		var err error
		start, err = strconv.Atoi(parts[0])
		if err != nil || start < 0 || start >= total {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return 416, "media"
		}
		if parts[1] == "" {
			end = total - 1
		} else {
			end, err = strconv.Atoi(parts[1])
			if err != nil || end < start {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return 416, "media"
			}
			if end >= total {
				end = total - 1
			}
		}
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)
	w.Write(data[start : end+1])
	return 206, "media"
}

// inferMediaFormat infers media format from path structure and Accept header
// when no file extension is present.
func (h *Handler) inferMediaFormat(path string, r *http.Request) media.Format {
	lower := strings.ToLower(path)
	// Path-based inference for common patterns
	switch {
	case strings.Contains(lower, "/video/") || strings.Contains(lower, "/stream/video"):
		return media.FormatMP4
	case strings.Contains(lower, "/audio/") || strings.Contains(lower, "/stream/audio"):
		return media.FormatMP3
	case strings.Contains(lower, "/image/") || strings.Contains(lower, "/photo/"):
		return media.FormatJPEG
	case strings.Contains(lower, "/live/") || strings.Contains(lower, "/hls/"):
		return media.FormatHLS
	case strings.Contains(lower, "/dash/"):
		return media.FormatDASH
	case strings.Contains(lower, "/icon/") || strings.Contains(lower, "/favicon"):
		return media.FormatICO
	}

	// Accept header-based inference
	accept := r.Header.Get("Accept")
	switch {
	case strings.Contains(accept, "video/"):
		return media.FormatMP4
	case strings.Contains(accept, "audio/"):
		return media.FormatMP3
	case strings.Contains(accept, "image/webp"):
		return media.FormatWebP
	case strings.Contains(accept, "image/"):
		return media.FormatJPEG
	}
	return ""
}
