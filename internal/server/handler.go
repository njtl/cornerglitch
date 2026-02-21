package server

import (
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/glitchWebServer/internal/adaptive"
	"github.com/glitchWebServer/internal/analytics"
	"github.com/glitchWebServer/internal/api"
	"github.com/glitchWebServer/internal/captcha"
	"github.com/glitchWebServer/internal/content"
	"github.com/glitchWebServer/internal/errors"
	"github.com/glitchWebServer/internal/fingerprint"
	"github.com/glitchWebServer/internal/framework"
	"github.com/glitchWebServer/internal/honeypot"
	"github.com/glitchWebServer/internal/labyrinth"
	"github.com/glitchWebServer/internal/metrics"
	"github.com/glitchWebServer/internal/pages"
	"github.com/glitchWebServer/internal/vuln"
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
) *Handler {
	return &Handler{
		collector: collector,
		fp:        fp,
		adapt:     adapt,
		errGen:    errGen,
		pageGen:   pageGen,
		lab:       lab,
		content:   contentEng,
		apiRouter: apiRouter,
		honey:     honey,
		fw:        fw,
		captcha:   captchaEng,
		vulnH:     vulnH,
		analytix:  analytix,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h.collector.ActiveConns.Add(1)
	defer h.collector.ActiveConns.Add(-1)

	// Step 1: Fingerprint the client
	clientID := h.fp.Identify(r)
	clientClass := h.fp.ClassifyClient(r)

	// Step 2: Apply framework emulation headers/cookies for this client
	if h.fw != nil {
		fwProfile := h.fw.ForClient(clientID)
		h.fw.Apply(w, fwProfile, clientID)
	}

	// Step 3: Get adaptive behavior for this client
	behavior := h.adapt.Decide(clientID, clientClass)

	// Step 4: Decide what to do with this request
	statusCode, responseType := h.dispatch(w, r, behavior, clientID, string(clientClass))

	// Step 5: Record metrics
	latency := time.Since(start)
	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	h.collector.Record(metrics.RequestRecord{
		Timestamp:    start,
		ClientID:     clientID,
		Method:       r.Method,
		Path:         r.URL.Path,
		StatusCode:   statusCode,
		Latency:      latency,
		ResponseType: responseType,
		UserAgent:    r.UserAgent(),
		RemoteAddr:   r.RemoteAddr,
		Headers:      headers,
	})

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
	}

	log.Printf("%s[%s]%s %s %s %d %s (client=%s class=%s mode=%s)",
		color, responseType, reset,
		r.Method, r.URL.Path, statusCode, latency,
		clientID[:16], clientClass, behavior.Mode)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request, behavior *adaptive.ClientBehavior, clientID, clientClass string) (int, string) {
	// API requests bypass error injection and go straight to the API router
	if h.apiRouter != nil && h.apiRouter.ShouldHandle(r.URL.Path) {
		status := h.apiRouter.ServeHTTP(w, r)
		return status, "api"
	}

	// Analytics beacon/tracking endpoints
	if h.analytix != nil && h.analytix.ShouldHandle(r.URL.Path) {
		status := h.analytix.ServeHTTP(w, r)
		return status, "analytics"
	}

	// Captcha verification endpoint
	if h.captcha != nil && r.URL.Path == "/captcha/verify" && r.Method == "POST" {
		status := h.captcha.HandleVerify(w, r)
		return status, "captcha"
	}

	// OWASP vulnerability emulation
	if h.vulnH != nil && h.vulnH.ShouldHandle(r.URL.Path) {
		status := h.vulnH.ServeHTTP(w, r)
		return status, "vuln"
	}

	// Honeypot: catch scanner probes on known vuln paths
	if h.honey != nil && h.honey.ShouldHandle(r.URL.Path) {
		status := h.honey.ServeHTTP(w, r)
		return status, "honeypot"
	}

	// Captcha challenge: intercept requests that should be challenged
	if h.captcha != nil {
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
	if h.shouldLabyrinth(r, behavior) {
		status := h.lab.Serve(w, r)
		return status, "labyrinth"
	}

	// Roll for error injection
	errType := h.errGen.Pick(behavior.ErrorProfile)

	// Apply error — if it fully handled the response, we're done
	if h.errGen.Apply(w, r, errType) {
		statusCode := h.errTypeToStatus(errType)
		if errors.IsError(errType) {
			return statusCode, string(errType)
		}
		return statusCode, string(errType)
	}

	// If it was a delay (but not terminal), we still serve a page
	responseType := "ok"
	if errors.IsDelay(errType) {
		responseType = "delayed"
	}

	// Try content engine first for rich HTML pages
	if h.content != nil && h.content.ShouldHandle(r.URL.Path) {
		accept := r.Header.Get("Accept")
		if accept == "" || contains(accept, "text/html") || contains(accept, "*/*") {
			status := h.content.Serve(w, r)
			return status, responseType
		}
	}

	// Serve a page based on the path and behavior settings
	pageType := h.selectPageType(r, behavior)
	h.pageGen.Generate(w, r, pageType)

	return http.StatusOK, responseType
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
	case contains(accept, "application/json"):
		return pages.PageJSON
	case contains(accept, "application/xml"):
		return pages.PageXML
	case contains(accept, "text/event-stream"):
		return pages.PageSSE
	case contains(accept, "text/csv"):
		return pages.PageCSV
	case contains(accept, "text/markdown"):
		return pages.PageMarkdown
	}

	// If high page variety, pick randomly
	if rand.Float64() < behavior.PageVariety {
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
	default:
		return 200
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
