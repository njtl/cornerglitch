package analytics

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// transparentGIF is a minimal 1x1 transparent GIF image (43 bytes).
var transparentGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
	0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
	0x01, 0x00, 0x3b,
}

// Beacon represents a single analytics beacon received by any endpoint.
type Beacon struct {
	Timestamp time.Time
	Endpoint  string
	ClientIP  string
	UserAgent string
	Params    map[string]string
	Body      string
}

// Engine is the analytics and tracking emulation engine.
// It provides JS snippet injection for HTML pages and server-side
// beacon collection endpoints.
type Engine struct {
	mu         sync.RWMutex
	beacons    []Beacon
	beaconIdx  int
	bufferSize int
	events     []eventRecord
	eventIdx   int
	eventSize  int
}

// eventRecord stores a single event from the /events endpoint.
type eventRecord struct {
	Event     string `json:"event"`
	Target    string `json:"target"`
	Page      string `json:"page"`
	Timestamp int64  `json:"timestamp"`
	Received  time.Time
}

// NewEngine creates a new analytics Engine with ring buffers initialized.
func NewEngine() *Engine {
	return &Engine{
		bufferSize: 1000,
		beacons:    make([]Beacon, 1000),
		eventSize:  500,
		events:     make([]eventRecord, 500),
	}
}

// ShouldHandle returns true if the path corresponds to an analytics endpoint.
func (e *Engine) ShouldHandle(path string) bool {
	switch path {
	case "/collect", "/tr", "/events", "/analytics/beacon", "/analytics/config":
		return true
	}
	return false
}

// ServeHTTP handles analytics endpoints and returns the HTTP status code written.
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	switch r.URL.Path {
	case "/collect":
		return e.handleCollect(w, r)
	case "/tr":
		return e.handleTrackingPixel(w, r)
	case "/events":
		return e.handleEvents(w, r)
	case "/analytics/beacon":
		return e.handleBeacon(w, r)
	case "/analytics/config":
		return e.handleConfig(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
		return http.StatusNotFound
	}
}

// Snippet returns a combined <script> block containing emulated analytics
// and tracking code for all major services. The pageURL parameter is embedded
// in the tracking calls so beacons reference the correct page.
func (e *Engine) Snippet(pageURL string) string {
	var sb strings.Builder

	// Escape pageURL for safe embedding in JS strings
	escaped := jsEscape(pageURL)

	sb.WriteString("<!-- Analytics & Tracking -->\n")

	// --- Google Analytics (gtag.js) ---
	sb.WriteString("<script async src=\"https://www.googletagmanager.com/gtag/js?id=G-GL1TCH0001\"></script>\n")
	sb.WriteString("<script>\n")
	sb.WriteString("window.dataLayer = window.dataLayer || [];\n")
	sb.WriteString("function gtag(){dataLayer.push(arguments);}\n")
	sb.WriteString("gtag('js', new Date());\n")
	sb.WriteString("gtag('config', 'G-GL1TCH0001', {\n")
	fmt.Fprintf(&sb, "  page_path: '%s',\n", escaped)
	sb.WriteString("  anonymize_ip: true,\n")
	sb.WriteString("  cookie_flags: 'SameSite=None;Secure'\n")
	sb.WriteString("});\n")
	sb.WriteString("gtag('config', 'UA-000000-1', {\n")
	fmt.Fprintf(&sb, "  page_path: '%s'\n", escaped)
	sb.WriteString("});\n")
	sb.WriteString("gtag('event', 'page_view', {\n")
	fmt.Fprintf(&sb, "  page_location: window.location.href,\n")
	fmt.Fprintf(&sb, "  page_path: '%s',\n", escaped)
	sb.WriteString("  page_title: document.title\n")
	sb.WriteString("});\n")

	// Beacon to /collect
	sb.WriteString("(function(){\n")
	sb.WriteString("  var cid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {\n")
	sb.WriteString("    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);\n")
	sb.WriteString("    return v.toString(16);\n")
	sb.WriteString("  });\n")
	fmt.Fprintf(&sb, "  var img = new Image();\n")
	fmt.Fprintf(&sb, "  img.src = '/collect?v=1&tid=UA-000000-1&cid=' + cid + '&t=pageview&dp=%s&dt=' + encodeURIComponent(document.title) + '&dr=' + encodeURIComponent(document.referrer);\n", escaped)
	sb.WriteString("})();\n")
	sb.WriteString("</script>\n")

	// --- Facebook Pixel ---
	sb.WriteString("<script>\n")
	sb.WriteString("!function(f,b,e,v,n,t,s)\n")
	sb.WriteString("{if(f.fbq)return;n=f.fbq=function(){n.callMethod?\n")
	sb.WriteString("n.callMethod.apply(n,arguments):n.queue.push(arguments)};\n")
	sb.WriteString("if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';\n")
	sb.WriteString("n.queue=[];t=b.createElement(e);t.async=!0;\n")
	sb.WriteString("t.src=v;s=b.getElementsByTagName(e)[0];\n")
	sb.WriteString("s.parentNode.insertBefore(t,s)}(window, document,'script',\n")
	sb.WriteString("'https://connect.facebook.net/en_US/fbevents.js');\n")
	sb.WriteString("fbq('init', '000000000000000');\n")
	sb.WriteString("fbq('track', 'PageView');\n")
	sb.WriteString("</script>\n")
	sb.WriteString("<noscript><img height=\"1\" width=\"1\" style=\"display:none\"\n")
	sb.WriteString("  src=\"/tr?id=000000000000000&ev=PageView&noscript=1\" /></noscript>\n")

	// --- Google Tag Manager ---
	sb.WriteString("<script>\n")
	sb.WriteString("(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':\n")
	sb.WriteString("new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],\n")
	sb.WriteString("j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;\n")
	sb.WriteString("j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;\n")
	sb.WriteString("f.parentNode.insertBefore(j,f);\n")
	sb.WriteString("})(window,document,'script','dataLayer','GTM-GL1TCH');\n")
	sb.WriteString("</script>\n")

	// --- Hotjar ---
	sb.WriteString("<script>\n")
	sb.WriteString("(function(h,o,t,j,a,r){\n")
	sb.WriteString("  h.hj=h.hj||function(){(h.hj.q=h.hj.q||[]).push(arguments)};\n")
	sb.WriteString("  h._hjSettings={hjid:0000000,hjsv:6};\n")
	sb.WriteString("  a=o.getElementsByTagName('head')[0];\n")
	sb.WriteString("  r=o.createElement('script');r.async=1;\n")
	sb.WriteString("  r.src=t+h._hjSettings.hjid+j;\n")
	sb.WriteString("  a.appendChild(r);\n")
	sb.WriteString("})(window,document,'https://static.hotjar.com/c/hotjar-','.js?sv=6');\n")
	fmt.Fprintf(&sb, "hj('stateChange', '%s');\n", escaped)
	sb.WriteString("</script>\n")

	// --- Segment ---
	sb.WriteString("<script>\n")
	sb.WriteString("!function(){var analytics=window.analytics=window.analytics||[];if(!analytics.initialize)\n")
	sb.WriteString("if(analytics.invoked)window.console&&console.error&&console.error('Segment snippet included twice.');\n")
	sb.WriteString("else{analytics.invoked=!0;analytics.methods=['trackSubmit','trackClick','trackLink',\n")
	sb.WriteString("'trackForm','pageview','identify','reset','group','track','ready','alias','debug',\n")
	sb.WriteString("'page','once','off','on','addSourceMiddleware','addIntegrationMiddleware',\n")
	sb.WriteString("'setAnonymousId','addDestinationMiddleware'];\n")
	sb.WriteString("analytics.factory=function(e){return function(){var t=Array.prototype.slice.call(arguments);\n")
	sb.WriteString("t.unshift(e);analytics.push(t);return analytics}};\n")
	sb.WriteString("for(var e=0;e<analytics.methods.length;e++){var key=analytics.methods[e];\n")
	sb.WriteString("analytics[key]=analytics.factory(key)}\n")
	sb.WriteString("analytics.load=function(key,e){var t=document.createElement('script');\n")
	sb.WriteString("t.type='text/javascript';t.async=!0;\n")
	sb.WriteString("t.src='https://cdn.segment.com/analytics.js/v1/'+key+'/analytics.min.js';\n")
	sb.WriteString("var n=document.getElementsByTagName('script')[0];n.parentNode.insertBefore(t,n);\n")
	sb.WriteString("analytics._loadOptions=e};\n")
	sb.WriteString("analytics._writeKey='gl1tch_fake_segment_write_key';\n")
	sb.WriteString("analytics.SNIPPET_VERSION='4.15.3';\n")
	sb.WriteString("analytics.load('gl1tch_fake_segment_write_key');\n")
	fmt.Fprintf(&sb, "analytics.page('%s');\n", escaped)
	sb.WriteString("}}();\n")
	sb.WriteString("</script>\n")

	// --- Custom Event Tracking ---
	sb.WriteString("<script>\n")
	sb.WriteString("(function(){\n")

	// Link click tracking
	sb.WriteString("  document.addEventListener('click', function(e) {\n")
	sb.WriteString("    var target = e.target;\n")
	sb.WriteString("    while (target && target.tagName !== 'A') { target = target.parentElement; }\n")
	sb.WriteString("    if (target && target.href) {\n")
	sb.WriteString("      var data = JSON.stringify({\n")
	sb.WriteString("        event: 'link_click',\n")
	sb.WriteString("        target: target.href,\n")
	fmt.Fprintf(&sb, "        page: '%s',\n", escaped)
	sb.WriteString("        timestamp: Date.now()\n")
	sb.WriteString("      });\n")
	sb.WriteString("      if (navigator.sendBeacon) {\n")
	sb.WriteString("        navigator.sendBeacon('/events', data);\n")
	sb.WriteString("      } else {\n")
	sb.WriteString("        var xhr = new XMLHttpRequest();\n")
	sb.WriteString("        xhr.open('POST', '/events', true);\n")
	sb.WriteString("        xhr.setRequestHeader('Content-Type', 'application/json');\n")
	sb.WriteString("        xhr.send(data);\n")
	sb.WriteString("      }\n")
	sb.WriteString("    }\n")
	sb.WriteString("  }, true);\n")

	// Scroll depth tracking
	sb.WriteString("  var scrollMarks = {25: false, 50: false, 75: false, 100: false};\n")
	sb.WriteString("  window.addEventListener('scroll', function() {\n")
	sb.WriteString("    var scrollTop = window.pageYOffset || document.documentElement.scrollTop;\n")
	sb.WriteString("    var docHeight = Math.max(\n")
	sb.WriteString("      document.body.scrollHeight, document.documentElement.scrollHeight,\n")
	sb.WriteString("      document.body.offsetHeight, document.documentElement.offsetHeight\n")
	sb.WriteString("    ) - window.innerHeight;\n")
	sb.WriteString("    if (docHeight <= 0) return;\n")
	sb.WriteString("    var pct = Math.round((scrollTop / docHeight) * 100);\n")
	sb.WriteString("    [25, 50, 75, 100].forEach(function(mark) {\n")
	sb.WriteString("      if (pct >= mark && !scrollMarks[mark]) {\n")
	sb.WriteString("        scrollMarks[mark] = true;\n")
	sb.WriteString("        var data = JSON.stringify({\n")
	sb.WriteString("          event: 'scroll_depth',\n")
	sb.WriteString("          target: mark + '%',\n")
	fmt.Fprintf(&sb, "          page: '%s',\n", escaped)
	sb.WriteString("          timestamp: Date.now()\n")
	sb.WriteString("        });\n")
	sb.WriteString("        if (navigator.sendBeacon) {\n")
	sb.WriteString("          navigator.sendBeacon('/events', data);\n")
	sb.WriteString("        }\n")
	sb.WriteString("      }\n")
	sb.WriteString("    });\n")
	sb.WriteString("  });\n")

	// Time on page beacon
	sb.WriteString("  var pageStart = Date.now();\n")
	sb.WriteString("  window.addEventListener('beforeunload', function() {\n")
	sb.WriteString("    var duration = Math.round((Date.now() - pageStart) / 1000);\n")
	sb.WriteString("    var data = JSON.stringify({\n")
	sb.WriteString("      event: 'time_on_page',\n")
	sb.WriteString("      target: duration + 's',\n")
	fmt.Fprintf(&sb, "      page: '%s',\n", escaped)
	sb.WriteString("      timestamp: Date.now()\n")
	sb.WriteString("    });\n")
	sb.WriteString("    if (navigator.sendBeacon) {\n")
	sb.WriteString("      navigator.sendBeacon('/events', data);\n")
	sb.WriteString("    }\n")
	sb.WriteString("  });\n")

	sb.WriteString("})();\n")
	sb.WriteString("</script>\n")

	return sb.String()
}

// GetRecentBeacons returns the last n beacons from the ring buffer,
// ordered from most recent to oldest.
func (e *Engine) GetRecentBeacons(n int) []Beacon {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if n > e.bufferSize {
		n = e.bufferSize
	}

	result := make([]Beacon, 0, n)
	idx := (e.beaconIdx - 1 + e.bufferSize) % e.bufferSize
	for i := 0; i < n; i++ {
		b := e.beacons[idx]
		if b.Timestamp.IsZero() {
			break
		}
		result = append(result, b)
		idx = (idx - 1 + e.bufferSize) % e.bufferSize
	}
	return result
}

// recordBeacon stores a beacon in the ring buffer.
func (e *Engine) recordBeacon(b Beacon) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.beacons[e.beaconIdx] = b
	e.beaconIdx = (e.beaconIdx + 1) % e.bufferSize
}

// recordEvent stores an event in the event ring buffer.
func (e *Engine) recordEvent(ev eventRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events[e.eventIdx] = ev
	e.eventIdx = (e.eventIdx + 1) % e.eventSize
}

// getRecentEvents returns the last n events, most recent first.
func (e *Engine) getRecentEvents(n int) []eventRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if n > e.eventSize {
		n = e.eventSize
	}

	result := make([]eventRecord, 0, n)
	idx := (e.eventIdx - 1 + e.eventSize) % e.eventSize
	for i := 0; i < n; i++ {
		ev := e.events[idx]
		if ev.Received.IsZero() {
			break
		}
		result = append(result, ev)
		idx = (idx - 1 + e.eventSize) % e.eventSize
	}
	return result
}

// handleCollect emulates a Google Analytics measurement protocol collector.
// It accepts GET and POST requests, records query parameters as a beacon,
// and returns a 1x1 transparent GIF.
func (e *Engine) handleCollect(w http.ResponseWriter, r *http.Request) int {
	params := make(map[string]string)
	for _, key := range []string{"v", "tid", "cid", "t", "dp", "dt", "dr"} {
		if val := r.URL.Query().Get(key); val != "" {
			params[key] = val
		}
	}

	// Also capture any additional query params
	for k, v := range r.URL.Query() {
		if _, exists := params[k]; !exists && len(v) > 0 {
			params[k] = v[0]
		}
	}

	var body string
	if r.Method == http.MethodPost && r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err == nil {
			body = string(bodyBytes)
		}
	}

	e.recordBeacon(Beacon{
		Timestamp: time.Now(),
		Endpoint:  "/collect",
		ClientIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Params:    params,
		Body:      body,
	})

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(transparentGIF)
	return http.StatusOK
}

// handleTrackingPixel serves a 1x1 transparent GIF and records all query params.
func (e *Engine) handleTrackingPixel(w http.ResponseWriter, r *http.Request) int {
	params := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	e.recordBeacon(Beacon{
		Timestamp: time.Now(),
		Endpoint:  "/tr",
		ClientIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Params:    params,
	})

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(transparentGIF)
	return http.StatusOK
}

// handleEvents serves the event ingestion API.
// POST: accepts JSON event data and returns acknowledgment.
// GET: returns recent events as JSON.
func (e *Engine) handleEvents(w http.ResponseWriter, r *http.Request) int {
	if r.Method == http.MethodGet {
		return e.serveRecentEvents(w)
	}

	// POST: ingest event
	if r.Body == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","message":"empty body"}`))
		return http.StatusBadRequest
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 16384))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","message":"failed to read body"}`))
		return http.StatusBadRequest
	}

	bodyStr := string(bodyBytes)

	// Try to parse as structured event
	var ev eventRecord
	if json.Unmarshal(bodyBytes, &ev) == nil {
		ev.Received = time.Now()
		e.recordEvent(ev)
	}

	// Also record as a general beacon
	params := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	e.recordBeacon(Beacon{
		Timestamp: time.Now(),
		Endpoint:  "/events",
		ClientIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Params:    params,
		Body:      bodyStr,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","message":"event recorded"}`))
	return http.StatusOK
}

// serveRecentEvents returns the last 100 events as JSON.
func (e *Engine) serveRecentEvents(w http.ResponseWriter) int {
	events := e.getRecentEvents(100)

	type eventResponse struct {
		Event     string `json:"event"`
		Target    string `json:"target"`
		Page      string `json:"page"`
		Timestamp int64  `json:"timestamp"`
		Received  string `json:"received"`
	}

	out := make([]eventResponse, len(events))
	for i, ev := range events {
		out[i] = eventResponse{
			Event:     ev.Event,
			Target:    ev.Target,
			Page:      ev.Page,
			Timestamp: ev.Timestamp,
			Received:  ev.Received.Format(time.RFC3339),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": out,
		"count":  len(out),
	})
	return http.StatusOK
}

// handleBeacon is a generic beacon endpoint that accepts POST JSON or form data
// and returns 204 No Content.
func (e *Engine) handleBeacon(w http.ResponseWriter, r *http.Request) int {
	params := make(map[string]string)

	// Collect query params
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	var body string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 16384))
		if err == nil {
			body = string(bodyBytes)
		}

		// Try to parse form data into params
		ct := r.Header.Get("Content-Type")
		if strings.Contains(ct, "application/x-www-form-urlencoded") {
			if err := r.ParseForm(); err == nil {
				for k, v := range r.PostForm {
					if len(v) > 0 {
						params["form_"+k] = v[0]
					}
				}
			}
		}
	}

	e.recordBeacon(Beacon{
		Timestamp: time.Now(),
		Endpoint:  "/analytics/beacon",
		ClientIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Params:    params,
		Body:      body,
	})

	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

// handleConfig returns a fake analytics configuration JSON document
// with all tracking IDs, configured events, and goals.
func (e *Engine) handleConfig(w http.ResponseWriter, r *http.Request) int {
	config := map[string]interface{}{
		"version": "1.0.0",
		"tracking_ids": map[string]string{
			"google_analytics_4": "G-GL1TCH0001",
			"google_analytics":   "UA-000000-1",
			"google_tag_manager": "GTM-GL1TCH",
			"facebook_pixel":     "000000000000000",
			"hotjar":             "0000000",
			"segment_write_key":  "gl1tch_fake_segment_write_key",
		},
		"endpoints": map[string]string{
			"collect": "/collect",
			"pixel":   "/tr",
			"events":  "/events",
			"beacon":  "/analytics/beacon",
			"config":  "/analytics/config",
		},
		"configured_events": []map[string]interface{}{
			{"name": "page_view", "auto": true, "platforms": []string{"ga4", "fbq", "segment"}},
			{"name": "link_click", "auto": true, "platforms": []string{"custom"}},
			{"name": "scroll_depth", "auto": true, "thresholds": []int{25, 50, 75, 100}},
			{"name": "time_on_page", "auto": true, "trigger": "beforeunload"},
			{"name": "form_submit", "auto": false, "platforms": []string{"ga4", "fbq"}},
			{"name": "video_play", "auto": false, "platforms": []string{"ga4"}},
			{"name": "file_download", "auto": false, "platforms": []string{"ga4"}},
			{"name": "outbound_click", "auto": false, "platforms": []string{"ga4"}},
		},
		"goals": []map[string]interface{}{
			{"id": 1, "name": "Sign Up", "type": "event", "event": "form_submit", "target": "#signup-form"},
			{"id": 2, "name": "Purchase", "type": "event", "event": "purchase", "value_field": "revenue"},
			{"id": 3, "name": "Engagement", "type": "scroll_depth", "threshold": 75},
			{"id": 4, "name": "Time Engaged", "type": "time_on_page", "min_seconds": 30},
		},
		"consent": map[string]interface{}{
			"required":        false,
			"default_granted":  true,
			"cookie_name":      "_glitch_consent",
			"cookie_max_age":   31536000,
			"categories":       []string{"analytics", "marketing", "functional"},
		},
		"sampling": map[string]interface{}{
			"rate":       1.0,
			"session_id": "_glitch_sid",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(config)
	return http.StatusOK
}

// jsEscape escapes a string for safe inclusion inside a JavaScript
// single-quoted string literal.
func jsEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "<", "\\x3c")
	s = strings.ReplaceAll(s, ">", "\\x3e")
	return s
}
