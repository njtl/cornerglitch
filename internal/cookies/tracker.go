package cookies

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CookieAnalysis holds the results of analyzing a client's cookie behavior.
type CookieAnalysis struct {
	HasSessionCookie  bool     // Did they send back the session cookie?
	HasTrapCookie     bool     // Did they send back a cookie they shouldn't have? (expired immediately)
	HasFingerprint    bool     // Did they send back the fingerprint cookie?
	CookieConsistency float64  // 0-1 how well their cookies match expectations
	BotScore          float64  // 0-1 likelihood of being a bot based on cookie behavior
	MissingExpected   []string // Names of cookies they should have but don't
	UnexpectedPresent []string // Names of cookies they shouldn't have but do
}

// clientState tracks what cookies have been set for a given client so
// we know what to expect on subsequent requests.
type clientState struct {
	firstSeen   time.Time
	cookiesSet  bool // true once SetTraps has been called at least once
	sessionVal  string
	fpVal       string
	trapVal     string
	domainVal   string
	secureVal   string
	samesiteVal string
}

// Tracker sets tracking cookies and uses cookie behavior to detect bots.
// Real browsers handle cookies correctly; scrapers often do not.
type Tracker struct {
	mu        sync.RWMutex
	clients   map[string]*clientState
	frequency int // how many of the 6 cookie types to set (0-6)
}

// NewTracker creates a new cookie Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		clients:   make(map[string]*clientState),
		frequency: 6, // default: all 6 cookie types
	}
}

// SetFrequency sets how many of the 6 cookie types to include in SetTraps.
// 0 = none, 1 = session only, 2 = session + fingerprint,
// 3 = + trap, 4 = + domain mismatch, 5 = + secure-on-HTTP, 6 = all.
func (t *Tracker) SetFrequency(freq int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if freq < 0 {
		freq = 0
	}
	if freq > 6 {
		freq = 6
	}
	t.frequency = freq
}

// GetFrequency returns the current cookie trap frequency setting.
func (t *Tracker) GetFrequency() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.frequency
}

// cookieNames used throughout the tracker.
const (
	cookieSession  = "_glitch_sid"
	cookieFP       = "_glitch_fp"
	cookieTrap     = "_glitch_trap"
	cookieDomain   = "_glitch_xd"
	cookieSecure   = "_glitch_sec"
	cookieSameSite = "_glitch_ss"
)

// maxCookieHeaderLen is the threshold above which a Cookie header is
// considered suspiciously large (cookie bomb detection).
const maxCookieHeaderLen = 8192

// deterministicValue derives a stable, unique value from a clientID and a
// purpose string using SHA-256.
func deterministicValue(clientID, purpose string) string {
	h := sha256.Sum256([]byte(clientID + ":" + purpose))
	return hex.EncodeToString(h[:])
}

// getOrCreateState returns the client state, creating it if necessary.
func (t *Tracker) getOrCreateState(clientID string) *clientState {
	t.mu.Lock()
	defer t.mu.Unlock()

	cs, ok := t.clients[clientID]
	if !ok {
		cs = &clientState{
			firstSeen: time.Now(),
		}
		t.clients[clientID] = cs
	}
	return cs
}

// getState returns the client state without creating it. Returns nil if unknown.
func (t *Tracker) getState(clientID string) *clientState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.clients[clientID]
}

// SetTraps sets various tracking and trap cookies on the response.
// It must be called before writing the response body.
// The number of cookies set is controlled by the frequency setting (0-6).
func (t *Tracker) SetTraps(w http.ResponseWriter, r *http.Request, clientID string) {
	t.mu.RLock()
	freq := t.frequency
	t.mu.RUnlock()

	// freq 0: don't set any cookies
	if freq <= 0 {
		return
	}

	cs := t.getOrCreateState(clientID)

	sessionVal := deterministicValue(clientID, "session")
	fpVal := deterministicValue(clientID, "fingerprint")
	trapVal := deterministicValue(clientID, "trap")
	domainVal := deterministicValue(clientID, "domain")
	secureVal := deterministicValue(clientID, "secure")
	samesiteVal := deterministicValue(clientID, "samesite")

	// 1. Session tracking cookie: normal HttpOnly cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     cookieSession,
		Value:    sessionVal,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   86400, // 24 hours
		SameSite: http.SameSiteLaxMode,
	})

	// 2. Fingerprint cookie: verifies cookie jar works.
	if freq >= 2 {
		http.SetCookie(w, &http.Cookie{
			Name:   cookieFP,
			Value:  fpVal,
			Path:   "/",
			MaxAge: 86400,
		})
	}

	// 3. Honeypot cookie: Max-Age=0 tells the browser to delete it immediately,
	//    but Expires is set far in the future. Compliant browsers honour Max-Age
	//    over Expires and discard the cookie. Naive scrapers that only look at
	//    Expires (or accept everything) will send it back.
	if freq >= 3 {
		http.SetCookie(w, &http.Cookie{
			Name:    cookieTrap,
			Value:   trapVal,
			Path:    "/",
			MaxAge:  0,                                   // delete immediately
			Expires: time.Now().Add(365 * 24 * time.Hour), // far-future (ignored by spec-compliant clients)
		})
	}

	// 4. Domain mismatch cookie: browsers reject cookies whose Domain attribute
	//    does not match the current host. Scrapers that blindly store all
	//    Set-Cookie values will send it back.
	if freq >= 4 {
		http.SetCookie(w, &http.Cookie{
			Name:   cookieDomain,
			Value:  domainVal,
			Domain: ".invalid-domain.test",
			Path:   "/",
			MaxAge: 86400,
		})
	}

	// 5. Secure-on-HTTP cookie: the Secure flag means the cookie must only be
	//    sent over HTTPS. On a plain HTTP connection browsers reject it.
	if freq >= 5 {
		http.SetCookie(w, &http.Cookie{
			Name:   cookieSecure,
			Value:  secureVal,
			Path:   "/",
			Secure: true,
			MaxAge: 86400,
		})
	}

	// 6. SameSite=Strict cookie on a path typically accessed cross-origin.
	if freq >= 6 {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieSameSite,
			Value:    samesiteVal,
			Path:     "/external/callback",
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400,
		})
	}

	// Record the values we set so Analyze can check them later.
	t.mu.Lock()
	cs.cookiesSet = true
	cs.sessionVal = sessionVal
	cs.fpVal = fpVal
	cs.trapVal = trapVal
	cs.domainVal = domainVal
	cs.secureVal = secureVal
	cs.samesiteVal = samesiteVal
	t.mu.Unlock()
}

// Analyze inspects the incoming cookies to detect bot behavior.
func (t *Tracker) Analyze(r *http.Request, clientID string) *CookieAnalysis {
	analysis := &CookieAnalysis{
		MissingExpected:   []string{},
		UnexpectedPresent: []string{},
	}

	cs := t.getState(clientID)

	// If we have never set cookies for this client, this is their first
	// request. Nothing to judge yet.
	if cs == nil || !cs.cookiesSet {
		analysis.CookieConsistency = 1.0
		analysis.BotScore = 0.0
		return analysis
	}

	// ---- Cookie bomb detection ----
	cookieHeader := r.Header.Get("Cookie")
	cookieBomb := len(cookieHeader) > maxCookieHeaderLen

	// ---- Gather incoming cookies ----
	incomingCookies := make(map[string]string)
	for _, c := range r.Cookies() {
		incomingCookies[c.Name] = c.Value
	}

	// ---- Check expected cookies ----
	t.mu.RLock()
	sessionVal := cs.sessionVal
	fpVal := cs.fpVal
	trapVal := cs.trapVal
	domainVal := cs.domainVal
	secureVal := cs.secureVal
	t.mu.RUnlock()

	// Session cookie: should be present and match.
	if v, ok := incomingCookies[cookieSession]; ok && v == sessionVal {
		analysis.HasSessionCookie = true
	} else {
		analysis.MissingExpected = append(analysis.MissingExpected, cookieSession)
	}

	// Fingerprint cookie: should be present and match.
	if v, ok := incomingCookies[cookieFP]; ok && v == fpVal {
		analysis.HasFingerprint = true
	} else {
		analysis.MissingExpected = append(analysis.MissingExpected, cookieFP)
	}

	// ---- Check trap cookies (should NOT be present) ----

	// Trap cookie (Max-Age=0): browser should have deleted it.
	if v, ok := incomingCookies[cookieTrap]; ok && v == trapVal {
		analysis.HasTrapCookie = true
		analysis.UnexpectedPresent = append(analysis.UnexpectedPresent, cookieTrap)
	}

	// Domain mismatch cookie: browser should have rejected it.
	if v, ok := incomingCookies[cookieDomain]; ok && v == domainVal {
		analysis.HasTrapCookie = true
		analysis.UnexpectedPresent = append(analysis.UnexpectedPresent, cookieDomain)
	}

	// Secure-on-HTTP cookie: browser should have rejected it on plain HTTP.
	// We only flag this if the request came over HTTP (not TLS).
	if r.TLS == nil {
		if v, ok := incomingCookies[cookieSecure]; ok && v == secureVal {
			analysis.HasTrapCookie = true
			analysis.UnexpectedPresent = append(analysis.UnexpectedPresent, cookieSecure)
		}
	}

	// ---- Compute CookieConsistency (0-1) ----
	// Points system: higher is more consistent / more human-like.
	points := 0.0
	maxPoints := 0.0

	// Session cookie present = good
	maxPoints += 1.0
	if analysis.HasSessionCookie {
		points += 1.0
	}

	// Fingerprint cookie present = good
	maxPoints += 1.0
	if analysis.HasFingerprint {
		points += 1.0
	}

	// Trap cookie absent = good
	maxPoints += 1.0
	if !analysis.HasTrapCookie {
		points += 1.0
	}

	// No cookie bomb = good
	maxPoints += 1.0
	if !cookieBomb {
		points += 1.0
	}

	if maxPoints > 0 {
		analysis.CookieConsistency = points / maxPoints
	}

	// ---- Compute BotScore (0-1) ----
	botScore := 0.0

	// Missing session cookie on a subsequent visit is a strong signal.
	if !analysis.HasSessionCookie {
		botScore += 0.3
	}

	// Missing fingerprint cookie is also suspicious.
	if !analysis.HasFingerprint {
		botScore += 0.2
	}

	// Presence of any trap cookie is a very strong signal.
	botScore += 0.3 * float64(len(analysis.UnexpectedPresent))
	if botScore > 1.0 {
		botScore = 1.0
	}

	// Cookie bomb.
	if cookieBomb {
		botScore += 0.2
		if botScore > 1.0 {
			botScore = 1.0
		}
	}

	analysis.BotScore = botScore

	return analysis
}

// GenerateJSStorage returns a <script> block that sets localStorage,
// sessionStorage, and document.cookie honey tokens for canary detection.
// If the client executes JavaScript, these values will be present; pure
// HTTP scrapers will never run them.
func (t *Tracker) GenerateJSStorage(clientID string) string {
	lsKey := "_glitch_ls"
	lsVal := deterministicValue(clientID, "localstorage")
	ssKey := "_glitch_ss_ts"
	ssVal := deterministicValue(clientID, "sessionstorage")
	jsCookieVal := deterministicValue(clientID, "jscookie")
	canaryID := "glitch-canary-" + deterministicValue(clientID, "canary")[:12]

	var sb strings.Builder
	sb.WriteString("<script>\n")
	sb.WriteString("(function(){\n")
	sb.WriteString("  try {\n")

	// localStorage item
	sb.WriteString(fmt.Sprintf("    localStorage.setItem(%q, %q);\n", lsKey, lsVal))

	// sessionStorage with timestamp
	sb.WriteString(fmt.Sprintf("    sessionStorage.setItem(%q, %q + '|' + Date.now());\n", ssKey, ssVal))

	// JS-set cookie (distinguishable from HTTP-set cookies by name prefix)
	sb.WriteString(fmt.Sprintf("    document.cookie = '_glitch_js=%s; path=/; max-age=86400';\n", jsCookieVal))

	// Invisible canary element that only JS can populate
	sb.WriteString(fmt.Sprintf("    var el = document.createElement('div');\n"))
	sb.WriteString(fmt.Sprintf("    el.id = %q;\n", canaryID))
	sb.WriteString("    el.style.display = 'none';\n")
	sb.WriteString(fmt.Sprintf("    el.setAttribute('data-token', %q);\n", deterministicValue(clientID, "canary-token")))
	sb.WriteString("    document.body.appendChild(el);\n")

	sb.WriteString("  } catch(e) {}\n")
	sb.WriteString("})();\n")
	sb.WriteString("</script>")

	return sb.String()
}
