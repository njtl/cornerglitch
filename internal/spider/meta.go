package spider

import (
	"net/http"
)

// serveManifest serves /manifest.json — a PWA web app manifest.
func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.MetaErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "manifest_error", errorRate) {
		return h.serveBrokenMeta(w, r, "application/json")
	}

	manifest := `{
  "name": "Glitch Web Server",
  "short_name": "Glitch",
  "description": "An intentionally unreliable, adaptive HTTP server",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#1a1a2e",
  "theme_color": "#e94560",
  "orientation": "portrait-primary",
  "icons": [
    {
      "src": "/favicon.ico",
      "sizes": "16x16",
      "type": "image/x-icon"
    },
    {
      "src": "/apple-touch-icon.png",
      "sizes": "180x180",
      "type": "image/png"
    }
  ],
  "categories": ["developer tools", "testing"],
  "lang": "en-US",
  "dir": "ltr",
  "scope": "/",
  "prefer_related_applications": false
}`

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	w.Write([]byte(manifest))
	return 200
}

// serveBrowserconfig serves /browserconfig.xml — Microsoft tile configuration.
func (h *Handler) serveBrowserconfig(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.MetaErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "browserconfig_error", errorRate) {
		return h.serveBrokenMeta(w, r, "application/xml")
	}

	xml := `<?xml version="1.0" encoding="utf-8"?>
<browserconfig>
  <msapplication>
    <tile>
      <square70x70logo src="/favicon.ico"/>
      <square150x150logo src="/favicon.ico"/>
      <square310x310logo src="/favicon.ico"/>
      <wide310x150logo src="/favicon.ico"/>
      <TileColor>#e94560</TileColor>
    </tile>
    <notification>
      <polling-uri src="/api/notifications/1"/>
      <polling-uri2 src="/api/notifications/2"/>
      <polling-uri3 src="/api/notifications/3"/>
      <frequency>30</frequency>
      <cycle>1</cycle>
    </notification>
  </msapplication>
</browserconfig>`

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	w.Write([]byte(xml))
	return 200
}

// serveHumans serves /humans.txt — a credits/team file.
func (h *Handler) serveHumans(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.MetaErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "humans_error", errorRate) {
		return h.serveBrokenMeta(w, r, "text/plain")
	}

	humans := `/* TEAM */
  Developer: Glitch Engineering Team
  Contact: dev@glitch.internal
  From: The Internet

/* THANKS */
  Name: The Open Source Community
  Name: OWASP Foundation

/* SITE */
  Last update: 2024-12-01
  Language: English
  Doctype: HTML5
  IDE: vim, vscode
  Standards: HTTP/1.1, HTTP/2
  Components: Go stdlib
  Software: Glitch Web Server v2.0`

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.WriteHeader(200)
	w.Write([]byte(humans))
	return 200
}

// serveAds serves /ads.txt — an IAB ads.txt file for ad network authorization.
func (h *Handler) serveAds(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.MetaErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "ads_error", errorRate) {
		return h.serveBrokenMeta(w, r, "text/plain")
	}

	ads := `# ads.txt - Glitch Web Server
# Authorized Digital Sellers

# Google AdSense
google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0

# Google Ad Manager
google.com, pub-9876543210987654, RESELLER, f08c47fec0942fa0

# Example ad network
exampleadnetwork.com, 12345, DIRECT
adexchange.example.com, 67890, RESELLER, 0123456789abcdef

# Contact
contact=adops@glitch.internal`

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	w.Write([]byte(ads))
	return 200
}

// serveSecurity serves /.well-known/security.txt — security contact information.
func (h *Handler) serveSecurity(w http.ResponseWriter, r *http.Request) int {
	h.cfg.mu.RLock()
	errorRate := h.cfg.MetaErrorRate
	h.cfg.mu.RUnlock()

	if shouldError(r.URL.Path, "security_error", errorRate) {
		return h.serveBrokenMeta(w, r, "text/plain")
	}

	security := `# Security Policy - Glitch Web Server
# https://securitytxt.org/

Contact: mailto:security@glitch.internal
Contact: https://glitch.internal/security/report
Encryption: https://glitch.internal/.well-known/pgp-key.txt
Acknowledgments: https://glitch.internal/security/hall-of-fame
Preferred-Languages: en
Canonical: https://glitch.internal/.well-known/security.txt
Policy: https://glitch.internal/security/policy
Hiring: https://glitch.internal/careers/security
Expires: 2026-12-31T23:59:59.000Z`

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(200)
	w.Write([]byte(security))
	return 200
}

// serveBrokenMeta returns a broken response for meta file endpoints.
func (h *Handler) serveBrokenMeta(w http.ResponseWriter, r *http.Request, expectedContentType string) int {
	rng := seedRand(r.URL.Path + "broken_meta")
	mode := rng.Intn(4)

	switch mode {
	case 0:
		// Empty response
		w.Header().Set("Content-Type", expectedContentType)
		w.WriteHeader(200)
		return 200
	case 1:
		// Wrong content type
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		garbage := make([]byte, 64)
		for i := range garbage {
			garbage[i] = byte(rng.Intn(256))
		}
		w.Write(garbage)
		return 200
	case 2:
		// 500 error
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte("Internal Server Error"))
		return 500
	case 3:
		// Truncated JSON/XML/text
		w.Header().Set("Content-Type", expectedContentType)
		w.WriteHeader(200)
		w.Write([]byte(`{"name": "Glitch", "broken`))
		return 200
	}

	return 200
}
