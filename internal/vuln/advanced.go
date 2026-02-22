package vuln

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

// AdvancedShouldHandle returns true if the path matches an advanced
// vulnerability emulation endpoint.
func (h *Handler) AdvancedShouldHandle(path string) bool {
	prefixes := []string{
		"/vuln/cors/",
		"/vuln/redirect",
		"/vuln/xxe/",
		"/vuln/ssti/",
		"/vuln/crlf/",
		"/vuln/host/",
		"/vuln/verb/",
		"/vuln/hpp/",
		"/vuln/upload/",
		"/vuln/cmd/",
		"/vuln/graphql/",
		"/vuln/jwt/",
		"/vuln/race/",
		"/vuln/deserialize/",
		"/vuln/path/",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ServeAdvanced handles all advanced vulnerability emulation endpoints.
// Returns the HTTP status code written to the response.
func (h *Handler) ServeAdvanced(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch {
	case strings.HasPrefix(path, "/vuln/cors/"):
		return h.serveCORS(w, r)
	case strings.HasPrefix(path, "/vuln/redirect"):
		return h.serveRedirect(w, r)
	case strings.HasPrefix(path, "/vuln/xxe/"):
		return h.serveXXE(w, r)
	case strings.HasPrefix(path, "/vuln/ssti/"):
		return h.serveSSTI(w, r)
	case strings.HasPrefix(path, "/vuln/crlf/"):
		return h.serveCRLF(w, r)
	case strings.HasPrefix(path, "/vuln/host/"):
		return h.serveHostHeader(w, r)
	case strings.HasPrefix(path, "/vuln/verb/"):
		return h.serveVerbTamper(w, r)
	case strings.HasPrefix(path, "/vuln/hpp/"):
		return h.serveHPP(w, r)
	case strings.HasPrefix(path, "/vuln/upload/"):
		return h.serveUpload(w, r)
	case strings.HasPrefix(path, "/vuln/cmd/"):
		return h.serveCmd(w, r)
	case strings.HasPrefix(path, "/vuln/graphql/"):
		return h.serveGraphQL(w, r)
	case strings.HasPrefix(path, "/vuln/jwt/"):
		return h.serveJWT(w, r)
	case strings.HasPrefix(path, "/vuln/race/"):
		return h.serveRace(w, r)
	case strings.HasPrefix(path, "/vuln/deserialize/"):
		return h.serveDeserialize(w, r)
	case strings.HasPrefix(path, "/vuln/path/"):
		return h.servePathNorm(w, r)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, h.wrapHTML("Not Found", "<p>Unknown advanced vulnerability demo path.</p>"))
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// 1. CORS Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveCORS(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "cors-misconfiguration")
	path := r.URL.Path
	rng := h.rngFromPath(path)

	sensitiveJSON := toJSON(map[string]interface{}{
		"user": map[string]interface{}{
			"id":    42,
			"name":  h.randomName(rng),
			"email": h.randomEmail(rng),
			"role":  "admin",
			"ssn":   fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
		},
		"api_key":  fmt.Sprintf("sk_%s", h.randomHex(rng, 32)),
		"internal": true,
	})

	switch {
	case strings.HasSuffix(path, "/reflect"):
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "https://evil.com"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, sensitiveJSON)
		return http.StatusOK

	case strings.HasSuffix(path, "/wildcard"):
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, sensitiveJSON)
		return http.StatusOK

	case strings.HasSuffix(path, "/null"):
		origin := r.Header.Get("Origin")
		if origin == "null" || origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, sensitiveJSON)
		return http.StatusOK

	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>CORS Misconfiguration Demos</h2>
<ul>
  <li><a href="/vuln/cors/reflect">Origin Reflection</a> — reflects Origin header in ACAO</li>
  <li><a href="/vuln/cors/wildcard">Wildcard + Credentials</a> — ACAO: * with credentials</li>
  <li><a href="/vuln/cors/null">Null Origin</a> — accepts Origin: null</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("CORS Misconfiguration", body))
		return http.StatusOK
	}
}

// ---------------------------------------------------------------------------
// 2. Open Redirect
// ---------------------------------------------------------------------------

func (h *Handler) serveRedirect(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "open-redirect")

	q := r.URL.Query()
	target := q.Get("url")
	if target == "" {
		target = q.Get("next")
	}
	if target == "" {
		target = q.Get("return_to")
	}

	if target == "" {
		// Show an info page when no redirect param is given
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>Open Redirect Demo</h2>
<p>Supply a target URL in any of these parameters:</p>
<ul>
  <li><a href="/vuln/redirect?url=https://evil.com">/vuln/redirect?url=https://evil.com</a></li>
  <li><a href="/vuln/redirect?next=https://evil.com">/vuln/redirect?next=https://evil.com</a></li>
  <li><a href="/vuln/redirect?return_to=https://evil.com">/vuln/redirect?return_to=https://evil.com</a></li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Open Redirect", body))
		return http.StatusOK
	}

	// Set the redirect header
	w.Header().Set("Location", target)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusFound) // 302

	// Also emit a Redirecting page with meta refresh for scanners
	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh" content="0;url=%s">
  <title>Redirecting...</title>
</head>
<body>
  <p>Redirecting to <a href="%s">%s</a>...</p>
</body>
</html>`, target, target, target)
	fmt.Fprint(w, page)
	return http.StatusFound
}

// ---------------------------------------------------------------------------
// 3. XXE - XML External Entity
// ---------------------------------------------------------------------------

func (h *Handler) serveXXE(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "xxe")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/parse"):
		return h.serveXXEParse(w, r)
	case strings.HasSuffix(path, "/upload"):
		return h.serveXXEUpload(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>XXE - XML External Entity Demos</h2>
<ul>
  <li><b>POST /vuln/xxe/parse</b> — send XML in body, entity expansion returned</li>
  <li><a href="/vuln/xxe/upload">/vuln/xxe/upload</a> — XML file upload form</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("XXE", body))
		return http.StatusOK
	}
}

func (h *Handler) serveXXEParse(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")

	// Read body if present (we just echo parts of it)
	var userXML string
	if r.Body != nil && r.ContentLength > 0 {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		userXML = string(buf[:n])
	}
	if userXML == "" {
		userXML = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>`
	}

	// Simulate entity resolution — always "resolve" file:///etc/passwd
	resolved := fakePasswd()

	resp := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<xxe-result>
  <status>parsed</status>
  <input><![CDATA[%s]]></input>
  <entity-resolution>
    <entity name="xxe" system="file:///etc/passwd">
      <resolved>true</resolved>
      <content><![CDATA[%s]]></content>
    </entity>
  </entity-resolution>
  <parser-info>
    <external-entities>enabled</external-entities>
    <dtd-validation>enabled</dtd-validation>
    <parser>libxml2 2.9.4</parser>
  </parser-info>
</xxe-result>`, userXML, resolved)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveXXEUpload(w http.ResponseWriter, r *http.Request) int {
	if r.Method == http.MethodPost {
		return h.serveXXEParse(w, r)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := `<h2>XML File Upload</h2>
<p>Upload an XML file for processing. External entities will be resolved.</p>
<form method="POST" action="/vuln/xxe/parse" enctype="multipart/form-data">
  <label>XML File: <input type="file" name="xmlfile" accept=".xml,text/xml"></label><br><br>
  <textarea name="xml" rows="10" cols="60" placeholder="Or paste XML here...">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;root&gt;
  &lt;data&gt;&amp;xxe;&lt;/data&gt;
&lt;/root&gt;</textarea><br><br>
  <button type="submit">Parse XML</button>
</form>`
	fmt.Fprint(w, h.wrapHTML("XXE Upload", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 4. SSTI - Server-Side Template Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveSSTI(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "ssti")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/render"):
		return h.serveSSTIRender(w, r)
	case strings.HasSuffix(path, "/preview"):
		return h.serveSSTIPreview(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>SSTI - Server-Side Template Injection Demos</h2>
<ul>
  <li><a href="/vuln/ssti/render?name={{7*7}}">/vuln/ssti/render?name={{7*7}}</a></li>
  <li><b>POST /vuln/ssti/preview</b> — send template body for rendering</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("SSTI", body))
		return http.StatusOK
	}
}

// evaluateTemplate does simplistic Jinja2/Twig-style evaluation.
func evaluateTemplate(input string) string {
	result := input
	// Find all {{ ... }} expressions and try to evaluate them
	for {
		start := strings.Index(result, "{{")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}}")
		if end == -1 {
			break
		}
		end += start + 2
		expr := strings.TrimSpace(result[start+2 : end-2])

		evaluated := evaluateExpr(expr)
		result = result[:start] + evaluated + result[end:]
	}
	return result
}

// evaluateExpr handles simple math and common SSTI probe patterns.
func evaluateExpr(expr string) string {
	// Try simple multiplication: 7*7
	if strings.Contains(expr, "*") {
		parts := strings.SplitN(expr, "*", 2)
		a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
		b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
		if errA == nil && errB == nil {
			return strconv.Itoa(a * b)
		}
	}
	// Try addition
	if strings.Contains(expr, "+") && !strings.Contains(expr, "'+") {
		parts := strings.SplitN(expr, "+", 2)
		a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
		b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
		if errA == nil && errB == nil {
			return strconv.Itoa(a + b)
		}
	}
	// Common SSTI class chain patterns
	if strings.Contains(expr, "__class__") {
		return "<class 'str'>"
	}
	if strings.Contains(expr, "config") {
		return "{'SECRET_KEY': 'super_secret_jwt_key_do_not_share_2024', 'DEBUG': True}"
	}
	if strings.Contains(expr, "lipsum") || strings.Contains(expr, "cycler") {
		return "<generator object at 0x7f1234abcdef>"
	}
	// Fallback: echo input (template reflected without evaluation)
	return expr
}

func (h *Handler) serveSSTIRender(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}

	rendered := evaluateTemplate(name)

	body := fmt.Sprintf(`<h2>Template Render Result</h2>
<p>Input: <code>%s</code></p>
<div style="background:#16213e;padding:15px;border:1px solid #0f3460;margin:10px 0;">
<p>Hello, <b>%s</b>!</p>
</div>
<p>Template engine: Jinja2 2.11.3</p>
<p>Try: <a href="/vuln/ssti/render?name={{7*7}}">{<!-- -->{7*7}}</a>,
<a href="/vuln/ssti/render?name={{config}}">{<!-- -->{config}}</a>,
<a href="/vuln/ssti/render?name={{''.__class__}}">{<!-- -->{''.__class__}}</a></p>`,
		name, rendered)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("SSTI Render", body))
	return http.StatusOK
}

func (h *Handler) serveSSTIPreview(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var template string
	if r.Method == http.MethodPost {
		template = r.FormValue("template")
	}
	if template == "" {
		template = r.URL.Query().Get("template")
	}
	if template == "" {
		template = "Hello, {{name}}!"
	}

	rendered := evaluateTemplate(template)

	body := fmt.Sprintf(`<h2>Template Preview</h2>
<h3>Input Template</h3>
<pre>%s</pre>
<h3>Rendered Output</h3>
<div style="background:#16213e;padding:15px;border:1px solid #0f3460;margin:10px 0;">
%s
</div>
<h3>Template Engine Info</h3>
<table border="1" cellpadding="4" cellspacing="0">
<tr><td>Engine</td><td>Jinja2 2.11.3</td></tr>
<tr><td>Auto-escape</td><td>disabled</td></tr>
<tr><td>Sandbox</td><td>disabled</td></tr>
<tr><td>Extensions</td><td>jinja2.ext.do, jinja2.ext.loopcontrols</td></tr>
</table>`, template, rendered)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("SSTI Preview", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 5. CRLF Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveCRLF(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "crlf-injection")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/set"):
		return h.serveCRLFSet(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>CRLF Injection Demos</h2>
<ul>
  <li><a href="/vuln/crlf/set?lang=en">/vuln/crlf/set?lang=en</a> — normal</li>
  <li><a href="/vuln/crlf/set?lang=en%0d%0aSet-Cookie:%20admin=true">/vuln/crlf/set?lang=en%0d%0aSet-Cookie: admin=true</a> — CRLF injection</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("CRLF Injection", body))
		return http.StatusOK
	}
}

func (h *Handler) serveCRLFSet(w http.ResponseWriter, r *http.Request) int {
	// Get the raw query to detect %0d%0a patterns
	lang := r.URL.Query().Get("lang")
	rawQuery := r.URL.RawQuery

	// Detect CRLF injection attempt in the raw query
	hasCRLF := strings.Contains(strings.ToLower(rawQuery), "%0d%0a")

	if hasCRLF {
		// Simulate header injection: set the lang header AND a fake admin cookie
		w.Header().Set("X-Language", lang)
		w.Header().Set("Set-Cookie", "admin=true; Path=/")
		w.Header().Set("X-Injected", "true")
	} else {
		w.Header().Set("X-Language", lang)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	body := fmt.Sprintf(`<h2>Language Set</h2>
<p>Language preference set to: <code>%s</code></p>
<p>Check the response headers for this request.</p>`, lang)
	fmt.Fprint(w, h.wrapHTML("CRLF - Language Set", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 6. Host Header Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveHostHeader(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "host-header-injection")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/reset"):
		return h.serveHostReset(w, r)
	case strings.HasSuffix(path, "/cache"):
		return h.serveHostCache(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>Host Header Injection Demos</h2>
<ul>
  <li><a href="/vuln/host/reset">/vuln/host/reset</a> — password reset using Host header</li>
  <li><a href="/vuln/host/cache">/vuln/host/cache</a> — cached page with Host-based links</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Host Header Injection", body))
		return http.StatusOK
	}
}

func (h *Handler) serveHostReset(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	rng := h.rngFromPath("/vuln/host/reset")
	token := h.randomHex(rng, 32)

	resetLink := fmt.Sprintf("http://%s/reset?token=%s", host, token)

	body := fmt.Sprintf(`<h2>Password Reset</h2>
<p>A password reset email has been sent to admin@glitchapp.com.</p>
<div class="warning">
<p>The reset link uses the Host header from the request:</p>
<pre>%s</pre>
<p>An attacker who controls the Host header can redirect the reset link to their own domain.</p>
</div>
<h3>Email Preview</h3>
<div style="background:#16213e;padding:15px;border:1px solid #0f3460;">
<p>From: noreply@glitchapp.com</p>
<p>To: admin@glitchapp.com</p>
<p>Subject: Password Reset Request</p>
<hr>
<p>Click the link below to reset your password:</p>
<p><a href="%s">%s</a></p>
<p>This link will expire in 24 hours.</p>
</div>`, resetLink, resetLink, resetLink)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Host Header - Password Reset", body))
	return http.StatusOK
}

func (h *Handler) serveHostCache(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}

	body := fmt.Sprintf(`<h2>Cached Page</h2>
<p>This page uses the Host header to construct links. Cache-Control is set to public.</p>
<nav>
  <a href="http://%s/">Home</a> |
  <a href="http://%s/login">Login</a> |
  <a href="http://%s/dashboard">Dashboard</a> |
  <a href="http://%s/api/v1/users">API</a>
</nav>
<p>If the Host header is manipulated, cached pages will contain malicious links.</p>
<h3>Resource URLs</h3>
<ul>
  <li>CSS: <code>http://%s/static/style.css</code></li>
  <li>JS: <code>http://%s/static/app.js</code></li>
  <li>API: <code>http://%s/api/v1/data</code></li>
</ul>`, host, host, host, host, host, host, host)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("Host Header - Cache Poisoning", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 7. HTTP Verb Tampering
// ---------------------------------------------------------------------------

func (h *Handler) serveVerbTamper(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "verb-tampering")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/admin"):
		return h.serveVerbAdmin(w, r)
	case strings.HasSuffix(path, "/delete"):
		return h.serveVerbDelete(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>HTTP Verb Tampering Demos</h2>
<ul>
  <li><a href="/vuln/verb/admin">/vuln/verb/admin</a> — 403 for GET, 200 for other methods</li>
  <li><a href="/vuln/verb/delete">/vuln/verb/delete</a> — GET deletes a resource</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Verb Tampering", body))
		return http.StatusOK
	}
}

func (h *Handler) serveVerbAdmin(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusForbidden)
		body := `<h2>403 Forbidden</h2><p>Access denied. Admin privileges required.</p>`
		fmt.Fprint(w, h.wrapHTML("Forbidden", body))
		return http.StatusForbidden
	}

	// HEAD, PUT, PATCH, OPTIONS, DELETE — all succeed
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		body := fmt.Sprintf(`<h2>Admin Panel</h2>
<p>Access granted via HTTP method: <code>%s</code></p>
<p>The access control only blocks GET requests. Try HEAD, PUT, PATCH, or OPTIONS.</p>
<h3>Admin Actions</h3>
<ul>
  <li>User Management: 847 users</li>
  <li>System Configuration: editable</li>
  <li>Database: backup available</li>
  <li>Logs: full access</li>
</ul>`, r.Method)
		fmt.Fprint(w, h.wrapHTML("Admin Panel - Verb Bypass", body))
	}
	return http.StatusOK
}

func (h *Handler) serveVerbDelete(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := toJSON(map[string]interface{}{
		"status":  "deleted",
		"method":  r.Method,
		"message": "Resource deleted successfully via " + r.Method + " request",
		"warning": "DELETE operation accepted via GET — should require POST or DELETE method",
		"resource": map[string]interface{}{
			"id":         42,
			"type":       "user_account",
			"deleted_at": time.Now().Format(time.RFC3339),
		},
	})
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 8. HTTP Parameter Pollution
// ---------------------------------------------------------------------------

func (h *Handler) serveHPP(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "parameter-pollution")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/transfer"):
		return h.serveHPPTransfer(w, r)
	case strings.HasSuffix(path, "/search"):
		return h.serveHPPSearch(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>HTTP Parameter Pollution Demos</h2>
<ul>
  <li><a href="/vuln/hpp/transfer?from=user&to=admin&amount=100">/vuln/hpp/transfer?from=user&amp;to=admin&amp;amount=100</a></li>
  <li><a href="/vuln/hpp/search?q=safe&q=<script>alert(1)</script>">/vuln/hpp/search?q=safe&amp;q=&lt;script&gt;alert(1)&lt;/script&gt;</a></li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("HTTP Parameter Pollution", body))
		return http.StatusOK
	}
}

func (h *Handler) serveHPPTransfer(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	q := r.URL.Query()
	from := q.Get("from")
	amount := q.Get("amount")

	// HPP: use the LAST value of "to" when duplicated
	toValues := q["to"]
	to := ""
	if len(toValues) > 0 {
		to = toValues[len(toValues)-1]
	}

	if from == "" {
		from = "user"
	}
	if to == "" {
		to = "admin"
	}
	if amount == "" {
		amount = "100"
	}

	resp := toJSON(map[string]interface{}{
		"status":  "completed",
		"from":    from,
		"to":      to,
		"amount":  amount,
		"warning": "When 'to' parameter is specified multiple times, the last value is used",
		"all_to_values": strings.Join(toValues, ", "),
		"note":    "HPP allows an attacker to override the 'to' field by appending a second parameter",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveHPPSearch(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	qValues := r.URL.Query()["q"]
	var query string
	if len(qValues) > 0 {
		query = qValues[len(qValues)-1] // Use last value
	}
	if query == "" {
		query = "test"
	}

	// Intentionally reflect the raw value (XSS via HPP)
	body := fmt.Sprintf(`<h2>Search Results</h2>
<p>Showing results for: <b>%s</b></p>
<p>All 'q' parameter values received: %s</p>
<p>The server uses the last value of duplicate parameters, potentially bypassing WAF filters
that only inspect the first value.</p>
<div class="warning">
<p>The search query is reflected without sanitization.</p>
</div>`, query, strings.Join(qValues, ", "))

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, h.wrapHTML("HPP Search", body))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 9. Insecure File Upload
// ---------------------------------------------------------------------------

func (h *Handler) serveUpload(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "insecure-upload")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/process"):
		return h.serveUploadProcess(w, r)
	default:
		return h.serveUploadForm(w, r)
	}
}

func (h *Handler) serveUploadForm(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	body := `<h2>File Upload</h2>
<p>Upload any file. No restrictions on file type, size, or content.</p>
<form method="POST" action="/vuln/upload/process" enctype="multipart/form-data">
  <label>Select file: <input type="file" name="file"></label><br><br>
  <button type="submit">Upload</button>
</form>
<div class="warning">
<p>No file type validation, no content scanning, no filename sanitization.</p>
</div>`
	fmt.Fprint(w, h.wrapHTML("Insecure File Upload", body))
	return http.StatusOK
}

func (h *Handler) serveUploadProcess(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	filename := "malicious.php"
	contentType := "application/octet-stream"
	size := 1337

	// Try to read from multipart form
	if r.Method == http.MethodPost {
		err := r.ParseMultipartForm(1 << 20) // 1 MB
		if err == nil {
			file, header, ferr := r.FormFile("file")
			if ferr == nil {
				filename = header.Filename
				contentType = header.Header.Get("Content-Type")
				size = int(header.Size)
				file.Close()
			}
		}
		// Also check form-encoded "filename" param as fallback
		if fn := r.FormValue("filename"); fn != "" {
			filename = fn
		}
	}

	// Return the "uploaded" file path without sanitization
	resp := toJSON(map[string]interface{}{
		"status":       "uploaded",
		"filename":     filename,
		"content_type": contentType,
		"size":         size,
		"url":          fmt.Sprintf("/uploads/%s", filename),
		"full_path":    fmt.Sprintf("/var/www/html/uploads/%s", filename),
		"warning":      "File uploaded without type checking, content scanning, or filename sanitization",
		"accessible_at": fmt.Sprintf("http://localhost:8765/uploads/%s", filename),
		"checks_performed": map[string]interface{}{
			"file_type_validation": false,
			"content_scanning":     false,
			"filename_sanitization": false,
			"size_limit":           false,
			"extension_whitelist":  false,
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 10. Command Injection
// ---------------------------------------------------------------------------

func (h *Handler) serveCmd(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "command-injection")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/ping"):
		return h.serveCmdPing(w, r)
	case strings.HasSuffix(path, "/dns"):
		return h.serveCmdDNS(w, r)
	case strings.HasSuffix(path, "/whois"):
		return h.serveCmdWhois(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>Command Injection Demos</h2>
<ul>
  <li><a href="/vuln/cmd/ping?host=127.0.0.1">/vuln/cmd/ping?host=127.0.0.1</a></li>
  <li><a href="/vuln/cmd/dns?domain=example.com">/vuln/cmd/dns?domain=example.com</a></li>
  <li><a href="/vuln/cmd/whois?target=example.com">/vuln/cmd/whois?target=example.com</a></li>
  <li><a href="/vuln/cmd/ping?host=127.0.0.1;id">/vuln/cmd/ping?host=127.0.0.1;id</a> — with injection</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Command Injection", body))
		return http.StatusOK
	}
}

// hasInjection returns true if the input contains shell meta-characters.
func hasInjection(input string) bool {
	for _, pattern := range []string{";", "|", "&&", "$("} {
		if strings.Contains(input, pattern) {
			return true
		}
	}
	return false
}

// injectedOutput returns fake output for the "injected" command.
func injectedOutput(input string) string {
	// Extract the part after the injection character
	for _, sep := range []string{";", "&&", "|"} {
		if idx := strings.Index(input, sep); idx >= 0 {
			injected := strings.TrimSpace(input[idx+len(sep):])
			return fakeCommandOutput(injected)
		}
	}
	if idx := strings.Index(input, "$("); idx >= 0 {
		end := strings.Index(input[idx:], ")")
		if end > 0 {
			injected := input[idx+2 : idx+end]
			return fakeCommandOutput(injected)
		}
	}
	return ""
}

func fakeCommandOutput(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "id":
		return "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
	case cmd == "whoami":
		return "www-data\n"
	case strings.HasPrefix(cmd, "cat /etc/passwd"):
		return fakePasswd()
	case cmd == "uname -a":
		return "Linux web-03.prod.internal 5.4.0-135-generic #152-Ubuntu SMP x86_64 GNU/Linux\n"
	case cmd == "ls":
		return "app.py\nconfig.yml\nrequirements.txt\nuploads/\nstatic/\ntemplates/\n"
	case cmd == "env":
		return "DB_PASSWORD=xK9#mP2$vL5nQ8wR!\nSECRET_KEY=super_secret_jwt_key\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	default:
		return fmt.Sprintf("%s: command output simulated\n", cmd)
	}
}

func (h *Handler) serveCmdPing(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}

	rng := h.rngFromPath("/vuln/cmd/ping/" + host)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("$ ping -c 4 %s\n", host))

	// Get base host (before any injection)
	baseHost := host
	for _, sep := range []string{";", "|", "&&"} {
		if idx := strings.Index(baseHost, sep); idx >= 0 {
			baseHost = strings.TrimSpace(baseHost[:idx])
		}
	}
	if idx := strings.Index(baseHost, "$("); idx >= 0 {
		baseHost = strings.TrimSpace(baseHost[:idx])
	}

	sb.WriteString(fmt.Sprintf("PING %s (%s): 56 data bytes\n", baseHost, baseHost))
	for i := 0; i < 4; i++ {
		ms := float64(rng.Intn(50)+1) + rng.Float64()
		sb.WriteString(fmt.Sprintf("64 bytes from %s: icmp_seq=%d ttl=64 time=%.3f ms\n", baseHost, i, ms))
	}
	sb.WriteString(fmt.Sprintf("\n--- %s ping statistics ---\n", baseHost))
	sb.WriteString("4 packets transmitted, 4 packets received, 0%% packet loss\n")

	if hasInjection(host) {
		sb.WriteString(fmt.Sprintf("\n$ %s\n", strings.TrimSpace(host[strings.IndexAny(host, ";|&$")+1:])))
		sb.WriteString(injectedOutput(host))
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveCmdDNS(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = "example.com"
	}

	baseDomain := domain
	for _, sep := range []string{";", "|", "&&"} {
		if idx := strings.Index(baseDomain, sep); idx >= 0 {
			baseDomain = strings.TrimSpace(baseDomain[:idx])
		}
	}

	rng := h.rngFromPath("/vuln/cmd/dns/" + domain)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("$ nslookup %s\n", domain))
	sb.WriteString("Server:  8.8.8.8\nAddress: 8.8.8.8#53\n\n")
	sb.WriteString(fmt.Sprintf("Non-authoritative answer:\nName:\t%s\nAddress: %d.%d.%d.%d\n",
		baseDomain, rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1))

	if hasInjection(domain) {
		sb.WriteString("\n")
		sb.WriteString(injectedOutput(domain))
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

func (h *Handler) serveCmdWhois(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "text/plain")
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "example.com"
	}

	baseTarget := target
	for _, sep := range []string{";", "|", "&&"} {
		if idx := strings.Index(baseTarget, sep); idx >= 0 {
			baseTarget = strings.TrimSpace(baseTarget[:idx])
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("$ whois %s\n", target))
	sb.WriteString(fmt.Sprintf(`Domain Name: %s
Registry Domain ID: 1234567890_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example-registrar.com
Registrar URL: http://www.example-registrar.com
Updated Date: 2024-01-15T12:00:00Z
Creation Date: 2000-01-01T00:00:00Z
Registrar: Example Registrar, Inc.
Registrar Abuse Contact Email: abuse@example-registrar.com
Registrar Abuse Contact Phone: +1.5555551234
Domain Status: clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
`, baseTarget))

	if hasInjection(target) {
		sb.WriteString("\n")
		sb.WriteString(injectedOutput(target))
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, sb.String())
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 11. GraphQL Vulnerabilities
// ---------------------------------------------------------------------------

func (h *Handler) serveGraphQL(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "graphql")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/batch"):
		return h.serveGraphQLBatch(w, r)
	case strings.HasSuffix(path, "/depth"):
		return h.serveGraphQLDepth(w, r)
	default:
		// Introspection endpoint
		return h.serveGraphQLIntrospection(w, r)
	}
}

func (h *Handler) serveGraphQLIntrospection(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	schema := `{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"user","args":[{"name":"id","type":{"name":"Int"}}],"type":{"name":"User"}},{"name":"users","args":[{"name":"limit","type":{"name":"Int"}},{"name":"offset","type":{"name":"Int"}}],"type":{"name":"[User]"}},{"name":"admin","args":[],"type":{"name":"AdminPanel"}},{"name":"secret","args":[],"type":{"name":"Secret"}},{"name":"internalConfig","args":[],"type":{"name":"Config"}}]},{"kind":"OBJECT","name":"Mutation","fields":[{"name":"deleteUser","args":[{"name":"id","type":{"name":"Int"}}],"type":{"name":"Boolean"}},{"name":"updateRole","args":[{"name":"id","type":{"name":"Int"}},{"name":"role","type":{"name":"String"}}],"type":{"name":"User"}},{"name":"resetPassword","args":[{"name":"email","type":{"name":"String"}}],"type":{"name":"Boolean"}}]},{"kind":"OBJECT","name":"User","fields":[{"name":"id","type":{"name":"Int"}},{"name":"email","type":{"name":"String"}},{"name":"password_hash","type":{"name":"String"}},{"name":"ssn","type":{"name":"String"}},{"name":"role","type":{"name":"String"}},{"name":"api_key","type":{"name":"String"}}]},{"kind":"OBJECT","name":"AdminPanel","fields":[{"name":"users","type":{"name":"[User]"}},{"name":"config","type":{"name":"Config"}},{"name":"logs","type":{"name":"[LogEntry]"}}]},{"kind":"OBJECT","name":"Secret","fields":[{"name":"api_keys","type":{"name":"[String]"}},{"name":"db_password","type":{"name":"String"}},{"name":"jwt_secret","type":{"name":"String"}}]},{"kind":"OBJECT","name":"Config","fields":[{"name":"debug","type":{"name":"Boolean"}},{"name":"database_url","type":{"name":"String"}},{"name":"secret_key","type":{"name":"String"}}]}]}}}` //nolint:lll

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, schema)
	return http.StatusOK
}

func (h *Handler) serveGraphQLBatch(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath("/vuln/graphql/batch")

	// Simulate batch query response (array of results)
	var results []string
	for i := 0; i < 5; i++ {
		results = append(results, fmt.Sprintf(`{"data":{"user":{"id":%d,"email":"%s","role":"admin","api_key":"sk_%s"}}}`,
			i+1, h.randomEmail(rng), h.randomHex(rng, 16)))
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "[%s]", strings.Join(results, ","))
	return http.StatusOK
}

func (h *Handler) serveGraphQLDepth(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	rng := h.rngFromPath("/vuln/graphql/depth")

	email := h.randomEmail(rng)
	// Deeply nested response — no depth limiting
	resp := fmt.Sprintf(`{"data":{"user":{"id":1,"email":"%s","friends":[{"id":2,"email":"friend1@example.com","friends":[{"id":3,"email":"friend2@example.com","friends":[{"id":4,"email":"friend3@example.com","friends":[{"id":5,"email":"friend4@example.com","friends":[{"id":6,"email":"friend5@example.com","friends":[{"id":7,"email":"deep@example.com","secret":{"api_key":"sk_%s","db_password":"Pr0d_DB!2024"}}]}]}]}]}]}]}}}`,
		email, h.randomHex(rng, 16))

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 12. JWT Vulnerabilities
// ---------------------------------------------------------------------------

func (h *Handler) serveJWT(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "jwt")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/none"):
		return h.serveJWTNone(w, r)
	case strings.HasSuffix(path, "/weak"):
		return h.serveJWTWeak(w, r)
	case strings.HasSuffix(path, "/kid"):
		return h.serveJWTKid(w, r)
	case strings.HasSuffix(path, "/jwks"):
		return h.serveJWTJWKS(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>JWT Vulnerability Demos</h2>
<ul>
  <li><a href="/vuln/jwt/none">/vuln/jwt/none</a> — JWT with alg:none</li>
  <li><a href="/vuln/jwt/weak">/vuln/jwt/weak</a> — JWT signed with weak key "secret"</li>
  <li><a href="/vuln/jwt/kid">/vuln/jwt/kid</a> — JWT with kid: /dev/null</li>
  <li><a href="/vuln/jwt/jwks">/vuln/jwt/jwks</a> — Fake JWKS endpoint</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("JWT Vulnerabilities", body))
		return http.StatusOK
	}
}

func (h *Handler) serveJWTNone(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	claims := map[string]interface{}{
		"sub":   "1",
		"name":  "Admin User",
		"email": "admin@glitchapp.internal",
		"role":  "superadmin",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(720 * time.Hour).Unix(),
	}

	token := fakeJWT(claims) // alg:none from owasp.go

	resp := toJSON(map[string]interface{}{
		"token":      token,
		"algorithm":  "none",
		"warning":    "JWT uses alg:none — no signature verification",
		"decoded":    claims,
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveJWTWeak(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	header := `{"alg":"HS256","typ":"JWT"}`
	claims := fmt.Sprintf(`{"sub":"1","name":"Admin User","role":"superadmin","iat":%d,"exp":%d}`,
		time.Now().Unix(), time.Now().Add(720*time.Hour).Unix())

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(claims))
	signingInput := headerB64 + "." + claimsB64

	// Sign with the weak key "secret"
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := signingInput + "." + sig

	resp := toJSON(map[string]interface{}{
		"token":        token,
		"algorithm":    "HS256",
		"signing_key":  "secret",
		"warning":      "JWT signed with trivially guessable key: 'secret'",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveJWTKid(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	header := `{"alg":"HS256","typ":"JWT","kid":"/dev/null"}`
	claims := fmt.Sprintf(`{"sub":"1","name":"Admin User","role":"superadmin","iat":%d,"exp":%d}`,
		time.Now().Unix(), time.Now().Add(720*time.Hour).Unix())

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	claimsB64 := base64.RawURLEncoding.EncodeToString([]byte(claims))
	signingInput := headerB64 + "." + claimsB64

	// Sign with empty key (content of /dev/null)
	mac := hmac.New(sha256.New, []byte(""))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := signingInput + "." + sig

	resp := toJSON(map[string]interface{}{
		"token":     token,
		"algorithm": "HS256",
		"kid":       "/dev/null",
		"warning":   "JWT kid header points to /dev/null — signing key is empty",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveJWTJWKS(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	jwks := `{"keys":[{"kty":"RSA","kid":"glitchapp-key-1","use":"sig","alg":"RS256","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"},{"kty":"RSA","kid":"glitchapp-key-2","use":"sig","alg":"RS256","n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q","e":"AQAB"}]}` //nolint:lll

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, jwks)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 13. Race Condition
// ---------------------------------------------------------------------------

func (h *Handler) serveRace(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "race-condition")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/coupon"):
		return h.serveRaceCoupon(w, r)
	case strings.HasSuffix(path, "/transfer"):
		return h.serveRaceTransfer(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>Race Condition Demos</h2>
<ul>
  <li><a href="/vuln/race/coupon">/vuln/race/coupon</a> — apply coupon (no rate limiting)</li>
  <li><a href="/vuln/race/transfer">/vuln/race/transfer</a> — fund transfer (no locking)</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Race Condition", body))
		return http.StatusOK
	}
}

func (h *Handler) serveRaceCoupon(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	coupon := r.URL.Query().Get("code")
	if coupon == "" {
		coupon = "DISCOUNT50"
	}

	resp := toJSON(map[string]interface{}{
		"status":   "applied",
		"coupon":   coupon,
		"discount": "50%",
		"message":  "Coupon applied successfully",
		"warning":  "No rate limiting or single-use enforcement — coupon can be applied multiple times via race condition",
		"order": map[string]interface{}{
			"subtotal": "100.00",
			"discount": "50.00",
			"total":    "50.00",
		},
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveRaceTransfer(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	amount := r.URL.Query().Get("amount")
	if amount == "" {
		amount = "100"
	}

	resp := toJSON(map[string]interface{}{
		"status":  "completed",
		"amount":  amount,
		"from":    "account_001",
		"to":      "account_002",
		"balance": "900.00",
		"warning": "No database locking — concurrent requests can overdraw the account (TOCTOU race)",
		"note":    "Send multiple simultaneous requests to exploit: balance is read before deduction is applied",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 14. Insecure Deserialization Extended
// ---------------------------------------------------------------------------

func (h *Handler) serveDeserialize(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "insecure-deserialization")
	path := r.URL.Path

	switch {
	case strings.HasSuffix(path, "/java"):
		return h.serveDeserializeJava(w, r)
	case strings.HasSuffix(path, "/python"):
		return h.serveDeserializePython(w, r)
	case strings.HasSuffix(path, "/php"):
		return h.serveDeserializePHP(w, r)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		body := `<h2>Insecure Deserialization Demos</h2>
<ul>
  <li><b>POST /vuln/deserialize/java</b> — Java serialized object (aced0005 magic bytes)</li>
  <li><b>POST /vuln/deserialize/python</b> — Python pickle data</li>
  <li><b>POST /vuln/deserialize/php</b> — PHP serialized data</li>
</ul>`
		fmt.Fprint(w, h.wrapHTML("Insecure Deserialization", body))
		return http.StatusOK
	}
}

func (h *Handler) serveDeserializeJava(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	payload := ""
	if r.Body != nil && r.ContentLength > 0 {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		payload = fmt.Sprintf("%x", buf[:n])
	}
	if payload == "" {
		payload = "aced00057372001e636f6d2e6578616d706c652e557365720000000000000001"
	}

	hasJavaMagic := strings.HasPrefix(payload, "aced0005")

	resp := toJSON(map[string]interface{}{
		"status":         "deserialized",
		"format":         "java-serialized-object",
		"magic_bytes":    "aced0005",
		"magic_detected": hasJavaMagic,
		"raw_hex":        payload,
		"result": map[string]interface{}{
			"class":      "com.example.User",
			"serialVersionUID": "1",
			"fields": map[string]interface{}{
				"username": "admin",
				"role":     "SUPERADMIN",
				"cmd":      "Runtime.getRuntime().exec('id')",
			},
		},
		"warning": "Java deserialization without type whitelist — vulnerable to gadget chains (Commons Collections, etc.)",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveDeserializePython(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	payload := ""
	if r.Body != nil && r.ContentLength > 0 {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		payload = string(buf[:n])
	}
	if payload == "" {
		payload = "cos\nsystem\n(S'id'\ntR."
	}

	resp := toJSON(map[string]interface{}{
		"status":  "unpickled",
		"format":  "python-pickle",
		"input":   payload,
		"result": map[string]interface{}{
			"type":       "os.system",
			"args":       "id",
			"output":     "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
			"returncode": 0,
		},
		"warning": "Python pickle.loads() called on untrusted input — arbitrary code execution possible",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

func (h *Handler) serveDeserializePHP(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")

	payload := ""
	if r.Body != nil && r.ContentLength > 0 {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		payload = string(buf[:n])
	}
	if payload == "" {
		payload = `O:4:"User":3:{s:4:"name";s:5:"admin";s:4:"role";s:10:"superadmin";s:3:"cmd";s:9:"phpinfo()";}`
	}

	resp := toJSON(map[string]interface{}{
		"status":  "unserialized",
		"format":  "php-serialized",
		"input":   payload,
		"result": map[string]interface{}{
			"class":      "User",
			"properties": map[string]interface{}{
				"name": "admin",
				"role": "superadmin",
				"cmd":  "phpinfo()",
			},
			"magic_methods_called": []string{"__wakeup()", "__toString()"},
		},
		"warning": "unserialize() called on untrusted input — __wakeup() and __destruct() may execute arbitrary code",
	})

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, resp)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// 15. Path Normalization
// ---------------------------------------------------------------------------

func (h *Handler) servePathNorm(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln-Type", "path-normalization")

	// Get the raw path (before Go normalizes it)
	rawPath := r.URL.RawPath
	if rawPath == "" {
		rawPath = r.URL.Path
	}

	// Decode common path traversal patterns
	decoded, _ := url.PathUnescape(rawPath)

	// Check for traversal patterns
	traversalPatterns := []string{
		"..", "%2e%2e", "%2e.", ".%2e", "..%2f", "%2f..",
		"....//", "..;/",
	}

	isTraversal := false
	for _, pattern := range traversalPatterns {
		if strings.Contains(strings.ToLower(decoded), pattern) || strings.Contains(strings.ToLower(rawPath), pattern) {
			isTraversal = true
			break
		}
	}
	// Also check for explicit /etc/passwd references
	if strings.Contains(decoded, "etc/passwd") || strings.Contains(decoded, "etc\\passwd") {
		isTraversal = true
	}

	if isTraversal {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, fakePasswd())
		return http.StatusOK
	}

	// No traversal detected — show info page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := fmt.Sprintf(`<h2>Path Normalization Demos</h2>
<p>Current raw path: <code>%s</code></p>
<p>Decoded path: <code>%s</code></p>
<h3>Test URLs</h3>
<ul>
  <li><code>/vuln/path/..%%2f..%%2fetc/passwd</code> — double-encoded traversal</li>
  <li><code>/vuln/path/....//....//etc/passwd</code> — dot-segment bypass</li>
  <li><code>/vuln/path/..%%252f..%%252fetc/passwd</code> — triple-encoded</li>
</ul>`, rawPath, decoded)
	fmt.Fprint(w, h.wrapHTML("Path Normalization", body))
	return http.StatusOK
}
