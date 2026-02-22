package framework

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// Emulator makes the glitch server appear to run on different web frameworks
// by injecting framework-specific headers, cookies, error pages, and server
// signatures. The assigned framework is deterministic per-client, derived
// from the client fingerprint hash.
type Emulator struct {
	mu              sync.RWMutex
	frameworks      []Framework
	activeFramework string // "auto" or specific framework name
}

// Framework describes the HTTP surface of a particular web stack.
type Framework struct {
	Name         string
	ServerHeader string
	PoweredBy    string
	Cookies      []Cookie
	Headers      map[string]string
	ErrorPage    func(status int) string // generates framework-specific error HTML
}

// Cookie models a Set-Cookie value template. The Value field may contain
// {session_id}, {token}, {signature}, {value}, or {uuid} placeholders
// that are resolved at apply time from the client fingerprint.
type Cookie struct {
	Name     string
	Value    string // template — can contain {session_id}, {token}, etc.
	Path     string
	HttpOnly bool
	Secure   bool
}

// NewEmulator builds an Emulator pre-loaded with 12 framework profiles.
func NewEmulator() *Emulator {
	return &Emulator{
		activeFramework: "auto",
		frameworks: []Framework{
			expressFramework(),
			djangoFramework(),
			railsFramework(),
			laravelFramework(),
			springBootFramework(),
			aspnetFramework(),
			flaskFramework(),
			fastapiFramework(),
			nextjsFramework(),
			nginxFramework(),
			apacheFramework(),
			caddyFramework(),
		},
	}
}

// ForClient deterministically selects a framework for the given clientID.
func (e *Emulator) ForClient(clientID string) *Framework {
	h := sha256.Sum256([]byte(clientID))
	// Use first two bytes as a uint16, mod framework count.
	idx := (int(h[0])<<8 | int(h[1])) % len(e.frameworks)
	fw := e.frameworks[idx]
	return &fw
}

// ForRequest deterministically selects a framework based on both clientID
// and request path, providing variety across different pages for the same client.
// If an active framework has been set (not "auto"), that framework is always returned.
func (e *Emulator) ForRequest(clientID, path string) *Framework {
	e.mu.RLock()
	af := e.activeFramework
	e.mu.RUnlock()

	if af != "" && af != "auto" {
		if fw := e.findByName(af); fw != nil {
			return fw
		}
	}
	// Original logic
	h := sha256.Sum256([]byte(clientID + "::" + path))
	idx := (int(h[0])<<8 | int(h[1])) % len(e.frameworks)
	fw := e.frameworks[idx]
	return &fw
}

// SetActiveFramework sets the active framework by name.
// Use "auto" to revert to the default deterministic selection.
func (e *Emulator) SetActiveFramework(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeFramework = name
}

// GetActiveFramework returns the current active framework setting.
func (e *Emulator) GetActiveFramework() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeFramework
}

// findByName returns a pointer to a copy of the framework matching the given
// name (case-insensitive, substring match). Returns nil if no match is found.
func (e *Emulator) findByName(name string) *Framework {
	lower := strings.ToLower(name)
	for i := range e.frameworks {
		if strings.ToLower(e.frameworks[i].Name) == lower ||
			strings.Contains(strings.ToLower(e.frameworks[i].Name), lower) {
			fw := e.frameworks[i]
			return &fw
		}
	}
	return nil
}

// FrameworkNames returns the names of all available frameworks.
func (e *Emulator) FrameworkNames() []string {
	names := make([]string, len(e.frameworks))
	for i, fw := range e.frameworks {
		names[i] = fw.Name
	}
	return names
}

// Apply sets framework-specific response headers and cookies on w.
func (e *Emulator) Apply(w http.ResponseWriter, fw *Framework, clientID string) {
	sessionID := deriveSessionID(clientID)
	token := deriveToken(clientID)
	sig := deriveSignature(clientID)
	uuid := deriveUUID(clientID)
	value := deriveValue(clientID)

	// Server header
	if fw.ServerHeader != "" {
		w.Header().Set("Server", fw.ServerHeader)
	}

	// X-Powered-By
	if fw.PoweredBy != "" {
		w.Header().Set("X-Powered-By", fw.PoweredBy)
	}

	// Extra framework headers
	for k, v := range fw.Headers {
		resolved := replacePlaceholders(v, sessionID, token, sig, uuid, value)
		w.Header().Set(k, resolved)
	}

	// Cookies
	for _, c := range fw.Cookies {
		val := replacePlaceholders(c.Value, sessionID, token, sig, uuid, value)
		cookie := &http.Cookie{
			Name:     c.Name,
			Value:    val,
			Path:     c.Path,
			HttpOnly: c.HttpOnly,
			Secure:   c.Secure,
		}
		http.SetCookie(w, cookie)
	}
}

// ErrorPage returns framework-specific error HTML for the given status code.
func (e *Emulator) ErrorPage(fw *Framework, status int) string {
	if fw.ErrorPage != nil {
		return fw.ErrorPage(status)
	}
	return fmt.Sprintf("<html><body><h1>%d</h1></body></html>", status)
}

// ---------------------------------------------------------------------------
// Deterministic derivation helpers
// ---------------------------------------------------------------------------

func deriveSessionID(clientID string) string {
	h := sha256.Sum256([]byte("session:" + clientID))
	return hex.EncodeToString(h[:16])
}

func deriveToken(clientID string) string {
	h := sha256.Sum256([]byte("token:" + clientID))
	return hex.EncodeToString(h[:20])
}

func deriveSignature(clientID string) string {
	h := sha256.Sum256([]byte("sig:" + clientID))
	return hex.EncodeToString(h[:20])
}

func deriveUUID(clientID string) string {
	h := sha256.Sum256([]byte("uuid:" + clientID))
	hex := hex.EncodeToString(h[:16])
	// Format as UUID: 8-4-4-4-12
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[4:8], hex[8:12], hex[12:16], hex[16:28])
}

func deriveValue(clientID string) string {
	h := sha256.Sum256([]byte("value:" + clientID))
	return hex.EncodeToString(h[:12])
}

func replacePlaceholders(s, sessionID, token, sig, uuid, value string) string {
	s = strings.ReplaceAll(s, "{session_id}", sessionID)
	s = strings.ReplaceAll(s, "{token}", token)
	s = strings.ReplaceAll(s, "{signature}", sig)
	s = strings.ReplaceAll(s, "{uuid}", uuid)
	s = strings.ReplaceAll(s, "{value}", value)
	return s
}

func statusText(code int) string {
	text := http.StatusText(code)
	if text == "" {
		text = "Unknown Error"
	}
	return text
}

// ---------------------------------------------------------------------------
// Framework definitions
// ---------------------------------------------------------------------------

func expressFramework() Framework {
	return Framework{
		Name:         "Express.js",
		ServerHeader: "",
		PoweredBy:    "Express",
		Headers: map[string]string{
			"X-Response-Time":          "42ms",
			"ETag":                     `W/"5ef-1a2b3c4d"`,
			"X-Content-Type-Options":   "nosniff",
		},
		Cookies: []Cookie{
			{
				Name:     "connect.sid",
				Value:    "s%3A{session_id}.{signature}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`{"error":{"message":"%s","status":%d}}`, statusText(status), status)
		},
	}
}

func djangoFramework() Framework {
	return Framework{
		Name:         "Django",
		ServerHeader: "WSGIServer/0.2 CPython/3.11.5",
		PoweredBy:    "",
		Headers: map[string]string{
			"X-Frame-Options":        "DENY",
			"X-Content-Type-Options": "nosniff",
			"Vary":                   "Accept, Cookie, Accept-Language",
			"X-Request-Id":          "{uuid}",
		},
		Cookies: []Cookie{
			{
				Name:     "csrftoken",
				Value:    "{token}",
				Path:     "/",
				HttpOnly: false,
				Secure:   false,
			},
			{
				Name:     "sessionid",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8">
  <title>%s at /</title>
  <style>
    html * { padding:0; margin:0; }
    body * { padding:10px 20px; }
    body * * { padding:0; }
    body { font:small sans-serif; }
    body>div { border-bottom:1px solid #ddd; }
    h1 { font-weight:normal; }
    #summary { background:#ffc; }
    #summary h2 { font-weight:normal; color:#666; }
    #explanation { background:#eee; }
    #traceback { background:#eee; }
    #requestinfo { background:#f6f6f6; padding-left:120px; }
    #summary table { border:none; background:transparent; }
    #requestinfo h2, #requestinfo h3 { position:relative; margin-left:-100px; }
    #requestinfo h3 { margin-bottom:-1em; }
    .hierarchical-path { font-family:monospace; color:#666; }
  </style>
</head>
<body>
<div id="summary">
  <h1>%s <span>(%d)</span></h1>
  <table class="meta">
    <tr><th>Request Method:</th><td>GET</td></tr>
    <tr><th>Request URL:</th><td>http://localhost/</td></tr>
    <tr><th>Django Version:</th><td>4.2.7</td></tr>
    <tr><th>Python Version:</th><td>3.11.5</td></tr>
  </table>
</div>
<div id="explanation">
  <p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>
</div>
</body>
</html>`, statusText(status), statusText(status), status)
		},
	}
}

func railsFramework() Framework {
	return Framework{
		Name:         "Ruby on Rails",
		ServerHeader: "Puma",
		PoweredBy:    "Phusion Passenger",
		Headers: map[string]string{
			"X-Runtime":              "0.042369",
			"X-Request-Id":          "{uuid}",
			"X-Content-Type-Options": "nosniff",
			"X-Download-Options":     "noopen",
			"X-Permitted-Cross-Domain-Policies": "none",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
			"Cache-Control":          "no-cache",
		},
		Cookies: []Cookie{
			{
				Name:     "_session_id",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>We're sorry, but something went wrong (%d)</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    body {
      background-color: #EFEFEF;
      color: #2E2F30;
      text-align: center;
      font-family: arial, sans-serif;
      margin: 0;
    }
    div.dialog {
      width: 95%%;
      max-width: 33em;
      margin: 4em auto 0;
    }
    div.dialog > div {
      border: 1px solid #CCC;
      border-right-color: #999;
      border-left-color: #999;
      border-bottom-color: #BBB;
      border-top: #B00100 solid 4px;
      border-top-left-radius: 9px;
      border-top-right-radius: 9px;
      background-color: white;
      padding: 7px 12%% 0;
      box-shadow: 0 3px 8px rgba(50, 50, 50, 0.17);
    }
    h1 {
      font-size: 100%%;
      color: #730E15;
      line-height: 1.5em;
    }
    div.dialog > p {
      margin: 0 0 1em;
      padding: 1em;
      background-color: #F7F7F7;
      border: 1px solid #CCC;
      border-right-color: #999;
      border-left-color: #999;
      border-bottom-color: #999;
      border-bottom-left-radius: 4px;
      border-bottom-right-radius: 4px;
      border-top-color: #DADADA;
      color: #666;
      box-shadow: 0 3px 8px rgba(50, 50, 50, 0.17);
    }
  </style>
</head>
<body>
  <div class="dialog">
    <div>
      <h1>We're sorry, but something went wrong.</h1>
    </div>
    <p>If you are the application owner check the logs for more information.</p>
  </div>
</body>
</html>`, status)
		},
	}
}

func laravelFramework() Framework {
	return Framework{
		Name:         "Laravel",
		ServerHeader: "Apache/2.4.52 (Ubuntu)",
		PoweredBy:    "PHP/8.2.0",
		Headers: map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Cache-Control":          "no-cache, private",
		},
		Cookies: []Cookie{
			{
				Name:     "laravel_session",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
			{
				Name:     "XSRF-TOKEN",
				Value:    "{token}",
				Path:     "/",
				HttpOnly: false,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>%s | %d</title>
    <style>
        body {
            font-family: 'Nunito', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
        }
        .container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .content {
            text-align: center;
        }
        .title {
            font-size: 36px;
            color: #636b6f;
            padding: 20px;
        }
        .code {
            font-size: 128px;
            font-weight: bold;
            color: #e3342f;
            border-right: 2px solid #e3342f;
            padding-right: 30px;
            margin-right: 30px;
            display: inline-block;
        }
        .message {
            font-size: 24px;
            color: #636b6f;
            display: inline-block;
            text-align: left;
            vertical-align: middle;
        }
        .whoops {
            font-size: 18px;
            color: #999;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <div>
                <span class="code">%d</span>
                <span class="message">%s</span>
            </div>
            <p class="whoops">Whoops, looks like something went wrong.</p>
            <p class="whoops">Laravel v10.28.0 (PHP v8.2.0)</p>
        </div>
    </div>
</body>
</html>`, statusText(status), status, status, statusText(status))
		},
	}
}

func springBootFramework() Framework {
	return Framework{
		Name:         "Spring Boot",
		ServerHeader: "Apache-Coyote/1.1",
		PoweredBy:    "",
		Headers: map[string]string{
			"X-Application-Context": "application",
			"X-Content-Type-Options": "nosniff",
			"X-XSS-Protection":      "1; mode=block",
			"Cache-Control":          "no-cache, no-store, max-age=0, must-revalidate",
			"Pragma":                 "no-cache",
			"Expires":                "0",
		},
		Cookies: []Cookie{
			{
				Name:     "JSESSIONID",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<html>
<body>
<h1>Whitelabel Error Page</h1>
<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>
<div id='created'>Thu Feb 20 14:32:17 UTC 2026</div>
<div>There was an unexpected error (type=%s, status=%d).</div>
<div>%s</div>
</body>
</html>`, statusText(status), status, statusText(status))
		},
	}
}

func aspnetFramework() Framework {
	return Framework{
		Name:         "ASP.NET",
		ServerHeader: "Microsoft-IIS/10.0",
		PoweredBy:    "ASP.NET",
		Headers: map[string]string{
			"X-AspNet-Version":       "4.0.30319",
			"X-AspNetMvc-Version":    "5.2",
			"X-SourceFiles":          "=?UTF-8?B?QzpcaW5ldHB1Ylx3d3dyb290?=",
			"X-Content-Type-Options": "nosniff",
			"X-XSS-Protection":      "1; mode=block",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		},
		Cookies: []Cookie{
			{
				Name:     "ASP.NET_SessionId",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
			{
				Name:     ".AspNetCore.Antiforgery.{token}",
				Value:    "{value}",
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>IIS 10.0 Detailed Error - %d.0 - %s</title>
<style type="text/css">
body { margin:0; font-size:.7em; font-family:Verdana,Arial,Helvetica,sans-serif; background:#CBE1EF; }
.content-container { background:#fff; width:96%%; margin-top:0; padding:0 2%%; border:1px solid #DCDCDC; }
fieldset { padding:0 15px 10px 15px; }
h1 { font-size:2.4em; margin:0; color:#FCC000; }
h2 { font-size:1.7em; margin:0; color:#CC0000; }
h3 { font-size:1.2em; margin:10px 0 0 0; color:#000000; }
#header { width:96%%; margin:0 0 0 0; padding:6px 2%% 6px 2%%; font-family:"trebuchet MS",Verdana,sans-serif; color:#FFF; background-color:#5C87B2; }
#content { margin:0 0 0 2%%; position:relative; }
.heading1 { background-color:#EB5E00; width:100%%; }
.config_source code { font-size:.8em; color:#000000; }
ul,ol { margin:10px 0 10px 40px; }
table { margin:10px 0 10px 2%%; }
td,th { vertical-align:top; padding:3px; }
</style>
</head>
<body>
<div id="header"><h1>Server Error</h1></div>
<div id="content">
  <div class="content-container">
    <fieldset>
      <h2>HTTP Error %d.0 - %s</h2>
      <h3>The page cannot be displayed because an internal server error has occurred.</h3>
    </fieldset>
  </div>
  <div class="content-container">
    <fieldset>
      <h4>Most likely causes:</h4>
      <ul>
        <li>The website is under maintenance.</li>
        <li>The website has a programming error.</li>
      </ul>
    </fieldset>
  </div>
  <div class="content-container">
    <fieldset>
      <h4>Detailed Error Information:</h4>
      <table>
        <tr><th>Module</th><td>ManagedPipelineHandler</td></tr>
        <tr><th>Notification</th><td>ExecuteRequestHandler</td></tr>
        <tr><th>Handler</th><td>System.Web.Mvc.MvcHandler</td></tr>
        <tr><th>Error Code</th><td>0x00000000</td></tr>
      </table>
    </fieldset>
  </div>
  <div class="content-container">
    <fieldset>
      <h4>More Information:</h4>
      <p>This error means that there was a problem while processing the request. The request was received by the Web server, but during processing a fatal condition was encountered, causing the server to return this %d status.</p>
      <p><a href="https://go.microsoft.com/fwlink/?LinkID=62293&amp;IIS70Error=%d,0,0,0,0">Microsoft Knowledge Base Article</a></p>
    </fieldset>
  </div>
</div>
</body>
</html>`, status, statusText(status), status, statusText(status), status, status)
		},
	}
}

func flaskFramework() Framework {
	return Framework{
		Name:         "Flask",
		ServerHeader: "Werkzeug/2.3.7 Python/3.11.5",
		PoweredBy:    "",
		Headers: map[string]string{
			"Vary": "Cookie",
		},
		Cookies: []Cookie{
			{
				Name:     "session",
				Value:    "eyJfcGVybWFuZW50Ijp0cnVlLCJjc3JmX3Rva2VuIjoie3Rva2VufSIsInVzZXJfaWQiOiJ7c2Vzc2lvbl9pZH0ifQ.{signature}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
  "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <title>%s // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css" type="text/css">
    <link rel="shortcut icon" href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script type="text/javascript" src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script type="text/javascript">
      var TRACEBACK = 0, CONSOLE_MODE = false, EVALEX = true,
          EVALEX_TRUSTED = false, SECRET = "not-so-secret";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
      <h1>%s</h1>
      <div class="detail">
        <p class="errormsg">%s</p>
      </div>
      <div class="plain">
        <p>
          This is the Werkzeug interactive debugger. A %d error
          was raised by the application. The debugger caught it and is
          displaying this page to help you debug the issue.
        </p>
      </div>
      <div class="footer">
        Brought to you by <strong class="resolve">DON'T PANIC</strong>, your
        friendly Werkzeug powered traceback interpreter.
      </div>
    </div>
  </body>
</html>`, statusText(status), statusText(status), statusText(status), status)
		},
	}
}

func fastapiFramework() Framework {
	return Framework{
		Name:         "FastAPI",
		ServerHeader: "uvicorn",
		PoweredBy:    "",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Cookies: []Cookie{},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`{"detail":"%s"}`, statusText(status))
		},
	}
}

func nextjsFramework() Framework {
	return Framework{
		Name:         "Next.js",
		ServerHeader: "Next.js",
		PoweredBy:    "Next.js",
		Headers: map[string]string{
			"X-Nextjs-Cache":       "HIT",
			"X-Nextjs-Matched-Path": "/",
			"Cache-Control":         "s-maxage=1, stale-while-revalidate",
		},
		Cookies: []Cookie{
			{
				Name:     "__next_auth.session-token",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta charset="utf-8"/>
<title>%d: %s</title>
<style>
body{color:#000;background:#fff;margin:0}
.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}
@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}
</style>
</head>
<body>
<div style="font-family:-apple-system,BlinkMacSystemFont,Roboto,'Segoe UI','Fira Sans',Avenir,'Helvetica Neue','Lucida Grande',sans-serif;height:100vh;text-align:center;display:flex;flex-direction:column;align-items:center;justify-content:center">
  <div>
    <style>body{color:#000;background:#fff;margin:0}.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}</style>
    <h1 class="next-error-h1" style="display:inline-block;margin:0 20px 0 0;padding:0 23px 0 0;font-size:24px;font-weight:500;vertical-align:top;line-height:49px">%d</h1>
    <div style="display:inline-block;text-align:left;line-height:49px;height:49px;vertical-align:middle">
      <h2 style="font-size:14px;font-weight:normal;line-height:49px;margin:0;padding:0">%s.</h2>
    </div>
  </div>
</div>
</body>
</html>`, status, statusText(status), status, statusText(status))
		},
	}
}

func nginxFramework() Framework {
	return Framework{
		Name:         "nginx",
		ServerHeader: "nginx/1.24.0",
		PoweredBy:    "",
		Headers: map[string]string{
			"X-Nginx-Cache": "HIT",
		},
		Cookies: []Cookie{},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<html>
<head><title>%d %s</title></head>
<body>
<center><h1>%d %s</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>`, status, statusText(status), status, statusText(status))
		},
	}
}

func apacheFramework() Framework {
	return Framework{
		Name:         "Apache",
		ServerHeader: "Apache/2.4.57 (Ubuntu)",
		PoweredBy:    "PHP/7.4.33",
		Headers: map[string]string{
			"Accept-Ranges": "bytes",
		},
		Cookies: []Cookie{
			{
				Name:     "PHPSESSID",
				Value:    "{session_id}",
				Path:     "/",
				HttpOnly: true,
				Secure:   false,
			},
		},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>%d %s</title>
</head><body>
<h1>%s</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator at
 webmaster@localhost to inform them of the time this error occurred,
 and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
<hr>
<address>Apache/2.4.57 (Ubuntu) Server at localhost Port 80</address>
</body></html>`, status, statusText(status), statusText(status))
		},
	}
}

func caddyFramework() Framework {
	return Framework{
		Name:         "Caddy",
		ServerHeader: "Caddy",
		PoweredBy:    "",
		Headers: map[string]string{
			"Alt-Svc": `h3=":443"; ma=2592000`,
		},
		Cookies: []Cookie{},
		ErrorPage: func(status int) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Error %d</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
        }
        .error {
            text-align: center;
            padding: 2em;
        }
        .error h1 {
            font-size: 8em;
            margin: 0;
            color: #22b573;
            font-weight: 200;
        }
        .error h2 {
            font-size: 1.5em;
            color: #666;
            font-weight: 400;
            margin-top: 0;
        }
        .error p {
            color: #999;
            margin-top: 2em;
        }
    </style>
</head>
<body>
    <div class="error">
        <h1>%d</h1>
        <h2>%s</h2>
        <p>Caddy &middot; Powered by Go</p>
    </div>
</body>
</html>`, status, status, statusText(status))
		},
	}
}
