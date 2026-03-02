package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/glitchWebServer/internal/audit"
)

// ---------------------------------------------------------------------------
// Password configuration
// ---------------------------------------------------------------------------

var (
	adminPasswordMu sync.RWMutex
	adminPassword   string
)

// SetAdminPassword sets the admin panel password.
func SetAdminPassword(password string) {
	adminPasswordMu.Lock()
	defer adminPasswordMu.Unlock()
	adminPassword = password
}

// getAdminPassword returns the current admin password, generating one if not set.
func getAdminPassword() string {
	adminPasswordMu.RLock()
	pw := adminPassword
	adminPasswordMu.RUnlock()
	if pw != "" {
		return pw
	}

	// Generate a random password.
	adminPasswordMu.Lock()
	defer adminPasswordMu.Unlock()
	if adminPassword != "" {
		return adminPassword
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		adminPassword = "glitch-admin-changeme"
	} else {
		adminPassword = hex.EncodeToString(b)[:16]
	}
	fmt.Fprintf(os.Stderr, "\033[33m[glitch]\033[0m Admin password (auto-generated): %s\n", adminPassword)
	return adminPassword
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

const (
	sessionCookieName = "glitch_admin_session"
	sessionTTL        = 8 * time.Hour
)

var sessions sync.Map // map[string]time.Time (token → expiry)

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func createSession(w http.ResponseWriter) {
	token, err := generateSessionToken()
	if err != nil {
		return
	}
	sessions.Store(token, time.Now().Add(sessionTTL))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func validateSession(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	val, ok := sessions.Load(cookie.Value)
	if !ok {
		return false
	}
	expiry, ok := val.(time.Time)
	if !ok || time.Now().After(expiry) {
		sessions.Delete(cookie.Value)
		return false
	}
	return true
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		sessions.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

// AuthMiddleware wraps an http.Handler and requires authentication for
// admin panel routes (/admin and /admin/api/*).
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip auth for monitoring API endpoints (used by selftest pipeline).
		if !strings.HasPrefix(path, "/admin") {
			next.ServeHTTP(w, r)
			return
		}

		// Handle login/logout endpoints.
		if path == "/admin/login" {
			handleLogin(w, r)
			return
		}
		if path == "/admin/logout" {
			handleLogout(w, r)
			return
		}

		// Check session cookie.
		if validateSession(r) {
			addSecurityHeaders(w)
			next.ServeHTTP(w, r)
			return
		}

		// Check basic auth (for CLI/programmatic access, no WWW-Authenticate header).
		_, pass, ok := r.BasicAuth()
		if ok && checkPassword(pass) {
			createSession(w)
			addSecurityHeaders(w)
			next.ServeHTTP(w, r)
			return
		}

		// Not authenticated — redirect to login (never show basic auth prompt).
		if strings.HasPrefix(path, "/admin/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required","redirect":"/admin/login"}`))
			return
		}

		http.Redirect(w, r, "/admin/login", http.StatusFound)
	})
}

func checkPassword(password string) bool {
	expected := getAdminPassword()
	return subtle.ConstantTimeCompare([]byte(password), []byte(expected)) == 1
}

func addSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
}

// ---------------------------------------------------------------------------
// Login / Logout handlers
// ---------------------------------------------------------------------------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Already authenticated? Redirect to admin.
		if validateSession(r) {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		addSecurityHeaders(w)
		w.Write([]byte(loginPage("")))
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Accept both form data and JSON.
	var password string
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		var req struct {
			Password string `json:"password"`
		}
		json.Unmarshal(body, &req)
		password = req.Password
	} else {
		r.ParseForm()
		password = r.FormValue("password")
	}

	clientIP := r.RemoteAddr
	if checkPassword(password) {
		createSession(w)
		audit.LogEntry(audit.Entry{
			Actor:    "admin",
			Action:   "auth.login",
			Resource: "auth.session",
			ClientIP: clientIP,
			Status:   "success",
		})
		if strings.Contains(contentType, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true,"redirect":"/admin"}`))
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}
		return
	}

	// Failed login.
	audit.LogEntry(audit.Entry{
		Actor:    "unknown",
		Action:   "auth.login_failed",
		Resource: "auth.session",
		ClientIP: clientIP,
		Status:   "error",
	})
	if strings.Contains(contentType, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid password"}`))
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		addSecurityHeaders(w)
		w.Write([]byte(loginPage("Invalid password")))
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	audit.LogAction("admin", "auth.logout", "auth.session", nil)
	clearSession(w, r)
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// ChangePassword validates the current password and sets a new one.
func ChangePassword(current, newPassword string) error {
	if !checkPassword(current) {
		audit.LogEntry(audit.Entry{
			Actor:    "admin",
			Action:   "auth.password_change",
			Resource: "auth.password",
			Status:   "error",
			Details:  map[string]interface{}{"reason": "incorrect current password"},
		})
		return fmt.Errorf("current password is incorrect")
	}
	SetAdminPassword(newPassword)
	// Invalidate all existing sessions
	sessions = sync.Map{}
	audit.LogAction("admin", "auth.password_change", "auth.password", nil)
	return nil
}

// ---------------------------------------------------------------------------
// Login page HTML
// ---------------------------------------------------------------------------

func loginPage(errMsg string) string {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div style="color:#f85149;margin-bottom:16px;padding:8px 12px;background:#2d1418;border:1px solid #f85149;border-radius:6px;">` + errMsg + `</div>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Glitch Admin — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#0d1117;color:#c9d1d9;font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;}
.login-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:32px;width:100%;max-width:360px;}
h1{font-size:1.4em;color:#58a6ff;margin-bottom:8px;}
p{color:#8b949e;font-size:0.9em;margin-bottom:24px;}
label{display:block;font-size:0.85em;color:#8b949e;margin-bottom:6px;}
input[type=password]{width:100%;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:1em;margin-bottom:16px;}
input[type=password]:focus{outline:none;border-color:#58a6ff;}
button{width:100%;padding:10px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:1em;cursor:pointer;font-weight:600;}
button:hover{background:#2ea043;}
</style>
</head>
<body>
<div class="login-box">
<h1>Glitch Admin</h1>
<p>Enter the admin password to continue.</p>
` + errorHTML + `
<form method="POST" action="/admin/login">
<label for="password">Password</label>
<input type="password" id="password" name="password" autofocus required>
<button type="submit">Sign In</button>
</form>
</div>
</body>
</html>`
}
