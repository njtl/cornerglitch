package oauth

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// jwtSecret is the HMAC-SHA256 signing key for fake JWTs.
const jwtSecret = "glitch-secret-key"

// Handler emulates full OAuth2/SSO authorization flows.
type Handler struct {
	issuerBase string
}

// NewHandler creates a new OAuth handler.
func NewHandler() *Handler {
	return &Handler{}
}

// ShouldHandle returns true for OAuth, OIDC, SAML, and social login endpoints.
func (h *Handler) ShouldHandle(path string) bool {
	if strings.HasPrefix(path, "/oauth/") {
		return true
	}
	if strings.HasPrefix(path, "/saml/") {
		return true
	}
	switch path {
	case "/.well-known/openid-configuration", "/.well-known/jwks.json":
		return true
	case "/auth/google", "/auth/github", "/auth/facebook":
		return true
	}
	return false
}

// ServeHTTP dispatches OAuth/SSO requests and returns the HTTP status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	// Derive issuer base URL from the request Host header so all URLs are self-referential.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	h.issuerBase = fmt.Sprintf("%s://%s", scheme, r.Host)

	path := r.URL.Path

	switch {
	// OAuth2 Authorization Code Flow
	case path == "/oauth/authorize" && r.Method == http.MethodGet:
		return h.serveAuthorizePage(w, r)
	case path == "/oauth/authorize" && r.Method == http.MethodPost:
		return h.processAuthorize(w, r)
	case path == "/oauth/token" && r.Method == http.MethodPost:
		return h.serveToken(w, r)
	case path == "/oauth/token" && r.Method == http.MethodGet:
		return h.serveTokenInfo(w, r)
	case path == "/oauth/callback":
		return h.serveCallback(w, r)
	case path == "/oauth/userinfo":
		return h.serveUserInfo(w, r)

	// OpenID Connect Discovery
	case path == "/.well-known/openid-configuration":
		return h.serveOIDCDiscovery(w, r)
	case path == "/.well-known/jwks.json":
		return h.serveJWKSResponse(w, r)

	// SAML Endpoints
	case path == "/saml/metadata":
		return h.serveSAMLMetadata(w, r)
	case path == "/saml/sso":
		return h.serveSAMLSSO(w, r)
	case path == "/saml/acs" && r.Method == http.MethodPost:
		return h.serveSAMLACS(w, r)

	// Social Login Pages
	case path == "/auth/google":
		return h.serveSocialLogin(w, r, "Google", "#4285F4", "#fff")
	case path == "/auth/github":
		return h.serveSocialLogin(w, r, "GitHub", "#24292e", "#fff")
	case path == "/auth/facebook":
		return h.serveSocialLogin(w, r, "Facebook", "#1877F2", "#fff")
	}

	http.NotFound(w, r)
	return http.StatusNotFound
}

// ---------------------------------------------------------------------------
// OAuth2 Authorization Code Flow
// ---------------------------------------------------------------------------

func (h *Handler) serveAuthorizePage(w http.ResponseWriter, r *http.Request) int {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		clientID = "glitch-app-" + randHex(4)
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.issuerBase + "/oauth/callback"
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "openid profile email"
	}
	state := q.Get("state")
	if state == "" {
		state = randHex(16)
	}

	scopes := strings.Fields(scope)

	var scopeItems strings.Builder
	for _, s := range scopes {
		desc := scopeDescription(s)
		scopeItems.WriteString(fmt.Sprintf(
			`<li style="padding:8px 0;border-bottom:1px solid #eee">
				<strong style="text-transform:capitalize">%s</strong>
				<br><span style="color:#666;font-size:13px">%s</span>
			</li>`, s, desc))
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authorize %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:420px;max-width:95vw;overflow:hidden}
.header{background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);padding:32px 24px;text-align:center;color:#fff}
.header h1{font-size:20px;margin-bottom:8px}
.header p{font-size:14px;opacity:.85}
.avatar{width:64px;height:64px;border-radius:50%%;background:#fff3;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:28px}
.body{padding:24px}
.body h2{font-size:16px;margin-bottom:12px;color:#333}
.scopes{list-style:none;margin-bottom:20px}
.actions{display:flex;gap:12px}
.actions button{flex:1;padding:12px;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s}
.btn-allow{background:#5c6bc0;color:#fff}
.btn-allow:hover{opacity:.9}
.btn-deny{background:#e0e0e0;color:#333}
.btn-deny:hover{background:#ccc}
.divider{text-align:center;color:#999;font-size:13px;margin:20px 0;position:relative}
.divider::before,.divider::after{content:"";position:absolute;top:50%%;width:40%%;height:1px;background:#ddd}
.divider::before{left:0}
.divider::after{right:0}
.social{display:flex;flex-direction:column;gap:10px}
.social a{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:8px;text-decoration:none;font-weight:500;font-size:14px;transition:opacity .2s}
.social a:hover{opacity:.85}
.g-btn{background:#4285F4;color:#fff}
.gh-btn{background:#24292e;color:#fff}
.fb-btn{background:#1877F2;color:#fff}
.footer{padding:16px 24px;border-top:1px solid #eee;text-align:center;font-size:12px;color:#999}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="avatar">&#128274;</div>
    <h1>%s wants to access your account</h1>
    <p>This application is requesting the following permissions</p>
  </div>
  <div class="body">
    <h2>Requested permissions</h2>
    <ul class="scopes">%s</ul>
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="%s">
      <input type="hidden" name="redirect_uri" value="%s">
      <input type="hidden" name="scope" value="%s">
      <input type="hidden" name="state" value="%s">
      <input type="hidden" name="response_type" value="code">
      <div class="actions">
        <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
        <button type="submit" name="action" value="allow" class="btn-allow">Authorize</button>
      </div>
    </form>
    <div class="divider">or sign in with</div>
    <div class="social">
      <a href="/auth/google" class="g-btn">&#9679; Continue with Google</a>
      <a href="/auth/github" class="gh-btn">&#9679; Continue with GitHub</a>
      <a href="/auth/facebook" class="fb-btn">&#9679; Continue with Facebook</a>
    </div>
  </div>
  <div class="footer">
    By authorizing, you agree to the application's Terms of Service and Privacy Policy.<br>
    Powered by GlitchAuth &mdash; OAuth 2.0 / OpenID Connect
  </div>
</div>
</body>
</html>`, clientID, clientID, scopeItems.String(),
		clientID, redirectURI, scope, state)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) processAuthorize(w http.ResponseWriter, r *http.Request) int {
	_ = r.ParseForm()

	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		redirectURI = h.issuerBase + "/oauth/callback"
	}
	state := r.FormValue("state")
	action := r.FormValue("action")

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	q := u.Query()
	if action == "deny" {
		q.Set("error", "access_denied")
		q.Set("error_description", "The resource owner denied the request")
	} else {
		code := "glitch_code_" + randHex(16)
		q.Set("code", code)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
	return http.StatusFound
}

func (h *Handler) serveToken(w http.ResponseWriter, r *http.Request) int {
	_ = r.ParseForm()

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		grantType = "authorization_code"
	}

	now := time.Now()
	accessExp := now.Add(1 * time.Hour)
	refreshExp := now.Add(24 * time.Hour)

	scope := r.FormValue("scope")
	if scope == "" {
		scope = "openid profile email"
	}

	sub := "user_" + randHex(8)
	accessClaims := map[string]interface{}{
		"iss":   h.issuerBase,
		"sub":   sub,
		"aud":   r.FormValue("client_id"),
		"exp":   accessExp.Unix(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"scope": scope,
		"jti":   "at_" + randHex(16),
		"name":  "Glitch User",
		"email": "user@glitch.example",
	}

	accessToken := signJWT(accessClaims)

	refreshClaims := map[string]interface{}{
		"iss": h.issuerBase,
		"sub": sub,
		"exp": refreshExp.Unix(),
		"iat": now.Unix(),
		"jti": "rt_" + randHex(16),
	}
	refreshToken := signJWT(refreshClaims)

	resp := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         scope,
	}

	// For authorization_code grant, include an id_token
	if grantType == "authorization_code" || grantType == "refresh_token" {
		idClaims := map[string]interface{}{
			"iss":                h.issuerBase,
			"sub":                sub,
			"aud":                r.FormValue("client_id"),
			"exp":                accessExp.Unix(),
			"iat":                now.Unix(),
			"nonce":              r.FormValue("nonce"),
			"name":               "Glitch User",
			"email":              "user@glitch.example",
			"email_verified":     true,
			"preferred_username": "glitchuser",
			"picture":            h.issuerBase + "/static/avatar.png",
		}
		resp["id_token"] = signJWT(idClaims)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
	return http.StatusOK
}

func (h *Handler) serveTokenInfo(w http.ResponseWriter, r *http.Request) int {
	info := map[string]interface{}{
		"endpoint":             h.issuerBase + "/oauth/token",
		"supported_grant_types": []string{"authorization_code", "client_credentials", "refresh_token", "password"},
		"token_type":           "Bearer",
		"description":          "Exchange authorization codes, client credentials, or refresh tokens for access tokens.",
		"documentation":        h.issuerBase + "/.well-known/openid-configuration",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
	return http.StatusOK
}

func (h *Handler) serveCallback(w http.ResponseWriter, r *http.Request) int {
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")
	state := r.URL.Query().Get("state")

	var statusMessage string
	if errParam != "" {
		statusMessage = fmt.Sprintf(
			`<div style="background:#fff3f3;border:1px solid #e53935;border-radius:8px;padding:20px;margin-bottom:20px">
				<h2 style="color:#e53935;margin-bottom:8px">Authorization Failed</h2>
				<p><strong>Error:</strong> %s</p>
				<p><strong>Description:</strong> %s</p>
			</div>`, errParam, r.URL.Query().Get("error_description"))
	} else if code != "" {
		statusMessage = fmt.Sprintf(
			`<div style="background:#f3fff3;border:1px solid #43a047;border-radius:8px;padding:20px;margin-bottom:20px">
				<h2 style="color:#43a047;margin-bottom:8px">Authorization Successful</h2>
				<p><strong>Code:</strong> <code style="background:#e8e8e8;padding:2px 6px;border-radius:4px;word-break:break-all">%s</code></p>
				<p><strong>State:</strong> <code style="background:#e8e8e8;padding:2px 6px;border-radius:4px">%s</code></p>
			</div>
			<form method="POST" action="/oauth/token" id="exchange-form">
				<input type="hidden" name="grant_type" value="authorization_code">
				<input type="hidden" name="code" value="%s">
				<input type="hidden" name="redirect_uri" value="%s/oauth/callback">
				<button type="submit" style="background:#5c6bc0;color:#fff;border:none;border-radius:8px;padding:12px 24px;font-size:15px;font-weight:600;cursor:pointer">
					Exchange Code for Token
				</button>
			</form>`, code, state, code, h.issuerBase)
	} else {
		statusMessage = `<div style="background:#fff8e1;border:1px solid #ffa000;border-radius:8px;padding:20px">
			<h2 style="color:#ffa000;margin-bottom:8px">No Authorization Data</h2>
			<p>No code or error received. <a href="/oauth/authorize?client_id=demo-app&response_type=code&scope=openid+profile+email">Start authorization flow</a></p>
		</div>`
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OAuth Callback</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:520px;max-width:95vw;padding:32px}
h1{font-size:20px;margin-bottom:20px;color:#333}
code{font-family:"SF Mono",Monaco,Consolas,monospace;font-size:13px}
</style>
</head>
<body>
<div class="card">
  <h1>OAuth 2.0 Callback</h1>
  %s
</div>
</body>
</html>`, statusMessage)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveUserInfo(w http.ResponseWriter, r *http.Request) int {
	// Accept any Bearer token (this is a fake server)
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="glitch"`)
		http.Error(w, `{"error":"invalid_token","error_description":"Bearer token required"}`, http.StatusUnauthorized)
		return http.StatusUnauthorized
	}

	userInfo := map[string]interface{}{
		"sub":                "glitch_user_" + randHex(8),
		"name":               "Glitch User",
		"given_name":         "Glitch",
		"family_name":        "User",
		"preferred_username": "glitchuser",
		"email":              "user@glitch.example",
		"email_verified":     true,
		"picture":            h.issuerBase + "/static/avatar.png",
		"locale":             "en-US",
		"zoneinfo":           "America/New_York",
		"updated_at":         time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// OpenID Connect Discovery
// ---------------------------------------------------------------------------

func (h *Handler) serveOIDCDiscovery(w http.ResponseWriter, _ *http.Request) int {
	doc := map[string]interface{}{
		"issuer":                                h.issuerBase,
		"authorization_endpoint":                h.issuerBase + "/oauth/authorize",
		"token_endpoint":                        h.issuerBase + "/oauth/token",
		"userinfo_endpoint":                     h.issuerBase + "/oauth/userinfo",
		"jwks_uri":                              h.issuerBase + "/.well-known/jwks.json",
		"registration_endpoint":                 h.issuerBase + "/oauth/register",
		"scopes_supported":                      []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "implicit", "client_credentials", "refresh_token", "password"},
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"HS256", "RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce",
			"name", "given_name", "family_name", "preferred_username",
			"email", "email_verified", "picture", "locale", "zoneinfo",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
		"service_documentation":            h.issuerBase + "/docs/oauth",
		"end_session_endpoint":             h.issuerBase + "/oauth/logout",
		"revocation_endpoint":              h.issuerBase + "/oauth/revoke",
		"introspection_endpoint":           h.issuerBase + "/oauth/introspect",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(doc)
	return http.StatusOK
}

// serveJWKSResponse serves a fake but properly structured JWKS document.
func (h *Handler) serveJWKSResponse(w http.ResponseWriter, _ *http.Request) int {
	// Fake RSA public key components (properly base64url-encoded, structurally valid JWKS)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "glitch-key-1",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_" +
					"BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0" +
					"_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI" +
					"4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB",
			},
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "glitch-key-2",
				"n": "sXchDaQebHnPiGvhGPEQBGrDAtxSJ1hMHxb8kMPCtMzLFqS5tUGLAKrhUOo2DKPbzC9F3PRxYmLJ1xOdo7ok5g" +
					"G6ToBBNE_GMBY4lcz-dM5Xh1r3RMPXVLVQ5jSlV_A7RzQfkHpLE0IRkvPRRxRoCOksGxZ3GFE5HxZGxSQu9O" +
					"S0b2-fYrVZa4xRZIwACZDJ2MIm0OOHm3bMglXbIBqZkJc8K0x-nFNpeeKoJ3iseEMHwvCBy3HeOCbrVbEKc" +
					"oI2bFDJ7U9I7r1MJ-B_HBh_LKsz7BPPAFMBpily3_eS-dF-reFq5DJ_dJ0RopfCjhCJe6GXKx9VONy6T" +
					"HydRAbPSJ0D2w",
				"e": "AQAB",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jwks)
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// SAML Endpoints
// ---------------------------------------------------------------------------

func (h *Handler) serveSAMLMetadata(w http.ResponseWriter, _ *http.Request) int {
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="%s"
                     validUntil="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="true"
                      WantAssertionsSigned="true"
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
MIICpDCCAYwCCQDU+q0kCBMoRjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3pEhEwSxQHMcgc2FMvGMEz3VeyMFaBMGGDjERmIBd5MwKDixzpo/MPh
lUJLNiEb1FmwXzCasIhtAB7GKS4MH/xmwqlmaJYFfGmVPIQFm8fMOOGpeFk2MmE0
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                Location="%s/saml/acs"
                                index="0"
                                isDefault="true"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
                                Location="%s/saml/acs"
                                index="1"/>
  </md:SPSSODescriptor>
  <md:Organization>
    <md:OrganizationName xml:lang="en">GlitchAuth</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">GlitchAuth Identity Provider</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">%s</md:OrganizationURL>
  </md:Organization>
  <md:ContactPerson contactType="technical">
    <md:GivenName>Glitch</md:GivenName>
    <md:SurName>Admin</md:SurName>
    <md:EmailAddress>admin@glitch.example</md:EmailAddress>
  </md:ContactPerson>
</md:EntityDescriptor>`,
		h.issuerBase,
		time.Now().Add(365*24*time.Hour).Format("2006-01-02T15:04:05Z"),
		h.issuerBase,
		h.issuerBase,
		h.issuerBase)

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml))
	return http.StatusOK
}

func (h *Handler) serveSAMLSSO(w http.ResponseWriter, _ *http.Request) int {
	now := time.Now()
	assertionID := "_" + randHex(20)
	responseID := "_" + randHex(20)
	sessionIndex := "_" + randHex(16)
	issueInstant := now.UTC().Format("2006-01-02T15:04:05Z")
	notOnOrAfter := now.Add(5 * time.Minute).UTC().Format("2006-01-02T15:04:05Z")

	samlResponse := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%s" Version="2.0" IssueInstant="%s"
    Destination="%s/saml/acs">
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@glitch.example</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s/saml/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction>
        <saml:Audience>%s</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="%s">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>user@glitch.example</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="firstName"><saml:AttributeValue>Glitch</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="lastName"><saml:AttributeValue>User</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		responseID, issueInstant, h.issuerBase, h.issuerBase,
		assertionID, issueInstant, h.issuerBase,
		notOnOrAfter, h.issuerBase,
		issueInstant, notOnOrAfter, h.issuerBase,
		issueInstant, sessionIndex)

	encodedResponse := base64.StdEncoding.EncodeToString([]byte(samlResponse))

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAML SSO Redirect</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:400px;padding:32px;text-align:center}
h1{font-size:18px;color:#333;margin-bottom:12px}
p{color:#666;font-size:14px;margin-bottom:20px}
.spinner{width:40px;height:40px;border:4px solid #e0e0e0;border-top:4px solid #5c6bc0;border-radius:50%%;animation:spin 1s linear infinite;margin:0 auto 20px}
@keyframes spin{0%%{transform:rotate(0deg)}100%%{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>Completing Single Sign-On</h1>
  <p>Redirecting you to the application...</p>
  <form method="POST" action="%s/saml/acs" id="saml-form">
    <input type="hidden" name="SAMLResponse" value="%s">
    <input type="hidden" name="RelayState" value="%s">
    <noscript>
      <button type="submit" style="background:#5c6bc0;color:#fff;border:none;border-radius:8px;padding:12px 24px;font-size:15px;cursor:pointer">Continue</button>
    </noscript>
  </form>
  <script>document.getElementById('saml-form').submit();</script>
</div>
</body>
</html>`, h.issuerBase, encodedResponse, h.issuerBase)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (h *Handler) serveSAMLACS(w http.ResponseWriter, r *http.Request) int {
	_ = r.ParseForm()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAML Login Successful</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:480px;max-width:95vw;overflow:hidden}
.header{background:linear-gradient(135deg,#43a047 0%%,#2e7d32 100%%);padding:32px 24px;text-align:center;color:#fff}
.header h1{font-size:22px;margin-bottom:8px}
.check{font-size:48px;margin-bottom:16px}
.body{padding:24px}
.body table{width:100%%;border-collapse:collapse}
.body td{padding:10px 8px;border-bottom:1px solid #eee;font-size:14px}
.body td:first-child{font-weight:600;color:#555;width:140px}
.body td:last-child{color:#333;word-break:break-all}
.footer{padding:16px 24px;border-top:1px solid #eee;text-align:center}
.footer a{color:#5c6bc0;text-decoration:none;font-size:14px}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="check">&#10003;</div>
    <h1>SAML Login Successful</h1>
    <p>You have been authenticated via SAML 2.0 SSO</p>
  </div>
  <div class="body">
    <table>
      <tr><td>Name</td><td>Glitch User</td></tr>
      <tr><td>Email</td><td>user@glitch.example</td></tr>
      <tr><td>Role</td><td>admin</td></tr>
      <tr><td>Session</td><td>%s</td></tr>
      <tr><td>Auth Time</td><td>%s</td></tr>
      <tr><td>IdP</td><td>%s</td></tr>
    </table>
  </div>
  <div class="footer">
    <a href="/">Return to application</a>
  </div>
</div>
</body>
</html>`, randHex(16), time.Now().UTC().Format(time.RFC3339), h.issuerBase)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Social Login Pages
// ---------------------------------------------------------------------------

func (h *Handler) serveSocialLogin(w http.ResponseWriter, _ *http.Request, provider, bgColor, fgColor string) int {
	// Each social provider gets a unique accent and logo placeholder.
	var logoSVG string
	switch provider {
	case "Google":
		logoSVG = `<svg viewBox="0 0 48 48" width="24" height="24"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59A14.5 14.5 0 019.5 24c0-1.59.28-3.14.77-4.59l-7.98-6.19A23.97 23.97 0 000 24c0 3.77.87 7.36 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`
	case "GitHub":
		logoSVG = `<svg viewBox="0 0 24 24" width="24" height="24" fill="white"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>`
	case "Facebook":
		logoSVG = `<svg viewBox="0 0 24 24" width="24" height="24" fill="white"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in with %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:%s;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.2);width:400px;max-width:95vw;overflow:hidden}
.brand{background:%s;padding:32px 24px;text-align:center;color:%s}
.brand .logo{margin-bottom:16px}
.brand h1{font-size:22px;margin-bottom:4px}
.brand p{font-size:14px;opacity:.8}
.form-body{padding:28px 24px}
.form-body label{display:block;font-size:13px;font-weight:600;color:#555;margin-bottom:6px}
.form-body input[type=email],.form-body input[type=password]{width:100%%;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:15px;margin-bottom:16px;transition:border-color .2s}
.form-body input:focus{border-color:%s;outline:none;box-shadow:0 0 0 3px %s33}
.form-body button{width:100%%;padding:14px;background:%s;color:%s;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:opacity .2s}
.form-body button:hover{opacity:.9}
.extras{text-align:center;margin-top:16px;font-size:13px;color:#888}
.extras a{color:%s;text-decoration:none}
.footer{padding:16px 24px;border-top:1px solid #eee;text-align:center;font-size:12px;color:#aaa}
</style>
</head>
<body>
<div class="card">
  <div class="brand">
    <div class="logo">%s</div>
    <h1>Sign in with %s</h1>
    <p>Use your %s account to continue</p>
  </div>
  <div class="form-body">
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="provider" value="%s">
      <input type="hidden" name="action" value="allow">
      <input type="hidden" name="redirect_uri" value="/oauth/callback">
      <input type="hidden" name="state" value="%s">
      <label for="email">Email address</label>
      <input type="email" id="email" name="email" placeholder="you@example.com" value="user@glitch.example">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter your password" value="glitchpass123">
      <button type="submit">Sign in</button>
    </form>
    <div class="extras">
      <a href="#">Forgot password?</a> &middot; <a href="#">Create account</a>
    </div>
  </div>
  <div class="footer">
    This is a simulated %s login page for testing purposes.<br>
    No real authentication occurs. Powered by GlitchAuth.
  </div>
</div>
</body>
</html>`,
		provider, "#f0f2f5",
		bgColor, fgColor,
		bgColor, bgColor,
		bgColor, fgColor,
		bgColor,
		logoSVG, provider, provider,
		strings.ToLower(provider), randHex(16),
		provider)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// JWT Helpers
// ---------------------------------------------------------------------------

// signJWT creates an HS256-signed JWT from the given claims.
func signJWT(claims map[string]interface{}) string {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64URLEncode(headerJSON)
	claimsB64 := base64URLEncode(claimsJSON)

	signingInput := headerB64 + "." + claimsB64

	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	sigB64 := base64URLEncode(sig)

	return signingInput + "." + sigB64
}

// base64URLEncode encodes data using base64url encoding without padding, per RFC 7515.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// ---------------------------------------------------------------------------
// Utility Helpers
// ---------------------------------------------------------------------------

// randHex returns a random hex string of n bytes (2n hex characters).
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

// scopeDescription returns a human-readable description for an OAuth scope.
func scopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Verify your identity"
	case "profile":
		return "Access your basic profile information (name, avatar)"
	case "email":
		return "View your email address"
	case "address":
		return "View your mailing address"
	case "phone":
		return "View your phone number"
	case "offline_access":
		return "Maintain access when you are not actively using the app"
	case "read":
		return "Read access to your resources"
	case "write":
		return "Write access to your resources"
	case "admin":
		return "Full administrative access"
	default:
		return "Access to " + scope
	}
}
