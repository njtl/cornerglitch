package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Router handles all /api/ requests and dispatches to the appropriate handler.
type Router struct {
	users   *UsersAPI
	ecom    *EcommerceAPI
	infra   *InfraAPI
	cms     *CmsAPI
	forms   *FormsAPI
	swagger *SwaggerHandler
	graphql *GraphQLHandler
}

// NewRouter creates a new API router with all sub-handlers.
func NewRouter() *Router {
	r := &Router{
		users:   NewUsersAPI(),
		ecom:    NewEcommerceAPI(),
		infra:   NewInfraAPI(),
		cms:     NewCmsAPI(),
		forms:   NewFormsAPI(),
		swagger: NewSwaggerHandler(),
		graphql: NewGraphQLHandler(),
	}
	return r
}

// ShouldHandle returns true if this path should be handled by the API router.
func (rt *Router) ShouldHandle(path string) bool {
	if strings.HasPrefix(path, "/api/") {
		return true
	}
	switch path {
	case "/swagger.json", "/openapi.json", "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/",
		"/api-docs", "/api-docs/", "/graphql":
		return true
	}
	return false
}

// ServeHTTP dispatches API requests to the appropriate handler.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	// Swagger/OpenAPI
	switch path {
	case "/swagger.json", "/openapi.json":
		return rt.swagger.ServeSpec(w, r)
	case "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui/", "/api-docs", "/api-docs/":
		return rt.swagger.ServeUI(w, r)
	case "/graphql":
		return rt.graphql.ServeHTTP(w, r)
	}

	// Strip /api prefix
	apiPath := strings.TrimPrefix(path, "/api")

	// Form-related endpoints (auth, search, contact, etc.)
	if rt.forms.Matches(apiPath) {
		return rt.forms.ServeHTTP(w, r, apiPath)
	}

	// Versioned API endpoints
	if strings.HasPrefix(apiPath, "/v1/users") || strings.HasPrefix(apiPath, "/v1/roles") {
		return rt.users.ServeHTTP(w, r, apiPath)
	}
	if strings.HasPrefix(apiPath, "/v1/products") || strings.HasPrefix(apiPath, "/v1/orders") ||
		strings.HasPrefix(apiPath, "/v1/cart") || strings.HasPrefix(apiPath, "/v1/categories") {
		return rt.ecom.ServeHTTP(w, r, apiPath)
	}
	if strings.HasPrefix(apiPath, "/v1/servers") || strings.HasPrefix(apiPath, "/v1/deployments") ||
		strings.HasPrefix(apiPath, "/v1/containers") || strings.HasPrefix(apiPath, "/v1/clusters") {
		return rt.infra.ServeHTTP(w, r, apiPath)
	}
	if strings.HasPrefix(apiPath, "/v1/posts") || strings.HasPrefix(apiPath, "/v1/pages") ||
		strings.HasPrefix(apiPath, "/v1/media") || strings.HasPrefix(apiPath, "/v1/tags") {
		return rt.cms.ServeHTTP(w, r, apiPath)
	}

	// Unknown API endpoint
	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error":   "not_found",
		"message": "The requested API endpoint does not exist",
		"path":    path,
		"docs":    "/swagger-ui/",
	})
	return http.StatusNotFound
}

// --- Common utilities used by all API handlers ---

// pathSeed returns a deterministic random source seeded from the path.
func pathSeed(path string) *rand.Rand {
	h := sha256.Sum256([]byte(path))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(seed))
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	addCommonHeaders(w)
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

// addCommonHeaders adds rate-limit and other common API headers.
func addCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("X-RateLimit-Limit", "1000")
	w.Header().Set("X-RateLimit-Remaining", "997")
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	w.Header().Set("X-Request-Id", randHex(16))
	w.Header().Set("X-API-Version", "1.0.0")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
}

// PaginatedResponse wraps a list of items with pagination metadata.
type PaginatedResponse struct {
	Data       interface{}        `json:"data"`
	Pagination PaginationMetadata `json:"pagination"`
	Links      PaginationLinks    `json:"_links"`
}

// PaginationMetadata contains pagination details.
type PaginationMetadata struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// PaginationLinks contains HATEOAS-style pagination links.
type PaginationLinks struct {
	Self  string `json:"self"`
	First string `json:"first"`
	Last  string `json:"last,omitempty"`
	Next  string `json:"next,omitempty"`
	Prev  string `json:"prev,omitempty"`
}

// parsePagination extracts page and per_page from query parameters.
func parsePagination(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if pp := r.URL.Query().Get("per_page"); pp != "" {
		if v, err := strconv.Atoi(pp); err == nil && v > 0 && v <= 100 {
			perPage = v
		}
	}
	return
}

// paginatedJSON writes a paginated JSON response.
func paginatedJSON(w http.ResponseWriter, r *http.Request, items interface{}, total int) {
	page, perPage := parsePagination(r)
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}

	basePath := r.URL.Path
	resp := PaginatedResponse{
		Data: items,
		Pagination: PaginationMetadata{
			Page:       page,
			PerPage:    perPage,
			Total:      total,
			TotalPages: totalPages,
		},
		Links: PaginationLinks{
			Self:  fmt.Sprintf("%s?page=%d&per_page=%d", basePath, page, perPage),
			First: fmt.Sprintf("%s?page=1&per_page=%d", basePath, perPage),
			Last:  fmt.Sprintf("%s?page=%d&per_page=%d", basePath, totalPages, perPage),
		},
	}
	if page < totalPages {
		resp.Links.Next = fmt.Sprintf("%s?page=%d&per_page=%d", basePath, page+1, perPage)
	}
	if page > 1 {
		resp.Links.Prev = fmt.Sprintf("%s?page=%d&per_page=%d", basePath, page-1, perPage)
	}

	writeJSON(w, http.StatusOK, resp)
}

// extractID extracts a resource ID from a path segment.
// e.g., "/v1/users/42" with prefix "/v1/users" returns "42"
func extractID(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimPrefix(rest, "/")
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return rest[:idx]
	}
	return rest
}

// subResource returns the sub-resource path after the ID.
// e.g., "/v1/users/42/posts" with prefix "/v1/users" returns "posts"
func subResource(path, prefix string) string {
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimPrefix(rest, "/")
	// skip past ID
	if idx := strings.Index(rest, "/"); idx >= 0 {
		return strings.TrimPrefix(rest[idx:], "/")
	}
	return ""
}

// randHex generates a random hex string of the given byte length.
func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "0123456789abcdef"[rand.Intn(16)]
	}
	return string(b)
}

// deterministicUUID generates a deterministic UUID from a seed and index.
func deterministicUUID(rng *rand.Rand) string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// deterministicEmail generates a fake email address.
func deterministicEmail(rng *rand.Rand, name string) string {
	domains := []string{"gmail.com", "yahoo.com", "outlook.com", "company.io", "example.org", "mail.net"}
	name = strings.ToLower(strings.ReplaceAll(name, " ", "."))
	return fmt.Sprintf("%s@%s", name, domains[rng.Intn(len(domains))])
}

// deterministicTimestamp generates a timestamp within the past year.
func deterministicTimestamp(rng *rand.Rand) string {
	daysAgo := rng.Intn(365)
	t := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -daysAgo)
	t = t.Add(time.Duration(rng.Intn(86400)) * time.Second)
	return t.Format(time.RFC3339)
}

// handleOptions responds to CORS preflight requests.
func handleOptions(w http.ResponseWriter) int {
	addCommonHeaders(w)
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

// methodNotAllowed returns a 405 response.
func methodNotAllowed(w http.ResponseWriter, allowed string) int {
	w.Header().Set("Allow", allowed)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
		"error":   "method_not_allowed",
		"message": "This endpoint does not support this HTTP method",
		"allowed": allowed,
	})
	return http.StatusMethodNotAllowed
}
