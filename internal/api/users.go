package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var firstNames = []string{
	"Alice", "Benjamin", "Charlotte", "Daniel", "Eleanor",
	"Felix", "Grace", "Henry", "Isabella", "James",
	"Katherine", "Liam", "Mia", "Nathan", "Olivia",
	"Patrick", "Quinn", "Rachel", "Samuel", "Tessa",
}

var lastNames = []string{
	"Anderson", "Brooks", "Chen", "Dawson", "Evans",
	"Fischer", "Garcia", "Hayward", "Ibrahim", "Jensen",
	"Kovalenko", "Larsson", "Mitchell", "Nakamura", "O'Brien",
	"Patel", "Quinn", "Ramirez", "Sullivan", "Tanaka",
}

var userRoles = []string{"admin", "editor", "viewer", "user"}
var userStatuses = []string{"active", "suspended", "pending"}

const totalUsers = 247

// UsersAPI handles user management REST API endpoints.
type UsersAPI struct{}

// NewUsersAPI creates a new UsersAPI handler.
func NewUsersAPI() *UsersAPI {
	return &UsersAPI{}
}

// ServeHTTP dispatches user API requests to the appropriate handler.
func (u *UsersAPI) ServeHTTP(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	// GET /v1/roles
	if strings.HasPrefix(apiPath, "/v1/roles") {
		return u.handleRoles(w, r)
	}

	// /v1/users endpoints
	id := extractID(apiPath, "/v1/users")

	if id == "" {
		// Collection endpoint: /v1/users
		return u.handleUsersCollection(w, r)
	}

	// Check for sub-resources: /v1/users/{id}/...
	sub := subResource(apiPath, "/v1/users")
	if sub != "" {
		switch sub {
		case "posts":
			return u.handleUserPosts(w, r, id)
		case "activity":
			return u.handleUserActivity(w, r, id)
		default:
			writeJSON(w, http.StatusNotFound, map[string]interface{}{
				"error":   "not_found",
				"message": fmt.Sprintf("Sub-resource '%s' not found", sub),
			})
			return http.StatusNotFound
		}
	}

	// Single user endpoint: /v1/users/{id}
	return u.handleSingleUser(w, r, id)
}

// handleUsersCollection handles GET /v1/users and POST /v1/users.
func (u *UsersAPI) handleUsersCollection(w http.ResponseWriter, r *http.Request) int {
	switch r.Method {
	case http.MethodGet:
		return u.listUsers(w, r)
	case http.MethodPost:
		return u.createUser(w, r)
	default:
		return methodNotAllowed(w, "GET, POST, OPTIONS")
	}
}

// handleSingleUser handles GET/PUT/DELETE /v1/users/{id}.
func (u *UsersAPI) handleSingleUser(w http.ResponseWriter, r *http.Request, id string) int {
	switch r.Method {
	case http.MethodGet:
		return u.getUser(w, r, id)
	case http.MethodPut:
		return u.updateUser(w, r, id)
	case http.MethodDelete:
		return u.deleteUser(w, r, id)
	default:
		return methodNotAllowed(w, "GET, PUT, DELETE, OPTIONS")
	}
}

// generateUser creates a deterministic user object from an index.
func generateUser(index int) map[string]interface{} {
	rng := pathSeed(fmt.Sprintf("user-%d", index))

	first := firstNames[rng.Intn(len(firstNames))]
	last := lastNames[rng.Intn(len(lastNames))]
	fullName := first + " " + last
	username := strings.ToLower(first) + "." + strings.ToLower(last) + strconv.Itoa(rng.Intn(100))

	return map[string]interface{}{
		"id":         deterministicUUID(rng),
		"username":   username,
		"email":      deterministicEmail(rng, fullName),
		"full_name":  fullName,
		"role":       userRoles[rng.Intn(len(userRoles))],
		"status":     userStatuses[rng.Intn(len(userStatuses))],
		"created_at": deterministicTimestamp(rng),
		"last_login": deterministicTimestamp(rng),
		"avatar_url": fmt.Sprintf("https://avatars.example.com/u/%d.png", index),
	}
}

// generateDetailedUser creates a detailed user object with extra fields.
func generateDetailedUser(index int) map[string]interface{} {
	user := generateUser(index)

	// Use a separate seed for the extra detail fields to keep the base fields stable.
	rng := pathSeed(fmt.Sprintf("user-detail-%d", index))

	areaCodes := []string{"212", "310", "415", "312", "206", "512", "617", "303", "404", "503"}
	streets := []string{"Main St", "Oak Ave", "Elm Dr", "Park Blvd", "Cedar Ln", "Maple Way", "Pine Rd", "Lake St", "River Rd", "Hill Ave"}
	cities := []string{"New York", "Los Angeles", "Chicago", "Seattle", "Austin", "Boston", "Denver", "Atlanta", "Portland", "San Francisco"}
	states := []string{"NY", "CA", "IL", "WA", "TX", "MA", "CO", "GA", "OR", "CA"}
	themes := []string{"light", "dark", "auto"}
	languages := []string{"en", "es", "fr", "de", "ja", "zh", "pt", "ko"}
	timezones := []string{
		"America/New_York", "America/Los_Angeles", "America/Chicago",
		"Europe/London", "Europe/Berlin", "Asia/Tokyo", "Asia/Shanghai",
	}

	cityIdx := rng.Intn(len(cities))

	user["phone"] = fmt.Sprintf("+1-%s-%03d-%04d", areaCodes[rng.Intn(len(areaCodes))], rng.Intn(1000), rng.Intn(10000))
	user["address"] = map[string]interface{}{
		"street":  fmt.Sprintf("%d %s", 100+rng.Intn(9900), streets[rng.Intn(len(streets))]),
		"city":    cities[cityIdx],
		"state":   states[cityIdx],
		"zip":     fmt.Sprintf("%05d", 10000+rng.Intn(90000)),
		"country": "US",
	}
	user["preferences"] = map[string]interface{}{
		"theme":          themes[rng.Intn(len(themes))],
		"language":       languages[rng.Intn(len(languages))],
		"timezone":       timezones[rng.Intn(len(timezones))],
		"notifications":  rng.Intn(2) == 1,
		"email_digest":   rng.Intn(2) == 1,
		"items_per_page": 10 + rng.Intn(4)*5, // 10, 15, 20, 25
	}
	user["login_count"] = rng.Intn(500) + 1
	user["two_factor_enabled"] = rng.Intn(3) != 0 // ~67% have 2FA

	return user
}

// listUsers handles GET /v1/users with pagination and filtering.
func (u *UsersAPI) listUsers(w http.ResponseWriter, r *http.Request) int {
	roleFilter := r.URL.Query().Get("role")
	statusFilter := r.URL.Query().Get("status")

	// Generate all users and apply filters.
	var allUsers []interface{}
	for i := 0; i < totalUsers; i++ {
		user := generateUser(i)
		if roleFilter != "" && user["role"] != roleFilter {
			continue
		}
		if statusFilter != "" && user["status"] != statusFilter {
			continue
		}
		allUsers = append(allUsers, user)
	}

	total := len(allUsers)
	w.Header().Set("X-Total-Count", strconv.Itoa(total))

	// Apply pagination.
	page, perPage := parsePagination(r)
	start := (page - 1) * perPage
	if start >= total {
		paginatedJSON(w, r, []interface{}{}, total)
		return http.StatusOK
	}
	end := start + perPage
	if end > total {
		end = total
	}

	paginatedJSON(w, r, allUsers[start:end], total)
	return http.StatusOK
}

// userIndexFromID finds the user index matching the given ID, or -1.
func userIndexFromID(id string) int {
	for i := 0; i < totalUsers; i++ {
		user := generateUser(i)
		if user["id"] == id {
			return i
		}
	}
	return -1
}

// getUser handles GET /v1/users/{id}.
func (u *UsersAPI) getUser(w http.ResponseWriter, r *http.Request, id string) int {
	idx := userIndexFromID(id)
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("User '%s' not found", id),
		})
		return http.StatusNotFound
	}

	user := generateDetailedUser(idx)
	writeJSON(w, http.StatusOK, user)
	return http.StatusOK
}

// createUser handles POST /v1/users.
func (u *UsersAPI) createUser(w http.ResponseWriter, r *http.Request) int {
	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_json",
			"message": "Request body must be valid JSON",
		})
		return http.StatusBadRequest
	}

	// Generate a new user deterministically from the request body content.
	seedStr := "create-user"
	if v, ok := input["username"]; ok {
		seedStr += fmt.Sprintf("-%v", v)
	}
	if v, ok := input["email"]; ok {
		seedStr += fmt.Sprintf("-%v", v)
	}
	rng := pathSeed(seedStr)

	newUser := map[string]interface{}{
		"id":         deterministicUUID(rng),
		"username":   fmt.Sprintf("user%d", rng.Intn(100000)),
		"email":      "",
		"full_name":  "",
		"role":       "user",
		"status":     "pending",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"last_login": nil,
		"avatar_url": fmt.Sprintf("https://avatars.example.com/u/%s.png", randHex(8)),
	}

	// Merge input fields over the generated defaults.
	for _, field := range []string{"username", "email", "full_name", "role", "status", "phone", "avatar_url"} {
		if v, ok := input[field]; ok {
			newUser[field] = v
		}
	}

	// Derive email from username if not provided.
	if newUser["email"] == "" || newUser["email"] == nil {
		name := fmt.Sprintf("%v", newUser["username"])
		newUser["email"] = deterministicEmail(rng, name)
	}

	w.Header().Set("Location", fmt.Sprintf("/api/v1/users/%s", newUser["id"]))
	writeJSON(w, http.StatusCreated, newUser)
	return http.StatusCreated
}

// updateUser handles PUT /v1/users/{id}.
func (u *UsersAPI) updateUser(w http.ResponseWriter, r *http.Request, id string) int {
	idx := userIndexFromID(id)
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("User '%s' not found", id),
		})
		return http.StatusNotFound
	}

	var input map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_json",
			"message": "Request body must be valid JSON",
		})
		return http.StatusBadRequest
	}

	user := generateDetailedUser(idx)
	user["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	// Merge input fields over the generated data.
	for _, field := range []string{"username", "email", "full_name", "role", "status", "phone", "avatar_url"} {
		if v, ok := input[field]; ok {
			user[field] = v
		}
	}

	writeJSON(w, http.StatusOK, user)
	return http.StatusOK
}

// deleteUser handles DELETE /v1/users/{id}.
func (u *UsersAPI) deleteUser(w http.ResponseWriter, r *http.Request, id string) int {
	idx := userIndexFromID(id)
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("User '%s' not found", id),
		})
		return http.StatusNotFound
	}

	addCommonHeaders(w)
	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent
}

// handleUserPosts handles GET /v1/users/{id}/posts.
func (u *UsersAPI) handleUserPosts(w http.ResponseWriter, r *http.Request, id string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	idx := userIndexFromID(id)
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("User '%s' not found", id),
		})
		return http.StatusNotFound
	}

	rng := pathSeed(fmt.Sprintf("user-posts-%d", idx))
	postCount := 15 + rng.Intn(16) // 15-30

	postTitles := []string{
		"Getting Started with Microservices",
		"Understanding REST API Design",
		"Best Practices for Database Indexing",
		"A Deep Dive into Container Orchestration",
		"Building Scalable Web Applications",
		"Introduction to Event-Driven Architecture",
		"How to Write Clean Code",
		"Monitoring and Observability in Production",
		"Security Best Practices for APIs",
		"Automating Your CI/CD Pipeline",
		"The Future of Serverless Computing",
		"Data Modeling for NoSQL Databases",
		"Performance Tuning Your Go Applications",
		"Working with WebSockets in Practice",
		"GraphQL vs REST: A Practical Comparison",
		"Infrastructure as Code with Terraform",
		"Debugging Distributed Systems",
		"Designing Fault-Tolerant Systems",
		"Machine Learning in Production",
		"Real-Time Data Processing Patterns",
		"Effective Code Reviews",
		"Managing Technical Debt",
		"Zero Downtime Deployments",
		"API Versioning Strategies",
		"Caching Strategies for High Traffic",
		"Load Testing Your Application",
		"Secrets Management in the Cloud",
		"Building Developer Portals",
		"Logging Best Practices",
		"Event Sourcing Explained",
	}

	postStatuses := []string{"published", "draft", "archived"}

	user := generateUser(idx)
	var posts []interface{}
	for i := 0; i < postCount; i++ {
		pRng := pathSeed(fmt.Sprintf("user-%d-post-%d", idx, i))
		title := postTitles[pRng.Intn(len(postTitles))]
		posts = append(posts, map[string]interface{}{
			"id":         deterministicUUID(pRng),
			"title":      title,
			"slug":       strings.ToLower(strings.ReplaceAll(title, " ", "-")),
			"status":     postStatuses[pRng.Intn(len(postStatuses))],
			"author_id":  user["id"],
			"created_at": deterministicTimestamp(pRng),
			"updated_at": deterministicTimestamp(pRng),
			"word_count": 200 + pRng.Intn(2800),
		})
	}

	total := len(posts)
	w.Header().Set("X-Total-Count", strconv.Itoa(total))

	page, perPage := parsePagination(r)
	start := (page - 1) * perPage
	if start >= total {
		paginatedJSON(w, r, []interface{}{}, total)
		return http.StatusOK
	}
	end := start + perPage
	if end > total {
		end = total
	}

	paginatedJSON(w, r, posts[start:end], total)
	return http.StatusOK
}

// handleUserActivity handles GET /v1/users/{id}/activity.
func (u *UsersAPI) handleUserActivity(w http.ResponseWriter, r *http.Request, id string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	idx := userIndexFromID(id)
	if idx < 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error":   "not_found",
			"message": fmt.Sprintf("User '%s' not found", id),
		})
		return http.StatusNotFound
	}

	rng := pathSeed(fmt.Sprintf("user-activity-%d", idx))

	actionTypes := []string{
		"login", "logout", "page_view", "post_create", "post_edit",
		"post_delete", "comment_add", "profile_update", "password_change",
		"settings_update", "file_upload", "api_key_create",
	}
	resources := []string{
		"/dashboard", "/settings", "/posts", "/profile",
		"/api/v1/users", "/api/v1/posts", "/media/uploads",
	}
	ipPrefixes := []string{"192.168.1.", "10.0.0.", "172.16.0.", "203.0.113."}

	activityCount := 20 + rng.Intn(30)
	user := generateUser(idx)
	var activities []interface{}

	for i := 0; i < activityCount; i++ {
		aRng := pathSeed(fmt.Sprintf("user-%d-activity-%d", idx, i))
		activities = append(activities, map[string]interface{}{
			"id":         deterministicUUID(aRng),
			"user_id":    user["id"],
			"action":     actionTypes[aRng.Intn(len(actionTypes))],
			"resource":   resources[aRng.Intn(len(resources))],
			"ip_address": fmt.Sprintf("%s%d", ipPrefixes[aRng.Intn(len(ipPrefixes))], 1+aRng.Intn(254)),
			"user_agent": fmt.Sprintf("Mozilla/5.0 (compatible; client/%d.%d)", aRng.Intn(10), aRng.Intn(20)),
			"timestamp":  deterministicTimestamp(aRng),
			"success":    aRng.Intn(20) != 0, // 95% success
		})
	}

	total := len(activities)
	w.Header().Set("X-Total-Count", strconv.Itoa(total))

	page, perPage := parsePagination(r)
	start := (page - 1) * perPage
	if start >= total {
		paginatedJSON(w, r, []interface{}{}, total)
		return http.StatusOK
	}
	end := start + perPage
	if end > total {
		end = total
	}

	paginatedJSON(w, r, activities[start:end], total)
	return http.StatusOK
}

// handleRoles handles GET /v1/roles.
func (u *UsersAPI) handleRoles(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	roles := []interface{}{
		map[string]interface{}{
			"id":          "role-admin",
			"name":        "admin",
			"display_name": "Administrator",
			"description": "Full access to all resources and settings",
			"permissions": []string{"read", "write", "delete", "admin", "manage_users", "manage_roles", "manage_settings"},
			"user_count":  12,
		},
		map[string]interface{}{
			"id":          "role-editor",
			"name":        "editor",
			"display_name": "Editor",
			"description": "Can create, edit, and publish content",
			"permissions": []string{"read", "write", "publish", "manage_media"},
			"user_count":  45,
		},
		map[string]interface{}{
			"id":          "role-viewer",
			"name":        "viewer",
			"display_name": "Viewer",
			"description": "Read-only access to content and dashboards",
			"permissions": []string{"read"},
			"user_count":  78,
		},
		map[string]interface{}{
			"id":          "role-user",
			"name":        "user",
			"display_name": "Standard User",
			"description": "Default role with basic access to own resources",
			"permissions": []string{"read", "write_own", "delete_own"},
			"user_count":  112,
		},
	}

	w.Header().Set("X-Total-Count", strconv.Itoa(len(roles)))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":  roles,
		"total": len(roles),
	})
	return http.StatusOK
}
