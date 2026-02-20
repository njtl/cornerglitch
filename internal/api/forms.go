package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// FormsAPI handles form-related and auth endpoints.
type FormsAPI struct{}

// NewFormsAPI creates a new FormsAPI handler.
func NewFormsAPI() *FormsAPI {
	return &FormsAPI{}
}

// Matches returns true if this handler should handle the given API path.
func (f *FormsAPI) Matches(apiPath string) bool {
	switch {
	case apiPath == "/auth/login",
		apiPath == "/auth/register",
		apiPath == "/auth/logout",
		apiPath == "/auth/refresh":
		return true
	case apiPath == "/search",
		apiPath == "/autocomplete":
		return true
	case apiPath == "/contact",
		apiPath == "/newsletter/subscribe":
		return true
	case apiPath == "/comments",
		strings.HasPrefix(apiPath, "/comments/"):
		return true
	}
	return false
}

// ServeHTTP dispatches form/auth requests to the appropriate handler.
func (f *FormsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method == http.MethodOptions {
		return handleOptions(w)
	}

	switch {
	case apiPath == "/auth/login":
		return f.handleLogin(w, r)
	case apiPath == "/auth/register":
		return f.handleRegister(w, r)
	case apiPath == "/auth/logout":
		return f.handleLogout(w, r)
	case apiPath == "/auth/refresh":
		return f.handleRefresh(w, r)
	case apiPath == "/search":
		return f.handleSearch(w, r)
	case apiPath == "/autocomplete":
		return f.handleAutocomplete(w, r)
	case apiPath == "/contact":
		return f.handleContact(w, r)
	case apiPath == "/newsletter/subscribe":
		return f.handleNewsletterSubscribe(w, r)
	case apiPath == "/comments":
		return f.handleComments(w, r)
	case strings.HasPrefix(apiPath, "/comments/"):
		return f.handleCommentByID(w, r, apiPath)
	}

	writeJSON(w, http.StatusNotFound, map[string]interface{}{
		"error":   "not_found",
		"message": "Unknown forms/auth endpoint",
	})
	return http.StatusNotFound
}

// --- Auth endpoints ---

func (f *FormsAPI) handleLogin(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid JSON body",
		})
		return http.StatusBadRequest
	}

	username := body.Username
	if username == "" {
		username = "user"
	}

	rng := pathSeed("login:" + username)
	userID := deterministicUUID(rng)
	token := fakeJWT(username, userID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": 3600,
		"user": map[string]interface{}{
			"id":         userID,
			"username":   username,
			"email":      deterministicEmail(rng, username),
			"role":       "user",
			"created_at": deterministicTimestamp(rng),
			"last_login": time.Now().UTC().Format(time.RFC3339),
		},
	})
	return http.StatusOK
}

func (f *FormsAPI) handleRegister(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid JSON body",
		})
		return http.StatusBadRequest
	}

	username := body.Username
	if username == "" {
		username = "newuser"
	}
	email := body.Email
	if email == "" {
		rng := pathSeed("register:" + username)
		email = deterministicEmail(rng, username)
	}

	rng := pathSeed("register:" + username)
	userID := deterministicUUID(rng)
	token := fakeJWT(username, userID)
	now := time.Now().UTC().Format(time.RFC3339)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": 3600,
		"user": map[string]interface{}{
			"id":         userID,
			"username":   username,
			"email":      email,
			"role":       "user",
			"created_at": now,
			"verified":   false,
		},
	})
	return http.StatusCreated
}

func (f *FormsAPI) handleLogout(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Successfully logged out",
	})
	return http.StatusOK
}

func (f *FormsAPI) handleRefresh(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	rng := pathSeed("refresh:" + time.Now().UTC().Format("2006-01-02T15"))
	userID := deterministicUUID(rng)
	token := fakeJWT("user", userID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": 3600,
	})
	return http.StatusOK
}

// --- Search endpoints ---

func (f *FormsAPI) handleSearch(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "missing_parameter",
			"message": "Query parameter 'q' is required",
		})
		return http.StatusBadRequest
	}

	rng := pathSeed("search:" + query)

	titlePrefixes := []string{
		"Understanding", "A Guide to", "Introduction to", "Deep Dive into",
		"Best Practices for", "How to Use", "Getting Started with", "Advanced",
		"The Complete Guide to", "Everything You Need to Know About",
		"Top 10 Tips for", "Mastering", "Practical", "Essential",
		"Why You Should Learn", "Exploring",
	}
	titleSuffixes := []string{
		"in 2025", "- A Comprehensive Overview", "for Beginners",
		"for Professionals", "- Complete Tutorial", "| Expert Guide",
		"- Best Practices", "and Beyond", "Explained",
		"in Practice", "for Modern Development",
	}
	domains := []string{
		"www.example.com", "docs.techguide.io", "blog.devworld.net",
		"wiki.knowledge.org", "learn.codeacademy.com", "medium.com",
		"dev.to", "stackoverflow.com", "github.io", "tutorials.web.dev",
	}
	snippetTemplates := []string{
		"Learn how %s can transform your workflow with practical examples and real-world applications.",
		"This comprehensive guide covers everything you need to know about %s, from basics to advanced topics.",
		"Discover the key concepts behind %s and how to apply them effectively in your projects.",
		"%s is becoming increasingly important in modern development. Here's what you need to know.",
		"A detailed exploration of %s with code examples, best practices, and common pitfalls to avoid.",
		"Whether you're a beginner or expert, understanding %s is crucial for building reliable systems.",
		"Step-by-step tutorial on %s with hands-on exercises and downloadable resources.",
		"An in-depth analysis of %s covering architecture, performance, and scalability considerations.",
		"The ultimate resource for %s — bookmark this page for quick reference and updates.",
		"Practical tips and techniques for working with %s in production environments.",
	}

	results := make([]map[string]interface{}, 10)
	for i := 0; i < 10; i++ {
		prefix := titlePrefixes[rng.Intn(len(titlePrefixes))]
		suffix := titleSuffixes[rng.Intn(len(titleSuffixes))]
		domain := domains[rng.Intn(len(domains))]
		snippetTpl := snippetTemplates[rng.Intn(len(snippetTemplates))]

		slug := strings.ToLower(strings.ReplaceAll(query, " ", "-"))
		path := fmt.Sprintf("/%s/%s-%d", []string{"article", "guide", "tutorial", "blog", "docs"}[rng.Intn(5)], slug, rng.Intn(9999))

		score := 0.95 - float64(i)*0.07 + float64(rng.Intn(30)-15)*0.001
		if score < 0.1 {
			score = 0.1
		}
		if score > 1.0 {
			score = 1.0
		}

		results[i] = map[string]interface{}{
			"title":           fmt.Sprintf("%s %s %s", prefix, query, suffix),
			"url":             fmt.Sprintf("https://%s%s", domain, path),
			"snippet":         fmt.Sprintf(snippetTpl, query),
			"relevance_score": float64(int(score*1000)) / 1000,
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"query":        query,
		"result_count": len(results),
		"results":      results,
	})
	return http.StatusOK
}

func (f *FormsAPI) handleAutocomplete(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"suggestions": []string{},
		})
		return http.StatusOK
	}

	rng := pathSeed("autocomplete:" + query)

	suffixes := []string{
		" tutorial", " guide", " examples", " best practices",
		" documentation", " alternatives", " vs", " api",
		" for beginners", " advanced", " troubleshooting",
		" performance", " security", " configuration",
		" setup", " installation",
	}

	count := 5 + rng.Intn(4) // 5-8 suggestions
	suggestions := make([]string, count)
	used := make(map[int]bool)
	for i := 0; i < count; i++ {
		idx := rng.Intn(len(suffixes))
		for used[idx] {
			idx = (idx + 1) % len(suffixes)
		}
		used[idx] = true
		suggestions[i] = query + suffixes[idx]
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"suggestions": suggestions,
	})
	return http.StatusOK
}

// --- Contact / Newsletter endpoints ---

func (f *FormsAPI) handleContact(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	var body struct {
		Name    string `json:"name"`
		Email   string `json:"email"`
		Subject string `json:"subject"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid JSON body",
		})
		return http.StatusBadRequest
	}

	rng := pathSeed("contact:" + body.Email + body.Subject)
	ticketNum := 10000 + rng.Intn(90000)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":       "Thank you for contacting us",
		"ticket_id":     fmt.Sprintf("TK-%05d", ticketNum),
		"response_time": "24-48 hours",
	})
	return http.StatusOK
}

func (f *FormsAPI) handleNewsletterSubscribe(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		return methodNotAllowed(w, "POST, OPTIONS")
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid JSON body",
		})
		return http.StatusBadRequest
	}

	email := body.Email
	if email == "" {
		email = "subscriber@example.com"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Successfully subscribed",
		"email":   email,
		"list":    "general",
	})
	return http.StatusOK
}

// --- Comments endpoints ---

func (f *FormsAPI) handleComments(w http.ResponseWriter, r *http.Request) int {
	switch r.Method {
	case http.MethodGet:
		return f.listComments(w, r)
	case http.MethodPost:
		return f.createComment(w, r)
	default:
		return methodNotAllowed(w, "GET, POST, OPTIONS")
	}
}

func (f *FormsAPI) handleCommentByID(w http.ResponseWriter, r *http.Request, apiPath string) int {
	if r.Method != http.MethodGet {
		return methodNotAllowed(w, "GET, OPTIONS")
	}

	commentID := extractID(apiPath, "/comments")

	rng := pathSeed("comment:" + commentID)
	comment := generateComment(rng, commentID)

	writeJSON(w, http.StatusOK, comment)
	return http.StatusOK
}

func (f *FormsAPI) listComments(w http.ResponseWriter, r *http.Request) int {
	postID := r.URL.Query().Get("post_id")
	pageURL := r.URL.Query().Get("page_url")

	seed := postID
	if seed == "" {
		seed = pageURL
	}
	if seed == "" {
		seed = "default-comments"
	}

	rng := pathSeed("comments:" + seed)

	totalComments := 15 + rng.Intn(16) // 15-30 comments total
	page, perPage := parsePagination(r)

	// Generate all comments deterministically, then slice for the requested page
	allComments := make([]map[string]interface{}, totalComments)
	for i := 0; i < totalComments; i++ {
		cID := fmt.Sprintf("cmt_%s", deterministicUUID(rng))
		allComments[i] = generateComment(rng, cID)
	}

	// Paginate
	start := (page - 1) * perPage
	if start > len(allComments) {
		start = len(allComments)
	}
	end := start + perPage
	if end > len(allComments) {
		end = len(allComments)
	}
	pageItems := allComments[start:end]

	paginatedJSON(w, r, pageItems, totalComments)
	return http.StatusOK
}

func (f *FormsAPI) createComment(w http.ResponseWriter, r *http.Request) int {
	var body struct {
		PostID string `json:"post_id"`
		Author string `json:"author"`
		Body   string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid JSON body",
		})
		return http.StatusBadRequest
	}

	author := body.Author
	if author == "" {
		author = "Anonymous"
	}
	postID := body.PostID
	if postID == "" {
		postID = "unknown"
	}

	rng := pathSeed("newcomment:" + postID + ":" + author)
	commentID := "cmt_" + deterministicUUID(rng)
	now := time.Now().UTC().Format(time.RFC3339)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         commentID,
		"post_id":    postID,
		"author":     author,
		"avatar_url": fmt.Sprintf("https://avatars.example.com/%s.png", strings.ToLower(strings.ReplaceAll(author, " ", ""))),
		"body":       body.Body,
		"created_at": now,
		"likes":      0,
		"replies":    []interface{}{},
	})
	return http.StatusCreated
}

// --- Helpers ---

// generateComment creates a realistic-looking comment from a deterministic RNG.
func generateComment(rng *rand.Rand, commentID string) map[string]interface{} {
	firstNames := []string{
		"Alice", "Bob", "Charlie", "Diana", "Eve", "Frank",
		"Grace", "Hank", "Iris", "Jake", "Karen", "Leo",
		"Mia", "Noah", "Olivia", "Paul", "Quinn", "Rose",
		"Sam", "Tina", "Uma", "Victor", "Wendy", "Xander",
	}
	lastNames := []string{
		"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
		"Miller", "Davis", "Rodriguez", "Martinez", "Anderson", "Taylor",
		"Thomas", "Hernandez", "Moore", "Martin", "Jackson", "Thompson",
	}
	commentBodies := []string{
		"Great article! This really helped me understand the topic better.",
		"I've been looking for something like this. Thanks for sharing!",
		"Interesting perspective. I'd love to see a follow-up on this.",
		"Can you elaborate on the third point? I think there's more to discuss.",
		"This is exactly what I needed for my project. Bookmarked!",
		"I disagree with some points here, but overall a solid read.",
		"The code examples are very helpful. Works perfectly in my setup.",
		"Anyone else having trouble with the configuration step? Would appreciate help.",
		"Been using this approach for months now — can confirm it works well in production.",
		"Nice writeup. One small correction: the link in section 2 is broken.",
		"This saved me hours of debugging. Thank you so much!",
		"Would be great to see performance benchmarks compared to the alternatives.",
		"Clear and concise explanation. Shared this with my team.",
		"I implemented this differently but got similar results. Interesting!",
		"The diagram in this post really makes the architecture click.",
	}

	firstName := firstNames[rng.Intn(len(firstNames))]
	lastName := lastNames[rng.Intn(len(lastNames))]
	author := firstName + " " + lastName
	body := commentBodies[rng.Intn(len(commentBodies))]

	// Generate 0-3 replies
	replyCount := rng.Intn(4)
	replies := make([]map[string]interface{}, replyCount)
	for j := 0; j < replyCount; j++ {
		rFirstName := firstNames[rng.Intn(len(firstNames))]
		rLastName := lastNames[rng.Intn(len(lastNames))]
		rAuthor := rFirstName + " " + rLastName
		replies[j] = map[string]interface{}{
			"id":         "cmt_" + deterministicUUID(rng),
			"author":     rAuthor,
			"avatar_url": fmt.Sprintf("https://avatars.example.com/%s%s.png", strings.ToLower(rFirstName), strings.ToLower(rLastName)),
			"body":       commentBodies[rng.Intn(len(commentBodies))],
			"created_at": deterministicTimestamp(rng),
			"likes":      rng.Intn(50),
		}
	}

	return map[string]interface{}{
		"id":         commentID,
		"author":     author,
		"avatar_url": fmt.Sprintf("https://avatars.example.com/%s%s.png", strings.ToLower(firstName), strings.ToLower(lastName)),
		"body":       body,
		"created_at": deterministicTimestamp(rng),
		"likes":      rng.Intn(200),
		"replies":    replies,
	}
}

// fakeJWT generates a fake JWT token that looks realistic (three base64 segments separated by dots).
func fakeJWT(username, userID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"%s","name":"%s","iat":%d,"exp":%d,"iss":"glitch-server"}`,
		userID, username, now, now+3600)
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))

	// Fake signature — not cryptographically valid, just looks right
	rng := pathSeed("jwt:" + username + ":" + userID)
	sigBytes := make([]byte, 32)
	for i := range sigBytes {
		sigBytes[i] = byte(rng.Intn(256))
	}
	signature := base64.RawURLEncoding.EncodeToString(sigBytes)

	return header + "." + encodedPayload + "." + signature
}
