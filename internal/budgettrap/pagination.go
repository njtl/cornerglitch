package budgettrap

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

// ServeInfinitePagination returns an infinite paginated JSON API response.
// Each page is deterministic (same page number = same users) and always
// claims 999999999 total records, luring scanners into crawling forever.
func ServeInfinitePagination(w http.ResponseWriter, r *http.Request) (int, string) {
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}

	rng := rand.New(rand.NewSource(pageSeed(page)))

	// Generate 20 fake user records
	users := make([]map[string]interface{}, 20)
	baseID := (page - 1) * 20
	for i := range users {
		name := deterministicName(rng)
		users[i] = map[string]interface{}{
			"id":         baseID + i + 1,
			"name":       name,
			"email":      deterministicEmail(rng),
			"role":       roles[rng.Intn(len(roles))],
			"created_at": deterministicTimestamp(rng),
		}
	}

	basePath := r.URL.Path
	resp := map[string]interface{}{
		"data": users,
		"pagination": map[string]interface{}{
			"page":        page,
			"per_page":    20,
			"total":       999999999,
			"total_pages": 49999999,
			"has_next":    true,
		},
		"links": map[string]string{
			"self":  fmt.Sprintf("%s?page=%d", basePath, page),
			"next":  fmt.Sprintf("%s?page=%d", basePath, page+1),
			"first": fmt.Sprintf("%s?page=1", basePath),
		},
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Total-Count", "999999999")
	w.Header().Set("X-Page", strconv.Itoa(page))
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)

	return http.StatusOK, "pagination_trap"
}

// pageSeed returns a deterministic seed from a page number.
func pageSeed(page int) int64 {
	h := sha256.Sum256([]byte(fmt.Sprintf("pagination-%d", page)))
	return int64(binary.BigEndian.Uint64(h[:8]))
}

// pathSeed returns a deterministic int64 seed from a string path.
func pathSeed(s string) int64 {
	h := sha256.Sum256([]byte(s))
	return int64(binary.BigEndian.Uint64(h[:8]))
}

var firstNames = []string{
	"James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
	"David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
	"Thomas", "Sarah", "Christopher", "Karen", "Charles", "Lisa", "Daniel", "Nancy",
	"Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
}

var lastNames = []string{
	"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
	"Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
	"Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
	"White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
}

var roles = []string{
	"admin", "user", "editor", "viewer", "moderator", "analyst", "developer", "manager",
}

var emailDomains = []string{
	"gmail.com", "yahoo.com", "outlook.com", "company.io", "example.org", "mail.net",
	"protonmail.com", "fastmail.com", "icloud.com", "hotmail.com",
}

// deterministicName generates a "FirstName LastName" from the RNG.
func deterministicName(rng *rand.Rand) string {
	return firstNames[rng.Intn(len(firstNames))] + " " + lastNames[rng.Intn(len(lastNames))]
}

// deterministicEmail generates "user@example.com" from the RNG.
func deterministicEmail(rng *rand.Rand) string {
	first := strings.ToLower(firstNames[rng.Intn(len(firstNames))])
	last := strings.ToLower(lastNames[rng.Intn(len(lastNames))])
	domain := emailDomains[rng.Intn(len(emailDomains))]
	sep := []string{".", "_", ""}[rng.Intn(3)]
	return fmt.Sprintf("%s%s%s@%s", first, sep, last, domain)
}

// deterministicTimestamp generates a timestamp within the past year.
func deterministicTimestamp(rng *rand.Rand) string {
	daysAgo := rng.Intn(365)
	t := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, -daysAgo)
	t = t.Add(time.Duration(rng.Intn(86400)) * time.Second)
	return t.Format(time.RFC3339)
}
