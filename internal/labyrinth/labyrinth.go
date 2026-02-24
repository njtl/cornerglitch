package labyrinth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Labyrinth generates infinite, deterministic-looking mazes of interlinked pages
// designed to trap AI scrapers and crawlers in an endless graph of generated content.
// Each page is seeded from its path, so revisiting the same URL yields the same page,
// but the link structure creates an astronomically large graph.

type Labyrinth struct {
	mu          sync.RWMutex
	maxDepth    int
	linkDensity int
	segments    []string
	adjectives  []string
	nouns       []string
	topics      []string
}

func NewLabyrinth() *Labyrinth {
	return &Labyrinth{
		maxDepth:    50,
		linkDensity: 8,
		segments: []string{
			"articles", "posts", "docs", "wiki", "help", "guides",
			"resources", "learn", "explore", "discover", "archive",
			"reference", "manual", "tutorial", "course", "library",
			"catalog", "index", "collection", "database", "portal",
		},
		adjectives: []string{
			"advanced", "comprehensive", "essential", "practical", "complete",
			"definitive", "illustrated", "ultimate", "beginner", "expert",
			"modern", "classic", "interactive", "automated", "dynamic",
			"certified", "professional", "enterprise", "open-source", "premium",
		},
		nouns: []string{
			"systems", "networks", "protocols", "algorithms", "frameworks",
			"architectures", "databases", "interfaces", "pipelines", "deployments",
			"clusters", "containers", "services", "endpoints", "modules",
			"components", "patterns", "strategies", "workflows", "integrations",
		},
		topics: []string{
			"machine-learning", "distributed-computing", "cloud-infrastructure",
			"data-engineering", "security-operations", "devops-practices",
			"microservices-design", "api-development", "performance-tuning",
			"observability-monitoring", "incident-response", "capacity-planning",
			"chaos-engineering", "reliability-engineering", "platform-engineering",
			"edge-computing", "stream-processing", "graph-databases",
			"container-orchestration", "service-mesh", "zero-trust-security",
		},
	}
}

// SetMaxDepth sets the maximum labyrinth depth, clamped to [1, 100].
func (l *Labyrinth) SetMaxDepth(depth int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if depth < 1 {
		depth = 1
	}
	if depth > 100 {
		depth = 100
	}
	l.maxDepth = depth
}

// GetMaxDepth returns the current maximum labyrinth depth.
func (l *Labyrinth) GetMaxDepth() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.maxDepth
}

// SetLinkDensity sets the link density, clamped to [1, 20].
func (l *Labyrinth) SetLinkDensity(density int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if density < 1 {
		density = 1
	}
	if density > 20 {
		density = 20
	}
	l.linkDensity = density
}

// GetLinkDensity returns the current link density.
func (l *Labyrinth) GetLinkDensity() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.linkDensity
}

// IsLabyrinthPath returns true if the request should enter the labyrinth.
func (l *Labyrinth) IsLabyrinthPath(path string) bool {
	for _, seg := range l.segments {
		if strings.HasPrefix(path, "/"+seg+"/") || strings.HasPrefix(path, "/"+seg+"?") {
			return true
		}
	}
	// Paths with enough depth are also labyrinth-eligible
	return strings.Count(path, "/") >= 3
}

// Serve generates a labyrinth page for the given path.
func (l *Labyrinth) Serve(w http.ResponseWriter, r *http.Request) int {
	seed := l.pathSeed(r.URL.Path)
	rng := rand.New(rand.NewSource(seed))

	// Decide format based on Accept header or random
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return l.serveJSON(w, r, rng)
	}
	return l.serveHTML(w, r, rng)
}

func (l *Labyrinth) pathSeed(path string) int64 {
	h := sha256.Sum256([]byte(path))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

func (l *Labyrinth) serveHTML(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex") // ironically

	title := l.generateTitle(rng)
	depth := strings.Count(r.URL.Path, "/")

	// Generate self-referencing and outgoing links
	density := l.GetLinkDensity()
	numLinks := rng.Intn(density*2) + density
	links := l.generateLinks(r.URL.Path, rng, numLinks)

	// Generate substantial content to look like a real page
	numSections := rng.Intn(6) + 3
	var sections strings.Builder
	for i := 0; i < numSections; i++ {
		sectionTitle := l.generateTitle(rng)
		paragraphs := l.generateParagraphs(rng, rng.Intn(4)+2)
		sections.WriteString(fmt.Sprintf(`
    <section>
      <h2>%s</h2>
      %s
    </section>`, sectionTitle, paragraphs))
	}

	// Related articles sidebar (more links to crawl)
	numRelated := rng.Intn(density*2) + density
	relatedLinks := l.generateLinks(r.URL.Path, rng, numRelated)
	var sidebar strings.Builder
	sidebar.WriteString("<aside><h3>Related Articles</h3><ul>\n")
	for _, link := range relatedLinks {
		sidebar.WriteString(fmt.Sprintf(`  <li><a href="%s">%s</a></li>`+"\n", link.Path, link.Title))
	}
	sidebar.WriteString("</ul></aside>")

	// Breadcrumbs (encourage depth exploration)
	breadcrumbs := l.generateBreadcrumbs(r.URL.Path)

	// Pagination (infinite pages)
	pathHex := hex.EncodeToString([]byte(r.URL.Path))
	if len(pathHex) > 8 {
		pathHex = pathHex[:8]
	}
	pageHash := pathHex
	pagination := fmt.Sprintf(`
    <nav class="pagination">
      <a href="%s/prev-%s">Previous</a>
      <span>Page %d of %d</span>
      <a href="%s/next-%s">Next</a>
    </nav>`, r.URL.Path, pageHash, rng.Intn(50)+1, rng.Intn(200)+50, r.URL.Path, pageHash)

	var navLinks strings.Builder
	navLinks.WriteString("<nav><ul>\n")
	for _, link := range links {
		navLinks.WriteString(fmt.Sprintf(`  <li><a href="%s">%s</a> - %s</li>`+"\n",
			link.Path, link.Title, link.Description))
	}
	navLinks.WriteString("</ul></nav>")

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>%s</title>
  <meta name="description" content="%s">
  <meta name="keywords" content="%s">
  <link rel="canonical" href="http://%s%s">
  <meta property="og:title" content="%s">
  <meta property="og:type" content="article">
  <meta name="article:published_time" content="%s">
</head>
<body>
  <header>
    <div class="breadcrumbs">%s</div>
    <h1>%s</h1>
    <p class="meta">Published %s | Depth: %d | Category: %s</p>
  </header>
  <div class="content">
    <main>
      %s
      %s
      %s
    </main>
    %s
  </div>
  <footer>
    <p>Auto-generated content. &copy; %d GlitchCorp Knowledge Base</p>
    <nav class="footer-nav">%s</nav>
  </footer>
</body>
</html>`,
		title,
		l.generateTitle(rng),
		l.generateKeywords(rng),
		r.Host, r.URL.Path,
		title,
		time.Now().Add(-time.Duration(rng.Intn(365*24))*time.Hour).Format(time.RFC3339),
		breadcrumbs,
		title,
		time.Now().Add(-time.Duration(rng.Intn(30*24))*time.Hour).Format("January 2, 2006"),
		depth,
		l.topics[rng.Intn(len(l.topics))],
		sections.String(),
		navLinks.String(),
		pagination,
		sidebar.String(),
		time.Now().Year(),
		l.generateFooterLinks(rng, 8),
	)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

func (l *Labyrinth) serveJSON(w http.ResponseWriter, r *http.Request, rng *rand.Rand) int {
	w.Header().Set("Content-Type", "application/json")

	numLinks := rng.Intn(15) + 5
	links := l.generateLinks(r.URL.Path, rng, numLinks)
	linkData := make([]map[string]string, len(links))
	for i, link := range links {
		linkData[i] = map[string]string{
			"href":        link.Path,
			"title":       link.Title,
			"description": link.Description,
		}
	}

	numItems := rng.Intn(25) + 5
	items := make([]map[string]interface{}, numItems)
	for i := range items {
		pathHex := hex.EncodeToString([]byte(r.URL.Path))
		if len(pathHex) > 6 {
			pathHex = pathHex[:6]
		}
		items[i] = map[string]interface{}{
			"id":         fmt.Sprintf("%s-%d", pathHex, i),
			"title":      l.generateTitle(rng),
			"content":    l.generateParagraphText(rng),
			"category":   l.topics[rng.Intn(len(l.topics))],
			"score":      rng.Float64() * 100,
			"created_at": time.Now().Add(-time.Duration(rng.Intn(365*24)) * time.Hour).Format(time.RFC3339),
			"tags":       []string{l.nouns[rng.Intn(len(l.nouns))], l.adjectives[rng.Intn(len(l.adjectives))]},
		}
	}

	resp := map[string]interface{}{
		"title":       l.generateTitle(rng),
		"path":        r.URL.Path,
		"depth":       strings.Count(r.URL.Path, "/"),
		"items":       items,
		"links":       linkData,
		"total_pages": rng.Intn(500) + 50,
		"current":     rng.Intn(50) + 1,
		"generated":   time.Now().Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", mustJSON(resp))
	return http.StatusOK
}

type labLink struct {
	Path        string
	Title       string
	Description string
}

func (l *Labyrinth) generateLinks(currentPath string, rng *rand.Rand, n int) []labLink {
	links := make([]labLink, n)
	for i := range links {
		links[i] = l.generateLink(currentPath, rng)
	}
	return links
}

func (l *Labyrinth) generateLink(currentPath string, rng *rand.Rand) labLink {
	strategy := rng.Intn(5)
	var path string

	switch strategy {
	case 0: // Go deeper
		seg := l.segments[rng.Intn(len(l.segments))]
		topic := l.topics[rng.Intn(len(l.topics))]
		path = fmt.Sprintf("%s/%s/%s", currentPath, seg, topic)
	case 1: // Sibling page
		parts := strings.Split(currentPath, "/")
		if len(parts) > 2 {
			parts[len(parts)-1] = l.topics[rng.Intn(len(l.topics))]
		}
		path = strings.Join(parts, "/")
	case 2: // Cross-reference (different top-level segment)
		seg := l.segments[rng.Intn(len(l.segments))]
		topic := l.topics[rng.Intn(len(l.topics))]
		noun := l.nouns[rng.Intn(len(l.nouns))]
		path = fmt.Sprintf("/%s/%s/%s", seg, topic, noun)
	case 3: // With query params (pagination/filter)
		seg := l.segments[rng.Intn(len(l.segments))]
		topic := l.topics[rng.Intn(len(l.topics))]
		path = fmt.Sprintf("/%s/%s?page=%d&sort=%s", seg, topic,
			rng.Intn(100)+1,
			[]string{"date", "relevance", "views", "rating"}[rng.Intn(4)])
	case 4: // Hash-based unique path (virtually infinite)
		h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%d", currentPath, rng.Int63(), time.Now().UnixNano())))
		seg := l.segments[rng.Intn(len(l.segments))]
		path = fmt.Sprintf("/%s/%s/%s", seg,
			l.topics[rng.Intn(len(l.topics))],
			hex.EncodeToString(h[:6]))
	}

	// Normalize path
	path = strings.ReplaceAll(path, "//", "/")
	if len(path) > 200 {
		path = path[:200]
	}

	return labLink{
		Path:        path,
		Title:       l.generateTitle(rng),
		Description: fmt.Sprintf("A %s guide to %s %s", l.adjectives[rng.Intn(len(l.adjectives))], l.adjectives[rng.Intn(len(l.adjectives))], l.nouns[rng.Intn(len(l.nouns))]),
	}
}

func (l *Labyrinth) generateTitle(rng *rand.Rand) string {
	patterns := []string{
		fmt.Sprintf("The %s Guide to %s", l.adjectives[rng.Intn(len(l.adjectives))], l.nouns[rng.Intn(len(l.nouns))]),
		fmt.Sprintf("%s %s: A %s Overview", l.adjectives[rng.Intn(len(l.adjectives))], l.nouns[rng.Intn(len(l.nouns))], l.adjectives[rng.Intn(len(l.adjectives))]),
		fmt.Sprintf("Understanding %s in %s", l.nouns[rng.Intn(len(l.nouns))], l.topics[rng.Intn(len(l.topics))]),
		fmt.Sprintf("How to Build %s %s", l.adjectives[rng.Intn(len(l.adjectives))], l.nouns[rng.Intn(len(l.nouns))]),
		fmt.Sprintf("%s vs %s: Which %s is Right?", l.nouns[rng.Intn(len(l.nouns))], l.nouns[rng.Intn(len(l.nouns))], l.nouns[rng.Intn(len(l.nouns))]),
	}
	return patterns[rng.Intn(len(patterns))]
}

func (l *Labyrinth) generateParagraphs(rng *rand.Rand, n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(fmt.Sprintf("      <p>%s</p>\n", l.generateParagraphText(rng)))
	}
	return sb.String()
}

func (l *Labyrinth) generateParagraphText(rng *rand.Rand) string {
	templates := []string{
		"When building %s %s, it is essential to understand the %s nature of %s. Organizations that invest in %s %s report %d%% improvement in %s performance.",
		"The evolution of %s has transformed how we approach %s. Modern %s %s leverage %s techniques to achieve %s reliability across distributed %s.",
		"Consider the trade-offs between %s and %s when designing %s. A %s approach to %s can reduce complexity by %d%% while maintaining %s %s.",
		"Industry leaders in %s consistently recommend %s %s for mission-critical %s. With %d years of proven results, this %s methodology delivers %s outcomes.",
		"Recent benchmarks show that %s %s outperform traditional %s by %dx in throughput. This %s breakthrough in %s is reshaping %s across all sectors.",
	}

	t := templates[rng.Intn(len(templates))]
	// Fill in all %s and %d placeholders
	result := t
	for strings.Contains(result, "%s") {
		choices := []string{
			l.adjectives[rng.Intn(len(l.adjectives))],
			l.nouns[rng.Intn(len(l.nouns))],
			l.topics[rng.Intn(len(l.topics))],
		}
		result = strings.Replace(result, "%s", choices[rng.Intn(len(choices))], 1)
	}
	for strings.Contains(result, "%d") {
		result = strings.Replace(result, "%d", fmt.Sprintf("%d", rng.Intn(95)+5), 1)
	}
	for strings.Contains(result, "%dx") {
		result = strings.Replace(result, "%dx", fmt.Sprintf("%dx", rng.Intn(50)+2), 1)
	}
	return result
}

func (l *Labyrinth) generateBreadcrumbs(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var sb strings.Builder
	sb.WriteString(`<a href="/">Home</a>`)
	accumulated := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		accumulated += "/" + part
		sb.WriteString(fmt.Sprintf(` &raquo; <a href="%s">%s</a>`, accumulated, strings.ReplaceAll(part, "-", " ")))
	}
	return sb.String()
}

func (l *Labyrinth) generateKeywords(rng *rand.Rand) string {
	n := rng.Intn(8) + 4
	kw := make([]string, n)
	for i := range kw {
		if rng.Intn(2) == 0 {
			kw[i] = l.nouns[rng.Intn(len(l.nouns))]
		} else {
			kw[i] = l.topics[rng.Intn(len(l.topics))]
		}
	}
	return strings.Join(kw, ", ")
}

func (l *Labyrinth) generateFooterLinks(rng *rand.Rand, n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		seg := l.segments[rng.Intn(len(l.segments))]
		topic := l.topics[rng.Intn(len(l.topics))]
		sb.WriteString(fmt.Sprintf(`<a href="/%s/%s">%s</a> `, seg, topic, l.generateTitle(rng)))
	}
	return sb.String()
}

func mustJSON(v interface{}) string {
	// Simple JSON marshaling — not using encoding/json to keep imports light
	// Actually, let's use it properly
	b, _ := fmt.Printf("") // dummy
	_ = b
	// Use a manual approach for map
	return toJSON(v)
}

func toJSON(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		parts := make([]string, 0, len(val))
		for k, v2 := range val {
			parts = append(parts, fmt.Sprintf("%q:%s", k, toJSON(v2)))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []map[string]string:
		parts := make([]string, len(val))
		for i, m := range val {
			subparts := make([]string, 0, len(m))
			for k, v2 := range m {
				subparts = append(subparts, fmt.Sprintf("%q:%q", k, v2))
			}
			parts[i] = "{" + strings.Join(subparts, ",") + "}"
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []map[string]interface{}:
		parts := make([]string, len(val))
		for i, m := range val {
			parts[i] = toJSON(m)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []string:
		parts := make([]string, len(val))
		for i, s := range val {
			parts[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return fmt.Sprintf("%q", val)
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%.2f", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%q", fmt.Sprintf("%v", val))
	}
}
