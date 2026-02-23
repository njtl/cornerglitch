package content

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Engine generates realistic web pages from URL paths.
// Pages are deterministic (same path = same content) and cached for 24h.
type Engine struct {
	mu    sync.RWMutex
	cache *Cache
	words *WordBank
	elems *Elements
	theme string
}

// NewEngine creates a content engine with default cache settings.
func NewEngine() *Engine {
	words := NewWordBank()
	return &Engine{
		cache: NewCache(10000, 24*time.Hour),
		words: words,
		elems: NewElements(words),
		theme: "default",
	}
}

// Stop shuts down the cache cleanup goroutine.
func (e *Engine) Stop() {
	e.cache.Stop()
}

// CacheStats returns the current cache statistics.
func (e *Engine) CacheStats() CacheStats {
	return e.cache.Stats()
}

// SetTheme sets the content engine's CSS theme. Thread-safe.
func (e *Engine) SetTheme(theme string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.theme = theme
}

// GetTheme returns the current CSS theme. Thread-safe.
func (e *Engine) GetTheme() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.theme
}

// SetCacheTTL updates the cache's TTL duration.
func (e *Engine) SetCacheTTL(ttl time.Duration) {
	e.cache.SetTTL(ttl)
}

// themeCSS returns the CSS :root variables block for the current theme.
func (e *Engine) themeCSS() string {
	e.mu.RLock()
	theme := e.theme
	e.mu.RUnlock()

	switch theme {
	case "dark":
		return ":root { --primary: #60a5fa; --bg: #0f172a; --text: #e2e8f0; --border: #334155; --accent: #a78bfa; }"
	case "corporate":
		return ":root { --primary: #1e40af; --bg: #ffffff; --text: #111827; --border: #d1d5db; --accent: #059669; }"
	case "minimal":
		return ":root { --primary: #374151; --bg: #ffffff; --text: #1f2937; --border: #e5e7eb; --accent: #6b7280; }"
	case "vibrant":
		return ":root { --primary: #dc2626; --bg: #fffbeb; --text: #1c1917; --border: #fde68a; --accent: #7c3aed; }"
	default:
		return ":root { --primary: #2563eb; --bg: #f8fafc; --text: #1e293b; --border: #e2e8f0; --accent: #7c3aed; }"
	}
}

// ShouldHandle returns true if this path should be handled by the content engine.
// It handles most paths except those reserved for other subsystems.
func (e *Engine) ShouldHandle(path string) bool {
	// Don't handle API-specific paths (other subsystems handle these)
	reserved := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/graphql",
		"/ws/", "/oauth/", "/saml/",
		"/.well-known/", "/.env", "/.git/",
		"/health", "/healthz", "/ready", "/live",
		"/metrics", "/debug/", "/actuator/",
		"/favicon.ico", "/robots.txt", "/sitemap.xml",
	}
	for _, prefix := range reserved {
		if strings.HasPrefix(path, prefix) || path == prefix {
			return false
		}
	}
	return true
}

// Serve generates and serves a content page for the given request.
// Returns the HTTP status code used.
func (e *Engine) Serve(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path
	cacheKey := path

	// Check cache first
	if entry, ok := e.cache.Get(cacheKey); ok {
		for k, v := range entry.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(entry.Status)
		w.Write(entry.Body)
		return entry.Status
	}

	// Generate deterministic content from path
	seed := pathSeed(path)
	rng := rand.New(rand.NewSource(seed))

	// Determine page style from path
	style := e.detectPageStyle(path)

	// Generate the full page
	body := e.generatePage(rng, r, style)

	headers := map[string]string{
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "public, max-age=86400",
		"X-Content-Id":  fmt.Sprintf("cid-%x", seed&0xFFFFFFFF),
	}

	// Cache it
	e.cache.Set(cacheKey, &CacheEntry{
		Key:     cacheKey,
		Body:    []byte(body),
		Headers: headers,
		Status:  http.StatusOK,
	})

	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(body))
	return http.StatusOK
}

// PageStyle determines the type of content page to generate.
type PageStyle string

const (
	StyleArticle   PageStyle = "article"
	StyleProduct   PageStyle = "product"
	StyleCorporate PageStyle = "corporate"
	StyleService   PageStyle = "service"
	StyleHelp      PageStyle = "help"
	StyleDashboard PageStyle = "dashboard"
	StyleGeneric   PageStyle = "generic"
)

func (e *Engine) detectPageStyle(path string) PageStyle {
	p := strings.ToLower(path)
	segments := strings.Split(strings.Trim(p, "/"), "/")
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return StyleGeneric
	}

	first := segments[0]
	switch {
	case first == "blog" || first == "news" || first == "articles" || first == "posts" || first == "stories":
		return StyleArticle
	case first == "products" || first == "shop" || first == "store" || first == "catalog" || first == "marketplace":
		return StyleProduct
	case first == "about" || first == "team" || first == "careers" || first == "company" || first == "investors":
		return StyleCorporate
	case first == "services" || first == "solutions" || first == "features" || first == "platform":
		return StyleService
	case first == "help" || first == "support" || first == "faq" || first == "docs" || first == "knowledge-base":
		return StyleHelp
	case first == "dashboard" || first == "account" || first == "settings" || first == "profile" || first == "admin":
		return StyleDashboard
	default:
		return StyleGeneric
	}
}

func (e *Engine) generatePage(rng *rand.Rand, r *http.Request, style PageStyle) string {
	path := r.URL.Path
	vocab := e.words.TopicFor(path)
	host := r.Host
	if host == "" {
		host = "localhost"
	}

	// Generate page title from path
	title := e.titleFromPath(rng, path, vocab)

	// Build nav items
	navItems := e.generateNavItems(rng)

	// Build breadcrumbs
	breadcrumbs := e.elems.Breadcrumbs(path)

	// Build page-specific content
	var mainContent string
	switch style {
	case StyleArticle:
		mainContent = e.generateArticlePage(rng, path, vocab)
	case StyleProduct:
		mainContent = e.generateProductPage(rng, vocab)
	case StyleCorporate:
		mainContent = e.generateCorporatePage(rng, vocab)
	case StyleService:
		mainContent = e.generateServicePage(rng, vocab)
	case StyleHelp:
		mainContent = e.generateHelpPage(rng, vocab)
	case StyleDashboard:
		mainContent = e.generateDashboardPage(rng, vocab)
	default:
		mainContent = e.generateGenericPage(rng, path, vocab)
	}

	// Build sidebar with related links
	relatedLinks := e.generateRelatedLinks(rng, path, 8)
	sidebar := e.elems.Sidebar(rng, relatedLinks)

	// Build footer
	companyName := e.words.RandCompany(rng)
	footer := e.elems.Footer(rng, companyName)

	// Random chance to include extra elements
	var extras string
	if rng.Intn(3) == 0 {
		extras += e.elems.CookieConsent(rng)
	}
	if rng.Intn(4) == 0 {
		extras += e.elems.NotificationBanner(rng)
	}

	// Generate internal links for the page
	internalLinks := e.generateInternalLinks(rng, path, 10)
	var linkSection strings.Builder
	linkSection.WriteString(`<section class="related-content"><h3>Explore More</h3><ul>`)
	for _, link := range internalLinks {
		linkSection.WriteString(fmt.Sprintf(`<li><a href="%s">%s</a></li>`, link.Href, link.Label))
	}
	linkSection.WriteString(`</ul></section>`)

	// Meta description
	metaDesc := e.words.GenerateSentence(rng, vocab)

	// Keywords from path
	keywords := e.keywordsFromPath(path)

	// SVG hero image
	heroSVG := e.elems.ImagePlaceholder(rng, 1200, 400)

	// Generate API discovery elements for security scanners
	prefetchLinks := generateAPIPrefetchLinks(rng)
	hiddenAPILinks := generateHiddenAPILinks(rng)
	apiScript := generateAPIScriptBlock(rng)

	// Generate the full HTML document
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
  <meta property="og:description" content="%s">
  <meta property="og:type" content="website">
  <meta property="og:url" content="http://%s%s">
  <meta name="twitter:card" content="summary_large_image">
%s
  <style>
    %s
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
    a { color: var(--primary); text-decoration: none; } a:hover { text-decoration: underline; }
    .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    .layout { display: grid; grid-template-columns: 1fr 300px; gap: 40px; margin-top: 30px; }
    @media (max-width: 768px) { .layout { grid-template-columns: 1fr; } }
    main { min-width: 0; }
    h1 { font-size: 2.2em; margin-bottom: 0.5em; color: var(--text); }
    h2 { font-size: 1.5em; margin: 1.5em 0 0.5em; color: var(--text); }
    h3 { font-size: 1.2em; margin: 1em 0 0.5em; }
    p { margin-bottom: 1em; }
    .hero-image { width: 100%%; border-radius: 12px; margin: 20px 0; overflow: hidden; }
    .hero-image svg { width: 100%%; height: auto; display: block; }
    .breadcrumbs { padding: 15px 0; font-size: 0.9em; color: #64748b; }
    .breadcrumbs a { color: #64748b; } .breadcrumbs a:hover { color: var(--primary); }
    section { margin-bottom: 30px; }
    .related-content ul { list-style: none; } .related-content li { padding: 8px 0; border-bottom: 1px solid var(--border); }
    table { width: 100%%; border-collapse: collapse; margin: 1em 0; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #f1f5f9; font-weight: 600; }
    .card { background: white; border-radius: 8px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
    .btn { display: inline-block; padding: 10px 24px; background: var(--primary); color: white; border-radius: 6px; border: none; cursor: pointer; font-size: 1em; }
    .btn:hover { background: #1d4ed8; text-decoration: none; }
    .btn-secondary { background: white; color: var(--primary); border: 2px solid var(--primary); }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
    @media (max-width: 768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }
    .tag { display: inline-block; padding: 2px 10px; background: #eff6ff; color: var(--primary); border-radius: 20px; font-size: 0.85em; margin-right: 5px; }
  </style>
</head>
<body>
  %s
  <div class="container">
    <div class="breadcrumbs">%s</div>
    <div class="hero-image">%s</div>
    <div class="layout">
      <main>
        <h1>%s</h1>
        %s
        %s
      </main>
      <aside>
        %s
      </aside>
    </div>
  </div>
  %s
  %s
  %s
  %s
  %s
</body>
</html>`,
		escHTML(title),
		escHTML(metaDesc),
		escHTML(keywords),
		host, path,
		escHTML(title),
		escHTML(metaDesc),
		host, path,
		prefetchLinks,
		e.themeCSS(),
		e.elems.NavHeader(rng, navItems),
		breadcrumbs,
		heroSVG,
		escHTML(title),
		mainContent,
		linkSection.String(),
		sidebar,
		footer,
		extras,
		e.elems.SocialShareButtons(),
		hiddenAPILinks,
		apiScript,
	)

	return html
}

// --- Page Style Generators ---

func (e *Engine) generateArticlePage(rng *rand.Rand, path string, vocab *TopicVocab) string {
	var sb strings.Builder

	// Article metadata
	sb.WriteString(e.elems.ArticleMetadata(rng))

	// Article body - multiple sections
	numSections := rng.Intn(4) + 3
	for i := 0; i < numSections; i++ {
		sectionTitle := vocab.Titles[rng.Intn(len(vocab.Titles))]
		sb.WriteString(fmt.Sprintf(`<section class="card"><h2>%s</h2>`, escHTML(sectionTitle)))

		// Paragraphs
		numParagraphs := rng.Intn(3) + 2
		for j := 0; j < numParagraphs; j++ {
			sb.WriteString(fmt.Sprintf(`<p>%s</p>`, e.words.GenerateSentence(rng, vocab)))
		}

		// Sometimes include an image
		if rng.Intn(3) == 0 {
			sb.WriteString(fmt.Sprintf(`<div class="hero-image">%s</div>`, e.elems.ImagePlaceholder(rng, 800, 300)))
		}

		// Sometimes include a data table
		if rng.Intn(4) == 0 {
			sb.WriteString(e.elems.DataTable(rng, rng.Intn(3)+3, rng.Intn(5)+3))
		}

		sb.WriteString(`</section>`)
	}

	// Comment section
	sb.WriteString(e.elems.CommentSection(rng, rng.Intn(5)+2))

	// Newsletter signup
	if rng.Intn(2) == 0 {
		sb.WriteString(e.elems.NewsletterSignup(rng))
	}

	return sb.String()
}

func (e *Engine) generateProductPage(rng *rand.Rand, vocab *TopicVocab) string {
	var sb strings.Builder

	// Product grid
	numProducts := rng.Intn(6) + 3
	sb.WriteString(`<section><h2>Featured Products</h2><div class="grid-3">`)
	for i := 0; i < numProducts; i++ {
		sb.WriteString(e.elems.ProductCard(rng))
	}
	sb.WriteString(`</div></section>`)

	// Description section
	sb.WriteString(`<section class="card">`)
	sb.WriteString(fmt.Sprintf(`<h2>%s</h2>`, vocab.Titles[rng.Intn(len(vocab.Titles))]))
	for i := 0; i < rng.Intn(3)+2; i++ {
		sb.WriteString(fmt.Sprintf(`<p>%s</p>`, e.words.GenerateSentence(rng, vocab)))
	}
	sb.WriteString(`</section>`)

	// Pricing table
	if rng.Intn(2) == 0 {
		sb.WriteString(e.elems.PricingTable(rng))
	}

	// Testimonials
	sb.WriteString(`<section><h2>What Our Customers Say</h2><div class="grid-2">`)
	for i := 0; i < rng.Intn(3)+2; i++ {
		sb.WriteString(e.elems.Testimonial(rng))
	}
	sb.WriteString(`</div></section>`)

	return sb.String()
}

func (e *Engine) generateCorporatePage(rng *rand.Rand, vocab *TopicVocab) string {
	var sb strings.Builder

	// Hero section
	subtitle := e.words.GenerateSentence(rng, vocab)
	sb.WriteString(e.elems.HeroSection(rng, vocab.Titles[rng.Intn(len(vocab.Titles))], subtitle))

	// About section
	sb.WriteString(`<section class="card">`)
	sb.WriteString(fmt.Sprintf(`<h2>%s</h2>`, e.words.RandSection(rng)))
	for i := 0; i < rng.Intn(3)+2; i++ {
		sb.WriteString(fmt.Sprintf(`<p>%s</p>`, e.words.GenerateSentence(rng, vocab)))
	}
	sb.WriteString(`</section>`)

	// Team members
	sb.WriteString(`<section><h2>Our Team</h2><div class="grid-3">`)
	for i := 0; i < rng.Intn(4)+3; i++ {
		name := e.words.RandName(rng)
		title := e.words.RandJobTitle(rng)
		sb.WriteString(fmt.Sprintf(`<div class="card" style="text-align:center;">
			%s
			<h3>%s</h3>
			<p style="color:#64748b;">%s</p>
			<p>%s</p>
		</div>`, e.elems.ImagePlaceholder(rng, 120, 120), escHTML(name), escHTML(title), e.words.GenerateSentence(rng, vocab)))
	}
	sb.WriteString(`</div></section>`)

	// Stats
	sb.WriteString(`<section class="card"><div class="grid-3" style="text-align:center;">`)
	stats := []struct{ label string }{{"Customers"}, {"Countries"}, {"Team Members"}, {"Years"}, {"Projects"}, {"Awards"}}
	for i := 0; i < 3; i++ {
		stat := stats[rng.Intn(len(stats))]
		sb.WriteString(fmt.Sprintf(`<div><div style="font-size:2.5em;font-weight:700;color:var(--primary);">%d+</div><div>%s</div></div>`,
			(rng.Intn(99)+1)*100, stat.label))
	}
	sb.WriteString(`</div></section>`)

	// Contact form
	sb.WriteString(e.elems.ContactForm(rng))

	return sb.String()
}

func (e *Engine) generateServicePage(rng *rand.Rand, vocab *TopicVocab) string {
	var sb strings.Builder

	// Hero
	subtitle := e.words.GenerateSentence(rng, vocab)
	sb.WriteString(e.elems.HeroSection(rng, vocab.Titles[rng.Intn(len(vocab.Titles))], subtitle))

	// Features grid
	sb.WriteString(`<section><h2>Our Services</h2><div class="grid-3">`)
	numFeatures := rng.Intn(3) + 3
	for i := 0; i < numFeatures; i++ {
		sb.WriteString(fmt.Sprintf(`<div class="card">
			%s
			<h3>%s</h3>
			<p>%s</p>
			<a href="/%s/%s" class="btn btn-secondary" style="margin-top:10px;">Learn More</a>
		</div>`,
			e.elems.ImagePlaceholder(rng, 60, 60),
			vocab.Nouns[rng.Intn(len(vocab.Nouns))],
			e.words.GenerateSentence(rng, vocab),
			"services", slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))]),
		))
	}
	sb.WriteString(`</div></section>`)

	// Pricing
	sb.WriteString(e.elems.PricingTable(rng))

	// CTA
	sb.WriteString(fmt.Sprintf(`<section class="card" style="text-align:center;padding:60px 20px;">
		<h2>Ready to Get Started?</h2>
		<p style="font-size:1.2em;margin:20px 0;">%s</p>
		<a href="/contact" class="btn">%s</a>
	</section>`, e.words.GenerateSentence(rng, vocab), e.words.RandCTA(rng)))

	return sb.String()
}

func (e *Engine) generateHelpPage(rng *rand.Rand, vocab *TopicVocab) string {
	var sb strings.Builder

	// Search bar prominently
	sb.WriteString(`<section class="card" style="padding:40px;">`)
	sb.WriteString(`<h2 style="text-align:center;margin-bottom:20px;">How can we help?</h2>`)
	sb.WriteString(e.elems.SearchBar(rng))
	sb.WriteString(`</section>`)

	// FAQ sections
	numFAQs := rng.Intn(5) + 3
	sb.WriteString(`<section><h2>Frequently Asked Questions</h2>`)
	for i := 0; i < numFAQs; i++ {
		question := fmt.Sprintf("How do I %s %s?",
			vocab.Verbs[rng.Intn(len(vocab.Verbs))],
			vocab.Nouns[rng.Intn(len(vocab.Nouns))])
		answer := e.words.GenerateSentence(rng, vocab)
		sb.WriteString(fmt.Sprintf(`<div class="card">
			<h3>%s</h3>
			<p>%s</p>
			<p><a href="/help/%s">Read more &rarr;</a></p>
		</div>`, escHTML(question), answer, slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))])))
	}
	sb.WriteString(`</section>`)

	// Contact support
	sb.WriteString(e.elems.ContactForm(rng))

	return sb.String()
}

func (e *Engine) generateDashboardPage(rng *rand.Rand, vocab *TopicVocab) string {
	var sb strings.Builder

	// Dashboard header
	sb.WriteString(fmt.Sprintf(`<section class="card"><div class="grid-3" style="text-align:center;">
		<div><div style="font-size:2em;font-weight:700;">%d</div><div style="color:#64748b;">Total Views</div></div>
		<div><div style="font-size:2em;font-weight:700;">%d</div><div style="color:#64748b;">Active Users</div></div>
		<div><div style="font-size:2em;font-weight:700;">$%d</div><div style="color:#64748b;">Revenue</div></div>
	</div></section>`, rng.Intn(100000)+1000, rng.Intn(5000)+100, rng.Intn(50000)+1000))

	// Activity table
	sb.WriteString(e.elems.DataTable(rng, 5, rng.Intn(8)+5))

	// Login form (if not authenticated)
	if rng.Intn(3) == 0 {
		sb.WriteString(`<section class="card"><h2>Sign In Required</h2><p>Please sign in to access your dashboard.</p>`)
		sb.WriteString(e.elems.LoginForm(rng))
		sb.WriteString(`</section>`)
	}

	return sb.String()
}

func (e *Engine) generateGenericPage(rng *rand.Rand, path string, vocab *TopicVocab) string {
	var sb strings.Builder

	// Hero section
	subtitle := e.words.GenerateSentence(rng, vocab)
	sb.WriteString(e.elems.HeroSection(rng, vocab.Titles[rng.Intn(len(vocab.Titles))], subtitle))

	// Content sections
	numSections := rng.Intn(4) + 2
	for i := 0; i < numSections; i++ {
		sb.WriteString(`<section class="card">`)
		sb.WriteString(fmt.Sprintf(`<h2>%s</h2>`, vocab.Titles[rng.Intn(len(vocab.Titles))]))

		numParagraphs := rng.Intn(3) + 1
		for j := 0; j < numParagraphs; j++ {
			sb.WriteString(fmt.Sprintf(`<p>%s</p>`, e.words.GenerateSentence(rng, vocab)))
		}

		// Random element inclusion
		switch rng.Intn(6) {
		case 0:
			sb.WriteString(e.elems.DataTable(rng, rng.Intn(3)+3, rng.Intn(4)+3))
		case 1:
			sb.WriteString(fmt.Sprintf(`<div>%s</div>`, e.elems.ImagePlaceholder(rng, 600, 300)))
		case 2:
			sb.WriteString(e.elems.SearchBar(rng))
		}

		sb.WriteString(`</section>`)
	}

	// Random extra sections
	if rng.Intn(2) == 0 {
		sb.WriteString(e.elems.NewsletterSignup(rng))
	}
	if rng.Intn(3) == 0 {
		sb.WriteString(`<section><h2>Testimonials</h2><div class="grid-2">`)
		for i := 0; i < rng.Intn(2)+2; i++ {
			sb.WriteString(e.elems.Testimonial(rng))
		}
		sb.WriteString(`</div></section>`)
	}

	return sb.String()
}

// --- Navigation & Link Generators ---

func (e *Engine) generateNavItems(rng *rand.Rand) []NavItem {
	labels := e.words.RandNavLabels(rng, rng.Intn(4)+5)
	items := make([]NavItem, len(labels))
	for i, label := range labels {
		items[i] = NavItem{
			Label: label,
			Href:  "/" + slugify(label),
		}
	}
	// Occasionally include app-style links that point to vuln endpoints
	if rng.Intn(3) == 0 {
		items = append(items, NavItem{Label: "Dashboard", Href: "/vuln/dashboard/"})
	}
	if rng.Intn(4) == 0 {
		items = append(items, NavItem{Label: "Settings", Href: "/vuln/settings/"})
	}
	if rng.Intn(4) == 0 {
		items = append(items, NavItem{Label: "Users", Href: "/vuln/a01/"})
	}
	return items
}

func (e *Engine) generateRelatedLinks(rng *rand.Rand, currentPath string, n int) []NavItem {
	links := make([]NavItem, n)
	segments := pathSegments(currentPath)
	topic := "general"
	if len(segments) > 0 {
		topic = segments[0]
	}

	vocab := e.words.TopicFor(currentPath)
	for i := range links {
		strategy := rng.Intn(4)
		var href, label string

		switch strategy {
		case 0: // Sibling path
			noun := slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))])
			href = "/" + topic + "/" + noun
			label = vocab.Titles[rng.Intn(len(vocab.Titles))]
		case 1: // Deeper path
			adj := slugify(vocab.Adjectives[rng.Intn(len(vocab.Adjectives))])
			noun := slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))])
			href = currentPath + "/" + adj + "-" + noun
			label = fmt.Sprintf("%s %s", vocab.Adjectives[rng.Intn(len(vocab.Adjectives))], vocab.Nouns[rng.Intn(len(vocab.Nouns))])
		case 2: // Cross-topic
			otherTopics := []string{"blog", "products", "services", "help", "news", "about"}
			t := otherTopics[rng.Intn(len(otherTopics))]
			noun := slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))])
			href = "/" + t + "/" + noun
			label = vocab.Titles[rng.Intn(len(vocab.Titles))]
		case 3: // Paginated
			href = currentPath + fmt.Sprintf("/page/%d", rng.Intn(20)+2)
			label = fmt.Sprintf("Page %d", rng.Intn(20)+2)
		}

		// Normalize href
		href = strings.ReplaceAll(href, "//", "/")
		if len(href) > 150 {
			href = href[:150]
		}

		links[i] = NavItem{Label: label, Href: href}
	}

	// Occasionally mix in vuln-related links that look like real app pages
	if rng.Intn(3) == 0 {
		vulnLinks := []NavItem{
			{Label: "Admin Dashboard", Href: "/vuln/dashboard/"},
			{Label: "User Management", Href: "/vuln/a01/"},
			{Label: "System Settings", Href: "/vuln/settings/"},
			{Label: "Security Config", Href: "/vuln/a05/"},
			{Label: "Audit Logs", Href: "/vuln/a09/"},
		}
		pick := vulnLinks[rng.Intn(len(vulnLinks))]
		idx := rng.Intn(len(links))
		links[idx] = pick
	}

	return links
}

func (e *Engine) generateInternalLinks(rng *rand.Rand, currentPath string, n int) []NavItem {
	categories := []string{
		"blog", "news", "products", "services", "help", "about",
		"team", "careers", "support", "docs", "faq", "pricing",
		"features", "solutions", "resources", "community",
	}

	links := make([]NavItem, n)
	vocab := e.words.TopicFor(currentPath)

	for i := range links {
		cat := categories[rng.Intn(len(categories))]
		noun := slugify(vocab.Nouns[rng.Intn(len(vocab.Nouns))])
		adj := slugify(vocab.Adjectives[rng.Intn(len(vocab.Adjectives))])

		href := fmt.Sprintf("/%s/%s-%s", cat, adj, noun)
		label := fmt.Sprintf("%s %s", vocab.Adjectives[rng.Intn(len(vocab.Adjectives))], vocab.Nouns[rng.Intn(len(vocab.Nouns))])

		links[i] = NavItem{Label: label, Href: href}
	}
	return links
}

// --- Utility Functions ---

func (e *Engine) titleFromPath(rng *rand.Rand, path string, vocab *TopicVocab) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return vocab.Titles[rng.Intn(len(vocab.Titles))]
	}

	// Use the last meaningful segment as the basis
	last := segments[len(segments)-1]
	// Convert slug to title case
	words := strings.Split(last, "-")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	title := strings.Join(words, " ")

	// If it's too short, augment with vocab
	if len(title) < 10 {
		title = fmt.Sprintf("%s: %s", title, vocab.Titles[rng.Intn(len(vocab.Titles))])
	}

	return title
}

func (e *Engine) keywordsFromPath(path string) string {
	segments := pathSegments(path)
	if len(segments) == 0 {
		return "web, content, platform, technology"
	}

	keywords := make([]string, 0, len(segments)*2)
	for _, seg := range segments {
		words := strings.Split(seg, "-")
		keywords = append(keywords, words...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	unique := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		if kw != "" && !seen[kw] {
			seen[kw] = true
			unique = append(unique, kw)
		}
	}

	if len(unique) > 10 {
		unique = unique[:10]
	}
	return strings.Join(unique, ", ")
}

func pathSeed(path string) int64 {
	h := sha256.Sum256([]byte(path))
	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(h[i])
	}
	return seed
}

func pathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" && p != "page" {
			result = append(result, p)
		}
	}
	return result
}

func slugify(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	// Remove non-alphanumeric except hyphens
	var sb strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

func escHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// --- API Discovery for Security Scanners ---

// apiCallSnippet represents a JavaScript fetch/API call that security scanners can discover.
type apiCallSnippet struct {
	// id is a short identifier used for deterministic selection.
	id string
	// code is the JavaScript source to include in the script block.
	code string
}

// allAPICallSnippets returns the full pool of JavaScript API call snippets.
// Each snippet is a realistic fetch/XHR/beacon call that references a discoverable API endpoint.
func allAPICallSnippets() []apiCallSnippet {
	return []apiCallSnippet{
		{
			id: "autocomplete",
			code: `    // Search autocomplete
    fetch('/api/autocomplete?q=' + encodeURIComponent(document.querySelector('input[name=q]')?.value || 'test'))
      .then(r => r.json()).then(d => { /* populate suggestions */ });`,
		},
		{
			id: "comments",
			code: `    // Load comments for this page
    fetch('/api/comments?path=' + encodeURIComponent(location.pathname))
      .then(r => r.json()).then(d => { /* render comments */ });`,
		},
		{
			id: "analytics",
			code: `    // Analytics beacon
    navigator.sendBeacon('/collect', JSON.stringify({event:'pageview',path:location.pathname,ts:Date.now()}));`,
		},
		{
			id: "tracking",
			code: `    // Tracking pixel
    new Image().src = '/tr?t=' + Date.now() + '&p=' + encodeURIComponent(location.pathname);`,
		},
		{
			id: "auth-status",
			code: `    // Check auth status
    fetch('/api/auth/status', {credentials:'include'})
      .then(r => r.json()).then(d => { /* update UI */ });`,
		},
		{
			id: "notifications",
			code: `    // Load notifications
    fetch('/api/v1/notifications?limit=5')
      .then(r => r.json()).then(d => { /* show bell count */ });`,
		},
		{
			id: "user-me",
			code: `    // Load user data (if logged in)
    fetch('/api/v1/users/me', {headers:{'Authorization':'Bearer ' + (document.cookie.match(/token=([^;]+)/)||[])[1]}})
      .then(r => r.json()).catch(() => {});`,
		},
		{
			id: "newsletter",
			code: `    // Newsletter check
    fetch('/api/newsletter/status')
      .then(r => r.json()).then(d => { /* update form */ });`,
		},
		{
			id: "csrf",
			code: `    // CSRF token refresh
    fetch('/api/csrf-token').then(r => r.json()).then(d => {
      document.querySelectorAll('input[name=csrf_token]').forEach(i => i.value = d.token);
    });`,
		},
		{
			id: "websocket",
			code: `    // WebSocket connection for real-time updates
    if (window.WebSocket) {
      var ws = new WebSocket('ws://' + location.host + '/ws/notifications');
      ws.onmessage = function(e) { /* handle notification */ };
    }`,
		},
		{
			id: "related-content",
			code: `    // Dynamic content loading
    fetch('/api/v1/content/related?path=' + encodeURIComponent(location.pathname))
      .then(r => r.json()).then(d => { /* populate sidebar */ });`,
		},
		{
			id: "products-rec",
			code: `    // Product recommendations
    fetch('/api/v1/products/recommendations?limit=4')
      .then(r => r.json()).then(d => { /* show products */ });`,
		},
		{
			id: "search-suggest",
			code: `    // Search suggestions on input
    document.querySelector('#search-input')?.addEventListener('input', function(e) {
      fetch('/api/search/suggest?q=' + encodeURIComponent(e.target.value))
        .then(r => r.json()).then(d => { /* show dropdown */ });
    });`,
		},
	}
}

// generateAPIScriptBlock produces a <script> tag containing a deterministic subset of
// realistic JavaScript API calls. The RNG controls which 8-12 calls appear on this page.
func generateAPIScriptBlock(rng *rand.Rand) string {
	all := allAPICallSnippets()

	// Shuffle the pool deterministically using Fisher-Yates.
	shuffled := make([]apiCallSnippet, len(all))
	copy(shuffled, all)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	// Pick between 8 and 12 snippets (clamped to pool size).
	count := 8 + rng.Intn(5) // 8..12
	if count > len(shuffled) {
		count = len(shuffled)
	}
	selected := shuffled[:count]

	var sb strings.Builder
	sb.WriteString("  <script>\n  document.addEventListener('DOMContentLoaded', function() {\n")
	for i, snippet := range selected {
		sb.WriteString(snippet.code)
		sb.WriteString("\n")
		if i < len(selected)-1 {
			sb.WriteString("\n")
		}
	}
	sb.WriteString("  });\n  </script>")
	return sb.String()
}

// prefetchEntry represents a <link> prefetch/preconnect/dns-prefetch hint.
type prefetchEntry struct {
	rel  string
	href string
}

// allPrefetchEntries returns the full pool of link-hint entries for the <head>.
func allPrefetchEntries() []prefetchEntry {
	return []prefetchEntry{
		{rel: "prefetch", href: "/api/v1/users/me"},
		{rel: "preconnect", href: "/api/v1/notifications"},
		{rel: "dns-prefetch", href: "/api/v1/content/related"},
		{rel: "prefetch", href: "/api/auth/status"},
		{rel: "prefetch", href: "/api/csrf-token"},
		{rel: "preconnect", href: "/api/v1/products/recommendations"},
		{rel: "dns-prefetch", href: "/api/comments"},
		{rel: "prefetch", href: "/api/newsletter/status"},
		{rel: "dns-prefetch", href: "/api/autocomplete"},
		{rel: "prefetch", href: "/api/search/suggest"},
	}
}

// generateAPIPrefetchLinks produces 3-6 deterministic <link> prefetch/preconnect hints.
func generateAPIPrefetchLinks(rng *rand.Rand) string {
	all := allPrefetchEntries()

	// Shuffle deterministically.
	shuffled := make([]prefetchEntry, len(all))
	copy(shuffled, all)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	count := 3 + rng.Intn(4) // 3..6
	if count > len(shuffled) {
		count = len(shuffled)
	}

	var sb strings.Builder
	for _, entry := range shuffled[:count] {
		sb.WriteString(fmt.Sprintf("  <link rel=\"%s\" href=\"%s\">\n", entry.rel, entry.href))
	}
	return sb.String()
}

// hiddenLinkEntry represents a hidden <a> tag for API endpoint discovery.
type hiddenLinkEntry struct {
	href  string
	label string
}

// allHiddenLinks returns the full pool of hidden anchor links for scanner discovery.
func allHiddenLinks() []hiddenLinkEntry {
	return []hiddenLinkEntry{
		{href: "/api/v1/docs", label: "API Documentation"},
		{href: "/api/v2/graphql", label: "GraphQL"},
		{href: "/swagger/index.html", label: "Swagger UI"},
		{href: "/api/v1/openapi.json", label: "OpenAPI Spec"},
		{href: "/api/v1/health", label: "API Health"},
		{href: "/api/v2/schema", label: "API Schema"},
		{href: "/api/v1/admin", label: "Admin API"},
		{href: "/api/v1/debug", label: "Debug Console"},
		{href: "/.well-known/openid-configuration", label: "OpenID Config"},
		{href: "/api/v1/webhooks", label: "Webhooks"},
	}
}

// generateHiddenAPILinks produces 3-5 deterministic hidden <a> tags that reference
// API documentation and other discoverable endpoints.
func generateHiddenAPILinks(rng *rand.Rand) string {
	all := allHiddenLinks()

	shuffled := make([]hiddenLinkEntry, len(all))
	copy(shuffled, all)
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	count := 3 + rng.Intn(3) // 3..5
	if count > len(shuffled) {
		count = len(shuffled)
	}

	var sb strings.Builder
	for _, link := range shuffled[:count] {
		sb.WriteString(fmt.Sprintf("  <a href=\"%s\" style=\"position:absolute;left:-9999px\">%s</a>\n", link.href, link.label))
	}
	return sb.String()
}
